"""关联引擎：把日志行和 pcap 报文按「业务关联键」对齐。

设计立场（这是整个工具最容易被做错的地方）：
  1. 有真关联键 → 画业务时序图，标注耗时和失败点。
  2. 没有关联键 → 只出「请求-响应对 + 时间邻近」，图上明确标低置信度。
     绝不能凭时间挨得近就画成一条完整调用链，那会让工程师当真。

关联键的判定标准是「能在 pcap 报文里命中」，不是「看起来像 ID」。
一个只在日志里出现、抓包里搜不到的值，不是关联键，只是日志内容。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field as dataclass_field
from typing import Optional

# ── 候选键的正则 ──────────────────────────────────────────────────
# 每条都必须带足够的熵，否则日志里的普通数字会被当成键
KEY_PATTERNS = [
    ("uuid", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("hex32", re.compile(r"\b[0-9a-fA-F]{32}\b")),
    ("hex40", re.compile(r"\b[0-9a-fA-F]{40}\b")),
    ("reqid", re.compile(r"(?i)\b(?:request|req|trace|span|msg|message|notification|task|job|order|biz)"
                         r"[_-]?id\b\s*[:=]\s*[\"']?([A-Za-z0-9._:-]{6,64})")),
    ("longnum", re.compile(r"\b\d{15,20}\b")),
]

# 这些字段名是「业务键」的强暗示，优先尝试
KEY_FIELD_HINTS = re.compile(
    r"(?i)(request_?id|req_?id|trace_?id|span_?id|message_?id|msg_?id|"
    r"notification_?id|task_?id|job_?id|order_?id|biz_?id|event_?id|"
    r"correlation_?id|session_?id|guid|serial_?no|seq_?no)")


@dataclass
class KeyCandidate:
    kind: str
    value: str
    field_name: str = ""     # 从哪个字段名抽出来的（能拿到时）
    log_hits: int = 0        # 日志里出现次数
    pcap_hits: int = 0       # 抓包里出现次数
    log_sources: set = dataclass_field(default_factory=set)
    in_both: bool = False

    @property
    def score(self) -> float:
        """置信度：必须两边都命中才算强键；单边命中最多算弱证据。"""
        if self.pcap_hits <= 0:
            return 0.0
        s = 0.0
        if self.log_hits > 0 and self.pcap_hits > 0:
            s += 0.55
        # 两边都出现、且出现次数接近，说明是同一个业务流
        if self.log_hits > 0:
            ratio = min(self.log_hits, self.pcap_hits) / max(self.log_hits, self.pcap_hits)
            s += 0.25 * ratio
        # uuid/hex 这类高熵值比长数字更可靠
        s += {"uuid": 0.12, "hex40": 0.10, "hex32": 0.10, "reqid": 0.08}.get(self.kind, 0.02)
        if self.field_name:
            s += 0.05
        return round(min(s, 1.0), 3)


def extract_candidates_from_text(text: str, source: str, into: dict) -> None:
    """从一段文本里抽候选键，累加到 into（value → KeyCandidate）。"""
    if not text:
        return
    for kind, pat in KEY_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(1) if pat.groups else m.group(0)
            if not val:
                continue
            # 纯数字要排除明显是时间戳的（epoch 秒/毫秒），否则满屏假键
            if kind == "longnum":
                try:
                    iv = int(val)
                    if 1_300_000_000 <= iv <= 2_000_000_000:
                        continue
                    if 1_300_000_000_000 <= iv <= 2_000_000_000_000:
                        continue
                except Exception:
                    pass
            cand = into.get(val)
            if cand is None:
                cand = KeyCandidate(kind=kind, value=val)
                into[val] = cand
            cand.log_hits += 1
            cand.log_sources.add(source)
            if not cand.field_name:
                seg = text[max(0, m.start() - 40):m.start()]
                fm = KEY_FIELD_HINTS.findall(seg)
                if fm:
                    cand.field_name = fm[-1]
    # 字段名强暗示再扫一遍（值可能不被上面的正则覆盖）
    for m in KEY_FIELD_HINTS.finditer(text):
        tail = text[m.end():m.end() + 70]
        vm = re.match(r'["\']?\s*[:=]\s*["\']?([A-Za-z0-9._:-]{6,64})', tail)
        if not vm:
            continue
        val = vm.group(1)
        cand = into.get(val)
        if cand is None:
            cand = KeyCandidate(kind="field", value=val)
            into[val] = cand
        cand.log_hits += 1
        cand.log_sources.add(source)
        if not cand.field_name:
            cand.field_name = m.group(0)


def score_against_pcap(cands: dict, pcap_blobs: list) -> None:
    """在抓包报文里搜候选键，命中才算真键。

    pcap_blobs: [(名字, bytes)]。没有抓包时传空列表 —— 那种情况下任何候选键
    都不该升级为关联键（宁可不画图，也不画错图）。
    """
    if not pcap_blobs:
        for v in list(cands):
            cands.pop(v, None)
        return
    for cand in list(cands.values()):
        needle = cand.value.encode("utf-8", "replace")
        if len(needle) < 6:
            cands.pop(cand.value, None)
            continue
        hits = 0
        for _name, blob in pcap_blobs:
            if not blob:
                continue
            hits += blob.count(needle)
        cand.pcap_hits = hits
        cand.in_both = hits > 0 and cand.log_hits > 0
    # 抓包里一次都没出现的，不可能是关联键，直接丢掉（避免噪声淹没真键）
    for v in [c.value for c in cands.values() if c.pcap_hits <= 0]:
        cands.pop(v, None)


def pick_key(cands: dict) -> Optional[KeyCandidate]:
    """选出「代表性」关联键（分数最高的那个值）。

    注意语义：对接件通常每笔业务一个 UUID，所以真正的关联键是「一类键」
    （如 requestId），不是某一个值。这里返回的只是代表值，供报告的样例展示；
    分组/过滤要用 pick_key_field() 拿字段名，再看 key_values() 的全部取值。
    """
    live = [c for c in cands.values() if c.pcap_hits > 0 and c.log_hits > 0]
    if not live:
        return None
    live.sort(key=lambda c: (-c.score, -min(c.log_hits, c.pcap_hits), -len(c.value)))
    best = live[0]
    return best if best.score >= 0.5 else None


def key_field_of(cand) -> str:
    """推断这个候选值属于哪个字段（requestId / traceId / ...）。"""
    if cand is None:
        return ""
    if cand.field_name:
        return cand.field_name
    # 没有字段名时按类型给个通用叫法
    return {"uuid": "uuid", "hex32": "hex-id", "hex40": "hex-id",
            "reqid": "request-id"}.get(cand.kind, cand.kind or "id")


def group_keys(cands: dict, threshold: float = 0.5) -> dict:
    """把候选值按「字段」聚成关联键类。

    返回 {字段名: [KeyCandidate, ...]}，只含 score >= threshold 的值。
    这是报告里真正的“关联键”概念：一处键类，多个取值。
    """
    groups = {}
    for c in cands.values():
        if c.pcap_hits <= 0 or c.log_hits <= 0 or c.score < threshold:
            continue
        groups.setdefault(key_field_of(c), []).append(c)
    # 常见的通用名不值得单独成类；合并进最有代表性的那类
    for k in list(groups):
        groups[k].sort(key=lambda c: -c.score)
    return groups


def key_values(cands: dict, threshold: float = 0.5) -> list:
    """全部可信关联键的取值（用于时间线里“命中任一个”的过滤）。"""
    return [c.value for c in cands.values()
            if c.pcap_hits > 0 and c.log_hits > 0 and c.score >= threshold]


def secondary_keys(cands: dict, primary, limit: int = 4) -> list:
    live = [c for c in cands.values() if c.pcap_hits > 0 and c.log_hits > 0
            and (primary is None or c.value != primary.value)]
    live.sort(key=lambda c: -c.score)
    return live[:limit]


# ── 日志行结构化 ──────────────────────────────────────────────────
TS_PATTERNS = [
    (re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?"), "ymd"),
    (re.compile(r"(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})"), "clf"),
    (re.compile(r"^\[?(\d{10})(?:\.(\d{1,9}))?\b"), "epoch"),
]
_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}


def parse_line_ts(line: str, assume_offset_hours: float = 8.0) -> Optional[float]:
    """解析行首时间戳为 epoch 秒。解析不出返回 None。"""
    from datetime import datetime, timezone, timedelta
    for pat, kind in TS_PATTERNS:
        m = pat.search(line[:80])
        if not m:
            continue
        try:
            if kind == "ymd":
                g = m.groups()
                y, mo, d, hh, mi, ss = (int(g[i]) for i in range(6))
                frac = g[6] or "0"
                micro = int((frac + "000000")[:6])
                tzs = g[7]
                if tzs == "Z":
                    tz = timezone.utc
                elif tzs:
                    sign = 1 if tzs[0] == "+" else -1
                    t = tzs[1:].replace(":", "")
                    tz = timezone(sign * timedelta(hours=int(t[:2]), minutes=int(t[2:4])))
                else:
                    tz = timezone(timedelta(hours=assume_offset_hours))
                return datetime(y, mo, d, hh, mi, ss, micro, tzinfo=tz).timestamp()
            if kind == "clf":
                d, mon, y, hh, mi, ss = m.groups()
                tz = timezone(timedelta(hours=assume_offset_hours))
                return datetime(int(y), _MONTHS[mon.lower()[:3]], int(d),
                                int(hh), int(mi), int(ss), tzinfo=tz).timestamp()
            if kind == "epoch":
                return float(m.group(1) + "." + (m.group(2) or "0"))
        except Exception:
            continue
    return None


LEVEL_RE = re.compile(r"(?i)\b(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|SEVERE|CRITICAL)\b")

# 失败判定的关键词。注意 HTTP 状态码必须带边界和上下文：
# 曾经只用裸的 500|502|503|504，结果 UUID 里的片段（如 ...5b2cb2500）被误判成 500，
# 把「push ok」的成功日志标成了失败，报告里凭空多出假告警。
FAIL_RE = re.compile(
    r"(?i)("
    r"timeout|timed out|connect(?:ion)? (?:refused|reset)|read timed out|"
    r"socketexception|broken pipe|retry|retrying|failed|failure|"
    r"exception|refused|unreachable|no route|SSLHandshake|error|"
    r"|(?<![\w.])(?:HTTP[/ ]?)?[45]0[0234](?![\w.])"   # 带边界的 4xx/5xx
    r"|\bstatus[\s:=]+[45]\d\d\b"                       # status=500 / status: 503
    r"|\bhttp_code[\s:=]+[45]\d\d\b"
    r")")


def is_failure_line(line: str) -> bool:
    """判断一行日志是否为失败。

    除了正则，还要尊重日志级别：明确的 INFO/DEBUG 且不含强失败词时不算失败，
    避免 UUID、时间戳里的数字片段造成假告警。

    但「强失败词」必须包含 retry 和带上下文的错误码 —— 否则
    「[INFO] retrying attempt 2」「[INFO] resp status=500」这类
    明明是失败的日志会被漏掉，那种漏报比误报更危险。
    """
    m = FAIL_RE.search(line)
    if not m:
        return False
    hit = m.group(0).lower()
    # 纯状态码形态必须带 HTTP 上下文，否则容易被业务数字命中
    if re.fullmatch(r"(?:http[/ ]?)?[45]0[0234]", hit):
        if not re.search(r"(?i)(http|status|code|response|返回|状态码)", line):
            return False
    lm = LEVEL_RE.search(line[:160])
    level = lm.group(1).upper() if lm else ""
    strong = re.search(
        r"(?i)(timeout|timed out|refused|reset|failed|failure|exception|"
        r"error|fatal|unreachable|no route|retry|retrying|retries|"
        r"status[\s:=]+[45]\d\d|http_code[\s:=]+[45]\d\d|"
        r"http[/ ]?[45]0[0234])", line)
    if level in ("INFO", "DEBUG", "TRACE") and not strong:
        return False
    return True


@dataclass
class LogLine:
    ts: Optional[float]
    raw: str
    source: str
    lineno: int
    level: str = ""
    is_failure: bool = False
    keys: list = dataclass_field(default_factory=list)

    @property
    def short(self) -> str:
        return self.raw.rstrip("\n")[:400]


def load_log_lines(paths_and_texts, assume_offset_hours: float = 8.0,
                   max_lines: int = 200_000):
    """把多份日志切片读成 LogLine 列表。传入 [(来源名, 文本)]。"""
    out = []
    for src, text in paths_and_texts:
        for i, ln in enumerate(text.splitlines(), 1):
            if not ln.strip():
                continue
            ts = parse_line_ts(ln, assume_offset_hours)
            lm = LEVEL_RE.search(ln[:120])
            ll = LogLine(ts=ts, raw=ln, source=src, lineno=i,
                         level=(lm.group(1).upper() if lm else ""),
                         is_failure=is_failure_line(ln))
            out.append(ll)
            if len(out) >= max_lines:
                return out
    return out


def attach_keys(lines, cands: dict) -> None:
    """把已经判定为「真键」的值回填到日志行上，供排序/分组用。"""
    live = {c.value for c in cands.values() if c.pcap_hits > 0}
    if not live:
        return
    for ll in lines:
        for v in live:
            if v in ll.raw:
                ll.keys.append(v)


# ── 时间线构建 ────────────────────────────────────────────────────
@dataclass
class TimelineEvent:
    ts: float
    kind: str            # log / request / response
    label: str
    detail: str = ""
    level: str = ""
    is_failure: bool = False
    key: str = ""
    source: str = ""


def build_timeline(lines, txs, key_value: str = "", window=None,
                   key_values_any=None) -> list:
    """把日志行和事务合成一条按时间排序的事件流。

    key_value：单个键值（旧用法，精确匹配）。
    key_values_any：一组可接受的键值（新用法）。真实场景里每笔业务一个 UUID，
        所以必须「命中任一取值」才算命中，否则时间线只剩一笔业务。
    两者都空时全部保留（低置信度场景，调用方必须标注）。
    """
    accept = None
    if key_values_any:
        accept = set(key_values_any)
    elif key_value:
        accept = {key_value}

    def _match(text_or_bytes) -> bool:
        if accept is None:
            return True
        if isinstance(text_or_bytes, bytes):
            return any(v.encode("utf-8", "replace") in text_or_bytes for v in accept)
        return any(v in text_or_bytes for v in accept)

    events = []
    for ll in lines:
        if ll.ts is None:
            continue
        if window and not (window[0] <= ll.ts <= window[1]):
            continue
        if not _match(ll.raw):
            continue
        events.append(TimelineEvent(
            ts=ll.ts, kind="log", level=ll.level,
            label="%s %s" % (ll.level or "LOG", ll.raw.strip()[:160]),
            detail=ll.raw.strip()[:600],
            is_failure=ll.is_failure, key=key_value,
            source="%s:%d" % (ll.source, ll.lineno)))
    for tx in txs:
        if not _match(_tx_blob(tx)):
            continue
        t = tx.t_request
        if window and not (window[0] <= t <= window[1]):
            continue
        req = tx.request
        resp = tx.response
        label = "%s %s %s → %s" % (
            tx.client[0], tx.client[1],
            ("%s %s" % (req.method, req.path)) if req else "<no request>",
            ("%d %s" % (resp.status, resp.reason)) if resp else "无响应")
        events.append(TimelineEvent(
            ts=t, kind="request", label=label,
            detail=label, is_failure=bool(tx.error),
            key=key_value, source="pcap"))
        if resp is not None:
            events.append(TimelineEvent(
                ts=tx.t_response, kind="response",
                label="响应 %d %s (%.0fms)" % (resp.status, resp.reason,
                                               tx.latency_ms or 0),
                detail=label, is_failure=resp.status >= 400,
                key=key_value, source="pcap"))
    events.sort(key=lambda e: e.ts)
    return events


def _tx_blob(tx) -> bytes:
    parts = []
    if tx.request:
        parts.append(tx.request.raw_head)
        parts.append(tx.request.body)
    if tx.response:
        parts.append(tx.response.raw_head)
        parts.append(tx.response.body)
    return b"\n".join(p for p in parts if p)


def pcap_blobs(txs) -> list:
    """导出全部报文正文，供关联键探测用。"""
    out = []
    for i, tx in enumerate(txs):
        out.append(("tx%d" % i, _tx_blob(tx)))
    return out


# ── 诊断规则 ──────────────────────────────────────────────────────
@dataclass
class Finding:
    title: str
    confidence: str        # high / medium / low
    evidence: list = dataclass_field(default_factory=list)
    next_step: str = ""
    category: str = ""

    def to_dict(self):
        return {"title": self.title, "confidence": self.confidence,
                "evidence": self.evidence, "next_step": self.next_step,
                "category": self.category}


def diagnose(lines, txs, cands, key, gaps) -> list:
    """基于「证据」给下一步排查方向。只写能从证据里看出来的，不猜。"""
    out = []

    # 1) 请求没有响应
    no_resp = [t for t in txs if t.request is not None and t.response is None]
    rst = [t for t in txs if t.response is None and "RST" in (t.error or "")]
    if no_resp:
        ev = []
        for t in no_resp[:5]:
            ev.append("%s:%d -> %s:%d %s %s (%s)" % (
                t.client[0], t.client[1], t.server[0], t.server[1],
                t.request.method if t.request else "-",
                t.request.path if t.request else "-",
                t.error or "无响应"))
        if rst:
            next_step = ("连接被 RST 重置，通常是中间设备或对端主动拒绝（端口没监听、"
                         "被防火墙策略拒绝、或者对端进程崩了）。下一步：在目标机用 curl 打同一地址"
                         "看是否 connection refused，同时确认对端服务确实在跑。")
        else:
            next_step = ("先在对端确认这条请求是否收到：拿这个时间点和 requestId 去对端日志里搜。"
                         "若对端也没有，问题在传输链路（中间设备丢包/超时/ACL）；若对端有，"
                         "问题在它的处理逻辑或响应路径。")
        out.append(Finding(
            title="检测到 %d 次请求没有收到响应" % len(no_resp),
            confidence="high" if cands else "medium",
            evidence=ev, next_step=next_step, category="响应缺失"))

    # 2) 5xx / 4xx
    errs = [t for t in txs if t.response is not None and t.response.status >= 400]
    if errs:
        by_status = {}
        for t in errs:
            by_status.setdefault(t.response.status, 0)
            by_status[t.response.status] += 1
        ev = ["状态码分布: %s" % json.dumps(by_status, ensure_ascii=False)]
        for t in errs[:5]:
            ev.append("%s %s -> %d (响应体 %d 字节)" % (
                t.request.method if t.request else "-",
                t.request.path if t.request else "-",
                t.response.status, len(t.response.body)))
        ns = ("4xx 是我方报文不符合对端契约（字段缺失/格式错/鉴权失效），"
              "取响应体里的错误描述定位具体字段；5xx 是对端自身故障，把响应体原文交对端。")
        if any(t.response.status in (401, 403) for t in errs):
            ns += " 出现 401/403，优先查凭据是否过期、IP 白名单是否变了。"
        out.append(Finding(
            title="检测到 %d 次错误响应" % len(errs), confidence="high",
            evidence=ev, next_step=ns, category="对端拒绝"))

    # 3) 慢请求
    lat = [t for t in txs if t.latency_ms is not None]
    if lat:
        slow = sorted([t for t in lat if (t.latency_ms or 0) >= 1000],
                      key=lambda t: -(t.latency_ms or 0))
        if slow:
            ev = ["最慢 5 条（整条 TCP 流时长，含对端处理时间）:"]
            for t in slow[:5]:
                ev.append("%.0fms  %s %s" % (t.latency_ms,
                          t.request.method if t.request else "-",
                          t.request.path if t.request else "-"))
            out.append(Finding(
                title="检测到 %d 次慢请求（>=1s）" % len(slow), confidence="medium",
                evidence=ev,
                next_step="看慢请求的时间点和日志里的重试/超时是否重合；若同一对端全慢，"
                          "先怀疑对端或网络，而不是本机转换逻辑。",
                category="时延"))

    # 4) 日志里的失败/重试
    fails = [l for l in lines if l.is_failure]
    if fails:
        by_src = {}
        for l in fails:
            by_src.setdefault(l.source, 0)
            by_src[l.source] += 1
        ev = ["失败/异常行来源分布: %s" % json.dumps(by_src, ensure_ascii=False)]
        for l in fails[:6]:
            ev.append("%s:%d %s" % (l.source, l.lineno, l.raw.strip()[:200]))
        out.append(Finding(
            title="日志里有 %d 行失败/异常/重试记录" % len(fails),
            confidence="medium", evidence=ev,
            next_step="按时间对齐抓包：如果某条失败日志的同一时刻抓包里有请求但没有响应，"
                      "问题在链路或对端；如果日志失败但抓包里根本没请求出去，问题在本机发送侧"
                      "（连接池耗尽、DNS、代理配置）。",
            category="日志异常"))

    # 5) 时间戳解析不出来 —— 说明时间线不可用，必须明说
    lines_with_ts = [l for l in lines if l.ts is not None]
    if lines and len(lines_with_ts) / len(lines) < 0.5:
        out.append(Finding(
            title="多数日志行解析不出时间戳（%d/%d），时间线不可靠"
                  % (len(lines) - len(lines_with_ts), len(lines)),
            confidence="high", evidence=[
                "样例: %s" % (lines[0].raw[:200] if lines else "-")],
            next_step="先确认这份日志的时间格式（是否多行日志、是否没有时间前缀）。"
                      "在这种日志上做时间对齐会得出错误结论，报告里已标为低置信度。",
            category="证据不足"))

    # 6) 空白抓包
    if not txs:
        out.append(Finding(
            title="抓包里没有可解析的业务事务", confidence="high",
            evidence=["pcap 存在但没有 HTTP/1.x 明文事务"],
            next_step="三种可能：①窗口内没复现；②流量是 HTTPS 或私有二进制协议（本工具不解密）；"
                      "③过滤条件不对。先看 61_capture_result.txt 里的抓包统计和过滤条件。",
            category="证据不足"))

    # 7) 环境层 gap
    if gaps:
        out.append(Finding(
            title="采集阶段有 %d 项无法完成（权限/工具缺失）" % len(gaps),
            confidence="high", evidence=gaps[:8],
            next_step="这些层没采到，报告里对应的结论都不能当定论。要补齐需要 "
                      "root 或免密 sudo（读别的用户的 /proc、跑 tcpdump）。",
            category="证据不足"))

    return out
