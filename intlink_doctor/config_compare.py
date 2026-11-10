"""有效配置对照：把「配置里声明的值」和「抓包实际观测到的行为」放在一起比。

为什么这是这个工具唯一能给出「修复方向」而不是「现象描述」的地方：
  配置写着 timeout=30s，但抓包显示 3.0s 就 FIN/RST，说明实际生效的不是这份配置
  （读错了文件、被环境变量覆盖、或者代码里写死了）。这种结论有证据支撑，
  可以直接指向要改什么。

核心约束（宁可少说，不许瞎说）：
  1. 只对「可观测」的配置项做对照。超时能从抓包量出来，重试次数能数出来，
     但「线程池大小」抓包里看不到，就只能列出来，不下结论。
  2. 纯数字没有单位时（timeout: 30）无法判断秒还是毫秒，一律标「单位未知」，
     不给「配置与实测不符」的错误结论。
  3. 观测值来自有限窗口，窗口内没断连不等于「超时没触发」，只能说「窗口内未观测到」。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field as dataclass_field

# 可观测的配置项 → 怎么从抓包里量
OBSERVABLE = {
    "timeout": "抓包里请求发出到 FIN/RST 的时长",
    "keepalive": "抓包里空闲连接是否被探测/断开",
    "retry": "同一业务键在窗口内出现的次数",
    "pool": "同时刻并发连接数（ESTABLISHED 峰值）",
}

TOLERANCE_MS = 300        # 时钟精度 + 调度抖动，低于这个差不算「不符」
TOLERANCE_RATIO = 0.25    # 相对误差超过 25% 才算不符


@dataclass
class ConfigItem:
    pid: str
    key: str
    raw: str
    kind: str
    value_ms: object = None
    unit_src: str = ""
    host: str = ""
    port: object = ""
    file: str = ""
    line: object = 0

    @property
    def name(self) -> str:
        return self.key.split(".")[-1].lower()

    @property
    def full_name(self) -> str:
        """完整键名（小写）。判类时要看全名：
        pool.max_connections 的 name 是 max_connections，只看末段会漏掉「池」这个语义。"""
        return self.key.lower()

    @property
    def is_duration(self) -> bool:
        return self.kind in ("duration", "number") and self.value_ms not in (None, "")

    @property
    def is_observable(self) -> bool:
        n = self.full_name
        return any(t in n for t in ("timeout", "retry", "keepalive", "pool", "max_conn"))


@dataclass
class Comparison:
    item: ConfigItem
    observed: object            # 实测值（毫秒 / 次数 / 连接数）
    observed_desc: str          # 怎么量出来的
    verdict: str                # match / mismatch / unknown / unobservable
    detail: str = ""
    confidence: str = "medium"

    def to_dict(self):
        return {
            "key": self.item.key, "raw": self.item.raw,
            "unit_src": self.item.unit_src,
            "value_ms": self.item.value_ms,
            "observed": self.observed, "observed_desc": self.observed_desc,
            "verdict": self.verdict, "detail": self.detail,
            "confidence": self.confidence,
            "file": self.item.file, "line": self.item.line,
        }


def load_config_items(tsv_rows) -> list:
    """把 39_config_kv.tsv 的行转成 ConfigItem 列表。"""
    out = []
    for r in tsv_rows:
        vm = r.get("value_ms", "")
        try:
            vm = int(vm) if str(vm).strip() not in ("", "None") else None
        except (TypeError, ValueError):
            vm = None
        p = r.get("port", "")
        try:
            p = int(p) if str(p).strip().isdigit() else p
        except Exception:
            pass
        out.append(ConfigItem(
            pid=str(r.get("pid", "")), key=r.get("key", ""),
            raw=r.get("raw", ""), kind=r.get("kind", ""),
            value_ms=vm, unit_src=r.get("unit_src", ""),
            host=r.get("host", ""), port=p,
            file=r.get("file", ""), line=r.get("line", "")))
    return out


# ── 从抓包量实测值 ────────────────────────────────────────────────
def measure_timeouts(txs) -> dict:
    """量「请求发出 → 连接被断开」的时长，按对端归组。

    返回 {对端: {'samples': [ms...], 'median': ms, 'closed_by': rst/fin}}。
    只统计「有请求但没有响应」的连接 —— 那才是超时/拒绝的现场。
    有正常响应的连接不能用来量超时（它根本没等到超时）。
    """
    groups = {}
    for tx in txs:
        if tx.request is None:
            continue
        if tx.response is not None:
            continue      # 有响应，不是超时场景
        key = "%s:%s" % (tx.server[0], tx.server[1])
        # t_request 是请求最后一字节时间，t_response 我们先当成断开时间用
        # （build_transactions 里无响应时 t_response 保留流的最后时间）
        dur = (tx.t_response - tx.t_request) * 1000
        if dur < 0:
            continue
        g = groups.setdefault(key, {"samples": [], "closed_by": ""})
        g["samples"].append(round(dur, 1))
        if "RST" in (tx.error or ""):
            g["closed_by"] = "rst"
        elif not g["closed_by"]:
            g["closed_by"] = "fin_or_timeout"
    for k, g in groups.items():
        s = sorted(g["samples"])
        g["median"] = s[len(s) // 2] if s else None
        g["count"] = len(s)
        g["min"] = s[0] if s else None
        g["max"] = s[-1] if s else None
    return groups


def measure_retries(txs, key_vals=None) -> dict:
    """数「同一业务键在一个窗口内发了几次」——用于对照 retry 配置。

    没有业务键时无法可靠数重试（把两次不同的业务当成重试会得出错误结论），
    所以返回空，由调用方标为不可观测。
    """
    if not key_vals:
        return {}
    counts = {}
    blobs = []
    for tx in txs:
        blob = b""
        if tx.request:
            blob = tx.request.raw_head + tx.request.body
        blobs.append((tx, blob))
    for kv in key_vals:
        needle = kv.encode("utf-8", "replace")
        n = sum(1 for _tx, b in blobs if needle in b)
        if n > 1:
            counts[kv] = n
    return counts


def measure_concurrency(txs) -> dict:
    """算抓包窗口内同时存在的连接数峰值（对照 pool_size / max_connections）。"""
    events = []
    for tx in txs:
        t0 = tx.t_request
        t1 = tx.t_response if tx.t_response >= t0 else t0
        events.append((t0, 1))
        events.append((t1, -1))
    if not events:
        return {"peak": 0, "samples": 0}
    events.sort()
    cur = peak = 0
    for _t, d in events:
        cur += d
        peak = max(peak, cur)
    return {"peak": peak, "samples": len(txs)}


# ── 对照判定 ──────────────────────────────────────────────────────
def compare(items, txs, key_vals=None) -> list:
    """把配置项和实测值对照，产出 Comparison 列表。

    判定规则写死在下面，重点是「不符」必须能被证据推翻/确认：
      - 差在容差内 = match
      - 差超出容差 = mismatch（这是最有价值的结论）
      - 配置无单位 / 抓包窗口内无样本 = unknown（不许下结论）
      - 抓包里根本量不出来的项 = unobservable（只列出，不判定）
    """
    timeouts = measure_timeouts(txs)
    retries = measure_retries(txs, key_vals)
    conc = measure_concurrency(txs)
    out = []

    for it in items:
        name = it.name
        fname = it.full_name

        # ── 超时类 ──
        if "timeout" in fname:
            if it.kind == "number" or it.unit_src == "unitless":
                out.append(Comparison(
                    item=it, observed=None,
                    observed_desc="配置值没写单位（%s），无法判断是秒还是毫秒" % it.raw,
                    verdict="unknown", confidence="high",
                    detail="要对照必须先确认单位；工具不替你假设。"))
                continue
            if not it.is_duration:
                out.append(Comparison(
                    item=it, observed=None, observed_desc="配置值不是可解析的时长",
                    verdict="unobservable", confidence="high"))
                continue
            if not timeouts:
                out.append(Comparison(
                    item=it, observed=None,
                    observed_desc="抓包窗口内没有「有请求无响应」的连接，量不到超时",
                    verdict="unknown", confidence="high",
                    detail="窗口内没触发不代表没配错；要量超时需要制造一次失败。"))
                continue
            # 用样本最多的对端作为观测对象
            peer, g = max(timeouts.items(), key=lambda kv: len(kv[1]["samples"]))
            obs = g["median"]
            cfg = it.value_ms
            diff = abs(obs - cfg)
            tol = max(TOLERANCE_MS, cfg * TOLERANCE_RATIO)
            desc = ("对端 %s 有 %d 次无响应，断开时长中位数 %.0fms（范围 %.0f~%.0fms）"
                    % (peer, g["count"], obs, g["min"], g["max"]))
            if diff <= tol:
                out.append(Comparison(item=it, observed=obs, observed_desc=desc,
                                      verdict="match", confidence="high",
                                      detail="配置值与实测断开时长吻合（差 %.0fms，容差 %.0fms）"
                                             % (diff, tol)))
            else:
                ratio = obs / cfg if cfg else 0
                out.append(Comparison(
                    item=it, observed=obs, observed_desc=desc,
                    verdict="mismatch", confidence="high",
                    detail=("配置声明 %s（%dms），实测断开在 %.0fms，约为配置的 %.2f 倍。"
                            "说明这份配置很可能没生效：可能读了别的文件、被环境变量/"
                            "-D 参数覆盖、或代码里写死。下一步：确认进程实际加载的是哪份配置"
                            "（启动命令行/工作目录），以及有没有更外层配置覆盖它。"
                            % (it.raw, cfg, obs, ratio))))
            continue

        # ── 重试类 ──
        if "retry" in fname or "max_attempts" in fname:
            if it.kind not in ("duration", "number") and not str(it.raw).strip().isdigit():
                out.append(Comparison(item=it, observed=None,
                                      observed_desc="配置值不是数字", verdict="unobservable",
                                      confidence="high"))
                continue
            try:
                cfg_n = int(float(re.sub(r"[^\d.]", "", str(it.raw)) or 0))
            except ValueError:
                cfg_n = 0
            if not key_vals:
                out.append(Comparison(
                    item=it, observed=None,
                    observed_desc="没有业务关联键，无法可靠数重试次数",
                    verdict="unknown", confidence="high",
                    detail="同一业务发了几次要靠键区分；没有键时把不同业务当重试会得出错误结论。"))
                continue
            if not retries:
                out.append(Comparison(
                    item=it, observed=1, observed_desc="窗口内每个业务键只出现 1 次（没有重试）",
                    verdict="match" if cfg_n >= 0 else "unknown", confidence="medium",
                    detail="窗口内没观测到重试。若现场确有重试但发生在窗口外，此结论不成立。"))
                continue
            mx = max(retries.values())
            desc = "窗口内同一业务键最多出现 %d 次（%d 个键有重复）" % (mx, len(retries))
            attempt = mx - 1
            if attempt <= cfg_n:
                out.append(Comparison(item=it, observed=attempt, observed_desc=desc,
                                      verdict="match", confidence="medium",
                                      detail="观测到的重试次数未超过配置上限 %d" % cfg_n))
            else:
                out.append(Comparison(
                    item=it, observed=attempt, observed_desc=desc,
                    verdict="mismatch", confidence="medium",
                    detail=("配置声明最多重试 %d 次，实测同一业务键出现 %d 次（约 %d 次重试）。"
                            "可能配置未生效，或另有外层重试（网关/框架）叠加。"
                            % (cfg_n, mx, attempt))))
            continue

        # ── 连接池类 ──
        if "pool" in fname or "max_conn" in fname:
            try:
                cfg_n = int(float(re.sub(r"[^\d.]", "", str(it.raw)) or 0))
            except ValueError:
                cfg_n = 0
            peak = conc["peak"]
            desc = "抓包窗口内并发连接峰值 %d（基于 %d 笔事务）" % (peak, conc["samples"])
            if cfg_n and peak <= cfg_n:
                out.append(Comparison(item=it, observed=peak, observed_desc=desc,
                                      verdict="match", confidence="low",
                                      detail=("峰值未超过配置上限 %d。注意：抓包只能看到"
                                              "这个窗口内的并发，真实峰值可能更高。" % cfg_n)))
            elif cfg_n and peak > cfg_n:
                out.append(Comparison(
                    item=it, observed=peak, observed_desc=desc,
                    verdict="mismatch", confidence="low",
                    detail=("并发峰值 %d 超过配置上限 %d。可能是配置未生效，"
                            "或多实例/多进程共同对外（每个实例各自一份池）。" % (peak, cfg_n))))
            else:
                out.append(Comparison(item=it, observed=peak, observed_desc=desc,
                                      verdict="unknown", confidence="low"))
            continue

        # ── keepalive 等其它可观测项 ──
        if it.is_observable:
            out.append(Comparison(item=it, observed=None,
                                  observed_desc="需要在窗口内抓到空闲期才能判定",
                                  verdict="unknown", confidence="low"))
            continue

        # ── 连接地址/端口：与抓包实际目标对照 ──
        if it.kind in ("endpoint", "port"):
            hosts = set()
            for tx in txs:
                hosts.add("%s:%s" % (tx.server[0], tx.server[1]))
            # 监听端口：抓包里它是服务端端口，不是「连出去的目标」，
            # 所以要判「有没有流量打到这个端口」，而不是判「有没有连到它」。
            is_listen_port = (it.kind == "port" and not it.host)
            if is_listen_port:
                hit = any(str(it.port) == str(tx.server[1]) for tx in txs)
                desc = ("抓包里打到 %s 端口的事务：%d 笔；出现的服务端端口：%s"
                        % (it.port, sum(1 for tx in txs if str(tx.server[1]) == str(it.port)),
                           ", ".join(sorted({str(tx.server[1]) for tx in txs})) or "无"))
                if hit:
                    out.append(Comparison(item=it, observed=it.port, observed_desc=desc,
                                          verdict="match", confidence="high",
                                          detail="抓包里有流量打到这个端口。"))
                else:
                    out.append(Comparison(
                        item=it, observed=None, observed_desc=desc,
                        verdict="unknown", confidence="high",
                        detail=("这是配置里声明的监听端口，但抓包窗口内没有流量打到它。"
                                "可能客户端没连过来、被中间设备转走了，或应该抓的是它的"
                                "上游出口流量而不是入口。")))
                continue
            target = ("%s:%s" % (it.host, it.port)) if it.host else str(it.port)
            hit = any(str(it.port) and str(it.port) in h for h in hosts)
            out.append(Comparison(
                item=it, observed=target if hit else None,
                observed_desc="抓包里出现的对端：%s" % (", ".join(sorted(hosts)[:5]) or "无"),
                verdict="match" if hit else "unknown", confidence="high",
                detail="" if hit else "抓包窗口内没连到这个地址，可能没触发或走了别的路径。"))
            continue

        # 其它配置项：抓包量不出来，只列出
        out.append(Comparison(item=it, observed=None,
                              observed_desc="抓包里无法观测这一项",
                              verdict="unobservable", confidence="high"))

    return out


def summarize(comps) -> dict:
    d = {"match": 0, "mismatch": 0, "unknown": 0, "unobservable": 0}
    for c in comps:
        d[c.verdict] = d.get(c.verdict, 0) + 1
    return d


# ── 时长解析（目标机侧 39_config_kv.tsv 已归一，这里给 Windows 侧复用）──
DUR_RE = re.compile(
    r'(?i)^\s*["\']?(\d+(?:\.\d+)?)\s*'
    r'(ms|s|sec|secs|seconds?|m|min|mins|h|hour|hours)?\s*["\']?\s*$')


def parse_duration_ms(raw):
    """把 "30s" / "5000ms" / "2m" 归一成 (毫秒, 来源单位)。

    纯数字无法确定是秒还是毫秒，返回 ('unitless')，绝不替用户假设 ——
    猜错会直接导致「配置与实测不符」的错误结论。
    """
    m = DUR_RE.match(str(raw).strip())
    if not m:
        return None
    val = float(m.group(1))
    unit = (m.group(2) or "").lower()
    if not unit:
        return (int(val), "unitless")
    if unit == "ms":
        return (int(val), "ms")
    if unit in ("s", "sec", "secs", "second", "seconds"):
        return (int(val * 1000), "ms")
    if unit in ("m", "min", "mins"):
        return (int(val * 60000), "ms")
    if unit in ("h", "hour", "hours"):
        return (int(val * 3600000), "ms")
    return None
