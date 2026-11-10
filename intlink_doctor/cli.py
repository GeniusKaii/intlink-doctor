"""证据包读取 + 分析编排 + 命令行入口。

analyze 的输入是 intlink_probe.sh 产出的 tar.gz（或已解压的 evidence 目录）。
输出目录里全部是给人看的东西：report.md / report.html / timeline.json / findings.json。

关键约束：分析只看证据包里已有的东西，不连目标机、不猜缺失数据。
采不到的层（权限/工具）从 90_gaps.txt、91_parse_gaps.txt 读出来，原样进报告。
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tarfile
import tempfile

from . import config_compare as CC
from . import correlate as C
from . import pcap_http
from . import report as R


# ── 证据包 ────────────────────────────────────────────────────────
class Evidence:
    def __init__(self, root: str):
        self.root = root
        self.evd = self._find_evidence(root)

    @staticmethod
    def _find_evidence(root: str) -> str:
        # 包里通常有一层 intlink-out-<ts>/evidence
        cand = os.path.join(root, "evidence")
        if os.path.isdir(cand):
            return cand
        for dirpath, dirnames, _ in os.walk(root):
            if "evidence" in dirnames:
                return os.path.join(dirpath, "evidence")
        return root

    def path(self, name: str) -> str:
        return os.path.join(self.evd, name)

    def read(self, name: str, default: str = "") -> str:
        p = self.path(name)
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception:
            return default

    def tsv(self, name: str) -> list:
        txt = self.read(name)
        if not txt.strip():
            return []
        rows = []
        lines = txt.splitlines()
        head = lines[0].split("\t")
        for ln in lines[1:]:
            if not ln.strip():
                continue
            vals = ln.split("\t")
            rows.append({head[i] if i < len(head) else "c%d" % i:
                         (vals[i] if i < len(vals) else "") for i in range(len(head))})
        return rows

    def gaps(self) -> list:
        out = []
        for name in ("90_gaps.txt", "91_parse_gaps.txt"):
            txt = self.read(name)
            for ln in txt.splitlines():
                ln = ln.strip()
                if ln and ln not in out:
                    out.append(ln)
        return out

    def meta(self) -> dict:
        """从 05_env.txt 抽基本信息。"""
        txt = self.read("05_env.txt")
        m = {"hostname": "", "collected_at": "", "tz": "", "root": "",
             "container": "", "py": ""}
        for ln in txt.splitlines():
            if ln.startswith("collected_at_local:"):
                m["collected_at"] = ln.split(":", 1)[1].strip()
            elif ln.startswith("hostname:"):
                m["hostname"] = ln.split(":", 1)[1].strip()
            elif ln.startswith("TZ_env:"):
                m["tz"] = ln.split(":", 1)[1].strip()
            elif ln.startswith("is_root:"):
                m["root"] = ln.split(":", 1)[1].strip()
            elif ln.startswith("container_hint:"):
                m["container"] = ln.split(":", 1)[1].strip()
        return m

    def pcap_files(self) -> list:
        d = self.path("60_capture")
        out = []
        if not os.path.isdir(d):
            return out
        for nm in sorted(os.listdir(d)):
            if nm.endswith((".pcap", ".pcapng", ".cap")):
                p = os.path.join(d, nm)
                if os.path.getsize(p) > 0:
                    out.append(p)
        return out

    def log_slices(self) -> list:
        d = self.path("41_log_slices")
        out = []
        if not os.path.isdir(d):
            return out
        for nm in sorted(os.listdir(d)):
            p = os.path.join(d, nm)
            if os.path.isfile(p) and os.path.getsize(p) > 0:
                out.append(p)
        return out


def open_evidence(pkg: str, workdir: str = "") -> tuple:
    """返回 (Evidence, 临时目录或 None)。包是 tar.gz 就解到临时目录。"""
    if os.path.isdir(pkg):
        return Evidence(pkg), None
    if not os.path.isfile(pkg):
        raise FileNotFoundError("找不到证据包: %s" % pkg)
    # 判断是否 tar
    with open(pkg, "rb") as f:
        magic = f.read(2)
    if magic != b"\x1f\x8b" and not pkg.endswith((".tar", ".tar.gz", ".tgz")):
        raise ValueError("不是 tar.gz 证据包: %s" % pkg)
    tmp = workdir or tempfile.mkdtemp(prefix="intlink-analyze-")
    os.makedirs(tmp, exist_ok=True)
    with tarfile.open(pkg, "r:*") as t:
        # 防路径穿越
        for m in t.getmembers():
            if m.name.startswith("/") or ".." in m.name.split("/"):
                raise ValueError("包内含可疑路径: %s" % m.name)
        # Python 3.14 起 extractall 默认 filter='data' 会拒绝某些成员，
        # 这里显式指定 data 过滤器，行为在 3.12+ 与未来版本保持一致。
        try:
            t.extractall(tmp, filter="data")
        except TypeError:
            t.extractall(tmp)
    return Evidence(tmp), tmp


# ── 分析编排 ──────────────────────────────────────────────────────
def analyze(ev: Evidence, tz_offset_hours: float = 8.0,
            pkg_name: str = "") -> dict:
    meta = ev.meta()
    meta["package"] = pkg_name or ev.root
    gaps = ev.gaps()

    # 1. 抓包 → 事务
    txs = []
    pcap_info = []
    for pf in ev.pcap_files():
        try:
            packets, pmeta = pcap_http.read_pcap(pf)
            segs, smeta = pcap_http.parse_tcp(packets)
            streams = pcap_http.group_streams(segs)
            file_txs = pcap_http.build_transactions(streams)
            txs.extend(file_txs)
            pcap_info.append({
                "file": os.path.basename(pf),
                "packets": len(packets),
                "streams": len(streams),
                "transactions": len(file_txs),
                "meta": pmeta,
            })
        except Exception as e:
            gaps.append("pcap 解析失败 %s: %s" % (os.path.basename(pf), e))
    if not ev.pcap_files():
        gaps.append("证据包里没有 pcap（采集时抓包不可用或被跳过）")

    # 2. 日志
    texts = []
    for p in ev.log_slices():
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                texts.append((os.path.basename(p), f.read()))
        except Exception as e:
            gaps.append("日志切片读取失败 %s: %s" % (os.path.basename(p), e))
    log_lines = C.load_log_lines(texts, assume_offset_hours=tz_offset_hours)
    if not texts:
        gaps.append("证据包里没有日志切片（41_log_slices 为空）")

    # 3. 关联键：日志里抽候选 → 拿去抓包里搜
    cands = {}
    for ll in log_lines:
        C.extract_candidates_from_text(ll.raw, ll.source, cands)
    blobs = C.pcap_blobs(txs)
    C.score_against_pcap(cands, blobs)
    key = C.pick_key(cands)
    key_groups = C.group_keys(cands)
    key_vals = C.key_values(cands)
    C.attach_keys(log_lines, cands)

    # 4. 时间线：按「命中任一可信键值」过滤（每笔业务一个 UUID 是常态，
    #    只认单个值会把时间线砍成只剩一笔）
    window = None
    if txs:
        t0 = min(t.t_request for t in txs if t.t_request)
        t1 = max(t.t_response for t in txs if t.t_response)
        window = (t0 - 120, t1 + 120)
    events = C.build_timeline(log_lines, txs,
                              key_value=(key.value if key else ""),
                              window=window,
                              key_values_any=(key_vals if key else None))
    if not events:
        # 键过滤后为空，退回全量但明确标注
        events = C.build_timeline(log_lines, txs, key_value="", window=window)
        if key:
            gaps.append("按关联键过滤后时间线为空，已退回全量时间线（置信度下降）")

    # 5. 诊断
    findings = C.diagnose(log_lines, txs, cands, key, gaps)

    # 6. 报告上下文
    procs = ev.tsv("20_procs.tsv")
    log_files = ev.tsv("40_logs.tsv")

    # 7) 有效配置对照：配置声明值 vs 抓包实测行为
    cfg_items = CC.load_config_items(ev.tsv("39_config_kv.tsv"))
    comparisons = CC.compare(cfg_items, txs, key_vals) if cfg_items else []
    if not cfg_items:
        gaps.append("证据包里没有 39_config_kv.tsv（采集时没找到配置文件，"
                    "或目标机没有 python3），无法做配置与实测的对照")
    # 配置结论也要进 findings，否则报告里看不到「配置未生效」这种关键判断
    for cmp in comparisons:
        if cmp.verdict == "mismatch":
            findings.append(C.Finding(
                title="配置与实测行为不符：%s" % cmp.item.key,
                confidence="high" if cmp.confidence == "high" else "medium",
                evidence=[cmp.item.raw, cmp.observed_desc, cmp.detail],
                next_step=("确认进程实际加载的是哪份配置：看启动命令行（--config/-D）、"
                           "工作目录、以及是否存在环境变量覆盖。这份配置很可能没生效。"),
                category="配置对照"))

    ctx = {
        "meta": meta, "findings": findings, "key": key,
        "candidates": cands, "key_groups": key_groups,
        "key_vals": key_vals, "events": events, "log_lines": log_lines,
        "txs": txs, "gaps": gaps, "procs": procs, "log_files": log_files,
        "pcap_info": pcap_info,
        "config_items": cfg_items, "config_comparisons": comparisons,
        "mmd_seq": R.mermaid_sequence(events, key.value if key else "",
                                      bool(key)),
        "mmd_flow": R.mermaid_flow(findings, key.value if key else ""),
    }
    return ctx


def run_analyze(pkg: str, outdir: str, tz_offset_hours: float = 8.0) -> dict:
    ev, tmp = open_evidence(pkg)
    try:
        ctx = analyze(ev, tz_offset_hours, pkg_name=os.path.basename(pkg.rstrip("/\\")))
        paths = R.write_reports(ctx, outdir)
        summary = {
            "package": ctx["meta"].get("package"),
            "hostname": ctx["meta"].get("hostname"),
            "log_lines": len(ctx["log_lines"]),
            "transactions": len(ctx["txs"]),
            "key": ctx["key"].value if ctx["key"] else None,
            "key_score": ctx["key"].score if ctx["key"] else 0,
            "key_count": len(ctx.get("key_vals") or []),
            "findings": len(ctx["findings"]),
            "gaps": len(ctx["gaps"]),
            "outputs": paths,
        }
        with open(os.path.join(outdir, "summary.json"), "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=1)
        return summary
    finally:
        if tmp:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


# ── CLI ───────────────────────────────────────────────────────────
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="intlink_doctor",
                                 description="三方对接件排障：证据包分析")
    sub = ap.add_subparsers(dest="cmd")

    a = sub.add_parser("analyze", help="分析证据包并出报告")
    a.add_argument("package", help="intlink_probe.sh 产出的 tar.gz 或 evidence 目录")
    a.add_argument("--out", default="intlink-report", help="输出目录")
    a.add_argument("--tz", type=float, default=8.0,
                   help="日志本地时区偏移小时，默认 8")

    b = sub.add_parser("run", help="直接对目标机采集并分析")
    b.add_argument("--host", required=True, help="主机或 ssh config 别名")
    b.add_argument("--user", default="root")
    b.add_argument("--port", type=int, default=22)
    b.add_argument("--key", default="", help="私钥路径")
    b.add_argument("--password", default="", help="密码（不落盘，推荐用密钥）")
    b.add_argument("--hint", action="append", default=[], help="程序线索，可多次")
    b.add_argument("--pid", action="append", default=[], help="直接指定 PID，可多次")
    b.add_argument("--auto", action="store_true", help="自动挑有对外连接的进程")
    b.add_argument("--secs", type=int, default=60, help="抓包秒数")
    b.add_argument("--window-secs", type=int, default=900, help="日志回看秒数")
    b.add_argument("--ports", default="", help="强制抓的端口，逗号分隔")
    b.add_argument("--list-only", action="store_true", help="只侦察不抓包")
    b.add_argument("--out", default="intlink-report", help="报告输出目录")
    b.add_argument("--packages", default="", help="证据包落地目录，默认 ./intlink-packages")
    b.add_argument("--script", default="", help="采集脚本路径，默认随包的 agent/intlink_probe.sh")
    b.add_argument("--tz", type=float, default=8.0)

    c = sub.add_parser("selftest", help="跑内置自检")
    args = ap.parse_args(argv)

    if args.cmd == "analyze":
        s = run_analyze(args.package, args.out, args.tz)
        print("证据包: %s" % s["package"])
        print("主机:   %s" % s["hostname"])
        print("日志行: %d   抓包事务: %d" % (s["log_lines"], s["transactions"]))
        if s["key"]:
            print("关联键: %s (score=%.2f, %d 个取值)"
                  % (s["key"], s["key_score"], s.get("key_count", 1)))
        else:
            print("关联键: 未找到（报告已标注低置信度）")
        print("发现:   %d 条   采集缺口: %d 项" % (s["findings"], s["gaps"]))
        print("")
        print("报告: %s" % s["outputs"]["report_html"])
        print("      %s" % s["outputs"]["report_md"])
        return 0
    if args.cmd == "run":
        return _cmd_run(args)
    if args.cmd == "selftest":
        from . import selftest as st
        return st.main()
    ap.print_help()
    return 1


def _find_script(explicit: str = "") -> str:
    """找采集脚本，支持源码与 PyInstaller 打包两种布局。"""
    if explicit:
        return explicit if os.path.isfile(explicit) else ""
    here = os.path.dirname(os.path.abspath(__file__))
    cands = [os.path.join(os.path.dirname(here), "agent", "intlink_probe.sh"),
             os.path.join(here, "agent", "intlink_probe.sh"),
             os.path.join(os.path.dirname(here), "intlink_probe.sh")]
    base = getattr(sys, "_MEIPASS", "")
    if base:
        cands.insert(0, os.path.join(base, "agent", "intlink_probe.sh"))
        cands.insert(1, os.path.join(base, "intlink_probe.sh"))
    for c in cands:
        if os.path.isfile(c):
            return c
    return ""


def _cmd_run(args) -> int:
    from . import ssh_runner as SSH
    script = _find_script(args.script)
    if not script:
        print("找不到采集脚本 agent/intlink_probe.sh", file=sys.stderr)
        return 2
    target = SSH.Target(host=args.host, user=args.user, port=args.port,
                        key_path=args.key, password=args.password)
    opts = {"hint": args.hint, "pid": args.pid, "auto": args.auto,
            "secs": args.secs, "window_secs": args.window_secs,
            "list_only": args.list_only, "ports": args.ports}

    def on_line(tag, ln):
        if tag == "stage":
            print("» " + ln, flush=True)
        elif tag == "warn":
            print("! " + ln, flush=True)
        elif tag == "cmd":
            print("$ " + ln, flush=True)
        else:
            print("  " + ln, flush=True)

    pkgdir = args.packages or os.path.join(os.getcwd(), "intlink-packages")
    print("目标: %s" % target.describe())
    res = SSH.deploy_and_capture(target, script, opts, on_line=on_line,
                                 local_out_dir=pkgdir)
    if res.error:
        print("\n采集失败: %s" % res.error, file=sys.stderr)
        return 1
    print("\n证据包: %s" % res.local_pkg)
    s = run_analyze(res.local_pkg, args.out, args.tz)
    print("日志行 %d / 事务 %d / 发现 %d / 缺口 %d"
          % (s["log_lines"], s["transactions"], s["findings"], s["gaps"]))
    if s["key"]:
        print("关联键: %s (score=%.2f)" % (s["key"], s["key_score"]))
    else:
        print("关联键: 未找到（报告标低置信度）")
    print("报告: %s" % s["outputs"]["report_html"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
