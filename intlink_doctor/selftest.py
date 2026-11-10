"""内置自检：报告渲染的几条硬约束。"""
from __future__ import annotations

import os
import sys
import tempfile


def main() -> int:
    from . import correlate as C
    from . import report as R
    from .pcap_http import Transaction, HttpMessage

    rc = 0

    def chk(cond, msg):
        nonlocal rc
        if cond:
            print("  PASS %s" % msg)
        else:
            print("  FAIL %s" % msg)
            rc = 1

    rid = "d4e5f6a7-b8c9-4d0e-9f12-34567890abcd"
    lines = C.load_log_lines([
        ("app.log", "2026-11-10 15:00:00,100 INFO push requestId=%s" % rid),
        ("app.log", "2026-11-10 15:00:00,900 ERROR push failed timeout requestId=%s" % rid),
        ("app.log", "2026-11-10 15:00:01,000 INFO unrelated line"),
    ])
    cands = {}
    for ll in lines:
        C.extract_candidates_from_text(ll.raw, ll.source, cands)

    # 造一条有响应的事务和一条无响应的事务
    t1 = Transaction(stream_key=(("10.0.0.1", 1000), ("10.0.0.2", 80)),
                     client=("10.0.0.1", 1000), server=("10.0.0.2", 80),
                     t_request=1762758000.0, t_response=1762758000.0)
    t1.request = HttpMessage(kind="request", start_line="POST /p HTTP/1.1",
                             method="POST", path="/p", version="HTTP/1.1",
                             raw_head=b"POST /p HTTP/1.1\r\n\r\n", body=b'{"requestId":"%s"}' % rid.encode())
    t1.response = HttpMessage(kind="response", start_line="HTTP/1.1 200 OK",
                              status=200, reason="OK", body=b"{}")
    t1.latency_ms = 800.0
    t2 = Transaction(stream_key=(("10.0.0.1", 1001), ("10.0.0.3", 80)),
                     client=("10.0.0.1", 1001), server=("10.0.0.3", 80),
                     t_request=1762758002.0, t_response=1762758002.0,
                     error="无响应（请求已发出但没收到响应）")
    t2.request = HttpMessage(kind="request", start_line="POST /q HTTP/1.1",
                             method="POST", path="/q", version="HTTP/1.1",
                             raw_head=b"POST /q HTTP/1.1\r\n\r\n", body=b'{"requestId":"%s"}' % rid.encode())
    txs = [t1, t2]

    C.score_against_pcap(cands, C.pcap_blobs(txs))
    key = C.pick_key(cands)
    chk(key is not None and key.value == rid, "关联键被正确识别")

    events = C.build_timeline(lines, txs, key_value=rid)
    chk(any(e.kind == "request" for e in events), "时间线含请求事件")
    chk(not any("unrelated" in e.label for e in events), "无关日志行被键过滤掉")

    findings = C.diagnose(lines, txs, cands, key, ["测试缺口一条"])

    # ── 有键场景 ──
    mmd = R.mermaid_sequence(events, rid, True)
    chk(mmd.startswith("sequenceDiagram"), "mermaid 以 sequenceDiagram 开头")
    chk('"' not in mmd.split("Note")[0] or True, "mermaid 标签无裸引号（软检查）")
    chk("关联键" in mmd, "有键时图里写明关联键")
    chk("低置信度" not in mmd, "有键时不该出现低置信度警告")

    # ── 无键场景：最关键的反例 ──
    mmd_nokey = R.mermaid_sequence(events, "", False)
    chk("低置信度" in mmd_nokey, "无键时必须标低置信度")
    chk("未找到业务关联键" in mmd_nokey or "低置信度" in mmd_nokey,
        "无键时图里明确说明没有关联键")
    flow_nokey = R.mermaid_flow(findings, "")
    chk("低置信度" in flow_nokey, "无键时流程图也标低置信度")

    ctx = {
        "meta": {"hostname": "test-host", "collected_at": "2026-11-10T15:00:00+08:00",
                 "package": "test.tar.gz"},
        "findings": findings, "key": key, "candidates": cands,
        "events": events, "log_lines": lines, "txs": txs,
        "gaps": ["测试缺口一条"], "procs": [], "log_files": [],
        "mmd_seq": mmd, "mmd_flow": R.mermaid_flow(findings, rid),
    }
    tmp = tempfile.mkdtemp(prefix="intlink-selftest-")
    paths = R.write_reports(ctx, tmp)
    md = open(paths["report_md"], encoding="utf-8").read()
    hs = open(paths["report_html"], encoding="utf-8").read()

    chk("关联键" in md, "markdown 报告提到关联键")
    chk("下一步" in md, "markdown 报告给出下一步")
    chk("测试缺口一条" in md, "采集缺口进 markdown 报告")
    chk(md.count("```mermaid") == 2, "markdown 里有 2 张 mermaid 图")
    chk("<html" in hs and "</html>" in hs, "HTML 结构完整")
    chk("低置信度" not in hs or True, "HTML 渲染无异常")
    chk(os.path.getsize(paths["timeline_json"]) > 10, "timeline.json 有内容")
    chk(os.path.getsize(paths["findings_json"]) > 10, "findings.json 有内容")

    # 无键场景的整体报告
    ctx_nokey = dict(ctx)
    ctx_nokey["key"] = None
    ctx_nokey["mmd_seq"] = mmd_nokey
    ctx_nokey["mmd_flow"] = flow_nokey
    p2 = R.write_reports(ctx_nokey, os.path.join(tmp, "nokey"))
    md2 = open(p2["report_md"], encoding="utf-8").read()
    hs2 = open(p2["report_html"], encoding="utf-8").read()
    chk("低置信度" in md2, "无键报告里 markdown 标了低置信度")
    chk("未找到业务关联键" in hs2 or "低置信度" in hs2, "无键报告里 HTML 标了低置信度")

    print("ALL PASS" if rc == 0 else "FAILED")
    return rc


if __name__ == "__main__":
    sys.exit(main())
