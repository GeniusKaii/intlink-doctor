"""关联引擎的测试：重点验「有关联键」和「没关联键」两条路径必须出不同结论。

这是本工具的核心承诺：没键时不许画成看起来像完整调用链的东西。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intlink_doctor import correlate as C


def mk_lines(texts, offset=8.0):
    return C.load_log_lines([("test.log", t) for t in texts], offset)


def test_key_detection_with_real_key():
    """日志和报文里都有同一个 requestId → 必须被认成强关联键。"""
    rid = "a3f5c9e2-7b14-4d8a-9c11-0e2f4b6d8a91"
    log = mk_lines([
        "2026-11-10 15:00:00,100 INFO push start requestId=%s" % rid,
        "2026-11-10 15:00:00,150 INFO got response requestId=%s status=200" % rid,
    ])
    cands = {}
    for l in log:
        C.extract_candidates_from_text(l.raw, "test.log", cands)
    blobs = [("tx0", b'{"requestId":"%s","x":1}' % rid.encode())]
    C.score_against_pcap(cands, blobs)
    key = C.pick_key(cands)
    assert key is not None, "有真键时必须识别出来"
    assert key.value == rid, "选错键: %s" % key.value
    assert key.score >= 0.5, "置信度太低: %s" % key.score
    print("  PASS 有真键 → 识别为强键 score=%.3f kind=%s" % (key.score, key.kind))


def test_no_key_in_pcap():
    """日志里的 ID 在抓包里搜不到 → 不能当关联键。"""
    rid = "b9c8d7e6-1234-4abc-8def-001122334455"
    log = mk_lines(["2026-11-10 15:00:00,100 INFO requestId=%s" % rid])
    cands = {}
    for l in log:
        C.extract_candidates_from_text(l.raw, "test.log", cands)
    # 抓包里是另一个 ID
    C.score_against_pcap(cands, [("tx0", b'{"requestId":"zzzz-not-the-same"}')])
    key = C.pick_key(cands)
    assert key is None, "抓包里搜不到就不该当选关联键，却选出了 %s" % (key.value if key else None)
    print("  PASS 键不在抓包里 → 拒绝，返回 None（低置信度）")


def test_no_pcap_at_all():
    """完全没有抓包 → 必须返回 None，不能凭日志猜。"""
    log = mk_lines(["2026-11-10 15:00:00,100 INFO requestId=abcdef123456"])
    cands = {}
    for l in log:
        C.extract_candidates_from_text(l.raw, "test.log", cands)
    C.score_against_pcap(cands, [])
    key = C.pick_key(cands)
    assert key is None, "没有抓包却选出了关联键"
    print("  PASS 无抓包 → 拒绝高置信度关联")


def test_timestamp_as_id_should_be_rejected():
    """日志里的 13 位时间戳不能被当成业务关联键。"""
    cands = {}
    C.extract_candidates_from_text(
        "2026-11-10 15:00:00 INFO ts=1762758000000 seq=1762758000001", "t.log", cands)
    # 即便抓包里恰好也出现这个数（报文里常有时间戳），也不能当键
    C.score_against_pcap(cands, [("tx0", b'{"ts":1762758000000}')])
    key = C.pick_key(cands)
    assert key is None or not key.value.startswith("17627"), \
        "时间戳被误当成业务关联键: %s" % (key.value if key else None)
    print("  PASS 13 位 epoch 时间戳未被视为业务键")


def test_timeline_filters_by_key():
    """给定了键，时间线里只能出现含该键的日志行和事务。"""
    rid = "c1c2c3c4-d5d6-4e7f-8a9b-0c1d2e3f4a5b"
    log = mk_lines([
        "2026-11-10 15:00:00,100 INFO requestId=%s step=1" % rid,
        "2026-11-10 15:00:00,200 INFO requestId=OTHER-000000 step=1",
    ])
    events = C.build_timeline(log, [], key_value=rid)
    labels = " ".join(e.label for e in events)
    assert rid in labels, "含键的行应保留"
    assert "OTHER-000000" not in labels, "不含键的行不该进键过滤后的时间线"
    print("  PASS 按关联键过滤时间线")


def test_timeline_empty_key_keeps_all():
    """没有键时保留全部，但调用方必须标低置信度（此函数只负责保留）。"""
    log = mk_lines([
        "2026-11-10 15:00:00,100 INFO a",
        "2026-11-10 15:00:00,200 INFO b",
    ])
    events = C.build_timeline(log, [], key_value="")
    assert len(events) == 2, "无键时应保留全部行，得到 %d" % len(events)
    print("  PASS 无键时保留全部事件")


def test_diagnose_flags_missing_response():
    """请求无响应必须被诊断出来，且给出明确下一步。"""
    log = mk_lines(["2026-11-10 15:00:00,100 ERROR push failed timeout"])
    ev = [C.TimelineEvent(0, "request", "x")]
    # 造一个无响应事务
    tx = C.TimelineEvent(0, "request", "x")
    from intlink_doctor.pcap_http import Transaction, HttpMessage
    t = Transaction(stream_key=(("10.0.0.1", 1234), ("10.0.0.2", 80)),
                    client=("10.0.0.1", 1234), server=("10.0.0.2", 80),
                    t_request=1762758000.0, t_response=1762758002.0,
                    error="无响应（请求已发出但没收到响应）")
    t.request = HttpMessage(kind="request", start_line="POST /x HTTP/1.1",
                            method="POST", path="/x", version="HTTP/1.1")
    findings = C.diagnose(log, [t], {}, None, [])
    titles = " ".join(f.title for f in findings)
    assert "没有收到响应" in titles, "没诊断出无响应: %s" % titles
    noresp = [f for f in findings if "没有收到响应" in f.title][0]
    assert noresp.next_step, "没给下一步"
    assert noresp.evidence, "没给证据"
    print("  PASS 无响应被诊断，且带证据和下一步")


def test_diagnose_empty_pcap():
    findings = C.diagnose([], [], {}, None, [])
    titles = " ".join(f.title for f in findings)
    assert "没有可解析的业务事务" in titles, titles
    print("  PASS 空抓包被明确标为证据不足")


def test_diagnose_unparseable_timestamps():
    log = mk_lines(["this line has no timestamp at all", "neither does this one"])
    findings = C.diagnose(log, [], {}, None, [])
    titles = " ".join(f.title for f in findings)
    assert "解析不出时间戳" in titles, "时间戳解析失败必须明说，不能默默对齐: %s" % titles
    print("  PASS 时间戳无法解析时明确标注")


def test_gap_reported():
    findings = C.diagnose([], [], {}, None, ["非 root 且无免密 sudo，无法抓包"])
    titles = " ".join(f.title for f in findings)
    assert "无法完成" in titles, titles
    print("  PASS 采集缺口进结论")


def test_failure_detection_no_false_positive():
    """成功日志里的 UUID/数字片段不能被误判成失败。

    真实踩过的坑：FAIL_RE 里裸写 500|502|503|504，UUID 尾巴 ...5b2cb2500
    被当成 HTTP 500，把「push ok」标成失败，报告里凭空多出假告警。
    """
    no_fail = [
        "2026-11-10 15:43:49,204 [INFO ] push ok seq=16 requestId=dae71a62-1a91-4504-9847-5b2cb25",
        "2026-11-10 15:00:00,000 [INFO ] push ok seq=3 requestId=5b2cb2500",
        "2026-11-10 15:00:00,000 [INFO ] order 500 created",       # 业务数字
        "2026-11-10 15:00:00,000 [INFO ] all good",
        "2026-11-10 15:00:00,000 [INFO ] id=1234500 done",
        "2026-11-10 15:00:00,000 [INFO ] 用户5001 登录成功",
    ]
    for ln in no_fail:
        assert not C.is_failure_line(ln), "误报为失败: %s" % ln[:70]
    print("  PASS 成功日志不被误判为失败（%d 例）" % len(no_fail))


def test_failure_detection_no_false_negative():
    """真失败必须报出来，尤其 INFO 级别里带错误码的。"""
    must_fail = [
        "2026-11-10 15:00:00,000 [ERROR] push failed err=timeout",
        "2026-11-10 15:00:00,000 [INFO ] resp status=500",          # INFO 但明确 500
        "2026-11-10 15:00:00,000 [WARN ] got HTTP 503 from peer",
        "2026-11-10 15:00:00,000 [INFO ] Connection refused to peer",
        "2026-11-10 15:00:00,000 [DEBUG] retrying attempt 2",
        "2026-11-10 15:00:00,000 [WARN ] read timed out after 30s",
    ]
    for ln in must_fail:
        assert C.is_failure_line(ln), "漏报失败: %s" % ln[:70]
    print("  PASS 真失败不被漏判（%d 例，含 INFO 带错误码）" % len(must_fail))


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    rc = 0
    for t in tests:
        print("== %s ==" % t.__name__)
        try:
            t()
        except AssertionError as e:
            print("  FAIL %s" % e)
            rc = 1
        except Exception as e:
            print("  ERROR %s: %s" % (type(e).__name__, e))
            rc = 1
    print("ALL PASS" if rc == 0 else "FAILED")
    return rc


if __name__ == "__main__":
    sys.exit(main())
