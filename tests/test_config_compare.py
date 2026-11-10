"""有效配置对照的测试。

重点不是「能不能比」，而是「不该下结论时有没有闭嘴」：
  - 配置值没写单位 → 必须 unknown，不能瞎猜秒/毫秒
  - 抓包窗口内没有失败样本 → 必须 unknown，不能说「配置正确」
  - 没有业务键 → 不能数重试
  - 抓包量不出来的项（线程池深度等）→ unobservable，不判定
真正有价值的正例是「配置写 30s，实测 3s 断开」这种 mismatch。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intlink_doctor import config_compare as CC
from intlink_doctor.pcap_http import Transaction, HttpMessage

rc = 0


def chk(cond, msg):
    global rc
    if cond:
        print("  PASS %s" % msg)
    else:
        print("  FAIL %s" % msg)
        rc = 1


def item(key, raw, kind="duration", value_ms=None, unit_src="ms", **kw):
    return CC.ConfigItem(pid="1", key=key, raw=raw, kind=kind,
                         value_ms=value_ms, unit_src=unit_src, **kw)


def mk_tx(server=("10.0.0.2", 80), req_t=1000.0, resp_t=None,
          has_resp=True, err="", path="/api"):
    tx = Transaction(stream_key=(("10.0.0.1", 1000), server),
                     client=("10.0.0.1", 1000), server=server,
                     t_request=req_t, t_response=resp_t if resp_t else req_t)
    tx.request = HttpMessage(kind="request", start_line="POST %s HTTP/1.1" % path,
                             method="POST", path=path, version="HTTP/1.1",
                             raw_head=b"POST / HTTP/1.1\r\n\r\n", body=b'{}')
    if has_resp:
        tx.response = HttpMessage(kind="response", start_line="HTTP/1.1 200 OK",
                                  status=200, reason="OK", body=b"{}")
        tx.t_response = resp_t if resp_t else req_t + 0.05
    else:
        tx.t_response = resp_t if resp_t else req_t + 3.0
    tx.error = err
    return tx


def test_timeout_mismatch_is_detected():
    """配置 30s，实测 3s 断开 → 必须报 mismatch，并给可执行方向。"""
    it = item("push.timeout", "30s", value_ms=30000, unit_src="ms")
    txs = [mk_tx(req_t=1000.0, resp_t=1003.0, has_resp=False,
                 err="无响应（请求已发出但没收到响应）")]
    comps = CC.compare([it], txs)
    c = [x for x in comps if "timeout" in x.item.name][0]
    chk(c.verdict == "mismatch", "30s 配置 vs 3s 实测 → mismatch（实际 %s）" % c.verdict)
    chk("没生效" in c.detail or "覆盖" in c.detail,
        "结论指出配置可能未生效/被覆盖")
    chk(c.confidence == "high", "该结论置信度高")
    print("    实测: %s" % c.observed_desc)


def test_timeout_match_is_detected():
    """配置 3s，实测 3s 断开 → match，不能说「配置错了」。"""
    it = item("push.timeout", "3000ms", value_ms=3000)
    txs = [mk_tx(req_t=1000.0, resp_t=1003.0, has_resp=False)]
    c = [x for x in CC.compare([it], txs) if "timeout" in x.item.name][0]
    chk(c.verdict == "match", "3s 配置 vs 3s 实测 → match（实际 %s）" % c.verdict)


def test_no_unit_must_be_unknown():
    """配置写 timeout: 30 没单位 → 必须 unknown，不许猜。"""
    it = item("push.timeout", "30", kind="number", value_ms=30, unit_src="unitless")
    txs = [mk_tx(resp_t=1003.0, has_resp=False)]
    c = [x for x in CC.compare([it], txs) if "timeout" in x.item.name][0]
    chk(c.verdict == "unknown", "无单位配置 → unknown（实际 %s）" % c.verdict)
    chk("单位" in c.detail, "说明了是因为单位不确定: %s" % c.detail[:60])


def test_no_failure_sample_must_be_unknown():
    """窗口里全是成功请求，量不到超时 → 不能说配置对。"""
    it = item("push.timeout", "30s", value_ms=30000)
    txs = [mk_tx(resp_t=1000.05, has_resp=True)]   # 有响应
    c = [x for x in CC.compare([it], txs) if "timeout" in x.item.name][0]
    chk(c.verdict == "unknown", "无失败样本 → unknown（实际 %s）" % c.verdict)
    chk("没触发" in c.detail or "窗口内" in c.observed_desc,
        "说明了是因为窗口内没触发")


def test_no_keys_cannot_count_retries():
    """没有业务键时不能数重试。"""
    it = item("push.retry", "3", kind="number", value_ms=None, unit_src="none")
    txs = [mk_tx() for _ in range(3)]
    c = [x for x in CC.compare([it], txs, key_vals=None) if "retry" in x.item.name][0]
    chk(c.verdict == "unknown", "无键 → 重试判定为 unknown（实际 %s）" % c.verdict)
    chk("键" in c.detail or "键" in c.observed_desc, "说明了缺关联键")


def test_retry_mismatch_with_keys():
    """有键且同一业务出现多次、超过配置 → mismatch。"""
    it = item("push.retry", "1", kind="number", value_ms=None, unit_src="none")
    rid = "aaaa-bbbb-cccc"
    txs = []
    for i in range(3):
        tx = mk_tx(req_t=1000.0 + i)
        tx.request.body = ('{"requestId":"%s"}' % rid).encode()
        txs.append(tx)
    c = [x for x in CC.compare([it], txs, key_vals=[rid]) if "retry" in x.item.name][0]
    chk(c.verdict == "mismatch", "重试超限 → mismatch（实际 %s）" % c.verdict)
    chk(c.observed == 2, "观测到 2 次重试（实际 %s）" % c.observed)


def test_unobservable_items_not_judged():
    """抓包量不出来的项（如日志级别）只列出，不下结论。"""
    it = item("logging.level", "info", kind="other", value_ms=None, unit_src="none")
    c = CC.compare([it], [mk_tx()])[0]
    chk(c.verdict == "unobservable", "不可观测项 → unobservable（实际 %s）" % c.verdict)


def test_pool_peak_measured():
    """并发峰值能算出来；超上限时报 mismatch 但置信度低（窗口有限）。"""
    it = item("pool.max_connections", "2", kind="number", value_ms=None, unit_src="none")
    txs = [mk_tx(req_t=1000.0 + i * 0.1, resp_t=1000.5) for i in range(5)]
    c = [x for x in CC.compare([it], txs) if "pool" in x.item.full_name][0]
    chk(c.observed >= 1, "算出了并发峰值 %s" % c.observed)
    chk(c.confidence == "low", "并发结论置信度低（抓包窗口有限）")


def test_endpoint_match_against_capture():
    """配置声明的对端端口，和抓包里实际连的端口对照。"""
    it = item("push.endpoint", "http://10.0.0.2:18099/x", kind="endpoint",
              value_ms=None, unit_src="", host="10.0.0.2", port=18099)
    txs = [mk_tx(server=("10.0.0.2", 18099))]
    c = [x for x in CC.compare([it], txs) if x.item.kind == "endpoint"][0]
    chk(c.verdict == "match", "配置端口与实际连接一致 → match（实际 %s）" % c.verdict)


def test_parse_duration_units():
    """单位归一：s/ms/m 都要对上，无单位必须标 unitless。"""
    cases = [
        ("30s", 30000, "ms"), ("5000ms", 5000, "ms"), ("2m", 120000, "ms"),
        ("1h", 3600000, "ms"), ("30", 30, "unitless"),
    ]
    for raw, want_ms, want_src in cases:
        got = CC.parse_duration_ms(raw)
        chk(got == (want_ms, want_src),
            "parse_duration_ms(%r) = %s (期望 %s)" % (raw, got, (want_ms, want_src)))
    chk(CC.parse_duration_ms("abc") is None, "非时长返回 None")


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        print("== %s ==" % t.__name__)
        try:
            t()
        except AssertionError as e:
            print("  FAIL %s" % e)
            global rc
            rc = 1
        except Exception as e:
            print("  ERROR %s: %s" % (type(e).__name__, e))
            rc = 1
    print("ALL PASS" if rc == 0 else "FAILED")
    return rc


if __name__ == "__main__":
    sys.exit(main())
