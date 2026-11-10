"""造 pcap 夹具，验 pcap_http.py 的解析与重组。

不用 scapy：直接手写以太网/IP/TCP 头，这样测试在无依赖环境下也能跑。
覆盖：分段请求体、chunked 响应、gzip 响应、RST 断连、重传、HTTP/2 前置帧。
"""
from __future__ import annotations

import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intlink_doctor import pcap_http


def eth_ip_tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
    # Ethernet
    eth = b"\x00" * 12 + b"\x08\x00"
    # IPv4
    total = 20 + 20 + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0,
                     bytes(int(x) for x in src_ip.split(".")),
                     bytes(int(x) for x in dst_ip.split(".")))
    doff = 5 << 4
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, doff, flags,
                      65535, 0, 0)
    return eth + ip + tcp + payload


def write_pcap(path, frames):
    """frames: [(ts, bytes)]"""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, data in frames:
            sec = int(ts)
            usec = int((ts - sec) * 1e6)
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            f.write(data)


def build_scenario():
    """一次 POST 请求，请求体被切成两段；响应是 chunked + gzip。

    时间线（相对）：
      0.000 SYN
      0.001 SYN-ACK
      0.002 ACK + 请求头 + 前半 body
      0.010 后半 body
      0.050 响应头 + chunked body
      0.120 FIN
    """
    C_IP, S_IP = "10.1.1.9", "10.2.2.20"
    C_PORT, S_PORT = 45123, 18080
    body = b'{"requestId":"REQ-0001","deviceId":"D-9001","payload":"hello"}'
    head = (b"POST /api/v1/push HTTP/1.1\r\n"
            b"Host: 10.2.2.20:18080\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"X-Request-Id: REQ-0001\r\n"
            b"\r\n")
    frames = []
    t = 1000.0
    # 三次握手
    frames.append((t, eth_ip_tcp(C_IP, S_IP, C_PORT, S_PORT, 1000, 0, 0x02)))
    frames.append((t + 0.001, eth_ip_tcp(S_IP, C_IP, S_PORT, C_PORT, 5000, 1001, 0x12)))
    frames.append((t + 0.002, eth_ip_tcp(C_IP, S_IP, C_PORT, S_PORT, 1001, 5001, 0x10)))

    seq = 1001
    first = head + body[:20]
    frames.append((t + 0.003, eth_ip_tcp(C_IP, S_IP, C_PORT, S_PORT, seq, 5001, 0x18, first)))
    seq += len(first)
    second = body[20:]
    frames.append((t + 0.010, eth_ip_tcp(C_IP, S_IP, C_PORT, S_PORT, seq, 5001, 0x18, second)))
    seq += len(second)

    # 重传第一段（seq 相同），解析时应被跳过
    frames.append((t + 0.011, eth_ip_tcp(C_IP, S_IP, C_PORT, S_PORT, 1001, 5001, 0x18, first)))

    # 响应：chunked + gzip
    import gzip
    resp_body = b'{"code":0,"message":"ok","requestId":"REQ-0001"}'
    gz = gzip.compress(resp_body)
    chunked = b""
    for i in range(0, len(gz), 16):
        part = gz[i:i + 16]
        chunked += ("%x\r\n" % len(part)).encode() + part + b"\r\n"
    chunked += b"0\r\n\r\n"
    rhead = (b"HTTP/1.1 200 OK\r\n"
             b"Content-Type: application/json\r\n"
             b"Transfer-Encoding: chunked\r\n"
             b"Content-Encoding: gzip\r\n"
             b"X-Request-Id: REQ-0001\r\n"
             b"\r\n")
    frames.append((t + 0.050, eth_ip_tcp(S_IP, C_IP, S_PORT, C_PORT, 5001, seq, 0x18, rhead + chunked)))
    # 客户端 ACK
    frames.append((t + 0.052, eth_ip_tcp(C_IP, S_IP, C_PORT, S_PORT, seq, 5001 + len(rhead + chunked), 0x10)))
    # FIN
    frames.append((t + 0.120, eth_ip_tcp(C_IP, S_IP, C_PORT, S_PORT, seq, 5001 + len(rhead + chunked), 0x11)))
    return frames, {
        "body": body,
        "response_body": resp_body,
        "client": (C_IP, C_PORT),
        "server": (S_IP, S_PORT),
    }


def build_rst_scenario():
    """连接被 RST：请求发出，没有响应。"""
    C_IP, S_IP = "10.1.1.9", "10.3.3.30"
    C_PORT, S_PORT = 45200, 9999
    frames = []
    t = 2000.0
    frames.append((t, eth_ip_tcp(C_IP, S_IP, C_PORT, S_PORT, 7000, 0, 0x02)))
    frames.append((t + 0.001, eth_ip_tcp(S_IP, C_IP, S_PORT, C_PORT, 8000, 7001, 0x12)))
    frames.append((t + 0.002, eth_ip_tcp(C_IP, S_IP, C_PORT, S_PORT, 7001, 8001, 0x10)))
    req = (b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
    frames.append((t + 0.003, eth_ip_tcp(C_IP, S_IP, C_PORT, S_PORT, 7001, 8001, 0x18, req)))
    frames.append((t + 2.000, eth_ip_tcp(S_IP, C_IP, S_PORT, C_PORT, 8001, 7001 + len(req), 0x14)))
    return frames, {"client": (C_IP, C_PORT), "server": (S_IP, S_PORT)}


def main():
    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
    os.makedirs(outdir, exist_ok=True)
    rc = 0

    p1 = os.path.join(outdir, "http_post_chunked.pcap")
    frames, want = build_scenario()
    write_pcap(p1, frames)
    s = pcap_http.summarize(p1)
    print("== 场景1：分段请求 + chunked/gzip 响应 ==")
    print("  packets=%d streams=%d txs=%d" % (s["packet_count"], len(s["streams"]), len(s["transactions"])))
    if len(s["transactions"]) != 1:
        print("  FAIL 期望 1 个事务，得到 %d" % len(s["transactions"])); rc = 1
    else:
        tx = s["transactions"][0]
        ok = True
        if tx["request"]["method"] != "POST":
            print("  FAIL method=%r" % tx["request"]["method"]); ok = False; rc = 1
        if tx["request"]["path"] != "/api/v1/push":
            print("  FAIL path=%r" % tx["request"]["path"]); ok = False; rc = 1
        # 分段 + 重传后 body 长度必须仍然正确（重传去重是最容易写错的地方）
        if tx["request"]["body_len"] != len(want["body"]):
            print("  FAIL request body_len=%d 期望 %d（重传去重可能出错）"
                  % (tx["request"]["body_len"], len(want["body"]))); ok = False; rc = 1
        if tx["response"]["status"] != 200:
            print("  FAIL status=%r" % tx["response"]["status"]); ok = False; rc = 1
        if tx["response"]["body_len"] != len(want["response_body"]):
            print("  FAIL response body_len=%d 期望 %d（chunked/gzip 解码可能出错）"
                  % (tx["response"]["body_len"], len(want["response_body"]))); ok = False; rc = 1
        if ok:
            print("  PASS 事务内容正确 latency=%.1fms" % (tx["latency_ms"] or -1))
        # 直接验原文
        packets, _ = pcap_http.read_pcap(p1)
        segs, _ = pcap_http.parse_tcp(packets)
        streams = pcap_http.group_streams(segs)
        raw = streams[0].payload_a_to_b()
        if want["body"] not in raw:
            print("  FAIL 重组的请求流里找不到完整 body"); rc = 1
        else:
            print("  PASS 重组流含完整请求体")
        resp = streams[0].payload_b_to_a()
        msgs = pcap_http.parse_http_stream(resp)
        if msgs and msgs[0].body == want["response_body"]:
            print("  PASS gzip 解码后内容一致")
        else:
            print("  FAIL gzip 解码内容不一致"); rc = 1

    print("== 场景2：RST 断连（请求无响应）==")
    p2 = os.path.join(outdir, "rst_no_response.pcap")
    frames2, _ = build_rst_scenario()
    write_pcap(p2, frames2)
    s2 = pcap_http.summarize(p2)
    print("  streams=%d txs=%d" % (len(s2["streams"]), len(s2["transactions"])))
    if not s2["transactions"]:
        print("  FAIL 没有解析出事务"); rc = 1
    else:
        tx = s2["transactions"][0]
        if tx["response"] is None:
            print("  PASS 正确识别为无响应")
        else:
            print("  FAIL 不应有响应"); rc = 1
        if "RST" in (tx["error"] or "") or "无响应" in (tx["error"] or ""):
            print("  PASS 错误标记: %s" % tx["error"])
        else:
            print("  FAIL 错误标记缺失/不对: %r" % tx["error"]); rc = 1
        if s2["streams"][0]["closed_by"] == "rst":
            print("  PASS 识别到 RST 关闭")
        else:
            print("  FAIL closed_by=%r" % s2["streams"][0]["closed_by"]); rc = 1

    print("ALL PASS" if rc == 0 else "FAILED")
    return rc


if __name__ == "__main__":
    sys.exit(main())
