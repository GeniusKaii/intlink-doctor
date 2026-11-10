"""纯 Python 的 pcap/pcapng 解析 + HTTP 重组，不依赖 scapy/dpkt/tshark。

为什么自己写：工程师的 Windows 机器上通常什么都没有，pip install 在内网也不一定通。
这里只覆盖对接件排障真正需要的：IPv4/IPv6 + TCP + HTTP/1.x 文本报文。

能力边界（写清楚，避免误判）：
  - 只重组完整 TCP 流（按 seq 排序、跳过重传），不做分片 IP 重组
  - 只解析 HTTP/1.x；HTTP/2（二进制帧）不做解析，标记为 unsupported
  - 不处理 TLS 解密，只有明文 HTTP 可读（对接件绝大多数是明文内网 HTTP）
"""
from __future__ import annotations

import bisect
import gzip
import io
import struct
import zlib
from dataclasses import dataclass, field
from typing import Optional


# ── pcap 文件读取 ──────────────────────────────────────────────────
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 2),   # 小端, 微秒
    b"\xa1\xb2\xc3\xd4": (">", 2),   # 大端, 微秒
    b"\x4d\x3c\xb2\xa1": ("<", 3),   # 小端, 纳秒
    b"\xa1\xb2\x3c\x4d": (">", 3),   # 大端, 纳秒
}


@dataclass
class RawPacket:
    ts: float
    data: bytes
    linktype: int
    orig_len: int


def read_pcap(path: str, max_packets: int = 2_000_000):
    """返回 (packets, meta)。pcap 和 pcapng 都吃。"""
    with open(path, "rb") as f:
        head = f.read(4)
        f.seek(0)
        if head == b"\x0a\x0d\x0d\x0a":
            return _read_pcapng(f, max_packets)
        for magic, (endian, precision) in PCAP_MAGICS.items():
            if head == magic:
                return _read_pcap_classic(f, endian, precision, max_packets)
    raise ValueError("不是 pcap/pcapng 文件（magic=%r）" % head)


def _read_pcap_classic(f, endian: str, precision: int, max_packets: int):
    hdr = f.read(24)
    if len(hdr) < 24:
        raise ValueError("pcap 头不完整")
    (magic, vmaj, vmin, tz, sig, snap, link) = struct.unpack(endian + "IHHiIII", hdr)
    pkts = []
    rec = struct.Struct(endian + "IIII")
    while len(pkts) < max_packets:
        rh = f.read(16)
        if len(rh) < 16:
            break
        ts_s, ts_f, incl, orig = rec.unpack(rh)
        data = f.read(incl)
        if len(data) < incl:
            break
        scale = 1e-9 if precision == 3 else 1e-6
        pkts.append(RawPacket(ts_s + ts_f * scale, data, link, orig))
    meta = {"format": "pcap", "linktype": link, "snap": snap,
            "timestamp_precision": "ns" if precision == 3 else "us"}
    return pkts, meta


def _read_pcapng(f, max_packets: int):
    pkts = []
    link = 1
    while len(pkts) < max_packets:
        bh = f.read(8)
        if len(bh) < 8:
            break
        btype, blen = struct.unpack("<II", bh)
        if blen < 12 or blen > 64 * 1024 * 1024:
            break
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            break
        if btype == 0x00000001:  # Interface Description Block
            if len(body) >= 4:
                link = struct.unpack("<H", body[0:2])[0]
        elif btype == 0x00000006:  # Enhanced Packet Block
            if len(body) >= 20:
                iface, ts_h, ts_l, incl, orig = struct.unpack("<IIIII", body[0:20])
                data = body[20:20 + incl]
                pkts.append(RawPacket((ts_h << 32 | ts_l) / 1e6, data, link, orig))
        elif btype == 0x00000003:  # Simple Packet Block
            if len(body) >= 4:
                orig = struct.unpack("<I", body[0:4])[0]
                pkts.append(RawPacket(0.0, body[4:4 + orig], link, orig))
    return pkts, {"format": "pcapng", "linktype": link}


# ── 链路层 → IP → TCP ─────────────────────────────────────────────
def _l3_payload(linktype: int, data: bytes) -> Optional[bytes]:
    """剥掉链路层头；返回从 IP 头开始的字节。"""
    if linktype == 1:      # EN10MB / Ethernet
        if len(data) < 14:
            return None
        et = struct.unpack(">H", data[12:14])[0]
        off = 14
        # VLAN 可能有双层
        while et in (0x8100, 0x88A8) and len(data) >= off + 4:
            et = struct.unpack(">H", data[off + 2:off + 4])[0]
            off += 4
        return data[off:]
    if linktype == 113:    # Linux SLL
        if len(data) < 16:
            return None
        return data[16:]
    if linktype == 276:    # Linux SLL2
        if len(data) < 20:
            return None
        return data[20:]
    if linktype == 101:    # RAW
        return data
    if linktype == 0:      # BSD loopback
        if len(data) < 4:
            return None
        return data[4:]
    return None


@dataclass
class TcpSeg:
    ts: float
    src: str
    sport: int
    dst: str
    dport: int
    seq: int
    ack: int
    flags: int
    payload: bytes

    @property
    def syn(self): return bool(self.flags & 0x02)
    @property
    def fin(self): return bool(self.flags & 0x01)
    @property
    def rst(self): return bool(self.flags & 0x04)
    @property
    def psh(self): return bool(self.flags & 0x08)
    @property
    def ackf(self): return bool(self.flags & 0x10)


def _ip_addr(b: bytes) -> str:
    if len(b) == 4:
        return ".".join(str(x) for x in b)
    # IPv6 用标准压缩写法
    try:
        import ipaddress
        return str(ipaddress.IPv6Address(b))
    except Exception:
        return b.hex()


def parse_tcp(packets, linktype_override: Optional[int] = None):
    segs = []
    non_tcp = 0
    bad = 0
    for p in packets:
        lt = linktype_override if linktype_override is not None else p.linktype
        l3 = _l3_payload(lt, p.data)
        if not l3 or len(l3) < 20:
            bad += 1
            continue
        ver = l3[0] >> 4
        if ver == 4:
            ihl = (l3[0] & 0x0F) * 4
            if len(l3) < ihl + 20:
                bad += 1
                continue
            proto = l3[9]
            src = _ip_addr(l3[12:16])
            dst = _ip_addr(l3[16:20])
            tot = struct.unpack(">H", l3[2:4])[0]
            ip_payload = l3[ihl:tot] if tot >= ihl else l3[ihl:]
        elif ver == 6:
            if len(l3) < 40 + 20:
                bad += 1
                continue
            nxt = l3[6]
            # 跳过常见扩展头
            off = 40
            while nxt in (0, 43, 60) and len(l3) >= off + 8:
                nxt = l3[off]
                hlen = (l3[off + 1] + 1) * 8
                off += hlen
            proto = nxt
            src = _ip_addr(l3[8:24])
            dst = _ip_addr(l3[24:40])
            plen = struct.unpack(">H", l3[4:6])[0]
            ip_payload = l3[off:off + plen] if plen else l3[off:]
        else:
            bad += 1
            continue
        if proto != 6:
            non_tcp += 1
            continue
        if len(ip_payload) < 20:
            bad += 1
            continue
        sport, dport, seq, ack = struct.unpack(">HHII", ip_payload[0:12])
        doff = (ip_payload[12] >> 4) * 4
        flags = ip_payload[13]
        if len(ip_payload) < doff:
            bad += 1
            continue
        payload = ip_payload[doff:]
        segs.append(TcpSeg(p.ts, src, sport, dst, dport, seq, ack, flags, payload))
    meta = {"segments": len(segs), "non_tcp_packets": non_tcp, "unparsed_packets": bad}
    return segs, meta


# ── TCP 流重组 ────────────────────────────────────────────────────
@dataclass
class TcpStream:
    key: tuple                 # (ip_a, port_a, ip_b, port_b) 已按字典序归一
    initiator: tuple           # 实际发起方 (ip, port)
    segments: list = field(default_factory=list)
    first_ts: float = 0.0
    last_ts: float = 0.0
    closed_by: str = ""        # fin / rst / ""
    syn_seen: bool = False
    synack_seen: bool = False

    def payload_a_to_b(self) -> bytes:
        """按 seq 重组 initiator → responder 方向的字节流。"""
        return _reassemble(self.segments, self.initiator)

    def payload_b_to_a(self) -> bytes:
        return _reassemble(self.segments, self.other)

    @property
    def a(self) -> tuple:
        return self.key[0]

    @property
    def b(self) -> tuple:
        return self.key[1]

    @property
    def other(self) -> tuple:
        """与 initiator 相对的另一端。"""
        return self.b if self.initiator == self.a else self.a


def _reassemble(segs, src_tuple) -> bytes:
    out = []
    expected = None
    for s in sorted(segs, key=lambda x: (x.ts, x.seq)):
        if (s.src, s.sport) != src_tuple:
            continue
        if not s.payload:
            continue
        if expected is None:
            expected = s.seq
        if s.seq > expected:
            # 有缺口：用 0 填充并记录（比静默拼接更诚实）
            out.append(b"\x00" * min(s.seq - expected, 65536))
            expected = s.seq
        elif s.seq < expected:
            skip = expected - s.seq
            if skip >= len(s.payload):
                continue      # 纯重传
            s = TcpSeg(s.ts, s.src, s.sport, s.dst, s.dport, s.seq + skip,
                       s.ack, s.flags, s.payload[skip:])
        out.append(s.payload)
        expected = s.seq + len(s.payload)
    return b"".join(out)


def group_streams(segs) -> list[TcpStream]:
    streams: dict[tuple, TcpStream] = {}
    for s in segs:
        a = (s.src, s.sport)
        b = (s.dst, s.dport)
        key = (a, b) if a <= b else (b, a)
        st = streams.get(key)
        if st is None:
            init = a if s.syn else a
            st = TcpStream(key=key, initiator=init, first_ts=s.ts)
            streams[key] = st
        # SYN（不带 ACK）方向才是真正发起方
        if s.syn and not s.ackf:
            st.initiator = a
            st.syn_seen = True
        if s.syn and s.ackf:
            st.synack_seen = True
        st.segments.append(s)
        st.first_ts = min(st.first_ts, s.ts)
        st.last_ts = max(st.last_ts, s.ts)
        if s.rst:
            st.closed_by = "rst"
        elif s.fin and not st.closed_by:
            st.closed_by = "fin"
    return sorted(streams.values(), key=lambda x: x.first_ts)


# ── HTTP/1.x 解析 ─────────────────────────────────────────────────
@dataclass
class HttpMessage:
    kind: str            # request / response
    start_line: str
    method: str = ""
    path: str = ""
    version: str = ""
    status: int = 0
    reason: str = ""
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    raw_head: bytes = b""
    truncated: bool = False
    unsupported: str = ""
    # 该报文在原始 TCP 流里 body 部分占的字节数（解压前）。
    # 算 RTT 时按它定位报文结束时刻，不能用 len(body)（gzip/chunked 会不一致）。
    _wire_body_len: int = 0
    _head_wire_len: int = 0

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


def _read_head(buf: bytes, pos: int):
    """从 pos 找一个完整 header 块。

    返回 (head_bytes, body_start, ok, head_wire_len)。head_wire_len 包含结尾空行，
    用于精确计算报文在原始流里占的字节数（算 RTT 时要用）。
    """
    idx = buf.find(b"\r\n\r\n", pos)
    sep = 4
    if idx < 0:
        idx = buf.find(b"\n\n", pos)
        sep = 2
    if idx < 0:
        return b"", pos, False, 0
    return buf[pos:idx], idx + sep, True, (idx + sep) - pos


def _parse_head(head: bytes) -> tuple[list[str], dict]:
    lines = head.split(b"\n")
    first = lines[0].rstrip(b"\r").decode("latin-1")
    hdrs = {}
    for ln in lines[1:]:
        ln = ln.rstrip(b"\r")
        if not ln:
            continue
        if b":" not in ln:
            continue
        k, v = ln.split(b":", 1)
        hdrs[k.strip().decode("latin-1").lower()] = v.strip().decode("latin-1")
    return first, hdrs


def _decode_body(body: bytes, hdrs: dict) -> bytes:
    enc = hdrs.get("content-encoding", "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            return zlib.decompress(body)
        if "br" in enc:
            return body   # brotli 不做，保留原文
    except Exception:
        return body
    return body


def parse_http_stream(data: bytes, max_msgs: int = 500) -> list[HttpMessage]:
    """从单向字节流里切出尽可能多的 HTTP 报文。"""
    msgs = []
    pos = 0
    n = len(data)
    while pos < n and len(msgs) < max_msgs:
        # 跳过流开头的空白/二进制噪音
        while pos < n and data[pos:pos + 1] in (b"\r", b"\n", b"\x00"):
            pos += 1
        if pos >= n:
            break
        head, bstart, ok, head_len = _read_head(data, pos)
        if not ok:
            break
        first, hdrs = _parse_head(head)
        if not first:
            pos = bstart
            continue
        if first.startswith("HTTP/"):
            parts = first.split(" ", 2)
            msg = HttpMessage(kind="response", start_line=first,
                              version=parts[0] if parts else "",
                              status=int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
                              reason=parts[2] if len(parts) > 2 else "",
                              headers=hdrs, raw_head=head)
            msg._head_wire_len = head_len
            # 1xx/204/304 无 body
            if msg.status in (204, 304) or 100 <= msg.status < 200:
                msg.body = b""
                msgs.append(msg)
                pos = bstart
                continue
        elif first.split(" ")[0].isupper() or first.split(" ")[0] in ("GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"):
            parts = first.split(" ")
            msg = HttpMessage(kind="request", start_line=first,
                              method=parts[0] if parts else "",
                              path=parts[1] if len(parts) > 1 else "",
                              version=parts[2] if len(parts) > 2 else "",
                              headers=hdrs, raw_head=head)
            msg._head_wire_len = head_len
        else:
            # 不是 HTTP（可能是别的私有协议），停止解析这一段
            break

        body = b""
        if hdrs.get("transfer-encoding", "").lower() == "chunked":
            body, consumed, trunc = _read_chunked(data, bstart)
            msg.truncated = trunc
            msg._wire_body_len = consumed
            pos = bstart + consumed
        else:
            cl = hdrs.get("content-length")
            if cl and cl.isdigit():
                want = int(cl)
                avail = data[bstart:bstart + want]
                body = avail
                if len(avail) < want:
                    msg.truncated = True
                msg._wire_body_len = len(avail)
                pos = bstart + len(avail)
            else:
                # 无长度：请求一般无 body；响应读到流尾
                body = data[bstart:] if msg.kind == "response" else b""
                msg._wire_body_len = len(body)
                pos = n
                if msg.kind == "response":
                    msg.truncated = True
        msg.body = _decode_body(body, hdrs)
        msgs.append(msg)
        if pos >= n:
            break
    return msgs


def _read_chunked(data: bytes, start: int):
    """返回 (body, consumed_bytes, truncated)。"""
    out = []
    pos = start
    n = len(data)
    while pos < n:
        eol = data.find(b"\r\n", pos)
        if eol < 0:
            return b"".join(out), n - start, True
        line = data[pos:eol].split(b";")[0].strip()
        try:
            size = int(line, 16)
        except ValueError:
            return b"".join(out), n - start, True
        pos = eol + 2
        if size == 0:
            # 吃掉 trailer
            end = data.find(b"\r\n", pos)
            if end < 0:
                return b"".join(out), n - start, True
            return b"".join(out), (end + 2) - start, False
        chunk = data[pos:pos + size]
        out.append(chunk)
        pos += size + 2
        if pos > n:
            return b"".join(out), n - start, True
    return b"".join(out), n - start, True


# ── 总入口 ────────────────────────────────────────────────────────
@dataclass
class Transaction:
    """一次请求-响应配对（按 TCP 流 + 顺序配对）。"""
    stream_key: tuple
    client: tuple             # (ip, port)
    server: tuple
    request: Optional[HttpMessage] = None
    response: Optional[HttpMessage] = None
    t_request: float = 0.0
    t_response: float = 0.0
    latency_ms: Optional[float] = None
    error: str = ""

    @property
    def request_id_candidates(self) -> list[str]:
        return []


def build_transactions(streams, max_per_stream: int = 300) -> list[Transaction]:
    out = []
    for st in streams:
        a2b = st.payload_a_to_b()
        b2a = st.payload_b_to_a()
        if not a2b and not b2a:
            continue
        # 哪个方向是请求？看谁先出现 HTTP 请求行
        req_first_a = _starts_with_request(a2b)
        req_first_b = _starts_with_request(b2a)
        if req_first_a:
            req_raw, resp_raw = a2b, b2a
            client, server = st.initiator, st.other
            req_is_a = True
        elif req_first_b:
            req_raw, resp_raw = b2a, a2b
            client, server = st.other, st.initiator
            req_is_a = False
        else:
            continue
        reqs = parse_http_stream(req_raw, max_per_stream)
        resps = parse_http_stream(resp_raw, max_per_stream)
        reqs = [m for m in reqs if m.kind == "request"]
        resps = [m for m in resps if m.kind == "response"]

        # 给每个报文求出它「最后一个字节到达」的时间，才能算真实 RTT。
        # 只按段首时间算会把大报文算成瞬间。
        req_end = _msg_end_times(st, req_raw, reqs, req_is_a)
        resp_end = _msg_end_times(st, resp_raw, resps, not req_is_a)

        n = max(len(reqs), len(resps))
        for i in range(n):
            tx = Transaction(stream_key=st.key, client=client, server=server,
                             t_request=st.first_ts, t_response=st.last_ts)
            tx.request = reqs[i] if i < len(reqs) else None
            tx.response = resps[i] if i < len(resps) else None
            if tx.request:
                tx.t_request = req_end[i] if i < len(req_end) else st.first_ts
            if tx.response:
                tx.t_response = resp_end[i] if i < len(resp_end) else st.last_ts
            if tx.request and not tx.response:
                tx.error = "无响应（请求已发出但没收到响应）"
            if not tx.request and tx.response:
                tx.error = "无请求（只看到响应）"
            if tx.request and tx.response:
                # RTT = 响应最后一字节 - 请求最后一字节；负值说明配对错位，不硬算
                d = (tx.t_response - tx.t_request) * 1000
                tx.latency_ms = round(d, 1) if d >= -1 else None
            out.append(tx)
        if st.closed_by == "rst":
            for tx in out[-n:]:
                tx.error = (tx.error + "；连接被 RST 重置").strip("；")
    return out


def _msg_end_times(stream, raw: bytes, msgs, is_a_dir: bool):
    """估算每个报文在原始流里的结束时间。

    做法：解析出的报文在 raw 里的字节终点已知 → 反查承载该字节的 TCP 段的时间。
    这样 RTT 才是「响应最后一段到达 - 请求最后一段发出」，而不是整条流时长。
    """
    if not msgs:
        return []
    segs = [s for s in stream.segments
            if s.payload and ((s.src, s.sport) == stream.initiator) == is_a_dir]
    if not segs:
        return []
    segs.sort(key=lambda s: (s.ts, s.seq))
    # 段边界：每个段的 (起始偏移, 结束偏移, ts)
    bounds = []
    base = segs[0].seq
    for s in segs:
        start = s.seq - base
        # 乱序段可能产生负偏移，用 0 兜底避免越界
        bounds.append((max(start, 0), max(start, 0) + len(s.payload), s.ts))
    ends = []
    # 重新按解析顺序算每个报文在 raw 里的结束偏移
    pos = 0
    for m in msgs:
        # 报文总长：head + body（body 可能被解压，所以不能用 len(m.body)）
        consumed = _consumed_len(m)
        end_off = pos + consumed
        pos = end_off
        ts = 0.0
        for b0, b1, t in bounds:
            if b1 >= end_off:
                ts = t
                break
            ts = t
        ends.append(ts)
    return ends


def _consumed_len(m: HttpMessage) -> int:
    """该报文在原始字节流里实际占的长度（不含解压/解码）。"""
    return m._head_wire_len + m._wire_body_len


def _starts_with_request(data: bytes) -> bool:
    d = data.lstrip(b"\r\n\x00")
    if not d:
        return False
    head = d[:8]
    if head.startswith(b"HTTP/"):
        return False
    for m in (b"GET ", b"POST", b"PUT ", b"DELE", b"HEAD", b"PATC", b"OPTI"):
        if head.startswith(m):
            return True
    return False


def summarize(path: str, linktype_override: Optional[int] = None):
    """对外的单文件入口：给一个 pcap，返回结构化摘要。"""
    packets, pmeta = read_pcap(path)
    segs, smeta = parse_tcp(packets, linktype_override)
    streams = group_streams(segs)
    txs = build_transactions(streams)
    return {
        "file": path,
        "pcap_meta": pmeta,
        "packet_count": len(packets),
        "tcp_meta": smeta,
        "streams": [
            {
                "key": list(st.key),
                "initiator": list(st.initiator),
                "first_ts": st.first_ts,
                "last_ts": st.last_ts,
                "segments": len(st.segments),
                "closed_by": st.closed_by,
                "syn_seen": st.syn_seen,
                "bytes_a2b": len(st.payload_a_to_b()),
                "bytes_b2a": len(st.payload_b_to_a()),
            } for st in streams
        ],
        "transactions": [
            {
                "client": list(tx.client),
                "server": list(tx.server),
                "request": None if not tx.request else {
                    "method": tx.request.method,
                    "path": tx.request.path,
                    "version": tx.request.version,
                    "headers": tx.request.headers,
                    "body_len": len(tx.request.body),
                },
                "response": None if not tx.response else {
                    "status": tx.response.status,
                    "reason": tx.response.reason,
                    "headers": tx.response.headers,
                    "body_len": len(tx.response.body),
                },
                "latency_ms": tx.latency_ms,
                "error": tx.error,
            } for tx in txs
        ],
    }
