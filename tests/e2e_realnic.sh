#!/usr/bin/env bash
# 真实网卡抓包端到端验证。
#
# 为什么要单独验：回环（lo）上抓包永远不会「选错网卡」，也看不出跨网段的
# 地址解析问题。真实客户机流量走 eth0/ens*，网卡选择、BPF 过滤、时钟偏差
# 都可能出问题，所以必须用非 127.0.0.1 的地址跑一遍。
#
# 做法：在 WSL 自己的 eth0 地址上起假对端（绑定 0.0.0.0），
# 假对接件用「本机的 eth0 IP」而不是 127.0.0.1 去连，
# 这样流量一定经过 eth0，而不是走 lo 短路。
#
# 用法： bash tests/e2e_realnic.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d /tmp/intlink-realnic.XXXXXX)"
OUT_WIN="$ROOT/tests/realnic-out"
mkdir -p "$OUT_WIN"
FAIL=0
ok()  { echo "  PASS $*"; }
no()  { echo "  FAIL $*"; FAIL=$((FAIL+1)); }
chk() { if eval "$2"; then ok "$1"; else no "$1  [$2]"; fi; }

# 取本机非回环 IP
LOCAL_IP="$(ip -4 addr show | awk '/inet / && $2 !~ /^127\./ {split($2,a,"/"); print a[1]; exit}')"
if [ -z "$LOCAL_IP" ]; then echo "FAIL 找不到非回环 IPv4"; exit 1; fi
PEER_PORT=18099
echo "== 本机真实网卡 IP: $LOCAL_IP  对端端口: $PEER_PORT =="
echo "== work: $WORK =="

# ---- 假对端（绑 0.0.0.0，通过真实 IP 访问）----
cat > "$WORK/peer.py" <<'PY'
import socket, threading, time, sys
PORT = int(sys.argv[1])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('0.0.0.0', PORT))
srv.listen(32)
print('PEER_LISTENING', flush=True)
n = [0]
def h(c):
    try:
        buf = b''
        while True:
            d = c.recv(65536)
            if not d: break
            buf += d
            if b'\r\n\r\n' in buf:
                n[0] += 1
                body = b'{"code":0,"message":"accepted"}'
                c.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                          b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
                buf = b''
    except Exception: pass
    finally:
        try: c.close()
        except Exception: pass
while True:
    c, a = srv.accept()
    threading.Thread(target=h, args=(c,), daemon=True).start()
PY
python3 "$WORK/peer.py" "$PEER_PORT" > "$WORK/peer.out" 2>&1 & PEER=$!
for i in $(seq 1 30); do grep -q PEER_LISTENING "$WORK/peer.out" 2>/dev/null && break; sleep 0.2; done
chk "假对端已监听" "grep -q PEER_LISTENING \"\$WORK/peer.out\""

# ---- 假对接件：连真实 IP（关键：不是 127.0.0.1）----
mkdir -p "$WORK/adapter/logs" "$WORK/adapter/conf"
cat > "$WORK/adapter/conf/app.yaml" <<YML
server:
  port: 18080
logging:
  file: logs/adapter.log
  level: info
push:
  endpoint: http://$LOCAL_IP:$PEER_PORT/api/v1/report
  password: CrossNicSecret
YML

cat > "$WORK/adapter/adapter.py" <<PY
import socket, time, threading, os, datetime, uuid, json
PEER = ("$LOCAL_IP", $PEER_PORT)
LOGDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(LOGDIR, exist_ok=True)
log = open(os.path.join(LOGDIR, 'adapter.log'), 'a', buffering=1)
def ts(): return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
def pusher():
    n = 0
    while True:
        n += 1
        rid = uuid.uuid4()
        try:
            c = socket.create_connection(PEER, timeout=3)
            body = json.dumps({"requestId": str(rid), "seq": n}).encode()
            req = (b'POST /api/v1/report HTTP/1.1\r\nHost: ' + PEER[0].encode()
                   + b':' + str(PEER[1]).encode() + b'\r\nContent-Type: application/json\r\n'
                   + b'X-Request-Id: ' + str(rid).encode()
                   + b'\r\nContent-Length: %d\r\n\r\n' % len(body)) + body
            c.sendall(req)
            resp = c.recv(65536)
            log.write('%s [INFO ] push ok seq=%d requestId=%s\n' % (ts(), n, rid))
            c.close()
        except Exception as e:
            log.write('%s [ERROR] push failed requestId=%s err=%s\n' % (ts(), rid, e))
        time.sleep(0.9)
threading.Thread(target=pusher, daemon=True).start()
time.sleep(3600)
PY
( cd "$WORK/adapter" && exec python3 adapter.py cross-nic-adapter ) & ADP=$!
sleep 2.5
chk "假对接件在跑" "kill -0 $ADP 2>/dev/null"
chk "对接件已产生跨网卡流量" "grep -q 'push ok' \"\$WORK/adapter/logs/adapter.log\" 2>/dev/null"

echo "== 采集（抓包 20s，流量走 $LOCAL_IP）=="
OUT="$(cd "$WORK" && bash "$ROOT/agent/intlink_probe.sh" --hint cross-nic-adapter \
        --secs 20 --window-secs 300 --out "$WORK/cap" 2>"$WORK/probe.err")"
echo "$OUT" | sed 's/^/  /'
grep -E '开始抓包|抓到|GAP' "$WORK/probe.err" | sed 's/^/  /' | head -6

PKG="$(printf '%s' "$OUT" | awk -F= '/^RESULT=/{print $2}')"
chk "产出证据包" "[ -f \"\$PKG\" ]"
D="$WORK/x"; mkdir -p "$D"; tar xzf "$PKG" -C "$D" 2>/dev/null
E="$(find "$D" -type d -name evidence | head -1)"

echo "== 抓包结果校验（核心：必须是真实网卡，不能只有 lo）=="
PCAP="$(ls "$E"/60_capture/*.pcap 2>/dev/null | head -1)"
chk "抓到 pcap" "[ -n \"\$PCAP\" ] && [ -s \"\$PCAP\" ]"
if [ -n "${PCAP:-}" ] && [ -s "$PCAP" ]; then
  N="$(tcpdump -nn -r "$PCAP" 2>/dev/null | wc -l)"
  echo "    packets=$N"
  chk "pcap 非空" "[ $N -gt 10 ]"
  chk "pcap 含真实网卡 IP $LOCAL_IP" "tcpdump -nn -r \"\$PCAP\" 2>/dev/null | grep -q '$LOCAL_IP'"
  # 注意 tcpdump -nn 的格式是 IP 1.2.3.4.18099，用点号不是冒号
  chk "pcap 含对端端口 $PEER_PORT" "tcpdump -nn -r \"\$PCAP\" 2>/dev/null | grep -q \".$PEER_PORT\""
  LO_CNT="$(tcpdump -nn -r "$PCAP" 2>/dev/null | grep -c '127\.0\.0\.1' || true)"
  REAL_CNT="$(tcpdump -nn -r "$PCAP" 2>/dev/null | grep -c "$LOCAL_IP" || true)"
  echo "    回环包=$LO_CNT  真实网卡包=$REAL_CNT"
  chk "真实网卡流量多于回环" "[ \${REAL_CNT:-0} -gt \${LO_CNT:-0} ]"
fi

echo "== 过滤条件解析 =="
cat "$E/34_endpoint_candidates.tsv" 2>/dev/null | sed 's/^/    /' | head -5
chk "对端候选含 $LOCAL_IP" "grep -q '$LOCAL_IP' \"\$E/34_endpoint_candidates.tsv\""
# 35_filter_hints.txt 的格式是 peer_host<TAB>IP / port<TAB>N
chk "过滤条件含对端 $LOCAL_IP" "awk -F'\t' '\$1==\"peer_host\" && \$2==\"$LOCAL_IP\"{f=1} END{exit !f}' \"\$E/35_filter_hints.txt\""
chk "过滤条件含对端端口 $PEER_PORT" "awk -F'\t' '\$1==\"port\" && \$2==\"$PEER_PORT\"{f=1} END{exit !f}' \"\$E/35_filter_hints.txt\""

echo "== 日志与脱敏 =="
chk "日志切片非空" "[ -s \"\$(ls \"\$E/41_log_slices\"/* 2>/dev/null | head -1)\" ]"
chk "密码已脱敏" "! grep -rq 'CrossNicSecret' \"\$E\""

kill $ADP $PEER 2>/dev/null
BASE="$(basename "$PKG")"
cp -f "$PKG" "$OUT_WIN/$BASE"
echo ""
echo "包已放到: $OUT_WIN/$BASE"
if [ "$FAIL" -eq 0 ]; then echo "ALL PASS"; else echo "FAILED=$FAIL work=$WORK"; fi
