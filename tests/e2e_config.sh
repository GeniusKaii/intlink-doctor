#!/usr/bin/env bash
# 有效配置对照的真实验证：配置写 30s 超时，但对接件实际 3s 就放弃。
#
# 这是整个工具里最能给出「修复方向」的能力，必须用真流量验：
# 抓包量到的断开时长要能和配置值对上/对不上，而不是靠 mock 数据。
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d /tmp/intlink-cfg.XXXXXX)"
OUT_WIN="$ROOT/tests/cfg-out"
mkdir -p "$OUT_WIN"
FAIL=0
ok()  { echo "  PASS $*"; }
no()  { echo "  FAIL $*"; FAIL=$((FAIL+1)); }
chk() { if eval "$2"; then ok "$1"; else no "$1  [$2]"; fi; }

LOCAL_IP="$(ip -4 addr show | awk '/inet / && $2 !~ /^127\./ {split($2,a,"/"); print a[1]; exit}')"
PEER_PORT=18098
echo "== 真实网卡 IP: $LOCAL_IP =="

# 假对端：收下请求但不回（模拟对端卡住），让客户端等到自己超时
cat > "$WORK/peer.py" <<'PY'
import socket, threading, sys, time
PORT = int(sys.argv[1])
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('0.0.0.0', PORT)); srv.listen(32)
print('PEER_LISTENING', flush=True)
def h(c):
    try:
        c.recv(65536)
        time.sleep(60)          # 收下不回，故意挂住
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

# 假对接件：配置声明 timeout=30s，但代码里写死 3s（真实现场最常见的就是这种）
mkdir -p "$WORK/adapter/logs" "$WORK/adapter/conf"
cat > "$WORK/adapter/conf/app.yaml" <<YML
server:
  port: 18080
push:
  endpoint: http://$LOCAL_IP:$PEER_PORT/api/v1/report
  timeout: 30s
  retry: 2
  max_connections: 4
logging:
  level: info
  file: logs/adapter.log
YML

cat > "$WORK/adapter/adapter.py" <<PY
import socket, time, threading, os, datetime, uuid, json
PEER = ("$LOCAL_IP", $PEER_PORT)
LOGDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(LOGDIR, exist_ok=True)
log = open(os.path.join(LOGDIR, 'adapter.log'), 'a', buffering=1)
def ts(): return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
# 注意：配置写 30s，这里写死 3s —— 就是要让工具通过抓包发现这个不一致
HARDCODED_TIMEOUT = 3.0
def pusher():
    n = 0
    while True:
        n += 1
        rid = uuid.uuid4()
        try:
            c = socket.create_connection(PEER, timeout=HARDCODED_TIMEOUT)
            body = json.dumps({"requestId": str(rid), "seq": n}).encode()
            req = (b'POST /api/v1/report HTTP/1.1\r\nHost: ' + PEER[0].encode()
                   + b':' + str(PEER[1]).encode() + b'\r\nContent-Type: application/json\r\n'
                   + b'X-Request-Id: ' + str(rid).encode()
                   + b'\r\nContent-Length: %d\r\n\r\n' % len(body)) + body
            c.sendall(req)
            c.settimeout(HARDCODED_TIMEOUT)
            resp = c.recv(65536)      # 3 秒后必然超时
            log.write('%s [INFO ] push ok seq=%d requestId=%s\n' % (ts(), n, rid))
        except Exception as e:
            log.write('%s [ERROR] push failed requestId=%s err=%s\n' % (ts(), rid, e))
        finally:
            try: c.close()
            except Exception: pass
        time.sleep(1.0)
threading.Thread(target=pusher, daemon=True).start()
time.sleep(3600)
PY
( cd "$WORK/adapter" && exec python3 adapter.py cfg-test-adapter ) & ADP=$!
sleep 2.5
chk "假对接件在跑" "kill -0 $ADP 2>/dev/null"

echo "== 采集（抓包 25s）=="
OUT="$(cd "$WORK" && bash "$ROOT/agent/intlink_probe.sh" --hint cfg-test-adapter \
        --secs 25 --window-secs 300 --out "$WORK/cap" 2>"$WORK/probe.err")"
echo "$OUT" | sed 's/^/  /'
grep -E '开始抓包|抓到|config_kv' "$WORK/probe.err" | sed 's/^/  /' | head -5

PKG="$(printf '%s' "$OUT" | awk -F= '/^RESULT=/{print $2}')"
chk "产出证据包" "[ -f \"\$PKG\" ]"
D="$WORK/x"; mkdir -p "$D"; tar xzf "$PKG" -C "$D" 2>/dev/null
E="$(find "$D" -path '*evidence' -type d | head -1)"

echo "== 配置抽取是否工作 =="
echo "    --- 39_config_kv.tsv ---"
cat "$E/39_config_kv.tsv" 2>/dev/null | sed 's/^/    /' | head -12
chk "抽到了 timeout 配置" "grep -q 'timeout' \"\$E/39_config_kv.tsv\""
chk "timeout 值归一为 30000ms" "awk -F'\t' '\$2 ~ /timeout/ && \$5==\"30000\"{f=1} END{exit !f}' \"\$E/39_config_kv.tsv\""
chk "抽到了 retry 配置" "grep -q 'retry' \"\$E/39_config_kv.tsv\""
chk "抽到了对端地址" "grep -q '$LOCAL_IP' \"\$E/39_config_kv.tsv\""

kill $ADP $PEER 2>/dev/null
BASE="$(basename "$PKG")"
cp -f "$PKG" "$OUT_WIN/$BASE"
echo ""
echo "包: $OUT_WIN/$BASE"
if [ "$FAIL" -eq 0 ]; then echo "ALL PASS"; else echo "FAILED=$FAIL work=$WORK"; fi
