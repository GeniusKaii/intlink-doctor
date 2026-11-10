#!/usr/bin/env bash
# 端到端：WSL 里起假对接件 → 跑采集脚本 → 把包放回 Windows 侧 → 本地分析出报告
# 用法： bash tests/e2e.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WIN_ROOT="$(cd "$ROOT" && pwd -W 2>/dev/null || echo "$ROOT")"
OUT_WIN="$WIN_ROOT/tests/e2e-out"
WORK="$(mktemp -d /tmp/intlink-e2e.XXXXXX)"
mkdir -p "$OUT_WIN"

cleanup() { kill ${ADP:-} ${PEER:-} 2>/dev/null; }
trap cleanup EXIT

echo "== work: $WORK =="
echo "== 输出到 Windows: $OUT_WIN =="

cat > "$WORK/peer.py" <<'PY'
import socket, threading, time
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('0.0.0.0', 18099)); srv.listen(16)
N = [0]
def h(c):
    try:
        while True:
            d = c.recv(65536)
            if not d: break
            N[0] += 1
            # 每 5 条制造一次「收下但不回」：客户端会等到超时/自己断
            if N[0] % 5 == 0:
                time.sleep(8)
                continue
            body = b'{"code":0,"message":"accepted"}'
            c.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                      b'Content-Length: %d\r\n\r\n' % len(body) + body)
    except Exception: pass
    finally: c.close()
while True:
    c, _ = srv.accept()
    threading.Thread(target=h, args=(c,), daemon=True).start()
PY
python3 "$WORK/peer.py" & PEER=$!
sleep 0.4

mkdir -p "$WORK/fake-adapter/logs" "$WORK/fake-adapter/conf"
cat > "$WORK/fake-adapter/conf/app.yaml" <<'YML'
server:
  port: 18080
logging:
  file: logs/adapter.log
  level: info
push:
  endpoint: http://127.0.0.1:18099/api/v1/report
  password: TopSecret123
YML

cat > "$WORK/fake-adapter/adapter.py" <<'PY'
import socket, time, threading, os, datetime, uuid, json, random

LOGDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(LOGDIR, exist_ok=True)
log = open(os.path.join(LOGDIR, 'adapter.log'), 'a', buffering=1)
def ts(): return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]

def server():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 18080)); s.listen(16)
    while True:
        c, a = s.accept()
        log.write('%s [INFO ] inbound from=%s requestId=%s\n' % (ts(), a[1], uuid.uuid4()))
        c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'); c.close()

def pusher():
    n = 0
    while True:
        n += 1
        rid = uuid.uuid4()
        # 每 7 单造一次失败：连上就断，模拟超时
        fail = (n % 7 == 0)
        try:
            c = socket.create_connection(('127.0.0.1', 18099), timeout=2)
            body = json.dumps({"requestId": str(rid), "seq": n,
                               "deviceId": "D-%04d" % n}).encode()
            req = (b'POST /api/v1/report HTTP/1.1\r\nHost: 127.0.0.1:18099\r\n'
                   b'Content-Type: application/json\r\nX-Request-Id: ' + str(rid).encode() +
                   b'\r\nContent-Length: %d\r\n\r\n' % len(body)) + body
            c.sendall(req)
            if fail:
                log.write('%s [ERROR] push timeout requestId=%s seq=%d\n' % (ts(), rid, n))
                c.close()   # 不读响应就断，制造「无响应」
                time.sleep(1.2)
                continue
            resp = c.recv(65536)
            log.write('%s [INFO ] push ok seq=%d requestId=%s\n' % (ts(), n, rid))
            c.close()
        except Exception as e:
            log.write('%s [ERROR] push failed requestId=%s err=%s\n' % (ts(), rid, e))
        time.sleep(0.8)

threading.Thread(target=server, daemon=True).start()
threading.Thread(target=pusher, daemon=True).start()
time.sleep(3600)
PY

( cd "$WORK/fake-adapter" && exec python3 adapter.py green-adapter ) & ADP=$!
sleep 3
echo "== 假对接件 pid=$ADP, 假对端 pid=$PEER =="

echo "== 采集（抓包 20s，日志回看 600s）=="
OUT="$(cd "$WORK" && bash "$ROOT/agent/intlink_probe.sh" --hint green-adapter \
        --secs 20 --window-secs 600 --out "$WORK/cap" 2>"$WORK/probe.err")"
echo "$OUT" | sed 's/^/  /'
grep -E '抓到|GAP|开始抓包' "$WORK/probe.err" | sed 's/^/  /' | head -8

PKG="$(printf '%s' "$OUT" | awk -F= '/^RESULT=/{print $2}')"
if [ ! -f "$PKG" ]; then echo "FAIL 没拿到证据包"; exit 1; fi
echo "== 证据包: $PKG ($(stat -c %s "$PKG") 字节) =="

# 拷到 Windows 可见目录
BASE="$(basename "$PKG")"
cp -f "$PKG" "$OUT_WIN/$BASE"
echo "== 放到: $OUT_WIN/$BASE =="
echo "PKG_WIN=$(cygpath -w "$OUT_WIN/$BASE" 2>/dev/null || echo "$OUT_WIN/$BASE")"

say() { echo "$*"; }
say "== 下一步在 Windows 侧执行分析 =="
