#!/usr/bin/env bash
# 本地验证：起一个假对接件 + 假日志，跑 intlink_probe.sh，检查各产物。
# 用法： bash tests/run_local.sh [--keep]
set -u
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PROBE="$ROOT/agent/intlink_probe.sh"
WORK="$(mktemp -d /tmp/intlink-test.XXXXXX)"
FAIL=0
ok() { echo "  PASS $*"; }
no() { echo "  FAIL $*"; FAIL=$((FAIL+1)); }
chk() { if eval "$2"; then ok "$1"; else no "$1  [$2]"; fi; }

echo "== work dir: $WORK =="

# ---------- 假对端（服务端），用 python 起一个 TCP 监听 ----------
cat > "$WORK/peer.py" <<'PY'
import socket, threading, sys, time
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 18099)); srv.listen(8)
def h(c):
    try:
        while True:
            d = c.recv(4096)
            if not d: break
            c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
    except Exception: pass
    finally: c.close()
while True:
    c, _ = srv.accept()
    threading.Thread(target=h, args=(c,), daemon=True).start()
PY
python3 "$WORK/peer.py" & PEER=$!
sleep 0.5

# ---------- 假对接件：有配置、有日志、会周期性连对端 ----------
mkdir -p "$WORK/fake-adapter/logs" "$WORK/fake-adapter/conf"
cat > "$WORK/fake-adapter/conf/app.yaml" <<'YML'
server:
  port: 18080
logging:
  file: logs/adapter.log
  level: info
push:
  endpoint: http://127.0.0.1:18099/api/v1/report
  password: Sup3rS3cret
YML
cat > "$WORK/fake-adapter/adapter.py" <<'PY'
import socket, time, threading, sys, os, datetime, uuid
LOGDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(LOGDIR, exist_ok=True)
log = open(os.path.join(LOGDIR, 'adapter.log'), 'a', buffering=1)

def ts():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]

def server():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 18080)); s.listen(8)
    while True:
        c, a = s.accept()
        log.write('%s [INFO ] inbound,from=%s: requestId=%s\n' % (ts(), a[1], uuid.uuid4()))
        c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'); c.close()

def pusher():
    n = 0
    while True:
        n += 1
        rid = uuid.uuid4()
        try:
            c = socket.create_connection(('127.0.0.1', 18099), timeout=3)
            body = ('{"requestId":"%s","seq":%d,"payload":"hello"}' % (rid, n)).encode()
            req = b'POST /api/v1/report HTTP/1.1\r\nHost: 127.0.0.1:18099\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n' % len(body) + body
            c.sendall(req)
            resp = c.recv(4096)
            log.write('%s [INFO ] push ok seq=%d requestId=%s resp=%r\n' % (ts(), n, rid, resp[:40]))
            c.close()
        except Exception as e:
            log.write('%s [ERROR] push failed seq=%d requestId=%s err=%s\n' % (ts(), n, rid, e))
        time.sleep(2)

threading.Thread(target=server, daemon=True).start()
threading.Thread(target=pusher, daemon=True).start()
time.sleep(3600)
PY
( cd "$WORK/fake-adapter" && exec python3 adapter.py green-adapter ) & ADP=$!
sleep 2.5

echo "== 环境 =="
echo "  peer=$PEER adapter=$ADP"
chk "假对接件在跑" "kill -0 $ADP 2>/dev/null"

# ---------- 脚本自检 ----------
echo "== selftest =="
OUT_SELF="$(bash "$PROBE" --selftest 2>&1)"
printf '%s\n' "$OUT_SELF" | sed 's/^/    /'
chk "selftest 全 PASS" "! printf '%s' \"\$OUT_SELF\" | grep -q '^FAIL'"

# ---------- 只侦察 ----------
echo "== 侦察模式 --list-only --hint green-adapter =="
OUT1="$(cd "$WORK" && bash "$PROBE" --list-only --hint green-adapter --window-secs 600 2>"$WORK/run1.err")"
RC1=$?
echo "  rc=$RC1"
sed 's/^/    /' "$WORK/run1.err" | tail -20
chk "侦察模式退出码 0" "[ $RC1 -eq 0 ]"

PKG1="$(printf '%s' "$OUT1" | awk -F= '/^RESULT=/{print $2}')"
chk "产出包存在" "[ -f \"\$PKG1\" ]"
D1="$WORK/x1"; mkdir -p "$D1"; tar xzf "$PKG1" -C "$D1"
E1="$(find "$D1" -type d -name evidence | head -1)"
chk "evidence 目录存在" "[ -d \"\$E1\" ]"

echo "== 校验 00_summary =="
sed 's/^/    /' "$E1/00_summary.txt" | head -45

chk "识别到进程 pid" "grep -q green-adapter \"\$E1/20_procs.tsv\""
chk "识别到 LISTEN 18080" "awk -F'\t' '\$3==\"LISTEN\" && \$5 ~ /:18080$/ {f=1} END{exit !f}' \"\$E1/30_sockets.tsv\""
# 短连接在 /proc/<pid>/fd 的快照里本来就抓不到 ESTABLISHED，这是预期行为；
# 真正该验的是「从配置/日志里抽出的对端候选」是否正确，以及它有没有进抓包过滤。
chk "从配置抽出对端 127.0.0.1:18099" "awk -F'\t' '\$2==\"127.0.0.1\" && \$3==\"18099\" {f=1} END{exit !f}' \"\$E1/34_endpoint_candidates.tsv\""
chk "抓包过滤含 peer 端口 18099" "awk -F'\t' '\$1==\"port\" && \$2==\"18099\" {f=1} END{exit !f}' \"\$E1/35_filter_hints.txt\""
chk "抓包过滤含监听端口 18080" "awk -F'\t' '\$1==\"port\" && \$2==\"18080\" {f=1} END{exit !f}' \"\$E1/35_filter_hints.txt\""
chk "回环地址不进 host 过滤" "! grep -q 'peer_host' \"\$E1/35_filter_hints.txt\""
chk "从 fd 找到 adapter.log" "awk -F'\t' '\$2 ~ /^fd/ && \$3 ~ /adapter.log$/ {f=1} END{exit !f}' \"\$E1/40_logs.tsv\""
chk "日志切片非空" "[ -s \"\$(ls \"\$E1/41_log_slices\"/* 2>/dev/null | head -1)\" ]"
chk "切片含 requestId" "grep -q requestId \"\$E1\"/41_log_slices/* "
chk "配置里找出 logging 段下的 file 键" "grep -q 'adapter.log' \"\$E1/55_fd_evidence.txt\""
chk "密码已脱敏" "! grep -rq 'Sup3rS3cret' \"\$E1\""
chk "list-only 时抓包标记不可用" "grep -q 'capture_ok=0' \"\$E1/61_capture_result.txt\""

# ---------- 抓包模式 ----------
echo "== 抓包模式 --secs 12 =="
OUT2="$(cd "$WORK" && bash "$PROBE" --hint green-adapter --secs 12 --window-secs 300 2>"$WORK/run2.err")"
RC2=$?
echo "  rc=$RC2"
grep -E '抓包|抓到|RESULT' "$WORK/run2.err" | sed 's/^/    /' | head -12
PKG2="$(printf '%s' "$OUT2" | awk -F= '/^RESULT=/{print $2}')"
D2="$WORK/x2"; mkdir -p "$D2"; tar xzf "$PKG2" -C "$D2"
E2="$(find "$D2" -type d -name evidence | head -1)"
PCAP2="$(ls "$E2"/60_capture/*.pcap 2>/dev/null | head -1)"
chk "抓到 pcap" "[ -n \"\$PCAP2\" ] && [ -s \"\$PCAP2\" ]"
if [ -n "${PCAP2:-}" ] && [ -s "$PCAP2" ]; then
  N="$(tcpdump -nn -r "$PCAP2" 2>/dev/null | wc -l)"
  echo "    packets=$N"
  chk "pcap 里有包" "[ $N -gt 5 ]"
  chk "pcap 含 18099 流量" "tcpdump -nn -r \"\$PCAP2\" 2>/dev/null | grep -q 18099"
fi

# ---------- 降级路径 ----------
echo "== 降级：错误 hint 应无进程但仍出包 =="
OUT3="$(cd "$WORK" && bash "$PROBE" --list-only --hint no-such-program-xyz --secs 5 2>"$WORK/run3.err")"
chk "无匹配也出包" "[ -f \"\$(printf '%s' \"\$OUT3\" | awk -F= '/^RESULT=/{print \$2}')\" ]"
D3="$WORK/x3"; mkdir -p "$D3"; tar xzf "$(printf '%s' "$OUT3" | awk -F= '/^RESULT=/{print $2}')" -C "$D3" 2>/dev/null
E3="$(find "$D3" -type d -name evidence | head -1)"
if [ -n "${E3:-}" ]; then
  chk "gap 里记录了没匹配到进程" "grep -q '没有匹配到任何候选进程' \"\$E3/91_parse_gaps.txt\""
fi

# ---------- 收尾 ----------
kill $ADP $PEER 2>/dev/null
wait 2>/dev/null
echo ""
if [ "$FAIL" -eq 0 ]; then echo "ALL PASS"; [ "$KEEP" = 1 ] && echo "work=$WORK" || rm -rf "$WORK"; exit 0
else echo "FAILED=$FAIL  work=$WORK"; exit 1; fi
