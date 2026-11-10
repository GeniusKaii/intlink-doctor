#!/usr/bin/env bash
#
# intlink-doctor / agent / intlink_probe.sh
#
# 这是一个「目标机侧」单文件只读采集脚本。运行一次，出一个证据包，带回 Windows 侧分析。
#
# ── 为什么有这个脚本 ──────────────────────────────────────────────
# 对接件（三方系统 ↔ 中间件 ↔ 平台）故障时，工程师无法登机器反复试。本脚本把
# 「找进程 / 找端口 / 找日志 / 按时间窗抓包 / 采时钟」一次做完，采不到的层写进 gaps，
# 不影响其余部分出包。
#
# ── 本版要回答的问题 ──────────────────────────────────────────────
#   1. 对接件进程是哪个（裸进程 / 容器内），在哪个 netns
#   2. 它此刻的 TCP 五元组是什么（客户端临时端口也要，不只看 LISTEN）
#   3. 它实际在写的日志文件是哪些（从 /proc/<pid>/fd 看，不信配置文件）
#   4. 在指定时间窗内，这条链路上抓到了什么报文
#   5. 这台机/这个容器的时钟与时区，能不能和日志对齐
#   6. 上面哪些做不到、为什么（权限、缺工具、命名空间隔离）
#
# ── 只读保证 ──────────────────────────────────────────────────────
#   读：/proc/*、/etc/*、ss、ps、/etc/os-release、systemctl show（只读查询）
#   写：仅 $OUT（默认 $PWD/intlink-out-<ts>），不碰业务目录、不改配置、不重启服务
#   执行：tcpdump（只抓不发）、timeout、可选 nsenter/psql 不涉及
#   不发任何主动业务报文：抓包窗口内需要复现时，由人触发，脚本只等待
#
# ── 用法 ──────────────────────────────────────────────────────────
#   bash intlink_probe.sh --hint green-adapter --secs 60
#   bash intlink_probe.sh --hint java --pid 12345 --secs 30 --ports 18080
#   bash intlink_probe.sh --auto --list-only          # 只侦察，不抓包
#   bash intlink_probe.sh --selftest                  # 交付前自检
#
#   参数：
#     --hint <str>     进程线索，可多次。匹配 cmdline / exe 路径 / comm。
#                      也可以直接给 PID（纯数字）。
#     --pid <n>        直接指定 PID（可多次），优先级高于 --hint
#     --auto           不给线索时自动挑「有对外 ESTABLISHED 连接」的候选进程
#     --secs <n>       抓包窗口秒数，默认 60
#     --ports <list>   额外强制抓的端口，逗号分隔，如 8080,18080
#     --peers <list>   额外强制抓的对端 IP/网段，逗号分隔
#     --list-only      只做侦察，跳过抓包
#     --no-capture     同 --list-only
#     --window-secs <n>  日志切片回看的窗口，默认 900（15 分钟）
#     --max-log-mb <n>   单份日志切片上限，默认 8
#     --out <dir>      输出目录
#     --no-redact      不脱敏（默认脱敏，只有明确要原始凭据时才关）
#     --selftest       只跑内置断言，不采集
#
#   产出：intlink-probe-<host>-<YYYYmmdd-HHMMSS>.tar.gz
#         尾部打印 RESULT=<路径> 与 SHA256=<校验值>
#
# ── 注意 ──────────────────────────────────────────────────────────
#   - 本脚本必须 LF 换行。若从 Windows 拷来，先跑：sed -i 's/\r$//' intlink_probe.sh
#   - 抓包窗口内需要复现时，脚本会在 stderr 打大字提示，请按提示在对端触发
#   - pcap 可能含个人信息，外发前必须脱敏
#

set -u

VERSION="1.0.0"
SECS="${SECS:-60}"
LIST_ONLY=0
AUTO_PICK=0
WINDOW_SECS="${WINDOW_SECS:-900}"
MAX_LOG_MB="${MAX_LOG_MB:-8}"
REDACT=1
OUT_DIR=""
HINTS=()
PIDS=()
EXTRA_PORTS=""
EXTRA_PEERS=""

# ── 基础工具 ──────────────────────────────────────────────────────
have() { command -v "$1" >/dev/null 2>&1; }

# 进度/诊断一律走 stderr：stdout 可能被上层捕获当数据
say() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die() { say "FATAL: $*"; exit 2; }

# 所有外部命令走超时包裹，缺 timeout 就退化为直跑
if have timeout; then
  T() { local s="$1"; shift; timeout "$s" "$@"; }
else
  T() { shift; "$@"; }
fi

# 统一脱敏：URL 凭据 / --password= / JSON 里的 token|session_id|passwd
# 必须写成多个 -e：用反斜杠续行拼成一条 sed 表达式时，BSD/GNU sed 都会把
# 续行后的空白吃掉导致 "unterminated address regex"（实测 bash 5 + sed 4.7 复现）。
mask() {
  sed -E \
    -e 's#(://[^:/@[:space:]]+):[^@/[:space:]]+@#\1:***REDACTED***@#g' \
    -e 's/(--?[A-Za-z_.-]*(pass|passwd|password|token|secret)[A-Za-z_.-]*)([= :])[^ "]*/\1\3***REDACTED***/gI' \
    -e 's/("[A-Za-z_]*(pass|passwd|password|token|secret|session_id|sessionid|access_?key)[A-Za-z_]*"[[:space:]]*:[[:space:]]*")[^"]*/\1***REDACTED***/gI'
}
redact() { if [ "$REDACT" = 1 ]; then mask; else cat; fi; }

# grep -c 在 0 命中时打印 0 且返回非 0，必须收口成一个数字
gcount() { local n; n="$(grep -acE "$1" "$2" 2>/dev/null || true)"; printf '%s' "${n:-0}"; }

# ── 自检 ──────────────────────────────────────────────────────────
selftest() {
  local rc=0

  # 1) hex 地址解析（IPv4 反序）
  local got
  got="$(printf '%s\n' '0100007F:1F90' | _hex_to_ip4 2>/dev/null || true)"
  if [ "$got" = "127.0.0.1:8080" ]; then echo "PASS hex_to_ip4"; else echo "FAIL hex_to_ip4 got=[$got]"; rc=1; fi

  # 2) 脱敏
  local m
  m="$(printf '%s\n' 'url=ftp://bob:secret123@1.2.3.4/x' '--password=hunter2' '{"host":"h","session_id":"abc","token":"t0k"}' | mask)"
  if printf '%s' "$m" | grep -q 'secret123\|hunter2\|t0k'; then echo "FAIL mask 泄漏了明文"; rc=1; else echo "PASS mask"; fi

  # 3) 时间戳解析（python 侧逻辑，走同一份 parse.py）
  if [ -n "${PY3:-}" ] && [ -f "${PY_SCRIPT:-}" ]; then
    got="$("$PY3" "$PY_SCRIPT" --selftest 2>&1 || true)"
    if printf '%s' "$got" | grep -q '^PASS'; then echo "PASS py_selftest"; else echo "FAIL py_selftest: $got"; rc=1; fi
  else
    echo "SKIP py_selftest (python3 不可用或无 parse.py)"
  fi

  # 4) gcount 0 命中只返回一个 0
  local tmpf; tmpf="$(mktemp)" || return 1
  printf 'nothing here\n' > "$tmpf"
  got="$(gcount 'nomatch-xyz' "$tmpf")"
  rm -f "$tmpf"
  if [ "$got" = "0" ]; then echo "PASS gcount_zero"; else echo "FAIL gcount_zero got=[$got]"; rc=1; fi

  # 5) 行尾必须是 LF
  if tr -cd '\r' < "$0" | grep -q .; then echo "FAIL line_endings 存在 CR"; rc=1; else echo "PASS line_endings"; fi

  return $rc
}

# bash 侧 IPv4 hex 解码（selftest 用，主解析在 python）
_hex_to_ip4() {
  local s h p b1 b2 b3 b4
  s="$(cat)"
  h="${s%%:*}"; p="${s##*:}"
  b1="${h:6:2}"; b2="${h:4:2}"; b3="${h:2:2}"; b4="${h:0:2}"
  printf '%d.%d.%d.%d:%d' "0x$b1" "0x$b2" "0x$b3" "0x$b4" "$((16#$p))"
}

# ── 参数解析 ──────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --hint)        HINTS+=("${2:-}"); shift 2 ;;
    --pid)         PIDS+=("${2:-}"); shift 2 ;;
    --auto)        AUTO_PICK=1; shift ;;
    --secs)        SECS="${2:-60}"; shift 2 ;;
    --ports)       EXTRA_PORTS="${2:-}"; shift 2 ;;
    --peers)       EXTRA_PEERS="${2:-}"; shift 2 ;;
    --list-only|--no-capture) LIST_ONLY=1; shift ;;
    --window-secs) WINDOW_SECS="${2:-900}"; shift 2 ;;
    --max-log-mb)  MAX_LOG_MB="${2:-8}"; shift 2 ;;
    --out)         OUT_DIR="${2:-}"; shift 2 ;;
    --no-redact)   REDACT=0; shift ;;
    --selftest)
      # 自检时 parse.py 还没落地，把本文件里的 python 块抽到临时文件再跑其内部断言
      PY3="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)"
      if [ -n "$PY3" ]; then
        _tmp_py="$(mktemp)" || _tmp_py=""
        if [ -n "$_tmp_py" ]; then
          awk '/^cat > "\$PY_SCRIPT" <<.PYEOF./{f=1;next} f&&/^PYEOF$/{exit} f' "$0" > "$_tmp_py"
          [ -s "$_tmp_py" ] && PY_SCRIPT="$_tmp_py"
        fi
      fi
      selftest; _rc=$?
      [ -n "${_tmp_py:-}" ] && rm -f "$_tmp_py"
      exit $_rc ;;
    -h|--help)     sed -n '3,60p' "$0"; exit 0 ;;
    *)             say "忽略未知参数: $1"; shift ;;
  esac
done

# 数值合法性
case "$SECS" in ''|*[!0-9]*) SECS=60 ;; esac
[ "$SECS" -lt 5 ] && SECS=5
[ "$SECS" -gt 1800 ] && SECS=1800
case "$WINDOW_SECS" in ''|*[!0-9]*) WINDOW_SECS=900 ;; esac
case "$MAX_LOG_MB" in ''|*[!0-9]*) MAX_LOG_MB=8 ;; esac

# ── 运行环境探测 ──────────────────────────────────────────────────
HOSTNAME_S="$(hostname 2>/dev/null || echo unknown)"
TS="$(date +%Y%m%d-%H%M%S)"
START_EPOCH="$(date +%s)"
PY3="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)"

if [ -z "$OUT_DIR" ]; then
  if [ -w "$PWD" ]; then OUT_DIR="$PWD/intlink-out-$TS"
  elif [ -w /tmp ]; then OUT_DIR="/tmp/intlink-out-$TS"
  else OUT_DIR="$HOME/intlink-out-$TS"; fi
fi
mkdir -p "$OUT_DIR" || die "无法创建输出目录 $OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
EVD="$OUT_DIR/evidence"
mkdir -p "$EVD" "$EVD/41_log_slices" "$EVD/60_capture" || die "无法创建证据目录"

# 本脚本自身复制一份进包，便于复核算了什么
cp -f "$0" "$OUT_DIR/intlink_probe.sh" 2>/dev/null || true

say "intlink-probe v$VERSION  host=$HOSTNAME_S  out=$OUT_DIR"
say "抓包窗口=${SECS}s  list_only=$LIST_ONLY  python3=$([ -n "$PY3" ] && echo yes || echo NO)"

GAPS="$EVD/90_gaps.txt"
: > "$GAPS"
gap() { printf '%s\n' "$*" >> "$GAPS"; say "GAP: $*"; }

# 权限与工具
IS_ROOT=0; [ "$(id -u 2>/dev/null || echo 1)" = "0" ] && IS_ROOT=1
SUDO_NOPASS=0
if [ "$IS_ROOT" = 0 ] && have sudo && sudo -n true 2>/dev/null; then SUDO_NOPASS=1; fi
SU() { if [ "$IS_ROOT" = 1 ]; then "$@"; elif [ "$SUDO_NOPASS" = 1 ]; then sudo -n "$@"; else return 1; fi; }

# 容器检测（三层交叉，记原始证据，不靠单点下结论）
CONT_HINT=0; CONT_EVIDENCE=""
[ -f /.dockerenv ] && { CONT_HINT=1; CONT_EVIDENCE="$CONT_EVIDENCE dockerenv"; }
if grep -qE 'docker|kubepods|containerd|lxc|podman' /proc/1/cgroup 2>/dev/null; then
  CONT_HINT=1; CONT_EVIDENCE="$CONT_EVIDENCE cgroup"
fi
if have systemd-detect-virt; then
  v="$(systemd-detect-virt -c 2>/dev/null || true)"
  case "$v" in docker|podman|lxc|systemd-nspawn) CONT_HINT=1; CONT_EVIDENCE="$CONT_EVIDENCE virt=$v" ;; esac
fi

# ── 05_env.txt：时钟、时区、系统 ──────────────────────────────────
say "采集环境与时钟..."
{
  echo "== intlink-probe v$VERSION =="
  echo "collected_at_local: $(date -Ins 2>/dev/null || date)"
  echo "collected_at_utc:   $(date -u -Ins 2>/dev/null || date -u)"
  echo "epoch:              $START_EPOCH"
  echo "hostname:           $HOSTNAME_S"
  echo "kernel:             $(uname -a 2>/dev/null)"
  echo "uptime:             $(uptime 2>/dev/null)"
  echo "proc_uptime_sec:    $(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
  echo "btime:              $(awk '/^btime/{print $2}' /proc/stat 2>/dev/null)"
  echo ""
  echo "-- identity --"
  echo "id:                 $(id 2>/dev/null)"
  echo "is_root:            $IS_ROOT"
  echo "sudo_nopass:        $SUDO_NOPASS"
  echo ""
  echo "-- timezone --"
  echo "TZ_env:             ${TZ:-<unset>}"
  echo "/etc/timezone:      $(cat /etc/timezone 2>/dev/null || echo '<none>')"
  echo "/etc/localtime:     $(readlink -f /etc/localtime 2>/dev/null || echo '<none>')"
  echo "localtime_inode:    $(stat -c '%i' /etc/localtime 2>/dev/null || echo '?')"
  echo ""
  echo "-- clock sync --"
  if have timedatectl; then T 5 timedatectl 2>&1 | sed 's/^/  /'; else echo "  timedatectl: absent"; fi
  if have chronyc; then echo "  chronyc tracking:"; T 5 chronyc tracking 2>&1 | sed 's/^/    /'; fi
  if have ntpq; then echo "  ntpq -p:"; T 5 ntpq -pn 2>&1 | head -6 | sed 's/^/    /'; fi
  echo ""
  echo "-- os --"
  cat /etc/os-release 2>/dev/null | sed 's/^/  /' || echo "  <none>"
  echo ""
  echo "-- container --"
  echo "container_hint:     $CONT_HINT ($CONT_EVIDENCE )"
  echo "/proc/1/cgroup:     $(tr '\n' '|' < /proc/1/cgroup 2>/dev/null)"
  echo "self_netns:         $(readlink /proc/self/ns/net 2>/dev/null)"
  echo "self_pidns:         $(readlink /proc/self/ns/pid 2>/dev/null)"
  echo ""
  echo "-- tools --"
  for t in tcpdump ss lsof nsenter docker crictl python3 journalctl systemctl; do
    printf '  %-12s %s\n' "$t" "$(command -v $t 2>/dev/null || echo '-')"
  done
  echo ""
  echo "-- disk --"
  df -h "$OUT_DIR" 2>/dev/null | sed 's/^/  /'
} > "$EVD/05_env.txt" 2>&1

# ── 工具就绪检查 ──────────────────────────────────────────────────
CAP_OK=1; CAP_REASON=""
if [ "$LIST_ONLY" = 1 ]; then CAP_OK=0; CAP_REASON="list-only 模式"
elif ! have tcpdump; then CAP_OK=0; CAP_REASON="tcpdump 不存在"
elif [ "$IS_ROOT" = 0 ] && [ "$SUDO_NOPASS" = 0 ]; then CAP_OK=0; CAP_REASON="非 root 且无免密 sudo，无法抓包"
fi
if [ "$CAP_OK" = 0 ] && [ "$LIST_ONLY" = 0 ]; then
  gap "抓包不可用: $CAP_REASON（已降级为连接/重传统计，报告会明写此层缺失）"
fi

# ── python 解析器 ─────────────────────────────────────────────────
PY_SCRIPT="$OUT_DIR/parse.py"
cat > "$PY_SCRIPT" <<'PYEOF'
import os, re, sys, json, time, pwd, ipaddress
from datetime import datetime, timezone, timedelta

STATES = {
 '01':'ESTABLISHED','02':'SYN_SENT','03':'SYN_RECV','04':'FIN_WAIT1','05':'FIN_WAIT2',
 '06':'TIME_WAIT','07':'CLOSE','08':'CLOSE_WAIT','09':'LAST_ACK','0A':'LISTEN','0B':'CLOSING',
}
CONFIG_EXT = ('.yaml','.yml','.properties','.json','.ini','.conf','.toml','.xml','.cfg','.env')
LOG_KEY_RE = re.compile(r'(?i)(log[._-]?(file|path|dir|dir_path|file_path)|logging\.file|log4j|'
                        r'logback|log_dir|logfile|access_log|error_log|log_path)')

TS_PATTERNS = [
    # 2026-11-10T15:09:58.123+08:00 / 2026-11-10 15:09:58,123
    (re.compile(r'^\[?(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?'), 'ymd'),
    # [10/Nov/2026:15:09:58 +0800]
    (re.compile(r'^\[?(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})'), 'clf'),
    # 1731232198.123
    (re.compile(r'^\[?(\d{10})(?:\.(\d{1,9}))?\b'), 'epoch'),
]
MONTHS = {m:i for i,m in enumerate(
    ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'], start=1)}

def parse_ts(line, assume_tz):
    """返回 epoch 秒；解析不了返回 None。"""
    for pat, kind in TS_PATTERNS:
        m = pat.match(line)
        if not m:
            continue
        try:
            if kind == 'ymd':
                y, mo, d, hh, mm, ss = (int(m.group(i)) for i in range(1, 7))
                frac = m.group(7) or '0'
                micro = int((frac + '000000')[:6])
                tzs = m.group(8)
                if tzs == 'Z':
                    tz = timezone.utc
                elif tzs:
                    sign = 1 if tzs[0] == '+' else -1
                    tzs = tzs[1:].replace(':','')
                    tz = timezone(sign * timedelta(hours=int(tzs[:2]), minutes=int(tzs[2:4])))
                else:
                    tz = assume_tz
                return datetime(y, mo, d, hh, mm, ss, micro, tzinfo=tz).timestamp()
            if kind == 'clf':
                d, mon, y, hh, mm, ss = m.groups()
                dt = datetime(int(y), MONTHS[mon.capitalize()], int(d), int(hh), int(mm), int(ss),
                              tzinfo=assume_tz)
                return dt.timestamp()
            if kind == 'epoch':
                return float(m.group(1) + '.' + (m.group(2) or '0'))
        except Exception:
            continue
    return None

def hex_to_addr(s):
    """解析 /proc/net/tcp{,6} 的 local_address / rem_address。"""
    ip_h, port_h = s.split(':')
    port = int(port_h, 16)
    raw = bytes.fromhex(ip_h)
    if len(raw) == 4:
        return '.'.join(str(b) for b in reversed(raw)), port, 4
    # IPv6：每个 32bit 字是 little-endian
    words = [raw[i:i+4][::-1] for i in range(0, 16, 4)]
    return str(ipaddress.IPv6Address(b''.join(words))), port, 6

def read_socket_table(netns_pid):
    """读某个进程所属 netns 的 tcp/tcp6 表，返回 inode -> 记录。"""
    out = {}
    for fam in ('tcp', 'tcp6'):
        path = '/proc/%s/net/%s' % (netns_pid, fam)
        try:
            with open(path, 'r', errors='replace') as f:
                next(f, None)
                for ln in f:
                    p = ln.split()
                    if len(p) < 10:
                        continue
                    try:
                        lip, lp, ver = hex_to_addr(p[1])
                        rip, rp, _ = hex_to_addr(p[2])
                    except Exception:
                        continue
                    inode = p[9]
                    out[inode] = {
                        'family': 'v6' if ver == 6 else 'v4',
                        'local_ip': lip, 'local_port': lp,
                        'remote_ip': rip, 'remote_port': rp,
                        'state': STATES.get(p[3].upper(), p[3]),
                        'tx_queue': p[4].split(':')[0] if ':' in p[4] else '0',
                        'rx_queue': p[4].split(':')[1] if ':' in p[4] else '0',
                        'uid': p[7], 'inode': inode,
                    }
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return out

def proc_field(pid, name):
    try:
        with open('/proc/%s/%s' % (pid, name), 'r', errors='replace') as f:
            return f.read().strip()
    except Exception:
        return ''

def collect_procs():
    """枚举进程。

    关键：非 root 用户读别的用户的 /proc/<pid>/cmdline 会得到空内容（不是异常），
    但 comm / exe / status 通常仍可读。所以绝不能因为 cmdline 空就把进程丢掉 ——
    否则在客户机（普通账号）上根本找不到对接件。这里把 cmdline 视为可选字段，
    并用 comm/exe 兜底匹配。
    """
    procs = {}
    unreadable_cmdline = 0
    for d in os.listdir('/proc'):
        if not d.isdigit():
            continue
        pid = d
        cmdline = ''
        try:
            with open('/proc/%s/cmdline' % pid, 'rb') as f:
                cmdline = f.read().replace(b'\x00', b' ').decode('utf-8', 'replace').strip()
        except Exception:
            cmdline = ''
        exe = ''
        try:
            exe = os.readlink('/proc/%s/exe' % pid)
        except Exception:
            pass
        comm = proc_field(pid, 'comm')
        # 内核线程 exe 为空且 comm 形如 [kworker]；保留它们但标记，后面按需过滤
        if not cmdline:
            unreadable_cmdline += 1
        procs[pid] = {'pid': pid, 'cmdline': cmdline, 'exe': exe, 'comm': comm,
                      'cmdline_readable': bool(cmdline)}
    procs['__meta__'] = {'unreadable_cmdline': unreadable_cmdline}
    return procs

def proc_meta(pid):
    m = {}
    m['ppid'] = ''
    m['uid'] = ''
    try:
        with open('/proc/%s/status' % pid, 'r', errors='replace') as f:
            for ln in f:
                # 注意：PPid 和 Uid 是两行，不能命中 PPid 就 break，
                # 否则 uid 永远为空，后面按 uid 反查 socket 的降级路径会失效。
                if ln.startswith('PPid:'):
                    m['ppid'] = ln.split()[1]
                elif ln.startswith('Uid:'):
                    m['uid'] = ln.split()[1]
                if m['ppid'] and m['uid']:
                    break
    except Exception:
        pass
    try:
        m['user'] = pwd.getpwuid(int(m.get('uid') or -1)).pw_name
    except Exception:
        m['user'] = m.get('uid', '')
    m['cwd'] = ''
    try:
        m['cwd'] = os.readlink('/proc/%s/cwd' % pid)
    except Exception:
        pass
    m['netns'] = ''
    try:
        m['netns'] = os.readlink('/proc/%s/ns/net' % pid)
    except Exception:
        pass
    m['cgroup'] = proc_field(pid, 'cgroup').replace('\n', '|')
    cid = ''
    for pat in (r'[0-9a-f]{64}', r'cri-containerd-([0-9a-f]{64})', r'docker-([0-9a-f]{64})'):
        mm = re.search(pat, m['cgroup'])
        if mm:
            cid = mm.group(0) if mm.lastindex is None else mm.group(1)
            break
    m['container_id'] = cid
    # 进程启动时刻 = btime + starttime/HZ
    m['start_epoch'] = ''
    try:
        with open('/proc/stat') as f:
            btime = 0
            for ln in f:
                if ln.startswith('btime'):
                    btime = int(ln.split()[1]); break
        st = proc_field(pid, 'stat')
        if st:
            rp = st[st.rfind(')') + 2:].split()
            hz = os.sysconf('SC_CLK_TCK') or 100
            m['start_epoch'] = int(btime + int(rp[19]) / hz)
    except Exception:
        pass
    return m

def score_hint(info, hint):
    """给「进程 ↔ 线索」打分。绝不因为 cmdline 里出现一个子串就当成对接件，
    必须按可信度排序，避免把探针自己/父 shell 一起捞进来。

    非 root 场景下 cmdline 可能读不到（返回空），所以 comm/exe 必须能独立命中；
    comm 被内核截断到 15 字符，还要支持前缀匹配（java 进程常靠这个）。
    """
    hl = hint.lower()
    comm = (info.get('comm') or '').lower()
    exe = (info.get('exe') or '')
    exe_base = os.path.basename(exe).lower()
    cmdline = (info.get('cmdline') or '')
    cmd_l = cmdline.lower()

    # 自排除：探针自身与解析器永远不是对接件
    if 'intlink_probe.sh' in cmd_l or '/parse.py' in cmd_l or cmd_l.startswith('python3 /'):
        if 'intlink-doctor' in cmd_l or 'intlink_probe' in cmd_l:
            return 0

    if comm == hl:
        return 100
    if exe_base == hl or exe_base == hl + '.exe':
        return 95
    # comm 最长 15 字符（内核截断），线索更长时按前缀认
    if comm and hl.startswith(comm) and len(comm) == 15:
        return 88
    if exe_base and hl.startswith(exe_base) and len(exe_base) >= 12:
        return 85
    if hl in exe_base:
        return 80
    # 逐 token 完整匹配 > 子串匹配（子串最容易误伤）
    for tok in cmdline.split():
        if os.path.basename(tok).lower() == hl:
            return 70
    if hl and hl in cmd_l:
        return 40
    return 0


def is_noise_proc(pid, info, self_chain, self_pid=None):
    """过滤「探针自己这条执行链」，但绝不能把 SSH 会话的 sshd 一起排掉。

    踩过的坑：一开始把整条祖先链都当噪声，结果 SSH 登录跑时祖先链里必然有
    sshd（bash 的父进程就是 sshd），于是 --hint sshd 永远匹配不到任何进程。
    正确做法是只排除：
      1) 探针自己（shell 解释器 + python 解析器）
      2) 探针的直接命令载体（命令行里带 intlink_probe / intlink-out 的）
    不含 sshd、systemd、init 这类「会话基础设施」。
    """
    cmd = (info.get('cmdline') or '').lower()
    exe = (info.get('exe') or '').lower()
    comm = (info.get('comm') or '').lower()

    # 明确的探针痕迹
    if 'intlink_probe' in cmd or 'intlink_doctor' in cmd or 'intlink-out-' in cmd:
        return True
    if '/parse.py' in cmd or exe.endswith('/parse.py'):
        return True

    # 探针自身的解释器进程（bash/python）才排除，且必须由本进程链确认，
    # 不能只凭 comm 就排（否则同机的 bash 全被排掉）
    if self_pid and pid == self_pid:
        return True
    if pid in self_chain:
        # 祖先里只排「解释器」这一层，不排 sshd/init/systemd 这类会话基础设施
        infra = {'sshd', 'systemd', 'init', 'init(Ubuntu)', 'login',
                 'su', 'sudo', 'tmux', 'screen', 'cron', 'dbus-daemon'}
        if comm in infra:
            return False
        return True
    return False


def self_process_chain(max_depth=12):
    """本进程 + 所有祖先（用于识别探针链路，不含基础设施判断）。"""
    chain = set()
    pid = str(os.getpid())
    for _ in range(max_depth):
        chain.add(pid)
        try:
            with open('/proc/%s/status' % pid) as f:
                ppid = None
                for ln in f:
                    if ln.startswith('PPid:'):
                        ppid = ln.split()[1]; break
            if not ppid or ppid == '0' or ppid in chain:
                break
            pid = ppid
        except Exception:
            break
    return chain


def discover_configs(cwd, exe, limit=8):
    """命令行没给配置文件时，按 cwd/exe 邻近目录找（配置常在 conf/ config/）。"""
    bases = []
    if cwd and os.path.isdir(cwd):
        bases.append(cwd)
    exed = os.path.dirname(exe or '')
    if exed and os.path.isdir(exed):
        bases.append(exed)
    found = []
    for b in dict.fromkeys(bases):
        dirs = [b] + [os.path.join(b, s) for s in
                      ('conf', 'config', 'etc', 'conf.d', 'resources', 'deploy')]
        for d in dirs:
            if not os.path.isdir(d):
                continue
            try:
                names = sorted(os.listdir(d))
            except Exception:
                continue
            for nm in names:
                if not nm.endswith(CONFIG_EXT):
                    continue
                p = os.path.join(d, nm)
                if not os.path.isfile(p):
                    continue
                size = file_meta(p)['size']
                if size <= 0 or size > 4 * 1024 * 1024:
                    continue
                found.append(p)
                if len(found) >= limit:
                    return found
    return found

def fd_scan(pid):
    """返回 (socket_inodes, log_like_files, all_open_regular)"""
    inodes, logs, regular = set(), [], []
    d = '/proc/%s/fd' % pid
    try:
        names = os.listdir(d)
    except PermissionError:
        raise PermissionError('EACCES reading %s' % d)
    except Exception:
        return inodes, logs, regular
    for fd in names:
        p = os.path.join(d, fd)
        try:
            tgt = os.readlink(p)
        except Exception:
            continue
        if tgt.startswith('socket:['):
            inodes.add(tgt[8:-1])
            continue
        if not tgt.startswith('/'):
            continue
        deleted = tgt.endswith(' (deleted)')
        clean = tgt[:-len(' (deleted)')] if deleted else tgt
        if re.search(r'(?i)\.(log|log\.\d+|out|err|trace)(\.\d+)?$', clean) or \
           re.search(r'(?i)/(log|logs)/', clean):
            logs.append({'path': clean, 'fd': fd, 'deleted': deleted})
        regular.append(clean)
    return inodes, logs, regular

def file_meta(p):
    try:
        st = os.stat(p)
        return {'size': st.st_size, 'mtime': int(st.st_mtime), 'inode': st.st_ino}
    except Exception:
        return {'size': -1, 'mtime': -1, 'inode': -1}

def log_candidates_from_cmdline(cmdline, cwd):
    """从命令行里挑出配置文件与日志路径。"""
    cfgs, logpaths = [], []
    for tok in re.split(r'\s+', cmdline):
        if not tok or tok.startswith('-D') and '=' not in tok:
            continue
        cand = tok
        if '=' in tok and (tok.startswith('-D') or tok.startswith('--')):
            cand = tok.split('=', 1)[1]
        cand = cand.strip('"\'')
        if not cand.startswith('/'):
            cand = os.path.join(cwd, cand) if cwd and not cand.startswith('-') else cand
        if not cand.startswith('/'):
            continue
        if cand.endswith(CONFIG_EXT):
            cfgs.append(cand)
        elif re.search(r'(?i)\.(log|out|err)$|/(log|logs)/', cand):
            logpaths.append(cand)
    return cfgs, logpaths

SECTION_RE = re.compile(r'^\s*(?P<key>[A-Za-z0-9_.-]+)\s*:\s*(?:#.*)?$')
CHILD_LOG_KEY = re.compile(r'(?i)^\s*(?P<key>file|path|dir|directory|filename|file_name|'
                           r'log_file|logfile|log_path|location|output)\s*[:=]\s*(?P<val>\S.*)$')
LOG_SECTION_RE = re.compile(r'(?i)^(logging|log|logger|logs|log4j|logback|accesslog|errorlog)')

def scan_config(p):
    """在配置文件里找日志相关键。

    必须处理两种写法：
      1) 平铺  logging.file: logs/x.log  /  log.path=...
      2) 嵌套  logging:\n  file: logs/x.log   ← YAML 最常见，按单行正则必漏
    所以按「段名」跟踪：进入 logging/log 段后，缩进更深的 file/path 键也要算命中。
    """
    hits = []
    try:
        st = os.stat(p)
        if st.st_size > 4 * 1024 * 1024:
            return [('# file too large: %d bytes' % st.st_size)]
        cur_section = ''
        cur_indent = -1
        with open(p, 'r', errors='replace') as f:
            for i, ln in enumerate(f, 1):
                if len(ln) > 2000:
                    continue
                hit = False
                if LOG_KEY_RE.search(ln):
                    hit = True
                m = SECTION_RE.match(ln.rstrip())
                if m:
                    indent = len(ln) - len(ln.lstrip())
                    if LOG_SECTION_RE.match(m.group('key')):
                        cur_section, cur_indent = m.group('key').lower(), indent
                    elif cur_indent >= 0 and indent <= cur_indent:
                        cur_section, cur_indent = '', -1
                    hit = hit or bool(cur_section)
                elif cur_section:
                    indent = len(ln) - len(ln.lstrip())
                    if ln.strip() and indent <= cur_indent and not ln.lstrip().startswith('#'):
                        cur_section, cur_indent = '', -1
                    elif CHILD_LOG_KEY.match(ln):
                        hit = True
                if hit:
                    hits.append('%s:%d: %s' % (p, i, ln.rstrip()[:400]))
                if len(hits) >= 40:
                    hits.append('%s: <truncated at 40 hits>' % p)
                    break
    except Exception as e:
        hits.append('%s: <unreadable: %s>' % (p, e))
    return hits

EP_RE = re.compile(
    r'(?:(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://)?'
    r'(?P<host>(?:\d{1,3}(?:\.\d{1,3}){3})|(?:\[[0-9a-fA-F:]+\])|(?:[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z]{2,}))'
    r'(?::(?P<port>\d{1,5}))?')
EP_SCHEME_PORT = {'http': 80, 'https': 443, 'ftp': 21, 'sftp': 22, 'ssh': 22,
                  'telnet': 23, 'ws': 80, 'wss': 443, 'kafka': 9092, 'amqp': 5672,
                  'redis': 6379, 'mysql': 3306, 'postgresql': 5432, 'jdbc': 0}

# ── 有效配置提取 ──────────────────────────────────────────────────
# 目标：把「程序里/配置里声明的行为参数」抽成结构化键值，供 Windows 侧
# 拿去和抓包实测行为对照。这是本工具唯一能给出「修复方向」而不是
# 「现象描述」的地方，所以抽取必须保守：宁可抽不到，也不许瞎猜。
TIME_KEY_RE = re.compile(
    r'(?i)(timeout|time_out|read_timeout|write_timeout|connect_timeout|'
    r'socket_timeout|so_timeout|idle_timeout|keepalive|keep_alive|'
    r'retry|retries|retry_count|max_attempts|max_retries|'
    r'interval|period|delay|backoff|pool_size|max_conn|max_connections|'
    r'connect_timeout_ms|read_timeout_ms)')
CONN_KEY_RE = re.compile(
    r'(?i)(endpoint|url|uri|host|addr|address|server|base_url|baseurl|'
    r'peer|target|upstream|push_url|report_url|port)')

# 值里带单位的时长：30s / 5000ms / 2m / 1h / 3000000（毫秒）
DUR_RE = re.compile(r'(?i)^\s*["\']?(\d+(?:\.\d+)?)\s*(ms|s|sec|secs|seconds?|m|min|mins|h|hour|hours)?\s*["\']?\s*$')
NUM_RE = re.compile(r'^\s*["\']?(\d+)\s*["\']?\s*$')

KV_YAML = re.compile(r'^\s*(?P<k>[A-Za-z0-9_.\-]+)\s*:\s*(?P<v>.+?)\s*$')
KV_PROPS = re.compile(r'^\s*(?P<k>[A-Za-z0-9_.\-]+)\s*[=:]\s*(?P<v>.+?)\s*$')


def parse_duration_ms(raw):
    """把 "30s" / "5000ms" / "3000000" 归一成毫秒。

    纯数字没有单位时无法确定是秒还是毫秒 —— 这种情况返回 (值, 'unknown')，
    绝不替用户假设。带单位才给确定单位。
    """
    m = DUR_RE.match(str(raw).strip())
    if not m:
        return None
    val = float(m.group(1))
    unit = (m.group(2) or '').lower()
    if not unit:
        return (int(val), 'unitless')
    if unit in ('ms',):
        return (int(val), 'ms')
    if unit in ('s', 'sec', 'secs', 'second', 'seconds'):
        return (int(val * 1000), 'ms')
    if unit in ('m', 'min', 'mins'):
        return (int(val * 60000), 'ms')
    if unit in ('h', 'hour', 'hours'):
        return (int(val * 3600000), 'ms')
    return None


def extract_config_kv(path, max_keys=200):
    """从配置文件抽「行为参数」键值（超时/重试/连接地址/池大小）。

    支持 yaml/properties/ini/json 的常见平铺写法；嵌套按「段.键」拼路径，
    这样 logging.file 和 push.timeout 都能保留上下文，报告里不会歧义。
    """
    out = []
    try:
        st = os.stat(path)
        if st.st_size > 4 * 1024 * 1024:
            return out
        with open(path, 'r', errors='replace') as f:
            lines = f.readlines()
    except Exception:
        return out

    # 简单栈式缩进跟踪，用于 yaml 嵌套
    stack = []   # [(indent, key)]

    def full_key(k):
        parts = [s[1] for s in stack] + [k]
        return '.'.join(p for p in parts if p)

    for i, ln in enumerate(lines, 1):
        if not ln.strip() or ln.lstrip().startswith(('#', ';', '!', '--')):
            continue
        if len(ln) > 2000:
            continue
        indent = len(ln) - len(ln.lstrip())
        m = KV_YAML.match(ln.rstrip())
        if not m:
            m = KV_PROPS.match(ln.rstrip())
        if not m:
            continue
        k = m.group('k').strip()
        v = m.group('v').strip()
        # 值还是空的 → 这是一个新段，压栈
        if v == '' or v.startswith('#'):
            while stack and stack[-1][0] >= indent:
                stack.pop()
            stack.append((indent, k))
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        fk = full_key(k)
        v = v.split(' #')[0].split('\t#')[0].strip()
        v = v.strip('"\'')
        if not v or v.startswith('{') or v.startswith('['):
            continue
        if TIME_KEY_RE.search(k) or TIME_KEY_RE.search(fk):
            # 只有「时长类」键才尝试解析成毫秒。retry/interval 这类是次数/秒数，
            # 一律当 duration 会在报告里显示成「1 ms」，让人误读。
            is_dur_key = bool(re.search(
                r'(?i)(timeout|time_out|delay|backoff|keepalive|keep_alive|'
                r'interval|period)', k))
            dur = parse_duration_ms(v)
            if is_dur_key and dur is not None:
                out.append({'key': fk, 'raw': v, 'kind': 'duration',
                            'value_ms': dur[0], 'unit_src': dur[1],
                            'file': path, 'line': i})
                if len(out) >= max_keys:
                    return out
                continue
            n = NUM_RE.match(v)
            if n:
                out.append({'key': fk, 'raw': v, 'kind': 'number',
                            'value_ms': None, 'unit_src': 'none',
                            'file': path, 'line': i})
                if len(out) >= max_keys:
                    return out
                continue
        if CONN_KEY_RE.search(k) or CONN_KEY_RE.search(fk):
            eps = extract_endpoints(v, 3)
            if eps:
                for host, port, scheme in eps:
                    out.append({'key': fk, 'raw': v, 'kind': 'endpoint',
                                'value_ms': None, 'unit_src': '',
                                'host': host, 'port': port,
                                'file': path, 'line': i})
            elif k.lower().endswith('port') and v.isdigit():
                out.append({'key': fk, 'raw': v, 'kind': 'port',
                            'value_ms': None, 'unit_src': '',
                            'host': '', 'port': int(v),
                            'file': path, 'line': i})
            if len(out) >= max_keys:
                return out
    return out


def extract_endpoints(text, max_n=24):
    """从任意文本里抽对端 host:port。这是抓包过滤条件最实际的来源：
    短连接在 /proc/<pid>/fd 快照里常常抓不到 ESTABLISHED，但配置和日志里
    一定有对端地址。返回 [(host, port, 依据)]，port=0 表示没写端口。"""
    out, seen = [], set()
    for m in EP_RE.finditer(text or ''):
        host = m.group('host'); port = m.group('port'); scheme = (m.group('scheme') or '').lower()
        if not port:
            port = EP_SCHEME_PORT.get(scheme, 0)
        try:
            port = int(port or 0)
        except Exception:
            port = 0
        if host.startswith('['):
            host = host.strip('[]')
        # 丢掉明显的版本号/无意义匹配（1.2.3 之类已在正则里被 4 段限制）
        if port == 0 and not scheme:
            continue
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        out.append((host, port, scheme or 'bare'))
        if len(out) >= max_n:
            break
    return out

def nearby_logs(cwd, exe, window_start, want=6):
    """兜底：cwd / exe 目录下近期改动的日志文件。"""
    dirs = []
    for base in (cwd, os.path.dirname(exe or '')):
        if not base or not os.path.isdir(base):
            continue
        dirs.append(base)
        for sub in ('log', 'logs', 'data/logs'):
            p = os.path.join(base, sub)
            if os.path.isdir(p):
                dirs.append(p)
    found = []
    for d in dict.fromkeys(dirs):
        try:
            for nm in os.listdir(d):
                if not re.search(r'(?i)\.(log|log\.\d+|out|err)$', nm):
                    continue
                p = os.path.join(d, nm)
                m = file_meta(p)
                if m['mtime'] < 0:
                    continue
                if window_start and m['mtime'] < window_start - 3600:
                    continue
                found.append((m['mtime'], p))
        except Exception:
            continue
    found.sort(reverse=True)
    return [p for _, p in found[:want]]

def extract_window(path, start, end, out_path, max_bytes, assume_tz):
    """把窗口内的行切出来；解析不出时间的行按位置保留。"""
    total = 0; kept = 0; first_ts = last_ts = None; parsed = 0; unparsed = 0
    try:
        f = open(path, 'r', errors='replace')
    except Exception as e:
        return {'ok': False, 'err': str(e), 'kept': 0}
    with f, open(out_path, 'w', errors='replace') as o:
        for ln in f:
            total += 1
            ts = parse_ts(ln, assume_tz)
            if ts is None:
                unparsed += 1
                continue
            parsed += 1
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            if start - 5 <= ts <= end + 5:
                b = len(ln.encode('utf-8', 'replace'))
                if kept + b > max_bytes:
                    o.write('... <TRUNCATED: reached --max-log-mb=%s>\n' % (max_bytes // (1024*1024)))
                    break
                o.write(ln)
                kept += b
    return {'ok': True, 'lines_total': total, 'lines_parsed': parsed,
            'lines_unparsed': unparsed, 'kept_bytes': kept,
            'first_ts': first_ts, 'last_ts': last_ts}

def selftest():
    rc = 0
    tz = timezone(timedelta(hours=8))
    cases = [
        ('2026-11-10 15:09:58 INFO x', True),
        ('2026-11-10T15:09:58.123+08:00 x', True),
        ('[10/Nov/2026:15:09:58 +0800] "GET"', True),
        ('1731232198.5 x', True),
        ('no timestamp here', False),
    ]
    for s, want in cases:
        got = parse_ts(s, tz) is not None
        if got != want:
            print('FAIL ts %r want=%s got=%s' % (s, want, got)); rc = 1
    if rc == 0:
        print('PASS ts_parsing')
    if hex_to_addr('0100007F:1F90')[:2] != ('127.0.0.1', 8080):
        print('FAIL hex_to_addr'); rc = 1
    else:
        print('PASS hex_to_addr')
    try:
        if hex_to_addr('00000000000000000000000001000000:0050')[0] != '::1':
            print('FAIL hex_to_addr_v6 got=%s' % hex_to_addr('00000000000000000000000001000000:0050')[0]); rc = 1
        else:
            print('PASS hex_to_addr_v6')
    except Exception as e:
        print('FAIL hex_to_addr_v6 %s' % e); rc = 1
    return rc

def reslice_only(a, evd, win_start, win_end, max_log_bytes, assume_tz,
                 gaps, gap):
    """只重切日志窗口，不重跑进程发现。

    抓包结束后必须再切一次：解析阶段切的窗口在抓包开始前就定死了，
    抓包期间产生的日志（真正要复现的那批）一行都进不去。
    日志文件清单从 40_logs.tsv 读回来，保证两次切的是同一批文件。
    """
    rows = []
    p = os.path.join(evd, '40_logs.tsv')
    try:
        with open(p, 'r', errors='replace') as f:
            head = f.readline().rstrip('\n').split('\t')
            for ln in f:
                vals = ln.rstrip('\n').split('\t')
                if len(vals) < len(head):
                    continue
                rows.append(dict(zip(head, vals)))
    except Exception as e:
        gap('重切日志时读不到 40_logs.tsv: %s' % e)
        return

    if not rows:
        gap('重切日志时日志清单为空（解析阶段没找到日志文件）')
        return

    # 清掉旧切片，避免旧窗口的内容与新的混在一起
    slicedir = os.path.join(evd, '41_log_slices')
    try:
        for nm in os.listdir(slicedir):
            fp = os.path.join(slicedir, nm)
            if os.path.isfile(fp):
                os.unlink(fp)
    except Exception:
        pass

    slice_meta = []
    kept_any = 0
    for r in rows:
        path = r.get('path', '')
        if not path:
            continue
        base = re.sub(r'[^A-Za-z0-9._-]', '_', path.strip('/'))[-120:]
        outp = os.path.join(slicedir, 'pid%s_%s' % (r.get('pid', '0'), base))
        res = extract_window(path, win_start, win_end, outp, max_log_bytes,
                             assume_tz)
        meta = dict(r); meta['slice'] = os.path.basename(outp)
        meta['phase'] = a.get('phase', '')
        meta.update(res)
        slice_meta.append(meta)
        if res.get('ok') and res.get('kept_bytes', 0) > 0:
            kept_any += 1
        elif not res.get('ok'):
            gap('日志切不出窗口: %s (%s)' % (path, res.get('err')))

    if kept_any == 0:
        gap('抓包窗口内所有日志切片都是空的：这份日志在复现期间没有任何输出'
            '（可能日志级别太高、或日志写到了别的地方）')

    with open(os.path.join(evd, '42_log_slice_meta.json'), 'w') as f:
        json.dump(slice_meta, f, indent=1, default=str)

    with open(os.path.join(evd, '91_parse_gaps.txt'), 'w') as f:
        f.write('\n'.join(gaps) + '\n')

    print(json.dumps({'phase': a.get('phase', ''), 'slices': len(slice_meta),
                      'non_empty': kept_any, 'gaps': len(gaps)},
                     ensure_ascii=False))


def main():
    if '--selftest' in sys.argv:
        return selftest()
    a = json.loads(sys.argv[1])
    evd = a['evd']; hints = a['hints']; pids_in = a['pids']
    auto = a['auto']; win_start = a['win_start']; win_end = a['win_end']
    max_log_bytes = a['max_log_mb'] * 1024 * 1024
    assume_tz = timezone(timedelta(seconds=time.timezone * -1))

    gaps = []
    def gap(msg):
        gaps.append(msg)

    if a.get('reslice_only'):
        return reslice_only(a, evd, win_start, win_end, max_log_bytes,
                            assume_tz, gaps, gap)

    procs = collect_procs()

    # 1) 选进程
    matched = {}
    self_chain = self_process_chain()
    if pids_in:
        for p in pids_in:
            p = str(p).strip()
            if p.isdigit() and os.path.isdir('/proc/' + p):
                matched[p] = 'explicit_pid'
            else:
                gap('指定 PID 不存在: %s' % p)
    for h in hints:
        h = (h or '').strip()
        if not h:
            continue
        if h.isdigit() and os.path.isdir('/proc/' + h):
            matched.setdefault(h, 'hint_pid')
            continue
        scored = []
        self_pid = str(os.getpid())
        for pid, info in procs.items():
            if pid == '__meta__':
                continue
            if is_noise_proc(pid, info, self_chain, self_pid):
                continue
            sc = score_hint(info, h)
            if sc > 0:
                scored.append((sc, pid))
        if not scored:
            meta = procs.get('__meta__') or {}
            extra = ''
            if meta.get('unreadable_cmdline'):
                extra = ('。注意：本机有 %d 个进程的 cmdline 读不到（通常是别的用户的进程，'
                         '非 root 读 /proc/<pid>/cmdline 会返回空），这类进程只能用 '
                         'comm/exe 匹配；必要时用 --pid 直接指定'
                         % meta.get('unreadable_cmdline'))
            gap('线索 "%s" 没有匹配到任何进程（已排除探针自身链路）%s' % (h, extra))
            continue
        # 只取最高分那一档，避免把一个子串命中的 shell 也当成对接件
        top = max(s for s, _ in scored)
        for sc, pid in scored:
            if sc == top:
                matched.setdefault(pid, 'hint:%s(score=%d)' % (h, sc))
        if top < 70:
            gap('线索 "%s" 只有弱匹配（score=%d，仅 cmdline 子串），可能是同一台机器上'
                '命令行里恰好含这个词的无关进程。请用 --pid 或更精确的 --hint 复核' % (h, top))
    if not matched and auto:
        # 自动挑有对外 ESTABLISHED 的候选
        for pid in list(procs):
            if pid == '__meta__':
                continue
            try:
                inodes, _, _ = fd_scan(pid)
            except Exception:
                continue
            if not inodes:
                continue
            tab = read_socket_table(pid)
            for ino in inodes:
                r = tab.get(ino)
                if r and r['state'] == 'ESTABLISHED' and not r['remote_ip'].startswith(('127.', '::1')):
                    matched.setdefault(pid, 'auto_outbound')
                    break
    if not matched:
        gap('没有匹配到任何候选进程（hints=%s）。可用 --auto 或给更精确的 --hint/--pid' % (hints,))

    # 2) 逐进程采集
    sock_rows = []          # 五元组明细
    proc_rows = []          # 进程明细
    log_rows = []           # 日志候选
    fd_evidence = []
    filter_hosts = set()    # 非回环对端 IP，用于抓包过滤 host
    filter_ports = set()    # 监听端口 + 对端端口，用于抓包过滤 port
    ep_rows = []            # 对端候选（配置/日志/命令行里抽出来的地址）
    ep_seen = set()
    kv_rows = []            # 有效配置键值（超时/重试/池大小/连接地址）

    for pid, why in sorted(matched.items(), key=lambda kv: int(kv[0])):
        meta = proc_meta(pid)
        info = procs.get(pid, {})
        fd_denied = False
        try:
            inodes, logfds, regular = fd_scan(pid)
        except PermissionError as e:
            # 非 root 读别的用户的 /proc/<pid>/fd 会被拒。这不是致命错误：
            # socket 还能靠 uid 从 netns 的 tcp 表里反查（下面 fallback），
            # 日志则确实拿不到 fd 路径，只能靠配置/命令行/邻近目录。
            gap('PID %s 的 /proc/%s/fd 不可读（权限拒绝），已降级：'
                'socket 按 uid 从 netns 表反查，日志路径改从配置与命令行推断' % (pid, pid))
            inodes, logfds, regular = set(), [], []
            fd_denied = True
        tab = read_socket_table(pid)
        if not tab:
            gap('PID %s 的 netns socket 表读不到（权限或命名空间隔离）' % pid)

        # fallback：fd 不可读时，用进程 uid 从同 netns 的 tcp 表里筛出属于它的 socket。
        # 代价是会把同 uid 其它进程的连接也算进来，所以必须把这一点写进报告。
        if fd_denied and tab:
            uid = str(meta.get('uid') or '')
            cand = [ino for ino, r in tab.items() if str(r.get('uid')) == uid]
            if cand:
                inodes = set(cand)
                gap('PID %s 的 socket 是按 uid=%s 推断的（%d 条），'
                    '同一用户下的其他进程连接会混进来，需人工确认'
                    % (pid, uid, len(cand)))

        # 解析 shell 侧之前先算，供 --auto 用；这里不重复
        my_socks = []
        for ino in inodes:
            r = tab.get(ino)
            if r:
                my_socks.append(r)
            else:
                my_socks.append({'family': '-', 'local_ip': '?', 'local_port': '?',
                                 'remote_ip': '?', 'remote_port': '?',
                                 'state': 'NOT_IN_TABLE', 'tx_queue': '0', 'rx_queue': '0',
                                 'uid': '', 'inode': ino})
        for r in my_socks:
            sock_rows.append({
                'pid': pid, 'why': why, 'state': r['state'], 'family': r['family'],
                'local': '%s:%s' % (r['local_ip'], r['local_port']),
                'remote': '%s:%s' % (r['remote_ip'], r['remote_port']),
                'inode': r['inode'], 'txq': r['tx_queue'], 'rxq': r['rx_queue'],
                'netns': meta.get('netns', ''),
            })
            rip = str(r['remote_ip'])
            rport = r['remote_port']
            lp = r['local_port']
            # 端口永远可用；host 只收非回环（回环上用 host 127.0.0.1 会抓到满屏无关流量）
            if r['state'] == 'LISTEN':
                try:
                    filter_ports.add(int(lp))
                except Exception:
                    pass
            elif r['state'] == 'ESTABLISHED':
                try:
                    filter_ports.add(int(rport))
                except Exception:
                    pass
                if not rip.startswith(('127.', '::1', '0.0.0.0', '::', '?')):
                    filter_hosts.add(rip)

        # 五元组去重后给抓包过滤用
        proc_rows.append({
            'pid': pid, 'why': why, 'user': meta.get('user', ''),
            'comm': info.get('comm', ''), 'exe': info.get('exe', ''),
            'cwd': meta.get('cwd', ''), 'netns': meta.get('netns', ''),
            'container_id': meta.get('container_id', ''),
            'start_epoch': meta.get('start_epoch', ''),
            'cmdline': info.get('cmdline', '')[:900],
            'socket_count': len(inodes),
        })

        # 日志：fd 优先，其次命令行与配置
        seen = set()
        for lf in logfds:
            if lf['path'] in seen:
                continue
            seen.add(lf['path'])
            mt = file_meta(lf['path'])
            log_rows.append({'pid': pid, 'source': 'fd' + ('(deleted)' if lf['deleted'] else ''),
                             'path': lf['path'], 'size': mt['size'], 'mtime': mt['mtime'],
                             'fd': lf['fd']})
        cfgs, logpaths = log_candidates_from_cmdline(info.get('cmdline', ''), meta.get('cwd', ''))
        for p in logpaths:
            if p in seen:
                continue
            seen.add(p)
            mt = file_meta(p)
            log_rows.append({'pid': pid, 'source': 'cmdline', 'path': p,
                             'size': mt['size'], 'mtime': mt['mtime'], 'fd': ''})
        for p in nearby_logs(meta.get('cwd', ''), info.get('exe', ''), win_start):
            if p in seen:
                continue
            seen.add(p)
            mt = file_meta(p)
            log_rows.append({'pid': pid, 'source': 'nearby', 'path': p,
                             'size': mt['size'], 'mtime': mt['mtime'], 'fd': ''})

        # 配置文件：命令行给了就用命令行的；没给就按 cwd/exe 邻近目录找，
        # 否则 logging.file 这类键永远扫不到（实测漏检）。
        cfgs_extra = []
        if not cfgs:
            cfgs = discover_configs(meta.get('cwd', ''), info.get('exe', ''))
            if cfgs:
                cfgs_extra = cfgs

        fd_evidence.append('== PID %s (%s) ==' % (pid, why))
        fd_evidence.append('  exe=%s' % info.get('exe', ''))
        fd_evidence.append('  cwd=%s' % meta.get('cwd', ''))
        fd_evidence.append('  netns=%s' % meta.get('netns', ''))
        fd_evidence.append('  container_id=%s' % (meta.get('container_id') or '-'))
        fd_evidence.append('  open_regular_files: %d' % len(regular))
        for f in sorted(set(regular))[:80]:
            fd_evidence.append('    %s' % f)
        src = 'cmdline' if not cfgs_extra else 'discovered'
        fd_evidence.append('  config_candidates(%s): %s' % (src, cfgs or '-'))

        # 配置里找日志键；同时从命中的行里回捞日志路径
        cfg_log_paths = []
        for c in cfgs:
            for h in scan_config(c):
                fd_evidence.append('  %s' % h)
                mm = re.search(r'(?i)(?:log[._-]?(?:file|path|dir)|logfile|file|path|dir)'
                               r'\s*[:=]\s*["\']?(?P<v>[^\s"\'#,}]+)', h)
                if mm:
                    lp = mm.group('v')
                    if not re.search(r'(?i)\.(log|out|err)$|/', lp):
                        continue
                    if not lp.startswith('/'):
                        lp = os.path.join(meta.get('cwd', '') or '/', lp)
                    cfg_log_paths.append(lp)
        for p in cfg_log_paths:
            if p in seen:
                continue
            seen.add(p)
            mt = file_meta(p)
            if mt['size'] <= 0:
                gap('配置里声明的日志路径打不开或为空: %s（PID %s）' % (p, pid))
                continue
            log_rows.append({'pid': pid, 'source': 'config', 'path': p,
                             'size': mt['size'], 'mtime': mt['mtime'], 'fd': ''})

        # 对端候选：短连接快照抓不到 ESTABLISHED，配置/日志/命令行里的地址才是可靠来源
        ep_sources = [('cmdline', info.get('cmdline', ''))]
        for c in cfgs:
            try:
                if file_meta(c)['size'] <= 4 * 1024 * 1024:
                    with open(c, 'r', errors='replace') as f:
                        ep_sources.append(('config:' + os.path.basename(c), f.read()))
            except Exception:
                pass
        for lr in log_rows:
            if lr['pid'] != pid:
                continue
            try:
                with open(lr['path'], 'rb') as f:
                    f.seek(0, 2)
                    size = f.tell()
                    f.seek(max(0, size - 512 * 1024))
                    ep_sources.append(('log:' + os.path.basename(lr['path']),
                                       f.read().decode('utf-8', 'replace')))
            except Exception:
                pass
        for src_name, text in ep_sources:
            for host, port, scheme in extract_endpoints(text):
                key = (host, port)
                if key in ep_seen:
                    continue
                ep_seen.add(key)
                ep_rows.append({'pid': pid, 'host': host, 'port': port,
                                'scheme': scheme, 'evidence': src_name})

        # 有效配置：抽超时/重试/池大小/连接地址，供本地与实测行为对照
        cfg_sources = list(cfgs)
        # 命令行里的 -Dkey=value 也是生效配置（Java 常见），一并抽
        for m in re.finditer(r'-D([A-Za-z0-9_.\-]+)=([^\s]+)', info.get('cmdline', '')):
            kv_rows.append({'pid': pid, 'key': m.group(1), 'raw': m.group(2),
                            'kind': 'cmdline_sysprop', 'value_ms': None,
                            'unit_src': '', 'host': '', 'port': '',
                            'file': 'cmdline', 'line': 0})
        for c in cfg_sources:
            for kv in extract_config_kv(c):
                kv['pid'] = pid
                kv_rows.append(kv)

    # 3) 输出 TSV
    with open(os.path.join(evd, '20_procs.tsv'), 'w', errors='replace') as f:
        cols = ['pid','why','user','comm','exe','cwd','netns','container_id','start_epoch','socket_count','cmdline']
        f.write('\t'.join(cols) + '\n')
        for r in proc_rows:
            f.write('\t'.join(str(r.get(c, '')).replace('\t', ' ') for c in cols) + '\n')

    with open(os.path.join(evd, '30_sockets.tsv'), 'w', errors='replace') as f:
        cols = ['pid','why','state','family','local','remote','inode','txq','rxq','netns']
        f.write('\t'.join(cols) + '\n')
        for r in sock_rows:
            f.write('\t'.join(str(r.get(c, '')).replace('\t', ' ') for c in cols) + '\n')

    with open(os.path.join(evd, '40_logs.tsv'), 'w', errors='replace') as f:
        cols = ['pid','source','path','size','mtime','fd']
        f.write('\t'.join(cols) + '\n')
        for r in log_rows:
            f.write('\t'.join(str(r.get(c, '')).replace('\t', ' ') for c in cols) + '\n')

    with open(os.path.join(evd, '55_fd_evidence.txt'), 'w', errors='replace') as f:
        f.write('\n'.join(fd_evidence) + '\n')

    # 4) 日志切片（每份文件一份，带元信息）
    slice_meta = []
    for r in log_rows:
        p = r['path']
        base = re.sub(r'[^A-Za-z0-9._-]', '_', p.strip('/'))[-120:]
        outp = os.path.join(evd, '41_log_slices', 'pid%s_%s' % (r['pid'], base))
        res = extract_window(p, win_start, win_end, outp, max_log_bytes, assume_tz)
        meta = dict(r); meta['slice'] = os.path.basename(outp); meta.update(res)
        slice_meta.append(meta)
        if not res.get('ok'):
            gap('日志切不出窗口: %s (%s)' % (p, res.get('err')))
    with open(os.path.join(evd, '42_log_slice_meta.json'), 'w') as f:
        json.dump(slice_meta, f, indent=1, default=str)

    # 5) 抓包过滤提示
    #   合并两类来源：socket 表里真实看到的（最强）+ 配置/日志/命令行里抽到的对端候选。
    #   候选 host 只收公网/非回环、非本机的地址，否则过滤条件会被本机服务名塞爆。
    local_ips = set()
    try:
        for fam in ('fib_trie',):
            with open('/proc/net/' + fam, 'r', errors='replace') as f:
                for ln in f:
                    p = ln.split()
                    if len(p) >= 2 and '/' in p[1]:
                        local_ips.add(p[1].split('/')[0])
    except Exception:
        pass

    for r in ep_rows:
        host, port = r['host'], r['port']
        try:
            addr = ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            addr, is_ip = None, False
        if is_ip:
            if addr.is_loopback or addr.is_unspecified or addr.is_link_local:
                if port:
                    filter_ports.add(port)
                continue
            if str(addr) in local_ips:
                continue
            filter_hosts.add(host)
        else:
            # 域名只用作提示，不直接进 tcpdump（要解析，且多 A 记录会漏）
            pass
        if port and port < 65536:
            filter_ports.add(port)

    lines = []
    for h in sorted(filter_hosts):
        lines.append('peer_host\t%s' % h)
    for p in sorted(filter_ports):
        lines.append('port\t%d' % p)
    with open(os.path.join(evd, '35_filter_hints.txt'), 'w') as f:
        f.write('\n'.join(lines) + '\n')

    with open(os.path.join(evd, '34_endpoint_candidates.tsv'), 'w', errors='replace') as f:
        f.write('pid\thost\tport\tscheme\tevidence\n')
        for r in ep_rows:
            f.write('\t'.join(str(r[k]) for k in ('pid','host','port','scheme','evidence')) + '\n')

    # 39_config_kv.tsv：生效配置键值，供 Windows 侧做「配置 vs 实测」对照
    with open(os.path.join(evd, '39_config_kv.tsv'), 'w', errors='replace') as f:
        cols = ['pid','key','raw','kind','value_ms','unit_src','host','port','file','line']
        f.write('\t'.join(cols) + '\n')
        for r in kv_rows:
            f.write('\t'.join(str(r.get(c, '')).replace('\t', ' ').replace('\n', ' ')
                              for c in cols) + '\n')

    with open(os.path.join(evd, '91_parse_gaps.txt'), 'w') as f:
        f.write('\n'.join(gaps) + '\n')

    print(json.dumps({'procs': len(proc_rows), 'sockets': len(sock_rows),
                      'logs': len(log_rows), 'peers': len(filter_hosts),
                      'ports': sorted(filter_ports), 'config_kv': len(kv_rows),
                      'gaps': len(gaps)},
                     ensure_ascii=False))
    return 0

if __name__ == '__main__':
    sys.exit(main())
PYEOF

[ -f "$PY_SCRIPT" ] || die "parse.py 写不出来"

# ── 调用解析器 ────────────────────────────────────────────────────
END_EPOCH="$(date +%s)"
if [ -n "$PY3" ]; then
  say "解析进程/端口/日志..."
  HINTS_JSON="$(
    if [ "${#HINTS[@]}" -gt 0 ]; then
      printf '%s\n' "${HINTS[@]}" | "$PY3" -c 'import sys,json;print(json.dumps([l.rstrip("\n") for l in sys.stdin if l.strip()]))'
    else printf '[]'; fi
  )"
  PIDS_JSON="$(
    if [ "${#PIDS[@]}" -gt 0 ]; then
      printf '%s\n' "${PIDS[@]}" | "$PY3" -c 'import sys,json;print(json.dumps([l.rstrip("\n") for l in sys.stdin if l.strip()]))'
    else printf '[]'; fi
  )"
  ARGS_JSON="$(printf '{"evd":"%s","hints":%s,"pids":%s,"auto":%s,"win_start":%s,"win_end":%s,"max_log_mb":%s}' \
    "$EVD" "$HINTS_JSON" "$PIDS_JSON" \
    "$([ "$AUTO_PICK" = 1 ] && echo true || echo false)" \
    "$((START_EPOCH - WINDOW_SECS))" "$((END_EPOCH + 120))" "$MAX_LOG_MB")"
  if ! "$PY3" "$PY_SCRIPT" "$ARGS_JSON" 2>"$EVD/92_parse_stderr.txt"; then
    gap "解析器执行失败，见 92_parse_stderr.txt"
  fi
else
  gap "python3/python 都不存在，跳过 /proc 结构化解析；仅用 ss/ps 做降级采集"
  {
    echo '== ps =='
    T 10 ps -eo pid,ppid,user,etimes,args 2>/dev/null | head -200
    echo ''
    echo '== ss -tnp =='
    T 10 ss -tnp 2>/dev/null | head -300
    echo ''
    echo '== ss -tlnp =='
    T 10 ss -tlnp 2>/dev/null | head -100
  } > "$EVD/25_fallback_ps_ss.txt" 2>&1
  : > "$EVD/20_procs.tsv"; : > "$EVD/30_sockets.tsv"; : > "$EVD/40_logs.tsv"
  T 10 ss -tn 2>/dev/null | awk 'NR>1{print $1"\t"$4"\t"$5}' > "$EVD/30_sockets.tsv" || true
fi

# 补充：全局视图（不依赖 python）
say "采集全局连接视图..."
{
  echo '== ss -tnp (all) =='
  T 10 ss -tnp 2>/dev/null | head -300
  echo ''
  echo '== ss -tnHi (retransmit/queue) =='
  T 10 ss -tnHi 2>/dev/null | head -200
  echo ''
  echo '== conntrack (if any) =='
  T 10 conntrack -L 2>/dev/null | head -100 || echo '<no conntrack>'
} > "$EVD/15_ss_global.txt" 2>&1

# 服务的 systemd 状态（只读查询）
{
  echo '== matching systemd units =='
  if have systemctl; then
    T 10 systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null \
      | head -80 | sed 's/^/  /'
    for h in "${HINTS[@]:-}"; do
      [ -z "$h" ] && continue
      u="$(T 10 systemctl list-units --type=service --no-pager --no-legend 2>/dev/null | grep -i -- "$h" | head -3 || true)"
      [ -n "$u" ] && printf '  HINT[%s] -> %s\n' "$h" "$u"
    done
  else
    echo '  systemctl absent'
  fi
} > "$EVD/58_systemd.txt" 2>&1 || true

# 脱敏实现（真正执行挪到抓包+重切日志之后，见文末 redact_all）
redact_all() {
  [ "$REDACT" = 1 ] || return 0
  for f in "$EVD/05_env.txt" "$EVD/20_procs.tsv" "$EVD/40_logs.tsv" \
           "$EVD/55_fd_evidence.txt" "$EVD/58_systemd.txt" "$EVD/15_ss_global.txt" \
           "$EVD/34_endpoint_candidates.tsv" "$EVD/36_filter_used.txt"; do
    [ -f "$f" ] || continue
    mask < "$f" > "$f.masked" 2>/dev/null && mv -f "$f.masked" "$f" || rm -f "$f.masked"
  done
  # 日志切片也过一遍（凭据泄漏最常见的地方）
  if [ -d "$EVD/41_log_slices" ]; then
    for f in "$EVD/41_log_slices"/*; do
      [ -f "$f" ] || continue
      mask < "$f" > "$f.masked" 2>/dev/null && mv -f "$f.masked" "$f" || rm -f "$f.masked"
    done
  fi
}

# ── 抓包 ──────────────────────────────────────────────────────────
CAP_FILE="$EVD/60_capture/import.pcap"
CAP_LOG="$EVD/60_capture/tcpdump.log"
CAP_RESULT="$EVD/61_capture_result.txt"

build_filter() {
  # 过滤条件从 35_filter_hints.txt 统一取：peer_host 与 port 两类。
  # 只认这两种原子表达式，因为 engine 侧只会产出这两种；复杂过滤自己拼容易出语法错。
  local parts=() p ip seen_ports=" "
  if [ -s "$EVD/35_filter_hints.txt" ]; then
    while IFS=$'\t' read -r k v; do
      [ -z "$k" ] && continue
      case "$k" in
        peer_host)
          [ -z "$v" ] && continue
          case "$v" in 127.*|::1|0.0.0.0|'::'|'?'|'-') continue ;; esac
          parts+=("host $v") ;;
        port)
          case "$v" in ''|*[!0-9]*) continue ;; esac
          case "$seen_ports" in *" $v "*) continue ;; esac
          seen_ports="$seen_ports$v "
          parts+=("port $v") ;;
      esac
    done < "$EVD/35_filter_hints.txt"
  fi
  # 用户强制追加
  if [ -n "$EXTRA_PEERS" ]; then
    local IFS=','
    for ip in $EXTRA_PEERS; do [ -n "$ip" ] && parts+=("host $ip"); done
    unset IFS
  fi
  if [ -n "$EXTRA_PORTS" ]; then
    local IFS=','
    for p in $EXTRA_PORTS; do [ -n "$p" ] && parts+=("port $p"); done
    unset IFS
  fi
  if [ "${#parts[@]}" -eq 0 ]; then printf ''; return; fi
  local out="" i
  for i in "${parts[@]}"; do
    if [ -z "$out" ]; then out="$i"; else out="$out or $i"; fi
  done
  printf '%s' "$out"
}

FILTER="$(build_filter)"
{
  echo "filter=$FILTER"
  echo "secs=$SECS"
  echo "extra_ports=$EXTRA_PORTS"
  echo "extra_peers=$EXTRA_PEERS"
} > "$EVD/36_filter_used.txt"

run_capture() {
  local filter="$1" out="$2" log="$3"
  local tcp="tcpdump"
  [ "$IS_ROOT" = 0 ] && [ "$SUDO_NOPASS" = 1 ] && tcp="sudo -n tcpdump"
  # 语法预检
  if ! $tcp -d "$filter" >/dev/null 2>"$log.precheck"; then
    gap "BPF 语法预检失败，放弃抓包: $(head -2 "$log.precheck" 2>/dev/null | tr '\n' ' ')"
    return 3
  fi
  say "开始抓包 ${SECS}s  过滤: $filter"
  say ">>> 现在请在对端触发复现，窗口 ${SECS} 秒 <<<"
  printf 'CAPTURE_START now=%s filter=%s\n' "$(date -Ins)" "$filter" >> "$log"
  timeout -s INT "$SECS" $tcp -i any -n -s 0 -B 65536 -U -w "$out" "$filter" >> "$log" 2>&1
  local rc=$?
  printf 'CAPTURE_END rc=%s now=%s\n' "$rc" "$(date -Ins)" >> "$log"
  # 返回抓到的包数（从 tcpdump 自己的统计行取，最可靠）
  local n
  n="$(grep -aE 'packets captured' "$log" 2>/dev/null | tail -1 | awk '{print $1}' || true)"
  case "$n" in ''|*[!0-9]*) n=0 ;; esac
  printf '%s' "$n"
}

if [ "$CAP_OK" = 1 ] && [ -n "$FILTER" ]; then
  NPKT="$(run_capture "$FILTER" "$CAP_FILE" "$CAP_LOG")"
  NPKT="${NPKT:-0}"
  say "抓到 $NPKT 个包"
  # 0 包重试一次：放宽到纯端口/纯 host，多给 20 秒
  if [ "$NPKT" -eq 0 ]; then
    BROAD=""
    [ -n "$EXTRA_PORTS" ] && BROAD="port ${EXTRA_PORTS%%,*}"
    if [ -z "$BROAD" ] && [ -s "$EVD/35_filter_hints.txt" ]; then
      BROAD="host $(awk -F'\t' '$1=="peer_host"{print $2; exit}' "$EVD/35_filter_hints.txt")"
    fi
    if [ -n "$BROAD" ] && [ "$BROAD" != "$FILTER" ]; then
      say "0 包，用更宽的过滤条件重试: $BROAD"
      SECS=$((SECS + 20))
      NPKT="$(run_capture "$BROAD" "${CAP_FILE%.pcap}-broad.pcap" "${CAP_LOG}.broad")"
      NPKT="${NPKT:-0}"
      printf 'broad_filter=%s broad_packets=%s\n' "$BROAD" "$NPKT" >> "$CAP_LOG"
    fi
  fi
  {
    echo "capture_ok=1"
    echo "filter=$FILTER"
    echo "packets_total=$(grep -aE 'packets captured' "$CAP_LOG" 2>/dev/null | tail -1 || true)"
    ls -l "$EVD/60_capture" 2>/dev/null
    if [ "$NPKT" -gt 0 ] && have tcpdump; then
      echo ""
      echo "-- first 40 packets --"
      T 20 tcpdump -nn -r "$CAP_FILE" 2>/dev/null | head -40
    else
      echo ""
      echo "zero_packets_hint: 窗口内没有匹配流量。可能原因："
      echo "  1) 复现没有在窗口内发生"
      echo "  2) 过滤条件不对（对端 IP 变了 / 走了别的端口 / 走了 unix socket）"
      echo "  3) 流量不经过本网卡（容器 netns 或别的路由）"
    fi
  } > "$CAP_RESULT"
elif [ "$CAP_OK" = 1 ] && [ -z "$FILTER" ]; then
  gap "没有解析出任何抓包目标（既无对端 IP 也无监听端口），跳过抓包。可用 --ports/--peers 强制指定"
  { echo "capture_ok=0"; echo "reason=no_filter"; } > "$CAP_RESULT"
else
  { echo "capture_ok=0"; echo "reason=$CAP_REASON"; } > "$CAP_RESULT"
fi

# ── 日志切片（必须在抓包之后重新切一次）─────────────────────────
# 为什么放在这里而不是解析阶段：解析阶段切的窗口结束时间早于抓包开始，
# 抓包期间产生的日志（也就是真正要复现的那批）一行都进不了切片。
# 实测：先切后抓 → 切片里只有抓包开始前的历史，复现期日志全丢。
reslice_logs() {
  [ -n "$PY3" ] || return 0
  local phase="$1"
  local out_sub="41_log_slices"
  say "切日志窗口（$phase）..."
  ARGS_JSON="$(printf '{"evd":"%s","hints":[],"pids":[],"auto":false,"win_start":%s,"win_end":%s,"max_log_mb":%s,"reslice_only":true,"phase":"%s"}' \
    "$EVD" "$((START_EPOCH - WINDOW_SECS))" "$(( $(date +%s) + 60 ))" "$MAX_LOG_MB" "$phase")"
  "$PY3" "$PY_SCRIPT" "$ARGS_JSON" 2>>"$EVD/92_parse_stderr.txt" || true
}

reslice_logs "post-capture"

# 脱敏必须排在重切之后，否则新切出来的切片没被脱敏
redact_all

# ── 00_summary.txt ────────────────────────────────────────────────
say "生成摘要..."
END_ALL="$(date +%s)"
{
  echo "intlink-probe v$VERSION  证据包摘要"
  echo "================================================"
  echo "host:            $HOSTNAME_S"
  echo "采集开始:        $(date -d "@$START_EPOCH" -Ins 2>/dev/null || echo "$START_EPOCH")"
  echo "采集结束:        $(date -d "@$END_ALL" -Ins 2>/dev/null || echo "$END_ALL")"
  echo "耗时:            $((END_ALL - START_EPOCH))s"
  echo "日志回看窗口:    ${WINDOW_SECS}s（切片文件在 41_log_slices/）"
  echo "抓包窗口:        ${SECS}s"
  echo "root:            $IS_ROOT   sudo免密: $SUDO_NOPASS   容器内: $CONT_HINT"
  echo "python3:         $([ -n "$PY3" ] && echo "$PY3" || echo '缺失（已降级）')"
  echo "抓包可用:        $([ "$CAP_OK" = 1 ] && echo yes || echo "no ($CAP_REASON)")"
  echo "脱敏:            $([ "$REDACT" = 1 ] && echo yes || echo NO-RAW)"
  echo ""
  echo "-- 进程（20_procs.tsv）--"
  if [ -s "$EVD/20_procs.tsv" ]; then
    awk -F'\t' 'NR==1{next}{printf "  pid=%s why=%s user=%s comm=%s exe=%s netns=%s cid=%s\n",$1,$2,$3,$4,$5,$7,$8}' \
      "$EVD/20_procs.tsv" | head -20
  else
    echo "  <无>"
  fi
  echo ""
  echo "-- 连接（30_sockets.tsv）按状态计数 --"
  if [ -s "$EVD/30_sockets.tsv" ]; then
    awk -F'\t' 'NR>1{c[$3]++}END{for(k in c)printf "  %-14s %d\n",k,c[k]}' "$EVD/30_sockets.tsv" | sort
    echo ""
    echo "-- 对外 ESTABLISHED（前 15）--"
    awk -F'\t' 'NR>1 && $3=="ESTABLISHED" && $5 !~ /^127\.|^::1/{printf "  pid=%s %s -> %s\n",$1,$5,$6}' \
      "$EVD/30_sockets.tsv" | head -15
  else
    echo "  <无>"
  fi
  echo ""
  echo "-- 日志候选（40_logs.tsv）--"
  if [ -s "$EVD/40_logs.tsv" ]; then
    awk -F'\t' 'NR>1{printf "  pid=%s src=%-14s size=%-10s %s\n",$1,$2,$4,$3}' "$EVD/40_logs.tsv" | head -20
  else
    echo "  <无>"
  fi
  echo ""
  echo "-- 抓包 --"
  sed 's/^/  /' "$CAP_RESULT" 2>/dev/null | head -20
  echo ""
  echo "-- GAPS（采不到的都在这，报告会引用）--"
  if [ -s "$EVD/90_gaps.txt" ] || [ -s "$EVD/91_parse_gaps.txt" ]; then
    cat "$EVD/90_gaps.txt" "$EVD/91_parse_gaps.txt" 2>/dev/null | sed 's/^/  /'
  else
    echo "  <无>"
  fi
  echo ""
  echo "-- 包内文件 --"
  ( cd "$OUT_DIR" && find . -type f | sort | sed 's/^/  /' )
} > "$EVD/00_summary.txt" 2>&1

# ── 打包 ──────────────────────────────────────────────────────────
TAR="$OUT_DIR/../intlink-probe-$HOSTNAME_S-$TS.tar.gz"
say "打包..."
if ( cd "$OUT_DIR/.." && T 120 tar czf "$TAR" "$(basename "$OUT_DIR")" 2>/dev/null ); then
  :
else
  # 退化为 python 打包（路径含中文/[] 时 tar 可能静默失败）
  TAR="$OUT_DIR/intlink-probe-$HOSTNAME_S-$TS.tar.gz"
  "$PY3" - "$OUT_DIR" "$TAR" <<'PYEOF' 2>/dev/null || true
import sys, tarfile, os
outdir, tar = sys.argv[1], sys.argv[2]
with tarfile.open(tar, 'w:gz') as t:
    t.add(outdir, arcname=os.path.basename(outdir))
PYEOF
fi

if [ -f "$TAR" ] && [ "$(stat -c %s "$TAR" 2>/dev/null || echo 0)" -gt 200 ]; then
  SHA="$( (sha256sum "$TAR" 2>/dev/null || shasum -a 256 "$TAR" 2>/dev/null) | awk '{print $1}')"
  echo ""
  echo "RESULT=$TAR"
  echo "SHA256=$SHA"
  echo "SIZE=$(stat -c %s "$TAR" 2>/dev/null || echo '?')"
  say "完成。把上面 RESULT 指向的文件带回 Windows 侧分析。"
else
  say "打包失败，但证据目录仍可用: $OUT_DIR/evidence"
  echo "RESULT=$OUT_DIR/evidence"
  exit 3
fi
