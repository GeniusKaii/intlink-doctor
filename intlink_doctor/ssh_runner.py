"""SSH 编排：把采集脚本推过去、跑起来、把证据包拉回来。

设计取舍：
  - 不依赖 paramiko（内网 pip 装不上很常见），直接用系统自带的 ssh/scp。
    Windows 10+ 自带 OpenSSH，和其他 SSH 工具共用 ~/.ssh/config 与 known_hosts。
  - 密码登录不落盘、不进命令行（避免出现在 ps 里），走 SSH_ASKPASS 环境变量方式。
    更推荐密钥。密码模式下如果环境不支持 askpass，会明确报错而不是静默卡住。
  - 实时输出：解析 ssh 的 stdout/stderr 逐行喂给回调，GUI 才能滚动显示真实命令输出。
  - 证据包在目标机先落 /tmp，拉回后删掉，不在客户机留东西。
"""
from __future__ import annotations

import os
import posixpath
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid


# ── 连接参数 ──────────────────────────────────────────────────────
class Target:
    def __init__(self, host: str, user: str = "", port: int = 22,
                 key_path: str = "", password: str = "",
                 ssh_config_alias: str = "", jump: str = "",
                 ssh_exe: str = ""):
        self.host = host
        self.user = user
        self.port = int(port or 22)
        self.key_path = key_path
        self.password = password
        self.ssh_config_alias = ssh_config_alias
        self.jump = jump
        self.ssh_exe = ssh_exe or _which("ssh")
        self.scp_exe = ssh_exe.replace("ssh", "scp") if ssh_exe else _which("scp")

    @property
    def dest(self) -> str:
        """ssh 的目标串。用 alias 时直接用别名，别名里已含 host/user/port。"""
        if self.ssh_config_alias:
            return self.ssh_config_alias
        return ("%s@%s" % (self.user, self.host)) if self.user else self.host

    def common_args(self) -> list:
        a = ["-o", "BatchMode=yes" if not self.password else "BatchMode=no",
             "-o", "ConnectTimeout=10",
             "-o", "StrictHostKeyChecking=accept-new",
             "-o", "LogLevel=ERROR"]
        if self.ssh_config_alias:
            return a            # 别名模式下 port/key 都在 config 里
        if self.port and self.port != 22:
            a += ["-p", str(self.port)]
        if self.key_path:
            a += ["-i", self.key_path]
        if self.jump:
            a += ["-J", self.jump]
        return a

    def scp_common_args(self) -> list:
        a = list(self.common_args())
        # scp 用 -P 而不是 -p 表示端口
        for i, v in enumerate(a):
            if v == "-p" and i + 1 < len(a) and a[i + 1].isdigit():
                a[i] = "-P"
        return a

    def describe(self) -> str:
        if self.ssh_config_alias:
            return "ssh config 别名 %s" % self.ssh_config_alias
        return "%s@%s:%d" % (self.user or "<current>", self.host, self.port)


def _which(name: str) -> str:
    p = shutil.which(name)
    if p:
        return p
    for cand in (r"C:\Windows\System32\OpenSSH\%s.exe" % name,
                 "/usr/bin/%s" % name, "/bin/%s" % name):
        if os.path.isfile(cand):
            return cand
    return ""


# ── 结果 ──────────────────────────────────────────────────────────
class RunResult:
    def __init__(self):
        self.rc = -1
        self.stdout = ""
        self.stderr = ""
        self.remote_pkg = ""
        self.local_pkg = ""
        self.sha256 = ""
        self.error = ""
        self.duration = 0.0
        self.steps = []            # [(阶段名, 是否成功, 说明)]

    def to_dict(self):
        return {"rc": self.rc, "remote_pkg": self.remote_pkg,
                "local_pkg": self.local_pkg, "sha256": self.sha256,
                "error": self.error, "duration": round(self.duration, 1),
                "steps": self.steps}


def _try_askpass_script(password: str) -> str:
    """造一个临时 askpass 脚本，把密码从环境变量交给 ssh。

    为什么不直接 sshpass：Windows 上没有，也不该让用户装。
    Windows 上用 .bat 包一层 echo 也可以，但更稳的是用 python 小脚本。
    """
    d = tempfile.mkdtemp(prefix="intlink-askpass-")
    if os.name == "nt":
        p = os.path.join(d, "askpass.py")
        with open(p, "w", encoding="utf-8") as f:
            f.write("import os,sys\nsys.stdout.write(os.environ.get('INTLINK_PW',''))\n")
        bat = os.path.join(d, "askpass.bat")
        with open(bat, "w", encoding="utf-8") as f:
            f.write('@echo off\r\n"%s" "%s" %%*\r\n'
                    % (sys.executable, p.replace("\\", "\\\\")))
        os.chmod(bat, 0o700)
        return bat
    p = os.path.join(d, "askpass.sh")
    with open(p, "w", encoding="utf-8") as f:
        f.write('#!/bin/sh\nprintf "%s" "$INTLINK_PW"\n')
    os.chmod(p, 0o700)
    return p


def _cleanup_askpass(path: str):
    try:
        d = os.path.dirname(path)
        shutil.rmtree(d, ignore_errors=True)
    except Exception:
        pass


# ── 底层执行 ──────────────────────────────────────────────────────
def run_ssh(target: Target, remote_cmd: str, on_line=None, timeout=600) -> tuple:
    """执行远程命令，逐行回调。返回 (rc, stdout, stderr)。"""
    if not target.ssh_exe:
        return -1, "", "找不到 ssh 客户端（Windows 10+ 自带 OpenSSH，或装一个）"
    args = [target.ssh_exe] + target.common_args() + [target.dest, remote_cmd]
    env = dict(os.environ)
    askpass = ""
    if target.password:
        askpass = _try_askpass_script(target.password)
        env["SSH_ASKPASS"] = askpass
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["INTLINK_PW"] = target.password
        env.setdefault("DISPLAY", ":0")
    try:
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, text=True, encoding="utf-8", errors="replace",
            bufsize=1, stdin=subprocess.DEVNULL)
    except Exception as e:
        if askpass:
            _cleanup_askpass(askpass)
        return -1, "", "启动 ssh 失败: %s" % e

    out_lines, err_lines = [], []

    def pump(stream, bucket, tag):
        for ln in stream:
            bucket.append(ln.rstrip("\n"))
            if on_line:
                try:
                    on_line(tag, ln.rstrip("\n"))
                except Exception:
                    pass

    t1 = threading.Thread(target=pump, args=(proc.stdout, out_lines, "out"), daemon=True)
    t2 = threading.Thread(target=pump, args=(proc.stderr, err_lines, "err"), daemon=True)
    t1.start(); t2.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        if askpass:
            _cleanup_askpass(askpass)
        return -1, "\n".join(out_lines), "\n".join(err_lines) + "\n命令超时被终止"
    t1.join(timeout=5); t2.join(timeout=5)
    if askpass:
        _cleanup_askpass(askpass)
    return proc.returncode, "\n".join(out_lines), "\n".join(err_lines)


def run_scp_download(target: Target, remote_path: str, local_path: str,
                     on_line=None, timeout=900) -> tuple:
    if not target.scp_exe:
        return -1, "", "找不到 scp 客户端"
    args = [target.scp_exe] + target.scp_common_args() + \
           ["%s:%s" % (target.dest, remote_path), local_path]
    env = dict(os.environ)
    askpass = ""
    if target.password:
        askpass = _try_askpass_script(target.password)
        env["SSH_ASKPASS"] = askpass
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["INTLINK_PW"] = target.password
        env.setdefault("DISPLAY", ":0")
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, text=True, encoding="utf-8",
                                errors="replace", stdin=subprocess.DEVNULL)
        o, e = proc.communicate(timeout=timeout)
    except Exception as ex:
        if askpass:
            _cleanup_askpass(askpass)
        return -1, "", "scp 失败: %s" % ex
    if askpass:
        _cleanup_askpass(askpass)
    return proc.returncode, o or "", e or ""


# ── 预检 ──────────────────────────────────────────────────────────
PREFLIGHT_CMD = (
    'echo "===PREFLIGHT==="; '
    'echo "host=$(hostname 2>/dev/null)"; '
    'echo "user=$(id -un 2>/dev/null)"; '
    'echo "uid=$(id -u 2>/dev/null)"; '
    'echo "sudo_nopass=$(sudo -n true 2>/dev/null && echo yes || echo no)"; '
    'echo "tcpdump=$(command -v tcpdump 2>/dev/null || echo none)"; '
    'echo "python3=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || echo none)"; '
    'echo "timeout=$(command -v timeout 2>/dev/null || echo none)"; '
    'echo "date=$(date -Ins 2>/dev/null || date)"; '
    'echo "tz=$(cat /etc/timezone 2>/dev/null || echo unset)"; '
    'echo "docker=$(command -v docker 2>/dev/null || echo none)"; '
    'echo "os=$(. /etc/os-release 2>/dev/null && echo $PRETTY_NAME)"; '
    'echo "===END==="'
)


def preflight(target: Target, on_line=None) -> dict:
    """连接与能力预检。返回能力字典，任何一项缺失都不阻止继续（只会降级）。"""
    rc, out, err = run_ssh(target, PREFLIGHT_CMD, on_line, timeout=60)
    info = {"connected": rc == 0, "rc": rc, "raw": out, "stderr": err}
    if rc != 0:
        info["error"] = _explain_ssh_error(err)
        return info
    for ln in out.splitlines():
        if "=" in ln and not ln.startswith("==="):
            k, v = ln.split("=", 1)
            info[k.strip()] = v.strip()
    info["can_capture"] = bool(info.get("tcpdump") not in (None, "", "none")) and (
        info.get("uid") == "0" or info.get("sudo_nopass") == "yes")
    info["degraded"] = []
    if not info["can_capture"]:
        if info.get("tcpdump") in ("none", "", None):
            info["degraded"].append("目标机没有 tcpdump，只能拿连接统计，抓不到包")
        elif info.get("uid") != "0" and info.get("sudo_nopass") != "yes":
            info["degraded"].append("当前用户非 root 且无免密 sudo，抓不了包")
    if info.get("python3") in ("none", "", None):
        info["degraded"].append("目标机没有 python3，进程/端口解析会降级为 ss/ps 文本")
    return info


def _explain_ssh_error(err: str) -> str:
    e = (err or "").lower()
    if "permission denied" in e:
        return ("认证失败：用户名或密钥不对。若是密码登录，确认这台机器装了期望的 ssh，"
                "且 ~/.ssh/config 没有强制 BatchMode。")
    if "connection refused" in e:
        return "端口拒绝：目标机 sshd 没在监听该端口，或端口号写错了。"
    if "timed out" in e or "timeout" in e:
        return "连接超时：网络不通、IP 写错，或中间有防火墙。先 ping / telnet 端口确认。"
    if "no route to host" in e:
        return "路由不可达：中间有设备阻断，或不在同一网段。"
    if "host key verification failed" in e:
        return "主机密钥校验失败：目标机重装过或 IP 冲突。确认无误后执行 ssh-keygen -R <host>。"
    if "could not resolve" in e or "name or service not known" in e:
        return "域名解析失败：换用 IP 或检查 DNS。"
    return "SSH 连接失败，原始错误见上方。"


# ── 主流程 ────────────────────────────────────────────────────────
def deploy_and_capture(target: Target, local_script: str, opts: dict,
                       on_line=None, local_out_dir: str = "") -> RunResult:
    """完整流程：预检 → 推脚本 → 跑采集 → 拉回包 → 清理。

    opts 可含：hint(list), pid(list), secs, window_secs, list_only, auto, ports, peers
    """
    res = RunResult()
    t0 = time.time()

    def say(stage, ok, msg=""):
        res.steps.append((stage, ok, msg))

    def emit(tag, line):
        if on_line:
            on_line(tag, line)

    # 1. 预检
    emit("stage", "① 连接预检...")
    pf = preflight(target, on_line)
    say("preflight", pf.get("connected", False), pf.get("error", ""))
    if not pf.get("connected"):
        res.error = pf.get("error", "预检失败")
        res.stderr = pf.get("stderr", "")
        res.duration = time.time() - t0
        emit("stage", "✗ 预检失败：" + res.error)
        return res
    emit("stage", "✓ 已连接 %s（root=%s, tcpdump=%s, python3=%s）"
         % (pf.get("host", target.host), pf.get("uid"),
            pf.get("tcpdump"), pf.get("python3")))
    if pf.get("degraded"):
        for d in pf["degraded"]:
            emit("warn", "能力受限：" + d)
    res.steps[-1] = ("preflight", True, str(pf.get("degraded") or ""))

    # 2. 推脚本
    emit("stage", "② 上传采集脚本...")
    tag = uuid.uuid4().hex[:8]
    remote_script = "/tmp/intlink_probe_%s.sh" % tag
    if not os.path.isfile(local_script):
        res.error = "本地找不到采集脚本: %s" % local_script
        return res
    rc, out, err = run_scp_upload(target, local_script, remote_script, on_line)
    if rc != 0:
        res.error = "上传脚本失败（scp rc=%d）: %s" % (rc, err.strip()[:300])
        say("upload", False, res.error)
        emit("stage", "✗ " + res.error)
        res.duration = time.time() - t0
        return res
    say("upload", True, remote_script)
    emit("stage", "✓ 已上传到 %s" % remote_script)

    # 换行修正：从 Windows 传过去可能带 CR，bash 会报 syntax error
    run_ssh(target, "sed -i 's/\\r$//' %s 2>/dev/null; chmod +x %s"
            % (remote_script, remote_script), None, timeout=30)

    # 3. 跑采集
    emit("stage", "③ 开始采集（这一刻请在对端触发复现）...")
    args = ["bash", remote_script]
    for h in (opts.get("hint") or []):
        if str(h).strip():
            args += ["--hint", _q(str(h).strip())]
    for p in (opts.get("pid") or []):
        if str(p).strip():
            args += ["--pid", _q(str(p).strip())]
    if opts.get("auto"):
        args.append("--auto")
    if opts.get("list_only"):
        args.append("--list-only")
    if opts.get("secs"):
        args += ["--secs", str(int(opts["secs"]))]
    if opts.get("window_secs"):
        args += ["--window-secs", str(int(opts["window_secs"]))]
    if opts.get("ports"):
        args += ["--ports", _q(str(opts["ports"]))]
    if opts.get("peers"):
        args += ["--peers", _q(str(opts["peers"]))]
    if opts.get("out_dir_remote"):
        args += ["--out", _q(str(opts["out_dir_remote"]))]

    cmd = " ".join(args)
    emit("cmd", cmd)
    # 采集耗时会超过抓包窗口，留足余量
    budget = int(opts.get("secs") or 60) + 240
    rc, out, err = run_ssh(target, cmd, on_line, timeout=budget)
    res.rc = rc
    res.stdout = out
    res.stderr = err
    if rc != 0:
        res.error = "采集脚本退出码 %d。原始错误：%s" % (rc, (err or "")[-500:])
        say("capture", False, res.error)
        emit("stage", "✗ " + res.error)
        res.duration = time.time() - t0
        return res
    say("capture", True, "")

    remote_pkg = ""
    sha = ""
    for ln in out.splitlines():
        if ln.startswith("RESULT="):
            remote_pkg = ln.split("=", 1)[1].strip()
        elif ln.startswith("SHA256="):
            sha = ln.split("=", 1)[1].strip()
    res.remote_pkg = remote_pkg
    res.sha256 = sha
    if not remote_pkg:
        res.error = "采集跑完但没拿到 RESULT 行，说明脚本没正常结束。原始输出见下方。"
        emit("stage", "✗ " + res.error)
        res.duration = time.time() - t0
        return res
    emit("stage", "✓ 采集完成，证据包 %s" % remote_pkg)

    # 4. 拉回
    emit("stage", "④ 下载证据包...")
    if not local_out_dir:
        local_out_dir = os.path.join(os.getcwd(), "intlink-packages")
    os.makedirs(local_out_dir, exist_ok=True)
    local_pkg = os.path.join(local_out_dir, posixpath.basename(remote_pkg))
    local_pkg = _unique_path(local_pkg)
    rc, o, e = run_scp_download(target, remote_pkg, local_pkg, on_line, timeout=1800)
    if rc != 0 or not os.path.isfile(local_pkg):
        res.error = ("下载证据包失败（scp rc=%d）：%s\n可以手工取：\n"
                     "scp %s:%s ." % (rc, e.strip()[:300], target.dest, remote_pkg))
        say("download", False, res.error)
        emit("stage", "✗ " + res.error)
        res.duration = time.time() - t0
        return res
    res.local_pkg = local_pkg
    say("download", True, local_pkg)
    emit("stage", "✓ 已下载到 %s (%d 字节)"
         % (local_pkg, os.path.getsize(local_pkg)))

    # 校验 sha（脚本自己算过，能对上说明传输完整）
    if sha:
        import hashlib
        h = hashlib.sha256()
        with open(local_pkg, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() == sha:
            emit("stage", "✓ SHA256 校验通过")
        else:
            emit("warn", "SHA256 不一致（远端 %s / 本地 %s），包可能在传输中损坏"
                 % (sha[:12], h.hexdigest()[:12]))

    # 5. 清理远端
    emit("stage", "⑤ 清理目标机临时文件...")
    run_ssh(target, "rm -f %s; rm -rf %s"
            % (remote_script, posixpath.dirname(remote_pkg) or "/tmp/nonexistent"),
            None, timeout=30)
    emit("stage", "✓ 完成")

    res.duration = time.time() - t0
    return res


def run_scp_upload(target: Target, local_path: str, remote_path: str,
                   on_line=None, timeout=300) -> tuple:
    if not target.scp_exe:
        return -1, "", "找不到 scp 客户端"
    args = [target.scp_exe] + target.scp_common_args() + \
           [local_path, "%s:%s" % (target.dest, remote_path)]
    env = dict(os.environ)
    askpass = ""
    if target.password:
        askpass = _try_askpass_script(target.password)
        env["SSH_ASKPASS"] = askpass
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["INTLINK_PW"] = target.password
        env.setdefault("DISPLAY", ":0")
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, text=True, encoding="utf-8",
                                errors="replace", stdin=subprocess.DEVNULL)
        o, e = proc.communicate(timeout=timeout)
    except Exception as ex:
        if askpass:
            _cleanup_askpass(askpass)
        return -1, "", "scp 上传失败: %s" % ex
    if askpass:
        _cleanup_askpass(askpass)
    return proc.returncode, o or "", e or ""


def _unique_path(p: str) -> str:
    """同名文件已存在时找一个不冲突的名字。

    注意 .tar.gz 是双扩展名，用 splitext 会得到 xxx.tar-1.gz 这种丑名字，
    所以按已知的复合扩展名单独处理。
    """
    if not os.path.exists(p):
        return p
    for ext in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".pcapng", ".pcap"):
        if p.endswith(ext):
            stem = p[:-len(ext)]
            n = 1
            while os.path.exists("%s-%d%s" % (stem, n, ext)):
                n += 1
            return "%s-%d%s" % (stem, n, ext)
    stem, ext = os.path.splitext(p)
    n = 1
    while os.path.exists("%s-%d%s" % (stem, n, ext)):
        n += 1
    return "%s-%d%s" % (stem, n, ext)


def _q(s: str) -> str:
    """给远端 shell 用的最小引号包裹。"""
    if not s:
        return "''"
    if all(c.isalnum() or c in "-_./:@,=" for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"
