"""进程筛选逻辑的单元测试（纯函数，不需要目标机）。

这里守的是一个真实踩过的坑：SSH 登录跑采集时，bash 的父进程就是 sshd，
如果把「整条祖先链」都当噪声排掉，--hint sshd 永远匹配不到任何进程。
现场表现就是「工具跑完了，什么都没找到」，比报错更难查。
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROBE = os.path.join(ROOT, "agent", "intlink_probe.sh")


def load_parser():
    """从采集脚本里抽出内嵌的 python 解析器。

    解析器原本跑在 Linux 上，用了 Unix 专有的 pwd 模块。Windows 上没有这个模块，
    测试里塞一个最小桩（只需要 getpwuid），这样纯函数逻辑可以在 Windows 上验。
    """
    with open(PROBE, "r", encoding="utf-8", errors="replace") as f:
        src = f.read()
    start = src.find("cat > \"$PY_SCRIPT\" <<'PYEOF'")
    if start < 0:
        raise RuntimeError("找不到内嵌 python 块")
    body_start = src.find("\n", start) + 1
    end = src.find("\nPYEOF\n", body_start)
    if end < 0:
        raise RuntimeError("内嵌 python 块没有结束标记")
    code = src[body_start:end]
    tmp = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                      encoding="utf-8")
    tmp.write(code)
    tmp.close()

    if "pwd" not in sys.modules:
        try:
            import pwd  # noqa: F401
        except ImportError:
            import types

            class _PW:
                def __init__(self, name="stub"):
                    self.pw_name = name

            stub = types.ModuleType("pwd")
            stub.getpwuid = lambda uid: _PW("uid%d" % uid)
            sys.modules["pwd"] = stub

    spec = importlib.util.spec_from_file_location("probe_parser", tmp.name)
    m = importlib.util.module_from_spec(spec)
    sys.argv = ["probe_parser"]
    spec.loader.exec_module(m)
    os.unlink(tmp.name)
    return m


M = load_parser()
rc = 0


def chk(cond, msg):
    global rc
    if cond:
        print("  PASS %s" % msg)
    else:
        print("  FAIL %s" % msg)
        rc = 1


def proc(comm, exe="", cmdline=""):
    return {"comm": comm, "exe": exe, "cmdline": cmdline,
            "cmdline_readable": bool(cmdline), "pid": "1"}


def test_sshd_not_filtered_by_ancestor_chain():
    """sshd 是 SSH 会话的祖先进程，绝不能被当成噪声。"""
    chain = {"100", "101", "46"}      # 46 = sshd
    info = proc("sshd", exe="", cmdline="sshd: fde [priv]")
    chk(M.is_noise_proc("46", info, chain, self_pid="100") is False,
        "祖先链里的 sshd 不被过滤（SSH 场景必备）")
    chk(M.score_hint(info, "sshd") == 100,
        "sshd 用 comm 匹配得 100 分")


def test_probe_itself_is_filtered():
    """探针自己必须被排除，否则会把自己当成对接件。"""
    info = proc("bash", exe="/usr/bin/bash",
                cmdline="bash /tmp/intlink_probe_abc.sh --hint x")
    chk(M.is_noise_proc("200", info, set(), self_pid="999") is True,
        "命令行带 intlink_probe 的进程被过滤")
    info2 = proc("python3", exe="/usr/bin/python3",
                 cmdline="python3 /tmp/xxx/parse.py {...}")
    chk(M.is_noise_proc("201", info2, set(), self_pid="999") is True,
        "解析器 parse.py 进程被过滤")
    chk(M.is_noise_proc("100", proc("python3"), set(), self_pid="100") is True,
        "解析器自身被过滤")


def test_other_bash_not_filtered():
    """同机其他 bash 不能因为同名就被过滤。"""
    info = proc("bash", exe="/usr/bin/bash", cmdline="-bash")
    chk(M.is_noise_proc("300", info, {"100", "101"}, self_pid="100") is False,
        "与探针无亲缘关系的 bash 不被过滤")


def test_prefix_match_for_truncated_comm():
    """内核把 comm 截断到 15 字符，长程序名要靠前缀匹配。"""
    long_name = "green-adapter-service"       # 21 字符，comm 会被截成 15
    info = proc(long_name[:15], exe="/opt/app/green-adapter-service")
    sc = M.score_hint(info, long_name)
    chk(sc >= 80, "长程序名靠截断 comm/ exe 前缀命中（score=%d）" % sc)


def test_no_cmdline_still_matches():
    """非 root 读不到 cmdline 时，仍要能靠 comm/exe 匹配。"""
    info = {"comm": "adapter", "exe": "/opt/app/adapter", "cmdline": "",
            "cmdline_readable": False}
    chk(M.score_hint(info, "adapter") == 100,
        "cmdline 为空时 comm 精确匹配仍然生效")
    info2 = {"comm": "java", "exe": "/usr/bin/java", "cmdline": "",
             "cmdline_readable": False}
    chk(M.score_hint(info2, "java") == 100, "java 进程靠 comm 命中")
    # 但只给 jar 名而读不到 cmdline 时，应当匹配不到（诚实返回 0，而不是瞎猜）
    chk(M.score_hint(info2, "green-adapter.jar") == 0,
        "读不到 cmdline 且线索只出现在 cmdline 里时，不瞎猜（返回 0）")


def test_substring_is_weak():
    """子串命中只能是弱分，避免误伤。"""
    info = proc("java", exe="/usr/bin/java",
                cmdline="java -jar /opt/app/not-green-adapter-x.jar")
    sc = M.score_hint(info, "green-adapter")
    chk(0 < sc <= 40, "子串命中给弱分（score=%d），不会当强匹配" % sc)


def test_parse_ts_formats():
    """日志时间戳三种常见格式都要认。"""
    for line in ("2026-11-10 15:00:00,123 INFO x",
                 "2026-11-10T15:00:00.123+08:00 x",
                 "[10/Nov/2026:15:00:00 +0800] GET"):
        chk(M.parse_ts(line, M.timezone(M.timedelta(hours=8))) is not None,
            "解析时间戳: %s" % line[:30])
    chk(M.parse_ts("no timestamp at all",
                   M.timezone(M.timedelta(hours=8))) is None,
        "没有时间戳时返回 None（不瞎编）")


def test_uid_reverse_lookup_helper():
    """/proc/net/tcp 的 hex 地址解析（uid 反查 socket 时依赖它）。"""
    ip, port, ver = M.hex_to_addr("0100007F:1F90")
    chk(ip == "127.0.0.1" and port == 8080 and ver == 4,
        "IPv4 hex 地址解析正确")


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        print("== %s ==" % t.__name__)
        try:
            t()
        except AssertionError as e:
            global rc
            print("  FAIL %s" % e)
            rc = 1
        except Exception as e:
            print("  ERROR %s: %s" % (type(e).__name__, e))
            rc = 1
    print("ALL PASS" if rc == 0 else "FAILED")
    return rc


if __name__ == "__main__":
    sys.exit(main())
