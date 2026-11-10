"""本机循环自测：不连远程，验证 SSH 编排的非网络逻辑。

覆盖：
  - 引号包裹（远端命令注入风险最高处）
  - ssh 参数拼装（端口 -p/-P 分歧点）
  - 错误解释映射
  - 证据包不覆盖已有文件
  - askpass 临时文件能创建/清理
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intlink_doctor import ssh_runner as S


def test_quote():
    assert S._q("simple") == "simple"
    assert S._q("with space") == "'with space'"
    assert S._q("a'b") == "'a'\\''b'"
    assert S._q("") == "''"
    # 命令注入：分号必须被包住
    q = S._q("x; rm -rf /")
    assert q.startswith("'") and q.endswith("'"), q
    print("  PASS 引号包裹（含注入用例）")


def test_ssh_args_port():
    t = S.Target(host="10.0.0.9", user="ops", port=2222, key_path="/k/id")
    a = t.common_args()
    assert "-p" in a and a[a.index("-p") + 1] == "2222", a
    assert "-i" in a and a[a.index("-i") + 1] == "/k/id", a
    assert t.dest == "ops@10.0.0.9", t.dest
    print("  PASS ssh 参数含端口/密钥")


def test_scp_args_port_uppercase():
    """scp 用 -P 表示端口，拼错会静默按 22 连。"""
    t = S.Target(host="10.0.0.9", user="ops", port=2222)
    a = t.scp_common_args()
    assert "-P" in a, "scp 必须用大写 -P: %s" % a
    assert a[a.index("-P") + 1] == "2222"
    print("  PASS scp 用 -P 表示端口")


def test_alias_mode_ignores_port():
    """用 ssh config 别名时，端口/密钥都在 config 里，不该再拼。"""
    t = S.Target(host="", user="", port=2222, key_path="/k", ssh_config_alias="prodsrv")
    a = t.common_args()
    assert "-p" not in a, "别名模式不该自己拼端口: %s" % a
    assert "-i" not in a, "别名模式不该自己拼密钥: %s" % a
    assert t.dest == "prodsrv"
    print("  PASS 别名模式不覆盖 config")


def test_error_explain():
    cases = [
        ("Permission denied (publickey).", "认证失败"),
        ("ssh: connect to host x port 22: Connection refused", "端口拒绝"),
        ("connect to host x port 22: Connection timed out", "连接超时"),
        ("ssh: Could not resolve hostname foo", "域名解析失败"),
        ("Host key verification failed.", "主机密钥校验失败"),
        ("No route to host", "路由不可达"),
    ]
    for raw, want in cases:
        got = S._explain_ssh_error(raw)
        assert want in got, "%r 应解释为含 %r，实际 %r" % (raw, want, got)
    print("  PASS SSH 错误解释覆盖 %d 种常见错误" % len(cases))


def test_askpass_lifecycle():
    p = S._try_askpass_script("dummy-password")
    assert os.path.isfile(p), "askpass 脚本没造出来: %s" % p
    assert os.access(p, os.X_OK) or os.name == "nt", "askpass 应可执行"
    S._cleanup_askpass(p)
    assert not os.path.exists(os.path.dirname(p)), "askpass 临时目录没清理掉"
    print("  PASS askpass 创建与清理")


def test_preflight_command_shape():
    """预检命令必须能在没有 sudo/没有 tcpdump 的机器上也不报错退出。"""
    c = S.PREFLIGHT_CMD
    assert "sudo -n true" in c and "|| echo no" in c, "sudo 检测必须容错"
    assert "command -v tcpdump" in c and "|| echo none" in c
    assert "===PREFLIGHT===" in c and "===END===" in c
    print("  PASS 预检命令对缺工具容错")


def test_no_overwrite_local_package():
    """下载同名包时必须改名，不能覆盖（用户明确要求过）。"""
    import tempfile
    d = tempfile.mkdtemp(prefix="intlink-noov-")
    for name in ("intlink-probe-h-1.tar.gz", "a.pcap", "b.txt"):
        full = os.path.join(d, name)
        open(full, "wb").close()
        got = S._unique_path(full)
        assert got != full, "同名时没改名: %s" % name
        assert os.path.dirname(got) == d
        # 原名主体必须作为前缀保留（复合扩展名不能拆中间）
        stem = name
        for ext in (".tar.gz", ".pcap", ".txt"):
            if name.endswith(ext):
                stem = name[:-len(ext)]
                break
        assert os.path.basename(got).startswith(stem), "%s -> %s 丢了主体" % (name, got)
    # .tar.gz 不能被拆成 .tar-1.gz，而应整体保留后加 -1
    got = S._unique_path(os.path.join(d, "intlink-probe-h-1.tar.gz"))
    assert got.endswith("-1-1.tar.gz"), "复合扩展名拆错了: %s" % got
    assert ".tar-" not in got, "复合扩展名被 splitext 拆坏: %s" % got
    # 不存在的路径原样返回
    fresh = os.path.join(d, "never-exists.tar.gz")
    assert S._unique_path(fresh) == fresh
    print("  PASS 同名证据包自动改名不覆盖（含复合扩展名）")


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    rc = 0
    for t in tests:
        print("== %s ==" % t.__name__)
        try:
            t()
        except AssertionError as e:
            print("  FAIL %s" % e); rc = 1
        except Exception as e:
            print("  ERROR %s: %s" % (type(e).__name__, e)); rc = 1
    print("ALL PASS" if rc == 0 else "FAILED")
    return rc


if __name__ == "__main__":
    sys.exit(main())
