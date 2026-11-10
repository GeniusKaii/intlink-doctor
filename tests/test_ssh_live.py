"""真实 SSH 联调：把 WSL 当目标机，走一遍 预检→推脚本→采集→拉包。

前提：WSL 里 sshd 已起，且 Windows 侧能免密 ssh 到它。
密钥没配好时这个测试会跳过（不 fail），避免环境问题误报代码问题。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intlink_doctor import ssh_runner as S
from _livetest import target_host, target_user, target_port, skip


def main():
    host = target_host()
    if not host:
        return skip("没配 INTLINK_TEST_SSH_HOST，跳过真实 SSH 联调")
    user = target_user()
    port = target_port()

    t = S.Target(host=host, user=user, port=port)
    print("== 目标: %s ==" % t.describe())

    print("== 1. 预检 ==")
    pf = S.preflight(t)
    if not pf.get("connected"):
        print("  SKIP 连不上（%s）" % pf.get("error", "?"))
        print("  这不是代码问题：先让 Windows 侧能免密 ssh 到 %s" % t.dest)
        return 0
    for k in ("host", "user", "uid", "sudo_nopass", "tcpdump", "python3",
              "os", "date", "tz"):
        print("    %-12s %s" % (k, pf.get(k)))
    print("    can_capture  %s" % pf.get("can_capture"))
    if pf.get("degraded"):
        for d in pf["degraded"]:
            print("    degraded:    %s" % d)

    print("== 2. 部署并采集（只侦察，不抓包）==")
    script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "agent", "intlink_probe.sh")

    def on_line(tag, line):
        if tag in ("stage", "warn", "cmd"):
            print("    [%s] %s" % (tag, line))

    res = S.deploy_and_capture(
        t, script,
        {"hint": ["bash"], "list_only": True, "window_secs": 120, "secs": 5},
        on_line=on_line,
        local_out_dir=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "ssh-out"))

    print("== 3. 结果 ==")
    print("    rc=%s  耗时=%.1fs" % (res.rc, res.duration))
    print("    远端包: %s" % (res.remote_pkg or "-"))
    print("    本地包: %s" % (res.local_pkg or "-"))
    if res.error:
        print("    错误: %s" % res.error)
        return 1
    if not (res.local_pkg and os.path.isfile(res.local_pkg)):
        print("    FAIL 没拿到本地证据包")
        return 1

    print("== 4. 分析这个包 ==")
    from intlink_doctor import cli as CLI
    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssh-report")
    s = CLI.run_analyze(res.local_pkg, outdir)
    print("    日志行=%d 事务=%d 关联键=%s 发现=%d"
          % (s["log_lines"], s["transactions"],
             (s["key"][:16] + "...") if s["key"] else "无", s["findings"]))
    print("    报告: %s" % s["outputs"]["report_html"])
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
