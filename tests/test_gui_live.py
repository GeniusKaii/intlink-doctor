"""GUI 冒烟测试：自动填充 WSL 目标、点采集、等在后台跑完、截图。

不连网也能跑（连不上就在报告里 SKIP）。目的是证明「点一下能走完全流程」，
以及验证 UI 线程没有被后台线程搞崩。
"""
from __future__ import annotations

import os
import sys
import time
import tkinter as tk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intlink_doctor import cli as CLI
from intlink_doctor import gui as G
from intlink_doctor import ssh_runner as SSH
from _livetest import target_host, target_user, skip


def shot(root, path):
    """用 Windows 自带的方式截图。失败不算错。"""
    try:
        root.update()
        import subprocess
        ps = (
            "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;"
            "$b=New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,"
            "[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height);"
            "$g=[System.Drawing.Graphics]::FromImage($b);"
            "$g.CopyFromScreen(0,0,0,0,$b.Size);"
            "$b.Save('%s');" % path.replace("'", "''")
        )
        subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, timeout=30)
        return os.path.isfile(path)
    except Exception:
        return False


def main():
    host = target_host()
    user = target_user()
    if not host:
        return skip("没配 INTLINK_TEST_SSH_HOST，跳过 GUI 端到端")

    t = SSH.Target(host=host, user=user)
    pf = SSH.preflight(t)
    online = pf.get("connected")
    print("目标 %s@%s 可用: %s" % (user, host, online))

    root = tk.Tk()
    app = G.App(root)
    app.host.set(host)
    app.user.set(user)
    app.hint.set("bash")
    app.secs.set("6")
    app.window.set("120")
    app.list_only.set(True)
    root.update()
    root.lift()
    root.attributes("-topmost", True)
    root.update()
    time.sleep(0.6)

    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui-shots")
    os.makedirs(outdir, exist_ok=True)
    p1 = os.path.join(outdir, "gui-form.png")
    print("截图(空表单):", shot(root, p1))

    if not online:
        print("SKIP 采集（目标不可达）")
        root.destroy()
        return 0

    print("== 触发采集 ==")
    app._on_run()
    deadline = time.time() + 180
    while app.busy and time.time() < deadline:
        root.update()
        time.sleep(0.15)
    # 等队列把最后消息刷完
    for _ in range(40):
        root.update()
        time.sleep(0.05)

    p2 = os.path.join(outdir, "gui-done.png")
    print("截图(完成):", shot(root, p2))
    print("摘要行:", app.summary.cget("text"))
    print("报告:", app.last_html, "存在:", os.path.isfile(app.last_html or ""))

    ok = bool(app.last_html and os.path.isfile(app.last_html))
    text = app.log.get("1.0", "end")
    for must in ("①", "②", "③", "④", "⑤"):
        if must not in text:
            print("  FAIL 日志缺少阶段 %s" % must)
            ok = False
    if "⑥" not in text:
        print("  FAIL 日志缺少分析阶段 ⑥")
        ok = False
    if not ok:
        print("--- 日志尾部 ---")
        print("\n".join(text.splitlines()[-25:]))

    root.destroy()
    print("ALL PASS" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
