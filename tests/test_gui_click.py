"""GUI 真实交互测试：用鼠标键盘真的点一遍，不是只在后台调函数。

和 test_gui_live.py 的区别：
  test_gui_live 是「程序内调用 _on_run()」，验证的是后台链路；
  这个测试是「找到按钮的真实坐标 → pyautogui 点击 → 观察界面变化/截图」，
  验证的是用户真的能点到、界面真的响应。

为什么值得单独做：按钮被遮挡、绑定失效、控件禁用状态没解除，
这些只有真点才会暴露。
"""
from __future__ import annotations

import os
import sys
import time
import tkinter as tk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyautogui

from intlink_doctor import gui as G
from intlink_doctor import ssh_runner as SSH
from _livetest import target_host, target_user, skip

pyautogui.FAILSAFE = False
SHOTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui-shots")
os.makedirs(SHOTS, exist_ok=True)

FAIL = 0


def chk(cond, msg):
    global FAIL
    if cond:
        print("  PASS %s" % msg)
    else:
        print("  FAIL %s" % msg)
        FAIL += 1


def widget_center(w, root):
    """控件在屏幕上的中心坐标（tkinter 的 rootx/y 是屏幕绝对坐标）。"""
    root.update_idletasks()
    x = w.winfo_rootx() + w.winfo_width() // 2
    y = w.winfo_rooty() + w.winfo_height() // 2
    return x, y


def main():
    host = target_host()
    user = target_user()
    if not host:
        return skip("没配 INTLINK_TEST_SSH_HOST，跳过 GUI 真实点击测试")

    print("== 检查桌面可用（非锁屏）==")
    try:
        scr = pyautogui.screenshot()
        chk(scr.size[0] > 100, "能截屏（%dx%d）" % scr.size)
    except Exception as e:
        print("  SKIP 无桌面会话: %s" % e)
        return 0

    online = SSH.preflight(SSH.Target(host=host, user=user)).get("connected")
    print("    目标 %s@%s 可用: %s" % (user, host, online))

    root = tk.Tk()
    app = G.App(root)
    root.geometry("1080x760+60+40")     # 固定位置，方便点
    root.update_idletasks()
    root.update()
    root.lift()
    root.attributes("-topmost", True)
    root.update()
    time.sleep(0.8)

    # ── 1. 真的用鼠标点进输入框并打字 ──
    print("\n== 1. 鼠标点输入框 + 键盘输入 ==")
    entries = []

    def walk(w):
        if w.winfo_class() == "TEntry":
            entries.append(w)
        for c in w.winfo_children():
            walk(c)

    walk(root)
    if not entries:
        chk(False, "找不到任何输入框")
        root.destroy()
        return 1

    # 控件真实顺序：0=主机 1=端口 2=用户 3=密钥 4=密码 5=程序线索
    # 6=抓包秒数 7=日志回看 8=强制端口（写错索引会点到密码框，那种测试等于没测）
    chk(len(entries) >= 9, "输入框数量符合预期（%d 个）" % len(entries))

    hx, hy = widget_center(entries[0], root)
    pyautogui.click(hx, hy)
    time.sleep(0.2)
    pyautogui.hotkey("ctrl", "a")
    pyautogui.press("delete")
    pyautogui.typewrite(host, interval=0.01)
    root.update()          # 让 tk 处理完输入事件，否则 StringVar 还没更新
    time.sleep(0.35)
    got_host = app.host.get()
    chk(got_host == host, "点进输入框并打字生效（%r）" % got_host)

    # 用户输入框
    ux, uy = widget_center(entries[2], root)
    pyautogui.click(ux, uy)
    time.sleep(0.15)
    pyautogui.hotkey("ctrl", "a")
    pyautogui.press("delete")
    pyautogui.typewrite(user, interval=0.01)
    root.update()
    time.sleep(0.25)
    chk(app.user.get() == user, "用户框输入生效（%r）" % app.user.get())

    # 程序线索（索引 5，不是 4 —— 4 是密码框）
    cx, cy = widget_center(entries[5], root)
    pyautogui.click(cx, cy)
    time.sleep(0.15)
    pyautogui.hotkey("ctrl", "a")
    pyautogui.press("delete")
    pyautogui.typewrite("bash", interval=0.01)
    root.update()
    time.sleep(0.25)
    chk("bash" in app.hint.get(), "程序线索输入生效（%r）" % app.hint.get())
    chk(app.password.get() == "", "密码框没被误填（确认点的是线索框）")

    # 抓包秒数（索引 6）：点进去改成 8
    sx, sy = widget_center(entries[6], root)
    pyautogui.click(sx, sy)
    time.sleep(0.15)
    pyautogui.hotkey("ctrl", "a")
    pyautogui.press("delete")
    pyautogui.typewrite("8", interval=0.02)
    root.update()
    time.sleep(0.25)
    chk(app.secs.get() == "8", "抓包秒数可改（%r）" % app.secs.get())

    root.update()
    shot1 = os.path.join(SHOTS, "click_filled.png")
    pyautogui.screenshot(region=(root.winfo_rootx(), root.winfo_rooty(),
                                 root.winfo_width(), root.winfo_height())
                         ).save(shot1)
    print("    截图: %s" % shot1)

    # ── 2. 点「只侦察不抓包」复选框 ──
    print("\n== 2. 点复选框 ==")
    checks = []

    def walk2(w):
        if w.winfo_class() == "TCheckbutton":
            checks.append(w)
        for c in w.winfo_children():
            walk2(c)

    walk2(root)
    chk(len(checks) >= 2, "找到复选框（%d 个）" % len(checks))
    if checks:
        before = app.list_only.get()
        bx, by = widget_center(checks[0], root)
        pyautogui.click(bx, by)
        time.sleep(0.3)
        root.update()
        chk(app.list_only.get() != before,
            "点复选框真的改变了状态（%s → %s）" % (before, app.list_only.get()))

    # ── 3. 点「测试连接」按钮 ──
    print("\n== 3. 点「测试连接」按钮 ==")
    btn_test = None

    def walk3(w):
        nonlocal btn_test
        if w.winfo_class() == "TButton":
            try:
                if "测试连接" in str(w.cget("text")):
                    btn_test = w
            except Exception:
                pass
        for c in w.winfo_children():
            walk3(c)

    walk3(root)
    chk(btn_test is not None, "找到「测试连接」按钮")
    if btn_test:
        tx, ty = widget_center(btn_test, root)
        pyautogui.click(tx, ty)
        # 等连接完成（按钮会先禁用再恢复）
        for _ in range(120):
            root.update()
            time.sleep(0.1)
            if not app.busy:
                break
        time.sleep(0.5)
        root.update()
        label = app.conn_label.cget("text")
        print("    状态栏: %s" % label)
        if online:
            chk("已连接" in label or "✓" in label,
                "点按钮后真的连上了（%r）" % label)
        else:
            chk("失败" in label or "✗" in label,
                "连不上时给出明确失败（%r）" % label)
        shot2 = os.path.join(SHOTS, "click_tested.png")
        pyautogui.screenshot(region=(root.winfo_rootx(), root.winfo_rooty(),
                                     root.winfo_width(), root.winfo_height())
                             ).save(shot2)
        print("    截图: %s" % shot2)

    # ── 4. 按钮禁用态是否正确恢复 ──
    print("\n== 4. 按钮状态恢复 ==")
    chk(not app.busy, "空闲时 busy=False")
    chk(str(app.btn_run.cget("state")) == "normal", "「开始采集」恢复可点")
    chk(str(app.btn_analyze_local.cget("state")) == "normal", "「分析本地包」恢复可点")

    # ── 5. 点「开始采集并分析」，走完整流程 ──
    print("\n== 5. 点「开始采集并分析」跑完整流程 ==")
    btn_run = None

    def walk4(w):
        nonlocal btn_run
        if w.winfo_class() == "TButton":
            try:
                if "开始采集" in str(w.cget("text")):
                    btn_run = w
            except Exception:
                pass
        for c in w.winfo_children():
            walk4(c)

    walk4(root)
    chk(btn_run is not None, "找到「开始采集并分析」按钮")

    if btn_run and online:
        # 勾只侦察，避免真抓包拖时间；秒数设小
        if not app.list_only.get():
            bx, by = widget_center(checks[0], root)
            pyautogui.click(bx, by)
            root.update()
        app.secs.set("5")
        rx, ry = widget_center(btn_run, root)
        pyautogui.click(rx, ry)
        root.update()
        chk(app.busy, "点击后立即进入忙碌态（按钮应被禁用）")
        chk(str(app.btn_run.cget("state")) == "disabled",
            "忙碌时「开始采集」被禁用（防重复点击）")

        # 等流程跑完（只侦察 + 分析，正常几十秒内）
        deadline = time.time() + 240
        while app.busy and time.time() < deadline:
            root.update()
            time.sleep(0.15)
        for _ in range(60):
            root.update()
            time.sleep(0.05)

        chk(not app.busy, "流程结束后回到空闲（没有卡死）")
        chk(str(app.btn_run.cget("state")) == "normal", "结束后按钮恢复可点")
        chk(str(app.btn_open.cget("state")) == "normal",
            "「打开报告」被启用（说明报告已生成）")
        chk(bool(app.last_html and os.path.isfile(app.last_html)),
            "报告文件真实存在: %s" % (app.last_html or "-"))

        log_text = app.log.get("1.0", "end")
        for stage_mark in ("①", "②", "③", "④", "⑤", "⑥"):
            chk(stage_mark in log_text, "日志里出现阶段 %s" % stage_mark)
        chk("✓ 已下载到" in log_text, "日志里有下载完成的记录")
        chk("SHA256" in log_text, "日志里有 SHA256 校验")
        print("    摘要栏: %s" % app.summary.cget("text"))

        shot3 = os.path.join(SHOTS, "click_completed.png")
        pyautogui.screenshot(region=(root.winfo_rootx(), root.winfo_rooty(),
                                     root.winfo_width(), root.winfo_height())
                             ).save(shot3)
        print("    截图: %s" % shot3)

    root.destroy()
    print("\n" + ("ALL PASS" if FAIL == 0 else "FAILED=%d" % FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
