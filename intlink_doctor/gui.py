"""GUI：一屏填完 → 一键采集 → 实时看真实命令输出 → 直接出报告。

刻意不做向导。理由：现场工程师时间紧，点七步才跑起来的界面会被弃用；
所有参数一屏可见、默认值可用、失败就地提示缺什么。

界面分三块（从上到下）：
  1. 连接：主机/端口/用户/凭据（密钥优先）
  2. 采集：程序线索、时间窗、抓包时长、想不想抓包
  3. 输出：真实命令日志（后台线程流式追加）+ 结论摘要 + 打开报告

线程模型：采集和分析都在后台线程，UI 只用 after() 回主线程更新，
避免 tkinter 跨线程崩溃。
"""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

from . import cli as CLI
from . import ssh_runner as SSH

APP_TITLE = "对接件排障助手 · intlink-doctor"
SCRIPT_NAME = "intlink_probe.sh"


def _script_path() -> str:
    """找到随包的采集脚本。支持源码运行和 PyInstaller 打包两种。"""
    here = os.path.dirname(os.path.abspath(__file__))
    cands = [
        os.path.join(os.path.dirname(here), "agent", SCRIPT_NAME),
        os.path.join(here, "agent", SCRIPT_NAME),
        os.path.join(os.path.dirname(here), SCRIPT_NAME),
    ]
    base = getattr(sys, "_MEIPASS", "")
    if base:
        cands.insert(0, os.path.join(base, "agent", SCRIPT_NAME))
        cands.insert(1, os.path.join(base, SCRIPT_NAME))
    for c in cands:
        if os.path.isfile(c):
            return c
    return ""


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.q = queue.Queue()
        self.worker = None
        self.busy = False
        self.last_html = ""
        self.last_pkg = ""
        self._build()
        self.root.after(80, self._drain_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── 界面 ──────────────────────────────────────────────────────
    def _build(self):
        self.root.title(APP_TITLE)
        self.root.geometry("1080x760")
        self.root.minsize(900, 640)

        style = ttk.Style()
        try:
            style.theme_use("vista")
        except Exception:
            pass
        style.configure("Big.TButton", font=("Segoe UI", 10, "bold"), padding=(14, 7))
        style.configure("Head.TLabel", font=("Segoe UI", 11, "bold"))
        style.configure("Hint.TLabel", foreground="#666")

        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)

        # ── 1. 连接 ──
        c = ttk.LabelFrame(outer, text="① 连接目标机", padding=8)
        c.pack(fill="x", pady=(0, 6))
        g = c.grid_columnconfigure
        for i in (1, 3, 5):
            g(i, weight=1)

        ttk.Label(c, text="主机 / ssh别名").grid(row=0, column=0, sticky="w", padx=4)
        self.host = tk.StringVar()
        ttk.Entry(c, textvariable=self.host).grid(row=0, column=1, sticky="ew", padx=4)

        ttk.Label(c, text="端口").grid(row=0, column=2, sticky="w", padx=4)
        self.port = tk.StringVar(value="22")
        ttk.Entry(c, textvariable=self.port, width=8).grid(row=0, column=3, sticky="w", padx=4)

        ttk.Label(c, text="用户").grid(row=0, column=4, sticky="w", padx=4)
        self.user = tk.StringVar(value="root")
        ttk.Entry(c, textvariable=self.user, width=14).grid(row=0, column=5, sticky="w", padx=4)

        ttk.Label(c, text="密钥文件").grid(row=1, column=0, sticky="w", padx=4, pady=(6, 0))
        self.key = tk.StringVar()
        ttk.Entry(c, textvariable=self.key).grid(row=1, column=1, columnspan=3,
                                                sticky="ew", padx=4, pady=(6, 0))
        ttk.Button(c, text="浏览…", command=self._pick_key
                   ).grid(row=1, column=4, sticky="w", padx=4, pady=(6, 0))
        ttk.Label(c, text="留空＝用 ~/.ssh/config 或默认密钥",
                  style="Hint.TLabel").grid(row=1, column=5, sticky="w", padx=4, pady=(6, 0))

        ttk.Label(c, text="密码").grid(row=2, column=0, sticky="w", padx=4, pady=(6, 0))
        self.password = tk.StringVar()
        ttk.Entry(c, textvariable=self.password, show="•").grid(
            row=2, column=1, columnspan=2, sticky="ew", padx=4, pady=(6, 0))
        ttk.Label(c, text="推荐用密钥；密码不落盘、不进命令行",
                  style="Hint.TLabel").grid(row=2, column=3, columnspan=3,
                                            sticky="w", padx=4, pady=(6, 0))

        ttk.Button(c, text="测试连接", command=self._on_test
                   ).grid(row=3, column=5, sticky="e", padx=4, pady=(8, 0))
        self.conn_label = ttk.Label(c, text="未连接", style="Hint.TLabel")
        self.conn_label.grid(row=3, column=0, columnspan=5, sticky="w", padx=4, pady=(8, 0))

        # ── 2. 采集 ──
        p = ttk.LabelFrame(outer, text="② 采集什么", padding=8)
        p.pack(fill="x", pady=(0, 6))
        # 列宽策略：标签列固定窄，主输入列（1）权重最高，
        # 说明列（4）给足空间但让出宽度给输入框。
        # 之前把权重放在 1 和 3 上，导致「程序线索」输入框比右侧说明还窄，很难用。
        p.grid_columnconfigure(0, minsize=78)
        p.grid_columnconfigure(1, weight=5, minsize=220)
        p.grid_columnconfigure(2, minsize=78)
        p.grid_columnconfigure(3, weight=1, minsize=80)
        p.grid_columnconfigure(4, weight=3, minsize=180)

        ttk.Label(p, text="程序线索").grid(row=0, column=0, sticky="w", padx=4)
        self.hint = tk.StringVar()
        ttk.Entry(p, textvariable=self.hint).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Label(p, text="程序名/路径/PID，多个用逗号分隔（如 green-adapter, /opt/app/x.jar）",
                  style="Hint.TLabel").grid(row=0, column=2, columnspan=3,
                                            sticky="w", padx=4)

        ttk.Label(p, text="抓包秒数").grid(row=1, column=0, sticky="w", padx=4, pady=(6, 0))
        self.secs = tk.StringVar(value="60")
        ttk.Entry(p, textvariable=self.secs, width=8).grid(row=1, column=1, sticky="w",
                                                           padx=4, pady=(6, 0))
        ttk.Label(p, text="日志回看").grid(row=1, column=2, sticky="w", padx=4, pady=(6, 0))
        self.window = tk.StringVar(value="900")
        ttk.Entry(p, textvariable=self.window, width=8).grid(row=1, column=3, sticky="w",
                                                             padx=4, pady=(6, 0))
        # 说明紧跟在输入框右侧同一列，不再单独占一列被推到最右
        ttk.Label(p, text="秒（往前多看多少日志）", style="Hint.TLabel"
                  ).grid(row=1, column=4, sticky="w", padx=(2, 4), pady=(6, 0))

        ttk.Label(p, text="强制端口").grid(row=2, column=0, sticky="w", padx=4, pady=(6, 0))
        self.ports = tk.StringVar()
        ttk.Entry(p, textvariable=self.ports, width=18).grid(row=2, column=1, sticky="w",
                                                             padx=4, pady=(6, 0))
        ttk.Label(p, text="可选。自动解析不出来对端时才需要填，如 8080,18099",
                  style="Hint.TLabel").grid(row=2, column=2, columnspan=3,
                                            sticky="w", padx=4, pady=(6, 0))

        self.list_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(p, text="只侦察不抓包（客户机不让抓包时勾这个）",
                        variable=self.list_only).grid(row=3, column=0, columnspan=3,
                                                      sticky="w", padx=4, pady=(8, 0))
        self.auto_pick = tk.BooleanVar(value=False)
        ttk.Checkbutton(p, text="自动挑有对外连接的进程（不给线索时）",
                        variable=self.auto_pick).grid(row=3, column=3, columnspan=2,
                                                      sticky="w", padx=4, pady=(8, 0))

        # ── 按钮行 ──
        bar = ttk.Frame(outer)
        bar.pack(fill="x", pady=(0, 6))
        self.btn_run = ttk.Button(bar, text="开始采集并分析", style="Big.TButton",
                                  command=self._on_run)
        self.btn_run.pack(side="left")
        self.btn_open = ttk.Button(bar, text="打开报告", command=self._open_report,
                                   state="disabled")
        self.btn_open.pack(side="left", padx=6)
        self.btn_analyze_local = ttk.Button(bar, text="分析本地证据包…",
                                            command=self._on_analyze_local)
        self.btn_analyze_local.pack(side="left", padx=6)
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=180)
        self.progress.pack(side="right", padx=6)

        # ── 3. 输出 ──
        out = ttk.LabelFrame(outer, text="③ 执行过程（目标机上真实执行的命令与输出）", padding=6)
        out.pack(fill="both", expand=True)
        wrap = ttk.Frame(out)
        wrap.pack(fill="both", expand=True)
        self.log = tk.Text(wrap, height=14, wrap="none",
                           bg="#0f1419", fg="#d8dee9", insertbackground="#d8dee9",
                           font=("Consolas", 9), relief="flat")
        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.log.yview)
        hs = ttk.Scrollbar(wrap, orient="horizontal", command=self.log.xview)
        self.log.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.log.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        wrap.grid_rowconfigure(0, weight=1)
        wrap.grid_columnconfigure(0, weight=1)
        self.log.tag_configure("stage", foreground="#6ee7b7")
        self.log.tag_configure("warn", foreground="#fbbf24")
        self.log.tag_configure("err", foreground="#f87171")
        self.log.tag_configure("cmd", foreground="#93c5fd")
        self.log.tag_configure("dim", foreground="#7a8694")

        # ── 结论条 ──
        self.summary = ttk.Label(outer, text="就绪。填好连接信息后点「开始采集并分析」。",
                                 style="Hint.TLabel")
        self.summary.pack(fill="x", pady=(6, 0))

    # ── 小工具 ────────────────────────────────────────────────────
    def _pick_key(self):
        p = filedialog.askopenfilename(title="选择私钥文件",
                                       initialdir=os.path.expanduser("~/.ssh"))
        if p:
            self.key.set(p)

    def _append(self, text: str, tag: str = ""):
        self.log.insert("end", text + "\n", tag)
        self.log.see("end")
        self.log.update_idletasks()

    def _drain_queue(self):
        """后台线程只往队列放消息，UI 更新统一在这里做。"""
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "line":
                    tag, text = payload
                    self._append(text, tag)
                elif kind == "done":
                    self._finish(*payload)
                elif kind == "fail":
                    self._fail(payload)
                elif kind == "test_done":
                    self._test_done(payload)
        except queue.Empty:
            pass
        self.root.after(80, self._drain_queue)

    def _target(self) -> SSH.Target:
        host = self.host.get().strip()
        if not host:
            raise ValueError("主机不能为空")
        key = self.key.get().strip()
        return SSH.Target(host=host, user=self.user.get().strip(),
                          port=int(self.port.get().strip() or "22"),
                          key_path=key, password=self.password.get(),
                          ssh_exe=self._ssh_exe())

    def _ssh_exe(self) -> str:
        return SSH._which("ssh")

    def _set_busy(self, busy: bool):
        self.busy = busy
        state = "disabled" if busy else "normal"
        self.btn_run.configure(state=state)
        self.btn_analyze_local.configure(state=state)
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    # ── 测试连接 ──────────────────────────────────────────────────
    def _on_test(self):
        if self.busy:
            return
        try:
            t = self._target()
        except Exception as e:
            messagebox.showerror("参数有误", str(e)); return
        self._set_busy(True)
        self.conn_label.configure(text="连接中…")
        self._append("=" * 60)
        self._append("测试连接 → %s" % t.describe(), "stage")

        def work():
            pf = SSH.preflight(t, on_line=lambda tag, ln: self.q.put(
                ("line", ("dim", "  " + ln))))
            # 绝不能在这里调 self.root.after()：tkinter 不是线程安全的，
            # 从工作线程碰任何 tk 对象都会 RuntimeError: main thread is not in main loop
            # （实测真的会崩）。统一走队列，由主线程的 _drain_queue 处理。
            self.q.put(("test_done", pf))

        threading.Thread(target=work, daemon=True).start()

    def _test_done(self, pf: dict):
        self._set_busy(False)
        if not pf.get("connected"):
            self.conn_label.configure(text="✗ 连接失败")
            self._append("✗ %s" % pf.get("error", "失败"), "err")
            self.summary.configure(text="连接失败：" + pf.get("error", ""))
            return
        self.conn_label.configure(
            text="✓ 已连接  %s    root=%s  tcpdump=%s  python3=%s"
                 % (pf.get("host"), pf.get("uid"), pf.get("tcpdump"),
                    pf.get("python3")))
        self._append("✓ 已连接 %s" % pf.get("host"), "stage")
        self._append("  OS=%s  时区=%s  时间=%s" %
                     (pf.get("os"), pf.get("tz"), pf.get("date")), "dim")
        if pf.get("degraded"):
            for d in pf["degraded"]:
                self._append("  ⚠ " + d, "warn")
            self.summary.configure(text="已连接，但能力受限：" +
                                   "；".join(pf["degraded"]))
        else:
            self.summary.configure(text="已连接，具备完整采集能力。可以开始。")

    # ── 主流程 ────────────────────────────────────────────────────
    def _on_run(self):
        if self.busy:
            return
        try:
            t = self._target()
        except Exception as e:
            messagebox.showerror("参数有误", str(e)); return
        script = _script_path()
        if not script:
            messagebox.showerror("缺少采集脚本",
                                 "找不到 agent/%s。请确认包是完整的。" % SCRIPT_NAME)
            return

        hints = [h.strip() for h in self.hint.get().replace("，", ",").split(",")
                 if h.strip()]
        pids = [h for h in hints if h.isdigit()]
        hints = [h for h in hints if not h.isdigit()]
        if not hints and not pids and not self.auto_pick.get():
            if not messagebox.askyesno(
                    "没有给程序线索",
                    "没有指定程序线索，也没勾「自动挑进程」。\n"
                    "这样很可能找不到对接件。仍要继续吗？"):
                return

        opts = {
            "hint": hints, "pid": pids,
            "auto": self.auto_pick.get(),
            "secs": int(self.secs.get() or 60),
            "window_secs": int(self.window.get() or 900),
            "list_only": self.list_only.get(),
            "ports": self.ports.get().strip(),
        }

        self._set_busy(True)
        self._append("=" * 60)
        self._append("目标：%s" % t.describe(), "stage")
        self._append("采集脚本：%s" % script, "dim")
        if opts["list_only"]:
            self._append("模式：只侦察（不抓包）", "dim")
        else:
            self._append("模式：抓包 %ss（窗口内请在对端触发复现）" % opts["secs"], "warn")
        self.summary.configure(text="采集中…")

        def on_line(tag, ln):
            self.q.put(("line", (tag, ln)))

        def work():
            try:
                res = SSH.deploy_and_capture(t, script, opts, on_line=on_line)
            except Exception as e:
                self.q.put(("fail", "采集阶段异常：%s" % e)); return
            if res.error:
                self.q.put(("fail", res.error)); return
            # 采集成功 → 立刻分析
            self.q.put(("line", ("stage", "")))
            self.q.put(("line", ("stage", "⑥ 本地分析证据包…")))
            outdir = os.path.join(os.path.dirname(res.local_pkg) or ".",
                                  "report-%s" % time.strftime("%Y%m%d-%H%M%S"))
            try:
                s = CLI.run_analyze(res.local_pkg, outdir)
            except Exception as e:
                self.q.put(("fail", "分析失败：%s" % e)); return
            self.q.put(("done", (s, res)))

        threading.Thread(target=work, daemon=True).start()

    def _finish(self, s: dict, res):
        self._set_busy(False)
        self.last_html = s["outputs"]["report_html"]
        self.last_pkg = res.local_pkg
        self.btn_open.configure(state="normal")
        key = s.get("key")
        if key:
            self._append("✓ 找到关联键（%d 个取值，代表值 %s…），时间线可当因果看"
                         % (s.get("key_count", 1), key[:18]), "stage")
        else:
            self._append("⚠ 没找到业务关联键：时间线只按时间邻近，不能当因果", "warn")
        self._append("  日志 %d 行 / 抓包事务 %d / 发现 %d 条 / 采集缺口 %d 项"
                     % (s["log_lines"], s["transactions"], s["findings"], s["gaps"]),
                     "dim")
        self._append("  报告：%s" % self.last_html, "stage")
        self.summary.configure(
            text="完成。发现 %d 条问题%s。点「打开报告」看时间线与流程图。"
                 % (s["findings"],
                    "" if key else "（无关联键，结论置信度受限）"))
        try:
            webbrowser.open("file:///" + self.last_html.replace("\\", "/").lstrip("/"))
        except Exception:
            pass

    def _fail(self, msg: str):
        self._set_busy(False)
        self._append("✗ " + msg, "err")
        self.summary.configure(text="失败：" + msg.split("\n")[0][:160])

    # ── 本地分析 ──────────────────────────────────────────────────
    def _on_analyze_local(self):
        if self.busy:
            return
        pkg = filedialog.askopenfilename(
            title="选择证据包",
            filetypes=[("证据包", "*.tar.gz *.tgz *.tar"), ("所有文件", "*.*")])
        if not pkg:
            return
        self._set_busy(True)
        self._append("=" * 60)
        self._append("分析本地证据包：%s" % pkg, "stage")

        def work():
            outdir = os.path.join(os.path.dirname(pkg),
                                  "report-%s" % time.strftime("%Y%m%d-%H%M%S"))
            try:
                s = CLI.run_analyze(pkg, outdir)
            except Exception as e:
                self.q.put(("fail", "分析失败：%s" % e)); return
            class _R:
                local_pkg = pkg
            self.q.put(("done", (s, _R())))

        threading.Thread(target=work, daemon=True).start()

    def _open_report(self):
        if self.last_html and os.path.isfile(self.last_html):
            webbrowser.open("file:///" + self.last_html.replace("\\", "/").lstrip("/"))

    def _on_close(self):
        if self.busy and not messagebox.askyesno(
                "仍在运行", "采集还没结束，现在退出会中断。确定退出吗？"):
            return
        self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
