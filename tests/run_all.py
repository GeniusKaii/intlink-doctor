"""全量测试入口：一个命令跑完所有层（不含真实 SSH，那个需要环境）。

用法：
    python tests/run_all.py            # 跑全部（跳过需要环境的）
    python tests/run_all.py --with-live # 连 WSL 跑真实 SSH + GUI
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# (脚本, 说明, 是否需要真实目标机)
SUITES = [
    ("test_pcap.py", "pcap 解析与 TCP 重组", False),
    ("test_correlate.py", "关联引擎（真键/无键两条路径）", False),
    ("test_process_filter.py", "进程筛选/匹配（SSH 祖先链坑）", False),
    ("test_ssh_runner.py", "SSH 编排（引号/参数/错误解释）", False),
    ("test_config_compare.py", "有效配置对照（配置 vs 实测行为）", False),
    ("test_ssh_live.py", "真实 SSH 全流程（需目标机）", True),
    ("test_permission_degrade.py", "非 root 权限降级（需目标机低权账号）", True),
    ("test_gui_layout.py", "GUI 布局（PrintWindow 抓帧，锁屏可用）", False),
    ("test_gui_click.py", "GUI 真实鼠标点击（需桌面会话）", True),
    ("test_gui_live.py", "GUI 端到端（需目标机+桌面）", True),
]


def run_one(script, name):
    path = os.path.join(HERE, script)
    if not os.path.isfile(path):
        return "MISSING", ""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        p = subprocess.run([sys.executable, path], capture_output=True,
                           text=True, encoding="utf-8", errors="replace",
                           cwd=ROOT, env=env, timeout=600)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""
    out = (p.stdout or "") + (p.stderr or "")
    if "ALL PASS" in out:
        return "PASS", out
    if "SKIP" in out and p.returncode == 0:
        return "SKIP", out
    return "FAIL", out


def run_shell_suite(script, desc):
    """跑 WSL/bash 侧的测试（真实网卡抓包必须在 Linux 里跑）。"""
    path = os.path.join(HERE, script)
    if not os.path.isfile(path):
        return "MISSING", ""
    wsl = shutil.which("wsl")
    if not wsl:
        return "SKIP", "no wsl"
    # 把 Windows 路径换成 WSL 路径
    wpath = path.replace("\\", "/")
    if len(wpath) > 1 and wpath[1] == ":":
        wpath = "/mnt/" + wpath[0].lower() + wpath[2:]
    try:
        p = subprocess.run([wsl, "-d", "Ubuntu", "--", "bash", wpath],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=600)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""
    out = (p.stdout or "") + (p.stderr or "")
    if "ALL PASS" in out:
        return "PASS", out
    return "FAIL", out


def main():
    live = "--with-live" in sys.argv
    print("=" * 62)
    print("intlink-doctor 测试")
    print("=" * 62)

    results = []
    for script, desc, needs_env in SUITES:
        if needs_env and not live:
            results.append((script, desc, "SKIP", "未加 --with-live"))
            print("  SKIP  %-30s %s" % (script, desc))
            continue
        status, out = run_one(script, desc)
        results.append((script, desc, status, out))
        mark = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "SKIP",
                "MISSING": "MISS", "TIMEOUT": "TIME"}.get(status, status)
        print("  %-5s %-30s %s" % (mark, script, desc))
        if status == "FAIL":
            for ln in out.splitlines():
                if "FAIL" in ln or "Error" in ln or "Traceback" in ln:
                    print("        " + ln.strip()[:160])

    # Windows 侧起的假对端不再需要；真实网卡测试在 WSL 内自造流量
    if live:
        for sh, label in (("e2e_realnic.sh", "真实网卡跨网络抓包（非 lo）"),
                          ("e2e_config.sh", "有效配置抽取（真流量）")):
            status, out = run_shell_suite(sh, label)
            results.append((sh, label, status, out))
            print("  %-5s %-30s %s"
                  % ({"PASS": "PASS", "FAIL": "FAIL", "SKIP": "SKIP"}.get(status, status),
                     sh, label))
            if status == "FAIL":
                for ln in out.splitlines():
                    if "FAIL" in ln:
                        print("        " + ln.strip()[:160])

    # CLI 自检单独跑（不是独立脚本）
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    p = subprocess.run([sys.executable, "-m", "intlink_doctor.cli", "selftest"],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", cwd=ROOT, env=env, timeout=300)
    cli_ok = "ALL PASS" in ((p.stdout or "") + (p.stderr or ""))
    results.append(("cli selftest", "报告渲染与置信度标注",
                    "PASS" if cli_ok else "FAIL", ""))
    print("  %-5s %-30s %s" % ("PASS" if cli_ok else "FAIL", "cli selftest",
                               "报告渲染与置信度标注"))

    fails = [r for r in results if r[2] == "FAIL"]
    skips = [r for r in results if r[2] == "SKIP"]
    print("=" * 62)
    print("通过 %d / 失败 %d / 跳过 %d"
          % (len(results) - len(fails) - len(skips), len(fails), len(skips)))
    if skips:
        print("跳过的（需真实目标机）: " +
              ", ".join(s[0] for s in skips))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
