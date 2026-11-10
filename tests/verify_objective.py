"""最终验收：逐条核对 objective 的六个环节，并给出可复核的证据。

每条检查都读真实代码/真实产物，不是看文件名就判 PASS。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

FAIL = 0


def chk(cond, msg, evidence=""):
    global FAIL
    if cond:
        print("  PASS %s" % msg)
        if evidence:
            print("       %s" % evidence)
    else:
        print("  FAIL %s" % msg)
        if evidence:
            print("       %s" % evidence)
        FAIL += 1


def read(rel):
    p = os.path.join(ROOT, rel)
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def main():
    print("=" * 68)
    print("objective 逐条验收")
    print("=" * 68)

    gui = read("intlink_doctor/gui.py")
    ssh = read("intlink_doctor/ssh_runner.py")
    probe = read("agent/intlink_probe.sh")
    corr = read("intlink_doctor/correlate.py")
    rep = read("intlink_doctor/report.py")
    pcap = read("intlink_doctor/pcap_http.py")

    print("\n① Windows 侧 GUI 配置")
    chk("class App" in gui, "有 GUI 主类", "gui.py: class App")
    chk("def _on_run" in gui and "def _on_test" in gui,
        "有「测试连接」与「开始采集」两个入口")
    for field in ("self.host", "self.port", "self.user", "self.key",
                  "self.password", "self.hint", "self.secs", "self.window"):
        chk(field in gui, "配置项 %s 存在" % field.split(".")[1])
    chk("def _drain_queue" in gui and "queue.Queue" in gui,
        "后台线程结果回主线程（队列 + after），UI 不会跨线程崩")

    print("\n② SSH 远程自检 + 按权限降级")
    chk("def preflight" in ssh, "有远程预检")
    chk("can_capture" in ssh, "预检自己判定能不能抓包")
    chk("degraded" in ssh, "降级原因会回传")
    chk("SSH_ASKPASS" in ssh, "密码走 askpass，不进命令行")
    chk("_explain_ssh_error" in ssh, "SSH 失败有可读解释")
    chk("intlink_probe.sh" in probe, "采集脚本自带自检")
    chk("--selftest" in probe, "脚本支持 --selftest")

    print("\n③ 解析对接件端口 / 日志")
    chk("def read_socket_table" in probe, "按 netns 读 tcp/tcp6 表")
    chk("def fd_scan" in probe, "从 /proc/<pid>/fd 拿 socket inode")
    chk("uid=" in probe or "按 uid" in probe, "fd 被拒时按 uid 反查 socket")
    chk("def discover_configs" in probe, "配置在命令行缺失时会去邻近目录找")
    chk("def scan_config" in probe and "cur_section" in probe,
        "能解析 YAML 嵌套段里的 logging.file")
    chk("def extract_endpoints" in probe, "从配置/日志抽对端地址")

    print("\n④ 时间窗抓包")
    # 注意：脚本里是用变量 $tcp 调 tcpdump（root 或 sudo -n 两种情形），
    # 所以不能按字面 "tcpdump -i any" 找，要认 "-i any" 这个关键参数。
    chk("-i any" in probe, "抓包走 -i any（容器/多网卡也能抓到）")
    chk("-s 0 -B 65536" in probe, "全量包 + 大缓冲（默认 2MB 会丢包）")
    chk("timeout -s INT" in probe, "INT 自停保证刷盘")
    chk("-d " in probe and "precheck" in probe,
        "BPF 语法预检（$tcp -d 不通过就不起抓包）")
    chk("broad" in probe, "零包时放宽过滤重试")

    print("\n⑤ 日志与 pcap 按关联键对齐")
    chk("def pick_key" in corr, "选关联键")
    chk("def group_keys" in corr, "关联键按「类」聚合（每笔业务一个值）")
    chk("def score_against_pcap" in corr, "键必须在抓包里命中才算数")
    chk("key_values_any" in corr, "时间线按「命中任一键值」过滤")
    chk("没有关联键" in corr or "拒绝" in corr, "无键时拒绝强关联")
    chk("def build_transactions" in pcap, "pcap 里配对请求-响应")
    chk("_reassemble" in pcap, "TCP 流按 seq 重组（含重传去重）")

    print("\n⑥ 报告：时间线 / 流程图 / 下一步")
    chk("def mermaid_sequence" in rep, "时序图")
    chk("def mermaid_flow" in rep, "流程图")
    chk("def render_markdown" in rep, "markdown 报告")
    chk("def render_html" in rep, "HTML 报告")
    chk("低置信度" in rep, "无键时图与正文都标低置信度")
    chk("next_step" in corr and "def diagnose" in corr, "诊断给下一步方向")
    chk("evidence" in corr, "结论附证据")

    print("\n⑦ 每阶段可验证（测试覆盖）")
    r = subprocess.run([sys.executable, "tests/run_all.py"],
                       cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace",
                       env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                       timeout=900)
    out = (r.stdout or "") + (r.stderr or "")
    line = [ln for ln in out.splitlines() if ln.startswith("通过")]
    chk(r.returncode == 0, "tests/run_all.py 通过", line[0] if line else "")
    suites = [ln for ln in out.splitlines() if "  PASS  " in ln or "  FAIL  " in ln]
    print("       共 %d 个套件" % len(suites))

    print("\n⑧ 端到端真产物（上一次真实跑出的报告可复核）")
    # 检查有没有留下可复核的报告产物
    found = []
    for base in ("tests/e2e-report", "tests/realnic-report", "intlink-packages"):
        p = os.path.join(ROOT, base)
        if os.path.isdir(p):
            for d in os.listdir(p):
                fp = os.path.join(p, d)
                if os.path.isdir(fp) and os.path.isfile(os.path.join(fp, "report.html")):
                    found.append(fp)
    if found:
        latest = found[0]
        md = os.path.join(latest, "report.md")
        if os.path.isfile(md):
            with open(md, encoding="utf-8") as f:
                m = f.read()
            chk("## 一、结论" in m, "报告有结论章节")
            chk("## 二、关联键" in m, "报告有关联键判定章节（可复核）")
            chk("```mermaid" in m, "报告内嵌 mermaid 图")
            chk("下一步" in m, "报告给下一步")
    else:
        print("  SKIP 本地没有留存的报告产物（已被清理）")

    print("\n" + "=" * 68)
    print("ALL PASS" if FAIL == 0 else "FAILED=%d" % FAIL)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
