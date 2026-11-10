"""权限降级验证：用非 root、无免密 sudo 的账号跑一遍，确认

  1. 预检能判出「抓不了包」，而不是等到调 tcpdump 才失败
  2. 抓包不可用时，采集脚本仍跑完并出完整证据包（不白跑）
  3. 缺口原样写进报告，而不是让结论看起来完整
  4. 读不到别人进程的 /proc/<pid>/fd 时记 gap，不崩
  5. 日志读不到也如实反映

这是「一次搞定、不让人反复上机」的核心：降级也要出完整包。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intlink_doctor import cli as CLI
from intlink_doctor import ssh_runner as SSH
from _livetest import target_host, low_priv_user, skip


def main():
    rc = 0

    HOST = target_host()
    LOWUSER = low_priv_user()
    if not HOST:
        return skip("没配 INTLINK_TEST_SSH_HOST，跳过权限降级测试")
    if not LOWUSER:
        return skip("没配 INTLINK_TEST_LOW_USER（需要一台机器上的普通账号），跳过降级测试")

    def chk(cond, msg):
        nonlocal rc
        if cond:
            print("  PASS %s" % msg)
        else:
            print("  FAIL %s" % msg)
            rc = 1

    print("== 目标: %s@%s（非 root / 无免密 sudo）==" % (LOWUSER, HOST))
    t = SSH.Target(host=HOST, user=LOWUSER)

    print("== 1. 预检应能自己判出抓不了包 ==")
    pf = SSH.preflight(t)
    if not pf.get("connected"):
        print("  SKIP 连不上（%s）" % pf.get("error"))
        return 0
    print("    uid=%s sudo_nopass=%s tcpdump=%s"
          % (pf.get("uid"), pf.get("sudo_nopass"), pf.get("tcpdump")))
    chk(pf.get("uid") not in ("0", None), "确认是非 root 用户")
    chk(pf.get("sudo_nopass") != "yes", "确认没有免密 sudo")
    chk(pf.get("can_capture") is False, "预检判定不能抓包（can_capture=False）")
    degraded = " ".join(pf.get("degraded") or [])
    chk("抓不了包" in degraded or "无免密 sudo" in degraded,
        "降级原因写清楚了: %s" % degraded)

    print("== 2. 采集仍须跑完并出完整包（不白跑）==")
    script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "agent", "intlink_probe.sh")
    lines = []

    def on_line(tag, ln):
        lines.append((tag, ln))
        if tag in ("stage", "warn"):
            print("    [%s] %s" % (tag, ln))

    pkgdir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "lowperm-out")
    # 故意不传 --list-only：让它自己因为权限不足而降级，这才是要验的路径
    res = SSH.deploy_and_capture(
        t, script,
        {"hint": ["sshd"], "secs": 6, "window_secs": 120},
        on_line=on_line, local_out_dir=pkgdir)

    chk(not res.error, "采集没有报错退出: %s" % (res.error or "-")[:120])
    chk(bool(res.local_pkg and os.path.isfile(res.local_pkg)),
        "拿到了完整证据包: %s" % (res.local_pkg or "-"))
    if not res.local_pkg:
        return 1

    print("== 3. 分析：缺口必须进结论，不能被藏起来 ==")
    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "lowperm-report")
    s = CLI.run_analyze(res.local_pkg, outdir)
    print("    日志行=%d 事务=%d 发现=%d 缺口=%d"
          % (s["log_lines"], s["transactions"], s["findings"], s["gaps"]))
    chk(s["transactions"] == 0, "抓不了包 → 事务数为 0（没编造报文）")
    chk(s["gaps"] >= 1, "缺口 >= 1 条（如实记录降级）")

    md = open(s["outputs"]["report_md"], encoding="utf-8").read()
    chk("采集缺口" in md, "报告里有「采集缺口」章节")
    chk(("root" in md) or ("sudo" in md), "报告里说明了补证据需要 root/sudo")
    chk("未找到" in md or "低置信度" in md, "无关联键时明确标注低置信度")
    # 关键：不能出现「一切正常」式的结论
    chk("等于系统正常" not in md or "不等于" in md,
        "没有把「没发现异常」说成「系统正常」")

    print("== 4. 采集脚本的 gaps / 产物内容 ==")
    import tarfile
    gaps_txt = ""
    procs_tsv = ""
    socks_tsv = ""
    with tarfile.open(res.local_pkg, "r:*") as tf:
        for n in tf.getnames():
            if n.endswith("/20_procs.tsv"):
                procs_tsv = tf.extractfile(n).read().decode("utf-8", "replace")
            elif n.endswith("/30_sockets.tsv"):
                socks_tsv = tf.extractfile(n).read().decode("utf-8", "replace")
            elif n.endswith("90_gaps.txt") or n.endswith("91_parse_gaps.txt"):
                t = tf.extractfile(n).read().decode("utf-8", "replace").strip()
                if t:
                    gaps_txt += t + "\n"
                    print("    [%s]" % os.path.basename(n))
                    for ln in t.splitlines()[:6]:
                        print("      " + ln)

    # 核心承诺：非 root 也必须能找到进程（靠 comm），不能因为读不到 cmdline 就放弃
    chk(procs_tsv.count("\n") >= 2, "非 root 下仍识别到目标进程（%d 行）"
        % max(procs_tsv.count("\n") - 1, 0))
    chk("sshd" in procs_tsv, "靠 comm 匹配到了 sshd（不依赖 cmdline）")

    # fd 读不到时，socket 必须走 uid 反查兜底，并且把「可能混入同用户连接」写清楚
    if "fd 不可读" in gaps_txt or "权限拒绝" in gaps_txt:
        chk("按 uid" in gaps_txt,
            "fd 被拒后说明了改用 uid 反查（不是无声放弃）")
        chk("混进来" in gaps_txt or "人工确认" in gaps_txt,
            "写明了 uid 反查的副作用（同用户连接会混入）")
    else:
        print("    SKIP 本次 fd 可读，未触发 uid 反查路径")

    print("== 5. 证据包本身必须完整可解析 ==")
    ev, tmp = CLI.open_evidence(res.local_pkg)
    try:
        chk(os.path.isdir(ev.evd), "evidence 目录可定位")
        chk(bool(ev.read("00_summary.txt").strip()), "00_summary.txt 有内容")
        chk(bool(ev.read("05_env.txt").strip()), "05_env.txt 有内容")
        chk("is_root" in ev.read("05_env.txt"), "环境里记录了是否为 root")
    finally:
        if tmp:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    print("ALL PASS" if rc == 0 else "FAILED")
    return rc


if __name__ == "__main__":
    sys.exit(main())
