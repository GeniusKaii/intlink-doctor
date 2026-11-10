"""报告生成：把证据包 + 关联结果变成工程师能直接看的结论。

产出三份：
  1. report.md    —— markdown（进 git、粘贴给同事）
  2. report.html  —— 自带 mermaid 渲染，单文件可发
  3. timeline.mmd —— mermaid 源码（可文本 diff）

图的形态由关联键决定，这点在报告正文里必须写明：
  有键 → sequenceDiagram，按键绑定请求/响应/日志
  无键 → 只画请求-响应对，标题和正文都标「低置信度：无业务关联键」
"""
from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone, timedelta

CST = timezone(timedelta(hours=8))


def fmt_ts(epoch: float) -> str:
    if not epoch:
        return "-"
    try:
        return datetime.fromtimestamp(epoch, CST).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except Exception:
        return str(epoch)


def _esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def _mm_esc(s: str, limit: int = 90) -> str:
    """mermaid 标签里不能有裸引号/换行/分号。"""
    s = str(s).replace("\r", " ").replace("\n", " ")
    s = s.replace(";", ",").replace('"', "'")
    if len(s) > limit:
        s = s[:limit] + "..."
    return s


# ── mermaid ───────────────────────────────────────────────────────
def mermaid_sequence(events, key_value: str, has_key: bool,
                     max_events: int = 40) -> str:
    """按事件流画时序图。

    有键时：参与者是「对接件」和「对端」，每个请求/响应成对出现，日志挂在相应位置。
    无键时：只画请求-响应对，并加 note 明说置信度低。
    """
    lines = ["sequenceDiagram"]
    lines.append("    autonumber")
    if has_key:
        lines.append('    participant C as "对接件/客户端"')
        lines.append('    participant S as "对端服务"')
        lines.append('    Note over C,S: 关联键 %s' % _mm_esc(key_value, 60))
    else:
        lines.append('    participant C as "客户端"')
        lines.append('    participant S as "对端服务"')
        lines.append('    Note over C,S: 低置信度：未找到业务关联键，以下仅为时间邻近的请求-响应')

    shown = 0
    for ev in events:
        if shown >= max_events:
            lines.append("    Note over C,S: ...（后续 %d 条已省略，见 timeline 全量）"
                         % (len(events) - shown))
            break
        if ev.kind == "request":
            label = _mm_esc(ev.label)
            # 失败用 --x（叉号），正常用 ->>；注意 mermaid 要求带前导连字符
            arrow = "--x" if ev.is_failure else "->>"
            lines.append("    C%sS: %s" % (arrow, label))
        elif ev.kind == "response":
            lines.append("    S-->>C: %s" % _mm_esc(ev.label))
        else:
            # 日志行：只保留失败行和有键时的关键行，避免图被噪音淹没
            if ev.is_failure or (has_key and ev.level in ("ERROR", "WARN", "FATAL")):
                lines.append("    Note over C: %s" % _mm_esc(ev.label, 110))
        shown += 1
    if not any(l.strip().startswith(("C--", "C-x", "S--")) for l in lines):
        lines.append("    Note over C,S: 该窗口内没有可配对的请求-响应")
    return "\n".join(lines)


def mermaid_flow(findings, key_value: str) -> str:
    """flowchart：失败点分布 + 下一步方向，给「看整体」用。"""
    lines = ["flowchart LR"]
    lines.append('    A["采集证据包"] --> B["进程/端口/日志解析"]')
    lines.append('    B --> C["时间窗抓包"]')
    if key_value:
        lines.append('    C --> D["按关联键对齐<br/>键=%s"]' % _mm_esc(key_value, 40))
    else:
        lines.append('    C --> D["时间邻近对齐<br/>⚠ 无关联键·低置信度"]')
    lines.append('    D --> E["诊断"]')
    cats = []
    for f in findings:
        if f.category and f.category not in cats:
            cats.append(f.category)
    if not cats:
        cats = ["无异常发现"]
    idx = 0
    for c in cats:
        idx += 1
        lines.append('    E --> F%d["%s"]' % (idx, _mm_esc(c, 30)))
    return "\n".join(lines)


# ── markdown ──────────────────────────────────────────────────────
def render_markdown(ctx: dict) -> str:
    md = []
    A = md.append
    meta = ctx["meta"]
    findings = ctx["findings"]
    key = ctx["key"]
    events = ctx["events"]
    lines = ctx["log_lines"]
    txs = ctx["txs"]
    gaps = ctx["gaps"]
    key_vals = ctx.get("key_vals") or []

    A("# 对接件排障报告")
    A("")
    A("| 项 | 值 |")
    A("| --- | --- |")
    A("| 生成时间 | %s |" % fmt_ts(datetime.now(CST).timestamp()))
    A("| 证据包 | `%s` |" % meta.get("package", "-"))
    A("| 目标机 | `%s` |" % meta.get("hostname", "-"))
    A("| 采集时间 | %s |" % meta.get("collected_at", "-"))
    A("| 日志行数 | %d |" % len(lines))
    A("| 抓包事务数 | %d |" % len(txs))
    A("| 关联键 | %s |" % (
        "`%s` 等 %d 个值 (score=%.2f)" % (key.value, len(key_vals or [1]), key.score)
        if key else "**未找到**（结论置信度受限）"))
    A("")

    # 结论先行
    A("## 一、结论")
    A("")
    if not findings:
        A("本次证据里没有发现明确异常。这**不等于**系统正常——只说明在你给的窗口和过滤条件下"
          "抓到的报文与日志里没有可判定的失败。")
    else:
        order = {"high": 0, "medium": 1, "low": 2}
        for f in sorted(findings, key=lambda x: order.get(x.confidence, 3)):
            star = {"high": "【高置信】", "medium": "【中置信】", "low": "【低置信】"}.get(f.confidence, "")
            A("### %s%s" % (star, f.title))
            A("")
            if f.evidence:
                A("**依据**")
                A("")
                for e in f.evidence:
                    A("- `%s`" % str(e).replace("`", "'"))
                A("")
            if f.next_step:
                A("**下一步**：%s" % f.next_step)
                A("")
    A("")

    # 关联键判定过程 —— 这是可以让别人复核的部分
    A("## 二、关联键是怎么定的")
    A("")
    cands = ctx.get("candidates") or {}
    groups = ctx.get("key_groups") or {}
    if cands:
        A("在日志里抽候选值，再拿去 pcap 报文里搜。只有**两边都命中**的才算关联键。")
        A("")
        if groups:
            A("**识别到的键类**（真实场景里每笔业务一个值，所以键是「一类」而不是一个）：")
            A("")
            for field, items in groups.items():
                sample = ", ".join("`%s`" % str(c.value)[:40] for c in items[:3])
                A("- `%s` — %d 个取值，最高置信度 %.2f；样例 %s"
                  % (field, len(items), items[0].score, sample))
            A("")
            A("时间线按「命中任一个可信键值」过滤，因此保留的是全部 %d 笔相关业务，"
              "不是只有一笔。" % len(key_vals))
            A("")
        A("| 候选值 | 类型 | 日志命中 | pcap 命中 | 置信度 | 判定 |")
        A("| --- | --- | --- | --- | --- | --- |")
        top = sorted(cands.values(), key=lambda c: -c.score)[:12]
        for c in top:
            if c.score >= 0.5 and c.pcap_hits > 0:
                veredict = "关联键"
            elif c.pcap_hits > 0:
                veredict = "弱证据（<0.5）"
            else:
                veredict = "抓包未命中"
            A("| `%s` | %s | %d | %d | %.2f | %s |"
              % (str(c.value)[:48], c.kind, c.log_hits, c.pcap_hits, c.score, veredict))
        A("")
    else:
        A("**没有任何候选值同时出现在日志和抓包里**，因此本次只按时间邻近对齐。"
          "下面的图和时间线都只能作为线索，不能当调用链结论。")
        A("")

    # 时间线
    A("## 三、时间线")
    A("")
    if key:
        A("按关联键类过滤：只要日志行或报文里命中 %d 个可信键值中的任意一个即保留"
          "（样例 `%s`）。" % (len(key_vals), key.value))
    else:
        A("**低置信度**：未找到关联键，下列事件按时间排序，相邻不代表因果。")
    A("")
    A("| 时间 | 类型 | 来源 | 内容 | 失败 |")
    A("| --- | --- | --- | --- | --- |")
    for ev in events[:120]:
        A("| %s | %s | %s | %s | %s |" % (
            fmt_ts(ev.ts), ev.kind, _esc(ev.source),
            str(ev.label).replace("|", "\\|")[:200],
            "⚠" if ev.is_failure else ""))
    if len(events) > 120:
        A("")
        A("_（共 %d 条，前 120 条已列；完整数据见 timeline.json）_" % len(events))
    A("")

    # 流程图
    A("## 四、流程图")
    A("")
    A("```mermaid")
    A(ctx["mmd_seq"])
    A("```")
    A("")
    A("```mermaid")
    A(ctx["mmd_flow"])
    A("```")
    A("")

    # 采集情况
    A("## 五、有效配置对照")
    A("")
    comps = ctx.get("config_comparisons") or []
    if comps:
        A("把配置文件里声明的行为参数，和抓包实际观测到的行为放在一起比。"
          "**这是全篇唯一能指向「要改什么」的部分**，所以判定规则保守："
          "单位不明、窗口内没样本、抓包量不出来，一律标「不确定」而不是硬下结论。")
        A("")
        A("| 配置项 | 配置值 | 实测 | 判定 | 依据 |")
        A("| --- | --- | --- | --- | --- |")
        order = {"mismatch": 0, "match": 1, "unknown": 2, "unobservable": 3}
        for c in sorted(comps, key=lambda x: order.get(x.verdict, 9)):
            mark = {"mismatch": "**不符**", "match": "一致",
                    "unknown": "不确定", "unobservable": "不可观测"}.get(c.verdict, c.verdict)
            obs = "-" if c.observed is None else str(c.observed)
            # 只有「超时/keepalive」这类时长项才加 ms；重试次数、连接数不是时长，
            # 加了单位会让人误读成 1 毫秒。
            if c.item.kind == "duration" and c.observed is not None:
                obs = "%s ms" % c.observed
            elif c.item.kind == "number" and c.observed is not None:
                n = c.item.full_name
                if "retry" in n or "attempt" in n:
                    obs = "%s 次" % c.observed
                elif "conn" in n or "pool" in n:
                    obs = "%s 条" % c.observed
            A("| `%s` | `%s` | %s | %s | %s |" % (
                c.item.key, c.item.raw, obs, mark,
                str(c.observed_desc).replace("|", "\\|")[:150]))
        A("")
        # 把 mismatch 的详细结论单独展开
        bad = [c for c in comps if c.verdict == "mismatch"]
        for c in bad:
            A("### 不符详情：%s" % c.item.key)
            A("")
            A("- 配置：`%s`（%s:%s）" % (c.item.raw, c.item.file, c.item.line))
            A("- 实测：%s" % c.observed_desc)
            if c.detail:
                A("- 判读：%s" % c.detail)
            A("")
    else:
        A("证据包里没有可对照的配置项（配置里没有超时/重试/连接类参数，"
          "或采集时没找到配置文件）。这部分无法给出结论。")
        A("")
    A("")

    # 采集情况
    A("## 六、采集到的东西 / 没采到的")
    A("")
    procs = ctx.get("procs", [])
    if procs:
        A("| PID | 匹配方式 | 命令 | netns | 容器 |")
        A("| --- | --- | --- | --- | --- |")
        for p in procs[:10]:
            A("| %s | %s | `%s` | %s | %s |" % (
                p.get("pid"), p.get("why"), str(p.get("exe") or p.get("cmdline"))[:70],
                p.get("netns", "-"), p.get("container_id") or "-"))
        A("")
    logs = ctx.get("log_files", [])
    if logs:
        A("日志文件（来源可信度从高到低：fd > config > cmdline > nearby）：")
        A("")
        for l in logs[:12]:
            A("- `%s` — 来源 `%s`, %s 字节" % (l.get("path"), l.get("source"), l.get("size")))
        A("")
    if gaps:
        A("### 采集缺口（这些层没证据，相关结论不能当定论）")
        A("")
        for g in gaps:
            A("- %s" % g)
        A("")
    A("")

    # 附录
    A("## 七、复现与复核")
    A("")
    A("```")
    A("# 1. 目标机采集（只读，不装东西）")
    A("bash intlink_probe.sh --hint <程序名> --secs 60")
    A("")
    A("# 2. 带回 tar.gz，本地出报告")
    A("python -m intlink_doctor.cli analyze <包路径> --out <输出目录>")
    A("")
    A("# 3. 只重跑分析、不重新采集（证据包不变，结论可复算）")
    A("python -m intlink_doctor.cli analyze <包路径> --out <新目录>")
    A("```")
    A("")
    A("> pcap 可能含个人信息，外发前请脱敏；报告里的报文切片已按默认规则遮挡凭据。")
    return "\n".join(md)


# ── html ──────────────────────────────────────────────────────────
HTML_TMPL = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>对接件排障报告 - {host}</title>
<style>
 :root {{ --bg:#0f1419; --fg:#e6e6e6; --dim:#9aa4b2; --line:#2a323d;
          --hi:#6ee7b7; --med:#fbbf24; --low:#f87171; --card:#161c24; }}
 * {{ box-sizing:border-box; }}
 body {{ margin:0; padding:28px; background:var(--bg); color:var(--fg);
        font:14px/1.65 -apple-system,"Segoe UI",system-ui,"Microsoft YaHei",sans-serif; }}
 h1 {{ font-size:22px; margin:0 0 6px; }}
 h2 {{ font-size:17px; margin:30px 0 12px; padding-bottom:6px;
       border-bottom:1px solid var(--line); }}
 h3 {{ font-size:15px; margin:18px 0 8px; }}
 .sub {{ color:var(--dim); font-size:12px; margin-bottom:18px; }}
 .kpis {{ display:flex; flex-wrap:wrap; gap:10px; margin:16px 0 8px; }}
 .kpi {{ background:var(--card); border:1px solid var(--line); border-radius:8px;
         padding:10px 14px; min-width:130px; }}
 .kpi b {{ display:block; font-size:17px; margin-top:2px; }}
 .kpi span {{ color:var(--dim); font-size:11px; }}
 .card {{ background:var(--card); border:1px solid var(--line); border-radius:8px;
          padding:14px 16px; margin:10px 0; }}
 .badge {{ display:inline-block; padding:1px 7px; border-radius:4px; font-size:11px;
           font-weight:600; margin-right:8px; vertical-align:2px; }}
 .high {{ background:rgba(110,231,183,.16); color:var(--hi); }}
 .medium {{ background:rgba(251,191,36,.16); color:var(--med); }}
 .low {{ background:rgba(248,113,113,.16); color:var(--low); }}
 table {{ border-collapse:collapse; width:100%; margin:8px 0; font-size:12.5px; }}
 th,td {{ border:1px solid var(--line); padding:6px 9px; text-align:left;
          vertical-align:top; }}
 th {{ background:#1c232c; color:var(--dim); font-weight:600; }}
 td.mono {{ font-family:ui-monospace,Consolas,monospace; font-size:11.5px; }}
 .ev {{ font-family:ui-monospace,Consolas,monospace; font-size:11.5px;
        color:var(--dim); word-break:break-all; }}
 .fail {{ color:var(--low); font-weight:700; }}
 .warn {{ background:rgba(251,191,36,.08); border-left:3px solid var(--med);
          padding:10px 14px; border-radius:4px; margin:10px 0; }}
 .gap {{ background:rgba(248,113,113,.07); border-left:3px solid var(--low);
         padding:10px 14px; border-radius:4px; margin:10px 0; }}
 code {{ background:#1c232c; padding:1px 5px; border-radius:3px;
         font-family:ui-monospace,Consolas,monospace; font-size:12px; }}
 pre {{ background:#0b0f14; border:1px solid var(--line); border-radius:6px;
        padding:12px; overflow:auto; font-size:12px; }}
 pre.mmd {{ background:#fff; }}
 .note {{ color:var(--dim); font-size:12px; }}
 details {{ margin:8px 0; }}
 summary {{ cursor:pointer; color:var(--dim); }}
</style></head><body>
<h1>对接件排障报告</h1>
<div class="sub">{host} · 采集于 {collected} · 报告生成于 {now}</div>

<div class="kpis">
  <div class="kpi"><span>日志行</span><b>{n_lines}</b></div>
  <div class="kpi"><span>抓包事务</span><b>{n_txs}</b></div>
  <div class="kpi"><span>关联键</span><b>{key_short}</b></div>
  <div class="kpi"><span>发现</span><b>{n_findings}</b></div>
  <div class="kpi"><span>采集缺口</span><b>{n_gaps}</b></div>
</div>

{key_banner}

<h2>一、结论</h2>
{findings_html}

<h2>二、关联键判定</h2>
{keys_html}

<h2>三、流程图</h2>
<p class="note">上图按关联键绑定；下图是诊断路径。</p>
<div class="card"><pre class="mmd mermaid">{mmd_seq}</pre></div>
<div class="card"><pre class="mmd mermaid">{mmd_flow}</pre></div>

<h2>四、时间线</h2>
<div class="card">{timeline_html}</div>

<h2>五、有效配置对照</h2>
{config_html}

<h2>六、采集情况</h2>
{procs_html}
{logs_html}
{gaps_html}

<h2>七、复现</h2>
<pre># 目标机采集（只读）
bash intlink_probe.sh --hint &lt;程序名&gt; --secs 60

# 本地分析（可反复重算，不用重新采集）
python -m intlink_doctor.cli analyze &lt;包路径&gt; --out &lt;输出目录&gt;</pre>
<p class="note">pcap 可能含个人信息，外发前请脱敏。</p>

<script type="module">
import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
mermaid.initialize({{ startOnLoad:true, theme:'default', sequence:{{wrap:true}} }});
</script>
</body></html>
"""


def render_html(ctx: dict) -> str:
    meta = ctx["meta"]
    findings = ctx["findings"]
    key = ctx["key"]
    events = ctx["events"]
    gaps = ctx["gaps"]

    key_banner = ""
    if key:
        key_banner = ('<div class="card"><b>关联键</b>：<code>%s</code>'
                      '<span class="badge high">置信度 %.2f</span>'
                      '<div class="note">日志与抓包两边都命中，本节以下的时间线与流程图可信。</div></div>'
                      % (_esc(key.value), key.score))
    else:
        key_banner = ('<div class="warn"><b>未找到业务关联键</b>：日志里的候选值在抓包报文中均未命中。'
                      '下面的时间线和流程图只按<b>时间邻近</b>组织，<b>不代表因果</b>。'
                      '要得到可当结论的对齐，需要对接件在日志里打印对端报文中的 ID（如 requestId）。</div>')

    order = {"high": 0, "medium": 1, "low": 2}
    fh = []
    if not findings:
        fh.append('<div class="card">本次证据里没有发现明确异常。这不等于系统正常，'
                  '只说明在给定窗口与过滤条件下没有可判定的失败。</div>')
    for f in sorted(findings, key=lambda x: order.get(x.confidence, 3)):
        badge = ('<span class="badge %s">%s</span>' %
                 (f.confidence, {"high": "高置信", "medium": "中置信",
                                 "low": "低置信"}.get(f.confidence, f.confidence)))
        ev = "".join('<div class="ev">%s</div>' % _esc(e) for e in f.evidence[:8])
        ns = ('<div style="margin-top:8px"><b>下一步</b>：%s</div>' % _esc(f.next_step)) if f.next_step else ""
        fh.append('<div class="card"><h3>%s%s</h3>%s%s</div>' % (badge, _esc(f.title), ev, ns))
    findings_html = "\n".join(fh)

    cands = ctx.get("candidates") or {}
    groups = ctx.get("key_groups") or {}
    key_vals = ctx.get("key_vals") or []
    if cands:
        rows = ['<table><tr><th>候选值</th><th>类型</th><th>日志命中</th>'
                '<th>pcap 命中</th><th>置信度</th><th>判定</th></tr>']
        for c in sorted(cands.values(), key=lambda x: -x.score)[:12]:
            if c.score >= 0.5 and c.pcap_hits > 0:
                verd = "关联键"
            elif c.pcap_hits > 0:
                verd = "弱证据（&lt;0.5）"
            else:
                verd = "抓包未命中"
            rows.append('<tr><td class="mono">%s</td><td>%s</td><td>%d</td><td>%d</td>'
                        '<td>%.2f</td><td>%s</td></tr>'
                        % (_esc(str(c.value)[:52]), c.kind, c.log_hits, c.pcap_hits,
                           c.score, verd))
        rows.append("</table>")
        if groups:
            grp = ['<div class="card"><b>识别到的键类</b>'
                   '<div class="note">每笔业务一个值，所以键是「一类」而非一个；'
                   '时间线按命中任一个可信键值过滤。</div><ul>']
            for field, items in groups.items():
                sample = "、".join("<code>%s</code>" % _esc(str(c.value)[:38])
                                   for c in items[:3])
                grp.append('<li><b>%s</b> — %d 个取值，最高置信度 %.2f；样例 %s</li>'
                           % (_esc(field), len(items), items[0].score, sample))
            grp.append("</ul></div>")
            keys_html = "".join(grp) + "".join(rows)
        else:
            keys_html = "".join(rows)
    else:
        keys_html = ('<div class="warn">没有候选值同时出现在日志和抓包里。'
                     '这通常意味着：①对接件日志没打印对端报文里的 ID；②抓包窗口内没复现；'
                     '③流量是加密的。</div>')

    tl = ['<table><tr><th>时间</th><th>类型</th><th>来源</th><th>内容</th><th></th></tr>']
    for ev in events[:150]:
        tl.append('<tr><td class="mono">%s</td><td>%s</td><td class="mono">%s</td>'
                  '<td class="mono">%s</td><td class="fail">%s</td></tr>'
                  % (fmt_ts(ev.ts), ev.kind, _esc(ev.source),
                     _esc(str(ev.label)[:180]), "⚠" if ev.is_failure else ""))
    tl.append("</table>")
    if len(events) > 150:
        tl.append('<p class="note">共 %d 条，显示前 150 条；全量见 timeline.json。</p>' % len(events))
    timeline_html = "".join(tl)

    procs = ctx.get("procs", [])
    if procs:
        pr = ['<table><tr><th>PID</th><th>匹配</th><th>exe / cmdline</th>'
              '<th>netns</th><th>容器</th></tr>']
        for p in procs[:10]:
            pr.append('<tr><td>%s</td><td>%s</td><td class="mono">%s</td>'
                      '<td class="mono">%s</td><td class="mono">%s</td></tr>'
                      % (p.get("pid"), _esc(p.get("why")),
                         _esc(str(p.get("exe") or p.get("cmdline"))[:100]),
                         _esc(p.get("netns", "-")), _esc(p.get("container_id") or "-")))
        pr.append("</table>")
        procs_html = "<h3>进程</h3>" + "".join(pr)
    else:
        procs_html = "<h3>进程</h3><div class='warn'>没有识别到目标进程。</div>"

    logs = ctx.get("log_files", [])
    if logs:
        lg = ['<table><tr><th>日志文件</th><th>来源</th><th>大小</th></tr>']
        for l in logs[:14]:
            lg.append('<tr><td class="mono">%s</td><td>%s</td><td>%s</td></tr>'
                      % (_esc(l.get("path")), _esc(l.get("source")), l.get("size")))
        lg.append("</table>")
        logs_html = "<h3>日志文件</h3>" + "".join(lg)
    else:
        logs_html = "<h3>日志文件</h3><div class='warn'>没有找到日志文件。</div>"

    if gaps:
        gaps_html = ('<h3>采集缺口</h3><div class="gap">%s</div>'
                     % "".join("%s<br>" % _esc(g) for g in gaps))
    else:
        gaps_html = ""

    # 有效配置对照
    comps = ctx.get("config_comparisons") or []
    if comps:
        order = {"mismatch": 0, "match": 1, "unknown": 2, "unobservable": 3}
        ch = ['<p class="note">把配置声明的行为参数与抓包实际观测对照。'
              '单位不明 / 窗口内无样本 / 抓包量不出来的项一律标「不确定」，不硬下结论。</p>',
              '<table><tr><th>配置项</th><th>配置值</th><th>实测</th>'
              '<th>判定</th><th>依据</th></tr>']
        for c in sorted(comps, key=lambda x: order.get(x.verdict, 9)):
            label, cls = {
                "mismatch": ("不符", "fail"),
                "match": ("一致", ""),
                "unknown": ("不确定", ""),
                "unobservable": ("不可观测", ""),
            }.get(c.verdict, (c.verdict, ""))
            obs = "-" if c.observed is None else str(c.observed)
            if c.item.kind == "duration" and c.observed is not None:
                obs = "%s ms" % c.observed
            elif c.item.kind == "number" and c.observed is not None:
                n = c.item.full_name
                if "retry" in n or "attempt" in n:
                    obs = "%s 次" % c.observed
                elif "conn" in n or "pool" in n:
                    obs = "%s 条" % c.observed
            ch.append('<tr><td class="mono">%s</td><td class="mono">%s</td>'
                      '<td class="mono">%s</td><td class="%s">%s</td>'
                      '<td class="mono">%s</td></tr>'
                      % (_esc(c.item.key), _esc(c.item.raw), _esc(obs), cls,
                         _esc(label), _esc(str(c.observed_desc)[:150])))
        ch.append("</table>")
        for c in [x for x in comps if x.verdict == "mismatch"]:
            ch.append('<div class="gap"><b>不符详情：%s</b><br>'
                      '配置 <code>%s</code>（%s:%s）<br>%s<br>%s</div>'
                      % (_esc(c.item.key), _esc(c.item.raw), _esc(c.item.file),
                         _esc(str(c.item.line)), _esc(c.observed_desc),
                         _esc(c.detail)))
        config_html = "".join(ch)
    else:
        config_html = ('<div class="warn">证据包里没有可对照的配置项'
                       '（配置里没有超时/重试/连接类参数，或采集时没找到配置文件）。</div>')

    return HTML_TMPL.format(
        host=_esc(meta.get("hostname", "-")),
        collected=_esc(meta.get("collected_at", "-")),
        now=fmt_ts(datetime.now(CST).timestamp()),
        n_lines=len(ctx["log_lines"]), n_txs=len(ctx["txs"]),
        key_short=(_esc(key.value[:14]) + "...") if key else "未找到",
        n_findings=len(findings), n_gaps=len(gaps),
        key_banner=key_banner, findings_html=findings_html, keys_html=keys_html,
        mmd_seq=_esc(ctx["mmd_seq"]), mmd_flow=_esc(ctx["mmd_flow"]),
        timeline_html=timeline_html, procs_html=procs_html,
        logs_html=logs_html, gaps_html=gaps_html, config_html=config_html,
    )


def write_reports(ctx: dict, outdir: str) -> dict:
    os.makedirs(outdir, exist_ok=True)
    md = render_markdown(ctx)
    html_s = render_html(ctx)
    paths = {
        "report_md": os.path.join(outdir, "report.md"),
        "report_html": os.path.join(outdir, "report.html"),
        "timeline_mmd": os.path.join(outdir, "timeline.mmd"),
        "flow_mmd": os.path.join(outdir, "flow.mmd"),
        "timeline_json": os.path.join(outdir, "timeline.json"),
        "findings_json": os.path.join(outdir, "findings.json"),
    }
    with open(paths["report_md"], "w", encoding="utf-8") as f:
        f.write(md)
    with open(paths["report_html"], "w", encoding="utf-8") as f:
        f.write(html_s)
    with open(paths["timeline_mmd"], "w", encoding="utf-8") as f:
        f.write(ctx["mmd_seq"])
    with open(paths["flow_mmd"], "w", encoding="utf-8") as f:
        f.write(ctx["mmd_flow"])
    with open(paths["timeline_json"], "w", encoding="utf-8") as f:
        json.dump([{
            "ts": e.ts, "time": fmt_ts(e.ts), "kind": e.kind, "label": e.label,
            "detail": e.detail, "level": e.level, "is_failure": e.is_failure,
            "source": e.source,
        } for e in ctx["events"]], f, ensure_ascii=False, indent=1)
    with open(paths["findings_json"], "w", encoding="utf-8") as f:
        json.dump([fd.to_dict() for fd in ctx["findings"]], f,
                  ensure_ascii=False, indent=1)
    return paths
