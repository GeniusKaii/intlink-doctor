# intlink-doctor

三方系统对接件排障助手。A 系统 ↔ 对接件/中间件 ↔ B 系统，任何公司、任何协议都能用。

Windows 上开界面填几项 → 一键推到目标机采集 → 自动分析 → 出时间线、流程图和下一步方向。

## 它解决什么问题

对接件出故障时，工程师要回答的其实是四个问题：

1. 对接件到底是哪个进程，它连的是谁（哪个 IP 哪个端口）
2. 它实际在写哪份日志（不是配置里写的那个）
3. 那个时间窗里链路上到底发生了什么
4. 日志和报文对不对得上，对不上的话是谁的问题

传统做法是登机器、凭经验敲命令、来回几趟。这个工具把这套流程固定下来，
一次跑完出证据包，分析可以反复重算，不用二次上机。

## 核心设计

**分析全在 Windows 侧，目标机只做采集。** 客户机通常无 root、无 tcpdump、不能装包、
物理隔离。所以目标机零依赖（bash + 可选 python3），采不到就记缺口，解析和出图全在本地。

**端口靠 inode 反查，不靠程序名猜。** 对接件出问题多半坏在它作为客户端往外连的
那条连接上，所以走 `/proc/<pid>/fd` → `socket:[inode]` → netns 的 tcp 表反查五元组。

**日志以 fd 为准，不信配置。** 配置里写的路径经常不是实际写的（包内配置覆盖、
容器重定向）。四路来源按可信度排序：fd 实际打开的 > 配置声明 > 命令行 > 邻近目录。

**关联键决定图的形态，这是本工具最较真的地方。**

| 情况 | 输出 |
| --- | --- |
| 日志里的 ID 在抓包报文里也能找到 | 按该键绑定日志/请求/响应，画真实时序图 |
| 只在日志里有，抓包里搜不到 | 拒绝当键，退回时间邻近，图上标低置信度 |
| 完全没有抓包 | 不编造关联，明确写「证据不足」 |

宁可少画一张图，也不画一张让工程师当真的假图。

## 快速开始

```bash
# 界面（推荐）
python -m intlink_doctor

# 命令行：分析已有证据包，可反复重算
python -m intlink_doctor.cli analyze intlink-probe-xxx.tar.gz --out ./report

# 命令行：直接对目标机跑
python -m intlink_doctor.cli run --host 10.0.0.9 --user root --hint green-adapter --secs 60
```

目标机上也可以单独跑采集脚本（不需要 Windows 侧）：

```bash
bash agent/intlink_probe.sh --hint green-adapter --secs 60
bash agent/intlink_probe.sh --auto --list-only      # 只侦察不抓包
bash agent/intlink_probe.sh --selftest              # 交付前自检
```

产出 `intlink-probe-<host>-<时间戳>.tar.gz`，尾部打印 `RESULT=` 和 `SHA256=`。

## 目录

| 路径 | 说明 |
| --- | --- |
| `agent/intlink_probe.sh` | 目标机侧单文件采集脚本（只读） |
| `intlink_doctor/pcap_http.py` | 纯 Python pcap/pcapng 解析 + TCP 重组 + HTTP/1.x |
| `intlink_doctor/correlate.py` | 关联键探测、时间线、诊断规则 |
| `intlink_doctor/report.py` | markdown / HTML / mermaid 报告 |
| `intlink_doctor/ssh_runner.py` | SSH 预检、推送、采集、下载、校验 |
| `intlink_doctor/gui.py` | tkinter 界面 |
| `intlink_doctor/cli.py` | 命令行 |
| `tests/` | 全部测试（含真实 SSH 与 GUI 联调） |

## 有效配置对照（最能指向「要改什么」的一块）

光看配置没用，要看**配置声明的值**和**抓包实际观测到的行为**是否一致：

| 配置项 | 配置值 | 实测 | 判定 |
| --- | --- | --- | --- |
| `timeout` | `30s` | 3046 ms | **不符** |
| `endpoint` | `http://10.0.0.2:18098/api/report` | 10.0.0.2:18098 | 一致 |
| `retry` | `2` | 1 次 | 一致 |
| `port` | `18080` | - | 不确定 |

上面第一行是真流量跑出来的：配置写 30s，对接件实际 3s 就放弃，
说明这份配置很可能没生效（读错文件 / 被 `-D` 或环境变量覆盖 / 代码写死）。

判定规则刻意保守，不该下结论时一定标「不确定」：

- 配置写 `timeout: 30` 没单位 → 不确定（不猜秒还是毫秒）
- 窗口内全是成功请求、量不到超时 → 不确定（没说「配置正确」）
- 没有业务关联键 → 不能数重试
- 线程池深度这类抓包量不出来的 → 只列出，不判定

## 测试

```bash
python tests/run_all.py              # 不需要环境的全套
python tests/run_all.py --with-live  # 加上真实 SSH / 非 root 降级 / 真实网卡 / GUI
```

`--with-live` 需要一台能 SSH 的 Linux（本仓库用 WSL 验证）。

**当前验证状态**：13 个套件全 PASS，其中六个是真环境验证，不是 mock：

- 真实 SSH 全流程（预检→推脚本→采集→下载→SHA 校验→清理）
- 真实非 root、无免密 sudo 账号的降级路径
- 真实网卡跨网络抓包（220 个包 / 0 个回环包，确认流量走 `eth0` 而非 `lo`）
- GUI 真实窗口抓帧（`PrintWindow`，锁屏环境也能验排版）
- GUI 真实鼠标点击（pyautogui 点输入框/复选框/按钮，跑到出报告）
- 有效配置抽取的真流量验证

设计说明与四个现场坑的成因见 `DESIGN.md`。

## 边界（写清楚，避免误用）

- 只解析 HTTP/1.x **明文**。HTTPS 和私有二进制协议不解析，会明确标为「无可解析事务」。
- 不解 IP 分片重组，只做 TCP 流重组。
- 非 root 且无免密 sudo 时抓不了包，只能给连接与重传统计。
- 目标机没有 python3 时，进程/端口解析降级为 `ss`/`ps` 文本，日志发现能力下降。
- 反编译/修复方案**不做**。工具只给「包身份 + 有效配置对比 + 下一步方向」，
  不给代码级修复结论——那不是证据能支撑的东西。

## 安全

- 目标机侧只读：不写业务目录、不改配置、不重启服务。临时文件跑完就删。
- 密码不落盘、不进命令行（走 SSH_ASKPASS），推荐用密钥。
- 日志与报文切片默认脱敏（URL 账密、password/token/session_id）。
- pcap 可能含个人信息，**外发前必须自行脱敏**。
