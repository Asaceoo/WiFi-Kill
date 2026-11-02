# CLAUDE.md — WiFiKill AI 协作规则

> 本文件是给「在本仓库里工作的 AI 助手」的规则手册。人类快速上手看 README.md；
> 深入机制看 docs/。所有规则以「下次 AI 不看到就会犯错」为唯一标准，**不是变更日志**。

## 项目概览

WiFiKill 是一个 Windows 桌面 GUI 应用：扫描局域网设备，并对选中设备做 ARP 双向投毒阻断
（支持**占空比限速**：断断通通体感卡顿而非全断）；另含「本机守护（Guard）」被动防御——
持续核对并纠正网关真实映射，抵御外部 ARP/NDP 投毒；「全网哨兵（Sentinel）」设备基线库——
新设备上线告警、投毒者指认、事件流留痕。
纯标准库 + scapy，零第三方 UI 库；PyInstaller 单文件打包 + Inno Setup 安装版 + 打包版 zip。
当前版本 **v2.6.0**（版本真源 `versions.json`）。

## 技术栈与运行环境

- 语言：Python 3.10+（构建/CI 用 3.12；需自带 tkinter）
- 关键依赖：scapy 2.8.0（报文构造/发包）；PyInstaller + Inno Setup 6（仅构建）
- 运行时外部驱动：**Npcap**（发二层帧必需，安装时勾选 `WinPcap API-compatible Mode`）
- 平台：仅 Windows（Windows 10/11）

## 目录结构（角色）

| 文件 | 职责 |
|---|---|
| `core.py` | 逻辑层：设备发现 / 报文构造 / 阻断会话（含**占空比限速** `_should_poison`）/ 状态持久化 / 单实例锁 / 白名单 / 安全不变量（`Killer._is_protected_target` API 层强制）/ **本机守护 `Guard`** / **全网哨兵 `Sentinel`** |
| `gui.py` | 表现层：Canvas 自绘主窗口，耗时操作走工作线程，结果经队列回主线程 |
| `ui.py` | 视觉层：莫兰迪色板、圆角绘制、Canvas 按钮（换肤带动画代数令牌）、动效调度 `ui.Anim` |
| `tray.py` | 系统托盘：纯 ctypes 调 `Shell_NotifyIcon`，独立线程消息循环，`notify()` 气泡通知 |
| `ipv6.py` | IPv6 层：环境探测、LLA 探明、**多目标**定向 NDP 投毒（`NdpManager`/`NdpBlocker`，含 preflight 结构化护栏） |
| `selftest.py` | GUI 端到端自检（46 项，含守护演练与哨兵链路） |
| `tests/test_edge.py` | 边界与故障路径测试（34 项） |
| `tests/test_ipv6.py` | IPv6 报文级测试（58 项，CI 可跑） |
| `tests/test_guard.py` | 本机守护单元测试（21 项，CI 可跑） |
| `tests/test_sentinel.py` | 全网哨兵单元测试（10 项，CI 可跑） |
| `tests/test_throttle.py` | 占空比限速单元测试（6 项，CI 可跑） |
| `build.py` | 一键构建 + 语义化版本自增 + 文档版本同步 |
| `versions.json` | 版本真源（app / user_manual / tech_manual / build / released） |
| `WiFiKill.spec` | PyInstaller 配置 |
| `installer/` | Inno Setup 脚本与中文语言文件 |
| `tools/` | 图标与概念图生成（`make_images.py` 含 `make_guard`） |
| `.github/workflows/release.yml` | 推 tag `v*` 自动构建发布（跑五套测试 → 构建 → Release） |

## 常用命令

```bash
# 环境安装（首次）
python -m venv .buildenv
.buildenv\Scripts\pip install scapy pyinstaller

# 运行
python gui.py                    # 或 .buildenv\Scripts\python gui.py

# 测试（纯脚本，非 pytest，失败退出码非 0）
python tests/test_edge.py        # 边界 34 项，不碰真实设备
python tests/test_ipv6.py        # IPv6 报文级 58 项，不发包
python tests/test_guard.py       # 本机守护 21 项，不发包
python tests/test_sentinel.py    # 全网哨兵 10 项，不发包
python tests/test_throttle.py    # 占空比限速 6 项，不发包
python selftest.py               # GUI 端到端 46 项，驱动真实窗口（守护以演练模式）

# 构建
python build.py --bump minor     # 语义化版本自增 + 文档同步 + 出三产物
python build.py --no-bump        # 用当前版本重新打包（调试）
python build.py --zip-only       # 只出打包版 zip
```

## 环境变量

本项目**不使用任何环境变量**（`grep os.environ/getenv` 零命中）。
不要引入；确需引入时须同步更新本文档与 README。

## 硬边界（红线，违反即事故）

1. **禁止阻断网关与本机（API 层强制，任何调用方无法绕过）**：IPv4 走 `core.Killer.add`
   （目标 IP 或 MAC 任一命中网关/本机即抛 `BlockError`）；IPv6 走 `NdpManager.add` 结构化
   IP/MAC 校验 + `NdpBlocker.preflight` 双层拒绝。GUI 过滤只是第一道，不是唯一一道。
2. **Guard 只发真实信息**：纠正包只宣告「网关 IP/LLA ↔ 真实网关 MAC」，L2 源用本机 MAC
   不冒充网关；基准必须「缓存+实时」双源一致，分歧/不可达一律 fail closed；
   演练模式（dry_run）绝不发送真实包、**绝不触碰本机 ARP/NDP 缓存**。
3. **core.py 禁止 import tkinter**：逻辑层必须可被脚本 / 测试 / 未来 CLI 复用。
4. **不提交构建产物**：`dist/`、`build/`、`.buildenv/`、`__pycache__/`、`.wifikill-state.json`、
   `whitelist.txt`、`guard.json`、`sentinel.json`、`selftest_out.txt`、`t[0-9]*_*.png` 均已 gitignore。
5. **测试保持纯脚本语义**：`sys.exit(1 if FAIL)`；CI 已设 `PYTHONUTF8=1`，中文输出不崩溃。
6. **改动动效 / 图标后跑 `selftest.py`**；构建前跑全量测试（边界 + IPv6 + 守护 + 哨兵 + 限速 + 自检）；
   打 tag 前核对 `release.yml` 的发布说明 body 是否与版本内容一致。
7. **ui.py 常量先用先查**：引用 `ui.XXX` 前确认常量存在（OK_DK/OLIVE_DK 曾两次缺失，
   无头测试抓不到、真机渲染即崩）；core.py 内调用自身模块函数直接用裸名，禁止 `core.xxx` 自引用。

## 设计原则

- 三层架构：`core`（逻辑）/ `ui`（视觉）/ `gui`（表现 + 编排）；`core` 不引 tkinter。
- 所有耗时操作在工作线程，经队列回主线程；禁止在主线程发 ARP / 阻塞。
- 安全不变量是可测试纯函数；网关 / 本机在 IPv4 与 IPv6 两条路径上都不可阻断。
- 崩溃恢复：每次增删目标都原子写 `.wifikill-state.json`，异常退出后重启主动询问恢复；
  残留记录与当前网络（iface / gateway_ip）不一致时自动忽略并清除。
- 线程启停一律「防并发」：`start()` 前先 join 尚未退出的旧线程（`Guard` / `Killer` 同源模式）；
  UI 动画用代数令牌（`_anim_gen`），旧动画循环在新动画/启停开始时立即退场。
- 广播帧不会回环本机协议栈：跨机纠正靠重宣告，本机自愈靠 `arp -d` 删除脏缓存后重建。

## 深入文档

| 文档 | 受众 | 内容 |
|---|---|---|
| `README.md` | 人类 | 入门 + 概念图 + 20 个使用实例 + 免责声明 |
| `docs/USER_MANUAL.md` | 使用者 | 完整操作步骤 + 故障排查（v1.6.0） |
| `docs/TECH_MANUAL.md` | 开发者 | 报文结构 / 线程模型 / 测试 / 打包（v1.6.0） |
| `CHANGELOG.md` | 所有人 | 每个版本改了什么 |

<!-- neat-freak: initialized at 2026-11-02 -->
