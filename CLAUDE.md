# CLAUDE.md — WiFiKill AI 协作规则

> 本文件是给「在本仓库里工作的 AI 助手」的规则手册。人类快速上手看 README.md；
> 深入机制看 docs/。所有规则以「下次 AI 不看到就会犯错」为唯一标准，**不是变更日志**。

## 项目概览

WiFiKill 是一个 Windows 桌面 GUI 应用：扫描局域网设备，并对选中设备做 ARP 双向投毒阻断。
纯标准库 + scapy，零第三方 UI 库；PyInstaller 单文件打包 + Inno Setup 安装版 + 打包版 zip。
当前版本 **v2.3.0**（版本真源 `versions.json`）。

## 技术栈与运行环境

- 语言：Python 3.10+（构建/CI 用 3.12；需自带 tkinter）
- 关键依赖：scapy 2.8.0（报文构造/发包）；PyInstaller + Inno Setup 6（仅构建）
- 运行时外部驱动：**Npcap**（发二层帧必需，安装时勾选 `WinPcap API-compatible Mode`）
- 平台：仅 Windows（Windows 10/11）

## 目录结构（角色）

| 文件 | 职责 |
|---|---|
| `core.py` | 逻辑层：设备发现 / 报文构造 / 阻断会话 / 状态持久化 / 单实例锁 / 白名单 / 安全不变量 `is_protected()` |
| `gui.py` | 表现层：Canvas 自绘主窗口，耗时操作走工作线程，结果经队列回主线程 |
| `ui.py` | 视觉层：莫兰迪色板、圆角绘制、Canvas 按钮、动效调度 `ui.Anim` |
| `tray.py` | 系统托盘：纯 ctypes 调 `Shell_NotifyIcon`，独立线程消息循环 |
| `ipv6.py` | IPv6 层：环境探测、链路本地地址探明、定向 NDP 投毒与失控保护 |
| `selftest.py` | GUI 端到端自检（28 项） |
| `tests/test_edge.py` | 边界与故障路径测试（23 项） |
| `tests/test_ipv6.py` | IPv6 报文级测试（34 项，CI 可跑） |
| `build.py` | 一键构建 + 语义化版本自增 + 文档版本同步 |
| `versions.json` | 版本真源（app / user_manual / tech_manual / build / released） |
| `WiFiKill.spec` | PyInstaller 配置 |
| `installer/` | Inno Setup 脚本与中文语言文件 |
| `tools/` | 图标与概念图生成 |
| `.github/workflows/release.yml` | 推 tag `v*` 自动构建发布 |

## 常用命令

```bash
# 环境安装（首次）
python -m venv .buildenv
.buildenv\Scripts\pip install scapy pyinstaller

# 运行
python gui.py                    # 或 .buildenv\Scripts\python gui.py

# 测试（纯脚本，非 pytest，失败退出码非 0）
python tests/test_edge.py        # 边界 23 项，不碰真实设备
python tests/test_ipv6.py        # IPv6 报文级 34 项，不发包
python selftest.py               # GUI 端到端 28 项，驱动真实窗口

# 构建
python build.py --bump minor     # 语义化版本自增 + 文档同步 + 出三产物
python build.py --no-bump        # 用当前版本重新打包（调试）
python build.py --zip-only       # 只出打包版 zip
```

## 环境变量

本项目**不使用任何环境变量**（`grep os.environ/getenv` 零命中）。
不要引入；确需引入时须同步更新本文档与 README。

## 硬边界（红线，违反即事故）

1. **禁止阻断网关与本机**：任何路径（单目标 / 全阻断）都必须经 `core.is_protected()` 过滤，
   受保护设备提示并跳过。GUI 不提供绕过开关。
2. **core.py 禁止 import tkinter**：逻辑层必须可被脚本 / 测试 / 未来 CLI 复用。
3. **不提交构建产物**：`dist/`、`build/`、`.buildenv/`、`__pycache__/`、`.wifikill-state.json`、
   `whitelist.txt`、`t[0-9]*_*.png` 均已 gitignore。
4. **测试保持纯脚本语义**：`sys.exit(1 if FAIL)`；CI 已设 `PYTHONUTF8=1`，中文输出不崩溃。
5. **改动动效 / 图标后跑 `selftest.py`**；构建前跑全量测试（边界 + IPv6 + 自检）。

## 设计原则

- 三层架构：`core`（逻辑）/ `ui`（视觉）/ `gui`（表现 + 编排）；`core` 不引 tkinter。
- 所有耗时操作在工作线程，经队列回主线程；禁止在主线程发 ARP / 阻塞。
- 安全不变量 `is_protected()` 是可测试纯函数；网关 / 本机永远不可阻断。
- 崩溃恢复：每次增删目标都原子写 `.wifikill-state.json`，异常退出后重启主动询问恢复。

## 深入文档

| 文档 | 受众 | 内容 |
|---|---|---|
| `README.md` | 人类 | 入门 + 20 个使用实例 + 免责声明 |
| `docs/USER_MANUAL.md` | 使用者 | 完整操作步骤 + 故障排查（v1.3.0） |
| `docs/TECH_MANUAL.md` | 开发者 | 报文结构 / 线程模型 / 测试 / 打包（v1.3.0） |
| `CHANGELOG.md` | 所有人 | 每个版本改了什么 |

<!-- neat-freak: initialized at 2026-11-02 -->
