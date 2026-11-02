# WiFiKill 技术手册

> 文档版本：**v1.6.3** · 对应程序：**v2.6.3** · 更新日期：2026-11-02

面向**开发者**：模块边界、报文结构、线程模型、状态机、安全护栏、测试体系与发布流水线。
使用者请看 [USER_MANUAL.md](USER_MANUAL.md)。

---

## ⚠️ 免责声明

> 本项目仅用于**自有网络或已获书面授权**的安全测试、教学演示与研究。
> 未经授权干扰他人网络通信可能违反《网络安全法》第二十七条、《治安管理处罚法》第二十九条；
> 情节严重可触犯《刑法》第二百八十五条、第二百八十六条。
> **作者不对任何滥用行为承担责任。** 代码中的安全护栏用于降低误用风险，不构成使用授权。

---

## 1. 定位与技术栈

WiFiKill 是 Windows 桌面 GUI 工具：设备发现 → ARP/NDP 定向投毒阻断 → 本机主动防御 → 全网哨兵。

| 项 | 值 |
|---|---|
| 语言 / 运行时 | Python 3.10+（构建与 CI 用 3.12，需自带 tkinter） |
| 报文与抓包 | scapy 2.8.0 + Npcap（Windows；安装需勾选 `WinPcap API-compatible Mode`） |
| GUI | tkinter / ttk + Canvas 自绘（零第三方 UI 库） |
| 打包 | PyInstaller（单文件）+ Inno Setup 6（安装版） |
| 平台 | 仅 Windows 10/11；代码保留非 Windows 分支但未验证 |
| 环境变量 | **不使用任何环境变量**（`grep os.environ/getenv` 零命中，引入即破坏约定） |

## 2. 模块边界

| 文件 | 层 | 职责 |
|---|---|---|
| `core.py` | 逻辑 | 设备发现、报文构造、阻断会话、限速、状态持久化、单实例锁、白名单、安全不变量、`Guard`、`Sentinel` |
| `ui.py` | 视觉 | 莫兰迪色板、圆角绘制、Canvas 按钮（hover/press 插值）、波纹/光晕/呼吸灯、`ui.Anim` 调度器 |
| `gui.py` | 表现 | 主窗口编排、工作线程 + 队列回主线程、右键菜单、设置窗口、哨兵面板、托盘接线 |
| `tray.py` | 集成 | 纯 ctypes 调 `Shell_NotifyIcon`，独立线程消息循环，`notify()` 气泡 |
| `ipv6.py` | 协议 | IPv6 环境探测、LLA 探明（嗅探/mDNS）、多目标 NDP 投毒、三道失控保护 |

硬约束：**`core.py` 不 import tkinter**（逻辑层必须能被脚本/测试/未来 CLI 直接复用）；
UI 只消费 `core` 的返回值，不反向依赖。

### 2.1 阻断会话（`core.Killer`）

- 持有 `NetInfo` 快照、目标队列 `dict[ip -> Target]`、一个投毒线程、`interval`、`dry_run`；
- `add()` 先在 API 层校验受保护设备 → 验证报文可构造 → 入队 → **首发成功才 persist**，失败回滚；
- `remove()` 发送恢复帧 5 次，失败则把目标放回队列（避免「以为放行了其实还断着」）；
- `abandon()` 用于换网：停线程、丢队列、清状态文件，**不回填**（旧网关帧在新网段无意义）；
- `matches_network(ni)` 比对网卡 / 网关 IP / 网关 MAC，**两侧都非空**才算不一致。

### 2.2 限速（占空比）

- `Target.duty`（10–100）：100 = 恒投毒；`p` = 10 拍周期里阻断 `round(p/10)` 拍，其余拍发恢复帧；
- 决策函数 `_should_poison(t, cycle_idx)` 是纯函数，便于测试；
- `set_duty()` / `duty_of()` 对外接口，`duty` 进 `asdict()` 随状态落盘，恢复路径必须读回。

### 2.3 IPv6 层（`ipv6.py`）

- `probe_env()`：只读 `conf.route6`，得出 `supported / gw_lla / my_lla / prefixes`；
- `find_lla()`：被动嗅探（`AsyncSniffer`，只读不发）→ mDNS 主动询问（QU 位必须为 1）兜底；
- `NdpBlocker`：单目标 NDP 投毒 + 监听目标 NS 代为应答（否则 NUD 会自愈）+ `_watchdog` 自检；
- `NdpManager`：多目标并发管理，逐目标独立护栏，`active_ips()` / `state_of()` 供 UI 展示。

### 2.4 本机守护（`core.Guard`）

见 §2.7。它**只发真实映射**：免费 ARP / 单播 NA 宣告「网关 IP/LLA ↔ 真实网关 MAC」，
L2 源用本机 MAC（不冒充网关）；基准必须「缓存 + 实时询问」双源一致。

### 2.5 全网哨兵（`core.Sentinel`）

设备基线 `dict[mac -> {ip,name,known,first}]` + 事件流（上限 200 条），落盘 `sentinel.json`；
首轮扫描静默入册，之后新 MAC 触发 `new` 事件与去重通知（同 key 5 分钟内一次）。

## 3. 关键数据结构

```python
@dataclass
class NetInfo:      # iface / my_ip / my_mac / gateway_ip / gateway_mac / cidr / iface_name
@dataclass
class Device:       # ip / mac / vendor / dtype / note / state
@dataclass
class Target:       # ip / mac / note / duty(10-100)
@dataclass
class V6Env:        # supported / gw_lla / gw_mac / my_lla / my_globals / prefixes
```

状态文件（`<exe 目录>/.wifikill-state.json`）：

```json
{
  "updated": 1762012345.6,
  "iface": "\\\\Device\\\\NPF_{...}",
  "my_mac": "8c:e9:ee:a0:f3:b6",
  "gateway_ip": "192.168.1.1",
  "gateway_mac": "f8:79:28:cc:fc:e8",
  "targets": [{"ip": "192.168.1.5", "mac": "e6:ff:70:f3:de:66", "note": "", "duty": 100}]
}
```

解析一律走 `core.state_targets(data)`：非法条目跳过并记日志，`duty` 夹到 10–100，
坏记录不会掀翻整条恢复链（第 5 轮真实缺陷）。

## 4. 报文结构

### 4.1 为什么 ARP 能被伪造

ARP 应答没有认证也没有序列号：任何主机都能宣称「某 IP 在某个 MAC 上」，接收方只看谁先到、
就更新缓存。这正是本工具「双向投毒」的基础，也是 Guard 存在的理由。

### 4.2 双向投毒的两帧（IPv4）

```python
# 骗目标：网关 IP 的 MAC 是我（攻击方）
Ether(dst=target.mac) / ARP(op=2, hwsrc=gw_mac, psrc=gw_ip, hwdst=target.mac, pdst=target.ip)
# 骗网关：目标的 MAC 是我（攻击方）
Ether(dst=gw_mac) / ARP(op=2, hwsrc=my_mac, psrc=target.ip, hwdst=gw_mac, pdst=gw_ip)
```

恢复帧把 `hwsrc` 换成真实方（`restore=True`）：给目标的是**网关真实 MAC**，给网关的是**目标真实 MAC**。
每帧 `sendp(..., count=N)` 连发多次抵消丢包（投毒 3 次，恢复 5 次）。

### 4.3 为什么必须重发

目标与网关都会刷新 ARP 缓存（Windows 邻居表有可达性状态机），单次投毒会在十几秒到几分钟内
被真实应答覆盖。因此按 `interval`（0.5–10 秒）持续重发，直到停止会话或断开。

### 4.4 IPv6 / NDP 报文

NA（邻居通告）86 字节、`type=136`、`O=1`（允许覆盖缓存）、`S=0`（定向投毒用），
携带目标地址与链路层地址选项：

```python
build_na(eth_src, eth_dst, ipv6_src, ipv6_dst, tgt=gw_lla, lladdr=my_mac)
```

若目标发来 NS 询问网关，必须回一条 `S=1` 的 NA 代为应答，否则 NUD 会把缓存改回真实网关。
`_send()` 是唯一出口，**拒绝任何组播/广播目的 MAC**（`ff02::1` 对应 `33:33:00:00:00:01`），
防止误发把整网 IPv6 打掉。

## 5. 线程模型

| 线程 | 名称 | 周期 | 职责 |
|---|---|---|---|
| 投毒 | `wifikill-poison` | `interval` | 遍历队列，按 duty 决定发投毒帧或恢复帧 |
| 守护 | `wifikill-guard` | 2.0s | 核对网关映射、漂移纠正、IPv6 重宣告（约 10s 一次） |
| 嗅探 | `wifikill-hunt` | 事件触发 | 漂移后短嗅探 4s 定位投毒者（单飞，不堆积） |
| IPv6 | `NdpBlocker` 内部线程 + `AsyncSniffer` | `interval` | 定向 NDP 投毒 + NS 代答 |
| UI 工作线程 | 无名 daemon | 按操作 | 扫描、阻断、恢复、保存设置等耗时动作 |
| 托盘 | `TrayIcon` 内部线程 | 消息循环 | `Shell_NotifyIcon` 消息泵 |

三条铁律：

1. **UI 线程不阻塞**：所有发包/扫描在 worker 线程，结果经 `queue` 回主线程（`_post`）；
2. **启动防并发**：`start()` 前先 `join()` 尚未退出的旧线程，仍不退出则拒绝本次启动；
3. **日志线程安全**：`core.LOG.emit` 逐 sink try/except，一个订阅者坏掉不影响其他；
   GUI 侧再经 `after_idle` 回投主线程。

### 5.1 关闭竞态与发送顺序（第 7 轮闭环）

只靠 `stop()` 置 Event 并不能保证「恢复帧排在最后」：投毒线程可能正卡在 `sendp` 里，
那一帧会在恢复帧之后落地，目标就残留被阻断。现在用两个机制合起来闭环：

| 机制 | 作用 |
|---|---|
| `Killer._gen`（会话代际） | `stop()` / `remove()` / 换网时 `_bump_gen()`，使**在途批次的剩余发送全部作废** |
| `Killer._send_lock`（发送锁） | 单帧发送排他；`_bump_gen()` 也要拿这把锁，因此「推进代际」必然发生在当前 `sendp` 返回之后 |

顺序保证：推进代际（等当前 sendp）→ 恢复帧在锁内发送 → 之后任何过期批次都被代际检查拦下。
`_late_sends` 记录被作废的发送次数，供测试与日志观察。`remove()` 只影响本目标的在途批次，
其他目标下一轮用新代际继续，不会被误停。

`join(3s)` 仍可能超时（驱动层 sendp 不返回），此时如实告警，而不是假装干净。

`stop()` 置 `Event` 并 `join(3s)`。若线程卡在 `sendp` 里没退出，`Killer.stop()` 会**明确告警**
（恢复帧可能与最后一批投毒帧交叉）；`NdpBlocker` 同理，`stop(restore=True)` 会先停线程再回填。

### 5.2 工作线程与队列

`gui.py` 的 `_post(fn)` 把回调放入 `queue.Queue`，主线程 `after(70ms)` 轮询执行；
任何 `_post` 的回调都在主线程，可直接改控件——这是 Tk 线程安全的唯一通道。

## 6. 阻断会话状态机

```
IDLE ──add()──► ARMED ──start()──► ACTIVE ⇄ (duty<100) THROTTLED
                  ▲                    │
                  └──自动离开──────────┘
  ▲                                    │
  └─────────remove() / restore_all() ◄─┘
```

| 状态 | 判据 | 恢复手段 |
|---|---|---|
| IDLE | 队列空、无状态文件 | — |
| ARMED | 队列非空、线程未启动 | 启动线程或直接 `restore_all()` |
| ACTIVE | 线程存活且未置停止位 | `remove()` / `restore_all()` / `abandon()` |
| THROTTLED | 目标 `duty < 100` | 逐拍交替发投毒/恢复帧 |

`persist()` 在**每次增删目标**时原子写状态文件；`dry_run` 时直接返回（绝不落盘）。

## 7. 状态持久化

| 文件 | 用途 | 写入方 |
|---|---|---|
| `.wifikill-state.json` | 残留阻断状态（崩溃恢复用） | `Killer.persist()` / `core.write_state()` |
| `whitelist.txt` | 白名单（IP/MAC 双键，一行一个） | `core.save_whitelist()` |
| `aliases.json` | 设备备注（mac/ip → 名字） | `core.save_aliases()` |
| `guard.json` | 守护开关 `{"enabled": bool}` | `core.set_guard_enabled()` |
| `sentinel.json` | 哨兵基线 + 事件流（≤200 条） | `Sentinel.save()` |

统一约定：**原子写**（先写 `*.tmp` 再 `os.replace()`）、演练模式不落盘、空列表即删文件、
写失败只记日志不抛给 GUI（状态写不进去不该把界面打崩）。

恢复流程：启动读状态 → `state_targets()` 解析 → 弹窗询问 → 用状态里的 MAC 发恢复帧 → 成功删文件。
若网卡或网关 IP 与当前网络不一致，直接忽略并清除（旧网络的恢复帧只会发向失效 MAC）。

**状态与网络绑定（第 5 轮）**：`Killer` 持有创建时的 `NetInfo` 快照，换网后继续沿用会把帧发向
旧网关 MAC——界面「阻断中」而目标照常上网。GUI 每次扫描后调用 `matches_network()` 比对，
不一致即 `abandon()`，并**立刻摘掉旧对象**，确保下次阻断用新上下文重建。

## 8. 安全护栏的实现点

| 护栏 | 实现位置 | 逻辑 |
|---|---|---|
| 网关保护 | `gui.do_block()` 过滤 **+ `core.Killer.add` API 层强制** | 目标 IP 或 MAC 任一命中网关即抛 `BlockError` |
| 本机保护 | 同上 | 目标 IP 或 MAC 任一命中本机即拒绝；`resolve_mac()` 遇本机 IP 直接返回本机 MAC |
| 白名单 | `gui` 的 `_state_of()` + `picks` 过滤 | 单目标与全阻断两条路径都过滤（IP 或 MAC 命中即跳过） |
| MAC 合法性 | `Killer._frames()` | 正则 `^([0-9a-f]{2}:){5}[0-9a-f]{2}$`，不合法抛 `BlockError` |
| 网关 MAC 缺失 | `Killer._frames()` | 缺失即拒绝，绝不用空串构造 `Ether(dst="")` |
| IPv6 受保护校验 | `NdpManager.add` + `NdpBlocker.preflight` | 结构化比对 IP/MAC/LLA，与 note 标注无关（防 API 直调绕过） |
| 组播出口 | `NdpBlocker._send()` | 拒绝一切组播/广播目的 MAC |
| 失控回滚 | `NdpBlocker._watchdog()` | 每 5 拍核对本机网关映射，被改坏立即停手并回填 |
| 守护 fail closed | `Guard._establish_baseline()` | 缓存与实时询问分歧 / 不可达 → 不启动、不采纳 |
| 单实例 | `core.SingleInstance` | 绑定 `127.0.0.1:51999`，失败即认为已有实例 |
| 换网中止 | `Killer.matches_network()` + `abandon()` | 防「界面阻断中、目标照常上网」的静默失效 |

## 9. 环境探测

- **二层可用性**（`l2_check`）：只判定「确定不能工作」的条件（scapy 缺失 / Npcap 未装），
  **不把管理员当作硬门槛**——Npcap 权限因安装选项而异，真实权限不足会在 `sendp` 时暴露；
- **网段推导**（`get_netinfo`）：从 `conf.route.routes` 里挑与本机同网、掩码最长的一条；
  只有 `/128` 主机路由时不算前缀（避免误判双栈）；
- **网卡友好名**：`\Device\NPF_{GUID}` → 「别名 · 描述」；
- **IPv6 环境**：`conf.route6.route("::")` 取默认网关 LLA，`route6.routes` 取全局前缀。

## 10. 异常处理约定

| 场景 | 行为 |
|---|---|
| `BlockError`（业务失败） | UI 弹窗或日志 warn；调用方可见 |
| `sendp` 底层异常 | 包装成 `BlockError("发送失败：...")`，并回滚队列 |
| 状态文件损坏 | `load_state()` 吞掉并返回 `{}`；逐条解析时跳过坏记录 |
| 哨兵基线损坏 | 按空基线重建并记日志（不再每次扫描抛异常） |
| 日志订阅者抛错 | `Logger.emit` 逐 sink try/except |
| 工作线程异常 | 恢复流程整体包裹并写日志；启动期异常由 `main()` 兜底弹窗 |

## 11. 测试体系

### 11.1 六套无头测试（176 项，CI 可跑）

| 套件 | 项数 | 覆盖 |
|---|---|---|
| `tests/test_edge.py` | 61 | 异常输入 / 并发 / 崩溃现场 / 安全不变量 API 层 / 第 5–7 轮回归 |
| `tests/test_ipv6.py` | 58 | 报文级：NA 结构、组播保险、preflight、mDNS、邻居表解析 |
| `tests/test_guard.py` | 21 | 守护：基准建立/重估/去抖/自愈/演练纯净 |
| `tests/test_sentinel.py` | 11 | 哨兵：基线、告警、去重、认领/移出、事件上限、损坏自愈 |
| `tests/test_throttle.py` | 6 | 占空比：档位、钳制、持久化、真循环交替 |
| `tests/test_gui_smoke.py` | 19 | 真实建窗 + 扫描渲染 + `ui` 常量静态校验（不发包，进 CI） |

### 11.2 真机 GUI 端到端（`selftest.py`，51 项）

启动**真实窗口**、走真实扫描，注入一台「幽灵设备」（`02:00:00:00:00:01`，全网不存在）后执行
阻断/限速/放行/守护演练/哨兵面板/换网中止等全链路断言，并逐步截图。
开头会备份并清空运行时状态文件（否则上一轮残留会让结果取决于「上次跑到哪一步」），结束时恢复。

### 11.3 对抗性审查与探针

每一轮审查的缺陷都先写成**可复现探针**（临时脚本）看到红，再改代码到绿，最后把等价断言
固化进上面三套测试。第 5 轮探针覆盖：发送失败回滚、状态文件容错、哨兵基线自愈、换网中止、
受保护设备四形态拒绝。

### 11.4 清单兜底

构建/发布前跑一次固定清单（编译、`core` 不含 tkinter、无环境变量、安全不变量、dry-run 纯净、
状态容错、换网中止、版本一致、gitignore 覆盖、文档计数与实跑一致、`ui` 常量引用全部存在）。
任何一条红即视为回归。

## 12. 打包与发布

### 12.1 版本真源

`versions.json` 是唯一真源：

```json
{"app": "2.6.2", "user_manual": "1.6.2", "tech_manual": "1.6.2", "build": 12, "released": "2026-11-02"}
```

### 12.2 构建流程（`build.py`）

```bash
python build.py --bump patch    # 默认：修复/文档
python build.py --bump minor    # 新功能
python build.py --no-bump       # 用当前版本重打（调试）
python build.py --zip-only      # 只重打 zip
```

1. 递增 `app`；`user_manual` / `tech_manual` 跟随（minor 及以上升 minor，否则升 patch）；`build` +1；
2. **同步文档版本**：两份手册头部（`文档版本` / `对应程序`）、README 的版本徽章、版本表、手册行；
3. **校验文档版本**（`build.py:verify_doc_versions()`）：上述标记若与 `versions.json` 不一致，
   **直接中止构建**——防止格式漂移导致
   版本号静默不同步、发布物带旧版本出厂（第 6 轮真实缺陷）；
4. 写 exe 版本资源 → PyInstaller 单文件打包 → 出三个产物：
   `WiFiKill-vX.Y.Z.exe`（单文件）、`WiFiKill-vX.Y.Z-setup.exe`（安装版）、
   `WiFiKill-vX.Y.Z-portable.zip`（exe + README + 两份手册 + 概念图 + 许可）。

### 12.3 安装包（`installer/WiFiKill.iss`）

- 构建时传入 `/DAppVersion=x.y.z`，输出到 `dist/`；
- **`LicenseFile=DISCLAIMER.txt`**：向导第一步展示中文免责声明，必须勾选同意；
- 安装内容：exe、README、两份手册、`docs/images/`（README 引用概念图，缺图会裂）、许可；
- 卸载时清理 `.wifikill-state.json`、`whitelist.txt`、`aliases.json`、`guard.json`、`sentinel.json`。

### 12.4 Release 流水线（`.github/workflows/release.yml`）

推 tag `v*` 触发：

1. **校验 tag 与 `versions.json` 一致**（不一致直接失败，防止产物名与 Release 标题错配）；
2. 装 Python 3.12（python.org 官方包，自带 tkinter）+ scapy + pyinstaller + Inno Setup；
3. 依次跑五套无头测试（任一失败即停）；
4. `python build.py --no-bump` 构建三种产物；
5. 发布 Release 并附上三种产物 + `README.md` + 两份手册，正文由 workflow 内的模板生成
   （含功能、验证数字与免责声明）。

> 真机 `selftest.py` 需要真实窗口与网卡，**不进 CI**，由本地发布前手工执行。

### 12.5 性能优化记录

| 优化 | 做法 | 实测 |
|---|---|---|
| 邻居表读取 | `core.arp_table()` 优先用 `iphlpapi.GetIpNetTable`（ctypes，免子进程），失败回退 `arp -a` | **3.2 ms/次 vs 104.6 ms/次 ≈ 33×**；守护每 2 秒一次，每小时省下约 180 秒进程开销，且结果与 `arp -a` 完全一致 |
| 表行转换 | `_arp_rows_to_table()` 为纯函数：过滤 invalid/组播/广播/短 MAC | 可无网卡单测（`t_arp_row_conversion`） |
| 井号/计数渲染 | 页脚徽章与状态列按需重绘，避免整体 `render_rows` | — |

## 13. 已知限制

1. **ARP 层做不了真限速**：占空比只是节流，依赖目标侧的缓存刷新行为；
2. **IPv6 只断经网关出站**：同链路直连不受影响；LLA 探明失败时只能降级为「仅 IPv4」；
3. ~~投毒线程 join 超时的交叉窗口~~：第 7 轮已用「会话代际 + 发送锁」闭环（见 §5.1）；剩余风险仅限驱动层 `sendp` 永不返回，此时会告警；
4. **换网判定依赖扫描**：探测为空时不敢判换网（避免误杀生效中的阻断），改为明确告警「仍有 N 台阻断，
   状态无法确认」，旧上下文保留到下一次能判定的扫描；
5. **嗅探定位非定罪**：以太网源 MAC 可被冒用，指认结论始终标注「疑似」；
6. **客户端隔离无法绕过**：路由器开了 AP Isolation 就看不到其他设备；
7. 非 Windows 分支未验证。

## 14. 扩展点

- **新阻断手段**：`Killer._frames()` 之外再实现一个会话类，复用 `matches_network()` 与受保护校验；
- **新防御策略**：`Guard` 的 `event_sink` 已解耦（GUI 注入 `Sentinel.feed_event`）；
- **新 UI**：`core` 不依赖 tkinter，可直接被 CLI / 服务包装；
- **新测试**：五套测试都是纯脚本（`sys.exit(1 if FAIL)`），新增套件只需在 CI 里加一步。

## 15. 附：一次真实运行的环境探测输出

```
Python      3.12.4
scapy       2.8.0
管理员权限  否
二层收发    可用
网卡        WLAN · Intel(R) Wi-Fi 6 AX201 160MHz
本机        192.168.1.250  8c:e9:ee:a0:f3:b6
网关        192.168.1.1    f8:79:28:cc:fc:e8
网段        192.168.1.0/24
```

（以上输出由「环境自检」按钮生成；`selftest.py` 全部断言均在同类真机环境下执行通过。）

---

> **免责声明**：本项目仅用于自有网络或已获书面授权的安全测试、教学演示与研究。
> 未经授权干扰他人网络通信可能违反《网络安全法》第二十七条、《治安管理处罚法》第二十九条；
> 情节严重可触犯《刑法》第二百八十五条、第二百八十六条。**作者不对任何滥用行为承担责任。**
