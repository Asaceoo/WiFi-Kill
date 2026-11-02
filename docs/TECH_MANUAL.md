# WiFiKill 技术手册

> 文档版本：**v1.7.3** · 对应程序：**v2.7.3** · 更新日期：2026-11-02

面向**开发者**：模块边界、报文、线程、状态机、安全护栏、测试体系与发布流水线。
使用者请看 [USER_MANUAL.md](USER_MANUAL.md)。

---

## ⚠️ 免责声明

> 本项目仅用于**自有网络或已获书面授权**的安全测试、教学演示与研究。
> 未经授权干扰他人网络通信可能违反《网络安全法》第二十七条、《治安管理处罚法》第二十九条；
> 情节严重可触犯《刑法》第二百八十五条、第二百八十六条。
> **作者不对任何滥用行为承担责任。** 代码中的安全护栏用于降低误用风险，不构成使用授权。

---

## 1. 定位与技术栈

| 项 | 值 |
|---|---|
| 语言 / 运行时 | Python 3.10+（构建与 CI 用 3.12，需自带 tkinter） |
| 报文与抓包 | scapy 2.8.0 + Npcap（安装需勾 `WinPcap API-compatible Mode`） |
| GUI | tkinter / ttk + Canvas 自绘（零第三方 UI 库） |
| 打包 | PyInstaller（单文件）+ Inno Setup 6（安装版） |
| 平台 | 仅 Windows 10/11；非 Windows 分支保留但未验证 |
| 环境变量 | **不使用任何环境变量**（`grep os.environ/getenv` 零命中） |

## 2. 模块边界

| 文件 | 层 | 职责 |
|---|---|---|
| `core.py` | 逻辑 | 发现、报文、阻断会话、限速、状态持久化、单实例、白名单、安全不变量、`Guard`、`Sentinel`、`verify_targets` |
| `ui.py` | 视觉 | 色板、圆角、Canvas 按钮、波纹/光晕、`ui.Anim` 调度 |
| `gui.py` | 表现 | 主窗口编排、worker + 队列、右键菜单、设置/哨兵面板、托盘接线 |
| `tray.py` | 集成 | 纯 ctypes `Shell_NotifyIcon`，独立线程消息循环 |
| `ipv6.py` | 协议 | IPv6 探测、LLA 探明、多目标 NDP 投毒、三道失控保护 |

硬约束：**`core.py` 不 import tkinter**；UI 只消费 `core` 返回值。

### 2.1 阻断会话 `core.Killer`

- 状态：`NetInfo` 快照、`dict[ip -> Target]`、投毒线程、`interval`、`dry_run`、`_gen`、`_send_lock`；
- `add()`：受保护校验 → 报文可构造 → 入队 → **首发成功才 persist**，失败回滚；
- `remove()`：先出队、推进代际（作废在途批次）→ 发恢复帧 5 次；失败把目标放回队列；
- `abandon()`：换网时停线程、丢队列、清状态（不回填）；
- `matches_network(ni)`：比对网卡 / 网关 IP / 网关 MAC，**两侧都非空**才算不一致。

### 2.2 限速（占空比）

- `Target.duty`（10–100）：100 = 恒投毒；`p` = 10 拍里阻断 `round(p/10)` 拍，其余发恢复帧；
- `_should_poison()` 纯函数；`set_duty()` / `duty_of()` 对外；`duty` 随状态落盘。

### 2.3 IPv6 层

- `probe_env()`：只读 `conf.route6` → `supported / gw_lla / my_lla / prefixes`；
- `find_lla()`：被动嗅探（只读）→ mDNS 询问（QU 位必须为 1）兜底；
- `NdpBlocker`：单目标投毒 + NS 代答 + `_watchdog` 自检；`NdpManager`：多目标并发 + 逐目标护栏；
  第 11 轮起与 `core.Killer` 同源具备**会话代际 + 发送锁**（`_gen` / `_send_lock`），
  并对同一目标拒绝重复 `start()`（防双线程并发发包）。

### 2.4 本机守护 `Guard`

只发真实映射（`网关 IP/LLA ↔ 真实网关 MAC`），L2 源用本机 MAC；基准必须「缓存 + 实时」双源一致，
否则 fail closed；漂移时 `arp -d` 自愈本机缓存；IPv6 重宣告单播到本机。

### 2.5 全网哨兵 `Sentinel`

基线 `dict[mac -> {ip,name,known,first}]` + 事件流（≤200），落盘 `sentinel.json`；首轮静默入册，
**基线上限 `SENTINEL_MAX_KNOWN = 2000`**（第 11 轮）：超限按「未认领优先、出现最早优先」淘汰并留事件，
防止开启「私有 Wi-Fi 地址」的设备轮换 MAC 时把 `sentinel.json` 与待认领列表撑爆（探针：20 轮 × 50 台新 MAC
曾让基线从 20 涨到 1020）；
之后新 MAC 触发 `new` 事件与去重通知（同 key 5 分钟一次）。

### 2.6 阻断验证 `verify_targets`

**被动**判定投毒是否生效，不额外发包。判据（`classify_target_frames` 纯函数）：投毒生效后目标发给
网关的帧二层目的地址变成**本机 MAC**，因此这些帧真的会送到我们网卡上；若仍看到「目标 → 真实网关 MAC」
的帧，说明目标缓存仍是真实映射。

| 计数 | duty=100 判定 | duty<100 判定 |
|---|---|---|
| hits>0, leaks=0 | ok | throttled（限速中，属预期） |
| hits>0, leaks>0 | partial | throttled |
| hits=0, leaks>0 | fail | unknown（只见到放行拍，建议重验） |
| 均为 0 | unknown（设备空闲） | unknown |

限速目标存在「恢复拍」——那几拍我们主动告诉目标真实网关 MAC，它当然直连网关；若不单独判定，
每一台限速设备都会被误报成半失效（第 10 轮真实缺陷）。

### 2.7 发布链（`build.py`）

版本自增 → 文档版本同步 → **校验**（不一致即中止）→ 版本资源 → PyInstaller → Inno Setup → zip。
详见 §12。

## 3. 关键数据结构

```python
@dataclass
class NetInfo:   # iface / my_ip / my_mac / gateway_ip / gateway_mac / cidr / iface_name
@dataclass
class Device:    # ip / mac / vendor / dtype / note / state
@dataclass
class Target:    # ip / mac / note / duty(10-100)
@dataclass
class V6Env:     # supported / gw_lla / gw_mac / my_lla / my_globals / prefixes
```

状态文件 `<exe 目录>/.wifikill-state.json`：

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

解析一律走 `core.state_targets(data)`：非法条目跳过并记日志，`duty` 夹到 10–100。

## 4. 报文结构

### 4.1 为什么 ARP 能被伪造

ARP 应答没有认证也没有序号：任何主机都能宣称「某 IP 在某个 MAC 上」，接收方只看谁先到。

### 4.2 双向投毒（IPv4）

```python
# 骗目标：网关 IP 的 MAC 是我
Ether(dst=target.mac) / ARP(op=2, hwsrc=gw_mac, psrc=gw_ip, hwdst=target.mac, pdst=target.ip)
# 骗网关：目标的 MAC 是我
Ether(dst=gw_mac) / ARP(op=2, hwsrc=my_mac, psrc=target.ip, hwdst=gw_mac, pdst=gw_ip)
```

恢复帧把 `hwsrc` 换成真实方；`sendp(count=N)` 连发抵消丢包（投毒 3 次、恢复 5 次）。

### 4.3 为什么必须重发

目标与网关都会刷新 ARP 缓存（Windows 邻居表有可达性状态机），单次投毒会被真实应答覆盖，
因此按 `interval`（0.5–10 秒）持续重发。

### 4.4 IPv6 / NDP

NA（邻居通告）86 字节、`type=136`、`O=1`（允许覆盖）、`S=0`（定向投毒），携带目标地址与链路层选项。
目标发 NS 询问网关时必须回 `S=1` 的 NA 代答，否则 NUD 会把缓存改回真实网关。
`_send()` 是唯一出口，**拒绝任何组播/广播目的 MAC**（`ff02::1` → `33:33:00:00:00:01`）。

## 5. 线程模型

| 线程 | 名称 | 周期 | 职责 |
|---|---|---|---|
| 投毒 | `wifikill-poison` | `interval` | 遍历队列，按 duty 发投毒帧或恢复帧 |
| 守护 | `wifikill-guard` | 2.0s | 核对网关映射、纠正、IPv6 重宣告（约 10s 一次） |
| 嗅探 | `wifikill-hunt` | 事件触发 | 漂移后短嗅探 4s 指认（单飞） |
| IPv6 | `NdpBlocker` 内部线程 + `AsyncSniffer` | `interval` | 定向投毒 + NS 代答 |
| UI worker | 无名 daemon | 按操作 | 扫描、阻断、恢复、验证、保存设置 |
| 托盘 | `TrayIcon` | 消息循环 | `Shell_NotifyIcon` 消息泵 |

三条铁律：UI 线程不阻塞（worker + `_post` 回主线程）、启动防并发（先 `join` 旧线程）、
日志线程安全（逐 sink try/except，GUI 侧再 `after_idle` 回投）。

### 5.1 关闭竞态与发送顺序（第 7 轮闭环）

| 机制 | 作用 |
|---|---|
| `Killer._gen`（会话代际） | `stop()` / `remove()` / 换网时 `_bump_gen()`，使在途批次剩余发送全部作废 |
| `Killer._send_lock`（发送锁） | 单帧发送排他；推进代际也要拿锁 → 必然发生在当前 `sendp` 返回之后 |

顺序保证：推进代际（等当前 sendp）→ 恢复帧在锁内发送 → 之后任何过期批次被代际检查拦下。
`_late_sends` 记录作废次数供测试观察。`join(3s)` 仍可能超时（驱动层不返回），此时如实告警。

### 5.2 工作线程与队列

`gui._post(fn)` 把回调塞进 `queue.Queue`，主线程 `after(70ms)` 轮询执行——Tk 线程安全的唯一通道。

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

`persist()` 在每次增删目标时原子写状态；`dry_run` 直接返回（绝不落盘）。

## 7. 状态持久化

| 文件 | 用途 | 写入方 |
|---|---|---|
| `.wifikill-state.json` | 残留阻断状态（崩溃恢复） | `Killer.persist()` / `write_state()` |
| `whitelist.txt` | 白名单（IP/MAC 双键） | `save_whitelist()` |
| `aliases.json` | 设备备注 | `save_aliases()` |
| `guard.json` | 守护开关 | `set_guard_enabled()` |
| `sentinel.json` | 哨兵基线 + 事件流（≤200） | `Sentinel.save()` |

约定：原子写（`*.tmp` → `os.replace`）、演练模式不落盘、空列表即删文件、写失败只记日志。

恢复流程：读状态 → `state_targets()` 解析 → 弹窗询问 → 用状态里的 MAC 发恢复帧 → 成功删文件。
网卡或网关 IP 与当前网络不一致则忽略并清除。

**状态与网络绑定**：`Killer` 持有创建时的 `NetInfo`；扫描后发现 `matches_network()` 不一致即
`abandon()` 并立刻摘掉旧对象，确保下次阻断用新上下文重建。

## 8. 安全护栏的实现点

| 护栏 | 实现位置 | 逻辑 |
|---|---|---|
| 网关保护 | `gui.do_block()` 过滤 + `core.Killer.add` API 层 | 目标 IP 或 MAC 任一命中即抛 `BlockError` |
| 本机保护 | 同上 | 同上；`resolve_mac()` 遇本机 IP 直接返回本机 MAC |
| 白名单 | `gui._state_of()` + `picks` 过滤 | 单目标与全阻断两条路径都过滤 |
| MAC 合法性 | `Killer._frames()` | 正则校验，不合法抛错；网关 MAC 缺失直接拒绝 |
| IPv6 受保护 | `NdpManager.add` + `NdpBlocker.preflight` | 结构化比对 IP/MAC/LLA，与 note 标注无关 |
| 组播出口 | `NdpBlocker._send()` | 拒绝一切组播/广播目的 MAC |
| 失控回滚 | `NdpBlocker._watchdog()` | 每 5 拍核对本机网关映射，被改坏立即停手回填 |
| 守护 fail closed | `Guard._establish_baseline()` | 双源分歧/不可达 → 不启动、不采纳 |
| 单实例 | `core.SingleInstance` | 绑定 `127.0.0.1:51999`；管理员重启时先释放锁再拉起新实例 |
| 换网中止 | `matches_network()` + `abandon()` | 防「界面阻断中、目标照常上网」 |
| IPv6 顺序保证 | `NdpBlocker._gen` + `_send_lock` | 与 IPv4 同源：恢复帧一定最后（第 11 轮补齐） |
| 基线上限 | `Sentinel._trim()` | 超限淘汰最早未认领设备，防无限增长 |

## 9. 环境探测

- **二层可用性**（`l2_check`）：只判「确定不能工作」的条件（scapy 缺失 / Npcap 未装），**不把管理员当硬门槛**；
- **网段推导**：从 `conf.route.routes` 挑与本机同网、掩码最长的一条；`/128` 主机路由不算前缀；
- **网卡友好名**：`\\Device\\NPF_{GUID}` → 「别名 · 描述」；
- **IPv6**：`conf.route6.route("::")` 取默认网关 LLA，`route6.routes` 取全局前缀。

## 10. 异常处理约定

| 场景 | 行为 |
|---|---|
| `BlockError` | UI 弹窗或日志 warn，调用方可见 |
| `sendp` 异常 | 包装成 `BlockError("发送失败：…")` 并回滚队列 |
| 状态文件损坏 | `load_state()` 返回 `{}`；逐条解析跳过坏记录 |
| 哨兵基线损坏 | 按空基线重建并记日志 |
| 日志订阅者抛错 | `Logger.emit` 逐 sink try/except |
| 验证嗅探异常 | worker 兜底：错误进日志与弹窗，忙碌态一定放回 |
| 工作线程异常 | 恢复流程整体包裹并写日志；启动期异常由 `main()` 兜底弹窗 |

## 11. 测试体系

### 11.1 六套无头测试（205 项，CI 可跑）

| 套件 | 项数 | 覆盖 |
|---|---|---|
| `tests/test_edge.py` | 75 | 异常输入 / 并发 / 崩溃现场 / 安全不变量 API 层 / 第 5–10 轮回归 |
| `tests/test_ipv6.py` | 65 | 报文级：NA 结构、组播保险、preflight、mDNS、邻居表解析 |
| `tests/test_guard.py` | 21 | 守护：基准建立/重估/去抖/自愈/演练纯净 |
| `tests/test_sentinel.py` | 12 | 哨兵：基线、告警、去重、认领/移出、事件上限、损坏自愈 |
| `tests/test_throttle.py` | 6 | 占空比：档位、钳制、持久化、真循环交替 |
| `tests/test_gui_smoke.py` | 26 | 真实建窗 + 扫描渲染 + 新功能入口 + `ui` 常量静态校验（不发包，进 CI） |

### 11.2 真机 GUI 端到端（`selftest.py`，51 项）

启动**真实窗口**、走真实扫描，注入幽灵设备（`02:00:00:00:00:01`）后执行阻断/限速/放行/守护演练/
哨兵面板/换网中止等全链路断言并截图；开头备份并清空运行时状态文件（避免结果取决于上次跑到哪）。

### 11.3 探针与清单

每轮审查的缺陷先写成**可复现探针**看到红，再改到绿，最后把等价断言固化进上面三套测试。
发布前跑固定清单（编译、红线、安全不变量、dry-run 纯净、状态容错、换网中止、版本一致、
gitignore 覆盖、文档计数与实跑一致、`ui` 常量存在），任一红即视为回归。

## 12. 打包与发布

### 12.1 版本真源

```json
{"app": "2.7.2", "user_manual": "1.7.2", "tech_manual": "1.7.2", "build": 16, "released": "2026-11-02"}
```

### 12.2 构建流程（`build.py`）

1. 递增 `app`；两份手册跟随（minor 及以上升 minor，否则升 patch）；`build` +1；
2. 同步文档版本：手册头部（`文档版本` / `对应程序`）、README 版本徽章/版本表/手册行；
3. **校验**（`verify_doc_versions()`）：上述标记与 `versions.json` 不一致即**中止构建**；
4. 写 exe 版本资源 → PyInstaller 单文件 → 三产物：`WiFiKill-vX.Y.Z.exe`、`-setup.exe`、`-portable.zip`
   （zip 含 exe + README + 两份手册 + 概念图 + 许可）。

### 12.3 安装包（`installer/WiFiKill.iss`）

- `/DAppVersion=x.y.z` 传入版本，输出到 `dist/`；
- **`LicenseFile=DISCLAIMER.txt`**：首屏展示中文免责声明，必须勾选同意；
- 安装 exe、README、两份手册、`docs/images/`（README 相对引用图片，缺图会裂）、许可；
- 卸载清理 `.wifikill-state.json` / `whitelist.txt` / `aliases.json` / `guard.json` / `sentinel.json`。

### 12.4 Release 流水线（`.github/workflows/release.yml`）

推 tag `v*` 触发：① 校验 tag 与 `versions.json` 一致；② 装 Python 3.12（含 tkinter）+ scapy + pyinstaller
+ Inno Setup；③ 依次跑六套无头测试（含 GUI 冒烟）；④ `build.py --no-bump` 构建三产物；
⑤ 发布 Release 并附三产物 + README + 两份手册，正文含功能、验证数字与免责声明。

> 真机 `selftest.py` 需要真实窗口与网卡，**不进 CI**，由本地发布前手工执行。

### 12.5 性能优化记录

| 优化 | 做法 | 实测 |
|---|---|---|
| 邻居表读取 | `arp_table()` 优先 `iphlpapi.GetIpNetTable`（ctypes，免子进程），失败回退 `arp -a` | **3.2 ms vs 104.6 ms ≈ 33×**；守护常驻每小时少起 1800 个进程，结果逐条一致 |
| 表行转换 | `_arp_rows_to_table()` 纯函数：过滤 invalid/组播/广播/短 MAC | 可无网卡单测 |

## 13. 已知限制

1. **ARP 层做不了真限速**：占空比只是节流，依赖目标侧缓存刷新行为；
2. **IPv6 只断经网关出站**：同链路直连不受影响；LLA 探明失败时降级为「仅 IPv4」；
3. **IPv6 侧生效判定未自动化**：验证断网只判 IPv4 投毒（帧是否被打到本机）；
4. **验证能力的边界**：`verify_targets()` 只能证明投毒生效，不能证明目标彻底无网
   （IPv6 直连、蜂窝网络、目标自开热点都绕开被投毒的二层路径）；
5. **驱动层 `sendp` 不返回**：代际+发送锁保证恢复帧最后，但 `join` 仍可能超时，此时告警；
6. **换网判定依赖扫描**：探测为空时不判换网（避免误杀），改为明确告警；
7. **嗅探定位非定罪**：以太网源 MAC 可被冒用，指认结论标注「疑似」；
8. **客户端隔离无法绕过**；
9. 非 Windows 分支未验证。

## 14. 扩展点

- **新阻断手段**：另写会话类，复用 `matches_network()` 与受保护校验；
- **新防御策略**：`Guard.event_sink` 已解耦（GUI 注入 `Sentinel.feed_event`）；
- **新 UI**：`core` 不依赖 tkinter，可被 CLI / 服务包装；
- **新测试**：六套都是纯脚本（`sys.exit(1 if FAIL)`），新增套件在 CI 里加一步即可。

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

---

> **免责声明**：本项目仅用于自有网络或已获书面授权的安全测试、教学演示与研究。
> 未经授权干扰他人网络通信可能违反《网络安全法》第二十七条、《治安管理处罚法》第二十九条；
> 情节严重可触犯《刑法》第二百八十五条、第二百八十六条。**作者不对任何滥用行为承担责任。**
