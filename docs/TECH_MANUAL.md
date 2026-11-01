# WiFiKill 技术手册

> 文档版本：**v1.3.0** · 对应程序：**v2.3.0** · 更新日期：2026-11-02

---

## ⚠️ 免责声明

本仓库提供的代码与文档仅用于**自有网络**或**已获书面授权**的安全测试、教学与研究。

未经授权使用 ARP 欺骗干扰他人网络通信，可能违反《中华人民共和国网络安全法》第二十七条、
《治安管理处罚法》第二十九条，情节严重可触犯《刑法》第二百八十五条、第二百八十六条；
境外同样受 CFAA §1030、Computer Misuse Act 1990 s.3 等条款约束。

**作者不对任何滥用行为承担责任。**

---

## 1. 定位与技术栈

| 项 | 值 |
|---|---|
| 语言 | Python 3.10+ |
| UI | Tkinter / ttk（标准库，无第三方 UI 依赖） |
| 抓包与注入 | scapy 2.8 + Npcap（Windows）/ libpcap（Linux） |
| 打包 | PyInstaller 6.x，`--onefile --windowed` |
| 产物体积 | 约 16.8 MB（排除 numpy/PIL 等非必需依赖后） |
| 代码规模 | core.py ≈ 730 行，gui.py ≈ 780 行 |

设计约束（刻意的）：

1. **core 不向 stdout 写任何东西** —— `--windowed` 打包后 `sys.stdout is None`，任何 print 都会崩。
2. **core 不引用 tkinter** —— 保证逻辑层可被脚本、测试、未来的 CLI 复用。
3. **零第三方 UI 库** —— 避免 Qt 那类 100 MB+ 的打包体积。

---

## 2. 模块边界

```
gui.py  ──── 依赖 ────►  core.py  ──── 依赖 ────►  scapy / Npcap
   │                        │
   └─ Tk 主循环             └─ 工作线程池（每次操作一个 thread）
```

| 模块 | 允许做的事 | 禁止做的事 |
|---|---|---|
| `gui.py` | 创建控件、读取控件、派发任务到线程、从队列取结果 | 直接调用 `sendp`、在 Tk 线程里做超过 50 ms 的阻塞调用 |
| `core.py` | 计算、发包、读写状态文件、通过 `LOG` 回调上报 | 触碰任何 Tk 对象、向 stdout/stderr 输出 |
| `ipv6.py` | IPv6 路由表读取、报文构造、定向投毒、自检 | 发往组播/广播地址、触碰 Tk、并发多目标 |

跨层通信只有两条通道：

- **下行**：`gui` 调 `core` 的函数/方法（在工作线程里）
- **上行**：`core.LOG.emit(level, msg)` → `gui._log_sink` → `queue` → `_drain`（主线程）

---

## 2.5 IPv6 / NDP 层（v2.1.0 新增）

### 为什么必须做

ARP 是纯 IPv4。国内宽带普遍 RA + SLAAC 下发全局 IPv6，双栈设备访问双栈站点时
按 RFC 6724 优先走 IPv6，这些帧直接发往路由器的真实 MAC，**绕过投毒方**，
于是出现「界面显示阻断中、目标照常上网」的静默失效。

### 报文

```
Ether(14) / IPv6(40) / ICMPv6 NA(32) = 86 字节

  ICMPv6 type = 136 (Neighbor Advertisement)
  tgt         = 被冒充的地址（这里是网关链路本地地址，如 fe80::1）
  O = 1       覆盖已有缓存项，这是投毒生效的关键位
  S = 0       非请求应答；代理应答对方 NS 时才置 1
  选项        携带「tgt 现在在哪个 MAC 上」
```

### 三个方向的帧

| 方向 | 以太目的 | IPv6 源 | 宣称内容 |
|---|---|---|---|
| 正向投毒 | 目标 MAC | 网关 LLA | 网关 LLA 在本机 MAC 上 |
| 反向投毒 | 网关 MAC | 目标 LLA | 目标 LLA 在本机 MAC 上 |
| 回填（各 5 次） | 各自真实 MAC | 真实地址 | 真实映射 |

### 为什么光投毒不够

目标收不到回应会触发 NUD（邻居不可达检测）：先单播 NS 探测，探不通就删缓存、
重新组播询问，真路由器一应答就自动修好了。所以必须**同时监听目标的 NS 并代为应答**
（`_start_ns_sniffer`）。这与 ARP 侧「每 1.5 秒重发」是同一个道理，但更复杂。

### 三道防线

| 防线 | 实现位置 | 作用 |
|---|---|---|
| 结构性保险 | `NdpBlocker._send()` | 拒绝任何组播/广播目的 MAC；一条 NA 发不到 `ff02::1`，就断不了整网 |
| 人工门 | 设置项 + `do_block` | 默认关闭；开启后 `len(picks) > 1` 直接拒绝 |
| 运行时自检 | `NdpBlocker._watchdog()` | 每 5 个周期查本机邻居表里网关是否仍指向真实 MAC，异常立即停手回填 |

### 目标地址发现

定向投毒必须知道目标的链路本地地址，而 IPv4 侧只有 IP 与 MAC。两条路：

1. **被动嗅探**（`sniff_llas`）：只读不发，收 `fe80::` 源地址
2. **mDNS 主动询问**（`mdns_probe`）：带 QU 位要求单播回应

> **实机踩坑**：写 `qclass=0x8001` 会被 scapy 的 `BitField` 拆成
> `qclass(15 bit) + unicastresponse(1 bit)`，高位被吃掉，实际发出 `0x1`。
> 对方于是按组播回，而本机未必收得到 —— 现象就是「发了查询却没人应答」。
> 必须用 `unicastresponse=1`。

**WiFi 托管模式的物理限制**：其他客户端之间的单播由 AP 转发、目的不是我们，
网卡直接丢弃，因此被动嗅探只能看到广播/组播。设备休眠时两条路都探不到，
此时降级为「仅v4」并如实标注，不假装成功。

---

## 2.6 动效体系与图标（v2.2.0 新增）

### 调度器：ui.Anim

Tk 动画最经典的死法是：窗口销毁后 `after` 回调继续触发，抛
`invalid command name` 的 TclError，且异常被 Tk 吞掉，表现为静默错乱。

`ui.Anim` 把所有 `after` id 集中登记，窗口销毁时 `cancel_all()` 一把取消；
回调内部再用 `self._destroyed` 双保险。列表上限 300，超限时裁掉已触发的旧 id。

### 十类动效

| 动效 | 位置 | 实现 | 帧率控制 |
|---|---|---|---|
| 窗口淡入 | 启动 | `attributes("-alpha")` 步进 | 16ms |
| 横幅滑入 | 状态条内容变化时 | 先按 `dy=-10` 画好，再逐帧 `canvas.move` 回原位 | 仅内容变化时播一次 |
| 行错峰淡入 | 扫描结果落地 | `_render_rows(animate=True)` 逐行 `after(n*26)` 插入 | ≤24 行才启用 |
| 阻断行呼吸 | 有阻断目标时 | 70ms 改一次 `tag_configure("blocked", background=…)` | 单点更新，极廉价 |
| 页脚数字滚动 | 设备数变化 | ease_out 插值，12 帧改文本 | 24ms |
| 徽章弹跳 | 页脚数值变化 | 上移 3px → 分两步落回 | 触发式 |
| 按钮波纹 + hover 光晕 | 鼠标交互 | 波纹：扩散圆环，颜色向底色混合模拟淡出；光晕：按钮外两圈浅色描边 | 触发式 |
| 按钮流光 | 彩色按钮按下 | `CanvasButton._sheen()`：一道垂直高光带自左向右扫过并渐隐 | 触发式 |
| 标题强调线 | 首次渲染 | "WiFiKill" 下灰绿线从 0 生长到全宽（`_title_grown` 保证只播一次） | 22ms |
| 日志滚动高亮 | 每次写入 | 最新一条 `tag_add("fresh")` 浅绿底，620ms 后清除 | 触发式 |

外加常驻的：状态点呼吸 + 扩散光晕（`StatusDot`，40ms）与扫描流动条（`Shimmer`，24ms）。

### 性能约定

- Tkinter 没有 alpha 合成，「淡出」一律用**颜色向背景混合**模拟
- 逐行动画只在行数 ≤ 24 时启用，超过直接同步插入，避免大网络下像卡顿
- 所有动效回调第一步都检查 `self._destroyed`

### 一个重要的接口约定

`_render_rows(animate=False)` 默认同步插入。只有「扫描结果落地」这一处传
`animate=True`——因为阻断后刷新、右键菜单、自检脚本都默认「渲染完即可选中」，
异步插入会破坏这个约定。第一版没做这个区分，28 项自检立刻红了 9 项，就是它。

### 多尺寸图标

托盘图标在 16px 下如果沿用大图绘制参数，缩完就是一团糊。`tools/make_icon.py`
按尺寸分级绘制：

| 尺寸 | 元素 |
|---|---|
| ≤ 20px | 1 道弧 + 斜杠（粗笔画） |
| 21–32px | 2 道弧 + 斜杠 |
| > 32px | 3 道弧 + 圆点 + 斜杠 |

生成 9 个尺寸（16–256）打进单个 ICO，托盘/标题栏/任务栏各取所需。

---

## 3. 关键数据结构

```python
@dataclass
class NetInfo:
    iface: str          # \Device\NPF_{GUID}
    my_ip: str
    my_mac: str
    gateway_ip: str
    gateway_mac: str    # 空则拒绝阻断
    cidr: str           # 192.168.1.0/24（网络地址，不是主机地址）
    iface_name: str     # WLAN · Intel(R) Wi-Fi 6E AX211 160MHz

@dataclass
class Device:
    ip, mac, vendor, dtype, note, state

@dataclass
class Target:           # 阻断会话里的最小单位
    ip: str
    mac: str
```

`NetInfo.cidr` 必须是**网络地址**：`192.168.1.3/24` 这种写法 scapy 虽能解析，
但会让 `same_subnet()` 与日志产生歧义，因此 `get_netinfo()` 会做 `ip & mask` 归一化。

---

## 4. 报文结构

### 4.1 为什么 ARP 能被伪造

ARP（RFC 826）设计于 1982 年，用于把 IP 解析为 MAC。它有两条致命特性：

1. **无认证**：任何主机都能发送 ARP 应答，接收方不校验发送者身份
2. **无条件覆盖**：收到应答就更新本地缓存，旧记录直接被替换

因此只要发出格式合法的 ARP 应答，就能改写对端缓存。

### 4.2 双向投毒的两帧

设：本机 `192.168.1.3 / 8c:e9:ee:a0:f3:b6`，
网关 `192.168.1.1 / f8:79:28:cc:fc:e8`，
目标 `192.168.1.5 / e6:ff:70:f3:de:66`。

**帧 A — 欺骗目标**（让它以为网关在我这）：

```
以太头  dst=e6:ff:70:f3:de:66  src=8c:e9:ee:a0:f3:b6  type=0x0806
ARP     htype=1 ptype=0x0800 hlen=6 plen=4 op=2(Reply)
        sha =8c:e9:ee:a0:f3:b6   ← 本机 MAC
        spa =192.168.1.1         ← 冒充网关 IP
        tha =e6:ff:70:f3:de:66
        tpa =192.168.1.5
```

**帧 B — 欺骗网关**（让它以为目标在我这）：

```
以太头  dst=f8:79:28:cc:fc:e8  src=8c:e9:ee:a0:f3:b6  type=0x0806
ARP     op=2  sha=8c:e9:ee:a0:f3:b6  spa=192.168.1.5  tpa=192.168.1.1
```

两帧合计 42 字节（14 以太头 + 28 ARP），无填充。实测字节：

```
帧A  e6ff70f3de66 8ce9eea0f3b6 0806 0001 0800 06 04 0002
     8ce9eea0f3b6 c0a80101 e6ff70f3de66 c0a80105
帧B  f87928ccfce8 8ce9eea0f3b6 0806 0001 0800 06 04 0002
     8ce9eea0f3b6 c0a80105 f87928ccfce8 c0a80101
```

> `c0a80101` = 192.168.1.1，`c0a80105` = 192.168.1.5。这两串是 `_poison_frames()`
> 的单元测试断言依据。

### 4.3 为什么不开转发

ARP 投毒有两种用法：

| 模式 | 转发 | 效果 |
|---|---|---|
| 中间人 | 开（`ip_forward` / Npcap 转发） | 能嗅探改包，目标不断网 |
| **阻断** | **关** | 包到本机即丢弃，双向黑洞 |

WiFiKill 只做后者：`Killer` 不碰任何转发设置，Windows 默认也不转发。

### 4.4 为什么必须重发

ARP 缓存有超时（Windows 约 15–45 秒，Linux 约 30 秒，部分设备 60 秒），
且设备随时可能主动重发 ARP 请求覆盖。默认 1.5 秒一次的间隔足以压住绝大多数设备。

### 4.5 为什么不受 WPA3 / PMF 影响

802.11w（PMF）保护的是**管理帧**（deauth / disassoc），用于防止空口踢人。
ARP 属于**数据帧**，在关联并完成 4 次握手之后才产生，此时链路层已被 WPA3 加密保护——
但 ARP 欺骗是**在加密隧道内部**进行的，路由器会正常解密并转发这些伪造帧。

所以：**PMF 挡的是 deauth 攻击，不挡 ARP 攻击。** 这是本项目选择 ARP 路线的核心理由。

---

## 5. 线程模型

```
Tk 主线程
  ├── _drain()            每 80ms 排空 queue，执行跨线程回调
  ├── 按钮回调            只做「派发线程 + 置 busy」，立即返回
  └── 所有控件读写         仅在此线程

工作线程（每次操作新建，daemon）
  ├── core.scan()         可能 2–3 秒
  ├── core.resolve_mac()  可能触发一次全段扫描
  └── Killer.add/remove   单帧 sendp，毫秒级

投毒线程（Killer 内部，常驻）
  └── 每 interval 秒遍历 targets 发一轮
```

### 5.1 三条铁律

1. **任何可能阻塞超过 50 ms 的调用都必须在工作线程**
   —— 违反会导致窗口"未响应"白屏。
   > 实际踩过：初版在 `do_block()` 里同步调用 `resolve_mac()`，点阻断会卡 2–3 秒。

2. **工作线程绝不触碰控件**
   —— 结果是 `self._post(lambda: ...)` 投递回主线程执行。

3. **日志也被视为控件操作**
   —— `core.LOG.emit` 只入队，真正写 Text 控件发生在 `_drain` 里。

### 5.2 关闭竞态

初版关闭流程有个死锁：`on_close()` 置 `_closing=True` → `_drain()` 判断 `if not _closing` 后
不再重排 → 恢复线程投递的 `destroy` 永远不执行 → 窗口关不掉。

修法：改用独立的 `_destroyed` 标志，`_drain` 只在真正 destroy 之后才停止重排。

---

## 6. 阻断会话状态机

```
        add(t)                stop()
IDLE ──────────► ACTIVE ──────────► STOPPED
  ▲                │  ▲                  │
  │   remove(t)    │  │  start()         │ restore_all()
  └────────────────┘  └──────────────────┘
```

| 方法 | 前条件 | 副作用 |
|---|---|---|
| `add(t)` | 网关 MAC 合法、目标 MAC 合法、二层可用 | 先构造帧验证 → 入队 → 立即发 3 次 → 落盘 |
| `remove(ip)` | 目标存在 | 发 5 次恢复帧；**失败则把目标放回队列** |
| `start()` | 未启动 | 起 daemon 线程，按 interval 发 |
| `stop()` | —— | 置事件 + join(3s)，幂等 |
| `restore_all()` | —— | stop → 逐条恢复 → 全成功才清状态文件 |

**"失败要放回"是刻意的**：如果恢复帧发不出去却清空了状态文件，用户会以为已放行，
实际目标仍断网，且失去了"下次启动自动恢复"的机会——这是最坏的一种假成功。

---

## 7. 状态持久化

文件：`<exe 目录>/.wifikill-state.json`

```json
{
  "updated": 1762012345.6,
  "iface": "\\Device\\NPF_{...}",
  "my_mac": "8c:e9:ee:a0:f3:b6",
  "gateway_ip": "192.168.1.1",
  "gateway_mac": "f8:79:28:cc:fc:e8",
  "targets": [{"ip": "192.168.1.5", "mac": "e6:ff:70:f3:de:66", "note": ""}]
}
```

规则：

- **原子写**：先写 `.tmp`，再 `os.replace()`，避免断电留下半个 JSON
- **演练模式不落盘**：`persist()` 首行 `if self.dry_run: return`
  > 这条是边界测试 `t_dryrun_no_state` 测出来的真实缺陷：初版演练模式也会写状态，
  > 导致下次启动凭空出现"残留阻断"提示。
- **空列表即删文件**：避免留下 `{"targets": []}` 这种噪音

恢复流程：启动时读状态 → 有内容则弹窗询问 → 用户确认后用状态里的 MAC 发恢复帧 →
成功则删文件。

---

## 8. 安全护栏的实现点

| 护栏 | 实现位置 | 逻辑 |
|---|---|---|
| 网关保护 | `gui.do_block()` 的 `picks` 过滤（**单目标与全阻断两条路径**） | `core.is_protected(d)` 即 `d.note != "网关"`；v2.3.0 起单目标路径同样强制 |
| 本机保护 | 同上 | `core.is_protected(d)` 即 `d.note != "本机"`，且 `resolve_target()` 遇到本机 IP 直接返回本机 MAC |
| 白名单 | `_state_of()` + `picks` 过滤 | `ip in wl or mac in wl`（双键） |
| MAC 合法性 | `Killer._frames()` | 正则 `^([0-9a-f]{2}:){5}[0-9a-f]{2}$`，不合法抛 `BlockError` |
| 网关 MAC 缺失 | `Killer._frames()` | 缺失即拒绝，绝不用空串构造 `Ether(dst="")` |
| 单实例 | `core.SingleInstance` | 绑定 `127.0.0.1:51999`，失败即认为已有实例 |
| 组播/广播出口 | `ipv6.NdpBlocker._send()` | 拒绝一切组播/广播目的 MAC，防止误发 `ff02::1` 切断整网 |

---

## 9. 环境探测

### 9.1 为什么不再以「管理员」作为硬门槛

初版 `l2_check()` 在非管理员时直接返回 `no_admin`。实测发现这是**假阴性**：

```
管理员权限 否
抓到的 ARP 应答总数 = 6，命中本机投毒特征 = 3
判定： TX 链路真实可用 ✓
```

Npcap 安装时的选项决定了普通用户能否发帧。以 admin 作为门槛会让本来能用的机器被判定不可用。

**现行策略**：`l2_check()` 只判断"确定不可用"的条件（scapy 缺失、Npcap 缺失），
权限问题交给 `sendp()` 抛异常暴露，再由 UI 提示提权。

### 9.2 网卡友好名

`\Device\NPF_{GUID}` 对用户没有意义。scapy 的 `conf.ifaces` 提供三层信息：

| 属性 | 值 |
|---|---|
| key / `network_name` | `\Device\NPF_{54D4581C-...}` |
| `name` | `WLAN`（系统别名） |
| `description` | `Intel(R) Wi-Fi 6E AX211 160MHz` |

初版错误地用 `name` 去匹配 NPF 路径，永远匹配不上；正确做法是匹配 `network_name`。

### 9.3 网段推导

遍历 `conf.route.routes`，找出与 `my_ip` 同接口、掩码最长的路由（跳过 `/31`、`/32` 主机路由），
用 `ip & mask` 归一化为网络地址。Windows 路由表里同时存在 `/24` 与 `/32` 两条，
不跳过 `/32` 会算成 `192.168.1.3/32`。

---

## 10. 异常处理约定

| 异常 | 处理 |
|---|---|
| `BlockError` | 业务级失败，UI 弹窗或日志 warn |
| `sendp` 底层异常 | 包装成 `BlockError("发送失败：...")` |
| 状态文件损坏 | `load_state()` 吞掉并返回 `{}`，不阻止启动 |
| 日志回调抛错 | `Logger.emit` 逐 sink try/except，一个订阅者坏掉不影响其他 |
| 启动期未捕获异常 | `main()` 兜底弹窗（`--windowed` 下没有控制台，否则用户只看到闪退） |

---

## 11. 测试体系

三层，全部可重复执行。

### 11.1 边界测试 `tests/test_edge.py`（23 项）

不碰真实设备，全部用 `dry_run` 或伪造目标：

| 用例 | 断言 |
|---|---|
| `t_corrupt_state` | 损坏 JSON 不抛异常，返回 `{}` |
| `t_bad_mac` | 非法 MAC 抛 `BlockError` 且不污染队列 |
| `t_no_gateway_mac` | 网关 MAC 缺失必须拒绝 |
| `t_idempotent` | 重复 add 保持单条记录 |
| `t_concurrent` | 8 线程 × 20 轮 add/remove 无异常 |
| `t_dryrun_no_state` | 演练模式不写状态文件 |
| `t_single_instance` | 第二个实例被拒绝 |
| `t_bad_cidr` | 非法网段扫描不崩 |
| `t_whitelist_mac` | 白名单可只有 MAC，且自动小写 |
| `t_restore_clears` | 恢复后队列清空、计数正确 |
| `t_stop_is_clean` | stop 后线程退出、可重复调用 |
| `t_logger_isolation` | 日志回调抛错被隔离 |
| `t_protected_device` | 网关/本机被标记受保护、普通设备不受保护、单目标过滤只留普通设备、仅选网关无可阻断目标（v2.3.0 新增） |

### 11.2 IPv6 报文级 `tests/test_ipv6.py`（34 项）

不碰网卡、不发一个包 —— CI（ubuntu-latest，无 Npcap）也能跑：

| 组 | 断言 |
|---|---|
| 报文结构 | 86 字节、type=136、tgt 正确、O=1、S=0、携带 MAC 正确 |
| 代理应答 | `build_ns_reply` 必须置 S=1 |
| 回填帧 | 携带的是真实网关 MAC，不是本机 MAC |
| 组播保险 | `ff02::1` / mDNS / 广播 / `01:00:5e:*` 四种目的地址全部被拒 |
| preflight | 缺 IPv6 路由、缺网关 MAC、缺目标 LLA 三种情况都拒绝启动 |
| mDNS 报文 | 4 个问题、QU 位为 1、`qclass=1`、目的地址与组播 MAC 正确 |
| 邻居表解析 | 跳过 `00:00:00:00:00:00`、大小写不敏感、不存在返回 None |
| 双栈判定 | 只有 `/128` 主机路由时不算双栈 |
| MAC 校验 | 大小写、短写、非十六进制 |

### 11.3 GUI 自检 `selftest.py`（28 项）

开头会**备份并清空** `whitelist.txt` 与 `.wifikill-state.json`，结束时恢复——
否则上一轮中断残留的文件会让断言结果取决于"上次跑到哪一步"。这是实测踩过的坑：
一次空 `whitelist.txt` 让「行状态=阻断中」红了，排查半天发现是状态泄漏。

启动真实窗口，注入一台 **`02:00:00:00:00:01` 幽灵设备**（全网不存在），
对它执行阻断/放行，从而在不影响任何真人的前提下覆盖完整图形链路。

覆盖：自动扫描、网关/本机识别、网卡友好名、状态栏、日志、阻断按钮启用态、
Killer 建立、队列、投毒线程、状态文件落盘、行状态变色、放行按钮、
白名单增删、设置窗口、恢复后状态复位、关闭流程。

### 11.4 真机发包验证

```python
sn = AsyncSniffer(iface=ni.iface, lfilter=lambda p: p.haslayer(ARP) and p[ARP].op == 2)
sn.start()
for _ in range(3):
    k._emit(ghost_target)      # ghost MAC 不存在，零影响
pkts = sn.stop()
hit = [p for p in pkts if p[ARP].psrc == ni.gateway_ip
       and p[ARP].hwsrc.lower() == ni.my_mac.lower()]
```

实测结果：`命中本机投毒特征 = 3`，证明帧确实离开了网卡。

### 11.5 真机端到端验证（v2.3.0，第二台在线设备）

在网内存在**真实在线设备**（非网关、非本机）的条件下完成闭环：

**IPv4 阻断 + 恢复**（目标：`192.168.1.5`，真实手机）：

```
targets after add     = ['192.168.1.5']
is_active             = True
state file exists     = True          # 崩溃恢复状态已落盘
restore_all returned  = 1
targets after restore = []
state file after      = False         # 状态已清理
ARP frames on wire    = {target: 12, gw: 12}   # 24 帧真实毒化报文被嗅探捕获
```

说明：`0.6s` 间隔下约 2.2 秒，毒化线程每周期发 2 帧（目标 + 网关），
`add` 时再连发 3 帧、`restore_all` 时连发 5 帧 —— 共 24 帧在线上被捕捉，
证明双向投毒与恢复的真实报文都离开了网卡。

**IPv6 路径**（同一网络存在全局 IPv6 `2409:8a55:.../64`）：

| 检查 | 结果 |
|---|---|
| 网关 IPv6 LLA 可达 | `fe80::1 → f8:79:28:cc:fc:e8`（路由器） |
| 组播 NA 安全闸 | **PASS**：发往 `33:33:00:00:00:01` 被 `BlockError` 拒绝，零上线 |
| 真实单播 NA 上线 | `sent = 1`，嗅探捕获 1 帧 |
| 设备 LLA 探明 | 两台手机处于 IPv6 静默，返回「未探明」（见 §13 已知限制） |

> 诚实边界：两台在线设备均为 IPv6 静默（无邻居表项、不回应 mDNS），
> 因此无法对其 LLA 做**端到端 IPv6 阻断**——这正是 §13 记录的已知限制，
> 并非缺陷。IPv6 的报文构造、安全闸、单播上线与网关可达性均已真实验证。

---

## 12. 打包与版本管理

### 12.1 版本真源

`versions.json`：

```json
{"app": "2.0.0", "user_manual": "1.0.0", "tech_manual": "1.0.0", "build": 1, "released": "2026-11-02"}
```

### 12.2 构建流程

```
python build.py
  ├─ 1. app / user_manual / tech_manual 各 +1 patch，build +1，写回 json
  ├─ 2. 正则替换两份手册的「文档版本」「对应程序」标记
  ├─ 3. 生成 build/version_info.txt（Windows 文件版本资源）
  ├─ 4. PyInstaller --onefile --windowed --version-file ... gui.py
  ├─ 5. PyInstaller 出 dist/WiFiKill.exe
  ├─ 6. 复制为 dist/WiFiKill-vX.Y.Z.exe（单文件版）
  ├─ 7. ISCC 编译 installer/WiFiKill.iss → dist/WiFiKill-vX.Y.Z-setup.exe（安装版）
  └─ 8. 打 dist/WiFiKill-vX.Y.Z-portable.zip（exe + README + 两份手册 + LICENSE，打包版）
```

文档里的标记行格式固定，构建脚本靠正则定位：

```markdown
> 文档版本：**v1.3.0** · 对应程序：**v2.3.0** · 更新日期：2026-11-02
```

### 12.3 打包参数与取舍

| 参数 | 理由 |
|---|---|
| `--onefile` | 用户要"一个 exe" |
| `--windowed` | 不要黑框；代价是 `stdout=None`，故 core 禁止 print |
| `--collect-submodules scapy` + `--collect-data scapy` | scapy 有大量动态导入与数据库文件 |
| `--exclude-module numpy/matplotlib/pandas/PIL/setuptools/test` | 剔掉后 45 MB → 16.8 MB，启动 8.9 s → 2.3 s |
| `--version-file` | exe 属性里能看到版本号 |
| 干净 venv 构建 | 系统 Python 的 site-packages 太杂，模块图分析从 42 s 降到 ~45 s 且更可控 |

> 注：tkinter **不能**排除，它是 UI 本体。排除 PIL 只影响 `tools/make_images.py` 与 `selftest.py`。

---

## 12.5 托盘实现要点

不引入 pystray 的原因：它依赖 Pillow，会把打包体积从 16.9 MB 拉到 20 MB+。

自实现路径：

```
独立守护线程
  ├── RegisterClassExW 注册窗口类
  ├── CreateWindowExW 建不可见窗口
  ├── Shell_NotifyIconW(NIM_ADD) 挂图标
  └── GetMessageW / DispatchMessageW 消息循环
```

WndProc 处理三类消息：

| 消息 | 动作 |
|---|---|
| `WM_TRAY`（自定义 `WM_APP+1`） | 左键双击→显示主界面；右键→弹 `TrackPopupMenu` |
| `TaskbarCreated` | 资源管理器重启后重新挂图标 |
| `WM_CLOSE` | `NIM_DELETE` + `DestroyWindow`，干净退出 |

**踩过的坑**：ctypes 不给函数声明 `argtypes` 时会把指针当 32 位 int，
64 位下 `DefWindowProcW` 直接抛 `OverflowError: int too long to convert`，
且异常被 ctypes 吞成 "Exception ignored"，表现为托盘静默不出现。
修法是把 `DefWindowProcW`、`CreateWindowExW`、`LoadImageW` 等全部显式声明签名。

## 13. 已知限制

| 限制 | 原因 | 是否可解 |
|---|---|---|
| 客户端隔离网络无效 | AP 不转发站间流量，拿不到目标 MAC | 不可解，这是网络策略 |
| 静态 ARP 绑定的设备不受影响 | 对端不更新缓存 | 不可解 |
| 目标装了 ARP 防火墙 | 会校验并丢弃伪造应答 | 不可解 |
| IPv6 只断经网关的出站 | 只投毒默认路由的邻居项，同链路直连不经网关 | 不可解 |
| IPv6 目标地址依赖设备活跃 | 托管模式看不到他人单播，只能靠 mDNS/组播 | 部分可解（有线 + 端口镜像） |
| IPv6 同时只能断 1 台 | 刻意限制，降低整网失控风险 | 刻意为之 |
| 不支持 5GHz 特有行为 | 工作在二层之上，无频段概念 | 无影响 |
| 单文件启动约 2.3 s | PyInstaller 解包 | 可改 `--onedir`，但会变成文件夹 |

---

## 14. 扩展点

| 想做的事 | 改动位置 |
|---|---|
| 支持 IPv6（NDP 欺骗） | `core.Killer._frames()` 增加 ICMPv6 NA 帧 |
| 增加带宽限速而非全阻断 | 需开启转发 + 令牌桶，改动较大 |
| 定时策略（晚上自动阻断） | `gui` 加 `after` 定时器调用 `do_block` |
| 托盘常驻 | 引入 `pystray`，改写 `gui.main` |
| 设备备注持久化 | 状态文件加 `notes` 字段，`Device.note` 已有位置 |

---

## 15. 附：一次真实运行的环境探测输出

```
Python        3.13.14 / 3.12.4
scapy         2.8.0
管理员权限    否
二层收发      可用
网卡          WLAN · Intel(R) Wi-Fi 6E AX211 160MHz
本机          192.168.1.3  (8c:e9:ee:a0:f3:b6)
网关          192.168.1.1  (f8:79:28:cc:fc:e8)
网段          192.168.1.0/24
```

扫描合并结果（主动 2 台 + 缓存 3 台 = 5 台，验证了"两路合并"策略的必要性）：

```
192.168.1.1   f8:79:28:cc:fc:e8   —          网关
192.168.1.2   ee:89:6d:6f:b4:54   随机 MAC    移动设备?
192.168.1.3   8c:e9:ee:a0:f3:b6   —          本机
192.168.1.4   4e:55:a0:5f:47:20   随机 MAC    移动设备?
192.168.1.5   e6:ff:70:f3:de:66   随机 MAC    移动设备?
```

其中 `.2 / .4 / .5` 的第二字节 `0x89 / 0x55 / 0xff` 均带 locally-administered 位
（`& 0x02`），被正确识别为随机化 MAC。
