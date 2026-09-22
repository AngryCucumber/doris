<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# 故障当天 Master FE 的 ZGC 日志分析

分析日期：2026-09-22。用户确认这是 Master FE 日志，2026-09-20 当天开始卡顿；
尚无精确到分钟的故障起止时间。本次只在本地读取附件、解析统计并制图，没有连接生产进程。

**结论：本窗口没有显示能直接解释长时间入库卡住的 GC 长暂停或新增已记录分配阻塞。
堆内存可大幅回收，短窗口内也没有持续爬升的 Live 曲线。
明确值得继续定位的是约 1.25 万个 Java 线程的用途与等待链，以及持续较高的堆页分配速率。**
这不是“GC 完全没有开销”，也不能排除窗口外故障、尚未结束的等待、其他 safepoint 或 native 内存问题。

原始附件：[fe.gc.log.20260906-094933](/root/.codex/attachments/86eb0319-b9c7-496c-89f9-e4161e3167f6/fe.gc.log.20260906-094933)。
SHA-256：`b1e9396844bd6b2df98e3fa57442c2d23d46baa1a3c782dbc3c47360acad247d`。
关联：[配置分析](/data/project/massdb-sql/docs/fe-config-audit-20260922.md)、
[源码排查](/data/project/massdb-sql/docs/fe-stall-investigation-20260921.md)。

## 1. 覆盖范围与实际参数

| 项目 | 日志证据 |
|---|---|
| 附件规模 | 36,237 行，约 6.4MiB |
| 实际时间 | 2026-09-20 13:42:53.943～15:30:23.941，UTC+8 |
| 窗口长度 | 约 1 小时 47 分 30 秒，墙钟差 6449.998 秒 |
| 进程 uptime | 起点 1,223,600.285 秒，已运行约 14 天 3 小时 53 分钟 |
| 推算启动时间 | 2026-09-06 09:49:33.658，和文件名相符 |
| Min Capacity | 128000M = 125GiB |
| Max / Soft Max Capacity | 307200M = 300GiB |
| GC 原因 | 142 次均为 `Allocation Rate` |
| GC workers | 141 条记录中，138 轮为 24 个，21/22/23 个各 1 轮；首个周期缺开始部分 |

文件名是启动时间，**不能把附件当成从 9 月 6 日到 9 月 20 日的完整 GC 日志**。
容量数据见[原日志第 25 行](/root/.codex/attachments/86eb0319-b9c7-496c-89f9-e4161e3167f6/fe.gc.log.20260906-094933:25)。
日志确认了 125/300GiB 和软上限，但没有 JVM 启动版本头，17.0.2 补丁版本仍来自用户提供的信息。

## 2. 暂停很短，数秒 GC Cycle 是并发周期

| 指标 | 结果 |
|---|---:|
| 完成的 GC | 142 次，GC ID 37602～37743 连续 |
| 有完整开始/结束的周期 | 141 次；首轮缺开始行，但 Pause/结束完整 |
| 完整周期平均耗时 | 7.989 秒 |
| 完整周期最长耗时 | 约 10.692 秒 |
| 相邻完整周期开始间隔平均 | 45.633 秒 |
| Concurrent Mark 平均耗时 | 7.574 秒 |
| GC Pause 条数 | 426 条，每轮三类 Pause |
| Pause 总和 | 302.058 毫秒，约为窗口墙钟时间的 0.00468% |
| Pause 单次最大 | **3.306 毫秒** |

最大暂停发生在 14:05:13.689，见[原日志第 7584 行](/root/.codex/attachments/86eb0319-b9c7-496c-89f9-e4161e3167f6/fe.gc.log.20260906-094933:7584)。
Mark Start 最大 0.076ms，Mark End 最大 3.306ms，Relocate Start 最大 0.065ms。
不能把约 8 秒的并发周期、约 7.6 秒的并发标记当成所有业务线程停止同样长的时间。
并发 GC 仍消耗 CPU 和内存带宽；现有日志不能计算实际 GC CPU 占比。

**覆盖边界：** GC Pause 阶段计时不包含所有 JVM 停顿与进入 safepoint 的等待时间。
附件没有 safepoint 明细；如果故障时整体无响应，仍需核对 safepoint 的到达/总耗时，
以及 OS 调度、内存压力和业务锁。OpenJDK 17.0.2 的阶段计时位于对应 VM operation 内部，
见 [zDriver.cpp](https://github.com/openjdk/jdk17u/blob/jdk-17.0.2-ga/src/hotspot/share/gc/z/zDriver.cpp)。

## 3. Allocation Stall：有历史事件，本窗口没有新增记录

645 份统计中，Allocation Stall 的次数率与耗时均保持以下值，
见[开头第 43 行](/root/.codex/attachments/86eb0319-b9c7-496c-89f9-e4161e3167f6/fe.gc.log.20260906-094933:43)
及[结尾第 36196 行](/root/.codex/attachments/86eb0319-b9c7-496c-89f9-e4161e3167f6/fe.gc.log.20260906-094933:36196)：

| 统计列 | Allocation Stall 平均/最大耗时 | 含义 |
|---|---|---|
| Last 10s | 0 / 0 ms | 各短窗口没有新登记的完成事件 |
| Last 10m | 0 / 0 ms | 所有统计块的近十分钟同样为零 |
| Last 10h | 590.547 / 786.146 ms | 更早时段的历史事件 |
| Total | 750.369 / **4157.387** ms | 进程历史最大单次分配等待约 4.157 秒 |

没有独立的 Allocation Stall 事件行；ZGC Out Of Memory 统计各列也均为零。
因此不能把历史最大 4.157 秒说成这 108 分钟里发生的停顿，
也不能把分配线程的等待等同于全 JVM 的 STW。
`ops/s` 列的历史最大 1119 是事件完成速率，不是累计次数或并发等待线程数。
这些事件在结束时登记，不能仅凭零值排除仍未结束、尚未登记的等待。

同理，MMU 中 `2ms/0.0%, 5ms/0.0%, 10ms/0.0%` 在 142 个周期完全相同。
此版本保存历史最坏短窗口 MMU；它不是当前业务线程利用率，更不是当前吞吐为零。
统计窗口、MMU 累计最小值、critical 事件完成登记语义均核对了
[OpenJDK 17.0.2 zStat.cpp](https://github.com/openjdk/jdk17u/blob/jdk-17.0.2-ga/src/hotspot/share/gc/z/zStat.cpp)。

## 4. 高水位可回收，Live 与回收后 Used 要分开

| 堆指标 | 本窗口范围 |
|---|---:|
| 每轮标记的 Live | **29.698～36.877GiB** |
| GC 结束时 Used | **49.416～92.496GiB** |
| 每轮 Used 高水位 | **64.088～288.689GiB** |
| Capacity（各阶段及高低水位） | 约 207.734～294.244GiB |

最接近满堆的是 GC37661，14:24:57 左右，见
[原日志第 14323 行](/root/.codex/attachments/86eb0319-b9c7-496c-89f9-e4161e3167f6/fe.gc.log.20260906-094933:14323)：

```text
Used High:          295618M (96%)  = 288.689 GiB
GC 结束 Used:        58942M (19%)  =  57.561 GiB
Live:                34009M        =  33.212 GiB
```

峰值后明显回落，不能把 288.7GiB 当成长期存活的元数据体积。
回收后 Used 也不等于 Live：其中还包括本周期并发新分配、尚未回收的垃圾等。
首轮至末轮的回收后 Used 增加 8074MiB，但日志字段可拆成：
Live 增加 407MiB、Allocated 增加 7571MiB、Garbage 增加 96MiB。
因此不能只拿首尾 Used 相减就说泄漏了约 8GiB。

Live 多次回落，首尾为 30.418→30.815GiB；前 71 次与后 71 次 GC 的 Live 均值仅相差约 201MiB。
这段曲线不支持“窗口内存活堆持续快速增长”，但不足以排除此前两周的增长或 native 内存问题。

![堆使用趋势](/data/project/massdb-sql/.build-records/fe-gc-20260922/heap-overview.png)

折线连接的是各 GC 周期的数据点；高水位绘制在周期结束时刻，不能用于计算真实高占用持续时间。

## 5. 两条明确线索：堆页分配速率与约 1.25 万线程

**堆页分配：** 645 个 Last 10s 平均值的均值为 2749.35MiB/s，约 **2.69GiB/s**。
各 Last 10m 平均值约为 2.22～3.13GiB/s；本窗口采样秒峰值为 14982MiB/s，约 **14.63GiB/s**，
见[原日志第 11366 行](/root/.codex/attachments/86eb0319-b9c7-496c-89f9-e4161e3167f6/fe.gc.log.20260906-094933:11366)。
历史 Total 最大 32304MiB/s 已在窗口开始前出现，不应作为本窗口峰值。

OpenJDK 按非 GC worker relocation 的堆页分配大小累计，此处 MB/s 实际按 2^20 字节换算。
它不是导入数据吞吐、对象净增长，也不是精确的对象 payload 字节数。
来源见 [zPageAllocator.cpp](https://github.com/openjdk/jdk17u/blob/jdk-17.0.2-ga/src/hotspot/share/gc/z/zPageAllocator.cpp)。
高分配与低 Live 支持存在大量可回收对象/页的周转；是否超出健康业务所需，还要与同负载健康基线比较。
不能直接从 GC 日志定位到某个 Java 方法。

**线程：** 有效 Last 10s 采样平均值最低 12474，采样最大值最高 **12578**，
见[原日志第 23880 行](/root/.codex/attachments/86eb0319-b9c7-496c-89f9-e4161e3167f6/fe.gc.log.20260906-094933:23880)。
本窗口基本维持约 1.25 万，历史采样最大 12983。这为早期 4096 容量不足提供了当前规模的参考，
但不能回溯证明去年相同版本/负载，也没有提供当前 100000 Thrift 上限触顶的证据。
继续保留当前容量，先按名称与栈统计线程用途和等待状态。

这里是 JVM Java 线程总数，不是 Thrift 专属线程数，不代表线程都在消耗 CPU。
GC 操作完成时才采这个指标，645 个短窗中有 241 个非零有效窗口；
其余 `0/0` 表示无采样，不能画成线程归零。
同一窗口内的平均值也不是均匀的墙钟时间平均。

![GC、分配、线程完整趋势](/data/project/massdb-sql/.build-records/fe-gc-20260922/gc-overview.png)

## 6. 对此前假设的更新

| 原候选 | 新证据带来的调整 |
|---|---|
| GC 长 STW 导致这段时间持续卡住 | 明显下调；实际 Pause 很短，其他 safepoint 仍未覆盖 |
| 本窗口频繁分配阻塞 | 没有新增已完成事件记录；历史确实发生过 |
| 长期存活对象已接近 300GiB | 本窗口不支持；Live 约 30～37GiB |
| 10 万 Thrift 线程上限触顶 | 本窗口无支持，Java 线程样本约 1.25 万；保留上限并查占用 |
| 线程/业务锁/journal/发布等待 | 仍高优先级；GC 健康不能证明这些路径在前进 |
| 报告、发布扫描等高分配路径 | 值得采分配栈，但尚未定位主导者 |
| checkpoint 持续因内存跳过 | 尚未证明；瞬时 Used 高水位有机会触发保护，需要实际 checkpoint 时间 |
| 堆伸缩导致停顿 | 有 24 条 Uncommitted，共约 231.1GiB，最大一次约 65.35GiB；这不是耗时记录，不能据此认定延迟根因 |

默认 checkpoint 阈值的实际拒绝边界仍约为 213GiB **当时的 heap Used**。
142 轮 GC 中有 49 轮高水位达到该边界，但回收后 Used 全部低于约 92.5GiB。
**49/142 既不是 checkpoint 失败比例，也不是高占用时间比例。**
Live 不能替代 checkpoint 检查的即时 Used，不能据此保证一定成功或一定失败。
要核对 image 成功水位和日志中的实际跳过原因；不据此提高阈值或强制 GC。

## 7. 下一步取证与可验证改进

优先获取同一故障窗口的线程分布、请求进展和少量分配采样，原始记录可以保留现场。

1. **连续线程快照与连接数：** 区分等待下一条 Thrift 消息、读取未完整 report、
   事务/表锁、`EditLog-Flusher`、BDB、发布队列及日志缓冲等待。
   同时对照 9020 连接数、FD 和实际 Thrift pool size，不能把全部 1.25 万线程算成 Thrift。
2. **分配热点采样：** 优先比较 `TTablet/TTabletInfo.read`、`ReportHandler.buildTabletMap`、
   `TabletInvertedIndex.processTabletReportAsync`、发布事务列表扫描/排序、
   `TabletStatMgr`、checkpoint image 加载以及 metrics 的线程信息/字符串分配。
   前述均是代码候选，不是已证明的根因；按采样分配字节权重和调用栈排序。
3. **写路径进展：** 看 begin/commit/visible 的耗时、最老事务状态、journal 与 image 进展。
   若线程主要停在 journal/事务锁，先解决持锁者；高分配可能是并行背景负载。
4. **整体冻结而 GC Pause 短：** 补充 safepoint 总耗时、进程 CPU/系统内存压力。
   不能用 SSD、低 GC Pause 或较低平均主机 Load 替代这些观测。

可选的短时 JFR 示例（由现场先设置已确认的 `FE_PID`，并创建 FE 用户可写的新 `FE_DIAG_DIR`）：

```bash
/usr/local/deploy/java17/bin/jcmd "$FE_PID" JFR.start \
    name=fe_stall settings=profile duration=120s \
    filename="$FE_DIAG_DIR/fe-stall.jfr"
```

本地 OpenJDK 17.0.2 的 `profile.jfc` 已核对：启用带栈的 `jdk.ObjectAllocationSample`，
throttle 为 300/s；monitor/park、socket/file 耗时事件阈值为 10ms。
现场文件可能有自定义，使用前应核对；JFR 为短时采样，仍应观察采样开销。
命令参数见 [JDK 17 jcmd 文档](https://docs.oracle.com/en/java/javase/17/docs/specs/man/jcmd.html)。
本次没有在生产启动 JFR。

采样结束后先检查 `jfr summary` 的事件数量和 DataLoss；分配事件应按 `weight` 聚合，
不能按事件条数推算精确对象数。贯穿整个录制且未结束的 socket/锁等待可能没有耗时事件，
所以 JFR 不能替代线程快照。120 秒还可能错过 600 秒统计任务或 checkpoint，需对齐相应任务窗口。

在找到主导路径前，保持当前 125/300GiB 和 Thrift 容量作为对照基线。
若证实报告重复构造主导，则优化对象分配/缓存与报告频率；若是发布积压扫描，则先处理最老事务与扫描频率；
若为锁/journal 等待，则修复持锁路径。堆固定大小或 JDK 补丁对照放在相同负载下单独验证，
本日志没有证据支持仅靠增大堆、GC worker 或线程上限解决故障。

## 8. 本地验证与产物

两套独立解析对 GC 次数、暂停、Live/Used 范围和统计窗口进行了交叉核对；
核验了 GC ID 连续、645 个统计块约每 10 秒一次及原始关键行。
GC 周期耗时来自 uptime 开始/结束差；首轮不参与完整周期平均值；
Pause 总和仅计算逐事件行，不重复累计历史统计表。

- [逐 GC 数据 CSV](/data/project/massdb-sql/.build-records/fe-gc-20260922/cycles.csv)
- [解析数据 JSON](/data/project/massdb-sql/.build-records/fe-gc-20260922/parsed.json)
- [输入校验和与产物说明](/data/project/massdb-sql/.build-records/fe-gc-20260922/manifest.json)
- [制图脚本](/data/project/massdb-sql/.build-records/fe-gc-20260922/plot_gc.py)

生产日志不足以直接给出应用层根因，本轮结论是对已有候选的证据排序与可重复统计。
