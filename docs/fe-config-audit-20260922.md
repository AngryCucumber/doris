<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# FE 配置与周级入库卡顿：附件专项审计

2026-09-22，代码 HEAD `59329855b4e`，存算一体。输入为用户提供的 `fe(1).conf`，
仅按文本读取，没有执行其中的 shell 表达式。环境按 600 BE、200 万逻辑 tablet、
FE 主机 512G/96 核、OpenJDK 17.0.2 理解。用户确认 FE 元数据位于 SSD；
副本数及 FE 拓扑、元数据与日志是否共享设备尚未知。

结论：**配置中有明确无效项，也有能显著放大连接、事务、修复和锁压力的组合；
尚不能仅凭文件证明哪一个已在现场触发。** 最值得核查的是连接/线程实际增长、
事务与发布积压、修复活动和日志/journal 磁盘，而不是继续统一加大线程池、队列或超时。

本文补充并修正 [前次排查报告](/data/project/massdb-sql/docs/fe-stall-investigation-20260921.md)。
最重要的修正是：附件 JDK 17 参数为 **Xms125g/Xmx300g**，与此前口述 180g/360g 不同；
Thrift 上限为 **100000**，不能再按源码默认 4096 断言生产触顶。
用户已确认以本附件为准；下文的生产配置基线采用 125g/300g。

**后续 GC 实证：** 用户提供故障当天 Master 的 2026-09-20 13:42～15:30 日志。
142 轮 GC 的最大 Pause 为 3.306ms，Live 约 29.7～36.9GiB，GC 后 Used 约 49.4～92.5GiB；
本窗口没有新增已记录的 Allocation Stall，Java 线程采样约 1.25 万。
因此下调本窗口内“GC 长暂停、长期存活堆撑满、10 万 Thrift 上限触顶”的解释，
继续定位线程等待链与较高堆分配速率。详见
[GC 实证分析](/data/project/massdb-sql/docs/fe-gc-log-analysis-20260922.md)；本文其余风险是条件性源码分析。

## 1. 文件值还需与运行值区分

- `bin/start_fe.sh:117-131` 读取大写参数，随后 `bin/palo_env.sh` 可以覆盖。
  第 304-309 行 JDK 17 只选择 `JAVA_OPTS_FOR_JDK_17`；JDK 8 的 `JAVA_OPTS` 不合并进去。
- `DorisFE.java:140` 随后加载 `fe_custom.conf`；`ConfigBase.java:145-153` 明确其覆盖 `fe.conf`。
  动态配置、会话变量、用户属性及库级事务 quota 还可能与文件不同。
- `ConfigBase.java:230-257` 只遍历注册的 `@ConfField` 字段；未知名称不会按预期生效，
  也不会因为是未知项就阻止 FE 启动。注释掉的参数当然不参与配置。

以下“实际”指当前代码按本附件启动、没有上述覆盖的结果。具体故障 FE 以进程和管理接口为准。

## 2. 高优先级：Thrift 容量需求与线程占用原因

附件第 94-95 行：

```properties
thrift_server_type=THREADED
thrift_server_max_worker_threads=100000
```

用户补充：较小的 Thrift 线程上限会导致入库等操作遇到线程满，因此调大有实际容量背景。
**当前先保留 100000，不把这个上限本身判定为配置错误或周级卡顿根因。**
用户进一步说明：最初是 4096 不够，去年已逐步调大。将其记录为历史容量证据；
当时版本、规模、逐次阈值和当前实际线程数未确认，不把历史触顶当作本次周级故障的直接证据。
较小上限触顶尚不能区分正常连接需求、空闲连接占位与请求内部阻塞，
也不能推出确实需要 10 万个并行 RPC。

`THREADED` 不是当前有效名称。`ThriftServer.java:77-83` 将未知名称静默回退到
`THREAD_POOL`，最终仍是阻塞式 `TThreadPoolServer`。改成 `THREAD_POOL` 可消除歧义，
但不会改变这份配置的实际执行模式；不能把改拼写说成性能修复。也不要直接改成
`THREADED_SELECTOR`，需要先验证 BE/FE 客户端 transport 与协议兼容性。

未设置的 `thrift_client_timeout_ms` 默认为 0，当前用于 FE 接受的 socket 读超时
（`ThriftServer.java:241`），不是一次 BE RPC 的业务超时。
持久连接即使空闲，也能占用一个 worker。`ThreadPoolManager.java:119-123` 使用
core=0、max=100000、`SynchronousQueue`，按需增长，**不会启动时创建 10 万线程**。
池的空闲线程 keepalive 不会回收仍在连接读取循环中的 worker。

这把排查重点转向：达到 10 万前是否已遇到进程线程/FD 限额、cgroup pids 限制、
native 内存压力或过多可运行线程。600 BE 两套客户端缓存的潜在空闲保留容量约 12000，
不是现场实测，也远不能据此证明达到 100000。线程池使用率也会误导：
`active_thread_pct` 用最大线程数作分母（`ThreadPoolManager.java:95`），10000 个 active
worker 只显示 10%；active 包含正在阻塞读连接的 worker。

大量线程还增加 `JvmStats.java:117` 的线程信息枚举成本；这里取深度 0，并非采集完整线程栈。
旧报告中“拒绝策略吞异常、导致已接入连接没有服务”的代码缺口仍存在，但需实际发生拒绝才能归因。
若先出现 `unable to create native thread`，则应检查接收线程与 FE 进程状态，
不能只盯线程池拒绝计数；启动脚本还有 OOM 后杀进程选项。

处理：保留当前容量，先统计绝对线程数、9020 连接及来源、FD、限额和连续栈，
对齐 begin/commit/visible 吞吐和最老事务年龄，再制定连接保留/回收预算和 worker 上限。
**不建议直接从 100000 改回 4096，也不预设某个更小值可以满足现场。**
持续处理请求与等待下一条消息的连接都计入 active，池的 task/completed_task 计数对应连接处理任务，
不能直接当作 RPC 请求量和完成量。空闲超时须在测试中验证缓存重连、进行中请求和重试语义；
过短超时也可能增加 Broken pipe，不能把任意数值当通用处方。

| 连续观测 | 更支持的解释 | 处理方向 |
|---|---|---|
| 吞吐和耗时稳定，连接多，负载下降后大量 worker 仍等下一条消息 | 正常连接容量加缓存保留 | 测量峰值并治理空闲连接生命周期 |
| 线程增加而吞吐下降，最老等待增长，多份栈停在事务锁/journal/发布 | 请求阻塞向接入层传播 | 优先解除具体阻塞并约束上游重试 |
| 大量线程持续计算，CPU 与有效吞吐同时增长 | 实际处理负载 | 分析处理热点、报告批量与业务并发 |

socket read 还可能是在读取未收完的消息，不能只凭 Java RUNNABLE 或一份栈就算成空闲连接。
吞吐稳定与缓存保留也可能同时存在；线程高水位是否持续增长比单个静态上限更有诊断价值。

## 3. 高优先级：事务容量、超时、历史保留

| 配置 | 附件值 / 源码默认 | 判断 |
|---|---|---|
| `max_running_txn_num_per_db` | 100000 / 10000 | 默认额度放宽 10 倍；允许更多在途事务，不提高处理能力 |
| `max_stream_load_timeout_second` | 600 / 259200 秒 | 普通 Stream Load 请求显式 timeout 超过 600 时会拒绝，而非截为 600 |
| `stream_load_default_timeout_second` | 600 / 259200 秒 | 无显式 timeout 的普通流式事务默认 10 分钟；拥塞时更容易失败 |
| `streaming_label_keep_max_second` | 3600 / 43200 秒 | 流式等 Short 类型终态事务保留缩为 1 小时；不是在途超时 |
| `label_keep_max_second` | 1800 / 259200 秒 | 其他 Long 类型终态保留缩为 30 分钟；不要求名称上的 Long 必须大于 Short |
| `group_commit_timeout_multipler` | 3 / 10 | 只影响特定 Group Commit 计划路径；不是普通 Stream Load 的通用超时倍率 |

`DatabaseTransactionMgr.java:2112` 实际读取库的 `transactionQuotaSize`，不是每次 begin
直接读取 `max_running_txn_num_per_db`。`Database.java:159` 初始化默认值，第 715-717 行恢复时
优先采用库属性。可在健康期低频用 `SHOW PROC '/dbs'` 的 `TransactionQuota` 与
`RunningTransactionNum` 核对实际库；该命令还扫描大小/副本，故障期优先沿用已有结果并可跳过。
修改文件未必改变显式设置过 quota 的库。下调额度会使已有积压超过新额度时拒绝新事务，
应先控制输入并观察积压消退。

事务开始/提交被业务锁、journal 或 BE 发布拖慢时，较大的额度可能让更多对象、等待者和重试积累。
监控又会读取同一事务管理器，能形成入库和 metrics 同时变慢的链。
但 100000 是额度，不等于已占用 100000；事务状态与最老年龄比上限本身更有诊断价值。

`#max_publishing_txn_num_per_table=2000` 被注释，附件没有解除默认 **500** 的发布积压限制。
该检查使用定期更新的计数，并非精确瞬时硬上限。COMMITTED 太多仍可能拒绝新事务，
不因运行事务额度变为 10 万而解决。COMMITTED 不走普通 PREPARE 超时清理。

`GlobalTransactionMgr.java:174`、`FrontendServiceImpl.java:1289` 与
`NereidsStreamLoadPlanner.java:302` 确认 600 秒的检查和执行预算。
2PC 的 PRECOMMITTED 仍使用独立的 `stream_load_default_precommit_timeout_second`，
附件未配，默认 **3600 秒**（`TransactionState.java:270,685`）。
因此“所有挂住请求最多 600 秒就一定返回”不成立；HTTP、RPC、事务和客户端还有不同等待环节。

普通 Flink Stream Load/2PC 使用流式 Short 保留规则，不能把其 label 一律说成仅保留 1800 秒。
此外，未配置的 `label_num_threshold=2000` 可让终态历史按数量更早清理，1 小时也不是保证窗口。
重启/恢复需要旧 label 或事务状态时可能受影响，应按 connector 的恢复语义、完成速率、
最长恢复窗口共同确定 TTL 和数量预算。缩短 TTL 通常减少历史保留，不应直接当作内存积压原因；
它也不提高每库每轮最多清理 10000 个的吞吐能力。

`GroupCommitTableValuedFunction.java:79-83` 使用
`max(int(group_commit_interval_ms / 1000.0 × multipler), 600)`；
默认表间隔 10 秒时，倍率 3 和 10 最后都是 600 秒。不要据此声称导入超时被缩短为 3 秒。

处理：优先限制产生积压的小事务并发、优化批量并修复发布/journal 慢路径；
再依据实际健康峰值设库 quota。客户端超时和 600 秒上限应协调，但单独加大超时不修复卡顿。

## 4. 高优先级：副本修复与均衡组合

| 参数 | 附件值 | 源码默认 | 倍数/含义 |
|---|---:|---:|---|
| `schedule_batch_size` | 2000 | 50 | 每轮批量上限 40 倍 |
| `schedule_slot_num_per_hdd_path` | 32 | 4 | HDD 每路径 slot 上限 8 倍 |
| `schedule_slot_num_per_ssd_path` | 32 | 8 | SSD 每路径 slot 上限 4 倍 |
| `max_scheduling_tablets` | 30000 | 2000 | pending/running 阈值提高 15 倍 |
| `max_balancing_tablets` | 5000 | 100 | 均衡数量控制提高 50 倍 |
| `balance_slot_num_per_path` | 2 | 1 | 均衡另受更小的每路径 slot 控制 |
| `min_clone_task_timeout_sec` | 300 | 180 | 最短任务预算更长 |
| `max_clone_task_timeout_sec` | 14400 | 7200 | 最大任务预算到 4 小时 |

`TabletScheduler.java:279` 控制接纳，第 1794 行取批量时也受可用 slot 限制；
第 2352-2366 行区分普通与均衡 slot。`TabletSchedCtx.java:1071` 按大小估算并夹在最小/最大超时之间。
这些值不是“必然同时启动 30000 个 clone”，也不能把所有修复都按 32 个均衡任务/路径计算。

存在大量异常副本、节点反复失联或容量不均时，这组配置允许更强的复制 I/O、网络和元数据变更，
可能与导入/发布争资源，并增加 FE 报告、持锁、journal 与日志负载。没有实际修复任务时，
高上限不会凭空产生相同负载。应对齐故障窗口的 repair/balance 数、clone 速率、BE I/O 与 FE 锁栈。

若确认强相关，在测试中先降低每路径 slot 和每轮批量，一次只变一组并测量修复积压恢复速度。
不要永久关闭修复，也不要把缩小所有队列当作完成治理。HDD 与 SSD 应分别按实测能力预算。

## 5. 报告并发：可能放大争用，但不是简单的队列无限增长

`report_handler_worker_num=16`（默认 4）；`tablet_report_thread_pool_num=64`（默认 10）。
后者在 `TabletInvertedIndex.java:112` 建立的是 **全局共享 core=64/max=128 的分片池**，
不是每个 report worker 各建 64 线程；不能计算成 16×64 个实际工作线程。
`#tablet_report_queue_size=8192` 是注释，分片任务队列仍默认 **1024**。

`TabletInvertedIndex.java:158-175,247` 持倒排索引读锁提交分片并等待全部完成。
并发报告增加时，临时对象、CPU 与写锁等待可能增长；当前拒绝策略是 `CallerRunsPolicy`，
不是旧的丢弃分片而使 future 永不完成的实现。96 核不代表所有核都可分给此池，
但 64/16 也不能只因高于默认就认定错误：600 BE 可能确实需要更高报告吞吐。

`report_queue_size=20000` 是另一层队列的限制。
`ReportHandler.java:269-295` 按 `(BE,type)` 合并 pending 报告；有效保护阈值是
`max(report_queue_size,10×BE数)`，600 BE 在默认值下也已约 6000。
当前仅 TASK/DISK/TABLET/INDEX_POLICY 四类，不是每份历史报告都追加一个完整 pending 项。
**不能把 20000 简单等同于可积压 20000 份同一 BE 的旧全量 tablet 报告。**
内存仍有当前报告 payload 和处理中的临时对象开销。增大这一限制通常不解决本版本的报告消费瓶颈。

`tablet_stat_update_interval_second=600` 确实将统计周期从默认 60 秒拉长，降低频率但延迟统计；
单轮仍访问全体 BE，不能据此说 tablet 元数据扫描都已变成 10 分钟一次。

## 6. 已确认无效/放错位置的五项

| 附件配置 | 当前代码结果 | 正确核对位置 |
|---|---|---|
| `partition_in_memory_update_interval_secs=1800` | 无此 FE 字段；实际 `partition_info_update_interval_secs` 未配，默认 60 秒 | `PartitionInfoCollector.java:61` |
| `max_user_connections=10000` | 不修改用户连接额度 | 用户属性；`CommonUserProperties.java:42` 默认 100，既有用户可不同 |
| `wait_timeout=28800` | 不设置 SQL 会话变量；默认恰好也是 28800 秒 | `SessionVariable.java:1194`；现有 global/session 可覆盖 |
| `parallel_scan_max_scanners_count=18` | 不设置 scanner 会话变量 | `SessionVariable.java:1470`，显示名可能带 `experimental_` 前缀 |
| `enable_cpu_hard_limit=true` | 当前无此 FE 配置字段 | 不能据此认定 workload group CPU 已受硬限制 |

第一项尤其值得关注：`PartitionInfoCollector.java:75-118` 仍约每分钟一轮遍历库、OLAP 表与分区，
拿表读锁并构造 partition 信息 map；循环时间还要加上实际工作耗时。它并非每轮读取所有数据行，
开销主要取决于表/分区规模。正确名称对应的信息还含 visibleVersion，
不要不评估报告同步所需新鲜度就机械改成 1800 秒。

`qe_max_connection=10240` 则是有效的 MySQL 总连接上限。
因此可能出现 FE 总上限已提高、某用户仍被较低用户额度拒绝的情况；
这与 9020 Thrift 或 8030 HTTP 线程数是不同资源。

## 7. JVM、checkpoint、监控与日志

附件有效 JVM 段是 `-XX:+UseZGC -Xms125g -Xmx300g -XX:+AlwaysPreTouch`。
125g 是初始/最小堆，300g 是最大堆；没有证据表明此比例本身会造成周级故障。
JDK 8 段的 **G1、Xss4m、32G 上限均不应计入 JDK 17 运行值**。
`AlwaysPreTouch` 不等于现在就锁定整个 300GiB 堆的物理内存，也不代表以后没有内存伸缩。
JDK 17 ZGC 默认允许回收未使用的已提交内存；固定 Xms=Xmx 可以作为确认伸缩延迟后的对照，
前提是实际物理内存和 native/OS 预算足够。[JDK 17 GC 指南第 9 章](https://docs.oracle.com/en/java/javase/17/gctuning/hotspot-virtual-machine-garbage-collection-tuning-guide.pdf)

当前 `GcNames/JvmStats` 不把 ZHeap 识别成老年代；`Checkpoint.java:388-391` 退回 heap used/max。
默认 `metadata_checkpoint_memory_threshold=70`，`floor(used×100/max)<=70` 仍允许。
300GiB 最大堆下约 **used≥213GiB** 才因该默认检查拒绝，不是超过 210GiB 立即拒绝，
也不是按 Xms125GiB 的 70% 计算。持续高存活量可能使 image 长期不推进、journal 回收受阻。
应核对 image 成功时间、journal 差距、GC 后 used；不建议直接抬阈值或强制 checkpoint，
后者同 JVM 的额外元数据对象仍需要空间。

ZGC 不输出 old/young pool 指标的兼容问题会让按 G1 指标构建的面板缺数据，
通常从启动就存在；**不能用它解释所有指标在运行一两周后才间歇断线**。
实际 scrape 卡住还应查 `MetricRepo.java:1312` 的串行采集锁、事务锁、journal 和 HTTP worker。

`sys_log_mode=ASYNC` 是有效配置且是源码默认，但异步日志也可能在缓冲满时阻塞生产线程。
当前 `Log4jConfig.java:255-266` 保留类/方法/行号；`BRIEF` 才不记录这些位置信息。
本地依赖 Log4j2 2.25.3/Disruptor 3.4.4 的字节码核对确认普通业务线程在默认满环策略下可等待空间。
更具体的放大链是 `DatabaseTransactionMgr.java:184` **在真正 unlock 前写慢锁日志**，
第 2631-2642 行执行 `LOG.info`。若日志消费者受慢盘或轮转拖住，事务写锁可能被进一步延长，
连带阻塞入库和读事务指标。确认需看日志环等待栈、日志消费者栈与磁盘延迟；
ASYNC 本身不是故障证据。只有源位置采集开销显著时才优先考虑 BRIEF，慢盘仍应处理 I/O 与日志量。

`HeapDumpPath=$LOG_DIR` 使 OOM dump 与 FE 日志放同一目录。大堆 dump 可能产生很大的文件，
加重磁盘压力；文件大小不等于固定 300GiB。GC 日志每组 10×50MB 的轮转也不保证覆盖两周，
重启时新时间戳会另建组。路径文字不同不能证明 `meta_dir` 与 LOG_DIR 位于不同物理盘，
需要检查挂载和设备。OOM dump 属于 OOM 后的次生问题，不能当作没有 OOM 时的原因。

**SSD 信息对排查的修正：** 下调“元数据盘基础随机 I/O 能力不足”的优先级，
保留故障时的实际写入延迟、容量和复制等待检查。表/分区/replica 目录及事务对象主要在 Java 堆中，
report、统计扫描和业务锁等待不会因为持久化目录在 SSD 就消失。
附件未覆盖 BDB durability，当前默认 `master_sync_policy=SYNC`、`replica_sync_policy=SYNC`、
`replica_ack_policy=SIMPLE_MAJORITY`（`Config.java:294-305`，`BDBEnvironment.java:167-169`）。
有多个投票 FE 时，journal 完成还依赖满足确认策略的复制成员与链路；并非所有 FE 都须确认，
也不是本地 SSD 完成写入就必定完成整次提交。当前没有现场证据证明 SSD 已发生瓶颈。
若本地 I/O 延迟稳定且复制确认正常，应优先沿 journal/事务锁、线程占用和 checkpoint 进展继续定位。

启动脚本另有 `ALL-UNNAME` 拼写错误（`start_fe.sh:336`），本地 JDK 17 已复现模块警告。
这应修复为 `ALL-UNNAMED`，但目前没有证据把它与周级性能退化联系起来。

## 8. 有条件导致导入异常，但不够解释全部症状的其他项

- `dynamic_partition_check_interval_seconds=28800` 是 **8 小时**（默认 10 分钟）。
  确实会降低动态分区巡检频率；小时分区或预建窗口不足时，可能缺目标分区、延迟删除过期分区，
  延后 tablet 回收。也可能把多次分区变更集中到一轮。仅影响动态分区相关表，
  不等于全局自动分区都按该周期执行。建议先在测试中恢复 600 秒或按预建窗口设计周期。
- `storage_min_left_capacity_bytes=400GiB`、高水位 80%，比源码默认 2GiB/85% 更保守。
  普通选盘高水位检查是“剩余<400GiB **或** 已用>80%”。小盘可能很早不能接收新 tablet。
  flood 值为 100GiB/90%；`DiskInfo.exceedLimit(true)` 是“剩余<100GiB **且** 已用>90%”，
  而 `RootPathLoadStatistic.isFit` 的 clone 目的盘检查按 **或** 拒绝；不能统一成一种语义。
  `OlapTableSink.java:824` 导入计划也检查 flood 容量。保留阈值可能完全合理，须看每条路径容量；
  不应为了过检查而盲降。真实磁盘容量不足一般不会被重启 FE 持续治好。
- `max_backend_heartbeat_failure_tolerance_count=10`（默认 1）延缓判死，减少瞬时误判，
  也可能更久把故障 BE 当作存活。具体延迟还取决于心跳周期、超时和调度；不是固定 10 秒。
- `autobucket_min_buckets=10`、`autobucket_max_buckets=256`（默认 1/128）在使用自动分桶的建表/
  分区路径上可能产生更多 tablet；对许多小分区尤其应核查。不会自动把全部既有 tablet 翻倍，
  也不能只凭这个文件推算 200 万 tablet 的来源。
- `auto_check_statistics_in_minutes=10`（默认 1）降低自动统计检查频率；
  `workload_max_policy_num=50`（默认 25）仅扩大策略数量上限。均不是已发现的主要嫌疑。
- `enable_round_robin_create_tablet=true`、`enable_single_replica_load=false` 与当前默认相同。
  外表计算节点偏好及最少 3 节点只与相关外表场景有关；不是普通内部表 Stream Load 的修复旋钮。
  `enable_outfile_to_local=true` 影响 OUTFILE，端口、网络选择与 meta 路径需现场匹配，
  当前没有证据把这些值直接联系到运行两周后的积压。

## 9. 下一步：不用导出原始日志即可核对的事实

在健康时和故障时各记一次摘要；同一 FE 比较，并区分 Master/Follower。
`SHOW PROC '/dbs'` 还会统计库大小和副本，优先在健康期低频执行；
故障期可跳过 `/dbs`；管理接口本身也可能等待锁，SQL 应限时，不要高频重试查询或采集线程栈。
以下是现场只读核对示例，不会由本次审计自动对生产执行：

```sql
ADMIN SHOW FRONTEND CONFIG LIKE 'thrift%';
ADMIN SHOW FRONTEND CONFIG LIKE '%report%';
ADMIN SHOW FRONTEND CONFIG LIKE '%txn%';
ADMIN SHOW FRONTEND CONFIG LIKE '%partition%';
SHOW PROC '/dbs'; -- 仅健康期低频执行；故障期可跳过此全库扫描。
SHOW VARIABLES LIKE 'wait_timeout';
SHOW VARIABLES LIKE '%parallel_scan_max_scanners_count%';
-- 另对实际导入用户执行 SHOW PROPERTY，核对 max_user_connections。
```

只需记录：实际 InitialHeapSize/MaxHeapSize、线程总数与其中 Thrift 数、FD/9020 连接、
GC 后 heap used、image 最近成功时间与 journal 差距、各库 quota/在途数/最老事务状态、
修复与均衡活动、meta/log 盘剩余与 I/O 延迟。可用已有
[离线采集器](/data/project/massdb-sql/tools/fe-stall-collect.sh) 的有限采样，原始证据留在现场。
本轮没有运行生产命令、改配置、重启服务或做全规模压测。

单机复现基线应改用本附件的 125/300g、100000 上限及事务/调度配置；若现场另有覆盖则以覆盖为准。
资源不足时可以按比例/阈值缩小，但结果只能称机制验证。先分别测试连接增长、慢发布/重试、
clone 与导入竞争、日志慢盘、ZGC/checkpoint，再做长期组合负载，避免把多项同时修改后的好转当作根因证据。
