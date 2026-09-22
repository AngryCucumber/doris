<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# FE 内存、垃圾回收器兼容性与长期运行审查（2026-09-07）

## 结论（纳入外部审核后的修订版）

**外部审核提供了多条成立的新线索，但不能全部原样采纳。** 本版已逐项核对所列 23 项及两项非内存问题，
并继续检查正常结束、连接复用、多语句、超时、异常、catalog 删除和后台清理边界。
以下结论以当前源码为依据；“静态确认”不等于已经在生产复现。

针对反馈中的 **生产 ZGC、8 GiB 堆、运行约一周后堆满且 GC 周期变慢**，应首先检查 Java 堆里的
结果附加信息、事务积压、连接重置后遗留的预处理语句、统计任务和外部 catalog 引用链。
若使用 Ranger Hive，审计事件不清空也是本轮新增的优先检查项。
这些路径与生产的匹配程度，仍需用实际负载、GC 日志和对象保留量确认，尚不能指定唯一根因。

原版把 Arrow 堆外问题列为唯一 P1，未按本次生产症状安排顺序，这一点已修正。
Arrow 堆外泄漏成立，但它不直接增加 Java 堆存活集；没有使用 Flight 时，该分配路径不解释这次症状。
原版“已核对 Profile 清理”的表述也过宽：执行 profile 的兜底清理依赖完成标记，不能视作严格容量保障。
不过，外部审核所称“普通 Flight 查询因不取结果而必然不注销”忽略了外层 close，见后面的反证。

本报告现在维护 **22 个 MEM 编号**，并单列有界容量风险、Profile 清理缺口及不成立/需收窄的说法。
本轮另确认了原清单未覆盖的 **Ranger 审计保留、连接重置不释放 prepared statement、Flight 多语句注销错误 ID**，
并复现了 **DFS 清理器遇到未捕获异常后停止后续清理** 的扩展问题。

源码基线：`59329855b4e62497d927f3ccd547b866a190a0fc`。本地隔离 JVM：aarch64、OpenJDK 17.0.2。
生产环境信息来自本次反馈，未接入生产核验。原本地 G1、2 GiB 实例的观察仅保留为历史参照。
本轮没有修改数据库实现、运行配置或服务；显式 GC 仅发生在离线探针 JVM 内。

| 编号 | 问题 | 触发条件/范围 | 与本次症状的排查次序 | 证据 |
| --- | --- | --- | --- | --- |
| MEM-007 | 结果附加信息列表随批次累积 | MySQL 长连接、走 BE 返回批次 | P1：优先 | 当前类实测 |
| MEM-008 | Short 事务清理抢占 Long 预算 | 每轮至少 10,000 条可清 Short、同库有 Long | P1：按导入量核对 | 当前类实测 |
| MEM-020 | COM_RESET_CONNECTION 未释放预处理语句 | 使用协议重置复用连接 | P1：按客户端行为核对 | 当前类实测 |
| MEM-015 | analyze 历史淘汰让运行任务表无法清理 | 长统计任务与大量历史记录轮换 | P1：启用对应统计负载时 | 静态调用链 |
| MEM-010 | Gauge 引用已摘除的 catalog/cache | 不同名称 catalog 初始化/drop/rename | P1：外部元数据较大且发生变更时 | 当前类实测 |
| MEM-019 | Ranger Hive 审计列表不清、刷新线程被占住 | 配置 Ranger Hive 鉴权并产生审计事件 | P1：启用该功能时 | 当前类实测 |
| MEM-009 | 转发初始化异常遗漏上下文摘除 | 接收转发的 FE，setup/结果组装异常 | P2：按异常日志核对 | 静态具体异常路径 |
| MEM-011 | 超时中止未清自动分区位置缓存 | 已写入缓存的 FE 多实例导入 | P2 | 静态调用链 |
| MEM-016 | DFS 关闭失败保留资源；未捕获异常停掉清理 | 外部文件系统淘汰、关闭异常 | P2；清理全停需优先处理 | 静态 + 异常注入实测 |
| MEM-021 | Flight 多语句延迟注销读到最后一个 queryId | 前一语句从 BE 返回、后续语句更换 ID | P1：使用此 Flight 组合时 | 静态完整调用链 |
| MEM-001 | Flight 缓冲区与 allocator 未正确关闭 | Flight prepare、token 淘汰等 | P2：堆外问题单独排查 | G1/ZGC 实测 |
| MEM-002 | ZGC core 接口丢堆池指标 | core 指标接口 | P2：监控修复 | 当前类实测 |
| MEM-003 | 待注册表持有已关闭线程池 | 不同名称 HMS/Iceberg catalog 轮换 | P2 | 当前类实测 |
| MEM-004 | 驱动类加载器无界缓存 | 不同 JDBC driver URL 轮换 | P2 | 当前类实测 |
| MEM-005 | Group Commit 历史表统计不清 | 使用该功能且持续更换表 ID | P2 | 静态调用链 |
| MEM-012 | 已删除 catalog 的外部元数据 ID 树不清 | 有 ID 映射后 drop catalog | P2 | 静态调用链 |
| MEM-017 | BE 退役后 RPC client 缓存不主动摘除 | 历史不同 BE 地址持续增加 | P2 | 静态调用链 |
| MEM-006 | removeLastDBOfCatalog 实际执行 get | 长连接、历史 catalog 名称增加 | P3 | 当前类实测 |
| MEM-013 | 动态分区运行信息不随 drop 清理 | 历史动态分区表 ID 增加 | P3 | 静态调用链 |
| MEM-014 | MTMV 关系表留下空值集合的键 | 历史不同基础表/视图关系增加 | P3 | 静态调用链 |
| MEM-018 | 用户计数表零计数条目不摘除 | 历史用户名增加 | P3 | 静态调用链 |
| MEM-022 | AgentTaskQueue 留下空桶及峰值容量 | 任务高峰后、历史 BE ID 轮换 | P3 | 静态调用链 |

P1/P2/P3 表示在对应触发条件下的处理次序，不表示所有部署都受到同等影响。
固定活跃对象数量、相同操作反复执行后仍留下历史对象，才比单纯 RSS 增加更能说明生命周期问题。
数值与增长速度不能由源码直接外推为生产“一周必满”。

## 对外部审核 23 项的逐项判断

| 原编号 | 判断 | 修订后的结论/对应内容 |
| --- | --- | --- |
| A1 / 1 | 成立 | MEM-007；即使 attachedInfos 为 null，也会占一个列表槽；不等于每批都保留完整结果 |
| A2 / 2 | 成立 | MEM-008；饥饿以持续占满预算为条件，Short 压力下降后可以补清 |
| A3 / 3 | 容量风险成立 | CAP-001；默认检查实际允许 100,001 项；另有 MEM-020 重置语义缺陷，不能泛称无界 |
| A4 / 4 | 成立但需收窄 | MEM-009；普通 SQL 异常在 proxyExecute 内被捕获，明确漏的是外围初始化/组装异常 |
| A5 / 5 | 所述普通路径不成立 | 外层 try-with-resources 会 finalize；另发现真正的多语句错误 ID 问题 MEM-021 |
| A6 / 6 | 成立 | MEM-010；同名标签替换有别于不同名累计，未实测“每 catalog 几百 MB” |
| A7 / 7 | 成立但需限定 | MEM-011；仅已写入缓存的导入受影响，当前代码主动跳过 BE 发起/单实例导入 |
| B8 / 8 | 部分成立 | MEM-012；catalog 顶层没有删除，但库/表/分区 DELETE 映射已有删除路径 |
| B9 / 9 | 成立 | MEM-013；SHOW 的删除分支也不能可靠清理已经不存在的表 |
| B10 / 10 | 部分成立 | MEM-014；空键遗留，固定同一关系重复刷新不会每次增加键 |
| B11 / 11 | 成立 | MEM-015；历史 jobInfo 淘汰后，完成回调在删运行任务表之前早退 |
| B12 / 12 | 成立 | MEM-016；另补未捕获 RuntimeException 终止整个周期清理的边界 |
| B13 / 13 | 部分成立 | 失败任务不能一概判泄漏，ALTER/一致性检查有作业级清理；空桶保留见 MEM-022 |
| B14 / 14 | 成立但依赖历史键增长 | MEM-017、018；固定 BE/用户名下不按查询次数增长 |
| B15 / 15 | 所述普通异常路径不成立 | replacePartition 抛 Exception 后，调用方会 taskGroupFail；二次清理异常需另证 |
| C16 / 16 | 成立，数值需校正 | CAP-002；三个缓存各 50 万条，源码 912 MiB 示例针对 10 万条且含 128-bucket histogram |
| C17 / 17 | 部分成立 | CAP-003；有 TTL 和条数上限，软引用不承诺“只在堆满才清”；10 万是统计条目而非 PhysicalPlan 个数 |
| C18 / 18 | 部分成立 | CAP-004；2 MiB/连接成立，packetBuf 是最近包而非历史最大；16 MiB 是物理包而非逻辑请求总上限 |
| C19 / 19 | 成立，需限定队列语义 | CAP-005；只限条数且主队列 check/add 非原子；两个队列有共享引用，不能简单相加字节 |
| C20 / 20 | 容量风险成立 | CAP-006；Short 实际默认 12 小时，2000 是清理软阈值；alter 会 prune 部分结构 |
| C21 / 21 | 机制成立 | CAP-007；finalize 会延迟回收，是否形成积压需要 Finalizer 队列/对象证据 |
| C22 / 22 | 部分成立 | CAP-008；JDK 17 ZGC 不用压缩对象指针，但固定 20%–30% 与“周期时间直接等于存活集”不成立 |
| C23 / 23 | 成立 | CAP-009；把合法表/分区/tablet 增长作为独立基线 |

关于 Profile：兜底清理的确有完成标记条件，但“凡未 unregister 都永不删除，BE 每报一次就无界追加”过强。
历史 Profile 淘汰还会删除关联 ExecutionProfile，重复同名 pipeline 报告也会替换。
下面单列这个防护缺口及可以落到具体路径的 MEM-021，避免用假定的异常来证明泄漏。

## MEM-001：Arrow Flight 创建预处理语句时泄漏临时向量

**位置与调用链**：

- [fe/fe-core/src/main/java/org/apache/doris/service/arrowflight/DorisFlightSqlProducer.java:343–383](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/service/arrowflight/DorisFlightSqlProducer.java:343)：
  `createPreparedStatement` 在第 365–366 行执行 `createOneOneSchemaRoot(...).getSchema()`，随后丢弃 root，未关闭。
- [fe/fe-core/src/main/java/org/apache/doris/service/arrowflight/results/FlightSqlChannel.java:128–138](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/service/arrowflight/results/FlightSqlChannel.java:128)：
  创建 `VarCharVector`、`allocateNew()`、写入值，再返回 `VectorSchemaRoot`。
- 同文件第 48–52 行：channel 使用独立的 `RootAllocator(Long.MAX_VALUE)`；
  第 159–164 行：`close()` 只清空结果缓存，没有处理这次未进入缓存的临时 root。

**原因**：这里仅需要 schema，却分配了实际数据缓冲区。普通结果会进入有删除回调的缓存，
但这个临时 root 没有进入缓存，缓存的过期/清空机制无法关闭它。
即使客户端随后关闭 prepared statement，也没有对这份临时向量的引用可用于释放。

**离线复现**：重新编译当前 `FlightSqlChannel.java`，其余依赖使用本地 FE 包。
在独立的 256 MiB JVM 中只保存返回的 schema，循环调用生产分配方法；没有保存历史 root。
对照组使用 try-with-resources 关闭每个 root。

| 观测点 | G1 分配器占用（字节） | ZGC 分配器占用（字节） |
| --- | ---: | ---: |
| 初始 | 0 | 0 |
| 未关闭 1 个 root | 49,152 | 49,152 |
| 未关闭 100 个 root | 4,915,200 | 4,915,200 |
| 未关闭 1,000 个 root | 49,152,000 | 49,152,000 |
| 隔离 JVM 执行 System.gc 后 | 49,152,000 | 49,152,000 |
| 随后调用 channel.close | 49,152,000 | 49,152,000 |
| 对照：创建并关闭 1,000 个 root | 0 | 0 |

这里测的是 `BufferAllocator.getAllocatedMemory()`，不是生产 RSS 增长速率。
每次 48 KiB 是当前依赖与默认分配大小下的结果，不能推广为所有版本的固定值。
首轮覆盖实际分配子路径，channel/allocator 仍可达。本轮补充了不可达后的验证：
当前包使用 Arrow 17.0.0 的 arrow-memory-netty 与 Netty 4.1.130.Final；
创建 10 个 channel、共 1,000 个未关闭 root 后丢弃全部强引用，G1/ZGC 各执行 5 次隔离 GC。
channel 与 channel allocator 的弱引用存活数均为 0，但 Netty arena 的 active allocations 仍新增 2,000 个；
清空线程本地缓存后仍如此。对照组再创建并关闭 1,000 个 root，active allocations 净增为 0。
这是未归还的活动分配，不是把池内已经释放、留待复用的 chunk 容量当成泄漏；仍未测生产 RSS 斜率。

**补充两个生命周期缺口**：channel 的 `RootAllocator` 从无 close 调用；
[FlightTokenManagerImpl.java:74–84](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/service/arrowflight/tokens/FlightTokenManagerImpl.java:74) 的 token 删除监听只调用 `FlightSqlConnectPoolMgr.unregisterConnection()`，
后者第 57–64 行只退出事务并移除连接索引，不调用 `closeChannel()` 或结果缓存清理。
即使是进入 resultCache 的普通结果，也不能把“token 已淘汰、Java 对象不可达”等同于显式关闭缓冲区。
当前 NettyAllocationManager 的释放路径是 reference-count release，不能依赖 Java Cleaner 替本应用补上遗漏的 close。
上述 allocator 不可达验证支持这一结论；未运行真实 token 超时的协议级测试。

此项应以 Flight 使用情况和堆外趋势排优先级，不能直接解释 Java 堆 live set 增长或 ZGC 标记变慢。

**修复方向**：直接构造所需 `Schema`，避免分配数据向量；若需要 root，则明确以
try-with-resources 管理。补全 channel 的 allocator 生命周期，确保所有结果与临时 root
先释放再关闭 allocator，不能只在末尾关闭一个仍有未释放分配的 allocator。

**验收**：在同一长会话中重复 prepare/close，另测断连、异常返回与结果过期；
在 G1/ZGC 下确认分配器占用回到基线。再以固定并发运行协议压力测试，观察堆外占用是否形成平台。

## MEM-002：切换 ZGC 后，core 接口丢失堆使用率指标

**位置**：

- [fe/fe-core/src/main/java/org/apache/doris/monitor/jvm/GcNames.java:34–48](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/monitor/jvm/GcNames.java:34)：
  只映射传统 young/survivor/old 池名。
- [fe/fe-core/src/main/java/org/apache/doris/monitor/jvm/JvmStats.java:85–99](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/monitor/jvm/JvmStats.java:85)：未知池名被忽略。
- [fe/fe-core/src/main/java/org/apache/doris/metric/SimpleCoreMetricVisitor.java:79–95](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/metric/SimpleCoreMetricVisitor.java:79)：
  只输出映射后 young/old 使用率，没有总堆回退。
- [fe/fe-core/src/main/java/org/apache/doris/httpv2/rest/MetricsAction.java:51–53](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/rest/MetricsAction.java:51)：
  `/metrics?type=core` 使用该 visitor。

**当前类验证**：重新编译上述三个 JVM/metric 类，以实际 MXBean 数据运行。

| GC | 本机 JDK 能否启动 | 实际堆池 | core visitor 的堆指标 |
| --- | --- | --- | --- |
| G1 | 能 | G1 Eden Space、G1 Survivor Space、G1 Old Gen | 有 young/old |
| Parallel | 能 | PS Eden Space、PS Survivor Space、PS Old Gen | 有 young/old |
| ZGC | 能 | ZHeap | 全部缺失；此次 visitJvm 仅输出 jvm_thread |
| Shenandoah | 不能：本机二进制未提供 | 未实测 | 未完成运行验证 |

普通 Prometheus/JSON 指标仍有总堆数据。[PrometheusMetricVisitor.java:121–127](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/metric/PrometheusMetricVisitor.java:121) 的 `jvm_gc`
直接使用收集器原始名；ZGC Cycles 与 ZGC Pauses 的 Count/Time 均仍输出，不能说整个 FE 失去 GC 监控。
但只依赖 core 接口的看板或告警会缺失输入；这不代表真实堆占用为零。

OpenJDK 17 的 Shenandoah 池名为 `Shenandoah`，同样不在当前映射中。
这是源码推导，未在本机完成运行验证。
依据：[OpenJDK 17 ShenandoahMemoryPool](https://raw.githubusercontent.com/openjdk/jdk17u/master/src/hotspot/share/gc/shenandoah/shenandoahMemoryPool.cpp)。

**修复方向与验收**：增加与代际划分无关的总堆使用率指标，保留可识别的池级信息；
不要直接把 ZHeap 当作 old generation。分别核对各 GC 的 core、Prometheus、JSON 输出与告警缺失值行为。

## MEM-003：关闭 catalog 线程池后，静态注册表仍保留引用

**位置**：

- [fe/fe-core/src/main/java/org/apache/doris/common/ThreadPoolManager.java:76–86](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/ThreadPoolManager.java:76)：
  静态 `nameToThreadPoolMap` 保存待注册指标的线程池；`registerAllThreadPoolMetric()` 才会清空。
- 同文件第 202、221、235、265 行：`needRegisterMetric=true` 时写入 map；
  第 440–458 行：`shutdownExecutorService()` 等待或终止线程池，但没有删除 map 引用。
- [fe/fe-core/src/main/java/org/apache/doris/datasource/hive/HMSExternalCatalog.java:142–151](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/hive/HMSExternalCatalog.java:142)、
  [fe/fe-core/src/main/java/org/apache/doris/datasource/iceberg/IcebergExternalCatalog.java:136–141](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/iceberg/IcebergExternalCatalog.java:136)：
  初始化不同名称的 catalog 时创建对应名称的池，并要求注册指标。

**触发条件**：FE 完成启动/切主注册以后，持续初始化和删除不同名 catalog。
drop 虽然执行关闭，待注册表仍保留历史池；稳定运行期间该表没有周期性清理。
相同池名会覆盖旧项，因而不能按“每次刷新必增加一个池”估算。

**实测**：编译当前 `ThreadPoolManager.java`，创建 100 个不同名、需要注册指标的池，
不提交任务，调用实际 shutdown 方法。结果：`registryDelta=100`、
`retainedTerminated=100`、`completedTasks=0`。
这证明保留的是已终止的 executor 对象，**不是实测出 100 条线程仍在运行**。
preAuth 池的 ThreadFactory 还会引用认证对象（第 270–281 行），实际保留体积需按对象图测量。

**修复方向**：将动态池的指标注册/注销与池生命周期绑定；关闭时使用身份匹配删除，避免误删同名新池。
同时审查已注册 Gauge 是否仍持有旧池。以真实 HMS/Iceberg 初始化/drop 循环验收，
确认待注册表、指标数量和对象保留量回到基线。本次没有连接外部 metastore。

## MEM-004：JDBC 类加载器缓存无界保留历史驱动 URL

**位置**：

- [fe/fe-core/src/main/java/org/apache/doris/datasource/jdbc/client/JdbcClient.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/jdbc/client/JdbcClient.java) 的静态 `classLoaderMap`；
  第 172–180 行按 driver URL 创建并缓存 `URLClassLoader`。
- 第 150–164 行仅在部分驱动加载失败时移除；第 196–199 行的正常 `closeClient()` 只关闭数据源。
- [fe/fe-core/src/main/java/org/apache/doris/datasource/jdbc/JdbcExternalCatalog.java:146–151](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/jdbc/JdbcExternalCatalog.java:146)：
  catalog 关闭调用 `closeClient()`，但不释放这份共享缓存的历史引用。

**触发条件**：不同版本或不同地址的驱动 JAR 持续进入 FE。
缓存复用同一 URL 是合理的；问题是没有上限、引用计数或在最后一个使用者退出后的回收机制。
同一 URL 下反复建删 catalog 不等于每次都会新增 loader。

**实测**：重新编译当前 `JdbcClient.java`，用 32 个本地生成的不同 JAR URL 调用真实
`initializeClassLoader()`，加载测试类，再调用真实 `closeClient()`。
结果：32 次关闭后 `cachedLoadersDelta=32`、`retainedLoadedClassLoaders=32`。
测试用 Unsafe 跳过会建立数据库环境的构造步骤，通过反射调用初始化方法，Hikari 数据源未启动；
没有数据库连接和网络访问。因此确认的是强引用保留，未测真实驱动的 Metaspace 字节数或连接泄漏。

**影响与修复方向**：缓存会阻止这些 loader 及其已加载类进入正常卸载条件，
同时保留相关 Java 对象。应建立共享 loader 的引用计数与安全释放机制，
最后一个使用者退出后再移除、关闭；不能在任意一个 catalog 关闭时破坏其他 catalog 的共享驱动。
验收应同时覆盖多 catalog 共用驱动、驱动版本轮换和失败重试。

## MEM-005：Group Commit 的历史表统计对象没有清理入口

**位置**：

- [fe/fe-core/src/main/java/org/apache/doris/load/GroupCommitManager.java:64–67](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/load/GroupCommitManager.java:64)：
  `tableToBeMap` 与 `tableToPressureMap` 随 manager 长期存在。
- 第 393–395 行为选中 BE 的表写入路由与 `SlidingWindowCounter`；
  第 432–433 行更新统计。`tableToPressureMap` 没有 remove/clear/expire 路径。
- [fe/fe-core/src/main/java/org/apache/doris/common/util/SlidingWindowCounter.java:25–32](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/util/SlidingWindowCounter.java:25)：
  每个 counter 创建两个 `AtomicLongArray`，长度为 `group_commit_interval_ms / 1000 + 1`。

**触发条件与影响**：长期创建表、经 Group Commit 选择 BE/导入、再删除表。
删除后的表不会再访问该路由，但旧表 ID 和统计对象仍被 manager 引用。
路由表虽有按访问失效的 remove 分支（第 364、367 行），没有覆盖已删除且不再访问的表；
统计窗口“数值过期”也不会删除 counter 本身。
保留量随历史表 ID 数增长，而不是只随当前活跃表数量增长。

**证据边界**：已检查写入、读取、删除表相关生命周期及全仓引用，没有实际执行建表/drop 的长时间压力测试。
因此不提供每小时内存增长或达到 OOM 所需时间的估计。

**修复方向与验收**：在最终清理表/库时删除统计与所有 cluster 对应路由，
另为长期未使用的统计设置受控淘汰。处理回收站恢复和并发导入，避免删除后重新插入旧记录。
以固定活跃表数量、持续更换表 ID 的负载核对两个 map 的大小。

## MEM-006：会话 catalog 历史记录的 remove 方法没有删除

**位置**：

- [fe/fe-core/src/main/java/org/apache/doris/qe/ConnectContext.java:348–362](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/ConnectContext.java:348)：
  `removeLastDBOfCatalog()` 在第 357 行调用 `lastDBOfCatalog.get(catalog)`，应删除的项仍在 map 中。
- [fe/fe-core/src/main/java/org/apache/doris/catalog/Env.java:6295–6305](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/catalog/Env.java:6295)：切换 catalog 时记录旧 catalog 与数据库名。
- [fe/fe-core/src/main/java/org/apache/doris/datasource/CatalogMgr.java:273–274](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/CatalogMgr.java:273)：drop 依赖该方法清理当前会话。
- 同文件第 302–307 行：rename 先调用该方法，再加入新名称，导致旧名称累计。

**触发条件**：同一长连接使用 catalog 内的数据库，并切换到其他 catalog，使历史 map 已记录该名称后，
反复将其重命名为不同名称，或反复创建、留下上述历史记录、删除不同 catalog。
保留的是历史名称和数据库名，单项较小；不能据此推断一个连接会迅速耗尽数 GB 内存。
当前会话的 reset 有 clear 路径；会话正常释放且不再被引用后，这份 map 可以回收。

**验证与修复方向**：通过当前 `ConnectContext` 方法复现 add/remove 后旧项仍可读取，
并核对上述 DDL 调用链。重新编译当前完整生产类后，100 次 add/remove 保留 100 项，
1,000 次保留 1,000 项；已删除名称仍返回 `db_0`，显式 clear 后回到 0。
探针启用 `FeConstants.runningUnitTest`，没有建立连接或执行 catalog DDL。
修复为真正的 remove；覆盖 rename、drop、reset 的会话状态测试。
其他会话的失效通知需要单独设计，不能把修复当前 remove 方法等同于解决所有会话的一致性。

## MEM-007：长连接的结果附加信息列表按返回批次增长

**引用链与触发**：[ConnectContext.java:239](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/ConnectContext.java:239) 的 `resultAttachedInfo` 是会话级 ArrayList。
[StmtExecutor.java:1331–1354](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:1331) 处理每个非空结果批次时调用 `addResultAttachedInfo()`；
[ConnectContext.java:1207–1212](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/ConnectContext.java:1207) 不检查 null，直接 add。
同类第 848–851 行的 `clear()` 只释放 executor/statementContext，全仓未找到该列表的清空路径。
因此，同一物理 MySQL 连接反复查询，即使每批附加信息都是 null，也会不断增加数组槽位；
非空时还会保留 map 和其中的字符串。连接最终释放后可以回收，连接池长期复用则会长期保留。

**实测**：重新编译当前完整 ConnectContext，在隔离 ZGC JVM 中执行 100,000 次
`addResultAttachedInfo(null)`，每次随后调用真实 `clear()`，最终列表仍为 100,000 项。
再调用真实 COM_RESET_CONNECTION 处理函数，仍为 100,000 项。
这不是 100,000 份完整查询结果；只有 null 时保留的是引用数组容量，不能高估单项大小。

**修复与验收**：让附加信息归属于一次执行，按实际消费者需求保存；
[ExportTaskExecutor.java:163](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/load/ExportTaskExecutor.java:163) 需要在结果消费完成前读到信息，不能简单在返回前全部删掉。
覆盖普通查询、空附加信息、Export、多语句、失败及连接 reset；固定连接数增加批次数，
确认列表和保留容量不再按历史批次数增长。本轮未运行真实 JDBC 连接池压力测试。

## MEM-008：事务清理的 Short 队列可以持续饿死 Long 队列

**位置**：[DatabaseTransactionMgr.java:117](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/transaction/DatabaseTransactionMgr.java:117) 每轮每库最多删除 10,000 条；
第 1960–1980 行先清 Short，再将剩余额度给 Long。
第 1983–2010 行的过期清理和 `label_num_threshold` 清理都受剩余额度约束；
Short 用光预算时，两种 Long 清理都不执行。
[Env.java:2846–2850](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/catalog/Env.java:2846) 的清理线程使用默认 30 秒间隔；
[GlobalTransactionMgr.java:589–594](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/transaction/GlobalTransactionMgr.java:589) 在同一轮串行遍历数据库。

**触发与体积**：同一库持续产生足够多可清理的 Short 事务，同时有 Long 事务结束。
Short 分类包括 BACKEND_STREAMING、INSERT_STREAMING 和 ROUTINE_LOAD_TASK，见
[TransactionState.java:666–681](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/transaction/TransactionState.java:666)。剩余 TransactionState 及标签索引仍在 manager 中。
[TransactionState.java:791–795](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/transaction/TransactionState.java:791) 的 `pruneAfterVisible()` 只清 publish task、tablet delta、backend 集合，
不是清空全部表提交信息和 schema；ABORTED 不走该 prune。
仅说“label 阈值 2000，所以事务最多 2000”不成立。

**实测**：用当前 DatabaseTransactionMgr，向两条队列注入已过期状态，替换 edit-log 输出为无操作 sink。
连续三轮各加入 10,000 个 Short、100 个 Long：Short 每轮剩 0，Long 依次剩 100、200、300。
停止 Short 积压再清一次，Long 回到 0。这确认预算饥饿及恢复条件，未模拟真实导入、日志落盘或 30 秒调度。

**修复与验收**：为两队列保证最小额度或轮流起始，保留总耗时和锁占用上限；
监控各队列长度、最老过期时间和实际清理速率。测试持续高频导入与 Long 混合、负载下降后补清、
多库公平性及 edit-log/replay 一致性。这是可持续积压问题，不能称为负载降低后也永不回收。

## MEM-009：转发处理的外围异常留下 proxy ConnectContext

**位置与明确异常路径**：[FrontendServiceImpl.java:1116–1145](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/service/FrontendServiceImpl.java:1116) 创建上下文，
第 1134 行写入 `proxyQueryIdToConnCtx`，第 1137 行调用 `proxyExecute()`，
第 1143–1144 行清 ThreadLocal、删 map，但没有 finally。
[ConnectProcessor.java:630–668](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/ConnectProcessor.java:630) 在执行 try 之外还原 session/user variables；
第 780–790 行的用户变量还原会将 AnalysisException 转为 TException。
例如 [LiteralExpr.java:351–365](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/analysis/LiteralExpr.java:351) 收到不支持的 thrift literal 类型时会抛 AnalysisException。
此时服务已经 put，但无法走到 remove。

**范围纠正**：正常 SQL 执行抛出的异常由 [ConnectProcessor.java:669–729](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/ConnectProcessor.java:669) 内部 catch 转成错误响应，
不能一概当作泄漏；具体缺口在外围初始化或后续结果组装异常。
强引用根是服务实例的 proxy map，保留整个连接图；只有已积累结果的上下文才带对应结果缓冲，
初始化失败不一定已经有大结果。通常发生在接收转发的 master FE。

**修复与验收**：把注册后的 map 摘除和线程上下文恢复放进覆盖完整处理过程的 finally，
按 ID 与对象身份匹配删除。分别注入 setup、执行、结果组装异常，确认 map 回落，
并验证转发取消仍能找到正在执行的上下文。本轮为具体静态异常链，未发送畸形 RPC。

## MEM-010：全局 Gauge 钉住已移除的外部 catalog 与缓存

**引用链**：[ExternalSchemaCache.java:43–75](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/ExternalSchemaCache.java:43) 注册的匿名 Gauge 读取实例缓存，因此捕获外层 this，
外层又保存 catalog。[HiveMetaStoreCache.java:204–237](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/hive/HiveMetaStoreCache.java:204) 的三个缓存指标使用相同模式。
[DorisMetricRegistry.java:40–47](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/metric/DorisMetricRegistry.java:40)、第 121–124 行把 Metric 按名称和标签保存在全局注册表中。
[CatalogScopedCacheMgr.java:40–41](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/CatalogScopedCacheMgr.java:40) 的 remove 只删除 owner map；
[CatalogMgr.java:124–134](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/CatalogMgr.java:124) 的 catalog 删除和 [ExternalMetaCacheMgr.java:213–229](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/ExternalMetaCacheMgr.java:213) 的缓存摘除
没有同步注销这些指标，因而移除 owner 后仍存在 `registry → Gauge → cache → catalog`。

**触发条件**：不同名称 catalog 初始化并 drop/rename，或旧对象对应标签不再被新实例覆盖。
完全相同的指标名和标签会替换，不应按同名创建次数直接累计。
缓存条目自身可能过期，但 registry 持有 owner 并不因此自动解除；实际保留多少元数据需要对象图确认。

**实测**：编译当前 ExternalSchemaCache、CatalogScopedCacheMgr、DorisMetricRegistry。
创建 32 个不同名的空 HMS catalog/schema cache，调用 manager 的真实 remove，丢弃局部强引用并进行隔离 GC。
指标增量仍为 32，弱引用观察到 32 个 catalog 均存活。
未连接 metastore、未加载大表 schema，所以这里只证明强引用，不宣称每项已有数百 MB。

**修复与验收**：注册时保存可注销的 metric 句柄，关闭时按 owner 身份移除标签项，防止误删同名新实例。
覆盖 drop、rename、refresh 重建、初始化失败、并发指标采集及同名重建，检查旧 owner 能否回收。

## MEM-011：库级超时中止绕过自动分区缓存清理

**位置**：[AutoPartitionCacheManager.java:70–118](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/transaction/AutoPartitionCacheManager.java:70) 以 txn ID 保存分区/tablet 位置列表；
[GlobalTransactionMgr.java:403–406](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/transaction/GlobalTransactionMgr.java:403) 的常规 abort 在 finally 调用 `clearAutoPartitionInfo()`。
但 [DatabaseTransactionMgr.java:2483–2493](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/transaction/DatabaseTransactionMgr.java:2483) 的超时处理直接调用库级 abort，绕过上述包装。
已缓存的位置因而可在事务结束后继续保留，直至另一个显式清理路径命中或 FE 重启。

**必须限定的功能范围**：[FrontendServiceImpl.java:3746–3777](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/service/FrontendServiceImpl.java:3746) 明确要求 request 有 query ID、
能找到 coordinator 且执行 instance 数大于 1 才启用这一缓存；第 3957–3960 行才真正写入。
当前实现主动跳过 BE 发起和单实例导入。不能说“所有超时 stream load 都泄漏”。
本项确认的是走这条缓存路径的 FE 多实例自动分区导入，以及传统事务管理器的超时中止链。

**修复与验收**：将事务结束后的缓存生命周期统一收口，覆盖 visible、abort、timeout 和异常重试；
并另核对云模式由 MetaService 超时终止时 FE 如何收到清理通知。
测试已缓存后超时、创建分区中途失败、取消、多个实例同时请求相同分区，
确认终态事务 ID 从缓存消失且进行中的其他事务不受影响。本轮未做导入集成复现。

## MEM-012：drop catalog 未删除外部元数据 ID 树

[ExternalMetaIdMgr.java:47](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/ExternalMetaIdMgr.java:47) 的 `idToCtlMgr` 是长期存活的顶层 map，
第 110–115 行按 catalog ID 新建子树；全仓没有删除顶层 catalog 项的调用。
[CatalogMgr.java:124–134](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/CatalogMgr.java:124) 的 drop 生命周期也没有清理它。
使用过外部 ID 映射的 catalog 被删除后，其剩余库、表、分区 ID 映射仍可保留。

**收窄原结论**：[ExternalMetaIdMgr.java:145–168](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/ExternalMetaIdMgr.java:145) 已实现 DATABASE、TABLE、PARTITION 的 DELETE 分支，
不能说“所有分区 ID 都从不删除”。问题是 catalog 生命周期与顶层树断开；增长随历史 catalog 和剩余映射量。
修复需同时考虑 edit log/replay、延迟事件、同名不同 ID 重建；先确认删除的是最终废弃的 catalog，
再原子移除 ID 树。本轮为静态确认。

## MEM-013：动态分区运行信息未随表消失清理

[DynamicPartitionScheduler.java:103](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/clone/DynamicPartitionScheduler.java:103) 的 `runtimeInfos` 按表 ID 保存运行状态。
第 131–132 行注销调度只删调度集合；第 664–690 行发现库/表不存在时也只移除调度项。
第 140–141 行虽有 `removeRuntimeInfo()`，全仓调用来自
[ShowDynamicPartitionCommand.java:107](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/ShowDynamicPartitionCommand.java:107)，针对还能被 SHOW 遍历到且已关闭动态分区的表。
已经 drop 的表无法依赖这条命令可靠清理。

历史动态分区表 ID、状态和错误字符串因此可积累；固定表集合反复调度不必然增加 map 项。
修复应在调度注销、表最终清理和失效扫描中同步处理，覆盖 drop db、drop table、开关动态分区、
恢复回收站对象与并发调度。本轮为静态确认，预计优先级低于持有计划/大元数据的条目。

## MEM-014：MTMV 关系 map 删除值后保留空键

[MTMVRelationManager.java:69–72](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/mtmv/MTMVRelationManager.java:69) 的三个 map 保存基础表/视图到物化视图集合的关系；
第 175–176 行刷新先 remove 再 add，第 215–223 行 remove 仅从集合删除视图，未删除空集合对应的 key。
因此，历史上出现过但已没有关联物化视图的 BaseTableInfo 及空集合仍在 manager 中。

**不是每次刷新都增长**：同一组基础表、视图反复刷新会复用这些 key；
增长需要基础关系持续变化或历史对象 ID 增加。
修复时不能采用存在竞态的“读到 empty 后无条件 remove”；应把集合更新和空键移除置于同一原子操作，
覆盖同时增删不同 MV、替换依赖、drop/recreate 和恢复流程。本轮为静态确认。

## MEM-015：统计作业历史被淘汰后，运行任务 map 完成时早退

**位置与链路**：[AnalysisManager.java:1007–1015](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/statistics/AnalysisManager.java:1007) 的 `replayCreateAnalysisJob()`
按 `analyze_record_limit` 淘汰最早 jobInfo，没有排除仍有运行任务的作业。
[AnalysisManager.java:469–490](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/statistics/AnalysisManager.java:469) 的任务状态更新先找任务表，再找 jobInfo；
jobInfo 已不在历史 map 时，第 489 行直接 return。
正常全部任务结束后删除 `analysisJobIdToTaskMap` 的语句位于第 535 行，因早退无法到达。

**影响**：运行较久的统计任务遇到大量新作业/历史轮换，结束后仍能留下 BaseAnalysisTask 集合及其表、
列、统计上下文引用；历史条数有限不能限制这张另一用途的 map。
显式 kill 等路径另有 remove，不应描述为任意条件下都无法删除。

**修复与验收**：把运行任务生命周期与可淘汰的展示记录分开；缺失历史时也执行终态计数及任务释放。
以小 `analyze_record_limit`、慢作业和大量短作业交错测试，覆盖成功、部分失败、取消及回放，
确认终态任务最终从运行表移除。本轮为静态完整路径，未执行真实统计任务。

## MEM-016：DFS 关闭异常遗留强引用，未捕获异常还能停止后续清理

**原问题成立**：[RemoteFSPhantomManager.java:65–73](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/fs/remote/dfs/RemoteFSPhantomManager.java:65) 用静态 fsSet 保持底层 FileSystem。
第 105–121 行取到 PhantomReference 后先从 referenceMap 移除，再执行 `fs.close()` 和 `fsSet.remove(fs)`。
close 抛 IOException 时只记录日志，fsSet 删除未执行，引用已出队也不会自然再次触发该清理。
[FileSystemCache.java:40–46](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/fs/FileSystemCache.java:40) 没有 removal listener，缓存淘汰后的兜底依赖这套机制；
这不等于 FileSystem 在整个项目中不存在其他显式 close。

**本轮新增的失败边界**：回调只 catch IOException。若 FileSystem 实现的 close 抛 RuntimeException，
异常会穿出周期任务。ScheduledExecutorService 对失败的周期任务不再安排后续执行，
之后的待回收 FS 也失去该兜底。依据：[JDK 17 周期调度异常语义](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/concurrent/ScheduledExecutorService.html)。

**实测**：编译当前 RemoteFSPhantomManager，注册本地 fake FS，令 close 抛 IllegalStateException，
手工 enqueue phantom，运行真实清理回调。结果 completed task 为 1、后续 scheduled task 为 0，
fsSet 剩 1、referenceMap 为 0。未创建真实 HDFS 连接；此测试证明异常边界，
不表示常用 HDFS 版本在生产必然抛同一种异常。

**修复与验收**：让单项关闭失败不会终止全局清理，保留可观察、有限重试的失败项，
明确最终放弃时如何释放 owner 引用；不能简单以无限重试队列替换现在的泄漏。
分别测试 IOException、RuntimeException、成功重试及连续多个待清资源，并监控清理任务存活状态。

## MEM-017：已退役 BE 地址对应的 RPC client 无主动淘汰

[BackendServiceProxy.java:69](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/rpc/BackendServiceProxy.java:69) 的 serviceMap 按地址缓存 client；第 121–166 行创建或在再次访问时检查失效，
第 106–118 行可显式 remove。RPC 失败和 IP 变化有调用路径，但 BE drop/decommission 没有对应清理钩子。
不再被访问的历史地址因此能一直保留 client；同类 Holder 还维护多个 proxy 实例，
清理不能只处理其中一个。底层 channel 是否仍保留连接/线程还需按 client 实际状态检查，不能只凭 map 估算。

固定 BE 地址、稳定 client 下不是按查询次数无界增长；BE 经常扩缩容、换地址时才会积累历史键。
修复采用拓扑移除通知与闲置淘汰相结合，覆盖所有 proxy 实例，处理在途 RPC 和同地址重连，
验收 map 数量及已关闭 client 的可回收性。本轮为静态确认。

## MEM-018：查询实例计数表留下历史用户名的零计数项

[QeProcessorImpl.java:155–163](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/QeProcessorImpl.java:155) 按用户创建 `userToInstancesCount`；第 198 行结束时只扣计数，不删除归零键。
用户名和 AtomicInteger 因而随历史用户基数累计，即使用户已没有实例。
固定用户名集合时会形成小平台，不应作为普通查询按次数泄漏或数 GB 增长的主要解释。

修复需保证“归零摘除”与同时注册新查询原子协调，避免两个 counter 并存导致限额失效；
覆盖删用户、重建同名用户、查询失败、并发注册/注销。本轮为静态确认。

## MEM-019：Ranger Hive 审计事件不清空，定时刷新还存在生命周期缺口（新增）

**事件本身持续保留**：[RangerHiveAuditHandler.java:65–67](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/catalog/authorizer/ranger/hive/RangerHiveAuditHandler.java:65) 的 ArrayList 与 deniedExists 属于长期 handler。
第 239–255 行 flush 仅遍历发送，既不 clear，也不重置 deniedExists；processResult/processResults 持续 add。
所以正常 flush 成功也不会回收历史事件，并会重复处理旧事件；出现过一次拒绝后，旧 deniedExists
还会持续影响后续允许事件的过滤。实际事件产生取决于 Ranger 策略与审计配置。

**调度与 drop 边界**：[RangerHiveAccessController.java:53–68](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/catalog/authorizer/ranger/hive/RangerHiveAccessController.java:53) 为所有实例共用单线程 timer，
每个 handler 注册周期任务而不保存 Future；[RangerHiveAuditLogFlusher.java:33–43](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/catalog/authorizer/ranger/hive/RangerHiveAuditLogFlusher.java:33) 的一次 run
却包含无限循环和 sleep，并忽略中断退出。第一个正常运行的 flusher 占住线程，后续 handler 的任务无法开始。
[ExternalCatalog.java:723–735](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/ExternalCatalog.java:723)、[AccessControllerManager.java:172–179](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/mysql/privilege/AccessControllerManager.java:172) 移除权限控制器时没有取消这些任务，
历史 handler 还会被正在执行或排队的任务引用。
此外，查询线程 add 与刷新线程遍历共用非同步 ArrayList，存在并发修改异常/数据竞争边界，
未捕获的异常也可能终止该周期任务；本轮未依赖并发竞态来证明事件保留。

**实测**：编译当前 handler/flusher。经实际 add 路径注入 1,000 个事件，三次真实 flush 后仍留 1,000 个。
测试把事件设为允许并预置 deniedExists，以走过滤分支避免向真实审计系统发送消息，
所以它验证保留机制，未验证外部审计投递。
再在隔离 daemon timer 上运行当前 flusher，计数 handler 的首次 flush：第一个为 1，第二个为 0、任务仍在队列。
这不是 20 秒间隔的长期吞吐测试；它验证单次 run 未返回造成的排队，未连接 Ranger。

**修复与验收**：使用有字节/条数预算的线程安全批次交换或 drain；成功消费后释放该批，失败有限重试。
一次 run 只处理一次批次，交由调度器安排间隔；保存 Future 并在 catalog/controller 关闭时取消，正确响应中断。
覆盖允许/拒绝交替、并发审计、投递失败、多个 catalog、drop/recreate。
启用 Ranger Hive 时，此项与随查询次数增长的堆症状高度匹配；未启用时不适用。

## MEM-020：COM_RESET_CONNECTION 未释放旧 prepared statement（新增）

**位置与协议边界**：[ConnectProcessor.java:148–152](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/ConnectProcessor.java:148) 的 reset 仅切 catalog、清 lastDB map、返回 OK，
没有清 [ConnectContext.java:284](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/ConnectContext.java:284) 的 preparedStatementContextMap。
客户端采用连接 reset 归还/复用物理连接时，可以认为旧 prepared statement 已失效而不逐个 COM_STMT_CLOSE；
服务端却继续持有 PreparedStatementContext、StatementContext 和相关计划。
MySQL 的连接 reset 语义包括释放 prepared statements，见
[MySQL C API reset 说明](https://dev.mysql.com/doc/c-api/8.0/en/mysql-reset-connection.html)。

**实测**：编译当前 ConnectContext 和 ConnectProcessor，将 prepare 上限设为 2，真实注册方法接受 3 项
（检查使用 `>`，见 CAP-001）。调用真实 reset 后仍为 3，下一次 prepare 被拒绝；显式 remove 后变为 2。
该探针调用协议处理函数并使用实际上下文对象，未通过真实驱动建立连接，未验证全部 reset 语义。

**影响与修复**：这是连接复用后的资源遗留及容量耗尽，不是“任何连接都无限越过上限”。
需要在 reset 中释放/失效所有旧 statement 及关联缓冲，按协议整理其他会话状态；
客户端再次使用旧 statement ID 应按协议失败。
验收 prepare/execute/reset/再 prepare 循环、事务中 reset、短路计划、转发执行及连接池复用，
并确认不误用 COM_STMT_RESET 的不同语义。

## MEM-021：Flight 多语句延迟 finalize 时注销了其他语句的 ID（新增）

**具体调用链**：

1. [ConnectProcessor.java:253–338](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/ConnectProcessor.java:253) 允许解析多语句，每条创建新的 StmtExecutor。
   从 BE 返回的 Flight 执行器加入 `returnResultFromRemoteExecutor`，留到外层 close 再 finalize。
2. [StmtExecutor.java:479–486](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:479) 为每次 execute 生成新 ID；第 605–609 行写入共享 ConnectContext。
3. Flight 的“只能最后一条返回结果”检查只检查 FE channel 的 `resultNum()`，
   不检查前面已经存在的 BE 返回查询，所以前一条 BE 查询不会因该检查必然阻止后续执行。
4. [FlightSqlConnectProcessor.java:196–204](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/service/arrowflight/FlightSqlConnectProcessor.java:196) close 遍历以前保存的 executor；
   但 [StmtExecutor.java:874–879](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:874) 的 finalizeQuery 用的是 **此时的 context.queryId()**，
   而非该 executor 原先注册的查询 ID。

**可构造的触发序列**：在支持相应 Flight 请求的环境中，第一条执行实际下发到 BE 的
`SELECT col FROM tbl`，第二条执行 `SHOW DATABASES` 等 FE 返回语句。
第一条注册 A、FE resultNum 仍为 0；第二条把共享 ID 改为 B，最后 close 旧 executor 时注销的是 B。
即使外层 close 完整执行，A 仍可留在 [QeProcessorImpl.java:125–137](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/QeProcessorImpl.java:125) 的 coordinatorMap，
持有 QueryInfo、Coordinator、ConnectContext，启用 profile 时还缺少对应完成标记。
两条 BE 查询也需要覆盖。上面的 SELECT 必须确实下发 BE，常量 SELECT 或命中本地缓存不能替代该条件。

**证据边界**：本项完成源码调用链核对，未运行 Flight 多语句协议集成测试；
它是具体错误 ID 路径，不等同于外部审核提出的普通查询“不取结果就跳过清理”。
修复应保存每次成功注册的 ID 并在相同执行器内注销；逐项清理不能被前一项异常阻断。
若产品不支持这种多结果请求，应在执行任何语句前明确拒绝，不能先启动 A 再依赖 FE 结果个数检查。
验收多语句成功、后续语句失败、取消、重试及 close 异常后 coordinator/profile 两张表均回落。

## MEM-022：AgentTaskQueue 删除任务后留下空桶和峰值容量

[AgentTaskQueue.java:45–68](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/task/AgentTaskQueue.java:45) 用 Guava Table 按 backend ID、task type 保存内部 HashMap；
第 84–109 行的单任务/BE 清理移除内部条目，不删除对应 Table cell。
即使任务全部结束，空 HashMap 仍留在 Table 中，其内部数组也不会因逐项 remove 自动收缩。
历史 backend ID/type 越多，空桶越多；固定 backend/type 的保留容量主要由历史峰值决定。

**纠正失败任务推断**：[MasterImpl.java:156–179](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/master/MasterImpl.java:156) 对部分失败类型提前 return 不足以证明任务无主。
Schema change/rollup 在作业错误、取消路径中移除 batch；一致性检查的 clear 也会删除任务，见
[SchemaChangeJobV2.java:620](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/alter/SchemaChangeJobV2.java:620)、[SchemaChangeJobV2.java:850](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/alter/SchemaChangeJobV2.java:850)、[RollupJobV2.java:541](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/alter/RollupJobV2.java:541)、
[RollupJobV2.java:677](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/alter/RollupJobV2.java:677)、[CheckConsistencyJob.java:405–408](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/consistency/CheckConsistencyJob.java:405)。
需要结合所属 job 的退出/超时，不能把全部 ALTER/CHECK_CONSISTENCY 失败都列为永久任务泄漏。

修复空桶需和并发 add 保持原子一致，BE 最终移除时清整行；
验收任务突发后容量、历史 BE 轮换、失败重试及取消，不破坏任务计数。
本轮只确认空桶/容量保留，未宣称失败任务本体的所有生命周期都有问题。

## Profile 清理缺口与两条不应采纳的泄漏推断

**Profile 兜底存在缺口，但有其他删除入口**。
[ProfileManager.java:980–1007](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/profile/ProfileManager.java:980) 仅当 executionProfiles 超过 `2 × maxProfileNum` 才扫描，
扫描只删 finishTime 大于 0 且过期的对象；它不是严格的容量上限。
[QeProcessorImpl.java:173–209](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/QeProcessorImpl.java:173) 注销查询负责设置完成状态，漏注销时这一兜底不覆盖未完成项。
当前类探针把阈值设为 4，注入 5 个过期已完成和 5 个未完成 profile，清理后仍留 5 个未完成项。
这是兜底条件的实测，不单独证明某条真实查询必然漏注销。

但 [ProfileManager.java:1024–1039](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/profile/ProfileManager.java:1024) 的历史 Profile 淘汰也会删关联 ExecutionProfile，
并非所有未 unregister 的 profile 都只能永久保留。
[ExecutionProfile.java:221–264](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/profile/ExecutionProfile.java:221) 处理 BE 更新时，底层
[RuntimeProfile.java:702–723](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/profile/RuntimeProfile.java:702) 对同名未完成 child 会替换，对已完成 child 会跳过；
[ExecutionProfile.java:149–154](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/profile/ExecutionProfile.java:149) 的 backend map 也按 key 替换。
新实例/新 child 名仍可能增加结构，不能泛称“相同 BE 每次报告都无界追加”。
MEM-021 是本次找到的具体漏注销入口；其他入口仍应以注册、结束、清理三段调用链或运行证据确认。

**普通 Flight 的关闭流程确实存在**。
[DorisFlightSqlProducer.java:187–290](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/service/arrowflight/DorisFlightSqlProducer.java:187) 在 try-with-resources 中执行、获取 schema 并组装 FlightInfo；
离开作用域就执行 [FlightSqlConnectProcessor.java:196–204](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/service/arrowflight/FlightSqlConnectProcessor.java:196) 的 close，其中显式 finalize。
这发生在服务端处理返回或异常退出时，不依赖客户端后来是否取结果。
因此 [StmtExecutor.java:974](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:974) 跳过本地 finally 不能单独证明普通 Flight coordinator 泄漏。
结果缓存/Arrow 资源的独立生命周期缺陷仍见 MEM-001，多语句 ID 错误见 MEM-021。

**InsertOverwrite 普通 replacePartition 异常有调用方清理**。
[InsertOverwriteManager.java:180–201](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/insertoverwrite/InsertOverwriteManager.java:180) 的 taskGroupSuccess 自身没有 finally，
但 [InsertOverwriteTableCommand.java:210–218](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/insert/InsertOverwriteTableCommand.java:210)、第 257–264 行用外层 catch Exception 包住该调用，
失败时执行 taskGroupFail；[InsertOverwriteManager.java:164–175](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/insertoverwrite/InsertOverwriteManager.java:164) 随后调用 cleanTaskGroup，
第 204–208 行删除三张 map 的组信息。
只有进一步确认清理自身二次失败、Error 或其他绕过调用方的入口，才能增加具体泄漏条目。
“字段进 image”并不能替代这个异常传播核对。本轮不采纳原 B15 作为已确认问题。

## 容量、回收延迟及 GC 差异：与无界强引用保留分别处理

### CAP-001：prepared statement 上限过大，且边界多接受一项

[SessionVariable.java:2093–2098](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/SessionVariable.java:2093) 默认开启预处理语句，上限 100,000。
[ConnectContext.java:441–451](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/ConnectContext.java:441) 在 put 前检查 `size() > maxPreparedStmtCount`，
因此无并发因素也会接受 100,001 项；本轮用上限 2 实测接受 3。
[PreparedStatementContext.java:27–43](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/PreparedStatementContext.java:27) 持有 StatementContext、命令、SQL，
还可持有短路执行上下文和 GroupCommitPlanner，条数不能代表统一字节数。
客户端长期不发 COM_STMT_CLOSE 时会爬到上限；物理连接释放后可回收，reset 缺口另见 MEM-020。
建议校正边界，按生产客户端使用情况设置更小限额并监控占用，不能只靠换 GC 管理计划对象预算。

### CAP-002：统计缓存默认是三个各 50 万项，不是合计固定 912 MiB

[StatisticsCache.java:71–92](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/statistics/StatisticsCache.java:71) 的列统计、直方图、分区统计缓存各用 `stats_cache_size`，
默认 500,000，仅有 refreshAfterWrite，没有 expireAfterWrite/Access。
[Config.java:2644–2656](/data/project/massdb-sql/fe/fe-common/src/main/java/org/apache/doris/common/Config.java:2644) 的约 911.95 MiB 注释估算针对 **100,000 个示例条目**，
包含 128-bucket histogram、特定长度的列名/min/max；无 histogram 的示例约 61.28 MiB。
不能把该注释当作三个默认缓存当前实测总占用，更不能当可靠字节上限。
随着访问表/分区变多，数天才逐渐填满完全可能；需采集各自键数、hit rate、保留大小，
按对象权重和业务失效语义优化，避免缓存挤占查询工作内存。

### CAP-003：softValues 不是主动内存预算，HBO 默认值须区分缓存

[NereidsSqlCacheManager.java:172–183](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/cache/NereidsSqlCacheManager.java:172)、[NereidsSortedPartitionsCacheManager.java:148](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/cache/NereidsSortedPartitionsCacheManager.java:148)、
[HboPlanInfoProvider.java:49–68](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/stats/HboPlanInfoProvider.java:49) 使用 softValues，并有按配置启用的条数/时间限制。
软引用可由 JVM 按内存需求和策略清理，不保证“只在堆满才清”，也不提供固定缓存字节预算，见
[JDK 17 SoftReference](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/ref/SoftReference.html)。
对象若另有强引用，也不会因为缓存用了 softValues 就获得回收资格。

默认 SQL cache 为 100 项、300 秒；HboPlanInfoProvider 各缓存默认 1,000 个顶层条目、1,000 秒，
其中 value 可以包含多个计划/过滤信息。
[MemoryHboPlanStatisticsProvider.java:127–138](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/stats/MemoryHboPlanStatisticsProvider.java:127) 的 100,000 是 recent-run **统计缓存条目**，
默认每项最多 10 次运行、有效期 86,400 秒，不能改写成“默认保留 10 万个 PhysicalPlan”。
配置依据：[Config.java:1500–1532](/data/project/massdb-sql/fe/fe-common/src/main/java/org/apache/doris/common/Config.java:1500)、第 2429–2483 行。
部分构建器在容量/TTL 非正时根本不设置对应约束，需检查实际参数是否把两种边界都关闭。
建议在合理 TTL 外加可解释的权重预算；评测回收后重新解析/加载带来的 CPU 和尾延迟。

### CAP-004：连接缓冲确实大，但 packetBuf 不是历史最大包缓存

[MysqlChannel.java:129–131](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/mysql/MysqlChannel.java:129) 每个连接创建 2 MiB 堆内发送 ByteBuffer。
[Config.java:847](/data/project/massdb-sql/fe/fe-common/src/main/java/org/apache/doris/common/Config.java:847) 默认允许 1,024 个 MySQL 连接，全部占满时仅此项理论上就为 2 GiB，
不等于生产当前已经使用 2 GiB。[MysqlSerializer.java:35](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/mysql/MysqlSerializer.java:35)、第 72–73 行的
ByteArrayOutputStream reset 不收缩底层数组，会保持历史序列化峰值容量。

需要纠正接收包描述：[MysqlChannel.java:300–303](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/mysql/MysqlChannel.java:300) 每次接收从默认 16 KiB buffer 开始，
第 424–437 行扩容的是当次 buffer；[MysqlConnectProcessor.java:386](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/MysqlConnectProcessor.java:386) 每次请求替换 packetBuf，
所以空闲连接保留的是**最近请求**，不是永远保留该连接收到过的最大包。
另外 0xffffff 是单个物理包的边界，协议可拼成更大的逻辑请求，不能把 16 MiB 当总请求上限。
应同时测大请求后空闲、后续小请求、serializer 高水位、prepared execute 相关引用、SSL 缓冲和并发连接数。
建议按需分配发送缓冲，对异常大序列化数组在安全边界收缩，避免每条请求都重建大数组。

### CAP-005：审计按事件数限流，长 SQL 可提前耗尽堆

[AuditEventProcessor.java:51](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/AuditEventProcessor.java:51) 创建无容量参数的 LinkedBlockingDeque，
第 91–104 行用 size 检查默认 `audit_event_log_queue_size=250000` 再入队；
check/add 非原子，高并发下也不是精确 250,000 的物理容量边界。
[AuditLogHelper.java:112–114](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/AuditLogHelper.java:112) 按 [GlobalVariable.java:172](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/GlobalVariable.java:172) 默认 2,097,152 字节限制审计 SQL，
不同语句还可能有更小截断。[AuditLoader.java:94](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/plugin/audit/AuditLoader.java:94) 再建 100,000 项队列，启用 AuditLoader 才使用。

若消费落后，大 SQL 事件会在达到条数阈值前耗尽堆。两个队列之间存在共享 AuditEvent 引用，
不能简单把“25 万 + 10 万”乘 2 MB 当成准确独立分配量；flush 批次大小限制也不限制等待队列的字节总量。
优化应增加排队字节预算、消费滞后指标和明确的过载策略，验收长 SQL、审计目的端慢/不可用、
并发 check/add、启停插件，以及事件截断后字段的正确性。

### CAP-006：事务、alter 作业与回收站的历史保留本身有成本

[Config.java:204–227](/data/project/massdb-sql/fe/fe-common/src/main/java/org/apache/doris/common/Config.java:204) 默认 Long label 保留 3 天、streaming Short 保留 12 小时、alter 历史 7 天；
第 3079 行 `label_num_threshold=2000` 作用于清理循环中的每条队列，属于软阈值，
还受 MEM-008 预算约束，不是数据库总事务的硬上限。
[Config.java:808](/data/project/massdb-sql/fe/fe-common/src/main/java/org/apache/doris/common/Config.java:808) 回收站默认保留 1 天，其 Table/Partition 对象是恢复功能所需的合法保留。

alter 也不能简单认为保留完整原始对象七天：例如 [SchemaChangeJobV2.java:218–223](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/alter/SchemaChangeJobV2.java:218) 会 prune 部分结构，
但 job、剩余任务集合等仍有成本；未结束的作业还需要单独分析，不能按完成历史 TTL 推断其释放时间。
应监控历史作业、回收站对象和事务各自数量/字节，调整保留期前核对恢复、去重和运维查询需求。

### CAP-007：StatementContext.finalize 延迟整个规划对象图回收

[StatementContext.java:847–853](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/StatementContext.java:847) 非空 finalize 用于检查 planner resource/锁是否释放，
使对象进入可终结生命周期；第 857–859 行的显式 close 释放资源，但不会取消对象的 finalization。
该上下文持有表、统计、CTE 和计划等图结构，待终结期间也会延迟其回收。
finalization 时机/顺序没有及时性保证，不能固定描述为“恰好再活一个周期”。
依据：[JDK 17 Object.finalize](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/Object.html#finalize())。

在本环境的 HotSpot 17 中应检查 Finalizer 工作线程及待终结数量，区分生命周期开销与持续队列积压；
尚无生产 Finalizer 队列证据，不能据源码就断言它已造成 OOM。
建议优先以确定性的 close/finally 验证资源释放，减少依靠终结器做诊断；
若改用其他回收通知，不能让回调又强引用被观察的 StatementContext。

### CAP-008：JDK 17 ZGC 的对象指针与指标口径确有差异，不能固定外推比例

使用本机同一个 JDK 17.0.2，在独立 JVM 中以 `-Xms32m -Xmx8g` 检查最终 flags：

| 参数 | G1 | ZGC |
| --- | --- | --- |
| UseCompressedOops | true | false |
| UseCompressedClassPointers | true | true |

所以对包含大量对象引用的相同数据结构，ZGC 可能需要更多堆；这不等于所有对象都多占固定 20%–30%，
也不能把“压缩对象指针”和“压缩类指针”混为一谈。此处只测参数，未做生产对象图体积对照。
JDK 17 ZGC 的限制还可核对
[OpenJDK 17 ZGC 参数实现](https://raw.githubusercontent.com/openjdk/jdk17u/master/src/hotspot/share/gc/z/zArguments.cpp)。

JDK 17 的 ZGC 为非分代收集器，存活图增长会增加标记工作；但周期变慢还受分配速率、
CPU 配额/争用、GC worker、内存压力等影响，不能当作存活集增长的唯一直接读数。
Cycles 与 Pauses 必须分开，见下文计时口径。
Checkpoint 在 ZGC 下读取总 heap used，可能包含当时尚未回收的垃圾；这与 G1 old used 不是同一指标，
不应仅凭某次超过 70% 就判定存活对象已超过 70%，也不能把浮动垃圾视为 ZGC 独有缺陷。

生产反馈的 17.0.2 对应 2022-01-18；建议在相同 JDK 17 主版本内验证部署所用发行商当前维护补丁，
核对 GC、依赖及回归后升级。补丁升级不能释放应用仍强引用的对象，不承诺解决上述泄漏。
版本发布信息可查 [JDK 17 更新说明](https://www.oracle.com/java/technologies/javase/17u-relnotes.html)。

### CAP-009：元数据合法增长必须单列基线

动态/自动分区持续增加 Partition、Tablet、Replica，以及 TabletInvertedIndex 等索引，
是当前有效元数据增长，不需要存在泄漏就能增加长期堆存活集。
对比一周前后内存时，应同步比较有效表/分区/tablet/replica/列数、外部元数据工作集及保留期内历史任务。
固定活跃规模后的持续残留、删除后无法释放的旧 owner，才用于证明生命周期缺陷；
不能用合法增长掩盖 MEM-007 等与历史请求次数相关的保留，也不能把正常元数据全部判为泄漏。

## 外部审核附带的非内存问题

**PublishVersionDaemon：成立，已在功能报告登记 BUG-005。**
[PublishVersionDaemon.java:272](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/transaction/PublishVersionDaemon.java:272) 将本轮聚合字段重赋为单事务 map，后续向自身 putAll 不会恢复前面事务的数据，
可见版本通知因此丢掉前序事务。本轮不重复编号，不把它计为内存累计问题；
具体触发与证据见 [功能 bug 报告](/data/project/massdb-sql/docs/bug-audit-20260907.md)。

**InsertJob：内部进度字段的计算问题成立，“进度永远为 0”范围过大。**
[InsertJob.java:157](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/job/extensions/insert/InsertJob.java:157) 的 finishedTaskIds 没有新增入口；第 609–615 行用它计算内部 progress，
因此该更新路径在有任务时算出的数值为 0，第 711 行 getter 可以读到这一数值。
但同类第 451–463 行的 SHOW 数据从 ProgressManager 取进度，FINISHED 分支直接显示 100%，
不能说所有对外展示永远是 0。
应统一内部数值与任务完成状态，并分别验证 getter/持久化回放和 SHOW 展示；
本轮只记录这一范围明确的正确性问题，不归入 MEM。

## GC 切换还需要核对的行为

### Checkpoint 已有回退，但阈值口径不同

[fe/fe-core/src/main/java/org/apache/doris/master/Checkpoint.java:371–391](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/master/Checkpoint.java:371)：
找到 old 池时使用 old used/max，找不到时使用总 heap used/max。
因此不能报告“ZGC 没有 old 池，Checkpoint 就会空指针崩溃”。
但 G1/Parallel 与 ZGC 的计算口径不同，相同 70% 阈值不代表相同的检查点可用内存条件。
默认值见 [fe/fe-common/src/main/java/org/apache/doris/common/Config.java:1350](/data/project/massdb-sql/fe/fe-common/src/main/java/org/apache/doris/common/Config.java:1350)。

同文件配置第 3162 行，`checkpoint_manual_gc_threshold=0` 默认禁用手动 GC。
[Checkpoint.java:353–363](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/master/Checkpoint.java:353) 在连续超限计数恰好等于非零配置时调用一次 `System.gc()`；
它不是每轮持续回收机制，也不能解除强引用或替代 Arrow 资源关闭。
不能把“并发收集”解释为“System.gc 一定立即返回”：OpenJDK 17 ZGC 的该请求使用同步等待，
而 Java API 本身也不保证能回收指定数量的内存。
依据：[OpenJDK ZDriver](https://raw.githubusercontent.com/openjdk/jdk17u/master/src/hotspot/share/gc/z/zDriver.cpp)、
[JDK 17 System.gc](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/System.html#gc())。

### 规划 profile 的 GC 时间不是统一的暂停口径

[fe/fe-core/src/main/java/org/apache/doris/nereids/NereidsPlanner.java:796–805](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/NereidsPlanner.java:796)
把所有 GC MXBean 的 `CollectionTime` 相加，在第 219、267 行计算规划前后差值。
JDK 17 ZGC 同时暴露 `ZGC Cycles` 与 `ZGC Pauses`：前者包含整个周期，后者单独记录暂停。
求和存在计时范围重叠，也不能表示这条查询暂停了多久。
依据：[OpenJDK ZServiceability](https://raw.githubusercontent.com/openjdk/jdk17u/master/src/hotspot/share/gc/z/zServiceability.cpp)、
[OpenJDK ZDriver](https://raw.githubusercontent.com/openjdk/jdk17u/master/src/hotspot/share/gc/z/zDriver.cpp)。

隔离 ZGC JVM 的一次测量中，Cycles 增加 9 ms、Pauses 增加 0 ms 且计数增加 3。
这里的 0 是毫秒粒度的结果，不表示没有暂停；9 ms 也不能解释为规划线程停顿 9 ms。
建议分别展示周期与暂停，并注明这是全 JVM 计数差，不能准确归因到单条并发查询。
此项作为诊断口径问题记录，不另计入 MEM 编号。

### 当前启动约束

[bin/start_fe.sh:299–312](/data/project/massdb-sql/bin/start_fe.sh:299) 只接受 JDK 17，并使用 `JAVA_OPTS_FOR_JDK_17`。
[conf/fe.conf:30](/data/project/massdb-sql/conf/fe.conf:30) 模板配置 `-Xms8192m -Xmx8192m`，没有显式指定 GC。
当前本地运行实例则是 G1、`-Xms512m -Xmx2048m`，不能把模板参数当作实例实际配置。
应以目标 JDK 二进制与实际 VM flags 验证 GC 支持情况；本机 Shenandoah 无法启动。

本轮没有进行收集器的吞吐/延迟对比，不据此推荐直接更换生产 GC。
先修复已确认的生命周期问题，再在相同 JDK、堆配置、数据和并发下比较 G1/ZGC，
同时验收指标、Checkpoint、查询超时及 FE 心跳行为。

## 如何判断“运行越久，内存越不足”

不能只看操作系统的 free 或进程 RSS。需要同步观察以下量：

| 现象 | 优先检查 | 本轮对应线索 |
| --- | --- | --- |
| 数据与并发固定，完成回收后的堆基线持续增加 | 被引用对象、缓存键数、历史任务与会话 | 优先 MEM-007、008、010、015、019、020；其他项按功能核对 |
| 堆占用平稳，RSS 或堆外计数持续增加 | Arrow/Netty 分配、Metaspace、线程、原生库 | MEM-001、004 |
| 请求高峰增加，处理完后回落 | 同时执行的规划、队列积压、大结果与瞬时副本 | 容量或背压问题，需压测 |
| 缓存预热后趋稳 | 缓存上限、单项大小、TTL 及实际清理时间 | 有界缓存仍可能占用很大 |
| committed 高而 used 低 | 堆最小值和收缩行为 | 不应仅据此判定对象泄漏 |

`-Xmx` 限制 Java 堆，不是整个 FE 进程的 RSS 上限。Metaspace、线程栈与其他原生分配
需要另外计入预算；虚拟地址保留量也不等于已驻留物理内存。
依据：[JDK 17 java 参数说明](https://docs.oracle.com/en/java/javase/17/docs/specs/man/java.html)。

Profile 清理不能作为排除泄漏的依据：完成标记缺口及多语句注销路径见本版专节。
SQL 缓存、QueryDetailQueue、外部扫描 split 和线程上下文的部分清理路径已核对；
这不等于全部异常路径通过验收，也不等于“有条目数上限就有可靠的字节数上限”。
例如 Flight 普通结果缓存限制 100 项、10 分钟，却没有按结果字节加权的容量预算。
可继续评测大结果缓存、队列背压和单次规划内存预算；这些是容量优化候选，未计为已确认泄漏。

BDBJE 在 [fe/fe-core/src/main/java/org/apache/doris/journal/bdbje/BDBEnvironment.java:150](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/journal/bdbje/BDBEnvironment.java:150)
显式设置缓存大小；当前默认 `bdbje_cache_size_bytes` 为 10 MiB（[fe/fe-common/src/main/java/org/apache/doris/common/Config.java:340](/data/project/massdb-sql/fe/fe-common/src/main/java/org/apache/doris/common/Config.java:340)）。
不能套用其他部署的 JE 默认堆百分比来解释本仓库，也不能把这一项当作整个 BDBJE 内存总量。

## 原本地 FE 的只读观察（G1 / 2 GiB，仅为历史参照）

此实例与反馈中的生产 ZGC / 8 GiB 不同，以下数据不能外推生产趋势。

2026-09-07 11:06 左右，运行实例 PID 2637523。读取了 VM flags、heap info、
`/proc/PID/status` 和已有 GC 日志，未生成 heap dump、开启录制或触发 GC。
不同读数来自相邻时刻，不是一次原子采样。

| 项目 | 读数 |
| --- | --- |
| 实际 GC / JDK | G1 / 17.0.2 |
| 初始堆 / 最大堆 | 512 MiB / 2 GiB |
| heap info 当时已提交 / 已使用 | 512 MiB / 约 172.6 MiB |
| Metaspace 已使用 | 约 154 MiB |
| RSS | 864,076 KiB，约 843.8 MiB |
| 线程数 / Swap | 273 / 0 |
| NMT | 未启用 |

已有日志中的常规回收样本：

| 时间（UTC+8） | GC 日志中的堆变化 |
| --- | --- |
| 10:37:24 | 387M → 132M（512M） |
| 10:46:35 | 408M → 139M（512M） |
| 10:54:46 | 419M → 139M（512M） |
| 11:04:05 | 424M → 132M（512M） |

当前这份 GC 日志中未发现 Full GC 或 OOM 记录。年轻代回收后的占用不是严格的全堆存活集；
RSS 与堆 used 之差也不能直接算成“泄漏”。这份观察不足以判断生产环境数天或数周的趋势。

## 建议的后续验证与诊断

1. **先建立可比基线**：固定存量表、catalog、驱动版本与并发，采集堆 used/committed/max、
   自然 GC 后基线、RSS、Metaspace、线程、Arrow 分配器及相关 map/队列数量。
2. **按问题单独循环**：长连接多批查询与 prepare/reset；Short/Long 混合事务；统计任务历史淘汰；
   Ranger 审计；Flight prepare/close 与 BE→FE 多语句；外部 catalog 初始化/drop；
   驱动版本、Group Commit 表 ID 和 catalog 名称轮换。每组固定活跃对象数，对比历史操作后的残留。
3. **验证稳态与回落**：修复后先运行最小回归，再做 24–72 小时持续负载。
   等待实际异步清理完成，区分对象数回落与原生分配器保留已释放内存供复用。
4. **再比较 GC**：用相同负载比较回收后基线、P95/P99 延迟、CPU、暂停、Checkpoint 成功率。
   不能用不同元数据规模或不同堆大小的两组 RSS 判断收集器优劣。

目前可用的只读命令（将 PID 替换为目标实例，并使用对应 JDK 的 jcmd）：

```bash
jcmd PID VM.flags
jcmd PID GC.heap_info
jcmd PID VM.native_memory summary
```

第三条只有 JVM 启动时开启 NMT 才能提供分类信息。当前实例未开启，不能通过 jcmd 临时开启；
如需要，应在后续计划内重启的诊断配置中评估 `-XX:NativeMemoryTracking=summary` 的开销。
NMT 主要追踪 JVM 内部原生内存，并不完整覆盖第三方原生分配，不能用它代替 Arrow 分配器计数。
依据：[Oracle JDK 17 Native Memory Tracking](https://docs.oracle.com/en/java/javase/17/vm/native-memory-tracking.html)。

本报告没有执行这些长期负载或修改生产参数。应按本版首表及生产功能开关安排修复：
先检查堆内持续保留和容量预算，补齐 MEM-002 的监控；Flight 堆外问题按其实际使用情况单独处理。

## 本轮新增探针与证据范围

本轮复核的探针、当前类源码校验值、编译输出与原始结果归档于
[fe-memory-review-20260907.tar.gz](/data/project/massdb-sql/.build-records/fe-memory-review-20260907.tar.gz)，
校验文件为 [fe-memory-review-20260907.tar.gz.sha256](/data/project/massdb-sql/.build-records/fe-memory-review-20260907.tar.gz.sha256)。
归档 README 说明每个探针的隔离方式与未覆盖范围，run-probes.py 保存编译和运行命令。

| 探针 | 验证内容 | 实测摘要 |
| --- | --- | --- |
| ContextGrowthProbe | 当前会话类及 reset 处理函数 | 10 万批次后仍 10 万项；limit=2 接受 3 个 prepare，reset 后仍 3 |
| TxnBudgetProbe | 当前事务管理器的真实清理循环 | 三轮 Short 用尽额度，Long 剩 100/200/300；压力结束后回到 0 |
| MetricRetentionProbe | 当前 cache owner 与指标注册表 | 摘除 32 个 owner 后，32 个 Gauge 和 catalog 仍保留 |
| RangerAuditProbe | 当前事件列表/flush 与调度 run | 1,000 个事件 flush 三次不减；第一个无限 run 阻塞第二个任务 |
| ArrowOrphanProbe | 当前 channel、包内 Arrow/Netty 分配路径 | G1/ZGC 的 channel/allocator 弱引用归零，2,000 个活动分配未归还 |
| ProfileGuardProbe | 当前 ProfileManager 兜底条件 | 清掉过期完成项后，5 个未完成项仍超过阈值 4 |
| PhantomCleanupProbe | 当前 DFS 清理回调的异常边界 | 单项 RuntimeException 后不再调度，fsSet 剩 1 |
| gc-8g-flags.txt | 同一 JDK、同一 8 GiB 上限的参数 | G1/ZGC 的压缩对象指针开关不同，压缩类指针均开启 |

除 Arrow 同时使用 G1/ZGC，当前新增方法探针使用独立 ZGC、最大堆 512 MiB；
8 GiB 对比只启动小初始堆的参数探针，未进行 8 GiB 负载实验。
显式 GC、Unsafe 构造隔离、反射及异常注入均仅用于这些独立 JVM；
未接入生产、发送真实 SQL/畸形 RPC、建立 Ranger/HMS/HDFS 连接或执行完整 FE 集成测试。
本轮新查出的 Flight 多语句问题仍是静态调用链证据，不能与上述方法实测混写。

## 原版证据与整体覆盖限制

离线探针、原始输出和运行说明归档于 [.build-records/fe-memory-gc-audit-20260907.tar.gz](/data/project/massdb-sql/.build-records/fe-memory-gc-audit-20260907.tar.gz)，
校验文件为相邻的 `.sha256`；该目录按仓库规则忽略，不进入安装包。
归档包括 Flight 分配器 G1/ZGC 对照、GC pool/core 输出、ZGC 计时探针、
线程池/类加载器保留验证、会话 catalog 清理验证及运行中 FE 的只读观察摘要。

两轮探针复用现有构建产物中的依赖（发行包或 FE target），并将被测的当前生产源码重新编译到优先 classpath；
它们不等同于完整 FE 集成测试。本轮范围覆盖连接/协议、转发、规划与 profile、统计、事务/自动分区、
外部 catalog/文件系统/Ranger、任务队列、MTMV/动态分区、RPC、审计、缓存及 Checkpoint 的相关生命周期。
没有检查完全部 GC/JDK 组合、所有协议异常分支或全部后台任务，也未执行一周生产等价负载；
“未在所查路径确认问题”不代表该模块全部通过内存安全验证。
此前功能 bug 与性能机会分别记录在 [docs/bug-audit-20260907.md](/data/project/massdb-sql/docs/bug-audit-20260907.md) 和
[docs/performance-audit-20260907.md](/data/project/massdb-sql/docs/performance-audit-20260907.md)；本报告的 MEM 编号独立维护，避免把监控缺陷混作查询正确性 bug。
