<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# MassDB SQL 主要链路性能审查（2026-09-07）

## 结论与覆盖范围

发现 **10 项有具体源码依据的性能优化机会**，覆盖 FE 规划、分区裁剪、导入路由、
BE 排序与聚合、倒排搜索、文件缓存、compaction、云端 delete bitmap 同步和上报调度。
其中谓词推导运行了当前 Java 方法的微基准，TOPN 做了离线算法输出和比较次数对照；
其余为已核实调用路径的静态分析，尚未测量端到端收益。

上一轮不是只看 JDBC，还检查了倒排索引、NULL 语义、缓存和 FE 上报并发；
但它确实是围绕近期修复的定向审查。本轮扩大了功能覆盖，**仍不是所有文件、所有函数逐一审完**。
例如 Nereids 主源码就有 2,537 个 Java 文件。不能据本报告宣称数据库整体已通过功能或性能验收。

源码基线：`59329855b4e62497d927f3ccd547b866a190a0fc`。未修改数据库实现、配置或运行中的服务。

| 功能链路 | 本轮实际检查的主要入口/文件 | 覆盖程度 |
| --- | --- | --- |
| FE 查询规划 | `Rewriter`、`InferPredicates`、`PullUpPredicates`、`UnequalPredicateInfer` | 跟踪谓词推导调用链并运行真实方法 |
| FE 元数据与统计 | `PruneOlapScanPartition`、`LogicalOlapScan`、`PartitionInfo`、`InternalCatalog`，统计缓存相关路径 | 确认分区裁剪与查表代价；统计缓存候选未计入优化清单 |
| 导入与事务 | `GroupCommitManager`、`SlidingWindowCounter`、`PublishVersionDaemon`、`DatabaseTransactionMgr` | 查表开销、发布流程；额外复现一项通知遗漏 bug |
| BE 查询执行 | `HeapSorter`、`Sorter`、`sort_block`、TOPN 聚合系列、SEARCH collector/scorer | 排序、复制、结果选择和重复计算 |
| 存储和后台任务 | `FSFileCacheStorage`、`LocalFileSystem`、`BlockFileCache`、`StorageEngine`、`TabletManager`、`Tablet` | 淘汰 I/O、锁范围、compaction 候选选择 |
| 存算分离 | `CloudMetaMgr::_get_delete_bitmap_from_ms_by_batch`、MetaService `get_delete_bitmap` | 请求批次、响应截断、重复序列化 |
| FE 上报与调度 | `ReportHandler`、`TabletInvertedIndex`、`AgentTaskQueue`、`Env` 存储介质缓存 | 去重/并行现状、全局锁和分片任务聚合 |

Hash Join 全部变体、窗口函数、spill、全部外部 catalog、全部数据类型及函数、复制恢复、
权限与协议等未逐项完成审查。这里的覆盖表描述已读过的路径，不表示整个模块全部查完。

## 优先级总览

“优先”表示建议先实现并评测；“按负载”表示需确认部署模式或工作负载；
“后续”表示改动较广，应先采集 profile。优先级不是已经测得的收益排名。

| 编号 | 功能 | 具体优化点 | 建议次序 | 证据 |
| --- | --- | --- | --- | --- |
| PERF-001 | FE 规划 | 稀疏谓词图仍做完整三次方闭包计算 | 优先 | 当前方法耗时实测 |
| PERF-002 | 文件缓存 | 每删一个块都完整列目录，累计可达平方级扫描 | 优先 | 源码、操作次数模型 |
| PERF-003 | TOPN 聚合 | 仅需前 K 项却复制并完整排序全部不同值 | 优先 | 源码、算法对照 |
| PERF-004 | ORDER BY LIMIT | HEAP_SORT 完整排序并复制整批后才淘汰 | 优先 | 源码调用链 |
| PERF-005 | 分区裁剪 | 手工指定分区时全表复制，并使用 List.contains | 优先 | 源码、复杂度分析 |
| PERF-006 | Group Commit | 每次 BE 选择都按 tableId 遍历数据库找表 | 按负载：多库、高频小批导入 | 源码调用链 |
| PERF-007 | SEARCH | 为取得 NULL 位图重复构造并执行布尔 scorer | 按负载：standard 复杂搜索 | 源码调用链 |
| PERF-008 | Compaction | 每块磁盘分别复制和遍历全 BE tablet | 按负载：多盘、多 tablet | 源码、操作次数模型 |
| PERF-009 | 云端元数据 | 分批取 delete bitmap 时反复发送全部未完成 rowset 描述 | 按负载：Cloud MoW、多批返回 | BE/MS 双端源码、操作次数模型 |
| PERF-010 | FE 上报 | 全局读锁覆盖任务排队和等待，共享结果逐条加锁 | 后续 | 锁与任务调用链；需 profile |

## PERF-001：谓词推导使用稠密矩阵和完整 Floyd 循环

**位置与调用链**：

- `fe/fe-core/src/main/java/org/apache/doris/nereids/jobs/executor/Rewriter.java:613–624` 注册常规推导规则。
- 经 `InferPredicates` → `PullUpPredicates` → `PredicateInferUtils`，进入
  `fe/fe-core/src/main/java/org/apache/doris/nereids/rules/rewrite/UnequalPredicateInfer.java`。
- 该文件第 145–154 行汇集端点并创建 `Relation[V][V]`；第 209–214 行执行三重循环，
  没有跳过不可达组合；第 543–551 行没有按图规模限制推导工作量。

**负载与代价**：宽表自动生成大量比较条件，或复杂连接含很多比较谓词。即使
`c0 > 0 AND c1 > 1 ...` 的关系互不相连，也放入一个矩阵计算。
空间 O(V²)，一次闭包 O(V³)，会消耗 FE CPU 并增加规划延迟。

**当前方法实测**：aarch64、JDK 17.0.2，编译当前源码，单 JVM，设置 `-XX:ActiveProcessorCount=1`（未绑核），
12 次小规模预热、每档 3 次测量。只计 `InferenceGraph.deduce()`，不含建图或完整 SQL 规划。

| 条件数 N | 顶点数 V=2N | 循环调用次数（按 V³ 计算） | 中位耗时 |
| ---: | ---: | ---: | ---: |
| 64 | 128 | 2,097,152 | 1.498 ms |
| 128 | 256 | 16,777,216 | 13.036 ms |
| 256 | 512 | 134,217,728 | 93.564 ms |
| 512 | 1,024 | 1,073,741,824 | 724.309 ms |

**优化方向**：先按弱连通分量拆图，在分量内推导；跳过没有可达边的组合。
极端图可考虑规划工作预算，保留原谓词作为停止推导的退路。保持推导结果和稳定输出顺序，
不能通过删除原过滤条件来省时。

**验收**：对独立分量、长链、稠密关系及 EQ/GT/GTE 混合分别核对推导结果；
再测完整 SQL 的 planning P50/P95、CPU 和分配量。当前测量不是优化后提速数据。

## PERF-002：缓存逐块删除触发重复全目录扫描

**位置与调用链**：

- `be/src/io/cache/fs_file_cache_storage.cpp:222–244`：每删一个 block 都调用 `fs->list()` 判断目录是否为空。
- `be/src/io/fs/local_file_system.cpp:226–242`：完整遍历剩余文件，构造 `FileInfo` 并读取文件大小。
- 同 hash/expiration 的块在同一目录（`fs_file_cache_storage.cpp:314–323`）。
- `be/src/io/cache/block_file_cache.cpp:887` 的 `get_or_set` 持有 `_mutex`，经
  `split_range_into_cells`、`try_reserve_for_lru:1546–1547` 到 `remove:1593` 同步调用存储删除；
  后台 GC 第 2158–2163 行也逐块删除。

**负载与代价**：单个缓存文件有很多块，且容量紧张或集中回收。若依次删掉一个目录的 N 个块，
会枚举 N(N−1)/2 个剩余目录项：1,024 块对应 523,776 项，4,096 块对应 8,386,560 项。
这是操作次数模型，不是实测系统调用次数；文件系统缓存会影响实际 I/O 成本。
前台淘汰路径还可能把这些工作计入其他请求的锁等待。

**优化方向**：按目录批量删除；或者用“仅删除空目录”的非递归操作取代完整列目录，
把目录非空作为正常结果。不能直接调用可递归删除的目录接口替代检查，否则可能删除仍有效的缓存块。
保留 TTL 旧格式清理、FD 缓存失效以及并发新建文件的处理。

**验收**：目录枚举项数、`getdents/stat` 次数、淘汰耗时、缓存锁等待、命中读取 P99、GC backlog；
覆盖 TTL、普通缓存、并发读和同目录并发写。

## PERF-003：TOPN 聚合输出只需 K 项，却完整排序全部不同值

**位置**：`be/src/vec/aggregate_functions/aggregate_function_topn.h:126–134` 将整个
`counter_map` 复制到 vector 并 `std::sort`。第 137–150 行序列化仅取前 `capacity` 项，
第 169–188 行输出仅取前 `top_num` 项。注册的函数包括 `topn`、`topn_array`、`topn_weighted`。

**负载与代价**：单组不同值 D 很大而 K 很小。完整排序需要 O(D log D) 次比较，辅助存储 O(D)；
字符串比较成本还取决于长度，并且需要复制所有不同值。序列化限制并不意味着此前的 `counter_map`
已被限制到该容量。

**优化方向**：输出按 `top_num`、中间态按 `min(capacity,D)` 选择，使用 `partial_sort`，
或 `nth_element` 后只排序保留部分；引用原 map 项的有界堆还能减少临时字符串复制。
保持“频次降序、并列按值降序”的现有比较规则，不改变计数、加权合并和容量截断语义。

**已执行算法对照**：固定随机种子 `20260907`，`pair<uint64_t,uint64_t>`，降序字典比较；
全部保留前缀均与完整排序严格相同。

| 项数 D | K | 完整排序比较次数 | partial_sort 比较次数 |
| ---: | ---: | ---: | ---: |
| 1,000,000 | 10 | 23,565,503 | 1,000,643 |
| 1,000,000 | 500 | 23,565,503 | 1,042,946 |
| 8,192 | 10 | 126,796 | 8,454 |
| 8,192 | 100 | 126,796 | 11,964 |

这些是 STL 算法模型的比较次数，**不是 BE 吞吐或查询时间的实测提升**。
BE 验收应补充字符串、高频并列、NULL、多局部聚合状态合并，核对最终输出与序列化字节，
测聚合 CPU、临时内存和结果阶段耗时。

## PERF-004：HEAP_SORT 排序并复制整批后才保留少量候选

**位置与调用链**：

- `fe/fe-core/src/main/java/org/apache/doris/planner/SortNode.java:110–120`：正常路径中较小的
  `limit+offset`（小于 50,000）选择 HEAP_SORT。
- `be/src/pipeline/exec/sort_sink_operator.cpp:49–53` 创建 `HeapSorter`。
- `be/src/vec/common/sort/heap_sorter.cpp:30–48` 先 `partial_sort(..., true)`，再淘汰到 K=`limit+offset`。
- `be/src/vec/common/sort/sorter.cpp:159–170`：`reversed=true` 强制排序 limit 为 0，即完整排序。
- `be/src/vec/core/sort_block.cpp:48–61,87–90` 对输出列做完整 `permute`。

**负载与代价**：K 远小于批大小 B，上游运行时过滤不能有效减少输入，尤其宽行或字符串载荷。
B=8,192、K=10 时，当前先排列并复制整批，而这一批最多只能贡献 10 个最终候选。
部分淘汰只是推进游标，不一定立即缩小底层 Block。数字单列可能使用线性排序优化，
不把所有类型的排序都归为 O(B log B)。

**优化方向**：按原始规则先选出本批最佳 K，再按现有反向比较规则排列这 K 项供堆淘汰。
**不能直接把反向排序的 limit 改成 K**，否则会保留本批最差 K 项。
准确保留 offset、NULL 排序、多键 ASC/DESC、并列及浮点特殊值语义。

**验收**：确认计划选择 HEAP_SORT；测试 B=4,096/8,192、K=10/100/1,000，
窄行和 1 KB 载荷宽行，随机/逆序/重复值/NULL；比较完整结果、`PartialSortTime`、复制字节与内存峰值。

## PERF-005：手工分区裁剪先复制全表再逐项线性查找

**位置**：

- `fe/fe-core/src/main/java/org/apache/doris/nereids/rules/rewrite/PruneOlapScanPartition.java:149–163`。
- `fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/logical/LogicalOlapScan.java:138,245,665–666`
  将手工分区保存为不可变 List。
- `fe/fe-core/src/main/java/org/apache/doris/catalog/PartitionInfo.java:152–162`：
  `getAllPartitions()` 复制正常和临时分区；`getItem(id)` 已提供单 ID 查找。

**负载与代价**：对多分区表用 `PARTITION(p1,...,pM)` 并带 WHERE。设全表 P 个分区，
先付出 O(P) map 复制，再通过 List.contains 筛选，最坏 O(P×M)。即使只选少量分区，也复制全表元数据。

**优化方向**：遍历手工指定的 M 个 ID，使用 `getItem(id)` 构造目标 map，平均 O(M) 查找、O(M) 临时存储。
保留正常/临时分区、重复或失效 ID 的既有行为。只把 List 改 Set 仍不能消除全表复制。

**验收**：P=1千/1万/5万，M=1/100/P÷2；比较裁剪集合、规则耗时、分配量及 EXPLAIN planning P95。

## PERF-006：Group Commit 选择 BE 时重复遍历数据库找表

**位置与调用链**：

- `fe/fe-core/src/main/java/org/apache/doris/load/GroupCommitManager.java:345–348` 的缓存选择路径，
  第 388–390 行的随机选择路径，都通过 `getTableByTableId(tableId)` 取得表。
- `fe/fe-core/src/main/java/org/apache/doris/datasource/InternalCatalog.java:313–320`
  遍历 `fullNameToDb.values()`，对每个数据库查一次该 tableId。

**负载与代价**：很多数据库、高 QPS 小批导入。即使 BE 路由缓存命中，每次也要先找表；
路由失效后随机选择还会重复一次。D 个数据库、Q 次选择最坏约 O(Q×D) 次元数据查找，
不是按全表数计算，也不是每次都发 RPC。少量数据库场景未必值得优先改。

**优化方向**：把已有 dbId/表上下文传到选择器，或维护 tableId→dbId 的目录索引。
处理建表、删表、恢复、replay 和 schema change 的一致性，不能长期缓存已删除的 OlapTable 引用。
同一请求至少可复用一次已取得的表，避免缓存和随机路径再次查找。

**验收**：D=1/100/1,000、热点表/均匀分布；统计数据库探测次数、选择器 CPU、导入 P95、分配量，
同时覆盖表删除重建与 follower 转发。

## PERF-007：standard 布尔 SEARCH 为取 NULL 再执行一遍 scorer

**位置与调用链**：

- `be/src/vec/functions/function_search.cpp:492–495` 先收集 TRUE，随后第 521–528 行再次逐段创建 scorer 取 NULL。
- `be/src/olap/rowset/segment_v2/inverted_index/query_v2/collect/doc_set_collector.cpp:52–66`
  第一次收集已创建 scorer。
- `be/src/olap/rowset/segment_v2/inverted_index/query_v2/boolean_query/operator_boolean_weight.h:46–48,157–175,238–274`
  非评分 scorer 构造会遍历叶子 postings 并物化、组合 TRUE/NULL 位图。

**负载与代价**：未命中 DSL 结果缓存、非评分、`standard` 模式的复合搜索，例如
`search('a:hot OR b:hot', '{"mode":"standard"}')`。两次构造重复遍历叶子、分配和组合位图。
即使没有 NULL，也要先构造第二次 scorer 才检查。能确认两遍计算，不能据此声称查询时间翻倍。

**优化方向**：单次 collector 同时返回 TRUE/NULL，复用本次计算。评分/WAND 提前终止时另行保证
NULL 集合完整；多段索引正确转换行号。必须保留 Bug 文档中要求的三值逻辑。

**验收**：关闭 DSL 结果缓存、预热索引页缓存；不同命中率、布尔深度、NULL 比例和段数下，
统计 scorer 构造数、叶子 advance/readBlock 次数、位图内存、CPU，逐一比较 TRUE/NULL 集合。

## PERF-008：Compaction 每块磁盘各扫描一遍全 BE tablet

**位置与调用链**：

- `be/src/olap/olap_server.cpp:988–1004` 逐 DataDir 选候选，经 CompactionSubmitRegistry
  进入 `be/src/olap/tablet_manager.cpp:848` 的 `for_each_tablet()`。
- `tablet_manager.cpp:606–621` 在每个 shard 读锁下复制所有 tablet 的 shared_ptr，再执行 handler。
- 到 `tablet_manager.cpp:761` → `be/src/olap/tablet.cpp:1012` 才排除其他 DataDir 的 tablet。

**负载与代价**：D 块盘、T 个 tablet，一轮各盘检查产生约 D×T 次条目复制/遍历。
T=200,000、D=8 的模型为 1,600,000 次，而不是 200,000 次；周期 score 更新路径在没有空闲 slot
时也可能触发。`Tablet::calc_compaction_score:1021–1039` **已经有缓存**，本项不是重新建议缓存 score。

**优化方向**：一次 snapshot 后按 DataDir 分组，分别选各盘 top-N；或维护按盘 tablet 索引。
保持可用 slot、tablet 状态、skip、score 刷新和并发删除语义，不在遍历时持有全局大锁。

**验收**：固定 T 比较 D=1/4/8/16，记录 tablet 访问数、shared_ptr 复制数、producer CPU、
shard 锁持有时间与候选排队延迟；候选结果与原实现核对。

## PERF-009：云端 delete bitmap 分批请求反复发送剩余全部描述

**位置与调用链**：

- `be/src/cloud/cloud_meta_mgr.cpp:887–940` 每轮扫描原始 N 个 rowset，
  第 906–911 行把所有未完成 rowset 及版本范围再次加入请求，第 914 行同步 RPC。
- `cloud/src/meta-service/meta_service.cpp:4446–4457` 根据返回字节阈值截断，
  因此请求尾部的描述会在下一轮再次发送。

**负载与代价**：Cloud MoW 大 tablet、delete bitmap 返回很多批。若平均每批处理 B 个 rowset，
R≈N/B，则 membership 检查为 N×R，描述传输量约 N²/(2B)。
N=10,000、B=100 的模型中，100 批做 1,000,000 次检查，发送 505,000 份描述，唯一 rowset 仅 10,000 个。
这不是实测网络字节，也不表示每个重复描述都会触发一次 FDB 读取。

**优化方向**：请求端也设置条数/序列化字节上限，用游标和有界未完成窗口推进。
保留 MS 响应字节阈值、完成 ID、版本和 rowset 过期校验。
客户端限制窗口后必须调整循环结束条件：当前窗口 `has_more=false` 不代表原始全部 rowset 已完成。
只移除已完成列表还不能消除反复发送全部剩余描述。

**验收**：累计请求条数/唯一条数、protobuf 请求字节与构造 CPU、峰值内存、RPC 数、同步时间，
覆盖超大单 rowset、部分批次、过期和重试；核对最终 delete bitmap 完全一致。

## PERF-010：上报全局读锁覆盖分片任务排队和等待

**位置与调用链**：

- `fe/fe-core/src/main/java/org/apache/doris/catalog/TabletInvertedIndex.java:158–175`
  持全局 StampedLock 读锁执行 `processTabletReportAsync()`。
- 第 218–256 行复制 entries、向共享 taskPool 提交分片并等待 allOf/join；等待期间读锁未释放。
- 第 310–350 行等路径对共享结果逐条 synchronized；增删副本第 838–879 行需要同一个锁的写锁。

**负载与代价**：大量 tablet、多个 BE 同时上报、副本调度频繁。线程池排队时间也变成元数据写锁
等待时间；同一报告分片产生很多同步/迁移项时，共享容器锁又会限制并行度。
这是源码确定的锁范围，尚未测到该部署的具体锁等待占比。

**优化方向**：先用每分片局部结果、完成后集中合并，降低逐条争抢；再评估带版本校验的短锁快照
和分批应用。现有过程会读写 Replica 状态，不能仅把 readUnlock 提前而不补一致性协议。
不要只增大 worker 数，把更多工作堆到同一全局锁和共享线程池上。

**验收**：报告处理/排队 P95、写锁等待、线程池队列、同步阻塞事件、FE 分配与 GC；
同时核对副本增删、版本更新、publish/clear 任务集合，确保报告没有漏项或用过期元数据覆盖新状态。

## 正确性前置：事务版本通知被覆盖

本轮额外发现 `PublishVersionDaemon.tryFinishTxnSync()` 在第 272–273 行重置实例累计 map，
覆盖同轮其他事务的 BE 可见版本通知；并行路径还会绕过 map 的锁协议。
已编译当前生产类，使用不联网的事务管理器替身连续完成两个事务，实际累计分区由 `{101}`
变为 `{202}`，应为 `{101,202}`。

这会使 BE 用于 compaction 的可见版本滞后，可能延后合并、增加 rowset 保留，
通常依赖后续 tablet report 补齐。不能由此断言永久数据丢失或成功事务必然无法查询。
详见 `docs/bug-audit-20260907.md` 的 **BUG-005**。
应先修复为每事务局部 map，再在现有锁内合并；无需把整个事务完成过程放入全局锁。

## 已存在的优化与未列入项

- `ReportHandler` 已按 backend/type 去重并使用 worker 分片，不能再次报告“仍然单线程、不去重”。
- `Env.getPartitionIdToStorageMediumMap()` 已有默认 60 秒缓存和互斥重建，不能声称每次报告都全量重建。
- Compaction score 已缓存；PERF-008 针对磁盘维度的重复遍历。
- 统计冷缓存提前返回、全局 AgentTaskQueue 锁和逐行有序归并值得 profile，但本轮没有额外凑成确认优化项。
- JDBC JSON 反复转换虽可继续评测，本轮优先扩展到上述其他功能；先前数组正确性问题仍应先修。

## 验证记录和建议落地顺序

本轮没有运行全量回归或生产负载压测，没有声明整体 QPS、P99 或成本能改善某个百分比。
算法模型仅验证局部工作量；局部耗时也不能直接外推成完整 SQL 耗时。

建议先修 BUG-005 及影响目标负载的其他正确性问题；随后从 PERF-001/003/005 这类边界清晰的
局部算法开始，与文件缓存和 HeapSort 的专项改动分别评测。Cloud 项仅在存算分离部署评测，
上报锁范围重构在采集 profile 后再推进。

每项验收均先核对结果一致性，再比较同机器、同数据、同配置、同缓存冷热状态下的耗时、CPU、内存；
包含 P95/P99 与资源消耗，不只看平均时间。功能回归、错误路径和并发验证应随实际修复加入对应 FE/BE 测试。

当前机器证据包括：

- `/tmp/massdb-fe-perf-audit-20260907/`：`InferBench.java`、运行脚本、环境与测量结果。
- `/tmp/massdb-performance-selection-count-20260907.cpp`：排序选择算法对照。
- `/tmp/massdb-publish-audit-20260907/`：真实发布方法的离线复现源程序与结果。

上述源码和文本记录另归档于忽略目录 `.build-records/performance-audit-20260907.tar.gz`。
关键输入、测量口径和结果已写入本文；文档是本轮交付物，归档是本机可复查的辅助材料。
