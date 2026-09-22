<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# MassDB SQL 深度性能审查：查询、写入、并发与长期运行

日期：2026-09-21。源码 HEAD：`59329855b4e62497d927f3ccd547b866a190a0fc`。

本轮发现 **6 项新增、可定位到当前源码的优化候选**。优先关注混合窗口聚合退化、
JSONB 逐行解析器分配，以及高并发调度的共享计数器；结合先前仍未修复的缓存淘汰、
FE 规划和会话/事务清理问题，形成覆盖四类负载的实施顺序。

本轮交付源码审查和隔离对照程序，未修改数据库执行实现。局部测试在 Apple Silicon
的 aarch64 Linux 虚拟机上完成，不是鲲鹏服务器，也不是端到端 SQL 压测。
测试时另有 BE 编译在运行；保留了每组 5 次原始样本、墙钟时间和进程 CPU 时间。
**以下局部加速比不能作为 MassDB 整体性能提升承诺。**

## 1. 哪些是新增机会

| 编号 | 场景 | 当前缺口 | 建议与收益边界 |
| --- | --- | --- | --- |
| DEEP-001 | 同一 ROWS 窗口计算 SUM/AVG 与 COUNT 等 | 整个算子共用一个增量支持标志；COUNT 关闭 SUM 的增量路径 | 优先；宽滑动窗口可减少大量重复计算 |
| DEEP-002 | 滑动窗口 MIN/MAX，单调或重复值 | 最值滑出就重算全窗，最坏 O(NW) | 按分布选择算法；随机数据原路径可能更快 |
| DEEP-003 | JSONB 转换、JSON 列反序列化 | 外层对象复用，但内部逐行创建 simdjson parser 与 padding 字符串 | 优先验证 JSONB 密集查询/导入；小文档较有利 |
| DEEP-004 | ARRAY 列筛选后的按 rowid 取值 | 每个选中行都 seek，再 next_batch(1) | 按数组负载验证批读；普通连续扫描已有快路径 |
| DEEP-005 | 多核、高频 pipeline 入队/出队 | 各队列更新同一个全局原子指标 | 先 profile，再分片计数；局部争用实测成立，QPS 收益未测 |
| DEEP-006 | BE 文件缓存 LRU 恢复 | protobuf 每消费一项便 erase(begin)，搬移剩余指针 | 恢复优化；不计为稳态查询吞吐收益 |

这里的“当前缺口”按实际调用路径判定，不表示整个模块没有优化。未将依赖库中已有
SVE 文件、已有 NEON/CRC、普通 SUM 增量、哈希预取重复计为新机会。

## 2. DEEP-001：一个 COUNT 让同窗 SUM 退回整窗扫描

**调用链已经核实：**

- [窗口分组规则](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/rules/implementation/LogicalWindowToPhysicalWindow.java:146)
  按 PARTITION BY、ORDER BY、frame 相同合并表达式，兼容性判断在同文件第 345 行附近。
- [计划翻译](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/glue/translator/PhysicalPlanTranslator.java:2612)
  将该组函数一起下发。
- [BE 初始化](/data/project/massdb-sql/be/src/pipeline/exec/analytic_sink_operator.cpp:140)
  对全部函数执行 `_support_incremental_calculate &= supported_incremental_mode()`。
- [滑动 ROWS 执行](/data/project/massdb-sql/be/src/pipeline/exec/analytic_sink_operator.cpp:205)
  标志为 false 时，每行 reset 全部聚合状态，再执行整个 frame。
- [SUM](/data/project/massdb-sql/be/src/vec/aggregate_functions/aggregate_function_sum.h:225)
  已支持增量；[COUNT 两个实现](/data/project/massdb-sql/be/src/vec/aggregate_functions/aggregate_function_count.h:179)
  都没有覆盖增量支持接口，继承基类的 false。COUNT(*) 自身可直接按区间长度计数，
  但它仍会让同窗 SUM 扫描 W 个元素；可空 COUNT 在有 NULL 时也扫描窗口。

触发 SQL 的形状如下。`t` 应有多行分区，避免规划器把单行分区窗口直接简化掉：

```sql
SELECT
    SUM(v) OVER (
        PARTITION BY p ORDER BY seq
        ROWS BETWEEN 1023 PRECEDING AND CURRENT ROW),
    COUNT(*) OVER (
        PARTITION BY p ORDER BY seq
        ROWS BETWEEN 1023 PRECEDING AND CURRENT ROW)
FROM t;
```

N 行、窗口宽 W 时，SUM 从增量 O(N) 退回 O(NW)。N=100,000、W=1,024 的
独立整数 SUM 对照中，重扫循环 **10.365 ms**，滚动加减 **0.066 ms**。
这是 SUM 循环模型，不包含 COUNT、排序、表达式调度或真实 SQL；只说明重复工作的量级。

**建议：**先给 COUNT(*)、COUNT(nullable) 实现增量路径，解除常见 SUM+COUNT 组合的退化；
再按函数保存增量能力，避免其他必须重算的聚合拖慢整组。后者只应重置需要重算的状态。
顺便缓存 `_execute_for_function()` 内每行重新构造的参数指针 vector，可作为后续小优化。

**验收：**比较单 SUM 与 SUM+COUNT 的计划及 ComputeAggDataTime；覆盖 NULL、空窗口、
PRECEDING/FOLLOWING、跨 block、分区切换、SUM 溢出及 decimal/浮点语义。
本轮尚未运行上述 SQL 的集群 A/B。

## 3. DEEP-002：MIN/MAX 增量算法存在特定分布下的退化

[当前 MIN/MAX](/data/project/massdb-sql/be/src/vec/aggregate_functions/aggregate_function_min_max.h:860)
已实现增量模式。问题是离开窗口的元素等于当前最值时，第 877 行之后 reset，并扫描全窗。

升序值上的滑动 MIN、降序值上的滑动 MAX，以及大量相等值，会频繁触发这个分支；
即使窗口中还有很多相同最值也会重扫。最坏 O(NW)。

可以使用单调队列维护候选位置，将相应情况降到摊还 O(N)，额外保存 O(W) 个候选。
但不能直接替换所有输入：本轮 N=100,000、W=1,024、无 NULL 的 int64 MIN 模型结果为：

| 输入分布 | 当前最值过期重扫模型 | 单调队列模型 | 判断 |
| --- | ---: | ---: | --- |
| 递增 | 20.180 ms | 0.177 ms | 重复扫描明显 |
| 全部相等 | 20.154 ms | 0.157 ms | 重复扫描明显 |
| 固定种子随机 | 0.091 ms | 0.550 ms | 单调队列反而约慢 6 倍 |

所有输出逐行比较一致。真实实现还含列访问、可空包装和聚合状态管理，表中不是 BE 算子耗时。

**建议：**先支持明确数据类型，依据重算频度/已扫描元素预算切换，或对重复值单独维护
最值计数，保留低成本原路径；评估切换初始化和额外内存。覆盖 NULL、NaN、字符串生命周期、
相同值比较语义，以及窗口缓冲列裁剪后的下标更新。不能仅用单调数据验收。

## 4. DEEP-003：JSONB 解析器仍按行创建

[function_jsonb.cpp](/data/project/massdb-sql/be/src/vec/functions/function_jsonb.cpp:291)
虽然在循环外创建 `JsonBinaryValue`，并注释 parser 可复用，但
[JsonBinaryValue::from_json_string](/data/project/massdb-sql/be/src/runtime/jsonb_value.h:59)
进入 [JsonbParser::parse](/data/project/massdb-sql/be/src/util/jsonb_parser_simd.h:87) 后，
第 93、94 行仍分别创建 `simdjson::ondemand::parser` 和复制输入的 `padded_string`。

[字符串 CAST 路径](/data/project/massdb-sql/be/src/vec/functions/cast/cast_to_jsonb.h:158)
还每行新建外层 JsonBinaryValue；
[JSONB SerDe](/data/project/massdb-sql/be/src/vec/data_types/serde/data_type_jsonb_serde.cpp:91)
也调用相同解析链。适用于经过这些转换的查询/写入，不能扩大为“所有 JSON 导入都逐行新建 parser”。

使用仓库依赖目录中的真实 simdjson 静态库，对 100,000 个整数数组 JSON 完整遍历所有元素：

| 每文档元素数 | 每行新 parser 与 padded_string | 只复用 parser | parser 与 padding 缓冲均复用 |
| --- | ---: | ---: | ---: |
| 16 | 11.674 ms | 8.715 ms | 8.294 ms（耗时约降 29%） |
| 128 | 56.114 ms | 51.720 ms | 51.708 ms（耗时约降 8%） |

三种路径校验结果一致；复用缓冲仍逐行 memcpy，未通过省略复制或不消费 JSON 制造加速。
测试没有 JSONB writer、复杂对象、错误处理和列插入，不能直接推导导入 rows/s。

**建议：**把 parser 和可增长 padding 缓冲放到表达式/执行线程/批次所属状态中，避免共享
可变 parser。CAST 可同时复用 writer。为偶发超大行设置缓冲回收策略，避免把短期节省变成长驻内存。
保持数字精度、128 位数、嵌套值、错误行策略及返回数据生命周期。

## 5. DEEP-004：ARRAY 按 rowid 读取仍逐行 seek

[ArrayFileColumnIterator::read_by_rowids](/data/project/massdb-sql/be/src/olap/rowset/segment_v2/column_reader.cpp:1648)
对每一行调用 `seek_to_ordinal(rowids[i])` 和 `next_batch(1)`。
而同类 `next_batch` 已能批量读取 offsets 和 items。

[SegmentIterator 延迟取列路径](/data/project/massdb-sql/be/src/olap/rowset/segment_v2/segment_iterator.cpp:2279)
会调用此接口。目标是过滤后读取 ARRAY 投影、且 rowid 仍有连续段的负载。
[普通扫描](/data/project/massdb-sql/be/src/olap/rowset/segment_v2/segment_iterator.cpp:2010)
已有整批及子批连续性判断，不能将它们算作尚无批读。

**建议：**先合并连续 rowid 段，以一次 seek+next_batch 读取每段；再评估批量读取 offsets、
合并 items 范围。N 个选中行、R 个连续段，迭代器 seek 调用可由 N 降至 R。
这不等于磁盘 I/O 也缩小 N/R：页面缓存及完全随机、稀疏 rowid 会改变收益。

**验收：**记录实际 rowid 连续段长度、列读取 CPU、解压与 seek 次数；分别测热/冷缓存、
稀疏/成段选择、NULL/空数组/嵌套数组及跨页边界。保留输入顺序和重复 rowid 语义。
本项本轮仅完成调用链确认，未量化真实读取收益。

## 6. DEEP-005：分队列之后仍共享一个高频原子指标

[PriorityTaskQueue](/data/project/massdb-sql/be/src/pipeline/task_queue.cpp:81)
每次出队都更新 `DorisMetrics::pipeline_task_queue_size`，第 131 行每次入队也更新它；
所有队列使用同一个 [IntCounter](/data/project/massdb-sql/be/src/util/doris_metrics.h:254)。
[AtomicMetric::increment](/data/project/massdb-sql/be/src/util/metrics.h:88)
调用没有指定 memory_order 的 `fetch_add`，使用默认顺序。

这使原本独立的工作队列仍共享一个需要修改的缓存行，而且更新处位于各自的队列锁内。
短任务频繁阻塞、唤醒、重新入队时比长时间连续执行更值得关注。

以相同默认原子顺序，比较全局计数器与 128 字节隔离的线程私有计数器：

| 线程数 | 原子更新总次数 | 全局计数器 | 分片计数器 |
| --- | ---: | ---: | ---: |
| 1 | 1,000,000 | 1.681 ms | 1.679 ms |
| 4 | 4,000,000 | 23.853 ms | 1.744 ms |

每个线程交替加一、减一，最终和校验为零；线程创建在计时区外，用 barrier 同步起止。
四线程进程 CPU 时间中位数分别约 94.485/6.710 ms。测试是原子争用模型，
没有执行真实 pipeline 或模拟实际任务间隔，不能把局部约 13.7 倍称为 QPS 提升。

**建议：**先采样验证调度路径所占比例。若值得优化，复用每队列已有计数或分片指标，
在采集时汇总；测量汇总开销并定义采样一致性。单纯更改原子内存顺序不能消除缓存行争用，
也不应批量放松业务同步操作。没有在本轮修改任何内存顺序。

## 7. DEEP-006：LRU 恢复有可消除的 protobuf 指针搬移

[CacheLRUDumper::parse_one_lru_entry](/data/project/massdb-sql/be/src/io/cache/cache_lru_dumper.cpp:408)
读取组内第 0 项后，在第 447 行 `erase(begin)`。依赖的 protobuf repeated pointer 容器
会移动后续指针；组元数据第 436 行也使用相同模式。

[写入分组](/data/project/massdb-sql/be/src/io/cache/cache_lru_dumper.cpp:158)
每 10,000 项 flush 一组。因此 G 项组内累计搬移 G(G−1)/2 个指针；固定组大小时，
总 N 项成本为 O(NG)，不能泛称整个文件无界 O(N²)。
[初始化](/data/project/massdb-sql/be/src/io/cache/block_file_cache.cpp:452)
持缓存锁恢复各队列；本项主要改善启动/恢复时间。

使用本仓库生成的 `file_cache.pb.cc` 和实际 protobuf 静态库，10 组×10,000 项：
原逐项头删 **145.914 ms**，索引游标遍历 **2.454 ms**。两边均复制每项消息并包含对象
销毁时间，输入组构造不计时；四个业务字段累加结果一致。
测试不含文件读、checksum、反序列化和 `add_cell`，不是完整 BE 启动提速约 59 倍。

**建议：**用 entry/group 游标消费，组耗尽后统一复用或清理；保留文件格式和恢复次序。
验收损坏文件、空组、跨组、跨队列重复、TTL 及解析失败清理。

## 8. 已有审查中仍应优先处理的问题

以下不是本轮“新增发现”。本轮复核了相关源码；先前实测数字来自各自报告及归档，
没有把它们写成本轮重新压测的结果。

| 目标 | 仍存在的问题 | 对整体性能的价值 |
| --- | --- | --- |
| 综合查询与高并发规划 | PERF-001：不等式推导对全部顶点做 Floyd 三重循环 | 宽表/生成 SQL 可被 FE 规划 CPU 卡住；先按关系图连通分量缩小计算 |
| 综合查询 | PERF-003/004：TOPN 聚合全量排序；HEAP_SORT 全批排序/复制后丢弃 | 小 K、大基数、宽行时值得优先验证，保留 NULL 与多列排序规则 |
| 存算分离、高并发与后台淘汰 | PERF-002：删一个缓存块就遍历剩余目录 | 同目录反复枚举，且部分路径持缓存锁；优先改批量回收/仅删除空目录 |
| 高频小批导入 | PERF-006：Group Commit 按 tableId 找表仍遍历各数据库 | 多库场景减少 FE 重复元数据工作；需处理表删除和缓存失效 |
| 多盘、多 tablet 写入 | PERF-008：compaction 选任务按每块盘重复扫描全体 tablet | 减少后台 CPU/锁压力，按盘维护候选；已有 score cache 不能重复计收益 |
| 长连接长期查询 | MEM-007：resultAttachedInfo 按返回批次追加，没有执行级释放 | 历史批次数越多，占用越大；null 占槽但不是保留完整结果集 |
| 持续高频写入 | MEM-008：Short 事务耗尽清理额度，Long 持续积压 | 改清理公平性，避免保留对象及 GC 压力增长；压力下降后原实现能够补清 |
| 连接池长期复用 | MEM-020：COM_RESET_CONNECTION 未释放 prepared statements | 防止复用后的计划保留和容量耗尽，需要真实驱动循环验证 |

详细证据见 [主要链路性能审查](/data/project/massdb-sql/docs/performance-audit-20260907.md)
和 [FE 内存/GC 审查](/data/project/massdb-sql/docs/fe-memory-gc-audit-20260907.md)。
例如前者用当前 Java 方法测到 512 个独立比较条件的闭包计算约 724 ms；后者用真实类
确认 100,000 次 null 附加信息追加后列表仍有 100,000 项。这些属于之前的隔离方法测量。

长期运行的优先目标是稳定回收后的堆基线、清理队列年龄和查询 P99；仅改 GC 选项不能
解决仍被业务对象引用的历史状态。清理附加信息时要保留 Export 等消费者的合法使用期限。

## 9. ARM/鲲鹏层面：已有优化与后续实验

这六项主要是算法、对象复用、批读和并发结构优化，不增加 SVE/SVE2 指令集要求。
可以在鲲鹏 920 这类 ARM 服务器上实现，也可惠及 x86。
官方 FAQ 明确列出鲲鹏 920 7260 不支持 SVE、5250 使用 128 位 NEON；具体服务器应记录
完整 CPU 型号与系统特性，不能只按“920 系列”推断所有后续型号能力。
参见 [鲲鹏硬件 FAQ](https://www.hikunpeng.com/document/detail/en/kunpengfaq/productfaq/hardwarefaq/hardware_faq_0001.html)。

当前版本已经有：

- NEON 位图/过滤相关基础操作与 IF 特化，见
  [bits.h](/data/project/massdb-sql/be/src/util/simd/bits.h:34)、
  [if.h](/data/project/massdb-sql/be/src/vec/functions/if.h:93)。
- ARM CRC 哈希与 libdivide NEON；[CMake](/data/project/massdb-sql/be/CMakeLists.txt:369)
  使用 ARM_MARCH，当前构建为 `-O3 -march=armv8-a+crc`。
- [哈希表预取](/data/project/massdb-sql/be/src/vec/common/hash_table/hash_map_context.h:112)，
  默认预取距离为 16；优化点应是针对目标 CPU/负载调距，而非“从无到有加预取”。
- 当前 Clang 20.1.8 编译探针及已检查的任务队列对象包含 `__aarch64_ldadd*` 等 outline
  atomic helper，不能仅因 march 是 armv8-a 就断言没有 LSE 运行时路径。
  helper 的运行时分派原理可参见
  [GCC AArch64 文档](https://gcc.gnu.org/onlinedocs/gcc/AArch64-Options.html#index-moutline-atomics)。

两项值得在目标服务器继续实验、但本轮没有测得整机收益的方向：

1. **NUMA 感知调度与内存放置。** [CpuInfo](/data/project/massdb-sql/be/src/util/cpu_info.cpp:209)
   已识别 NUMA；[任务窃取](/data/project/massdb-sql/be/src/pipeline/task_queue.cpp:176)
   仍按队列编号轮询，未按 NUMA 距离优先。可评估同节点优先、跨节点兜底、工作线程亲和性
   与分区数据首次触页配合。不能只绑定 CPU 却忽略内存分配或牺牲负载均衡。
   官方 FAQ 提供了鲲鹏多 NUMA 节点实例；本地单 NUMA 虚拟机无法验证其收益。
2. **PGO，以及单独验证 ThinLTO。** 当前主 BE 构建 flags 未发现 profile-use 或 flto。
   先以查询、导入、后台任务混合负载采集 profile，再评估 CPU、代码体积及链接内存。
   [Clang PGO 文档](https://clang.llvm.org/docs/UsersManual.html#profile-guided-optimization)
   强调训练输入要有代表性；不能用单条 SQL 的结果承诺普遍增益。

## 10. 排除或降级的线索

- **普通 RANGE 后缀窗口不是本轮确认的平方级缺陷。** BE `_get_next_for_range_between`
  确实逐行 reset/重算，但 FE
  [WindowFunctionChecker](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/rules/analysis/WindowFunctionChecker.java:462)
  会反转 `CURRENT ROW .. UNBOUNDED FOLLOWING` 的排序与边界，进入已有前缀路径；
  第 165 行还拒绝普通带 offset 的 RANGE。本轮曾测量 suffix 扫描模型，原始数据保留，
  **因未证明正常 SQL 可达，明确不计入优化收益或新增清单**。
- 分区 TOPN 已有周期性裁剪，半连接已有提前停止，ASOF 已有分组排序索引，普通 ROWS
  SUM/AVG 已有增量路径；不能把模块名直接写成“尚未优化”。
- Exchange 的多 block 分支有复制，但当前 `_send_multi_blocks` 初始化为 false；
  未证明启用前，不作为当前热路径缺陷。
- ARRAY 倒排写入的 `keep_readers` 实际在每行末尾 clear，排除“整批无限保留 reader”的猜测。
- multicast spill 恢复数组头删确实存在，但缓存批次有 32 块/约 2 MiB 上限；未证明为显著热点，
  不与 LRU 的 10,000 项分组等量看待。

## 11. 实施顺序与整体验收

建议第一批按生产 profile 选择：**混合窗口 COUNT 增量、缓存淘汰去重复列目录、JSONB parser
复用**；宽表自动生成 SQL 同时优先处理 FE 谓词推导。长期运行的会话状态与事务清理缺口也应
进入首批，它们影响持续负载后的性能稳定性。

第二批处理 MIN/MAX 自适应、ARRAY 批读、TOPN 候选选择以及调度指标分片。
LRU 游标改动适合独立的小范围恢复优化。NUMA、PGO 需要目标机器验证后再确定优先级。

| 负载 | A/B 应保持一致的条件与主要指标 |
| --- | --- |
| 综合查询 | 相同数据与计划、热/冷缓存分开、结果核对；planning/执行时间、CPU、P50/P95/P99 |
| 导入写入 | 相同批大小/并发/索引/持久性；rows/s、MB/s、CPU/GB、提交 P99、flush 与 compaction 积压 |
| 高并发 | 并发逐级增加，同时报告完成吞吐、排队及 P99；不能只测单 SQL 延迟 |
| 长期运行 | 固定连接数与数据规模的反复查询/写入，观察回收后堆、会话对象数、过期事务年龄与 GC CPU；建议 24–72 小时持续验收，再按实际运行周期延长 |

局部与整体收益按热点占比估计：总加速比约为 `1 / ((1-f) + f/s)`，其中 f 是改动前
该热点占总耗时比例，s 是局部加速比。例如占 40% 的热点快 10 倍，总体约快 1.56 倍；
若只占 1%，即使无限加速也约快 1.01 倍。这是算例，不是本轮整机结果。

本轮完成了源码路径复核、90 个算法/库样本和 20 个原子计数样本，并核对局部结果。
未执行数据库回归、鲲鹏整机压测或长期运行试验；这些属于实现后的验收工作。

## 12. 复现材料

[隔离探针及原始结果归档](/data/project/massdb-sql/.build-records/performance-deep-audit-20260921.tar.gz)
包含 `probe.cpp`、`atomic_probe.cpp`、构建说明、源码指纹、环境、JSONL 样本和汇总。
`probe.cpp` 链接当前安装的 simdjson/protobuf；窗口与原子测试是从已确认行为构造的独立模型。
报告中的时间为 5 次交替/轮换运行的墙钟中位数，未做核心绑定。

只有窗口模型逐行比较了结果向量；JSON、LRU 和原子探针校验的是各自的消费校验值/最终计数。
这些校验不替代 SQL 全类型、并发、错误路径及生命周期测试。
