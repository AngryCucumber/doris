# MassDB SQL rc415 代码审查（2026-10-28）

## 审查范围与结论

审查对象是分支 `2.1.5`（`49f67bdbb94`）相对于 tag `4.1.5-release` 的全部改动：
19 个提交、186 个文件，merge-base 即 tag 本身（`917b20be838`），分支不落后于 tag。
审查重点是功能性代码（`fe/fe-core`、`fe/be-java-extensions`、`be/src`、`cloud/src`、
`gensrc/script`、`ui/src`、回归框架与用例），法务、品牌资源和构建脚本只做了功能相关
部分的抽查。本文经过四轮核对：第一轮静态阅读，后三轮对前一轮结论逐条复核，用抽取
源码方法的隔离程序、真实连接池和受控线程交错做方法级验证，并补充遗漏。

结论：核心修复逻辑（report 队列去重与并行消费、group-commit 兜底、`build_basic_info`
幂等化、`BeIdComparator` 溢出修正、`meta_tool` 独立运行初始化）没有发现会导致数据错误
或崩溃的阻断性问题。本次合并引入或放大的问题中，需要处理的是 1 条性能问题、1 条并发
异常、1 条解析健壮性问题和 1 条 UI 资源地址错误，另有 5 条可用性、清理与规范问题。
此外发现 8 条继承自 4.1.5 的问题，其中 2 条涉及写入或查询结果正确性、2 条是并发修改
异常、1 条是取消机制缺口、1 条是连接池互等，本次合并没有引入也没有修复，单独列出。
测试改动均为让断言更精确或修正用例自身错误，没有发现放宽断言掩盖产品问题的情况。

按维护者指示，本文不展开以下两条已知事项，另行跟踪：
- `version_comment` 不再包含 `doris` 标识对外部工具识别的影响；
- Cloud compaction 路径（`be/src/storage/compaction/compaction.cpp:1866`）未同步
  `_is_vertical` 限制。使用 Cloud 模式且关闭垂直 compaction 时仍需单独处理。

## 问题归属：上游代码还是本分支提交

`4.1.5-release`（`917b20be838`）是上游 Apache Doris 的发布提交（作者 yiguolei，
`add 4.1.5 release (#68884)`），不含任何本分支改动。因此判定规则是：责任代码行在
`4.1.5-release` 中已存在的归上游；只在本分支 19 个提交中出现的归本分支。每条问题的
责任行均已用 `git blame` 和 `git merge-base --is-ancestor` 核对。上游后续版本是否已
修复这些问题，本文未核查。

| 编号 | 问题 | 归属 | 依据 |
| --- | --- | --- | --- |
| 1 | storage medium 缓存重建阻塞全部 worker | **本分支** | 全局构建锁、版本号与 `nextCooldownTimeMs` 逻辑来自 `8ee56df0ae4`、`8649f5f332e`；被包裹的无超时 `olapTable.readLock()` 是上游 2021 年代码（`f7730031b8e`），但在单线程下只阻塞自己 |
| 2 | 冷却副本检查并发修改异常 | **混合，本分支需修** | 无锁遍历 `replicaMetaTable` 是上游 branch-4.1 代码（`f7a4908b3d9`，#61455）；使其可被并发触发的多 worker 由本分支 `8ee56df0ae4` 引入 |
| 3 | DECIMAL 元素解析缺少防护 | **本分支** | 新增分支来自 `2b9869f8e1a` |
| 4 | UI 路由探测把同名库表段当作部署前缀 | **本分支** | `378493ca85f`、`780c640c987` 重写了 `index.html` 脚本；4.1.5 原脚本解析正确 |
| 5 | group-commit RPC 超时过长 | **本分支（残留）** | deadline 由 `52f961ee745` 新增；4.1.5 原代码完全没有超时，本分支是改善但不彻底 |
| 6 | 回归框架本地拷贝缺少转义 | **本分支** | `8649f5f332e` |
| 7 | AgentTaskCleanupDaemon 不可达分支 | **本分支** | `52f961ee745` |
| 8 | HardwareInfoController 死代码 | **本分支** | `378493ca85f` |
| 9 | 无代码差异文件带修改声明 | **本分支** | `780c640c987` 等法务提交 |
| P1 | UDF 解析变化后 SQL 缓存返回旧结果 | **上游** | `prefer_udf_over_builtin` 与缓存命中检查均在 4.1.5 中存在，本分支未触及 |
| P2 | 预编译 group-commit 复用首次规划时间与设置 | **上游** | 复用条件来自 `75ef6bd0b88a`（2025-01，group commit full prepare） |
| P3 | 预编译 group-commit 的 KILL QUERY 不取消 RPC | **上游** | 同 P2 的执行路径；`StmtExecutor.cancel` 为上游代码 |
| P4 | `findUdfBuilder` 返回可变列表 | **上游** | `c9a99ce171e7`（2023-07，#18257） |
| P5 | JDBC 获取列信息嵌套借两条连接 | **上游** | `eaaf5b4b3731`（2024-11）；4.1.5 中两处 `getConnection()` 相同 |
| P6 | TIMESTAMPTZ 列不受支持 | **上游** | 4.1.5 的 `dorisTypeToDoris` 同样没有该分支 |
| P7 | ARRAY<VARBINARY> 执行器不支持 | **上游** | 4.1.5 的 `getListTypeForArray` 同样没有该分支 |
| P8 | 树节点并发加载丢失表列表 | **上游** | `c5b034acc484`（2020-11，#4830）；本分支对该文件只改样式 |
| 另行跟踪 | `version_comment` 不含 `doris` | **本分支** | `2b9869f8e1a` |
| 另行跟踪 | Cloud compaction 缺少 `_is_vertical` 防护 | **混合** | 水平 compaction 丢索引是上游缺陷；本分支 `7fa1170075c` 只修了本地路径，Cloud 路径遗漏 |

汇总：本分支提交引入 9 条（含 1 条残留改善和 1 条混合），上游代码带来 8 条，另行
跟踪的 2 条分别为本分支与混合。本分支的 9 条中，第 1 到 4 条需要修复；上游的 8 条中
P1、P2 涉及结果正确性，建议单独排期并同时考虑向上游报告。

## 本次合并引入或放大、需要处理的问题

### 1. storage medium 映射缓存重建会阻塞全部 report worker（性能）

位置：`fe/fe-core/src/main/java/org/apache/doris/catalog/Env.java:5146`、`:5205`、`:5216`、`:5276`
来源提交：`8ee56df0ae4`、`8649f5f332e`

缓存重建分三个问题：

**a. 重建持有全局构建锁时，对每张表调用无超时的 `olapTable.readLock()`（`:5205`）。**
某张表长期持有写锁时，重建线程卡在该表的读锁上，其余 worker 全部卡在
`storageMediumMapBuildLock` 上。即使所有分区都是 HDD、完全没有冷却迁移，也会发生。
方法级验证（4 个 worker、受控线程交错）：持有表写锁期间，1 个 worker 等待读锁，3 个
等待全局构建锁，完成数 0；释放写锁后 4 个 worker 全部完成，共扫描 1 次。改动前单
report 线程在同一位置同样会阻塞，因此这不是新的阻塞点，但并行 worker 没有带来隔离：
被阻塞 worker 所负责 BE 的磁盘、任务上报也会一起排队。

**b. 快照发布后立即失效。** 扫描前记录 `PartitionInfo` 版本号，自身执行 SSD 到 HDD
迁移时调用 `partitionInfo.setDataProperty` 使版本号加一；同时第一遍扫描已把这些已过期
分区的 `cooldownTimeMs + 1` 记入 `nextCooldownTimeMs`，该值小于当前时间。两个条件任一
成立快照就失效，所以只抑制自身版本递增并不够。冷却迁移是一次性事件，代价是多一次
全量扫描，可以接受。

**c. 写锁获取失败时持续失效。** 已过期分区在 `tryWriteLockIfExist` 失败时保持 SSD，
`nextCooldownTimeMs` 持续小于当前时间，缓存在拿到写锁之前每次都重建。触发它需要该表
存在长读锁或锁竞争（因为长写锁会先在 a 处阻塞）。方法级验证：正常扫描 1 次；成功
冷却迁移后 2 次；写锁始终失败则连续 3 次调用扫描 3 次。

以上验证不是集群压测，不能据此给出 200 万 tablet 规模下的实际损失。

建议：
- 对表读锁改用带超时的 `tryReadLock`，超时则跳过该表。跳过会让本轮映射不完整：
  `checkStorageMediumMigration` 对 `null` 介质不做迁移判断，单轮影响有限，但该映射会
  按默认 60 秒 TTL 持续有效。因此被跳过的表必须进入重试机制：快照标记为不完整，
  `isValid` 对不完整快照使用更短的有效期（例如 1 到 5 秒）或在下一次调用时直接重建，
  并在日志中列出被跳过的表；不能只记录日志便认定影响可接受；
- `nextCooldownTimeMs` 只统计迁移阶段结束后仍为 SSD 的分区；对写锁失败的分区设为
  `now + 退避时间`（例如若干倍 `Table.TRY_LOCK_TIMEOUT_MS`）；
- **不能**改为"使用扫描结束时的版本号"，否则扫描期间其他线程对已扫描表的修改会被
  误判为已包含在快照中；
- `StorageMediumMapCacheTest` 增加"表写锁被占用时其他 worker 不被阻塞"、"被跳过的表
  在下一轮补齐"和"写锁失败不触发连续重建"用例。

### 2. 并行 tablet report 下冷却副本检查存在并发修改异常

位置：`fe/fe-core/src/main/java/org/apache/doris/catalog/LocalTabletInvertedIndex.java:139`、`:649`
来源提交：`8ee56df0ae4`（放大，无锁访问为上游既有）

`tabletReport` 在 `readUnlock(stamp)` 之后才调用 `handleCooldownConf`（`:139`，注释
说明是为了避免死锁）。`handleCooldownConf` 内部直接遍历 `replicaMetaTable.row(tabletId).values()`
（`:649`），这是 `HashBasedTable` 的可变视图。当上报包含有效冷却信息，同时另一个
report worker 对同一 tablet 执行 `deleteReplica`，遍历会抛出
`ConcurrentModificationException`。异常被 `consumeReportLoop` 的 `catch (Throwable)`
捕获，该次 tablet report 剩余的同步、删除、恢复等步骤全部中断，要等下一轮上报。
已用抽取的原方法和受控线程交错复现。改动前单 report 线程下这条路径不会与另一次
上报并发，本次引入多 worker 后成为可直接触发的并发路径。

建议：改用已有的持锁复制方法 `getReplicasByTabletId(tabletId)`（`:818`）取快照后遍历。

### 3. JDBC catalog 的 DECIMAL 元素解析缺少防护（健壮性）

位置：`fe/fe-core/src/main/java/org/apache/doris/datasource/jdbc/client/JdbcMySQLClient.java:461`、`:467`
来源提交：`2b9869f8e1a`

`dorisTypeToDoris` 新增的 DECIMAL 分支对括号内文本执行 `split(",")` 后无条件读取
下标 `[1]`；`dorisTypeLength` 则假设 `)` 是类型文本的最后一个字符。两处都没有防护，
也没有被捕获。

触发范围：Doris/MassDB 自身的类型输出（`Type.toSql`，`fe-common/.../Type.java:495`）
始终是 `decimal(p,s)` 形式，正常对接不会触发。只有远端输出 `DECIMAL(10)`（省略
scale）或 `)` 后带后缀的非规范类型文本时，才会抛出 `ArrayIndexOutOfBoundsException`
或 `NumberFormatException`，导致整张表的 schema 加载失败。改动前的代码读取 JDBC
元数据中的 precision/scale，不会因类型文本格式而失败。

建议：缺少 scale 时按 0 处理；用 `indexOf(')')` 截取而不是 `length() - 1`。顶层列解析
失败时可回退到 `fieldSchema.requiredColumnSize()` / `requiredDecimalDigits()`；**数组
元素不能回退**，因为递归使用的 `innerFieldSchema` 是外层列元数据的拷贝，其
precision/scale 属于外层列而不是元素，盲目回退会把显式报错变成错误的类型映射，
应改为返回 `UNSUPPORTED` 或明确报错。补充 `JdbcMySQLClientTest` 用例。

### 4. UI 路由探测把同名数据库段当作部署前缀，刷新后资源地址错误

位置：`ui/src/index.html:24` 到 `:32`
来源提交：`378493ca85f`、`780c640c987`

新的内联脚本把路径中**最后一个**匹配路由名称（`login`、`legal-notices`、`home`、
`Playground`、`System`、`QueryProfile`、`Session`、`Configuration`）的段当作应用路由
起点，其前面的所有段作为 `<base href>` 的部署前缀。数据库或表名与路由名相同时判断
出错：数据库名为 `home` 时访问 `/Playground/result/home`，`routeIndex` 落在 `home`
上，`base` 变为 `/Playground/result/`，入口脚本被解析为
`/Playground/result/main.<hash>.js`，正确地址应为 `/main.<hash>.js`。刷新或直接打开
该链接页面加载失败；名为 `Session`、`System` 等的库表同理。

`4.1.5-release` 的脚本只按路径段数量（大于 4 段时取前 5 段）判断前缀，同一路径解析
正确。已通过原脚本验证。

建议：不要凭路径段名称推断部署前缀。可选方案：由 webpack `publicPath` 或服务端注入
固定的 base；或只匹配第一个路由段（`routeIndex` 取首次命中即 `break`）；或保留 4.1.5
的段数规则，仅为新增的 `/legal-notices` 路由加特例。补充 `ui/scripts` 下的脚本级
测试覆盖 `home`、`Session` 作为库名的路径。

## 本次合并引入的可用性、清理与规范问题

### 5. group-commit RPC 超时在 BE 存活但挂住时过长（可用性）

位置：`fe/fe-core/src/main/java/org/apache/doris/planner/GroupCommitPlanner.java:167`
来源提交：`52f961ee745`

新增的 brpc deadline 使用 `ctx.getExecTimeoutS()`，对同步导入语句返回
`max(insert_timeout, query_timeout)`（`ConnectContext.java:1631`），默认可达 14400 秒。
gRPC 通道已配置 `keepAliveTime = grpc_keep_alive_second`（默认 10 秒）且
`keepAliveWithoutCalls(true)`（`OssBackendServiceClientChannelProvider.java:31`），
因此 BE 掉电、进程被杀等断连场景会在 keepalive 超时后较早失败，不会等满 4 小时。

真正的风险场景是 BE 进程存活、连接正常，但 group-commit RPC 处理挂住：此时 FE 线程
会阻塞到 insert_timeout 到期。持续负载下可能耗尽连接或执行线程。建议引入独立且较短
的 group-commit RPC 超时配置，而不是复用导入超时。单纯缩短超时不能替代取消支持，
取消缺口见 P3。

### 6. 回归框架本地拷贝分支缺少引号转义，主机解析可能提前失败

位置：`regression-test/framework/src/main/groovy/org/apache/doris/regression/suite/Suite.groovy:1447`、`:1467`
来源提交：`8649f5f332e`

`scpFiles` 新增的本地分支拼接 `cp -r -- ${files} ${filePath}`，没有像相邻的
mkdir/rm 分支那样使用 `quoteShellArgument`。路径含空格时会被 shell 拆分；拷贝失败
通常会被调用方断言捕获，不一定静默。当前仓库内所有调用方传入的都是普通路径，没有
依赖通配符展开，加引号不会改变现有语义。

`isLocalHostForUser` 在 scp 回退之前调用 `InetAddress.getByName`，仅在 SSH 配置中
定义的主机别名会被 Java DNS 解析拒绝并抛出 `UnknownHostException`，而原来通过 ssh
可以工作。建议对两个参数做引号转义，并把主机名解析失败视为"非本机"后继续走 scp。

### 7. AgentTaskCleanupDaemon 中不可达的空值分支

位置：`fe/fe-core/src/main/java/org/apache/doris/task/AgentTaskCleanupDaemon.java:76`
来源提交：`52f961ee745`

`PublishVersionTask` 已把 `succTablets` 默认初始化为空 map，setter 也做了空值归一，
因此 `getSuccTablets() == null` 永远为假。同一个 NPE 有三层重叠修复（字段默认值、
setter 归一、守护线程分支），使不变量更难推理。建议保留字段默认值，删除该分支及其注释。
低优先级。

### 8. HardwareInfoController 遗留死代码

位置：`fe/fe-core/src/main/java/org/apache/doris/httpv2/controller/HardwareInfoController.java:89`
来源提交：`378493ca85f`

`Processes` 行以注释形式禁用，但 `getProcesses()` 方法与相关 oshi 导入仍然保留且
无人调用。保留方法本身没有运行时采集开销。建议要么删除方法与导入，要么用配置项控制
该行是否展示。低优先级。

### 9. 无代码差异的文件带有修改声明

位置：
- `be/src/storage/index/inverted/query_v2/collect/multi_segment_util.h:17`
- `fe/fe-core/src/main/java/org/apache/doris/catalog/TabletInvertedIndex.java:17`
- `fe/fe-core/src/main/java/org/apache/doris/cloud/transaction/CloudGlobalTransactionMgr.java:17`
- `fe/fe-core/src/main/java/org/apache/doris/load/GroupCommitManager.java:17`
- `fe/fe-core/src/main/java/org/apache/doris/qe/Coordinator.java:17`
- `fe/fe-core/src/main/java/org/apache/doris/task/PublishVersionTask.java:17`

上述 6 个文件相对 `4.1.5-release` 的唯一差异是新增的一行
`Modified for MassDB SQL` 或 `Apache Doris backport` 声明，因为 4.1.5 已经包含
对应的上游 backport（#60652、#61555、#61881）。这些声明现在把未修改的上游代码标记为
本地修改或本地 backport，归属说明可以梳理。`MODIFICATIONS.md:371` 中
`multi_segment_util.h` 的旧路径位于明确标注的"Historical changes through bdd44bf2835b"
历史表中，不构成当前登记错误；`check-source-headers.py` 校验已通过。建议移除这 6 行
声明并同步 `dist/source-headers.json`，不强制。

## 继承自 4.1.5 的问题（本次合并未引入也未修复）

以下问题在 `4.1.5-release` 中同样存在，本次 diff 没有触及相关逻辑。列出的目的是
避免把它们误归因于本次合并，同时便于单独排期。

### P1. UDF 解析结果变化后 SQL 缓存仍返回内置函数的旧结果（正确性）

位置：`fe/fe-core/src/main/java/org/apache/doris/qe/SessionVariable.java:3652`、
`fe/fe-core/src/main/java/org/apache/doris/nereids/SqlCacheContext.java:161`、
`fe/fe-core/src/main/java/org/apache/doris/common/cache/NereidsSqlCacheManager.java:330`、`:607`、
`fe/fe-core/src/main/java/org/apache/doris/catalog/GlobalFunctionMgr.java:73`

有两条触发路径，根因相同：SQL 缓存的命中检查只比较表、数据、权限、使用到的变量和
标记为 `affectQueryResultInPlan` 的会话变量，不检查函数解析结果。

- **切换变量**：`prefer_udf_over_builtin` 会改变 `FunctionRegistry` 的函数解析结果，
  但其 `VarAttr` 只有 `needForward = true`，没有标记 `affectQueryResultInPlan`，因此
  不进入 `computeAffectQueryResultVariables` 的比较集合。先以默认设置缓存
  `SELECT abs(v) FROM t`，再切换该变量执行相同 SQL，预期走返回 `-1` 的同名 UDF，实际
  继续得到缓存中内置函数的 `1`。`MODIFICATIONS.md:84` 的基线验证记录已记载同一现象，
  且说明两个产品行为一致。
- **新增同名 UDF**：变量始终为 `true`，先在没有同名 UDF 时缓存查询，再 `CREATE FUNCTION`
  创建同名 UDF。函数解析结果已改变，但变量和表数据都没变。`GlobalFunctionMgr.addFunction`
  及其回放路径（`:73`）不触发 SQL 缓存失效，`tryParseSql`（`:330`）也不检查函数注册
  信息。库级 UDF 的注册路径同理。

本轮确认了两条代码链路，没有在集群复现。

建议：给 `prefer_udf_over_builtin` 加上 `affectQueryResultInPlan = true` 只覆盖第一条
路径。第二条路径需要记录函数解析所依赖的注册状态，而不只是"解析到的 UDF 签名"：
查询最初解析为内置函数时没有任何 UDF 签名可记录，只记签名覆盖不了"后来新增同名
UDF"。可行方案是在 `SqlCacheContext` 记录每个函数名在各作用域的查找结果（包括"无
UDF"），命中时重新查找比对；或在 UDF 创建、删除及其回放（全局与库级）时按作用域使
相关缓存失效。补充两条路径的用例。

### P2. 预编译 group-commit 复用计划时沿用首次规划的时间与会话设置（正确性）

位置：`fe/fe-core/src/main/java/org/apache/doris/planner/GroupCommitPlanner.java:217`、`:130`、
`fe/fe-core/src/main/java/org/apache/doris/nereids/load/NereidsStreamLoadPlanner.java:326`

`executeGroupCommitInsert` 复用 `preparedStmtCtx.groupCommitPlanner` 的条件只有表 ID
和 `baseSchemaVersion`（`:217`）。被复用的 `execPlanFragmentParamsBytes` 是首次规划时
由 `NereidsStreamLoadPlanner` 序列化的计划，其中 `TQueryGlobals` 带有当时的
`nowString`、`timestampMs`、`timeZone`（`:326`），`TQueryOptions` 带有当时的严格模式、
过滤比例，`StreamLoadTask` 带有当时的 group-commit 模式。4.1.5 的复用条件相同。

影响：同一个服务端 PreparedStatement 多次执行插入时，省略的 `DEFAULT CURRENT_TIMESTAMP`
列以及 `now()` 等函数沿用首次规划时间；执行期间修改 `enable_insert_strict`、
`insert_max_filter_ratio`、`group_commit` 模式或时区，后续执行仍按旧设置。已核对
FE 到 BE 调用链，尚未做集群写入复现。

建议：复用时每次刷新 `TQueryGlobals` 的时间字段（可在序列化前替换，或把时间字段从
缓存的计划中剥离出来按次填充），并把影响计划的会话设置纳入复用条件。

### P3. 预编译 group-commit 的 `KILL QUERY` 不会取消等待中的 RPC

位置：`fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/ExecuteCommand.java:158`、
`fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:1226`

`ExecuteCommand` 在 `enableGroupCommitFullPrepare` 下直接进入
`GroupCommitPlanner.executeGroupCommitInsert`（`:158`），没有普通查询的 `Coordinator`；
RPC 的 `Future` 是 `executeGroupCommitInsert` 内的局部变量。`StmtExecutor.cancel`
（`:1226`）只取消 `masterOpExecutor`、`Coordinator`、MySQL load 和 insert overwrite，
不接触这个 `Future`。对该连接执行 `KILL QUERY` 后，等待线程继续占用，直到 RPC 返回或
deadline 到期。方法级验证：调用取消后 `rpcCancelled=false`、`workerDone=false`。

建议：把 group-commit 的 `Future` 登记到 `StmtExecutor`（或 `ConnectContext`），在
`cancel` 中调用 `future.cancel(true)`。与第 5 条配合，才能真正限制挂住 RPC 的影响。

### P4. 查询解析与 UDF 重载注册并发时的并发修改异常

位置：`fe/fe-core/src/main/java/org/apache/doris/catalog/FunctionRegistry.java:254`、`:305`、`:316`

`findUdfBuilder` 在 `synchronized (name2UdfBuilders)` 内查找，但直接返回内部可变的
`ArrayList`；调用方（`:124`、`:144`、`:155`）在锁外遍历它。`addUdf`（`:305`）与
`dropUdf`（`:316`）在锁内对同一个列表 `add` / `removeIf`。一个连接正在匹配 `f(int)`
时，另一个连接创建 `f(int, int)` 或删除某个重载，原查询可能抛出
`ConcurrentModificationException`。已通过抽取当前查找、注册方法复现。

建议：`findUdfBuilder` 在锁内返回 `ImmutableList.copyOf(candidate)`。

### P5. JDBC 获取 Doris/MassDB 列信息时嵌套借用两条连接，单连接池必然超时

位置：`fe/fe-core/src/main/java/org/apache/doris/datasource/jdbc/client/JdbcMySQLClient.java:182`、`:404`

`getJdbcColumnsInfo` 持有一条连接读取 `DatabaseMetaData`（`:182`），`isDoris` 分支
在释放前调用 `getColumnsDataTypeUseQuery`，后者再 `getConnection()` 借第二条连接执行
`SHOW FULL COLUMNS`（`:404`）。第一条连接要等辅助方法返回才释放。4.1.5 的两处调用
相同（`:179`、`:401`）。

`connection_pool_max_size=1` 是允许的配置，此时无法加载 Doris/MassDB 远端表的
schema；容量较小时并发加载多张表也可能互等。已用抽取的原方法和真实 Hikari 连接池
复现：普通 MySQL 远端单连接成功；Doris 分支单连接超时；容量改为 2 后成功。

建议：`getColumnsDataTypeUseQuery` 复用外层传入的 `Connection`，不再自行借用。

### P6. 通过 JDBC catalog 读取 Doris/MassDB 的 TIMESTAMPTZ 列不受支持

位置：`fe/fe-core/src/main/java/org/apache/doris/datasource/jdbc/client/JdbcMySQLClient.java:477`

远端正常输出 `timestamptz` 或 `timestamptz(6)`（`Type.java:487`），但
`dorisTypeToDoris` 没有对应分支，映射为 `UNSUPPORTED`，相关列无法查询；数组递归得到
`ARRAY<UNSUPPORTED>`。4.1.5 原版的该方法同样没有 `TIMESTAMPTZ` 分支。已通过抽取当前
解析方法复现。

### P7. ARRAY<VARBINARY> 的 FE 元数据映射与执行器支持不一致

位置：`fe/fe-core/src/main/java/org/apache/doris/datasource/jdbc/client/JdbcMySQLClient.java:431`、
`fe/be-java-extensions/jdbc-scanner/src/main/java/org/apache/doris/jdbc/MySQLJdbcExecutor.java:383`

FE 接受 `ARRAY<VARBINARY(16)>`，但执行器 `getListTypeForArray` 的分派没有 `VARBINARY`，
抛出 `Unsupported column type: VARBINARY`。4.1.5 原版的执行器同样缺少该分支。触发范围
限于远端视图或外部来源暴露该类型；原生表不允许直接声明 VARBINARY 列，不能用普通建表
作为复现步骤。方法级异常已复现，视图到 JDBC 的完整链路仍待集成验证。

### P8. Playground 并发展开数据库节点会丢失先返回的表列表（UI）

位置：`ui/src/pages/playground/tree/index.tsx:104`

`onLoadData` 的异步回调使用请求发起时闭包捕获的 `treeData`，再
`setTreeData(updateTreeData(treeData, key, children))`。同时展开数据库 A、B：A 先返回
并写入表列表，B 随后基于捕获时的旧 `treeData` 更新，把 A 的表列表覆盖掉；Tree 组件
已把 A 标记为加载完成，重新展开也不会补加载。4.1.5 的同一函数相同（`:104`）。已用
原函数和受控响应顺序复现。本次合并对该文件的修改只涉及样式与品牌，没有触及该逻辑。

建议：使用函数式更新 `setTreeData(prev => updateTreeData(prev, key, children))`，并
让 `getRealTree` 基于更新后的状态派生（例如改为 `useMemo` 或在 effect 中同步）。

## 已审阅且未发现问题的改动

- **ReportHandler 去重与并行消费**（`8ee56df0ae4`、`f500cb3762f`）：`putToQueue` 在
  `reportTasks` 锁内先替换待处理 payload 再决定是否入队，`takeReportTask` 先 take 再
  在同一锁内取出并移除，两者组合下不会丢失最新 payload，也不会出现队列有 key 而 map
  无 task 的情况。分片按 `beId % worker` 保证单 BE 串行。`SystemInfoService.updatePathInfo`
  已加锁覆盖多 worker 并发写 `pathHashToDiskInfoRef`。`LocalTabletInvertedIndex` 的
  diff 线程池改用 `CallerRunsPolicy`，消除了 `DiscardOldestPolicy` 导致 future 永不完成的
  挂起风险。多 worker 带来的新并发路径见第 2 条。
- **compaction 计数器**（`7fa1170075c`）：`build_basic_info` 重置累加器并改用
  `COUNTER_SET`，新增单测覆盖 ordered 回退场景；这些 counter 没有其他写入点。
- **BeIdComparator**（`1126412ac6c`）：与上游 apache/doris#63565 一致。
- **meta_tool**（`4d5175a7958`）：`config::init(nullptr, false, false, true)` 与当前签名
  匹配；`DORIS_HOME` 只在未设置时回退为 `.`。
- **MySQLJdbcExecutor 数组解码**（`2b9869f8e1a`）：全局 Gson 改为
  `LAZILY_PARSED_NUMBER` 只影响 `List.class` 反序列化出的 `Object` 元素，现有分支均按
  `Number`/`String` 处理，带类型的 `listType` 路径不受影响；`DATETIME` 格式化器接受
  0 到 6 位小数，覆盖 MySQL 与 Doris 的全部精度。
- **版本号上报**（`2b9869f8e1a`）：FE 侧对 BE `version` 只做相等比较与展示，没有解析
  `doris-x.y.z` 的逻辑；`ExternalCatalog.DORIS_VERSION_VALUE`、Flight SQL 与审计日志
  仍使用 `DORIS_BUILD_VERSION`，与提交说明一致。
- **回归用例修正**：`test_drop_catalog_recycle_bin` 改为按 DbId 过滤并修正了 p111/p222
  前后不匹配的拷贝错误；`partition_col_stats` 通过新连接读取全局变量并在结束时恢复
  原值；`test_show_data_warehouse` 改用 `toLong` 避免溢出。

## 其他备注

- `dist/RELEASE-NOTES.txt:84` 记录：部署完整 Release 调试符号（`lib/debug_info/*.dbg`）
  在同机验证中使 BE RSS 增加约 300 到 400 MiB，其中包含可共享的文件映射。本轮未重新
  测量。精简包不含符号，栈回溯可能显示未解析地址。

## 审查方法

第一轮逐 hunk 阅读 FE/BE 功能性 diff 及其所在函数；对每个被删除或替换的行确认其约束
在新代码中的落点；对 `getPartitionIdToStorageMediumMap`、`invalidateStorageMediumMap`、
`construct_output_rowset_writer`、`versionComment`、`scpFiles` 等符号追踪了调用方与
被调方。后三轮对前一轮每条结论回到源码核对触发条件与旧行为，并与 `4.1.5-release`
同一位置比对以区分"引入"与"继承"；执行了源码头检查；用抽取当前源码方法的隔离程序
（桩对象、真实 Hikari 连接池、受控线程交错与受控响应顺序）验证了 DECIMAL 解析、数组
解码、缓存失效与锁阻塞、冷却副本遍历、UDF 查找注册、预编译 group-commit 取消、JDBC
嵌套借连接、UI 路由探测与树节点并发加载等逻辑。新增同名 UDF 的缓存问题和预编译
group-commit 计划复用问题目前是静态调用链结论。四轮均未执行完整 FE/BE 单测或集群
压测，结论不能用于量化线上发生频率和性能损失。
