<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# P0 基线：实际路径前提与证明

> **2026-09-24 范围收敛说明：** 本文保留原版路径与失败证据；当前实施及验收适用范围以[五出口执行计划](/data/project/massdb-sql/docs/license-certificate-execution-plan-20260922.md)为准。旧性能 JSON 的全部 26 项扩展矩阵不再作为功能开发前置条件，未经重新映射不能直接成为当前发布门槛。保留场景的正式数值精度、结果正确性及页面独立口径不降低，原失败和未执行项不改为通过。

适用于 LP001–007/009，源码基线 `23e39e63295fd730523da8d916c898c28b903216`。SET 成功、结果正确、运行变快均不足以证明命中特定路径。本记录补充[性能输入](/data/project/massdb-sql/docs/license-performance-cases-20260922.json)，不把普通扫描改名为短路/缓存通过，不把单 BE 模拟认作多 BE 扇出。

## 1. 短路点查及二进制预编译

[LogicalResultSinkToShortCircuitPointQuery](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/rules/rewrite/LogicalResultSinkToShortCircuitPointQuery.java:63)实际条件包括 `enable_short_circuit_query=true`、表 `light_schema_change=true`、Unique Key merge-on-write、`store_row_column=true`、无 Variant 列；逻辑形状是 ResultSink→可选Project→Filter→OlapScan，所有主键都由字面量等值条件覆盖。只设置开关和Unique Key不足以命中。

LP001/002 必须归档 SHOW CREATE TABLE 的三项表属性、同会话完整 EXPLAIN、实际执行结果和会话设置。EXPLAIN 中 [OlapScanNode](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/planner/OlapScanNode.java:1082)明确输出 `SHORT-CIRCUIT`。普通 Profile 不是必需短路证据：[StmtExecutor.isProfileSafeStmt](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:1011)为了点查性能主动不产生短路 Profile。应结合该计划标记、实际结果与条件一致的执行入口；若附RPC/指标观测，只使用已存在且实际可获取的指标，不假设存在未验证的点查计数器。

LP002 除上述前提，还要保存真实驱动 server-prepared 身份/COM_STMT_PREPARE/COM_STMT_EXECUTE 证据，在同一 PreparedStatement 上多次绑定不同主键执行。第一次建立 shortCircuitQueryContext，后续 [ExecuteCommand](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/ExecuteCommand.java:99)在schema版本一致且无非确定性函数时直达 PointQueryExecutor。不同连接每次重新 PREPARE 不证明同连接复用，客户端字符串代换不证明二进制协议。此分支不支持prepared命中普通SQL结果缓存。

2026-09-22 初次私有namespace只读probe归档 `.build-records/license-p0-p1-20260922/path-probes/point.log`：旧fixture未声明store_row_column，EXPLAIN没有SHORT-CIRCUIT，因此不能作为LP001或prepared短路复用的正证明。MariaDB驱动实例为 `org.mariadb.jdbc.ServerPreparedStatement`、绑定42/43/44分别返回正确MD5，仅证明真实二进制prepared执行可达。修正表后须重新记录，不能复用该失败路径记录。

## 2. FE管理的SQL结果缓存（LP003）

[CacheAnalyzer](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/cache/CacheAnalyzer.java:134)除会话 `enable_sql_cache=true`，还依赖FE `cache_enable_sql_mode=true`；业务表最新版本距当前时间至少 `cache_last_version_interval_second`，默认30秒。数据刚导入完成时立即连跑不一定缓存。`sql_select_limit/default_order_by_limit`、dry_run、skip数据检查类设置、隐藏列等也影响资格。默认结果上限为3000行/30MiB，FE缓存容量100、闲置过期300秒；记录实际运行值。

固定相同账号、默认catalog/database、规范化SQL及影响结果的会话变量，静置达到版本间隔后执行至少两次同一SUM(v)。通过 `EXPLAIN PHYSICAL PLAN SELECT SUM(v) ...`确认 `PhysicalSqlCache`，并保存实际查询 Profile 的 `Is Cached: Yes` 和结果。ConnectProcessor 对 EXPLAIN 会剥离解释前缀查原SQL cache key，所以该EXPLAIN可用于实际缓存资格验证。禁止计时期间插入、更新、切账号或更改结果变量造成无意失效。

这里不是“纯FE内存结果且零BE请求”的承诺。[NereidsSqlCacheManager](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/cache/NereidsSqlCacheManager.java:422)允许FE管理缓存上下文、从BE SqlCache取缓存行；PhysicalSqlCache显示backend地址。FE内存ResultSet主要来自常量/空结果的 PhysicalOneRowRelation/PhysicalEmptyRelation，显示backend=none。SUM(v)业务表用例必须准确记录实际后端地址，不与纯FE常量缓存混为一谈。

## 3. BE聚合query cache（LP004）

LP004应显式关闭SQL cache，开启query cache并保持 `query_cache_force_refresh=false`；后者否则每次重填而不使用缓存。执行 `SELECT grp,SUM(v) ... GROUP BY grp`至少两次，数据/版本/会话结果变量及BE包保持不变。

[PhysicalPlanTranslator](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/glue/translator/PhysicalPlanTranslator.java:3354)仅给满足条件的确定性聚合标候选；[QueryCacheNormalizer](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/planner/normalize/QueryCacheNormalizer.java:129)还要求适当的聚合→OlapScan形状，不跨Exchange，带target runtime filter的fragment不合格。常量折叠/下推改变形状也可能导致未设置query_cache_param，故单看开关不够。

记录实际BE `query_cache_size`、entry最大行/字节限制（默认500000/5242880），保存对应请求Profile中CacheSourceOperator的 `CacheTabletId` 和 `HitCache: 1`。字段来自 [cache_source_operator.cpp](/data/project/massdb-sql/be/src/pipeline/exec/cache_source_operator.cpp:62)，它属于既有BE观测。SQL缓存的 `Is Cached: Yes` 不能替代BE query cache命中证据。仅有CacheSourceOperator但HitCache=0是路径可达，仍不能算命中。

## 4. 元数据混合、复杂冷/热及扇出

| 用例 | 仍须冻结或补充的真实前提 | 对应正证明 |
| --- | --- | --- |
| LP005 | 50%SELECT 1、25%SHOW TABLES、25%DESCRIBE必须体现在请求序列；SQL/HTTP两个客户端分开，DB内表数与DESCRIBE列数冻结 | 原始请求计数吻合比例；账号权限、返回结构/行数正确。单跑SELECT 1不能覆盖整个用例；A不存在的许可异常态是后续B语义证据 |
| LP006 | 精确归档16分支CTE/4次JOIN/32表达式SQL；禁SQL/query cache；按用例新连接。明确“冷”为每次完整分析/优化，不以更改字面量冒充冷，更不承诺OS页缓存/JIT重置 | EXPLAIN/Profile显示真实完整规划，parse/analyze/rewrite/optimize证据，Logical/PhysicalSqlCache缺席；计时外确认SQL形状及结果。新连接本身不清全局元数据/编译器缓存 |
| LP007 | 本分支复杂PREPARE不具有通用物理计划复用：ExecuteCommand除短路/GroupCommit分支仍executor.execute。应冻结实际支持的LogicalSqlCache复用模式，并提供SQL中真实引用的兼容view或函数依赖，t=180s由事件harness修改；原LP006纯表SQL不自动产生视图依赖 | 修改前PhysicalSqlCache/命中；依赖修改后缓存失效、重新分析且结果/权限正确；重建后再次命中。不能把复杂PREPARE重复全规划或仅BE数据页热当成FE热计划复用。当前只读runner不执行DDL依赖事件，因此不能独立覆盖整项 |
| LP009 | 3FE/4BE、1千万行、64/256/1024tablet各fixture，冻结parallelism和实际分布；用例期间禁结果/query cache避免扇出被省略 | SHOW BACKENDS/TABLETS及profile中真实BE地址、fragment/instance/tablet数相互对应。4个BE注册但任务全落1个BE不合格；早期1FE/1BE记录不能证明此项，2026-09-24真实四BE功能证据见下文 |

`run_performance_baseline.py`支持明确的reuse与per_request连接模式；后者把每请求新连、初始化和prepare纳入端到端成本，前者保留固定worker连接。它不自动实现LP005 HTTP比例、LP006所有规划/缓存重置条件、LP007并行依赖事件、LP009多FE/4BE部署。精确复杂SQL与依赖事件fixture已另存P0机器契约，执行器接受fixture不等于整项行为都被测量。这些限制须在每份结果清晰列出，不能因工具接受某个LP ID就把全部子场景标为通过。

## 5. 修正fixture后的只读正证明

同日私有namespace在父任务重建row-store表并再次验证百万行后执行低频只读探测，没有DDL、配置持久变更、压测或服务启停。证据汇总：[reachability-report.json](/data/project/massdb-sql/.build-records/license-p0-p1-20260922/path-probes/reachability-report.json)。

- LP001：[point-rowstore.log](/data/project/massdb-sql/.build-records/license-p0-p1-20260922/path-probes/point-rowstore.log)具有store_row_column/light_schema_change/MoW属性、同会话EXPLAIN `SHORT-CIRCUIT`及正确点查结果。
- LP002：同一日志记录ServerPreparedStatement及42/43/44三次绑定的正确结果。真实二进制执行及短路前提已验证；未独立采集directExecuteShortCircuitQuery方法分支计数/栈，不能把源代码推断包装成该方法实际调用的独立观测。
- LP003：[sql-cache.log](/data/project/massdb-sql/.build-records/license-p0-p1-20260922/path-probes/sql-cache.log)出现PhysicalSqlCache、backend=127.0.0.1:29050及SUM=49999500000；[对应Profile](/data/project/massdb-sql/.build-records/license-p0-p1-20260922/path-probes/sql-cache-profile.txt)为 `Is Cached: Yes`，Analysis/Rewrite不再执行。
- LP004：两次分组结果各1024行，按grp排序完全一致、sum合计49999500000；[对应Profile](/data/project/massdb-sql/.build-records/license-p0-p1-20260922/path-probes/be-cache-profile.txt)包含16个tablet的CacheSourceOperator `HitCache: 1`，SQL摘要为 `Is Cached: No`，准确区分两套缓存。

这些是该次原版发行包的路径可达证明。它们不证明完整低高并发、各连接模式、依赖失效事件、授权候选行为或A/A/A/B性能。LP005/006/007/009的后续独立功能记录分别列在下文及实施记录中，不能将早期路径证明追溯升级为完整用例通过。

后续已补P0固定复杂SQL及低频事件探测：冷计划中实际有4个PhysicalHashJoin，输入SQL为16 UNION ALL/32聚合算术输出；view事件前后33列结果均吻合独立模型。SQLcache状态依次为未命中→预热命中→180秒view变更后失效→新值重建后命中，最后恢复view。记录见[completion-report.json](/data/project/massdb-sql/.build-records/license-p0-short-connections/completion-report.json)。事件发生在静止等待后，不证明与业务负载并发时的所有行为；多并发/连接模式及A/A/A/B仍需完整测量。

## 6. 2026-09-24 后续完整数据功能证据

精确 Temurin 17.0.4+8、同一未修改原版发行包上的 LP005 元数据/权限 fixture 已通过，
见 [实际结果](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp005-probe-jdk1704-v3/report.json)。
后续点查客户端对每次请求的 payload 按预计算 MD5 模型核对，text/prepared × reuse/per_request
四组合共 1,248 次真实计时请求全部内容正确，见
[独立核验](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/point-payload-oracle-smoke/completion.json)。
这是短功能 smoke；早期只核对行数的性能诊断保留原工具摘要和原有证据边界。

LP009 已在七个不同私有 namespace 上建立真实三个投票 FE、四个 BE；实际加入、选主、
远端心跳、journal 回放与 1484 项原包/配置/工具绑定核对通过。
64/256/1024 分桶各写入完整 10,000,000 行，分别核对全部 ID 唯一性、字段/payload 和全部 1024 组结果。
原始执行 profile 显示每档四 BE 各扫描 2,500,000 行，每 BE 分别为 16/64/256 个 tablet、
2 个实际 scan task，合计每档 16 个实例。见
[89 份原始 SQL 回执及 profile 审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp009-fanout-v2/completion-audit.json)。
测试临时表和服务均已清理，停止前 manifest 保留；详见
[多节点记录](/data/project/massdb-sql/tools/license-checks/multinode-baseline-cluster.md)和
[fanout 工具](/data/project/massdb-sql/tools/license-checks/fanout-fixture.md)。

上述七节点共享同机 CPU 6–9，FE 各 1 GiB heap、BE 各 2 GiB 进程限额，不能当作多机资源隔离或正式性能结果。
初次 bootstrap 常量 SELECT 失败、全表 DISTINCT 超测试内存限制的记录均保留。
后者通过 20 个无遗漏 ID 区间完成独立内容核对，实际被测聚合仍扫描全表，不缩减千万行规模。
LP006/007 的并发依赖事件、全部规定负载矩阵和精度要求仍需后续实测。
