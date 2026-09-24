<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP026 原版后台维护与独立 HTTP 夹具准备

状态：`actual_independent_prerequisites_observed_original_parquet_reader_close_failed`，2026-09-24。
本文整理 LP026 已有范围的输入、观测、原始失败和待验证依赖。
现已写入 [controller](/data/project/massdb-sql/tools/license-checks/background_http_fixture.py) 和
[离线测试源码](/data/project/massdb-sql/tools/license-checks/test_background_http_fixture.py)，
以及专用 [资源观察模块](/data/project/massdb-sql/tools/license-checks/background_http_resources.py) 和
[资源边界测试源码](/data/project/massdb-sql/tools/license-checks/test_background_http_resources.py)。
精确Temurin17.0.4+8编译、broker无socket自检及真实CSV/Parquet输入生成和独立读取已通过。
原版 v6 已证明字典自然刷新和两轮 MV 后台任务；自然统计 job/task 完成及数值正确，但旧 FULL 方法断言使该轮失败，
原始 FAIL 不改写。独立 v7 的自然统计、ES root/mapping/search 和 CSV 预览通过；Parquet 的 HTTP200/code0、
625 字节文件和两行完整内容正确，但原 FE 未关闭其 reader，阶段和整体保持 `FAILED`。
broker 共打开 2 个 reader、客户端关闭 1 个，清理前剩余 Parquet reader 1 个；测试 helper 强制关闭该 1 个后为 0，
这不证明原 FE 正常关闭，因此 v7 的 `cleanup.complete=false` 保留。
独立 cleanup-audit 确认 owned DB/catalog/broker 缺席、端口可重新绑定、helper 进程组无成员，原 FE/BE/supervisor 身份不变。
物理回收完成与产品 reader 关闭失败分别记录，不合并 v6/v7 为同一轮完整通过，完整性能矩阵未运行。
最新 65 项离线测试（47 controller、18 resources）及此前 100 个真实短命 Python/JDK helper 检查通过。
证据分别保存在 `.build-records/license-p0-p1-20260924/lp026-background-http-actual-v6/`、`lp026-background-http-actual-v7/`、
`lp026-background-http-actual-v7-control/cleanup-audit/` 和 `tool-validation-20260924/lp026-sample-subset-v1/`；
每轮绑定自己的源码/JDK/包摘要，旧失败及取消记录均保留。
源码依据为当前工作区；将来执行前必须绑定原版 A 的源码提交、真实发行包/JAR、JDK、配置和工具摘要。
不能仅凭当前源码推断某个旧发行包已经包含对应实现。

原始范围见 [LP026 性能输入](/data/project/massdb-sql/docs/license-performance-cases-20260922.json:1888)
及 [C38 维护要求](/data/project/massdb-sql/docs/license-p0-contract-20260922.json:4547)。
字典、MV、统计三种维护任务必须各有独立证据；ES mapping/search 和远程文件预览分别观察。
原版 A 没有许可状态。将来 VALID 等价负载、EXPIRED 允许后台负载和 B 独立拒绝检查继续分开；
功能探测不替代原定并发 1/8/32、180 秒预热、600 秒窗口、至少五对及精度门槛。
本文的小型确定性输入仅用于原版路径前提，不替换正式 `bench_small_plus_write_target` 数据集。

## 已写入的工具与尚未验证的执行入口

默认 `--mode plan` 仅在新的 checkout `.build-records` 子目录保存计划，不加载数据库、不启动 JVM 或网络服务。
`--mode probe` 必须显式提供 `--cluster-record`、`--expected-fe-sha256`、`--expected-be-sha256`，
并绑定实际 JDK 17.0.4 的完整 `--jdk-runtime-version`（默认 `17.0.4+8`）。工具核对当前 namespace、
FE/BE/supervisor PID 与 start ticks、安装路径、实际端口、运行可执行文件和原版包摘要；检测到本仓库的
正式测量 controller 或 JVM 时拒绝运行，包括相对参数启动及 JVM 窗口间隙。

probe 内才编译现有 JDBC helper 以及
[只读 broker](/data/project/massdb-sql/tools/license-checks/LicenseReadOnlyBrokerFixture.java) 和
[输入生成/独立 Parquet reader](/data/project/massdb-sql/tools/license-checks/LicenseReadOnlyBrokerInputs.java)，
使用同一原版 FE 包依赖和 JDK17，记录源码、JAR 与实际 class 摘要；不下载依赖。辅助代码采用 `--release 17`，
不是产品许可核心的字节码兼容承诺。输入 manifest、ready、请求 JSONL 和 final summary 在本次 owned 目录内关联。

默认主工作上界 2400 秒、独立清理工作预算 180 秒（本地关闭另有下述有限 grace）、字典自动刷新等待 750 秒、自然统计 300 秒、每轮 MV 120 秒、
状态轮询间隔 5 秒、broker 最长 300 秒；CLI 仅接受声明范围内的有限值。字典生命周期仍为 600 秒。
`--phases` 默认选择全部六阶段；可显式选择 `dictionary mv statistics es file_review_csv file_review_parquet`
中的非重复子集，按上述固定顺序执行。未选项始终保留 `not_run`，即使所选前提全部成功也只能得到
`ORIGINAL_FUNCTIONAL_SUBSET_COMPLETE`，不能得到完整六阶段通过或 LP026 性能通过。
历史结果只可按其原源码/公共依赖摘要独立关联，不拼成同一轮完整执行，也不改写旧 FAIL。阶段失败保存已完成证据，后续未运行项保留。
原版 Parquet 预览若留下 reader，即使最终强制关闭了 recorder，仍记失败，不把强制资源回收当客户端正确关闭。
最终 broker summary 还须与 ready 的 PID/namespace/输入摘要一致，逐条请求序号连续，并对账方法计数、
状态计数和真实返回字节；异常协议、超时终止、残缺 JSONL 或强制关闭 reader 都不能通过。
每次 SQL/HTTP 前后、阶段前后和最终成功前重新核对原 FE/BE/supervisor 的 PID/start ticks/namespace；
服务替换会阻止继续发 SQL（包括清理 SQL），本地 helper/recorder 的清理仍独立执行。
同步 helper 的 stdout/stderr 分别在读取时限制为 2 MiB，javac 和 Java helper 堆上限为 256 MiB；
HTTP 固定最长 30 秒并受主工作 deadline 约束，分块检查大小与剩余时间，socket watchdog 覆盖滴流响应头/正文。

实际输入生成首次因 `fe-common` 中旧Parquet格式类遮蔽1.17.0依赖而失败；现显式将唯一
`parquet-format-structures`放在helper类路径前端，并记录及核对实际PageHeader来源。
重新编译、生成及完整两行独立核对通过；失败和修复后的记录均保留在
[依赖修复验证](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/broker-dependency-fix/receipt.json)。
该调整只用于fixture helper，不修改原FE发行包的类路径或BE。真实原版probe仍待执行。

## 执行前的归属、资源与记录

本夹具执行前须确认没有正在运行的正式计时工作，
使用 checkout 内新的独立安装和私有网络 namespace；不得连接客户、宿主已有实例或复用历史 PID。
校核 supervisor/FE/BE/broker/recorder 的 PID、start ticks、namespace inode、实际监听端口、安装路径和摘要。
辅助服务只绑定该 namespace 的 loopback；没有外网依赖、生产秘密、BE 修改或新增协议字段。

每次使用全新输出目录、全新数据库 `lp026_<run_id>`、catalog 和 broker 名，失败也保存原始结果。
数据表、字典、MV、catalog、注册 broker、临时用户和服务逐一登记 owner；任何已有同名对象均拒绝接管。
记录实际 CPU 亲和性、堆/内存限制、采样频率、请求/SQL 超时、各阶段绝对 deadline 和允许重试次数后再启动。
工具的有限默认值已列于上节；尚未经过真实探测，不能把超时后的无限等待或自动重试作为实现默认值。
独立记录辅助服务 CPU/RSS/网络及 broker 活动 reader；它们的资源不冒充 FE/BE 开销。
新资源模块直接读取 `/proc`，不调用现有 `resource_observer`，不发 SQL/HTTP。固定每秒采样，子进程注册时
补一份初始采样，结束前补 controller/仍存活服务采样。每个原始 PID/start ticks/exe/namespace 和命令字节 SHA-256
分别记录；原始 argv/JVM properties/环境不归档。helper 实际命令摘要还与 controller 构造的精确 argv 对照。
命令、实例身份、资源读取或证据写入失败均保留 partial/failure，不能把缺测当零开销。

controller 与 ES/观察/输出线程共用进程内存，其实际 `VmRSS`、stat RSS 和 `VmHWM` 采样预算为 512 MiB；
每个 helper/JVM 为 768 MiB，当前存活 controller+helpers RSS 之和为 2048 MiB。controller 线程上界 32、
每 helper 128；ES 同时连接至多 8。FE/BE 与 namespace supervisor 单列观察，不算入辅助程序预算。
RSS 合计可能重复计算共享页；不把它当 PSS。JVM heap 上限不代表 RSS 上限。这些是**采样预算**，
可能漏过瞬时峰值或退出很快的 helper 峰值；内核 RSS 高水位可补充部分峰值信息，仍不构成内存硬隔离。

CPU user/system ticks 与 `/proc/<pid>/io` 的累计读写/调用计数按进程保存首末及逐次样本；退出前的最后样本
可能早于实际退出，不冒充精确全生命周期 CPU/I/O 总量。controller 的线程 CPU 单独记录 TID/start ticks 和已知角色，
线程共享 RSS 不重复求和。网络取 `/proc/net/dev`，只表示整个私有 namespace（包括 FE/BE、所有客户端和 observer）；
没有单进程网络归因，也不将 loopback RX/TX 相加后声称真实总流量。

`resources.jsonl` 在写前预留额度，最多 64 MiB；最多注册 4096 个进程，失败明细最多保留 32 条并另记失败总数。
后台 broker stdout/stderr 通过 PIPE 和独立 drain 线程写入，每流最多 2 MiB，超额块不会写入文件；记录字节、摘要和 EOF。
观察失败、RSS/线程/输出超限触发主工作取消。helper 读取与等待至多 0.2 秒检查一次取消，连接后的 HTTP watchdog
至多 0.1 秒检查一次；初始连接仍受其 30 秒请求上界约束。已建立的 ES 连接可在清理时主动中断。
取消/资源失败先关闭本地 ES/辅助进程，再尝试原数据库对象清理；独立清理工作预算 180 秒不因资源失败而被拒绝。
这 180 秒限制受控清理操作，不将随后仍必须执行的本地关闭 grace 隐含算成零秒。
子进程 TERM/KILL 等待各 3 秒，broker graceful exit 至多 10 秒，ES handler join 总计至多 5 秒，observer join 至多 3 秒。
清理 SQL 仍要求原实例身份；资源与证据失败均不能绕过所有 owned 子进程的最终 stop/reap，也不能把整体失败改成通过。
上述代码和新增离线测试均待独立验证窗口，当前不声明任何实际资源预算或性能验收已通过。

阶段记录至少包括：输入 SQL/HTTP 的脱敏正文与 SHA-256、UTC 和 monotonic 起止、请求 ID、原始返回码/错误、
数据库对象 ID/版本、job/task/query ID、模型比较、外发计数及 cleanup。HTTP 200 不等于业务成功。
recorder 记录阶段、方法、固定路径、请求体摘要、响应码/字节和活动请求数；不记录 Cookie、Authorization 或秘密。
阶段切换先等待活动请求归零；同一外发证据不得同时计入两个阶段。意外路由、重试和后台请求单独保存。

## 原权限和运行值

- [Config](/data/project/massdb-sql/fe/fe-common/src/main/java/org/apache/doris/common/Config.java:397)
  的源码默认 `enable_all_http_auth=false`。ES 与 file_review controller 都只在该开关开启时调用
  `executeCheckPassword`；其方法体未增加表级 SELECT 或 ADMIN 检查。上层过滤器、账号实际结果和部署配置
  仍需真实 probe，不能预写“非 ADMIN 必被拒绝”。先记录默认行为，再在专属安装中单独验证开启认证的行为；
  不把原版匿名可达性归因于许可证，也不为成功而临时关闭既有认证。
- 创建 ES catalog 检查 catalog `CREATE`，见
  [CreateCatalogCommand](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/CreateCatalogCommand.java:65)。
  创建及刷新异步 MV 检查目标 `CREATE`，见
  [CreateMTMVInfo](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/info/CreateMTMVInfo.java:139)
  和 [RefreshMTMVInfo](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/info/RefreshMTMVInfo.java:69)。
  源表读取的实际权限检查另外保留，不由这些入口检查推导完整授权结果。
- [AnalyzeTableCommand](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/AnalyzeTableCommand.java:165)
  对用户上下文检查表 `SELECT`；
  [ShowAnalyzeCommand](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/ShowAnalyzeCommand.java:131)
  检查全局 `SHOW`。准备阶段使用专属管理连接；普通账号结果单独验证，不混入维护耗时。
- 字典 create/refresh 命令到 manager 的完整权限边界尚未独立确认。不得从 ADMIN 下成功推断普通用户权限；
  自动任务以服务端构造的 ADMIN 上下文运行，不能用客户端自报 internal 标志模拟。

## 1. 字典初始化及真正的自动刷新

采用 [dictionary 回归语法](/data/project/massdb-sql/regression-test/suites/dictionary_p0/test_dict_get_many.groovy:37)，
独立库内输入模板如下；尚未在本次原版安装执行：

```sql
CREATE TABLE dict_source (k0 INT NOT NULL, payload VARCHAR(64) NOT NULL)
DUPLICATE KEY(k0) DISTRIBUTED BY HASH(k0) BUCKETS 1
PROPERTIES('replication_num'='1');
INSERT INTO dict_source VALUES (1,'lp026-a'),(2,'lp026-b');
CREATE DICTIONARY fixture_dict USING dict_source (k0 KEY, payload VALUE)
LAYOUT(HASH_MAP) PROPERTIES('data_lifetime'='600');
SHOW DICTIONARIES;
SELECT dict_get('lp026_<run_id>.fixture_dict','payload',1),
       dict_get('lp026_<run_id>.fixture_dict','payload',2);
INSERT INTO dict_source VALUES (3,'lp026-c');
```

独立模型固定三行键值；追加不同键避免重复键语义干扰。首次就绪要求本字典实际存在、`Status=NORMAL`、
`LastUpdateResult` 成功、分布覆盖实际 BE，且前两值正确；不能使用“空 SHOW 列表也算全部 ready”的断言。
记录初始版本及数据，再插入第三行，等待生命周期到达后的自动刷新，不发送 `REFRESH DICTIONARY`。
最终要求版本推进、再次 NORMAL、第三个 `dict_get(...,3)` 返回 `lp026-c`、三行源表仍完全一致。

[DictionaryManager](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/dictionary/DictionaryManager.java:322)
的 daemon 在源版本更新且 `nextRefreshTime < now` 时提交任务；源码轮询默认 5 秒，`data_lifetime` 单位为秒，
600 沿用已有回归输入。应在测量外完成就绪，等待上界须覆盖生命周期和实际调度周期，不能把 30 秒 ready helper
当自动刷新 deadline。[dataLoad](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/dictionary/DictionaryManager.java:392)
的自动入口为 `ctx=null`，构造 ADMIN 上下文及 `InsertIntoDictionaryCommand`。保存关联字典 ID、版本、
`Submit dictionary ... refresh task`/完成日志和 query ID，证明观察到自动路径。
[SHOW DICTIONARIES](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/ShowDictionariesCommand.java:58)
提供 Version/Status/DataDistribution/LastUpdateResult，且会访问 BE 状态；轮询自身的外发单列。
后续候选到期阶段不能把用于结果核对的用户 `dict_get` 当成允许后台维护负载；其核对时机须另行安排。

## 2. 支持的 MV 刷新作业

沿用 [内部表异步 MV 回归](/data/project/massdb-sql/regression-test/suites/mtmv_p0/test_agg_table_mtmv.groovy:42)：

```sql
CREATE TABLE mv_source (user_id INT NOT NULL, num SMALLINT SUM NOT NULL)
AGGREGATE KEY(user_id) DISTRIBUTED BY HASH(user_id) BUCKETS 2
PROPERTIES('replication_num'='1');
INSERT INTO mv_source VALUES (1,1),(1,2),(2,4);
CREATE MATERIALIZED VIEW fixture_mv
BUILD DEFERRED REFRESH AUTO ON MANUAL
DISTRIBUTED BY RANDOM BUCKETS 2 PROPERTIES('replication_num'='1')
AS SELECT * FROM mv_source;
REFRESH MATERIALIZED VIEW fixture_mv AUTO;
SELECT JobName FROM mv_infos('database'='lp026_<run_id>') WHERE Name='fixture_mv';
SELECT TaskId,JobId,JobName,MvId,Status,MvName,MvDatabaseName,ErrorMsg
FROM tasks('type'='mv') WHERE JobName='<observed_job_name>' ORDER BY CreateTime ASC;
SELECT * FROM fixture_mv ORDER BY user_id;
```

独立期望为 `(1,3),(2,4)`；再插入 `(2,5)`、再次 REFRESH，期望 `(1,3),(2,9)`。
两轮分别核对新 task ID、`SUCCESS`、job/MV/库身份及完整结果；前轮成功不能替代后轮完成。
手动提交刷新对应真实后台任务，不能称作定时调度已证明。
[MTMVTask.exec](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/job/extensions/mtmv/MTMVTask.java:317)
创建受控上下文并执行 `UpdateMvByPartitionCommand`，记录其 query/task ID。
上述状态 SQL 来自 [Suite helper](/data/project/massdb-sql/regression-test/framework/src/main/groovy/org/apache/doris/regression/suite/Suite.groovy:1992)；
不直接复用 helper 的后续 `ANALYZE TABLE ... WITH SYNC`，否则会把额外统计混入 MV 阶段。

## 3. 自动统计调度和完成

新建独立 `stats_source(k0 INT NOT NULL, v INT NOT NULL)` DUPLICATE KEY 表，1 bucket、1 replica，
输入精确为 `(1,10),(2,20),(3,30)`。设置本表 `auto_analyze_policy=enable`，先核对完整数据和实际上报行数，
归档已有 job 列表；该表不能事先执行同步 ANALYZE 来代替自动任务。

```sql
ALTER TABLE stats_source SET ('auto_analyze_policy'='enable');
SHOW INDEX STATS stats_source stats_source;
SHOW AUTO ANALYZE stats_source;
SHOW ANALYZE TASK STATUS <observed_job_id>;
SHOW TABLE STATS stats_source;
SHOW COLUMN STATS stats_source;
```

自然调度前提取自 [StatisticsJobAppender](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/statistics/StatisticsJobAppender.java:52)：
Master、统计表可用、collector ready、自动统计开启；appender 每秒检查，内部小表的低优先级遍历周期受一分钟间隔控制。
[StatisticsAutoCollector](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/statistics/StatisticsAutoCollector.java:63)
按 `auto_check_statistics_in_minutes`（源码默认 1）工作，首次还等待两倍 tablet 统计上报间隔。
实际 global `enable_auto_analyze`、`enable_auto_analyze_internal_catalog`、统计时间窗口、表策略、行数上报、
sample/full 选择及相关阈值均须归档，不能把源码默认值当运行值；session SET 不证明 daemon 读取的 global 值。

先通过新表自然被 appender/collector 处理的路径观察新的自动 job，保存创建时间、表 ID、job/task ID、
AUTOMATIC/SYSTEM 来源可见证据及 `FINISHED`，然后核对原始列统计及三行模型。
2026-09-24 的原版 v6 实测 job/task 已自然完成，完整数值正确，方法为 `SAMPLE`，旧工具误要求 `FULL`，
该轮 `FAILED` 和原始回执保留。当前工具在建表前明确读取 global `huge_table_lower_bound_size_in_bytes`，
要求精确为 `0`；[StatisticsAutoCollector](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/statistics/StatisticsAutoCollector.java:143)
对本 fixture 的非分区内表在该阈值下固定选择 `SAMPLE`。不同阈值拒绝运行，不修改 global，也不从结果反推放宽预期。
列方法必须是 `SAMPLE`、trigger 必须是 `SYSTEM`；count/NDV 必须精确为 3、null 为 0，
k0 的 min/max 必须为 1/3、v 为 10/30。此证据只证明自然调度和固定三行结果，不声称证明 `FULL` 算法。

已有 [自动统计回归](/data/project/massdb-sql/regression-test/suites/statistics/test_auto_analyze_black_white_list.groovy:98)
支持 `ANALYZE TABLE stats_source PROPERTIES('use.auto.analyzer'='true')`。
但 [AnalysisManager](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/statistics/AnalysisManager.java:197)
直接调用 `processOneJob`；这只能另作自动分析算法的显式触发 probe，不能替代上述 daemon 调度证据。
无法确认调度、被跳过、原权限拒绝或任务失败均保留 pending/failure，不以普通同步 ANALYZE 的成功补齐。

## 4. ES 结构和业务读取

[ESCatalogAction](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/restv2/ESCatalogAction.java:45)
精确入口为：

- `GET /rest/v2/api/es_catalog/get_mapping?catalog=<owned_catalog>&table=lp026_rows`
- `POST /rest/v2/api/es_catalog/search?catalog=<owned_catalog>&table=lp026_rows`

使用专属 catalog：`CREATE CATALOG <owned_catalog> PROPERTIES('type'='es','hosts'='http://127.0.0.1:<owned_port>')`，
语法依据 [ES 回归](/data/project/massdb-sql/regression-test/suites/external_table_p0/es/test_es_query.groovy:57)。
只使用单节点 HTTP mock，无真实 ES/用户凭据。请求 body 固定 `{"query":{"match_all":{}},"size":2}`，
避免空 body 使 [EsRestClient](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/es/EsRestClient.java:134)
选择 GET。mock 返回实际 JSON 字节，FE 自己发送外部请求、解析和包装响应：

| 外部交换 | 固定响应/断言 |
| --- | --- |
| `GET /` | HTTP 200 JSON `{"name":"lp026-fixture","version":{"number":"7.17.0"}}`；仅标识模拟响应，不宣称真实 ES 版本 |
| `GET /lp026_rows/_mapping` | `{"lp026_rows":{"mappings":{"properties":{"id":{"type":"integer"},"payload":{"type":"keyword"}}}}}` |
| `POST /lp026_rows/_search` | HTTP 200，hits.total=`{"value":2,"relation":"eq"}`；两个 `_source` 为 `{id:1,payload:"lp026-a"}` 和 `{id:2,payload:"lp026-b"}`，使用合法 JSON 编码 |

[EsExternalCatalog.initLocalObjectsImpl](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/es/EsExternalCatalog.java:128)
首先执行根路径 health；catalog 初始化还可能触发元数据调用。先独立记录初始化，所有未预期路由保存并使
最小协议 probe 失败，依据真实调用再补对应响应，不统一返回 200。当前仅由源码确认上述必要交换，尚未证明充分。
不预设所有调用恰好一次；失败重试为每节点最多三次，须保留原始请求，不能悄悄合并。

mapping 阶段要求返回精确结构且 search 计数为零；search 阶段要求 request body 摘要一致、两行业务值完全正确、
FE 包装中的 catalog/table/result 正确。mock 数据与独立 oracle 分别定义，不能用“把收到的数据原样作为期望”验证。
将来 B 禁止 search 的检查在初始化/计数稳定后单独执行并核对零业务外发，不把省去外部 IO 解释成性能提升。

## 5. 远程 file_review：CSV 与 Parquet

[ImportAction](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/restv2/ImportAction.java:76)
入口是 `POST /rest/v2/api/import/file_review`。body 模板：

```json
{
  "fileInfo": {"columnSeparator":",","fileUrl":"<owned_exact_file_uri>","format":"CSV"},
  "connectInfo": {"brokerName":"<owned_broker>","brokerProps":{"broker.name":"<owned_broker>"}}
}
```

`format` 实际支持 CSV/PARQUET；注释的 TXT 不受支持。`connectInfo` 被直接解引用，不能按“Optional”注释省略。
显式 `broker.name` 依据 [BrokerProperties](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/property/storage/BrokerProperties.java:61)
用于选择 broker 存储类型；[BrokerDesc](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/analysis/BrokerDesc.java:83)
在空 props 时可能不初始化 storageProperties，此精确 body 仍需原版 probe 后绑定。

两格式均先经 [BrokerUtil.parseFile](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/util/BrokerUtil.java:85)
和 FileSystemFactory 列目录，只有首个文件用于样本，fileNumber/fileSize 汇总全部列表。因此先用精确单文件 URI，
避免 glob 顺序改变期望。两格式都需要注册的 Thrift broker，已有 S3 TVF 成功不能替代此路径：

- CSV 经 [BrokerUtil.readFile](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/util/BrokerUtil.java:201)
  再次 listPath、openReader、pread（最多 1 MiB）、finally closeReader。解析最多 50 行，分隔符是 Java regex，
  不是完整 CSV quoting parser；使用 ASCII、逗号、LF、无引号/空末列的 `1,lp026-a\n2,lp026-b\n`，独立核对字节数、
  两行两列、sampleFileName、fileNumber=1 和完整内容。
- PARQUET 经 [ParquetReader.create](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/parquet/ParquetReader.java:57)
  → [BrokerInputFile](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/parquet/BrokerInputFile.java:65)
  → BrokerReader 的 list/open/pread。使用同两行、id INT32 与 payload UTF8 的真实 Parquet 字节，独立 reader 全读校验后
  再交给 broker；核对 colNames、两行值、maxColumnSize=2，记录 footer/row-group 实际读取，不假定只取 schema。
  ImportAction 当前未显式关闭其 ParquetReader；必须实测 open/close/未闭 reader 数，保留可能的原版资源问题，
  未明确清理和限额前不运行持续循环，不修改 FE/BE 来隐藏原行为。

只读 broker recorder 已按当前生成的 TPaloBrokerService 类型写入，返回真实固定文件字节，仍待编译和实测。
它记录 listPath、openReader、pread、closeReader、存活检查、EOF/错误码、随机读取和 reader 生命周期；
禁止写入/删除/任意路径访问，记录句柄而不泄漏凭据。注册/清理语法来自
[broker 回归](/data/project/massdb-sql/regression-test/suites/node_p0/test_broker.groovy:23)：

```sql
ALTER SYSTEM ADD BROKER <owned_broker> "127.0.0.1:<owned_port>";
SHOW BROKER;
ALTER SYSTEM DROP BROKER <owned_broker> "127.0.0.1:<owned_port>";
```

[AlterSystemCommand](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/AlterSystemCommand.java:68)
检查全局 OPERATOR（失败提示 NODE）；
[ShowBrokerCommand](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/ShowBrokerCommand.java:59)
允许 ADMIN 或 OPERATOR。注册 ACK 不表示存活；
[HeartbeatMgr](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/system/HeartbeatMgr.java:475)
发送 VERSION_ONE 的 `ping`，recorder 必须按当前 Thrift 返回对应状态。实际状态字段、存活/失联时序仍待 probe。
文件路径必须限制在本次输入集合；不得把客户端提供的路径直接映射到宿主任意文件。

路径只读检查发现现有包含
[apache_hdfs_broker.jar](/data/project/massdb-sql/output/massdb-sql-2.0.5-rc02-bin-arm64/extensions/apache_hdfs_broker/lib/apache_hdfs_broker.jar)
和 start/stop/conf；没有启动、加载或校验该 artifact。可据此核对已有依赖，不能据文件存在宣称 broker 可用。
当前实现选择只读 recorder，精确 URI 为 `lp026://fixture/rows.csv` 和 `lp026://fixture/rows.parquet`，
固定生成两行 id/payload 并独立全读；真实 FE 是否接受这组 broker properties、列表响应与 URI 仍待实测。
本工具不要求下载新服务。

## 完成记录、清理和待补门槛

实际报告分别标识字典初始化/自动刷新、两轮 MV、自然自动统计/显式算法 probe、ES 初始化/mapping/search、
CSV/Parquet 预览；每项保存来源身份、结果模型及原始证据，只有自己的成功可改善自己的前提状态。
全项通过也只能说明原版功能前提；LP026、许可拒绝、持续性能、P0/P1 总目标与发行验收均不能据此改为通过。

清理在成功、错误、取消、超时路径都执行：先停止新提交并等本次 job/task 完成，必要取消语法须先核实；
归档原始状态后 DROP 本次 MV/字典/表、catalog 和 broker 注册，确认对象不存在、任务不再运行。
字典删除后的 BE 卸载是异步的，须观察本次字典分布消失；不能仅凭 DROP ACK 宣称释放完成。
关闭 JDBC/HTTP 客户端和 recorder/broker，核对活动 reader/连接、PID/start ticks、端口；任何遗留独立记录。
只恢复本次改变且先前保存的配置/会话/用户，不强行覆盖别人的变更。若专属安装最终销毁，按安装 manifest
停止其服务并清理其新 metadata/storage/log；原始回执保留，不创建安装备份，不操作 checkout 外安装。

可执行源码已写入的静态绑定包括 broker 存活/EOF/reader 清理、统计 SYSTEM/AUTOMATIC job 和 FINISHED task、
MV task 取消、统计 KILL、字典 DROP 后卸载日志、对象及子进程清理。实际执行及未触发分支以每轮原始报告区分；
v6 的字典卸载、数据库删除及 helper 退出清理已完成；v7 的 CSV 客户端关闭已验证、Parquet 客户端关闭失败，
不得用测试 broker 的强制关闭或独立物理清理回执替代原客户端关闭证据。
字典完整用户权限、Parquet reader 原行为及运行 artifact 与当前源码对应关系仍需各自证据。
只在无计时负载的窗口做后续有界验证，记录成功和失败、实际运行值及需要修正的输入。
不得把语法错误、依赖缺失、认证失败、空对象集、原版缺陷或未发生的任务当作许可证拒绝/维护通过。
