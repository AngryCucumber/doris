<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# MassDB SQL 授权证书执行计划

初稿：2026-09-22；范围收敛：2026-09-24；当前 P0/P1/P2 核对：2026-09-25。源码基线：`2.0.5-license` / `23e39e63295`。

**当前方案：只改 FE、FE 管理页面和独立签发工具，围绕五类出口限制新的业务读取。保留入库、更新、元数据、节点额度、证书导入及详情页面；不改 BE，不改内部通信协议，不要求启用 SSL 或 mTLS。** 用户最新确认：另允许窄式 `SELECT 1 FROM t LIMIT 1` 探测。

这是收敛后的实施计划，不是整个授权功能已完成声明。P0 的具体用例/挂点与性能适用映射已补齐，P1 核心已交付；P2 的 Env/journal/image、SQL/HTTP 管理闭环已完成，183 项授权相关测试通过，并完成真实多 FE 导入、续期、恢复、切主、转发、旧版拒绝和新 FE 加入验证。各变体的单测/受控故障/真实 FE 范围见[P2 验收记录](license-p2-acceptance-20260925.md)。五出口与节点额度拦截、页面和完整性能验收仍待后续阶段。实现状态见[实施记录](/data/project/massdb-sql/docs/license-implementation-progress-20260922.md)。

本文替代旧版的全面 FE 出口治理要求。[当前 P0 契约](/data/project/massdb-sql/docs/license-p0-contract-20260922.md)定义 46 组具体运行用例、源码挂点及旧 LP001–026 到七组当前负载的适用映射。旧[协议说明](/data/project/massdb-sql/docs/license-protocol-v1-20260922.md)、[源码清单](/data/project/massdb-sql/docs/license-code-coverage-20260922.md)及旧 P0/性能/覆盖 JSON 保留为历史扩展范围参考；其中 H/C/LC 全量覆盖、全函数审计、规划零外部访问、全部 26 项基线前置要求和旧机器门槛不再定义当前任务。历史 FAIL、未执行和精度不足记录不能因此改为通过。证书核心契约及本文保留的性能数值继续有效。

## 1. 保留功能与明确边界

- 离线签名证书支持导入、验证、查看、续期、自动到期、集群绑定和 FE/BE 注册节点上限。
- SQL 与 HTTP 共用管理逻辑；FE 顶部新增“授权证书”Tab，提供详情和文件/文本导入。
- 无证书、过期、验签失败、缺少 DATA_QUERY、时钟异常、未就绪或实际节点超额时，限制下述五类新业务读取；有效授权正常工作。
- 所有操作保留既有数据库权限。root/ADMIN 也受业务读取限制，普通 SET/Hint 或客户端自报 internal 不能绕过。
- 保留现有已启动查询的超时、取消和内部重试机制；到期不主动取消在途查询。新的 EXECUTE、多语句下一条、过程内下一条查询需重新检查。
- 已下发的 BE 扫描计划、结果票据可以跨到期继续使用或重新打开；下一次向 FE 请求新计划再检查。该边界已获用户接受，不宣称其发生概率经过测量。
- 首版适用存算一体部署。Cloud 的实例/租户作用域和既有欠费控制另行验证。

这里是产品使用授权控制。允许更新条件、影响行数、统计 min/max 和表非空探测，本身可能透露数据；不承诺数据保密隔离或封堵一切数据外传。

## 2. 五类出口及统一规则

下表仅描述授权不可用时新增的限制；有效证书下不改变原查询语义。

| 出口 | 拦截条件 | 放行与实现边界 |
| --- | --- | --- |
| 1. SQL 查询结果，包括 INTO OUTFILE | 查询依赖受保护数据，且不符合下文明确例外 | 文本/预编译普通路径、多语句、过程内 SELECT、HTTP Query、FE Flight 共用 SQL 核心；返回 FE 结果、结果缓存或执行 OUTFILE 前检查 |
| 2. 预编译点查快路径 | 每次 EXECUTE 需要业务数据 | PREPARE 成功不是后续永久许可；在直达 PointQueryExecutor 的分支调用同一守卫 |
| 3. 向外部表写入 | 目标为外部表，来源需要受保护数据 | JDBC/Hive/Iceberg 等按实际目标判断；覆盖 INSERT SELECT、OVERWRITE 及分支实际支持的外部 CTAS；纯 VALUES 放行，内部落表放行 |
| 4. EXPORT | 新导出受保护表数据 | 提交前及异步任务实际开始前检查；提交时已无效须在登记作业、删除旧导出目录等副作用前拒绝 |
| 5. Spark/Flink 连接器取计划 | 新请求 `/api/{db}/{table}/_query_plan` 读取受保护数据 | 返回可执行计划前检查；拒绝为真正 HTTP 403，不能只是 HTTP 200 body 中写 403；旧 BE 计划不改 |

### 2.1 受保护来源

内部业务表、真实存储数据的系统表（例如 `__internal_schema.audit_log`）、外部 catalog 表，以及读取文件或执行远端查询的 TVF 均属于受保护数据。TVF 包括 `s3()`、`hdfs()`、`local()`、`file()`、`http()`、JDBC `query()` 及同类实际数据源；复用绑定后的对象类型判断，不能只按名称列正则黑名单。`numbers()`、`backends()`、`partitions()` 等不因使用 TVF 语法而一律受限。

以下依赖同样受保护：业务表 JOIN、子查询、CTE、UNION、视图展开、物化视图直接读取或改写，以及元数据查询中夹带的业务表读取。COUNT/SUM/DISTINCT/EXISTS 或只返回常量，不自动成为元数据。

`SELECT dict_get(...)`、`dict_get_many(...)` 也要限制。它们可以没有普通扫描节点，并可能在规划中折叠；仅为这些已确认读取能力保留必要来源标记，不引入覆盖所有内置函数和 UDF 的通用能力登记框架。

### 2.2 空计划与表非空探测例外

| 示例 | 决策 |
| --- | --- |
| `SELECT 1`、`SELECT @@version`、`SELECT DATABASE()`、`SELECT NOW()` | 放行原有无业务取数语义 |
| `SELECT * FROM t LIMIT 0`、`SELECT * FROM t WHERE 1=0` | 可证明最终输出零行且不执行取数时放行 |
| 分区裁剪后所有分区被排除 | 最终完整结果计划确认为零行空计划时放行 |
| `SELECT 1 FROM t LIMIT 1` | 按用户选择放行窄式表非空探测 |
| `SELECT 1 FROM t WHERE id=5 LIMIT 1`、普通 `SELECT 1 FROM t` | 仍属于业务读取，不能借用探测例外 |
| `SELECT count(*) FROM t`，包括空输入时返回 0 | 聚合业务读取；不能因输入为空或最终只返回常量就放行 |
| `SELECT * FROM t WHERE id=-1` | 若实际最终计划仍需业务扫描则拦截，不凭“预计查不到”放行 |

探测例外限定为：单个已绑定真实表、唯一投影为整数字面量 1、LIMIT 1、无 OFFSET 或 OFFSET 0，无 WHERE/HAVING/JOIN/子查询/CTE/UNION/聚合/窗口/DISTINCT/ORDER BY/函数/OUTFILE。不把含隐藏查询的视图或数据 TVF 当作这个例外。允许列别名及不改变该形状的括号。该操作会实际访问表并透露是否至少有一行，不将其称为零读取。

空计划依据优化器对**完整最终结果零行**的证明，不能用估计行数为 0、一个分支为空或 `getScanNodes().isEmpty()` 代替。缓存计划也须保留或重建这个依据；无法证明时按实际来源处理，不因缺少来源信息放行。

### 2.3 保持原有能力

- 写入：INSERT VALUES、UPDATE、DELETE（含业务表子查询）、事务提交/回滚、Stream/Routine/Broker Load、Group Commit；内部表的 INSERT SELECT、OVERWRITE、CTAS，包括外部源导入内部表。
- 元数据：SHOW DATABASES/TABLES/COLUMNS/CREATE TABLE/PARTITIONS、DESC、SHOW TABLE STATUS、纯 information_schema 和元数据 TVF。SHOW COLUMN STATS 的真实 min/max 保留，移除旧计划中的统计值裁剪工程。
- 管理：普通 EXPLAIN、用户权限管理、KILL、证书管理和原有运维命令。ALTER SYSTEM 保留，但 ADD 必须检查注册额度。
- 内部维护：统计收集、物化视图刷新、compaction、副本修复等；复用真实服务端调用用途，不按用户名或通用 internal 布尔值给予所有用户 SQL 豁免。
- `SELECT @@massdb_license` 当前不是已实现的系统变量，本轮不额外引入；状态统一通过拟新增 SHOW LICENSE 和管理 API 提供。

“内部 CTAS 放行”不等于全部 CTAS 放行：实际外部目标遵循出口 3，必须在建外部表或提交写事务前判断。用途从顶层操作和实际 sink 获取，不能因内部写入计划包含 ResultSink/SELECT 子树而误拦。

## 3. 缩小改造的具体办法

只建立一个 FE 许可守卫和小范围语义分类，复用已有绑定、计划、缓存依赖及内部任务上下文。不是 SQL 文本黑名单，也不逐请求扫描历史清点表。

| 最小接入位置 | 需要做的事 |
| --- | --- |
| [StmtExecutor.handleQueryStmt](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:1189) | 普通 EXPLAIN 分支之后，FE 计算结果、PhysicalSqlCache、旧缓存及执行结果分支之前共用一次判断；保留真实顶层写入/维护用途 |
| [ExecuteCommand](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/ExecuteCommand.java:93) | 补预编译点查直接执行分支；Group Commit 写入快路径不误拦 |
| [Coordinator.exec](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/Coordinator.java:684)、[NereidsCoordinator.exec](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/NereidsCoordinator.java:141) | 两种 coordinator 都须在排队结束、首次派发前复核；后一条在 enqueue 返回后、processTopSink/registerInstances 之前。已有 finally/close 释放名额与资源，不新增独立执行凭证/期限框架 |
| [InsertIntoTableCommand](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/insert/InsertIntoTableCommand.java:238)、[InsertOverwriteTableCommand](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/insert/InsertOverwriteTableCommand.java:127)、[CreateTableCommand](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/CreateTableCommand.java:102) | 共用源/目标判断；外部输出在 beginTransaction、overwrite 任务登记、createTable 之前拒绝；内部写入直接保留 |
| [ExportCommand](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/ExportCommand.java:128)、[ExportMgr](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/load/ExportMgr.java:98) | 提交前守卫覆盖目录副作用；后台 EXPORT 经 StmtExecutor 执行 OUTFILE 时复核，不创建通用后台作业治理体系 |
| [TableQueryPlanAction](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/rest/TableQueryPlanAction.java:108) | 独立取计划路径调用同一决策，返回前复核；显式生成 HTTP 403 响应 |
| 现有 Nereids 绑定/优化、缓存上下文 | 仅补实际需要的来源/空计划/探测信息，以及已知字典函数折叠前标记；优先复用 usedTables/usedViews 和现有 schema 失效机制 |

五类出口不等于只改五个文件。共享执行器、必要快路径、队列、持久化、额度及页面仍需少量配套改动；开发时以实际调用链确定文件，不预先承诺固定文件数。

缓存命中发生在授权异常之后也必须拦截普通业务查询。若旧缓存缺少可靠分类信息，在异常态重新规划或拒绝该业务读取，不能把“没有扫描节点”当作放行依据；不因到期全局清空缓存，也不在每次有效态查询重新完整分析 SQL。

MySQL/JDBC、HTTP Query、Flight 和过程内 SELECT 已汇入现有 SQL 执行链，不分别实现五套许可逻辑。仅在真实绕开共用入口的分支补挂点；过程运行标志不能整体放行其中 SELECT。

同一次查询已经实际开始执行后，内部重试只沿用该次既有上下文中的准入事实；新 EXECUTE、过程下一句、跨 FE 新执行不得复制这个事实。尚未首次派发的排队查询仍检查当前状态。无需新增 execution_id、独立期限或跨节点凭证框架。

“拒绝无副作用”限定为对应副作用开始前的准入拒绝。EXPORT 有效提交后若排队到期，后续执行会被拒绝，但已发生的作业登记或目录删除按原有取消/清理语义处理，不承诺恢复已删除文件；外部 CTAS、事务也不能因后续到期追溯撤销已完成动作。

### 3.1 本次移出的扩展治理

移出全函数/插件能力登记、对所有新增注册项的专用 CI、HPLSQL HOST/INCLUDE/UTL_FILE、远程 EXECUTE_STMT 方言分析、内部写语句 AI/RPC/UDF 外发检测、Profile/Minidump/统计值全面裁剪、备份/CDC 全生命周期治理、隐藏管理命令治理及所有 FE 独立读取接口改造。

按五出口方案，以下通道保留现状，不宣称被新许可封堵：

- 用户已列明的 BACKUP/RESTORE、CCR、BE HTTP 下载、旧 BE 计划、导入错误日志样本。
- 本次源码复核补充披露的 FE ES search、文件预览 `file_review`、非查询表达式赋值（例如 `SET @v=dict_get(...)`）、过程文件/进程能力及自定义函数的外发副作用。这些新增边界尚未由用户逐项确认接受；列为收敛方案的明确限制，不能写成已封堵或用户已确认。
- EXPLAIN、TVF/外部表 schema 推断和 JDBC prepare/getMetaData 可能访问外部系统，部分文件格式还会读取文件字节。当前约束是五类出口的新业务读取/输出受限，**不承诺规划阶段零外部访问**；不为这个承诺给每种 TVF 增加构造前拦截。

若后续要求上述渠道也全面受限，应单独增加范围与测试；不能又把它们隐含塞回本轮的“小范围查询拦截”。

## 4. 证书、时间与运行依赖

复用已实现的 14 个 Java 核心文件；不因收敛出口重写格式、验签或续期模型。接口与不变量见[导入核心](/data/project/massdb-sql/docs/license-import-core-20260922.md)和[时间核心](/data/project/massdb-sql/docs/license-clock-core-20260922.md)。

| 项目 | 保留口径 |
| --- | --- |
| 格式与算法 | `.massdb-license` compact JWS；固定 typ=massdb-license+jws、alg=Ed25519 和受信 kid；JDK 17 JCA 验签，复用现有 Jackson，不新增 Tink/Nimbus 验签依赖 |
| 签发 | 厂商离线工具签名，私钥仅在签发端；客户修改任一受签字节即验签失败，FE 仅安装生产公钥 |
| 关键声明 | schema_version、policy_version、license_id、issuer、customer_id、product、deployment_id、issued_at/not_before/expires_at、sequence、edition/features、max_fe_nodes/max_be_nodes |
| 集群绑定 | Master 持久生成一次 deployment_id UUID；不绑定 IP/MAC，不由 Follower 或状态查询生成临时身份 |
| 严格输入 | 原文最多 64 KiB，严格 UTF-8/JSON/字段类型/重复键/base64url，按原始签名字节验证；未知版本/算法/公钥拒绝 |
| 续期 | active + 至多一个 pending，sequence 单调递增；保护已接受覆盖及基础额度，失败不替换旧证；指纹幂等，至多 1,024 条成功回执 |
| 时间 | UTC Unix 秒，`not_before <= now < expires_at`；到期等号即失效，无默认宽限；不改变 SQL 会话/JVM 时区 |
| 防回拨 | 复用墙钟、单调推进及持久时间水位；回拨容差 5 秒、显著前跳阈值 300 秒、水位保存 60 秒，不逐查询写日志 |
| 修复 | 独立 time_repair 公钥用途与签名票据，24 小时单调挑战期限，绑定部署/任期/nonce/epoch；提交后生效，不延长原证书 |
| 信任轮换 | 显式生产公钥清单；仍被 active/pending/base 或恢复记录依赖的 key 不提前移除；测试根不进入生产 |

离线环境不要求公网校时，可使用公司内网时间服务；UTC 是时间表示，不会自动确保服务器准确。整盘状态和时钟一起回滚、替换二进制或宿主机完全受控不能由静态离线证书彻底防住。

用户于 2026-09-24 明确本版本先供自己使用：**麒麟/openEuler 和 ARM64/x86 等目标平台、架构矩阵暂不作为本轮目标，不计入剩余工作，也不作为开发、P1 完成或交付的前置门槛。** 按现有可用环境开发，并在实际自用环境验证；保留用户已说明的 JDK 17.0.4 兼容要求。已有 Fedora 42 aarch64 / Temurin 17.0.4+8 的测试记录仅证明该实际环境，不代表新增平台支持承诺。

签名真实性、公钥用途隔离和实际部署的显式信任配置仍保留；它们与跨平台发行矩阵是不同事项。实际公钥配置随 P2 管理接入及自用部署验证，不因尚未提供生产公钥清单而停止功能开发，也不将测试根默认安装为正式信任根。

## 5. 持久化、节点额度与管理接口

### 5.1 FE 持久化与额度

LicenseManager 挂到 Env，复用 journal/image。持久化部署身份、原始签名证书、active/pending/base、最高序号、回执、版本、时间水位及修复事实；先持久提交，再发布不可变内存快照。验签在全局锁外，短提交阶段重查状态/成员版本；不持有许可锁等待日志回调。

仅 Master 提交，Follower 保留原操作者身份转发并报告 committed_version/applied_version。提交超时按回执确认，不能误报从未提交。恢复逐槽验签；过期不导致 FE 启动失败，坏 pending 不拖垮有效 active，缺失/跳过记录不得推断为免费新集群。Checkpoint 使用所属 Env 的历史截面。混合版本须先完成所有可服务 FE 的格式兼容升级，再写新 journal/image、提高相关版本及激活；不要求 BE 升级。

| 额度场景 | 规则 |
| --- | --- |
| 计数 | FE 包含 Master/Follower/Observer；BE 按完整已注册执行/存储及计算成员计数。同机多身份分别占额 |
| 离线/重启/心跳恢复/切主 | 不释放也不重复占额，不按在线节点数计算 |
| ADD | 在 Env.addFrontend / SystemInfoService.addBackends 等权威变更处检查；批量预检、并发新增和证书切换统一串行提交，额度拒绝不留下半注册成员；原成员提交中途故障沿既有恢复机制处理，仍按实际已提交成员计额 |
| 缩容 | DECOMMISSION 期间仍计数；实际 DROP 成员提交后才释放。保留原副本、WAL、quorum 检查，不自动踢节点 |
| 到期 | 读取许可与已提交基础额度分开；保留最后可信基础额度约束，不因到期变为无限扩容 |
| pending | 生效时间可改变查询状态；新增节点依据的基础额度提升必须另行持久提交，不能仅凭到点推断 |
| 引导/降额 | 无可信额度仅允许已证明的新集群首 FE 引导；增加 BE 需要证书。新证不接受低于已占用/预留或已接受基础额度的降额 |

节点数由成员变更/恢复路径维护并发布，查询与页面读取快照；不在查询路径遍历成员或同步询问所有 FE。

### 5.2 SQL、HTTP 与页面

P2 已实现命令：`ADMIN IMPORT LICENSE '<compact>'`、`ADMIN VALIDATE LICENSE '<compact>'`、`SHOW LICENSE`、`SHOW LICENSE DEPLOYMENT`、`SHOW LICENSE IMPORT '<fingerprint>'`，以及 `ADMIN LICENSE CLOCK CHALLENGE`、`ADMIN REPAIR LICENSE CLOCK '<repair>'`、`SHOW LICENSE CLOCK REPAIR '<repair_id>'`。parser、实际 SQL 导入和错误传播已有验证；管理语句明确拒绝服务端 PREPARE，可使用文本 SQL 或文件导入辅助工具。具体步骤及驱动边界见[管理说明](license-management-p2.md)和[P2 验收记录](license-p2-acceptance-20260925.md)。

| HTTP API | 用途 |
| --- | --- |
| GET /api/license、GET /api/license/deployment | 状态/到期/用量/权限和签发申请信息 |
| POST /api/license/validate、POST /api/license/import | `{"certificate":"<compact>"}` 预检与持久导入 |
| GET /api/license/imports/{fingerprint} | 确认历史提交和当前应用进度 |
| POST /api/license/clock/challenge、POST /api/license/clock/repair | 申请挑战、提交 `{"repair_certificate":"<repair>"}` |
| GET /api/license/clock/repairs/{repair_id} | 修复回执查询 |

SQL 字面量是证书正文，不是服务器文件路径，不引入 LOCAL INFILE。管理操作使用现有认证及 ADMIN，Cookie 写请求检查同源/CSRF，Master 重验权限；证书异常不能阻止合法续期。普通用户只看脱敏状态，完整客户资料及管理操作仅管理员可见。

保留原接口限额：HTTP body 96 KiB、验签线程 2/队列 32、每用户每分钟 10 次/突发 3、提交后本 FE 等待最多 5 秒；已知提交但未应用返回 202 和版本。SQL 6200/45000 表示读取受限；6201–6204 分别保留候选无效、冲突、未就绪/提交不可确认、历史不可确认语义。HTTP 区分 400/401/403/409/429/503，不吞成成功或空结果；不得按每次拒绝写大日志。

新增命令的证书字面量在解析失败、多语句、审计、Profile、错误日志等处脱敏；不借此扩展为全产品诊断内容治理。验签、导入、详情读取都不能占用或长期锁住业务查询/入库线程。

页面放在顶部 Configuration 后，独立懒加载 /License，保留登录和反向代理前缀，补中英文菜单。显示 active/pending、服务端状态、UTC/本地到期时间、FE/BE 已用/上限；文件/文本导入先 validate、确认再 import，超时可查回执。证书正文只在弹窗临时内存中，不入 URL/localStorage/日志，关闭后清除。

其他 Tab 不发许可请求；进入证书页读取一次，默认手动刷新。仅提交待确认时串行轮询：2/4/8/16/30 秒，30 秒封顶、总预算 120 秒，隐藏或离开停止。服务端快照决定有效性，浏览器时间只用于展示。

## 6. 性能设计与验收

**目标保持为：在预先冻结负载和检测精度下，没有可测的业务性能回退。** 指令有成本，不能在实现和 A/B 之前承诺物理零开销。

1. 有效态走快照/可信时间和少量分支；不逐查询验签、解析证书、扫描规则表/成员表、写 journal 或发许可 RPC。异常态才展开需要的语义限制判断。
2. 来源信息尽量复用已有绑定和缓存依赖；需要的字典标记跟随既有规划阶段生成，不追加完整 AST 遍历。不得为少数异常态禁用正常缓存或重做规划。
3. 每次新执行仍需轻量检查到期和当前状态。仅靠后台定时设置 VALID/INVALID 会有到期漏拦窗口，不能把“异常时启用规则”理解成完全取消有效态时间检查。
4. 核心时钟原子操作、出队复核、持久化、额度维护和页面/API 的成本均计入真实 FE 结果；微基准只辅助定位。

改为先完成有针对性的原版基线与功能接入，再测实际修改路径的 A/B。不再要求全部 26 个扩展基线和通用测量工具工程先全部完成才能开工。正式测试前为下表冻结具体 SQL/fixture、规模、并发、连接模式、时长、指标与适用项；必须证明命中真实路径，不能只证明 SET 成功。

| 必测组 | 内容 |
| --- | --- |
| 查询热路径 | 短点查、重复 EXECUTE、SQL/结果缓存、普通/复杂查询、元数据/探活；覆盖长短连接、低高并发 |
| 五出口与例外 | 内外表、视图、聚合、数据 TVF、字典、外部写入/CTAS/OVERWRITE、EXPORT、_query_plan；空计划及窄式探测正反例 |
| 写入兼容 | 内部 INSERT SELECT/CTAS/OVERWRITE、UPDATE/DELETE/事务、Stream/Routine/Broker Load、Group Commit、内部统计/刷新；正常和许可异常时都可用 |
| 状态与并发 | 到期/续期/pending、排队跨期、缓存跨期、拒绝叠加合法写入、并发导入/ADD/DROP、恢复/切主/时钟修复 |
| 页面与管理 | 登录/权限/详情/导入/回执/离开取消、其他 Tab 无额外请求、后台业务性能及资源有界性 |

A/B 使用同一原版 BE、硬件、数据和既有连接配置；A 为 FE 接入前基线，B 为完整启用功能版本。保留至少 5 对独立 A/A 和 A/B 窗口、业务每窗 P99 至少 10,000 次成功操作、1% CPU/吞吐和 2% P95/P99 检测精度要求。查看 B 结果前冻结 A/A 噪声带及 95% 置信方法；端到端延迟包含排队，错误、超时和重试单列。精度不足记待定，不把“差异不显著”当等效，不以拒绝查询释放资源计为性能收益；可重复回退阻断发布。

页面与业务按用户已确认口径分开：页面 300 秒、10 秒手动刷新节奏，原 LP021 的 1/10/50 context、LP022 的 1/10 context 保留为适用并发输入；页面自身样本不足不宣称 P99 达标。原页面作为背景对照，新证书页/导入等 B 独有行为单独记录成本；同时运行的业务仍遵守前述精度和样本门槛。范围收敛不表示取消已确认并发档位。

保留全部原始失败：用户已接受的 BE Flight batch_size=65535 字符串缺陷、FE Parquet 预览 reader 未关闭，仍为原版 FAIL；它们不阻塞其余授权开发。原页面 actual-v4 在 50 context 准备期客户端 RSS 超限停止，剩余 51 窗未执行；它不是 FE 授权性能失败，也不是完整页面矩阵通过。旧 JSON 和工具记录仅作历史输入，不能迁移成新范围 PASS。

## 7. 实施顺序与完成条件

| 阶段 | 本轮保留工作 | 完成证据 |
| --- | --- | --- |
| P0 收敛 | 已冻结五出口、探测/空计划、接口及持久化输入；46 组运行用例和七组当前性能负载映射见 P0 契约 | 设计输入与实际挂点对应；用例运行仍待 P2/P3/P2U/P4，不把文档核对算成运行通过 |
| P1 证书核心 | 已完成的验签、快照、导入策略、时钟及签发工具直接复用；移出跨平台发行矩阵 | 核心 104 项、签发工具 25 项及实际 JDK 互通记录保留；当前核心按已完成记录，运行接入另验 |
| P2 管理闭环 | 已完成 Env/journal/image、SQL/HTTP、权限/脱敏、回执、恢复/混合 FE 升级 | 183 项测试及实际导入、到期/续期、失败保旧、重启/切主、旧 FE 拒绝、新 FE 加入、错误传播记录；验证层级和保留失败见 P2 验收记录 |
| P3 五出口/额度 | 一个守卫、必要旁路/出队检查、小范围分类、ADD/DROP 配额 | 上表正反例；副作用开始前的拒绝不创建事务/删除目录，跨期拒绝保留既有清理语义，无队列泄漏；写入/元数据兼容 |
| P2U 页面 | 顶部 Tab、详情、导入、权限、路由及有限轮询 | UI 构建、现有 notices/legal 检查、证书页浏览器用例及真实 FE 联调 |
| P4 性能/交付 | 按实际保留路径做 A/A、A/B 和状态切换；在实际自用环境验证部署 | 原始请求/配置/版本/统计记录；精度及结果满足门槛，失败与范围外明确列示；不要求麒麟/openEuler或多架构矩阵 |

不以开发前的全部长测代替功能实现，也不以单元测试或文档静态检查代替最终集成与性能验收。实际改动后按需要运行 Java Checkstyle、针对性 FE 测试、源码头检查及 UI 检查；纯文档修改不要求重新构建 FE/BE 或启动基准。

## 8. 控制交付体积

现有新增产品核心为 14 个 Java 文件；`tools/license-checks` 已有 104 个文件，另有大型源码/契约 JSON。文件多主要包含此前扩展范围的审计、测量和原版验证工具，不能把它们都视作数据库热路径改动。

后续产品提交保留实际使用的核心、必要适配、针对性测试、页面和签发工具；广泛清点及通用基准工具作为独立开发辅助材料处理，不作为客户运行依赖。本次先收敛执行要求，不直接删除未提交代码、工具或原始记录；拆分时须同步检查引用和源码头登记。

收敛前主计划及配套文件已按原字节保存在[本地历史副本清单](/data/project/massdb-sql/.build-records/license-scope-reduction-20260924/before-manifest.json)。旧主计划 SHA-256：`d37cdafb8d09fac5e390d8a32d0359a843721f221cfd5bc49e5b59442ed8361f`。这份归档只用于追溯，不恢复旧扩展任务的强制性。
