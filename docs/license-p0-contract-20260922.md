<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# P0：五类出口及补充 HTTP 入口实施契约与验收输入

当前范围冻结：2026-09-25（保留原文件名）；源码基线：`23e39e63295fd730523da8d916c898c28b903216`。本文落实[执行计划](/data/project/massdb-sql/docs/license-certificate-execution-plan-20260922.md)，以原五类出口、用户允许的窄式表非空探测及自用部署为基础；2026-09-29 用户另授权补充 ES search/file_review 两个 FE HTTP 读取入口。

**本轮状态：补充已实现，42 项定向测试及 FE 构建通过。** H01/H02 在原认证/重定向之后、ES 初始化或文件枚举/读取之前复用许可守卫；异常许可为真实 HTTP 403 和 `reason/message/retryable`，不依赖 `enable_all_http_auth` 是否开启。`get_mapping` 的正常索引/别名/逗号/通配选择器继续享有元数据例外，URL 控制参数另在外部初始化前拒绝；原 P4 已验收包不含此次新挂点；历史 46 组及原 FAIL/INCONCLUSIVE 不回写为新范围通过。本轮新增控制器 12 项与原守卫/快照/取计划 30 项测试零失败/错误/跳过，使用真实 guard 与模拟外部依赖；Temurin 17.0.4+8 FE 构建及 Checkstyle 通过，实际层级和证据见[本轮补充记录](/data/project/massdb-sql/docs/license-http-read-admission-20260929.md)。未执行真实 HTTP 网络、ES/broker 集成或新性能测试。当前 P2/P3/P2U/P4 已完成范围以各验收记录及[实施记录](/data/project/massdb-sql/docs/license-implementation-progress-20260922.md)为准，下文最初冻结时的将来时措辞不表示这些旧阶段仍未实现。

**P0 交付的是源码挂点、接口/状态协议、具体正反用例及性能适用范围；运行测试由 P2/P3/P2U/P4 执行。** 下文 `specified_not_executed` 保留 P0 冻结当时的状态；后续 P2 的 M01–M08、M12–M14 管理部分结果逐项记录在[P2 验收记录](license-p2-acceptance-20260925.md)，分别注明单测、受控故障和真实 FE 范围。查询、ADD/DROP 额度和页面不因管理测试通过而视为已生效。

旧 [P0 JSON](/data/project/massdb-sql/docs/license-p0-contract-20260922.json)、[性能 JSON](/data/project/massdb-sql/docs/license-performance-cases-20260922.json)、[全量覆盖 JSON](/data/project/massdb-sql/docs/license-code-coverage-20260922.json)保留原字节，属于历史扩展范围与 fixture 资料；其 H/C/LC、`release_gate`、平台矩阵和旧检查程序均不定义当前开工/发布门槛。本文是当前适用映射，不重新建立 1,423 项入口或全函数能力审计框架。旧 P0 正文见[本次修改前的归档清单](/data/project/massdb-sql/.build-records/license-p0-p1-current-scope-20260924/before-manifest.json)。

## 1. 冻结范围及阶段边界

- 原 FE 普通 SQL 结果、预编译点查、外部表写入、EXPORT、新 `_query_plan` 五类出口保持原契约，覆盖缓存、过程子句、两种 coordinator 出队及转发；本轮只增加 ES search/file_review 两个独立 FE HTTP 入口，共用现有许可决策。
- 真实内部数据表、外部 catalog、文件/远端 SQL TVF、SELECT 中的已知字典取值受保护。内部写入、元数据、维护、普通 EXPLAIN 保持原能力。
- `SELECT 1 FROM t LIMIT 1` 限单真实表、整数字面量 1、无 OFFSET 或 OFFSET 0；无条件/关联/子查询/CTE/聚合/窗口/DISTINCT/排序/函数/OUTFILE。不把视图或 TVF 混入这个例外。完整最终零行计划可放行；估计零行、空输入 COUNT 或没有扫描节点不构成证明。
- 不新增 BE 校验、跨节点凭证/内部认证或通信要求。旧 BE 计划跨期与重新打开已获用户接受；除本轮 ES search/file_review 以外，主计划列明的其他非查询/独立 FE 通道仍是方案限制，不声称都已封堵或获得逐项确认。
- 正常态读取不可变快照及可信时间；异常态展开必要语义判断。状态不缓存成永久 VALID，节点统计不放入查询热路径；保留正常缓存和原超时/重试语义。
- 真实服务端入口提供元数据改写、内部落表或维护用途；普通会话变量、Hint、用户名/root、过程标志和通用 internal 位不能自授豁免。仅已实际开始的同次内部重试可沿用既有上下文；新 EXECUTE、下一条语句、跨 FE 新执行重新判断。
- 本轮为自用版本，麒麟/openEuler 和多架构发行矩阵退出目标；JDK 17.0.4 兼容、真实签名/公钥用途和实际部署验证仍保留，实际公钥配置在 P2 接入处理。
- P0 冻结以下功能输入并核对可复用的原版证据；2026-09-29 用户将 P4 调整为快速验收，最新执行范围见第 5 节开头与主计划第 6、7 节。已有 FAIL/INCONCLUSIVE 原样保留，不能以范围调整宣布历史性能门槛通过。

## 2. 固定管理协议与持久化输入

只冻结现有 FE 身份/用途和许可事实的接入约束，不创建内部执行凭证协议。完整核心接口继续以[导入核心](/data/project/massdb-sql/docs/license-import-core-20260922.md)、[时间核心](/data/project/massdb-sql/docs/license-clock-core-20260922.md)及源码为准。

### 核心状态与管理协议

证书保护头固定 `alg=Ed25519`、`typ=massdb-license+jws`、可信 `kid`，JDK 17 JCA 验签原始 compact signing input。`schema_version=1`、`policy_version=1`，固定产品 `MassDB SQL`，UTC 整数秒，`not_before <= now < expires_at`。64 KiB 原始证书上限；严格 JSON、base64url、UTF-8、字段类型及数值范围由 P1 验证器实现。

active、pending、基础额度来源分别验签，逐槽隔离。坏 pending 不使可信 active 失效；坏 base 关闭 ADD，不单独拒绝满足当前查询额度的可信 active/pending。查询按当前时间选择有效证书；ADD 只使用已提交基础额度来源。未来 pending 到点可用于读取，但基础额度提升须另行提交，不能从时间推导提交事实。

同 deployment 的最高接受序号单调增长；先按原始字节 SHA-256 指纹查当前槽/成功回执。已提交的相同指纹返回原结果，不能重应用历史证书；当前或已保留序号/ID 的不同内容冲突。回执最多 1,024 条，超出保留区间且不在槽位时返回历史不可确认，不虚构曾成功。失败候选不占回执。

续期须保护 active 和已接受 pending 的授权时间覆盖并集以及已提交基础额度，不缩短现有未结束覆盖、不在已承诺覆盖中制造新间隙、不削减查询能力或额度。原本未承诺覆盖的旧 active 结束至新 pending 开始之间可有空档；空档内查询仍按 EXPIRED 受限。最多 active+一个 pending；替换 pending 同样要求更高 sequence。候选验签/时间/序号/部署/覆盖失败保持旧事实不变，validate 与 import 使用同一纯策略；真正提交时再次核对状态版本和成员版本。

可信时间默认值冻结为：回拨容差 5,000 ms、显著前跳阈值 300,000 ms、周期水位保存 60 s、修复挑战单调有效期 24 h。可信 UTC 由墙钟及单调推进下界决定，向前校正提升下界；回拨不能降低已观测 UTC、冻结正常时间推进或复活过期授权。容差从不加到 expires_at。显著异常进入粘滞 CLOCK_SUSPECT；合法写入/安全元数据保留。管理read()返回同epoch不可变时间元组；热路径按epoch→UTC→suspect→epoch一致性复核，遇修复并发变化重试或保守拒绝，不能任意拼接跨epoch的UTC与异常标志。

修复采用独立 `typ=massdb-license-clock-repair+jws` 和 `purpose=time_repair` 公钥，绑定 deployment、当前 Master 任期/进程、nonce、clock_epoch、独立 repair_authorization_version。挑战只在签发进程和任期的 24 h 单调期限内有效；重启/切主作废。票据的 corrected wall 范围不超过 24 h，以已纠正墙钟验证，不用被前跳污染的旧水位验证。修复提交保留证书时间、最高序号、基础额度及原有在途查询语义；重复票据仅能确认旧回执，不能再次降低水位。

FE 数包含 Master/Follower/Observer 注册身份，BE 数包含已注册执行/存储及计算节点，离线不释放；同机多身份仍分别占额。并发及批量 ADD 在 Master 同一提交序列上重查基础额度+完整成员清单。实际 DROP 提交才释放，申请/失败/重复回放不释放；保留原副本/WAL/quorum安全约束。不承诺被 DROP 的旧 BE 进程失去原直连能力。

### 管理接口、错误及资源上限

SQL 与 HTTP 路由保持[当前主计划](/data/project/massdb-sql/docs/license-certificate-execution-plan-20260922.md)的接口名；新增对象都限 FE。SQL 字面量是证书正文，不是服务端文件路径；首版不承诺现有 parser 能 PREPARE ADMIN，P2 必须以实际驱动记录确认支持情况或提供正确转义的文件导入脚本。

| 固定项 | 首版值与语义 |
| --- | --- |
| 原文 / HTTP body | 64 KiB / 96 KiB；正文超限在排队/验签前拒绝 |
| 验签管理线程 / 队列 | 2 / 32；有界专用执行器，不占用查询/入库线程池 |
| 用户管理速率 | 每用户每分钟 10 次、突发 3；达到阈值 HTTP 429 + Retry-After；全局队列满也拒绝，不能无界等待 |
| 提交后本 FE 同步等待 | 5 s；超时且已知提交返回 202 COMMITTED_PENDING_APPLY，保持committed_version；不能误报未提交 |
| 页面确认轮询 | 初始 2 s，按 2 倍退避至最多 30 s，即 2/4/8/16/30 s；总预算 120 s，同时最多 1 个请求；离开/隐藏/卸载终止，超预算可手动查回执 |
| SQL errno / SQLSTATE | 6200 / 45000 读取受限；6201 / 45000 候选无效；6202 / 40001 版本冲突；6203 / HY000 未就绪或提交不可确认；6204 / HY000 历史不可确认 |
| HTTP | 400 格式/永久候选错误、401未认证、403权限/读取拒绝、409冲突、429限流、503未就绪/无法确认、200已提交且已应用、202已提交待同步 |

错误外壳固定 `reason`、`message`（脱敏）、`retryable`、`submission_status`（NOT_SUBMITTED/COMMITTED/APPLIED/UNKNOWN）、`fingerprint`/`repair_id`（适用时）、`committed_version`、`applied_version`。错误原因与传输码分离。UNKNOWN 不能让客户端盲目认定失败，应按 fingerprint/repair_id 查询；无回执仅表示当前无法确认，不推导从未提交。validate 不写任何事实，也不生成UUID。

读取许可原因稳定使用 `LICENSE_*` 前缀，P1 的解析/验签原因通过单一映射适配。SQL 包装、NereidsException、FoldConstantRule、ExpressionUtils、HTTP转发必须保留结构化原因，不按字符串匹配。认证失败仍遵守现有协议错误，不能用许可原因覆盖真实身份错误。

部署申请 DTO 精确为 `{schema_version:1,product:"MassDB SQL",deployment_id:<规范小写UUID>,registered_fe_nodes:<0..INTMAX>,registered_be_nodes:<0..INTMAX>}`。UTC日期输入必须有 Z 或 ±HH:MM 时区，拒绝无时区及 `-00:00`；输出整数epoch。JSON 信任清单为 `{schema_version:1,keys:[{kid,purpose,public_key_spki}]}`，1–32 项、64 KiB、kid全局唯一、purpose为license或time_repair、44字节Ed25519 SPKI规范无padding base64url；不同用途不得共用同一SPKI。私钥、测试公钥不得默认进入生产FE包。

管理接口始终验证原主体并要求 ADMIN；普通用户最多看脱敏状态/到期时间。Follower 专用许可适配必须保留 HTTP status/body、原 user@host 和来源，Master再次验证原权限；现有 `RestBaseController.forwardToMaster` 只返回 body，不足以直接承担此契约。证书安全表示在解析/日志之前建立，覆盖多语句、PREPARE、语法错误和失败审计，不只成功命令的 NeedAuditEncryption。

### FE 恢复格式与混合版本

P2 持久化使用 FE 全局 Env 独立对象；外壳 `format_version=1`、模块 `massdbLicenseV1`，单记录/模块上限 2 MiB。新 FE journal opcode 预留 6200–6205（与SQL错误号空间不同，P2写入前再次检查冲突），分别承载初始化、接受候选及回执、基础额度提升、水位、新时钟epoch及修复回执、单向激活/完整性事实。全部属于 FE 元数据，不增加 BE 识别字段。2026-09-24 已核对当前 ErrorCode、OperationType、PersistMetaModules 无 6200–6205 或 massdbLicenseV1 冲突；P2 落地时仍须重查。

外壳至少包含：deployment_id、单向激活状态、独立引导事实、记录/许可应用版本及完整性、raw active/pending/base、base sequence、最高已提交接受序号、紧凑导入回执、时间epoch/水位/修复权限版本/已消费修复回执。成功接受、最高序号和回执在同一原子记录里，不能拆成可见半状态。每个原始证书64 KiB，回执不重复保存完整历史证书。

恢复先读取有界稳定外壳，再对签名槽分开验证。未知外壳版本、长度/整体存储损坏遵守原恢复错误机制；可隔离的证书业务错误不让全FE停写。不得从未验证证书抬高序号、水位、额度。跳过相关记录、忽略新模块或无法确定恢复完整性时保持 NOT_READY；普通 replayedJournalId 不证明许可就绪。基础1FE/0BE仅由真正新集群已提交引导事实授权，缺槽不能推断新集群。

Checkpoint使用独立Env的历史截面，不能读线上静态快照；不生成UUID、不追加journal、不启动daemon，不按当前时间把pending永久晋升。在线Env完整回放后发布不可变快照；回放的历史过期证书派生EXPIRED，不因过期阻塞恢复。

升级分三步：先使全部提供SQL/HTTP/Flight/转发/计划服务的注册FE具备新格式能力；在受控发行窗口验证全部FE包及信任集；然后提交唯一deployment/首证书并单向激活。旧FE缺能力、未知版本、离线未验证FE不得被默认为可服务新规则。验证使用FE管理能力/发行清单，不改BE心跳协议。激活后，不支持把旧二进制直接加入服务或无备份格式迁移地降级；缺证、普通配置、skip journal不能取消激活。混合期不能宣称全FE读取许可已覆盖。

上述升级/格式是 P0 冻结输入。真实 mixed-FE、checkpoint、坏槽、skip、切主和丢响应恢复测试属于 P2/P4；本轮只冻结设计，不冒充运行时通过。

## 3. 五类出口：具体输入与源码挂点

### 共用夹具与观测约定

- 使用独占前缀 `lic_q_<runid>`；内部表 `t(k INT, v STRING, dt DATE)` 含至少三行不同 k，点查夹具采用原版支持的 unique-key/点查配置；另有空表 `empty_t`、两分区表 `pt`（仅 2026-01、2026-02）、视图 `v_t`、已刷新物化视图 `mv_t`、字典 `d`。表结构、创建语句、行摘要写入回执。示例 SQL 中省略前缀，执行器必须替换为夹具实际限定名。
- `V` = 有效且有 DATA_QUERY、节点未超额；`E` = 已到期；`D` = 无证书、尚未生效、非法签名、缺 DATA_QUERY、CLOCK_SUSPECT、LICENSE_NOT_READY、实际节点超额之一。Q01 的核心决策分别注入每种 D；其余以 E 为主并用 V 对照。时间边界用受控核心时钟/隔离 FE 测试注入，不修改共享主机时钟。通过真实导入路径制造的状态与单元注入状态分开记录，不能把后者当成 P2 集成通过。
- `R` 观测：客户端正确的许可证错误码/状态、无业务结果行；不能只匹配错误文案，也不能把语法/权限/环境失败算授权拒绝。V 对照先证明输入、权限、依赖可用。SQL/HTTP Query/Flight 保留各自协议错误映射；Q27 及本轮 H01/H02 要求真实 HTTP 403。
- `S` 观测：首次执行派发/结果发送与许可证检查的顺序；优先用 FE 单元 spy 或测试专用 latch、现有 query/profile/job 记录。不为测试增加 BE 授权代码，不从“结果为空”倒推“未派发”。正常规划可能访问 schema/远端 prepare，本轮不要求规划零外部 I/O。
- `C` 清理：finally 关闭结果集、statement、prepared handle、Flight stream、HTTP 会话；取消仍活动的本次 query/job，核查完成后删除本次表/视图/字典、外部路径、过程、workload group；恢复会话变量与测试时钟；许可状态变体使用新的独占 Env 或合法更高序号续期，不通过降序号/reset 开关回退。保留前后对象/任务/队列计数和实际返回码。只删除独占夹具，清理失败单独 FAIL；不以清理掩盖用例失败。
- 外部 JDBC/Hive/Iceberg/TVF 输入须先有 V 下成功样本和绑定对象/目标类型证据；缺依赖时记 `not_executed_missing_fixture`，不记 PASS。用例文件保存脱敏的实际 SQL 和对象/文件摘要，密钥不写回执。`TVF_X` 为下列固定六类须先在 V 下验证的完整关系表达式：`s3("uri"=...,"format"="csv",...)`、`hdfs("uri"=...,"format"="csv",...)`、`local("file_path"=...,"backend_id"=...,"format"="csv")`、`file("uri"="<owned_http_uri>","format"="csv","column_separator"=",","fs.http.support"="true")`、`http("uri"="<owned_http_uri>","format"="csv","column_separator"=",")`、`query("catalog"=...,"query"="SELECT k,v,dt FROM <remote_t>")`。file/http 模板对应 [现有 HTTP TVF 回归](/data/project/massdb-sql/regression-test/suites/external_table_p0/tvf/test_http_tvf.groovy:30)，实际端点/参数在执行回执固定；不能用构造失败充当许可证拒绝。
- 每组必须产生 `case_id / source_sha / fixture / input / license_state / expected / actual / observations / cleanup / status`。表内列出的变体都是该组的子用例；部分成功不能将整组改为 PASS。开发中先做共享决策单测，再跑实际入口集成，P0 冻结不要求现在运行 P3/P4。

### 查询用例 Q01–Q28

2026-09-25 P3 实施勘误：原 Q16 要求“配置旧 SQL/partition cache 并证明 `handleCacheStmt` 实际命中”，与本分支既有实现不符。[CacheAnalyzer.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/cache/CacheAnalyzer.java:133) 无条件关闭分区缓存入口，且 `getCacheData(false)` 在 fetch 前返回；[StmtExecutor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:1320) 的唯一旧 handler 调用明确传 false。该直接回送子项记为原版不适用，不记通过。Nereids 独立读取 BE cache 并构造 `LogicalSqlCache` 的路径仍真实存在，继续由 Q15 验收；Q16 的缺分类及 schema 变化负例保留。此勘误不改变当前业务拦截规则。

| ID / 出口 | 输入、前提与顺序 | 期望与必要负例 | 观测及清理 | 源码锚点 / 阶段 |
| --- | --- | --- | --- | --- |
| Q01 / 1 协议共用入口 | V、E、每种 D 下执行 `SELECT k,v FROM t WHERE k=1`；MySQL 文本、JDBC 普通及非点查 prepared、HTTP Query、FE Flight 各一次；root/ADMIN 与有 SELECT 权限普通用户 | V 返回夹具行；E/D 各协议 R；root 不豁免；无 SELECT 权限仍保留原权限错误；禁止仅文本入口生效 | R、S；核实 FE 结果路径和分布式结果路径；C，Flight 关闭流与票据句柄 | A01、A02、A03、A04 / P3→P4 |
| Q02 / 1 多语句 | 同一 multi-statement 包 `SELECT 1; SELECT k FROM t; SELECT 2`；另用 latch 在第一条完成后将 V 切 E | E 时第一条探活可成功、业务下一句 R，后续是否执行遵循原协议；V→E 时下一句重新判断；不能把首条准入扩大为整个包 | 保存每条的 ordinal/返回包与状态；清除 latch、连接 C | A01 `executeQuery` 每条新建 StmtExecutor、A02 / P3→P4 |
| Q03 / 1 过程内查询 | 参照现有 PL/SQL 语法建过程执行 `SELECT k FROM t`；另过程先 `INSERT INTO dst SELECT * FROM t` 再 SELECT；两句间 V→E | 过程 SELECT 同普通查询 R；内部写入允许，下一句 SELECT 重新检查；`isRunProcedure` 不能全放行；不用 HOST/文件功能扩大测试范围 | 实际过程调用及子查询 trace；先写后拒绝的写入按原事务语义核查；DROP 过程，C | A05、A02 / P3→P4 |
| Q04 / 1 一般业务依赖 | `SELECT count(*) FROM t`、`sum(k)`、`DISTINCT k`、`SELECT 1 FROM t WHERE k=1`、`SELECT EXISTS(SELECT 1 FROM t)`、JOIN、自有 CTE、UNION 各一条 | E 均 R；聚合/常量输出不等于元数据；负例 `SELECT 1` 允许 | 保存原始语句与绑定/最终计划；无结果 S；C | A02、A06 / P3→P4 |
| Q05 / 1 视图与 MV | `SELECT * FROM v_t`、`SELECT * FROM mv_t`；能在 V 下证实命中 MV 改写的源表查询；`SELECT 1 FROM v_t LIMIT 1` | E 均 R；视图隐藏查询不可借单真实表探测例外；源依赖在 MV 改写后仍保留；未证明改写的样本不能算改写子用例通过 | V 记录 EXPLAIN/命中依据；MV 刷新任务 C，DROP 依赖按逆序 | A02、A06、A07 / P3→P4 |
| Q06 / 1 元数据混合 | `SELECT table_name FROM information_schema.tables`；增加 `WHERE table_name IN (SELECT v FROM t)`；`SELECT * FROM backends()`/`partitions(...)` 的本分支合法元数据输入 | 纯元数据允许；混入业务源 E 时 R；不能只看最外层 information_schema/TVF 名称 | 绑定类型与来源集合；现有元数据权限保持；C | A02、A08 / P3→P4 |
| Q07 / 1 实际系统表及外部表 | `SELECT * FROM __internal_schema.audit_log LIMIT 10`（先确认存在/授权）；分别 `SELECT * FROM jdbc_cat.db.t`、Hive、Iceberg 的真实数据表 | E 全部 R；内部系统命名不等于元数据；每种外部源先 V 成功。已有系统表缺失时用绑定判定单测补覆盖，集成保留未执行 | R、外部读取执行次数/结果摘要 S；保持原审计表，外部独占夹具 C | A02、A06 / P3→P4 |
| Q08 / 1 数据 TVF | 六类各执行 `SELECT * FROM TVF_X`，V→E；对照 `SELECT * FROM numbers("number"="3")` 及元数据 TVF | 数据 TVF E 时 R；numbers/元数据允许；`SELECT 1 FROM TVF_X LIMIT 1` 不获探测例外；`http_stream` 导入不按名字误拦 | 记录实际 TVF 类及绑定 scan 类型；仅要求执行/输出门禁，schema 探测可发生；外部连接/文件 C | A02、A08、A09、A10 / P3→P4 |
| Q09 / 1 探活、管理、元数据 | E 下 `SELECT 1`、`SELECT @@version`、`SELECT DATABASE()`、`SELECT NOW()`、SHOW TABLES/COLUMNS/CREATE TABLE/TABLE STATUS、DESC、SHOW COLUMN STATS、EXPLAIN 业务 SELECT | 保持原能力/权限；真实 min/max 不裁剪；EXPLAIN 不执行结果查询；不把尚不存在的 `@@massdb_license` 列为原版兼容用例 | 结果与 V/原版摘要比较，时间值只核类型/合理范围；C。新增 SHOW LICENSE 属 P2 独立管理测试 | A02 EXPLAIN/handleQueryInFe、A08 / P3→P4 |
| Q10 / 1 最终零行证明 | `SELECT * FROM t LIMIT 0`、`SELECT * FROM t WHERE 1=0`；开/关相关优化或构造“证明未知”单测 | 有完整最终零行且无取数证明时允许；来源已知且证明未知时不能靠估计行数/scan list 空放行；`WHERE k=-1` 若仍扫描则 R | 最终根计划、来源与 proof 一起断言；无首次取数派发 S；C | A02、A11 / P3→P4 |
| Q11 / 1 分区空与非空外层 | `SELECT * FROM pt WHERE dt='2099-01-01'`；`SELECT count(*) FROM pt WHERE dt='2099-01-01'`；`SELECT k FROM pt WHERE dt='2099-01-01' UNION ALL SELECT k FROM t` | 仅第一条在完整最终空证明成立时允许；COUNT 输出一行 0、UNION 有业务非空支均 R；空子树不能代表完整结果为空 | 保存 partition prune 与最终计划、结果根 cardinality 证明，不能用估计代替；C | A02、A11、A12 / P3→P4 |
| Q12 / 1 窄式探测正例 | `SELECT 1 FROM t LIMIT 1`、`SELECT 1 AS alive FROM t LIMIT 1 OFFSET 0`、无改变形状的括号版本；对 empty_t；已绑定外部真实表同形状 | E 下允许；非空返回一个 1、空表零行；OFFSET 0 与省略等价；允许真实取数但不称零读取；普通权限检查保留 | 单真实表/唯一整数字面量/限制形状 proof；真实行访问仅此例外；C | A02、A06 / P3→P4 |
| Q13 / 1 窄式探测反例 | 至少三行 t：`SELECT 1 FROM t LIMIT 1 OFFSET 1`、`LIMIT 2`、省略 LIMIT、加 WHERE/HAVING/JOIN/CTE/UNION/DISTINCT/ORDER BY/窗口/函数/OUTFILE；`SELECT CAST(1 AS INT) FROM t LIMIT 1`；视图与 TVF 见 Q05/Q08 | E 均不能借探测例外；若其他完整零行例外独立成立须另判，夹具保证此组不是空计划；WHERE/ORDER/CAST 被优化删去/折叠也不能扩大原始窄式形状 | 分类单测保留原始语义形状与绑定证据，原查询合法性先 V 验证；OUTFILE 无新文件；C | A02、A06、A11 / P3→P4 |
| Q14 / 1 无扫描字典读取 | `SELECT dict_get('<db>.d','v',1)`、已有合法 `dict_get_many(...)`；BE 折叠开/关、可折叠字面量参数、混入普通表达式，各在 V/E 下 | E 时 R；折叠成字面量/无 scan 仍保留字典来源；普通纯函数常量保持放行；`SET @v=dict_get(...)` 不在本组覆盖，不宣称封堵 | 折叠前 marker 与最终分类断言；R 在返回字典值前；不扩展全函数登记；字典异步刷新/对象 C | A02、A13 / P3→P4 |
| Q15 / 1 FE 结果及 PhysicalSqlCache | V 下填充能确定命中的 FE/SQL cache 业务查询，变 E 后重发同 SQL；另命中纯元数据/探测/零行缓存 | 业务命中仍 R；无 scan 不是放行依据；确有分类证明的允许类保持允许；V 恢复不要求全局清 cache | 记录 cache hit 与返回分支 spy；验证检查先于 sendResultSet/sendCachedValues；每会话变量 C，不用清全局 cache 掩盖路径 | A01 cache parse、A02、A07 / P3→P4 |
| Q16 / 1 旧缓存入口可达性与缺分类 | 先核对本分支旧入口；构造缓存缺失许可来源/空计划证明，以及 schema 变化 | 当前旧 `handleCacheStmt` 直接回送 SQL/PartitionCache 命中不适用：分区入口已禁用，旧 handler 明确禁止 fetch，仍执行普通结果路径；真正 Nereids SQL 缓存命中按 Q15 验收。未知分类在异常态重新规划或拒绝业务读取，schema 变化失效 | 保留原不可达要求的勘误及源码证据，不把 N/A 写成运行通过；缺字段+schema 失效两负例仍必须测试；不在本版恢复旧缓存入口；C | A02 `handleCacheStmt`、A07 / P3→P4 |
| Q17 / 2 prepared 点查 | V 下 PREPARE `SELECT v FROM t WHERE k=?` 并至少执行一次建立 shortCircuit context；E 后同 handle EXECUTE；schema 版本变化重规划；prepared INSERT/Group Commit 对照 | 每个新 EXECUTE 点查和回退普通路径均 R；PREPARE 不提供永久许可；内部写 prepared 仍允许 | 记录 ExecuteCommand 真实短路分支与 PointQueryExecutor 调用次数；拒绝前不 executeAndSendResult；DEALLOCATE/C | A14、A02 / P3→P4 |
| Q18 / 1 实际出队跨期 | workload group 1 个运行槽，用受控阻塞占满；V 提交业务查询并证明 queued，切 E 后释放占槽；Coordinator 与 NereidsCoordinator 两种实际可达配置/单元分别覆盖 | 入队早检成功不代表首次执行已开始；出队时 R、无首次 BE 派发；纯写/元数据不得因为共用 coordinator 误拦；排队超时/取消沿原语义 | 队列 token 获得→拒绝→releaseAndNotify 顺序及运行/等待槽恢复原值；释放阻塞者、还原 workload 配置 C | A15、A02 / P3→P4 |
| Q19 / 1 同次重试与新执行 | V 下证明首次查询实际执行已开始；在可重试错误点暂停并切 E，继续该次内部 retry；再新执行相同 SQL（同连接及新连接）；另首次派发前的重试 | 同次已开始查询沿已有准入事实继续并受原超时/取消；后续新执行 R；首次派发前的 retry 不可凭“进入 retry”获得已开始标志；新 queryId 不等于新用户执行 | 记录 executor/context 生命周期、首次派发和每次 retry；完成/失败/取消后事实清理，不存 session 永久状态；C | A16、A02、A15 / P3→P4 |
| Q20 / 1 跨 FE 新执行 | 两 FE 同一有效证书；一 FE 上查询完成后切 E并确认另一 FE 已应用对应状态；经正常 forward 执行新业务查询；重连另一 FE；伪造 session/Hint internal | 执行侧新执行重新判断并 R；不能跨 FE 复制既往“已开始”事实；仅入站服务器内真实维护用途可豁免，用户名/客户端 Hint 不行；不新增跨节点 token/协议 | 保存 FE 状态版本、forward 路由、接收侧 context 创建证据；复制状态前的观察不能冒充收敛后断言；C | A17、A01 `proxyExecute`、A02 / P2前提、P3→P4 |
| Q21 / 1 OUTFILE | E 下 `SELECT * FROM t INTO OUTFILE '<owned_path>'`；`SELECT 1 FROM t LIMIT 1 INTO OUTFILE ...` 使用本分支合法次序；V 成功对照 | 数据 OUTFILE R；探测例外不能带 OUTFILE；首次拒绝前没有数据文件/成功标记；普通 EXPLAIN 仍按元数据规则 | 路径对象清单/摘要前后比较，结果发送与写 dispatch spy；仅清理 owned_path；C | A02 `handleQueryStmt/executeAndSendResult/outfileWriteSuccess` / P3→P4 |
| Q22 / 3 外部 INSERT | E：`INSERT INTO jdbc_cat.db.dst SELECT * FROM t`、Hive/Iceberg 同类；external→external；`INSERT INTO <external_dst> VALUES (...)` 与 internal dst SELECT 外部源对照 | 前三类受保护源→外部目标 R；纯 VALUES、内部目标允许；按实际 sink/绑定源判定，不按 SELECT 子树一刀切 | 守卫在 beginTransaction/finalizeSink 前；外部事务/行数/文件无新增；允许写用 V 时预存摘要或恢复 V 后核对；C | A18 / P3→P4 |
| Q23 / 3 外部 OVERWRITE | E 下 Hive/Iceberg `INSERT OVERWRITE TABLE ... SELECT * FROM t`；internal overwrite 同源对照；外部 VALUES 若原版支持也对照 | 外部受保护源 R；内部目标允许；提交已 E 时在 overwrite group/task/临时分区登记与事务前拒绝；原版不支持的句型记不适用证据 | before/after 目标数据摘要、临时分区/overwrite task 注册计数和外部事务；无破坏原数据；C | A19、A18 / P3→P4 |
| Q24 / 3 内外 CTAS | E 下 internal `CREATE TABLE dst ... AS SELECT * FROM t`；分支支持的 Hive/Iceberg external CTAS 同源；内部 CTAS 从 TVF/外部源读取 | 内部 CTAS 允许，不能因 validate 的 UnboundResultSink 误拦；外部受保护源 R，必须早于 createTable，不是建完空表再报错 | Env.createTable spy/外部 catalog tableExists、事务计数；已有效开始后的动作不追溯撤销；DROP 本次已成功内部目标 C | A20、A18 / P3→P4 |
| Q25 / 4 EXPORT 提交 | E 下 `EXPORT TABLE t TO '<owned_path>' PROPERTIES("delete_existing_files"="true",...)`；owned_path 预建哨兵，V 对照另路径 | 提交 E 时 R；必须在 addExportJobAndRegisterTask 前，不能登记 job/journal 或删哨兵/注册任务；权限先保留原检查 | ExportMgr/日志/TransientTask 调用 spy、哨兵摘要和路径清单不变；V 对照取消/等完成 C | A21 / P3→P4 |
| Q26 / 4 EXPORT 异步跨期 | V 合法提交但阻止 task 开始；确认提交副作用后切 E，释放任务；另 task 已首次开始后跨 E 的对照 | 未开始 task 经 OUTFILE 入口复核并拒绝；按原取消/清理记录 job 失败；已经发生的登记/删除不保证恢复；已开始查询按 Q19，不一到期就取消 | ExportTaskExecutor→StmtExecutor 顺序、任务状态终态/资源释放、未开始任务无新结果；不宣称“跨期无任何副作用”；C | A22、A21、A02 / P3→P4 |
| Q27 / 5 连接器新计划 | V、E 各 HTTP GET/POST `/api/<db>/t/_query_plan` body `{"sql":"SELECT k FROM <db>.t"}`；V 保存 opaque plan 后 E 再请求；错误权限/畸形 body 对照 | V 返回可用计划；E **真实 HTTP status=403** 且不返回 opaque plan/tablet 执行参数；不能是 200 body.status=403；保存旧 BE plan 仍按已接受边界，不要求 BE 撤权 | 用原始 HTTP client 断言 status line+body，handleQuery 返回前状态复核；不执行/修改 BE 通道；关闭 client C | A23 / P3→P4 |
| Q28 / 兼容写入及真实内部用途 | E 下内部 INSERT VALUES/SELECT（含 TVF→内部）、UPDATE/DELETE（含业务子查询）、内部 OVERWRITE/CTAS、事务；Stream/Routine/Broker Load、Group Commit 用既有成功最小夹具；统计收集和 MV 刷新 | 保持原权限与功能；用户普通 SELECT 不能因复用连接/context 继承写入/维护豁免；服务端真实用途传递且请求结束清理；不增加 compaction/BE 授权修改 | 每写入恢复 V 后比对行/校验和或事务结果；后台任务到终态与资源原值；紧接同连接新 SELECT 应 R；C | A18、A19、A20、A02；各 load/维护现有入口只作兼容回归，不新增独立守卫 / P3→P4 |

### 原 P0 源码锚点（基线行号，后续 P3 已接入）

- A01：[ConnectProcessor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/ConnectProcessor.java:209) `executeQuery`（每条建立 StmtExecutor）、cache 解析、`proxyExecute`；[MysqlConnectProcessor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/MysqlConnectProcessor.java:169) prepared 入口。
- A02：[StmtExecutor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:1189) `handleQueryStmt`；同文件 `handleCacheStmt`、`executeAndSendResult`(:1264)、`outfileWriteSuccess`。守卫须先于 FE 结果/PhysicalSqlCache/旧缓存返回。
- A03：[StatementSubmitter.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/util/StatementSubmitter.java:101) `Worker.call`，用 JDBC `stmt.execute`。
- A04：[FlightSqlConnectProcessor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/service/arrowflight/FlightSqlConnectProcessor.java:93) `handleQuery` 经共用 ConnectProcessor。
- A05：[PlsqlQueryExecutor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/plsql/executor/PlsqlQueryExecutor.java:41) `executeQuery`；夹具语法复用 [test_plsql_routine.groovy](/data/project/massdb-sql/regression-test/suites/plsql_p0/test_plsql_routine.groovy:45)。
- A06：[NereidsPlanner.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/NereidsPlanner.java:220) `plan` 及 `planWithLock`；绑定/原始形状信息在优化删除前保存，最终分类供 A02 读取。
- A07：[NereidsSqlCacheManager.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/cache/NereidsSqlCacheManager.java:331) `tryParseSql`、`tryLockTables`(:569)、`tablesOrDataChanged/viewsChanged`；复用 usedTables/usedViews；[PhysicalSqlCache.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/physical/PhysicalSqlCache.java:52) 缓存叶子无原始扫描。
- A08：[MetadataTableValuedFunction.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/tablefunction/MetadataTableValuedFunction.java:67) `getScanNode`；[BuiltinTableValuedFunctions.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/catalog/BuiltinTableValuedFunctions.java:51) 当前注册集合，不引入独立全量能力表。
- A09：[ExternalFileTableValuedFunction.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/tablefunction/ExternalFileTableValuedFunction.java:243) `getScanNode`；文件类来源由绑定类型识别。
- A10：[JdbcQueryTableValueFunction.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/tablefunction/JdbcQueryTableValueFunction.java:52) `getScanNode`；[JdbcClient.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/datasource/jdbc/client/JdbcClient.java:264) `getColumnsFromQuery` 的 prepare/getMetaData 属已披露规划访问。
- A11：[EliminateLimit.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/rules/rewrite/EliminateLimit.java:35)、[EliminateFilter.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/rules/rewrite/EliminateFilter.java:49)、[EliminateEmptyRelation.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/rules/rewrite/EliminateEmptyRelation.java:54) 的 `buildRules`；[PhysicalEmptyRelation.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/physical/PhysicalEmptyRelation.java:120) 最终空关系。
- A12：[PruneOlapScanPartition.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/rules/rewrite/PruneOlapScanPartition.java:64) `buildRules`。
- A13：[DictGet.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/expressions/functions/scalar/DictGet.java:89) 与 [DictGetMany.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/expressions/functions/scalar/DictGetMany.java:95) 的 `customSignatureDict`；[FoldConstantRuleOnBE.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/rules/expression/rules/FoldConstantRuleOnBE.java:147) `foldByBE`；复用 [test_dict_get_many.groovy](/data/project/massdb-sql/regression-test/suites/dictionary_p0/test_dict_get_many.groovy:59) 的合法字典夹具。
- A14：[ExecuteCommand.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/ExecuteCommand.java:69) `run`(:98 直接短路)；[PointQueryExecutor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/PointQueryExecutor.java:141) `directExecuteShortCircuitQuery`。
- A15：[Coordinator.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/Coordinator.java:684) `exec`、`close`；[NereidsCoordinator.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/NereidsCoordinator.java:141) `exec`、`enqueue`(:517，queueToken.get :535)、`close`。两条路径均在取得 token 后首次派发前复核。
- A16：[StmtExecutor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:489) `queryRetry`、`handleQueryWithRetry`(:882)；后者重试会更换 queryId，因此准入事实须随同次执行上下文而非仅依赖 queryId。
- A17：[FEOpExecutor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/FEOpExecutor.java:77) `execute/forward`；[MasterOpExecutor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/MasterOpExecutor.java:57) `execute`；A01 `proxyExecute` 由接收 FE 创建执行器。
- A18：[InsertIntoTableCommand.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/insert/InsertIntoTableCommand.java:238) `initPlan`，实际 `beginTransaction` :290；共用源/目标判定在副作用前。
- A19：[InsertOverwriteTableCommand.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/insert/InsertOverwriteTableCommand.java:127) `run`，task group/task 注册 :213/:228、后续委派 InsertIntoTableCommand :303。
- A20：[CreateTableCommand.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/CreateTableCommand.java:83) `run`，`validateCreateTableAsSelect` :133、实际 createTable :102、委派 INSERT :113；不能等后者才首次拒绝外部 CTAS。
- A21：[ExportCommand.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/ExportCommand.java:128) `run`；[ExportMgr.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/load/ExportMgr.java:98) `addExportJobAndRegisterTask` 先记 job/journal，再 delete_existing_files，再注册任务。
- A22：[ExportTaskExecutor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/load/ExportTaskExecutor.java:84) `execute`，:153 建立 StmtExecutor 后执行 OUTFILE。
- A23：[TableQueryPlanAction.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/rest/TableQueryPlanAction.java:108) `query_plan`、`handleQuery`；原 P0 基线 catch DorisHttpException 最终仍 ResponseEntityBuilder.ok，该问题后来由 P3 修复并验证真实 status，不能把基线描述当作当前实现。


### H01/H02：2026-09-29 独立 HTTP 读取补充

这两组独立于原 Q01–Q28/M01–M14/U01–U04，不改写原 46 组或历史 JSON。共同状态为“已实现，控制器定向测试及 FE 构建通过”，测试文件为 [LicenseExternalHttpAdmissionTest.java](/data/project/massdb-sql/fe/fe-core/src/test/java/org/apache/doris/httpv2/restv2/LicenseExternalHttpAdmissionTest.java)。本轮是控制器单测和模拟 HTTP 状态映射，真实 guard 配模拟外部依赖；12 项新测试与 30 项原回归均通过，见[v3 构建与测试回执](/data/project/massdb-sql/.build-records/license-http-admission-20260929/checks-v3/completion.json)。没有实际运行 HTTP/ES/broker 服务，不混用验证层级。

| ID | 输入和顺序 | 预期与观测 | 兼容与清理 |
| --- | --- | --- | --- |
| H01 / ES search | POST `/rest/v2/api/es_catalog/search`，使用可用请求体和 catalog/table；有效及过期等异常许可，分别开启/关闭 `enable_all_http_auth`；原认证失败和 HTTPS 重定向对照 | 原认证/重定向先处理；许可拒绝为真实 HTTP 403，JSON 包含 `reason/message/retryable`；不得返回 HTTP 200 错误外壳。拒绝时 catalog 初始化与 `searchIndex` 均不执行；有效态沿用原搜索结果与错误处理 | GET `/rest/v2/api/es_catalog/get_mapping` 保留正常索引/别名/逗号/`*` 元数据能力与原认证；空值、分隔符、查询/片段、百分号编码、空白/控制字符须在初始化前拒绝；关闭 HTTP 认证不关闭许可限制。清理模拟状态、响应及请求上下文，不改 BE |
| H02 / file_review | POST `/rest/v2/api/import/file_review`，使用有效 FileReviewRequestVo；有效及过期等异常许可，认证开关两态、认证失败和重定向对照 | 原认证/重定向先处理；许可拒绝为真实 HTTP 403 及相同结构字段，在文件枚举、broker reader/格式读取器创建及样本读取前返回。有效态沿用 CSV/Parquet 预览逻辑 | 原导入写入不新增许可限制；不扩大到所有文件/过程功能。原 Parquet reader 未关闭 FAIL 保留，本补充不修复或追认其关闭通过；恢复测试配置并释放本轮自有夹具 |

`get_mapping` 的元数据例外只接受保持在单个 URL 路径段内的索引选择器：拒绝空值、`/`、反斜杠、`?`、`#`、`%`、空白及控制字符；保留普通索引名、别名、逗号列表和 `*`。参数检查早于 catalog 初始化，防止 `_search#` 等输入把 `/_mapping` 变成 fragment 而转为业务搜索；非法选择器沿用参数错误响应，不冒充许可 HTTP 403。

两个控制器只调用 `LicenseQueryGuard.checkProtectedRead()`，不解析/重新验签证书，也不增加查询 RPC。`ESCatalogAction` 的搜索用途与 `get_mapping` 显式区分；`ImportAction` 只在 `fileReview` 的外部访问前补守卫。既有账号认证、连接重定向及受限读取判断各自保留，不用关闭认证来改变许可结论。

非查询 `SET @v=dict_get(...)`、过程文件/进程能力、UDF 外发仍是未封堵边界；本轮不恢复全函数/插件审计或零规划外部访问要求。

## 4. 管理、恢复、额度和页面的接入用例

本节为 P2/P3/P2U 输入，全部状态为 `specified_not_executed`；P1 的内存 Store/核心测试不能替代这些运行结果。每行列出的变体须分别记录结果，不能用其中一例通过覆盖整组。

| ID / 阶段 | 输入与前提 | 预期结果、负例及清理 | 源码接入依据 |
| --- | --- | --- | --- |
| M01 / P2 | 新空 Env；Master/Follower 同时 GET deployment；Master 重复初始化，再重启/切主 | 只有 Master 提交一个稳定 UUID；GET/Follower 不生成身份；初始化失败为未就绪，不能凭缺槽获得免费额度；新集群用例不预建业务表或证书 | K1 |
| M02 / P2 | ADMIN 分别用 SQL IMPORT 与 HTTP import 导入 VALID；同内容 VALIDATE；READER/匿名重复请求 | 两入口共用候选策略，提交后才发布版本；validate 不写 journal/UUID/回执；非 ADMIN/未认证按原权限拒绝且无状态改变 | K2、K3 |
| M03 / P2 | 已有 A 后提交：篡改字节、错误 kid/用途、跨 deployment、低 sequence、破坏已接受覆盖的间隙、降额、65 KiB 原文、超过 96 KiB HTTP body | 分别明确拒绝原因，A/最高序号/回执/基础额度保持不变；超限早于排队验签，日志无证书原文；不能用语法错误冒充验签拒绝 | K2、K3；P1 Import/Verifier |
| M04 / P2 | 导入 A 响应丢失后重试；导入 B 后再查 A；相同序号不同字节；两请求并发提交；超过 1,024 回执 | 指纹重试确认原提交而不回退 B；冲突保留旧状态；提交时重查版本，回执淘汰后返回历史不可确认；UNKNOWN 不作未提交，释放验签队列 | K1、K3 |
| M05 / P2 | 保存 image 后追加 journal，恢复及新 FE 加入；active 已过期、坏 pending、坏 base 各独立变体；checkpoint 独立 Env | 恢复同一已提交事实及原证书字节；过期正常派生 EXPIRED；坏 pending 不拖垮 active，坏 base 禁 ADD；checkpoint 不读在线静态快照、不造 UUID/新日志 | K1 |
| M06 / P2 | 跳过相关 journal、忽略新模块、未知外壳版本/超限载荷；混合新旧 FE；激活后尝试加入旧 FE | 不把不完整恢复当作未激活/免费集群；保留 NOT_READY 和原恢复错误语义；所有可服务 FE 格式兼容后才激活，旧格式不得加入已激活服务；BE 不升级 | K1 |
| M07 / P2/P3 | FE 测试时钟在 T、expires_at-1、expires_at；回拨 5 秒/超过 5 秒、前跳 300 秒/超过 300 秒；SET time_zone；重启恢复水位 | 边界等号到期、容差不延长证书，异常保留写入/元数据；SQL 时区不改授权；60 秒水位提交后才发布，查询不写日志；只注入 FE 测试时间，不改宿主时钟 | K1、Q18–Q20；P1 Clock |
| M08 / P2 | 前跳异常后纠正墙钟，申请挑战并提交正确修复票据；过期挑战、切主、错 nonce/epoch/用途及重复票据 | 验证当前进程/任期的 24 小时单调期限；以纠正后的墙钟验证修复；成功持久提交新 epoch，保留证书/最高序号/基础额度；重复仅查旧回执，失败无状态改变 | K1、K3；P1 Repair |
| M09 / P3 | 注册 FE/BE 恰好到限，角色含 Follower/Observer/计算节点；节点离线/重启/心跳恢复；证书过期后 ADD | 完整已注册成员计数，同机多身份分别占额；离线不释放，重连不重复占额；到期仍按已提交基础额度限制 ADD，不能变无限额度 | K4 |
| M10 / P3 | 仅剩一个名额时并发两个 ADD、批量 ADD 两个；与新证导入/基础额度激活交错；注册持久化故障 | 额度预检拒绝发生在任何成员副作用之前，成功新增不超额；并发共享权威提交顺序；原中途提交故障沿原恢复机制核对已提交成员，未消费预留归还，不承诺新增全批次事务 | K1、K4 |
| M11 / P3 | DECOMMISSION、失败 DROP、成功 DROP、重复重放 DROP，再 ADD 一个成员 | 只有实际删除提交释放一次名额；迁移期间仍计数，保留原副本/WAL/quorum 检查；被 DROP 的旧 BE 直连能力不纳入该保证 | K4 |
| M12 / P2/P3 | 导入未来更高额度 pending，推进到 not_before，基础额度提交暂停/失败后恢复；另测新 pending 晚于旧 active 结束且中间从未承诺授权 | 查询可按有效 pending 判断；ADD 在基础额度提交前仍用旧值，提交后用新值；不从墙钟生效推断已提交；恢复/重放不重复激活；未承诺的空档允许导入，空档内查询仍为 EXPIRED | K1、K4；P1 Import/Snapshot |
| M13 / P2 | Follower 上 validate/import/clock repair；Master 权限撤销/切换、HTTP 超时、5 秒未应用、原认证失败 | 原主体到 Master 重验；保留 HTTP 状态和 reason/receipt/version；已提交待应用为 202，未确认是 UNKNOWN；认证错误独立保留，不变成功或空结果 | K3 |
| M14 / P2 | 两验签 worker 忙、32 项队列满、单用户每分钟第 11 次/突发第 4 次；含证书的多语句、PREPARE、语法错误/失败日志 | 管理资源有界，429/Retry-After 或准确 SQL 映射；不长期持有业务全局锁；原文不出现在审计/Profile/HTTP/debug/error 可见记录中；失败/取消归还资源 | K2、K3 |
| U01 / P2U | 登录后其他 Tab、直达 /License、刷新、前进/后退、反向代理前缀、中英切换 | 其他 Tab 零新增许可请求；证书页加载一次，页面/资源/API 路径正确，Tab 选中与权限一致 | K5 |
| U02 / P2U | ADMIN 文件与文本导入、validate 后确认；普通已具 Web 登录资格用户看状态并直接 POST；超大输入/坏证 | 前后端都做权限和大小校验，旧许可保持；输入只在临时内存，关闭/成功/注销清空，URL/storage/日志无原文；不为该功能扩大原 Web 登录资格 | K3、K5 |
| U03 / P2U | 导入已提交待同步/响应丢失，进入回执查询；隐藏/离开页面/注销/网络失败 | 2/4/8/16/30 秒退避、单请求串行、总预算 120 秒；停止后不再自动发新请求，可手动查回执；不重复自动提交证书 | K3、K5 |
| U04 / P2U | active/pending/过期/未就绪/超额/时钟异常；修改浏览器时间；切换 ADMIN/普通用户 | 展示服务端状态、到期及节点用量；本地时间只展示；清除旧角色详情；无每次 GET 验签、全节点同步请求或无界轮询 | K3、K5 |

K1–K5 只定位现有接入点，尚不存在的 LicenseManager/命令/页面由对应阶段实现：

| 挂点 | 当前源码与需要补充的职责 |
| --- | --- |
| K1 | [Env](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/catalog/Env.java:2193) 的 loadImage/saveImage/replay、[EditLog](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/persist/EditLog.java)、[PersistMetaModules](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/persist/meta/PersistMetaModules.java)、[MetaPersistMethod](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/persist/meta/MetaPersistMethod.java)：独立 Env 事实、原子提交/回放/发布、升级激活 |
| K2 | [DorisParser.g4](/data/project/massdb-sql/fe/fe-core/src/main/antlr4/org/apache/doris/nereids/DorisParser.g4)、[LogicalPlanBuilder](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/parser/LogicalPlanBuilder.java)、[加密表示构造](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/parser/LogicalPlanBuilderForEncryption.java)：新增管理语法、权限及早期安全 SQL 表示 |
| K3 | [RestBaseController](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/rest/RestBaseController.java:217)：新增许可适配复用原认证，不能直接用只返回 body 的通用转发丢失 HTTP 状态；管理 API 与 SQL 共用核心 |
| K4 | [Env.addFrontend/dropFrontend](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/catalog/Env.java:3160)、[SystemInfoService.addBackends/dropBackend](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/system/SystemInfoService.java:190)：实际完整成员计数、额度预检及提交后释放 |
| K5 | [顶部菜单](/data/project/massdb-sql/ui/src/pages/layout/index.tsx)、[路由](/data/project/massdb-sql/ui/src/router/index.ts)、[基础路径](/data/project/massdb-sql/ui/src/index.html)、[API](/data/project/massdb-sql/ui/src/api/api.ts)、[请求适配](/data/project/massdb-sql/ui/src/utils/request.tsx)、[中文](/data/project/massdb-sql/ui/public/locales/zh-cn.json)、[英文](/data/project/massdb-sql/ui/public/locales/en-us.json)：懒加载页面、权限和非 2xx 原因/回执传播 |

## 5. 性能用例适用映射

**2026-09-29 最新执行口径：用户要求“完全实现 P4，不需要长时间测试，需要快速验收”。** 本节原 G1–G7 长测参数、容量 R、5 对 A/A 加 5 对 A/B、10,000 次成功和 1%/2% 置信精度方案保留为历史，不再作为本次完成前置条件；产品规则、完整结果 oracle、权限和副作用边界不改变。以下历史“当前”“保留”“正式”均描述调整前契约，不覆盖此处最新决定。

最新 P4 按[主计划第 6、7 节](license-certificate-execution-plan-20260922.md)完成：复用包/class/源码和页面资源明确绑定的 P2/P3/P2U 功能证据；同机、同原版 BE、同百万行数据做文本点查/服务端预编译/SQL-cache/元数据四类六项 A/B，每项每侧预热 10 秒、计时 30 秒；候选实际补五出口、写入、自然到期/续期、额度与页面抽查，最后完成独立自用包、公钥配置、启动及重启恢复。G2–G7 的广度由已有分层功能证据与该部署抽查覆盖，不再逐项重跑原性能窗口或扩建容量工具。

短窗只能报告本环境、本负载的有限性能结果；不能声称零开销、长期稳定或原精度达标。P4 完成状态以[进展记录](license-p4-progress-20260929.md)的最终真实回执为准，本文修订不新增运行通过。

### 历史长测范围与原判据（2026-09-29 快速范围调整前）

原七组代表负载及前置证明如下。“保留”指当时的性能目的，不代表旧 LP 的所有参数笛卡尔积；“部分”“仅观察”“历史退出”保留原含义。历史失败原样保留，不修改原始工具或报告的资格结论。

| 旧 ID | 当前处置 | 当前目的 / 对旧 fixture 的修订 |
| --- | --- | --- |
| LP001 | 保留 → G1 | 文本短路点查；保留真实 SHORT-CIRCUIT 和 payload oracle。 |
| LP002 | 保留 → G1 | COM_STMT_EXECUTE 复用快路径；每连接重新 PREPARE 不能冒充快路径复用。 |
| LP003 | 保留 → G1 | PhysicalSqlCache 命中仍查当前许可；记录实际 BE 缓存地址，不称纯 FE 零 BE。 |
| LP004 | 部分 → G2 | 已有 BE query-cache 命中功能回归；不新增 BE 计数器、认证或分批守卫。 |
| LP005 | 保留 → G1/G4 | 元数据比例和权限保留；另测窄式 SELECT 1 FROM t LIMIT 1、最终零行例外及反例。 |
| LP006 | 部分 → G2 | 复用精确 16 分支 / 4 JOIN / 32 表达式 fixture 检查分类规划成本；不引入全函数审计。 |
| LP007 | 部分 → G2 | 实际缓存依赖失效与结果正确；不要求所有复杂 PREPARE 可复用物理计划。 |
| LP008 | 部分 → G2/G3 | 文件 TVF SELECT / 向内部表导入；删除“规划前零外部访问”断言，schema 推断请求独立记录。 |
| LP009 | 仅观察 | 四 BE 扇出原始记录可复用；不新增逐 fragment 许可工作，不将 3 FE / 4 BE 全矩阵作为开工门槛。 |
| LP010 | 部分 → G2 | FE Flight 新查询许可与完整结果；旧票据跨期只观察。65535 原版 FAIL 保留，不改 BE。 |
| LP011 | 部分 → G3 | FE 新 _query_plan 返回真实 HTTP 403；旧 BE plan 重用仅观察，移除任何 BE 撤权要求。 |
| LP012 | 部分 → G4 | Stream Load 代表持续入库对照，保留真实提交可见性与全内容核对。 |
| LP013 | 部分 → G4 | Routine Load 跨期功能回归；不将旧 1/8/32 × 两批次 Kafka 全矩阵重新列为 P0 前置。 |
| LP014 | 部分 → G4 | Group Commit 的 prepared 写快路径回归，区分 ACK 与最终可见；不执行未改路径的全组合压测。 |
| LP015 | 保留 → G4/G3 | 内部 INSERT SELECT/UPDATE/DELETE/事务继续；外部目标读取受保护源转 G3，不能按写命令统一放行。 |
| LP016 | 保留 → G5 | 排队未派发跨期拒绝，已开始查询沿用原超时；不引入新的执行凭证或执行期限。 |
| LP017 | 保留 → G5 | pending / renewal 边界；查询额度与已持久提交 ADD 基础额度分开。 |
| LP018 | 保留 → G6 | 大输入/坏签名/重复导入管理压力，持续业务不受挤占。 |
| LP019 | 部分 → G5 | ADD/DROP/切主的额度功能；空测试 BE 安全删除；不要求节点失联自动释放。 |
| LP020 | 保留 → G6 | 高频拒绝下写入/元数据；拒绝率和拒绝延迟独立，不包装为查询吞吐收益。 |
| LP021 | 部分 → G7 | 保留页面 1/10/50 并发、300 秒、10 秒手动刷新；语言/前缀/权限做功能覆盖，不恢复旧 54 窗口前置。 |
| LP022 | 保留 → G7 | 页面导入 1/10 并发、回执和有限轮询，B 独有操作只报告实际成本。 |
| LP023 | 仅观察 | 已实现核心成本诊断可复用；无新的全函数分类微基准框架，不代替端到端证据。 |
| LP024 | 部分 → G5/G6 | 实际新增查询上下文/回执/分类状态的结束回收和上限验证；旧 4 小时 × 所有负载不作固定前置。 |
| LP025 | 保留 → G5 | 注入测试 Clock 检查异常/签名修复，背景业务对照；不修改宿主时间、不检查 BE epoch。 |
| LP026 | 部分 / 历史映射 | 保留统计、MV、字典维护兼容与 SELECT dict_get 拦截。ES/file_review 在原五出口收敛时退出，现仅按 H01/H02 补充许可守卫，不复活旧全量负载；全表达式外发仍退出，Parquet reader FAIL 仍留档。 |

### 历史 P4 代表负载与判据

所有组均先固定 A/B FE 源码/脏补丁/包 SHA、相同 BE 包、JDK/GC、CPU/内存/网络、账号和配置、客户端版本、数据哈希；只用实际自用环境。启动业务计时前须有真实路径及 oracle 通过回执，测试代码接受 LP ID 不算证明。

公共数据复用 bench_small：1,000,000 行，id=0..999999，grp=id%1024，v=id%100000，payload=MD5(id)，SUM(v)=49999500000；点表 MoW/store_row_column/light_schema_change=true。写目标每窗在计时外重置，并按已冻结请求数预建足量数据；不同 worker/request 使用不重叠的主键区间，确保每次 UPDATE/DELETE 均实际处理固定 100 行，专门并发冲突功能例外单列。客户端 oracle 使用独立公式而非相信返回行数。

公共到达采用种子 20260922 的固定开环序列，包含客户端排队和超时。在只观察 A 的阶段为每类负载记录明确数值的延迟/错误 SLO、容量校准结果 R 和代表低/高负载的 30%/85% R（状态/管理背景使用 60% R）；必须在看 B 前冻结，容量未证明不能沿用旧点查 4500 QPS 诊断为已合格速率。下列时长为最小窗，业务 P99 不够 10,000 次成功操作就延长。

| 组 | 冻结负载、并发、时长与连接 | 正确性 / 真实路径证据 / 子目标 |
| --- | --- | --- |
| G1 频繁查询与缓存 | point 文本、point server-prepared、固定 SUM SQL-cache、50% SELECT 1 + 25% SHOW TABLES + 25% DESC 分开运行；并发 1/16；预热 120 秒、每窗至少 300 秒；JDBC reuse/per_request 两模式，HTTP Query 使用固定 keep-alive。 | 点查逐次验证 MD5；SHOW/DESC 预先固定结构；点查 EXPLAIN SHORT-CIRCUIT，prepared 记录驱动类型且同句多次 EXECUTE，另取得测试范围的快路径分支证据；cache 的 PhysicalSqlCache + Is Cached:Yes。记录不同连接模式，不合并分位数；无效态缓存拒绝单独功能测。 |
| G2 普通规划和多种取数 | 复杂 SQL 冷/热、普通分组扫描、真实外部 catalog 查询、s3 文件 TVF、Flight 为各自代表窗口；并发 1/8；预热 180 秒、每窗至少 600 秒；冷规划关闭两类缓存且每请求新连接，其余复用；Flight 1024/8192 完整拉流，65535 原缺陷单列。 | 复杂 SQL 33 列按独立模型，固定 view 在 t=180 秒变更并核对失效后结果；分组 1024 组全值；文件复用 100 × 10,000 行 fixture 的 ID/payload；catalog 使用本地固定数据源；Flight 流式全量校验。外部 schema/prepare I/O 记录但不是拒绝失败，真正客户端业务结果受限。各 TVF s3/hdfs/local/file/http/query 做适用入口的功能检查，不每种再复制全性能矩阵。 |
| G3 独立出口和外部写入 | _query_plan + 原 BE scanner 全取数、向一个实际支持外部 sink 的 INSERT SELECT、EXPORT/OUTFILE 分别运行；并发 1/8，预热 180 秒、每窗至少 600 秒；HTTP keep-alive / JDBC reuse；每请求输出到唯一隔离前缀或以 run/request/id 标识行，窗口外清理。 | scanner 复用 1024/8192 fixture 并校验全行；外部写入固定 100 行源片段，sink 端独立读取全部主键和值；导出核对文件记录数/校验和并保存作业状态。外部 JDBC/Hive/Iceberg/CTAS/OVERWRITE 按实际支持做功能覆盖；后两类原 LP 无完整 fixture，P3 必须新增，不冒称已有基线。无效准入在相应 createTable/beginTransaction/作业登记/目录删除前拒绝；_query_plan 断言真实 HTTP 403。 |
| G4 持续允许的写入 | Stream Load 并发 1/8，批次 1000/10000；内部 INSERT SELECT/UPDATE/DELETE 各 100 行操作，JDBC reuse 并发 1/8；预热 180 秒、每窗至少 600 秒，VALID 与 EXPIRED 分别对照相同合法流量。 | Stream ACK 对应唯一事务、全输入哈希和最终所有 ID/列/可见性；DML 用独立预期终态和提交/回滚回执。Routine/Broker Load、Group Commit、内部 CTAS/OVERWRITE 与更新子查询是跨期功能回归；实际守卫若改到这些独立热路径，才追加其代表 A/B 窗口并冻结理由，不自动恢复 Kafka 全矩阵。 |
| G5 状态、队列、额度 | 固定 16 个复用 worker、600 秒窗：写入/元数据各 50%，在 A 已证明容量的 60%；状态事件、队列事件、额度/时钟事件分开。pending 导入 t=120、生效 t=240、续期 t=360；另一次短证书有效期 180 秒，同步长查询已启动及另一查询入队后跨期出队。 | A/B 持续允许背景同流量比较；B 独有状态延迟描述，查询开始/入队/首次派发时间与许可版本关联；通过原权限 DROP 空成员再 ADD/并发超额 ADD、FE 切主及恢复检查已提交额度。测试 Clock 正反异常/修复检查不延长旧证书或原超时；完成/取消/断连后新增上下文回收，1024 回执上限及淘汰后的低序号拒绝。 |
| G6 管理与拒绝隔离 | 600 秒窗，持续合法写入/元数据固定 A 容量 60%；管理并发 1/8/32、速率 1/10/100 req/s，含坏签名/错部署/65537 字节/重复证；另独立 100/1000/10000 req/s SELECT 拒绝，元数据 100 req/s。连接复用，管理 2 线程/32 队列/用户限速原计划不变。 | 记录正常业务完整结果、CPU/延迟/吞吐；管理 400/403/409/429/503/超时按契约核对且有效证书未变化，重复导入只提交一次。A 无授权 API，只比较同背景，B 附加成本单列；A 既有权限拒绝可作诊断，不能宣称它与 B 授权拒绝是完全同语义 A/B。日志、队列、回执/缓存数量须有界。 |
| G7 页面和业务背景 | 详情 1/10/50 browser contexts，300 秒、每 10 秒手动刷新；导入 1/10 contexts，每 context 3 次，300 秒。业务背景固定为 G5 相同两类流量；页面中英文、根路径/实际反向代理前缀、ADMIN/普通用户、Master/Follower 做功能覆盖。 | 其他 Tab 零许可请求；详情真实请求数、最大并发、导航与卸载取消；validate→import→回执遇丢响应，2/4/8/16/30 秒串行轮询、120 秒止；全文不入 URL/localStorage/日志。A 不存在的 License/import 只报 B 成本；业务仍按公共精度门槛。浏览器样本不足 10,000 不宣称合格 P99，绝不拿页面次数替代业务成功数。 |

G1/G2 的窄探测、空计划、外部数据表与字典函数，各 G3 外部目的地、过程内 SELECT、多语句下一句、队列跨期、root 无豁免，都须先有正反功能 oracle。缓存来源缺失不得默认为元数据。含条件探测、聚合空输入返回一行 0、数据 TVF 和隐藏视图查询不得落入例外。

每个保留的等效业务比较至少 5 对独立 A/A + 5 对 A/B，顺序预先冻结；95% 置信、1% 成功吞吐/每成功操作 CPU 和 2% P95/P99 检测精度继续。每窗至少 10,000 成功操作才评价业务 P99；拒绝、错误、超时不计成功。全量错误和排队仍计入报告；查看 B 前冻结各指标的不利变化方向、配对窗口统计方法及数值分辨带，以独立窗口为重采样单位执行 bootstrap；不利变化的置信上界落在该分辨带内且无可重复方向性退化才通过，精度不足记 INCONCLUSIVE，不把“不显著”当等效。

观测优先复用 FE/BE 既有 CPU/RSS/GC/IO/网络指标及计时外 Profile；短路不生成普通 Profile 是既有行为。如用采样分配量必须注明估计误差，不能把线程样本称进程总量。不开新的 BE 许可探针，不用大型通用观测工具工程作为功能开工前置；实际无法测到必要指标时 P4 如实待定。

### 原版证据的可复用范围

以下相对路径均以 `/data/project/massdb-sql` 为根；它们是原版 A 的历史功能/诊断资料，均不能证明候选许可或正式 A/B 已通过。

- LP001–004：`.build-records/license-p0-p1-20260922/path-probes/reachability-report.json` 记录真实短路、SQL cache、BE cache；prepared 驱动/结果不能替代快方法实际调用证据。`.build-records/license-p0-p1-20260924/point-payload-oracle-smoke/completion.json` 为四种连接/协议组合 1,248 次内容正确 smoke。
- LP005/008/014/015：依次为 `.build-records/license-p0-p1-20260924/{lp005-probe-jdk1704-v3,lp008-s3-be4g-v1,lp014-probe-jdk1704-be4g-v3,lp015-probe-jdk1704-be4g-v2}/report.json`；状态分别 FIXTURE_PASS、ORIGINAL_S3_SCHEMA_SELECT_INSERT_REACHABLE、FIXTURE_PASS、FIXTURE_PASS。仅证明原有路径及内容。
- LP006/007：`.build-records/license-p0-p1-20260924/lp007-concurrent-actual-v4-control/v4-completion-audit.json` 为功能窗通过；1,175 次测量请求、33 列正确，实际 SQL 峰值并发 2、DDL 重叠 0，不能证明旧全部并发矩阵或业务 P99 精度。
- LP009/011：`.../lp009-fanout-v2/completion-audit.json` 为真实四 BE / 千万行三档分桶；`.../lp011-external-scanner-be4g-v1/report.json` 为四百万行/重开扫描 fixture 通过。七 namespace 共享宿主不能外推独立多机性能，BE 重开不代表 FE 跨期控制。
- LP010：`.build-records/license-p0-p1-20260924/lp010-flight-be4g-v5/report.json` 状态 FAIL；1024/8192 可达，65535 字符串错误为用户已接受保留的原版 BE 缺陷。不能从当前范围删除失败或补写 PASS。
- LP012：`.../lp012-sustained-actual-v3/root-completion-audit.json` 功能窗通过，600 秒内 10,000 批 / 1,000 万行、实际请求峰值 8；仍无独立 A/A 精度或候选 A/B。LP013 的 `.../lp013-sustained-actual-v1-control/root-completion-recheck.json` 为 FULL_INPUT_WINDOW_COMPLETE_NOT_QUALIFIED，13M 总输入内容核对通过，但生产请求实际峰值 1，不能写成 8 并发完成。
- LP021：`.build-records/license-p0-p1-20260924/lp021-ui-concurrent-actual-v4-control/terminal-receipt.json` 已真实 wait exit 2、TERMINAL_FAILED_CLEANED_RELEASED；1/10 contexts 功能窗通过，50 contexts 在准备阶段 RSS 6963.9375 MiB 超 6144 MiB、尚未进入测量，51 窗未跑。旧 results.json 的 RUNNING 索引已过时，不能沿用作活动状态。
- LP026：`.build-records/license-p0-p1-20260924/lp026-background-http-actual-v7/report.json` 状态 FAILED，Parquet FE 预览遗留一个 reader，用户已接受保留；该 reader 关闭治理仍不属于本轮两入口许可补充，不能把原版关闭行为记为通过。后续关于 LP016–020/022/025 候选语义未实现、LP023 局部诊断及 LP024 无四小时证据的描述保留原冻结时点；当前阶段结果应看 P2/P3/P2U/P4 验收记录。
- 原冻结时 EXPORT、真实外部目标 INSERT/OVERWRITE/CTAS 性能 fixture 及许可 Tab/API 尚未接入；后续已实施范围见各阶段验收，不能把此历史待办当作当前缺项，也不能用原 P4 包证明本轮 H01/H02 已包含。

冻结结论：可据上述数据、矩阵、oracle、证据要求继续实现；性能零退化尚未证明。P0 完成只能表述为“适用范围和可执行验收契约已冻结”，不得表述为“上述负载均已通过”。

## 6. P0/P1 完成核对及后续责任

P0 的完成证据是本文的协议、不变量、Q01–Q28 / M01–M14 / U01–U04 共 46 组具体输入与源码挂点，以及 LP001–026 到七组当前负载的明确适用映射。P0 冻结时的原运行用例状态保留为 `specified_not_executed`，后续实际结果见阶段验收；H01/H02 按本轮新增记录单独验证；没有将任何旧 FAIL、INCONCLUSIVE 或未运行项升级为当前通过。新范围不要求完整旧 26 项基线、多平台验收或全函数框架先于功能开发完成。

P1 当前证据见[核心审计](/data/project/massdb-sql/.build-records/license-p0-p1-current-scope-20260924/p1-audit/report.json)：本轮独立断网编译 14 个当前核心源码，39 个 class 与实际 FE JAR 逐字一致；重新编译现有 8 个测试类并在同一实际 JAR、Temurin 17.0.4+8 上通过 104 项，零失败/跳过；历史签发工具 25 项和实际 JDK 互通 42 项的原始日志、依赖和源码绑定也已复核。历史 Maven target 内 8 份 XML 已不存在，原日志及汇总保留，本轮重新执行补足当前测试证明；不假装历史 XML 仍在。

该历史核对只证明当时的 P0 设计输入和 P1 证书核心，不包含后来 P2/P3/P2U/P4 的验收，也不包含本轮 H01/H02。实际自用环境的信任配置随 P2 接入验证，不安装默认测试根。当前归档、来源哈希和逐项完成判定保存在[本轮核对目录](/data/project/massdb-sql/.build-records/license-p0-p1-current-scope-20260924)。
