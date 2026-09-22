<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# MassDB SQL 授权证书执行计划

日期：2026-09-22。代码调研基线：当前工作区，HEAD `59329855b4e`。
本文是待实施的设计与任务拆分；SQL、API、类名和错误码均为拟新增内容，不表示当前版本已支持。

## 1. 目标与首版执行口径

实现离线签名的产品授权证书，通过 HTTP API 和 MySQL SQL 协议导入，支持查看、续期、自动到期、FE/BE 节点额度及多 FE 同步。
证书不可用时进入“限制业务数据读取”状态：**保持服务运行、数据入库、数据更新和元数据查询；拒绝新发起的业务数据查询及等价导出。**

用户已明确的要求是证书导入、到期管理、写入与元数据可用、限制类似 SELECT 的业务查询，以及限制 FE、BE 节点个数。
下列未明确细节采用建议默认值，便于直接拆任务；正式实现按本表冻结产品口径。

| 项目 | 首版建议默认值 |
| --- | --- |
| 证书作用域 | 一个 MassDB SQL 集群，覆盖该集群全部 FE/BE；不按数据库、用户分别收费 |
| 节点额度 | 证书分别签入 max_fe_nodes、max_be_nodes，按已注册成员计数；不是在线节点数或物理主机数 |
| 超额策略 | 新增时预检并拒绝超额请求；已有成员异常超额时限制新业务读取及继续扩容，保留写入和维护 |
| 导入方式 | HTTP API、SQL 两种入口共用一套校验与持久化逻辑 |
| 到期后的写入 | 保留 INSERT、UPDATE、DELETE、各种 LOAD、事务提交/回滚及必要的内部读取 |
| 写入中的 SELECT | 保留写入集群内部表的 `INSERT INTO … SELECT`、`INSERT OVERWRITE`、CTAS 和更新子查询 |
| 元数据 | 保留结构、分区、索引、运行状态和驱动需要的元数据；限制混入业务数据的表达式/子查询 |
| 探活 | 保留 `SELECT 1`、会话变量及内置版本/当前库函数等经过分类的无业务数据语句 |
| 无证书/已过期 | 限制新业务读取；不停止 FE/BE，不切成禁止写入的数据库“只读模式” |
| 宽限期 | 默认 0；确需试用或延期时签发短期证书，不提供普通配置直接延长时间 |
| 已执行的查询 | 已取得执行准入的查询允许在原有超时内完成；排队未执行的查询在实际启动时重新检查 |
| 管理员 | 管理员也不能绕过业务读取限制；可登录、查看状态、导入和续期 |
| 首版范围 | 存算一体部署；Cloud 需独立验证实例/租户作用域与已有欠费策略后再声明支持 |

“保持写入”指授权模块不额外拒绝现有写入能力；账号权限、容量、集群故障和现有事务规则仍正常生效。
任意 UPDATE 条件、影响行数和运行时间本身可能透露数据信息，因此本方案是产品使用授权控制，不承诺数据保密隔离。

## 2. 操作放行与拦截矩阵

业务读取限制在授权不可用（包括实际节点超额）时生效；节点新增在任何状态下都需检查相应额度。所有操作继续遵守原有权限与执行安全规则。

| 操作 | 结果 | 判断要点 |
| --- | --- | --- |
| Stream Load、Routine Load、Broker Load、Group Commit、现有事务导入 | 放行 | 不在统一连接、鉴权、事务提交或 BE 扫描底层一刀切 |
| INSERT VALUES、UPDATE、DELETE、BEGIN/COMMIT/ROLLBACK | 放行 | 更新/删除执行中需要读原数据也必须正常工作 |
| INSERT SELECT、CTAS、INSERT OVERWRITE | 集群内落表放行 | 判断顶层写入目的和目标 sink，不因存在 SELECT 子树拒绝 |
| 读取受保护业务数据并写入外部 catalog、JDBC/对象存储等目标 | 按数据导出处理 | 从 MassDB 读取后输出到外部，是查询导出的等价通道；不涉及业务取数的外部 VALUES 写入及外部源导入内部表放行 |
| SHOW DATABASES/TABLES/COLUMNS、DESC、SHOW CREATE、分区/索引元数据 | 放行 | 保留原有权限；元数据命令改写成内部 SELECT 后仍保持该用途 |
| information_schema、系统元数据 TVF | 经真实对象和表达式分类后放行 | 不按库名字符串、别名或函数名称直接放行 |
| 元数据 JOIN 业务表、元数据 WHERE 中含业务表 EXISTS/标量子查询 | 拦截 | 检查 CTE、视图展开、表达式子查询及所有关系来源 |
| SELECT 1、SELECT @@version、SELECT DATABASE() | 放行 | 不读业务表；无 FROM 也要检查函数，UDF/文件访问不自动放行 |
| SELECT *、COUNT、SUM、DISTINCT、EXISTS、聚合、CTE、UNION | 拦截业务读取 | 不因只返回一个数字、只选择常量列或被优化成常量而放行 |
| SELECT 1 FROM 业务表、SELECT … LIMIT 0、WHERE 1=0 | 首版按业务读取拦截 | 防止优化后来源消失；驱动若依赖 LIMIT 0 探测结构，后续只增加可证明不执行的专门路径 |
| 普通 EXPLAIN | 放行不执行的计划说明 | 如支持会实际执行的 EXPLAIN ANALYZE，则按其真实读写用途判断 |
| SHOW COLUMN STATS、统计直方图 | 保留结构/统计状态，隐藏业务值 | 当前 min/max 等字段会返回真实值，不能将所有 SHOW 一概视为安全元数据 |
| SELECT INTO OUTFILE、EXPORT、外部读取任务 | 拦截 | 即使不通过 SQL 结果集返回，仍是业务数据输出 |
| JDBC/ODBC/MySQL、HTTP Query、Arrow Flight SQL | 规则一致 | 覆盖文本、预编译、多语句、已有连接、代理转发 |
| SQL/结果缓存、短路点查、物化视图命中 | 拦截新的业务读取 | 不要求“真的扫描 BE”才执行授权检查 |
| CALL、存储过程、用户提交的异步 SQL | 按实际子语句判断 | CALL 本身不整体豁免，写子句放行，读子句拒绝；遵守原有事务语义 |
| 自动统计、物化视图刷新、compaction、修复、复制、调度 | 放行可信内部维护 | 由服务端受控代码声明用途，客户端不能通过 SET/Hint/用户名伪造 |
| 备份/恢复、snapshot、binlog/CDC、文件下载 | 按入口细分 | 保留节点修复与恢复；面向用户输出业务数据的备份/CDC/下载不能被笼统标记为“内部任务” |
| SHOW LICENSE、证书导入、账户与授权管理、KILL、健康检查 | 放行 | 证书失效不能阻断续期与运维，现有访问权限仍需检查 |
| ADD FOLLOWER/OBSERVER/BACKEND、自动发现注册、HTTP 节点注册 | 检查节点额度 | 在权威成员变更前统一预检；超额请求不加入，也不使原本未超额的集群查询失效 |
| 已注册节点重启/重连、心跳恢复、FE 主从切换 | 放行 | 不增加已注册成员数，不重新占一个名额 |
| DECOMMISSION、DROP、修复与数据迁移 | 放行原有合法操作 | 保留副本/WAL/quorum 安全检查，不能因额度紧张强制删除节点或数据 |

首版不新增“DML RETURNING”能力；若当前或后续分支提供返回业务行的 DML，写入目的不能自动豁免其结果输出。
用户可执行的函数、TVF、插件和 UDF 必须有明确能力分类；未知且可能读取或输出业务数据的能力默认要求有效证书。
允许写语句正常返回影响行数和原有错误，不能为绕过读取限制提供原始行/样本输出。

## 3. 当前代码基础与改造位置

目前未发现可直接复用的商业证书导入与运行时 LicenseManager；现有 license 文字/版权展示不承担运行授权。
以下链接对应本次调研的具体挂点，行号会随实现变化。

| 位置 | 已确认行为与改造用途 |
| --- | --- |
| [StmtExecutor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:540) | 当前 execute 主流程使用 Nereids；不能照搬旧 Doris 双 planner 入口设计 |
| [StmtExecutor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:621) | 解析后区分 Command 和查询，适合先确定顶层用途，再在执行前统一准入 |
| [ConnectProcessor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/ConnectProcessor.java:240) | SQL 缓存可在解析前命中；Nereids 缓存路径也可能跳过绑定，需要复用并验证完整分类摘要 |
| [NereidsPlanner.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/NereidsPlanner.java:288) | analyze 后、rewrite 前记录真实表来源与用途，防止优化抹掉扫描节点 |
| [ExecuteCommand.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/ExecuteCommand.java:99) | 预编译点查有直达 PointQueryExecutor 的快路径，每次 EXECUTE 都需检查 |
| [StmtExecutor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:1211) | 存在直接返回缓存结果的路径，授权准入必须早于读取结果 |
| [StmtExecutor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:1897) | executeInternalQuery 会设置 internal 标志；这个通用标志不足以证明可豁免 |
| [ShowColumnsCommand.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/ShowColumnsCommand.java:167) | 部分 SHOW 转成内部 SELECT，需要保留可信元数据用途 |
| [ShowColumnStatsCommand.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/trees/plans/commands/ShowColumnStatsCommand.java:79) | 返回 min/max 等数据值，需要细分统计元数据输出 |
| [StatementSubmitter.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/util/StatementSubmitter.java:118) | HTTP Query 经本机 JDBC 执行，可共用 SQL 核心检查 |
| [TableQueryPlanAction.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/rest/TableQueryPlanAction.java:106) | _query_plan 独立规划并返回可执行计划与 tablet 路由，需要独立准入 |
| [backend_service.cpp](/data/project/massdb-sql/be/src/service/backend_service.cpp:765) | open_scanner 接收外部计划并启动执行，get_next 延续取数；需补 BE 执行凭证校验 |
| [http_service.cpp](/data/project/massdb-sql/be/src/service/http_service.cpp:322) | BE 存在导入、tablet、批量、副本和 binlog 下载路由；需区分用户读取和内部维护 |
| [SqlBlockRuleMgr.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/blockrule/SqlBlockRuleMgr.java:56) | 可借鉴全局对象持久化结构；不复用 SQL 正则黑名单做证书语义判断 |
| [Env.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/catalog/Env.java:2470) | 同类全局对象的 image load/save 接入位置 |
| [PersistMetaModules.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/persist/meta/PersistMetaModules.java:39) | image 模块登记需要和 MetaPersistMethod、Env 一起完成 |
| [MetaPersistMethod.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/persist/meta/MetaPersistMethod.java:183) | image 读写方法登记 |
| [ConnectProcessor.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/ConnectProcessor.java:185) | 现有 Cloud OVERDUE 检查早于语义分类，会整体拒绝部分请求；不可直接作为本功能状态复用 |
| [Env.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/catalog/Env.java:3160) | FE 新增的底层入口；已有 Env 锁，额度检查应早于 BDBHA 和成员表变更 |
| [SystemInfoService.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/system/SystemInfoService.java:190) | BE 批量新增入口；SQL、自动部署等会汇入，本身未提供覆盖所有调用者的额度串行化 |
| [SystemInfoService.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/system/SystemInfoService.java:1136) | 取得完整 Backend 注册快照用于计数；不得用受测试会话变量影响的 getBackendsNumber |

新增主体建议放在独立 `org.apache.doris.massdb.license` 包：

- `LicenseDocument`、`LicenseVerifier`：严格解析、验签和声明校验。
- `LicenseManager`、`LicenseSnapshot`：管理已接受证书、续期候选、版本和不可变内存快照。
- `LicenseClock`：可注入时间源、到期计算和时钟异常判断。
- `NodeQuotaGuard`、`NodeQuotaSnapshot`：基于权威成员表计算 FE/BE 用量，协调成员准入与证书切换，向查询路径发布不可变额度状态。
- `StatementAccessClassifier`、`ExecutionPurpose`：分类真实用途与可信内部来源。
- `LicenseGuard`：统一执行准入；SQL、HTTP 独立读取入口和外部扫描共用一致的决策模型。
- SQL 命令、HTTP Controller、journal/image 序列化适配器、指标与审计适配器。

保留原有用户权限校验。License 不授予 SELECT、LOAD 或 ADMIN 权限，也不把 root 当成免费查询通道。
Cloud 原有欠费限制若存在仍独立生效；本功能不能承诺绕过它来维持写入。

## 4. 证书格式与签发

建议使用离线签名的 JWS Compact 证书文件，扩展名 `.massdb-license`，不要求客户端访问公网。
保护头固定 `typ=massdb-license+jws`，包含 `kid` 和允许列表内的 `alg`。
首版建议 Ed25519，并在实际 JDK/签名库上验证兼容；Java 17 标准算法名包含 Ed25519，JOSE 的精确算法标识见 RFC 9864。
这两点分别依据 [Java 17 安全算法名称](https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html)
和 [RFC 9864 §2.2](https://www.rfc-editor.org/rfc/rfc9864.html#section-2.2)。

| 声明 | 用途 |
| --- | --- |
| schema_version、policy_version | 格式与策略版本；未知必需版本拒绝导入 |
| license_id、issuer、customer_id | 证书唯一标识、签发方、客户归属 |
| product | 固定为 MassDB SQL，防止跨产品使用 |
| deployment_id | 集群级随机 UUID，持久化并复制到所有 FE，支持扩缩容和普通故障恢复 |
| issued_at、not_before、expires_at | UTC 整数秒，明确起止语义；`now >= expires_at` 即失效 |
| sequence | 同一 deployment 单调递增的签发序号，拒绝旧证书回退 |
| edition、features | 首版包含业务查询能力；CPU、内存或存储容量计费不在本次范围内 |
| limits.max_fe_nodes、limits.max_be_nodes | 分别限制注册 FE/BE 数量，两者都必须参与签名，不能由客户端配置覆盖 |

验签覆盖原始 JWS signing input，不做“解析 JSON 后重新序列化再验签”。
拒绝重复关键字段、类型混淆、超长输入、未知关键扩展、`alg=none`、任意远程公钥 URL 和证书自带的不可信公钥。
限制证书大小，例如 64 KiB；格式解析和签名校验不在 SQL 高频路径执行。

签发工具与生产数据库分离：由签发方持有私钥，数据库仅安装可信公钥；开发测试使用专用测试密钥。
交付物包含生成部署申请信息、签发、离线验证、续期的工具及字段说明。
公钥按 `kid` 管理，支持新旧公钥重叠升级；生产包不包含签发私钥或测试信任根。
证书提供真实性/完整性，载荷不默认加密，因此仅放必要客户标识，不放联系方式或密码。

不直接用 IP、MAC、主机名或现有可配置整数 cluster_id 绑定，避免节点替换、容器重建和扩容频繁失效。
全量克隆元数据也会复制 deployment_id；普通离线绑定不能阻止拥有完整宿主机权限的克隆或修改二进制。
若需要防克隆、硬件绑定、强吊销或抗离线回滚，另行增加在线租约/可信硬件能力，不能把首版宣称为已解决。

### 4.1 FE/BE 节点数量限制

证书增加如下必需字段，示例表示最多 3 个 FE、10 个 BE；实际额度由签发时指定：

```json
{
  "limits": {
    "max_fe_nodes": 3,
    "max_be_nodes": 10
  }
}
```

两项首版均为正整数；缺失、0、负数、溢出或非整数拒绝导入，不约定缺失/0/-1 表示无限制。
许可格式/策略版本必须能识别这些必需字段；不让旧验证器静默忽略额度声明。
首次导入、续期、扩容都校验限额；扩容通过更高 sequence 的新证书提高上限，并沿用已有有效期不缩短的规则。

| 对象/状态 | 计数规则 |
| --- | --- |
| FE | Env.getFrontends(null) 的全部当前注册成员；含 Follower、Observer，Master 是其中一个成员的运行身份，不额外 +1 |
| BE | 完整 Backend 注册表按唯一成员 ID 计数；首版计算节点也占 BE 额度，不能靠角色标签变化绕过 |
| 离线、心跳失败、尚未启动的已注册节点 | 继续计数，防止停一个节点后加入新节点再恢复旧节点而超额 |
| 正在 DECOMMISSION 的 BE | 继续计数；原有安全检查及迁移完成、真正从成员表移除后才释放 |
| FE 主从切换、同一已注册身份重启、修改地址而未增加成员 | 不增加用量 |
| 同主机运行多个已注册进程 | 按成员数计，不能按唯一 IP 合并额度 |
| 已 DROP 的历史记录、Broker、Meta Service | 不计入 FE/BE 当前额度 |
| Cloud/多 compute group | 首版不声明支持；后续以实例权威成员服务原子校验，不能仅计算当前会话所在 group |

查询许可与基础节点额度的寿命分开：**查询授权过期后，最后已生效且仍可验证签名/集群绑定的基础额度继续约束节点管理**。
在该上限内允许正常注册与维护，过期状态仍拒绝新业务查询；未来生效的 pending 不能提前提供扩容额度。
没有任何可信已生效额度时，只允许全新集群初始化首个 FE 以生成 deployment_id 和导入证书；其他新注册先取得证书。
已有成员的启动、重放、重连和写入不依赖重新取得节点名额。无证书的全新单 FE 在加入 BE 前需要完成导入，这一前置条件应写入安装文档。

正常扩容按 `注册用量 + 已保留的新增名额 + 本次净新增数 <= 生效上限` 校验，FE/BE 分别计算，名额不能相互借用。
达到上限并不禁用查询；只有实际注册数超过上限才进入 LIMIT_EXCEEDED。拒绝一次超额 ADD 不改变当前授权状态。
完整计数失败应返回元数据/额度不可确定错误，不把异常空集合当作 0；此时拒绝新成员，继续保留原有写入/维护能力。

候选证书上限低于当前用量或已保留名额时拒绝导入，返回 actual/limit/缺口并保留旧证书；pending 同样提前校验。
仍有效的证书不允许通过替换降低当前额度；已接受 pending 也不能被替换成更低覆盖。
未来生效切换时再校验当前成员快照，异常超额不得导致 FE 启动/重放失败，而应派生 LIMIT_EXCEEDED 并报告原因。
恢复、历史状态或异常成员变更造成已有超额时，不自动摘除节点、不停止事务，不拒绝续期；合法缩容或导入足额证书后自动解除额度限制，时间/能力等其余条件也满足时恢复查询。

满额替换节点要单独处理：同一成员身份的原地重启不需要额外名额；若需要新旧节点并存以迁移数据，首版要求预留额度或导入正式扩容证书。
不能把“先强制 DROP 旧 BE 腾名额”作为默认方案，也不能跳过 FE quorum 或 BE 副本/WAL 检查。
若后续需要短期换机额度，应增加独立签名的、绑定替换对象和有效期的临时增量；到期回落到基础额度，不踢节点、不停写入或迁移，只对超额状态实施约定限制。
临时增量不能直接复用“过期后仍保留额度”的基础证书字段，否则临时升额会变成永久升额；首版不默认赠送无限制换机窗口。

### 4.2 节点准入的实现与性能

Master 的底层成员管理入口统一检查，覆盖 SQL、新旧语句适配、HTTP NodeAction、DeployManager 和内部自动发现。
不能只在 AlterSystemCommand/SystemHandler 加判断：其他调用者可以直接调用 Env.addFrontend 或 SystemInfoService.addBackends。
FE 在成员表/BDBHA 产生副作用之前检查；BE 先验证整个批次的合法性、重复身份和净新增数量，再开始任何单节点加入。
批量超额应整批拒绝，不能先加到上限再让剩余节点失败；日志/I/O 故障仍遵守原有可能部分提交的恢复语义，不承诺批量事务原子性。

节点新增与证书提交必须共用容量决策序列或可靠的名额预留，防止并发 ADD 和换证同时读取旧用量后各自通过。
明确 Env、成员管理和许可提交的锁顺序；不新增“持许可状态锁等待 journal，重放又等该锁”的环路，也不将重型验签放进 Env 锁。
若使用预留机制，提交不确定时不得提前释放名额，Master 切换/重启后按已提交日志与成员表恢复，保证不会双占或超发。
DROP、真正退役、ADD 提交、证书生效及重放都更新额度快照；replay/image 加载只恢复已提交事实，绝不按当前期限/额度拒绝历史成员记录。

每个查询只读取已发布的 used_fe/used_be、限额和状态做常数次比较，不遍历全部节点、不逐查询发 RPC。
完整成员表扫描集中在启动恢复、成员变更或换证等低频路径；计数必须使用无测试覆盖、无异常转空的完整注册快照。
许可版本与成员版本一起标识快照；Follower 通过日志回放更新，用现有节点就绪与回放滞后规则避免未恢复成员信息的节点提供业务查询。
传播延迟仍需明确展示与验证，不声称多 FE 在同一纳秒切换；Master 入口严格拒绝超额注册是防止常规绕过的首要保证。

## 5. 状态机、续期和时间处理

| 派生状态 | 条件 | 新业务读取 | 写入/元数据/续期 |
| --- | --- | --- | --- |
| MISSING | 无已接受证书 | 拒绝 | 放行 |
| VALID | 验签、绑定、能力、时间及节点额度均满足 | 放行 | 放行 |
| EXPIRING | 有效且进入预警窗口 | 放行并预警 | 放行 |
| NOT_YET_VALID | 只有未来生效证书 | 拒绝 | 放行 |
| EXPIRED | 已达到 expires_at | 拒绝 | 放行 |
| INVALID | 已保存的证书无法通过校验 | 拒绝 | 放行；允许用合法新证书修复 |
| CLOCK_SUSPECT | 检测到显著时间回拨/异常 | 拒绝 | 放行并告警 |
| LIMIT_EXCEEDED | 已注册 FE 或 BE 数超过生效额度 | 拒绝 | 放行，并保留修复/合法缩容；拒绝继续扩容 |

证书有效性、时间、FE 额度与 BE 额度保留独立原因，支持同时报告过期和超额；面向查询的最终判断是所有必要条件均满足。

状态按已验签快照和当前时间派生，不依赖定时器把 VALID 写成 EXPIRED。
每次业务读取准入进行 O(1) 内存和时间检查；定时任务仅用于告警、状态汇总和有限频率的时间水位保存。
无证书、过期或证书模块可隔离的故障不能导致整个 FE 启动失败；底层 image/journal 整体损坏仍按原有恢复机制处理。

导入规则：

1. 检查身份/导入权限和请求长度，严格解析、验签，再校验产品、deployment、时间、能力、节点限额及序号。
2. 完全相同证书重复导入返回幂等成功；同一 ID/序号却不同内容返回冲突。
3. 低于已接受最高序号的候选拒绝；已过期、篡改或绑定错误的候选拒绝，**保持现有有效证书不变**。
4. 首版续期只允许延长或保持授权覆盖，不得缩短仍有效授权的截止时间、削减查询能力/节点额度或破坏已接受 pending 的覆盖；这类缩权候选拒绝导入。
5. 续期证书已生效则提交后原子替换；未来生效证书作为 pending 保存，当前有效证书继续使用。
6. 首版最多保存 active 与一个 pending；替换 pending 也必须递增 sequence。到达 not_before 后按时间确定应使用的证书。
7. 没有合法 pending 时到期直接进入受限状态；续期成功后新查询自动恢复，原有连接无需重连或重启。

到期准入时刻定义为进入实际执行、读取缓存结果或建立外部扫描会话之前；不能在连接建立、PREPARE 或入队时永久缓存许可。
有效期内已开始的查询保留准入信息并受原有超时约束；内部重试只能继承同一 query 的有界准入，不得通过新 query ID 或无限续期延长。
严格“到点取消所有在途读取”会涉及 FE/BE 取消与客户端部分结果语义，作为可选产品策略，不默认开启。

时间以 UTC 校验，界面可另行显示当地时区。
进程内结合墙钟与单调时钟避免回拨延长当前许可；跨重启保存时间高水位并设置小幅校时容差，容差不得额外延长到期上界。
水位定期批量持久化，不逐查询写 journal；故障切换、时钟前跳后校正和旧快照恢复都需要专门测试。
异常大幅前跳导致的高水位锁定应有签发方签名的有界修复凭证或明确恢复流程，不提供普通 SQL 修改到期时间。
离线水位仅能发现部分回拨，无法防止整个状态和时钟一同回滚；此限制必须写入运维说明。

## 6. SQL 与 HTTP 接口

以下是拟定接口契约，实施时新增语法并做关键字兼容测试。

```sql
-- 原有数据库账号认证；仅授权管理员可执行。
ADMIN IMPORT LICENSE '<完整的 compact JWS 证书文本>';

-- 不写入状态，供上线前检查。
ADMIN VALIDATE LICENSE '<完整的 compact JWS 证书文本>';

-- 失效时仍可执行。
SHOW LICENSE;
SHOW LICENSE DEPLOYMENT;
```

SQL 导入证书内容，不把 `'/tmp/license'` 当成客户端文件路径，也不引入服务器任意文件读取或 LOCAL INFILE。
命令实现支持参数化提交作为目标；若首版驱动/语法不能 PREPARE ADMIN 命令，应在文档说明，并由安全脚本从文件读取后正确生成文本导入。
证书原文必须在命令审计、query profile、慢日志、异常、HTTP 日志和可见 SQL 状态中脱敏；不能只处理成功后的审计事件。

| HTTP | 用途 | 响应 |
| --- | --- | --- |
| GET /api/license | 当前及待生效授权摘要 | 状态、到期时间、features、FE/BE 用量与上限、指纹、许可/成员版本、查询是否可用、原因码 |
| GET /api/license/deployment | 签发申请信息 | deployment_id、产品、协议版本、当前 FE/BE 注册数；不返回集群认证 token |
| POST /api/license/validate | 验证候选证书，不提交 | 合法性、适用性、切换时间、将产生的状态、FE/BE 配额是否覆盖现有规模 |
| POST /api/license/import | 导入或续期 | 持久化版本、指纹、实际状态、多 FE 应用进度 |

POST 请求体统一 `{"certificate":"<compact JWS>"}`；API 客户端可从本地证书文件构造请求。
鉴权沿用现有体系，首版用既有 ADMIN 权限执行导入；完整客户/签发信息也仅管理员可见，普通用户最多获取脱敏状态与到期时间。
提供 TLS 部署示例，不另设无认证的“紧急导入”端口；过期状态仅跳过业务查询许可要求，不跳过密码与账号权限检查。

定义稳定原因码，例如 `LICENSE_MISSING`、`LICENSE_EXPIRED`、`LICENSE_INVALID_SIGNATURE`、
`LICENSE_DEPLOYMENT_MISMATCH`、`LICENSE_NOT_YET_VALID`、`LICENSE_ROLLBACK_REJECTED`、`LICENSE_CLOCK_SUSPECT`。
节点相关原因码增加 `LICENSE_FE_LIMIT_EXCEEDED`、`LICENSE_BE_LIMIT_EXCEEDED`、`LICENSE_NODE_LIMIT_TOO_SMALL`，错误中返回当前数、本次申请数和上限。
SHOW LICENSE 与 GET /api/license 都显示 registered_fe/max_fe、registered_be/max_be、剩余额度、pending 限额与生效时间；详细拓扑仍走现有 SHOW FRONTENDS/BACKENDS 权限。
SQL 分配不冲突的 MySQL 错误号和稳定 SQLSTATE，映射时保留授权原因；HTTP 区分 400 格式/候选无效、401 未认证、403 无权限/读取被拒绝、409 版本冲突、503 无法提交。
错误说明给出到期时间和恢复方式，不返回证书原文，不伪装成语法错误、空结果或数据库连接故障。
HTTP 和 SQL 返回相同的许可决策，不能出现 HTTP 限制而 JDBC 可读。

## 7. FE 持久化与多节点一致性

将 `LicenseManager` 作为 Env 的全局管理对象，复用现有 FE 元数据复制体系，不另起 SQL 业务表保存唯一真相。

1. deployment_id、active/pending 原始签名证书、已生效基础额度的证书来源/生效进度、最高接受序号、记录版本及时间水位进入 journal 和 image；恢复后重新验签，不信任脱离签名载荷的配额数值。
2. 新增 journal opcode、记录序列化/反序列化、EditLog 提交、replay，以及 image 模块和读写注册。
3. 只有 Master 执行导入提交；Follower/Observer 转发并等待相应日志版本，保留原始操作者身份。
4. 先在无全局锁条件下解析验签，再在短提交临界区重查版本并提交；重放同一记录幂等。
5. 不在持有 License 状态锁时等待日志确认；设计提交串行化和已提交快照发布顺序，避免日志线程回调锁环。
6. 提交持久化成功后发布不可变快照；提交失败保持旧授权。提交结果不确定时按指纹/请求标识查询确认后重试。
7. 启动、image 加载、journal 重放和新 FE 加入后重新验签并派生状态，不持久化一个永久 VALID 布尔值。
8. 接口返回 committed_version 和各服务 FE 的 applied_version；对落后节点返回“已提交、部分节点待同步”，不要误报所有节点即时生效。

候选导入校验与历史记录重放分开：历史证书已经到期或可隔离的证书验签失败，应形成 EXPIRED/INVALID 状态，不能因此令 journal replay 失败并阻断整个集群启动。

所有节点基于证书自身 expires_at 本地限制到期读取，不等 Master 广播“已过期”。
续期传播是有界最终一致：落后 FE 可以暂时拒绝查询，但不能因未收到到期事件继续无限读取。
导入节点具备读己之写保证；恢复查询的节点时延写入验收目标并实测。
不为每个 SELECT 同步 RPC 到 Master，否则授权故障容易放大为查询和入库故障。

首版不提供管理员任意缩短授权、删除 active 或在线吊销接口；签发方紧急撤销需要版本传播/租约的一致性设计。
“离线节点立即得知新吊销”无法靠静态证书保证，不应承诺。

## 8. 执行拦截与旁路闭合

核心判定是“来源 + 目的 + 输出位置”，而非 SQL 关键字或物理扫描节点数。

```text
客户端认证与原有权限
    -> 解析顶层语句，记录用户来源/服务器可信内部用途
    -> 绑定真实对象，递归检查视图、CTE、表达式子查询、TVF 与 sink
    -> 保存不可变访问分类摘要（早于 rewrite/常量折叠）
    -> 排队后/执行前 LicenseGuard 准入
    -> 分派 BE、点查、缓存结果、文件输出或外部扫描
```

实施细节：

- 类别至少包括 USER_DATA_READ、METADATA_READ、DATA_WRITE、SYSTEM_MAINTENANCE、LICENSE_ADMIN；未知可能读取的类别要求有效证书。
- 为 Command 编写显式解包与适配，不能假定所有命令支持通用 children 遍历；现有 isQuery 也不足以判定导出、EXECUTE 等用途。
- 内部用途由受控调用点创建并按作用域传递/恢复，禁止从 session variable、Hint、客户端 header、root 用户名或 `isInternal` 单独推导。
- WRITE 内部读取的豁免只作用于该次受控计划；用户 CALL 或用户定时任务不能把后续任意 SELECT 标成内部维护。
- 权限与表/函数绑定期间如需执行内部子查询，也要带明确用途；分类前不能先执行用户数据表达式或读取外部文件。
- 缓存条目和 prepared plan 保存访问分类与依赖对象版本。命中时重新读当前证书，摘要缺失/失效则重新分类或拒绝，不默认视为元数据。
- 每次 EXECUTE、转发后的新执行、多语句中的每条语句均检查当前证书；同一已准入查询的内部重试校验原准入信息和原截止时间，不因跨越到期而强制中止，也不得延期或扩大读取范围。
- 许可证拒绝必须作为终止性错误，不能被 fallback/retry 当成换路径即可恢复的错误；尚未准入的失败执行不能伪装成已有许可的重试。
- 异步导出创建及实际子任务启动都需检查；准入前不分配执行资源、不创建外部输出文件。
- 旧连接及缓存无需因续期强制清空；生效时机由当前快照和准入规则决定。

外部扫描是必做项：`_query_plan` 会输出可在 BE 执行的计划，BE `open_scanner` 再启动读取，之后 `get_next` 取数。
FE 发计划前检查；BE 建立外部扫描时也验证受信任 FE 发出的有界读取凭证，不能把旧的 Base64 plan 当成永久授权。
凭证至少绑定集群、许可版本、query/scan 标识、计划摘要、允许的操作与建立扫描的期限，期限不得晚于证书到期。
凭证使用独立集群密钥/受信任服务身份体系，不能把厂商证书签发私钥下发给 FE；现有 RPC 认证不能单独替代到期检查。
需要测试跨 BE 重放和多分片使用，允许范围由 scan/fragment 绑定决定；客户端不可扩大 tablet/计划范围或伪装内部任务。
已建立扫描继续取数遵守在途策略及原有超时，不能在 get_next 中延长期限或创建新扫描。

BE `_download`、tablet/snapshot 文件、binlog/CDC、Arrow Flight 结果等逐项列出实际用户入口与集群内部调用。
对用户新发起的业务读取执行许可检查或有界凭证校验，同时保留复制、修复、入库排错所需内部链路并控制样本数据展示。
只在网络层关闭整个 BE HTTP/RPC 端口会破坏写入和维护，不能作为实现方案。
若某类用户可达读取旁路未闭合，则该通道不能算在首版已完成的支持范围内。

## 9. 任务拆分、依赖和交付物

以下为工程估算，单位人日；以熟悉当前 FE/BE 的开发者为前提，实际由旁路清单和集成测试结果修订。

| 阶段 | 工作与交付 | 估算 | 完成条件 |
| --- | --- | --- | --- |
| P0 规则与入口清单 | 冻结放行矩阵、接口、证书声明；枚举正常与旁路入口 | 2–3 | 每个入口有用途、改动位置和对应测试；无“所有 SELECT/SHOW”粗分类 |
| P1 证书核心 | 签发/验证工具、可信公钥、状态/时间/续期模型、单测 | 3–4 | 篡改、边界时间、错集群、旧序号和幂等用例通过 |
| P2 持久化与管理 | Env、journal/image、API、SQL、权限、脱敏、多 FE 状态 | 4–5 | 重启/重放/主切换不丢授权，导入失败不伤旧证书 |
| P3 SQL 准入 | 语义分类、可信用途、缓存/点查/预编译、写入和元数据保留 | 5–7 | 文本/JDBC/HTTP/Flight 到期后行为一致，写入与驱动元数据不误伤 |
| P3Q 节点额度 | FE/BE 注册计数、底层准入、并发/批量预检、换证协调、额度状态/API | 3–5 | SQL/HTTP/自动发现均不超发；离线/退役/重放/主切换和满额维护语义通过验收 |
| P4 外部读取 | query_plan/open_scanner 凭证、导出与其他用户读取旁路闭合 | 4–6 | 旧计划重放、新扫描和用户外部数据输出不能绕过到期限制 |
| P5 集成与交付 | 多 FE/BE、故障/时间/升级测试，性能对照，文档与告警 | 4–5 | 全矩阵验收、持续入库到期续期演练、兼容升级演练完成 |

加入节点额度后合计约 **25–35 人日**；两名熟悉 FE/BE 的开发者并行、测试同步准备，日历排期可先按 **4–5 周**估算。
P1 与 P0 已确定的分类调研可并行；P2/P3 在核心接口确定后并行，P3Q 依赖许可快照与提交契约并与 P2 联调；P4 的凭证契约应尽早确定，P5 依赖全部路径联调。
只完成“证书解析 + SELECT 拦截”的演示不能作为正式版本验收。

首版交付包含：生产功能、签发/验签工具、测试证书、SQL/API 文档、状态/指标说明、部署申请与续期操作手册、升级兼容说明。
管理 UI、提前 30/7/1 天之外的通知渠道、自助签发平台、在线吊销、硬件绑定、短期换机增量及 CPU/存储容量计费属于后续可选项；FE/BE 基础节点额度已纳入首版。
提前 30/7/1 天的基础告警事件与可抓取指标应在首版提供；不在高频拒绝路径重复打印大段错误或证书。
节点指标增加 FE/BE 注册数、额度、剩余名额、准入拒绝数、额度异常和各 FE 许可/成员版本差异；满额与实际超额用不同状态表示。

## 10. 验收与测试计划

| 组别 | 必测场景 |
| --- | --- |
| 证书正确性 | 合法、缺失、损坏、篡改、错误签名/kid/算法、重复字段、超长、错产品/集群、未知必需版本 |
| 生命周期 | not_before 前/恰好生效、expires_at 前/恰好到期、预警、pending 自动切换、有效期有间隙、重复导入、旧序号、失败导入保持旧证书 |
| 节点限额 | FE/BE 分别在 limit-1/limit/limit+1 下的新增；字段缺失/0/负数/溢出、配额不足导入、未来配额不提前使用、正式升额后扩容 |
| 节点计数 | Master 不重复、Observer 计入、离线与未完成退役仍占额、真正 DROP 释放、同机多实例、计算节点改角色、测试变量/会话 group 不影响权威用量 |
| 准入并发 | 同时 ADD、整批超额零新增、HTTP/自动部署旁路、ADD 与导入/生效竞争、提交不确定、切主后名额重建、成员读取失败不作0 |
| 维护与超额恢复 | 同身份重启、满额换机不强制DROP、过期后基础额度内维护、过期且超额时仍可入库/更新/迁移/续期、安全缩容/扩容换证后恢复查询 |
| 写入持续性 | 测试开始前启动持续 Stream/Routine/Group Commit 入库，跨到期/续期运行；核对提交、可见行数、重试和事务结果 |
| 数据修改 | VALUES、INSERT SELECT、CTAS、OVERWRITE、UPDATE JOIN/子查询、DELETE、已开启事务跨到期后提交/回滚；以当前语法支持为准 |
| 元数据兼容 | SHOW/DESC、JDBC DatabaseMetaData、常见驱动连接初始化与探活、metadata TVF、外部 catalog 元数据、统计字段脱敏 |
| 读语义 | 聚合、CTE、视图、子查询、UNION、元数据混入业务读取、业务表 LIMIT 0/恒假条件、TVF/UDF、外部数据源 |
| 执行快路径 | PREPARE 有效时/EXECUTE 到期后，点查、缓存命中、物化视图改写、排队跨到期、重试、转发、已有连接、多语句 |
| 非 SQL 通道 | HTTP Query、Flight、query_plan、有效期内取得计划在过期后 open_scanner、get_next 在途超时、EXPORT/OUTFILE、用户下载/CDC |
| 内部来源 | SHOW 改写、统计、MV 刷新正常；SET/Hint 伪造 internal 无效；用户 CALL/异步任务内部 SELECT 不能豁免 |
| 多 FE 与持久化 | Follower 导入、并发导入、日志确认失败/结果不确定、重放两次、checkpoint 后重启、Master 切换、Observer 落后/加入 |
| 时间与恢复 | 单调时钟、墙钟回拨/前跳、容差边界、重启高水位、校时恢复、旧 image 恢复、不同 FE 时钟差异 |
| 运维与性能 | 无证书仍可登录/导入/探活，root 同样限制业务读，API/审计/profile 脱敏，告警限流，不逐查询验签/持锁写日志/RPC |
| 版本兼容 | 旧 image 升级、新模块/新 opcode、滚动阶段禁止过早写新格式、激活后的旧节点阻止加入、既定回退流程 |

多语句和存储过程还需验证“前序写入已成功、后续读取因授权失败”的部分成功语义，客户端不得盲目重试整个批次造成重复写入。

单元测试注入 Clock，避免等待实际天数；集成测试以分钟级测试证书验证真实到期链路。
新增 FE 测试放在对应 JUnit 目录，BE 凭证/扫描测试放在匹配的 GoogleTest 目录，SQL 集成在 regression-test 增加独立 license suite。
测试集群使用专用签发密钥和数据，不从客户集群导出业务样本。
性能以相同数据、并发和环境对照短点查、缓存命中与持续写入；先记录基线，再将可接受回归阈值写入发布验收，不能未经测量宣称零开销。

实现阶段执行相关 FE/BE 定向单测、授权回归套件及必要集成构建，并执行：

```bash
python3 build-support/check-source-headers.py
(cd fe && mvn checkstyle:check)
```

改动上游文件保留原头并补修改声明；独立新文件按 MassDB 商业头登记，更新 MODIFICATIONS.md。
本文提交阶段仅做文档与引用检查，不宣称功能测试通过。

## 11. 发布、恢复与容易遗漏的约束

当前旧 FE 对未知 journal opcode/image 模块有失败路径，因此先完成全部 FE 的格式兼容升级，再写新格式和启用执行限制。
兼容阶段必须显式抑制新增 image 模块/日志记录的写入，不能以为“没有导入证书就不会产生新格式”。
激活使用集群级持久化版本/受控升级步骤，不提供能被普通 SET 或本地配置长期关闭的生产绕过开关。
BE 外部扫描凭证涉及协议兼容，所有承接该类读取的 BE 完成升级后才开放该路径；旧节点不能继续作为绕过入口。

存量集群在切换限制前先取得并验证匹配 deployment_id 的证书、检查各节点应用状态，再完成激活。
全新受管安装无证书时直接进入受限状态，保留导入和写入；兼容升级过渡行为与新安装行为要分开测试。
本次计划不执行部署、重建数据或清理现有安装。

证书业务恢复优先通过合法续期/更高序号修正证书完成。
代码回退只能使用能读取新元数据的兼容版本；不能简单把旧二进制覆盖回来，也不能恢复旧 image 丢弃激活后的写入。
在此工作区进行后续测试重建时遵循 AGENTS.md 已授权的本地测试安装处理规则；生产恢复另按真实环境运行手册执行。

发布前逐项确认以下遗漏已被覆盖：

1. 无证书、未来生效、签名错误与过期都有明确状态；坏证书导入不覆盖正常证书。
2. 管理员、旧连接、PREPARE、缓存、短路点查和重试都不能永久保留曾经有效的许可。
3. SELECT 不等于业务读取，SHOW 不等于无业务值；写入计划中的读取及元数据内部 SELECT 不被误伤。
4. EXPORT、OUTFILE、外部 sink、query_plan/BE 扫描、用户下载/CDC 都有明确策略。
5. 故障切换、落后 FE、checkpoint、重启、滚动升级和降级的行为可验证。
6. 证书原文、客户信息和私钥不会进入日志、测试生产信任根或对普通用户的状态响应。
7. 到期不会中断已承诺保留的写入和提交；恢复查询不要求服务重启。
8. 产品范围明确区分“拒绝新业务读取”“取消在途查询”“防克隆”“数据保密”和“在线吊销”，不混为一项承诺。
9. FE/BE 额度已签名且按完整注册成员计算，不能通过停机、Observer/计算节点角色、会话测试变量或并发注册绕过。
10. 达到上限不影响已有合法集群；超额 ADD 在产生副作用前拒绝；满额维护、过期基础额度与未来配额的边界明确，不以删数据换取名额。
