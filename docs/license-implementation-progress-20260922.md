<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# 授权证书 P0/P1/P2/P3 实施记录

> **2026-09-24 范围收敛：后续工作以[五出口执行计划](/data/project/massdb-sql/docs/license-certificate-execution-plan-20260922.md)为准。** 用户明确允许窄式 `SELECT 1 FROM t LIMIT 1`；保留可证明最终零行的空计划。旧全函数/FE 出口审计、零规划外部访问和全部 26 项基线前置要求已移出当前任务。下文历史阶段编号、强制矩阵与待办不自动恢复为新要求；核心/发行、导入、持久化、额度、页面和正式性能数值继续保留。范围收敛当时仅修订文档，未接入运行时、未重启基准，也未删除旧代码或证据；后续 P2 进展以本节更新为准。

初始日期：2026-09-22；更新：2026-09-25。分支：`2.0.5-license`；初始基线：`23e39e63295fd730523da8d916c898c28b903216`；P0/P1 交付提交：`77e367e422a0df2843e4dee52873ab8d2249a51c`。

**最新使用范围：用户明确本版本先供自己使用，麒麟/openEuler 及目标架构矩阵暂不列为目标、剩余工作或验收前置条件。P1 证书核心按已完成记录；后续聚焦 P2 管理持久化、P3 五出口与额度、P2U 页面和 P4 实际自用环境的集成/性能验证。** JDK 17.0.4 兼容、实际公钥信任配置及原性能要求保留。下文历史“目标平台待验证”“发行矩阵未完成”不再作为当前任务阻塞项；原始测试和失败证据不改变。

当前 P0 已重冻为五出口契约，补齐 Q01–Q28、M01–M14、U01–U04 共 **46 组具体输入/预期/清理/挂点**，并把旧 LP001–026 明确映射到七组当前性能负载；`specified_not_executed` 是 P0 冻结时的状态，后续 P2 管理结果见下文及[P2 验收记录](license-p2-acceptance-20260925.md)。补足两种 coordinator 出队复核，限定原始窄式探测形状，并使续期空档规则与已实现核心一致。详见[当前 P0 契约](/data/project/massdb-sql/docs/license-p0-contract-20260922.md)。

P1 提交前的[独立核验](/data/project/massdb-sql/.build-records/license-p0-p1-current-scope-20260924/p1-audit/review.md)完成：当时 14 个源码在隔离断网环境编译得到的 **39 个 class 与实际 FE JAR 逐字一致**；8 个测试类重新编译并在该 JAR、Temurin 17.0.4+8 上执行 **104/104 通过**，零失败/跳过。签发工具 25 项与实际 JDK 互通 42 项的历史源码、日志、依赖及产物绑定仍一致。29 项审计检查不能与测试数量相加。该记录保留其原有源码和产物范围，P2 修改后的源码以本次重新构建和测试为准。

**2026-09-25 P2 完成：管理、持久化及对应集群验证已交付。** 已实现 Env/journal/image、部署标识、导入与时间修复回执、已注册 FE 兼容检查、SQL/HTTP 管理、权限与脱敏、有界队列及限流。精确 JDK 17.0.4 上执行 `mvn -o -pl fe-core -am package -Dtest=License*Test -DfailIfNoTests=false`，最终 FE 构建与 **183 项**授权测试全部通过，无失败、错误或跳过，见[构建及源码绑定](/data/project/massdb-sql/.build-records/license-p2-20260925/package-6-evidence/summary.json)。183 项包含原有 104 项核心测试；SQL 文本导入工具另有 4 项测试通过。初次 P2 提交 `328f88166232d4dd931b992a44e6e76c61e0a6d5` 的 173 项和未完成集成状态保留为历史记录。

实际多 FE 已验证 SQL/HTTP 导入与失败保旧、自然到期/续期、重启恢复、Master 故障切换、旧 FE 拒绝、新 Observer 加入、权限撤销与原主体重验、响应丢失和 202→200 原提交确认。最终日志/Profile 扫描及临时集群清理通过，原 FE/BE 未改。每个 M 用例的真实范围、单测注入范围、包/源码绑定与失败保留见[P2 验收记录](license-p2-acceptance-20260925.md)；操作步骤见[管理说明](license-management-p2.md)。不把 1,024 条历史、坏元数据、队列饱和等受控测试写成真实集群压测。临时夹具、测试密钥与构建产物不提交。

**2026-09-25 P3 完成：五出口与节点额度已实现并完成约定范围的分层功能验收。** 已接入共享读取守卫、规划/缓存分类、首次派发前复核，以及与证书提交串行的成员 ADD/DROP 额度准入。Q01–Q28、M09–M12 的实际协议、受控故障和不适用边界见[P3 验收记录](license-p3-acceptance-20260925.md)；不把 P2 的 183 项或分轮测试相加当作一次 P3 全绿。下列各轮记录保留当时的包、源码与结论，最新收口及清理事实在本节末尾说明；原始失败保存在 `.build-records/license-p3-20260925/`。

P3 历史开发轮次 `tests-5` 编译并执行 242 项测试：241 项通过、1 项过程查询桥接断言失败，零错误或跳过；完整报告保存在 `tests-5-evidence/`。查询分类、真实规划/缓存、点查派发前复核、两类协调器出队清理、外部写入副作用边界、EXPORT、连接器控制器适配和额度用例已有通过记录；控制器适配单测不是实际 HTTP 网络验收。过程错误传递已补保留 6200 的路径，当时仍需定位该剩余断言；后续锁等待和按 ID 删除并发测试在该轮尚未执行。原始失败保留，不将本轮部分通过写成 P3 完成。

P3 `tests-6` 随后执行 286 项：原有成员管理测试 2 项失败、协调器测试 1 项错误，授权测试 244 项全部通过；原始 XML 和日志保留。前者的模拟管理器未执行成员回调，后者缺少显式有效许可状态，现已仅修复测试夹具并保留原断言。过程桥接、首次派发前跨期、执行锁等待跨期和排队删除遇同地址新节点的测试已在该轮通过。

`tests-7` 在 JDK 17.0.4 上完成 **288 项全部通过，零失败、错误或跳过**，其中授权相关 246 项、选定原有功能回归 42 项。新增同一 prepared handle 再执行及 schema 变化回退测试也通过。37 份 XML、完整日志、源码和 10,396 个测试时产品 class 摘要见[本轮记录](/data/project/massdb-sql/.build-records/license-p3-20260925/tests-7-evidence/summary.json)。这些是 FE 单测及受控入口回归，不能单独据此将 P3 标为验收完成。

候选 `package-1` 随后构建成功，未重复运行已通过且源码未变的测试。打包产物与测试时 10,396 个产品 class 的摘要比较，仅四个使用构建版本信息的类不同，其余包括许可准入类逐字一致；这四个类未另做指令级差异审计。[构建记录](/data/project/massdb-sql/.build-records/license-p3-20260925/package-1-evidence/summary.json)保留当时尚未开始真实运行的状态，后续运行记录见下文。

`runtime-v1` 已实际运行 package-1 FE、未修改的原版 BE 和独立 PostgreSQL。root、ADMIN 和只读账号各完成有效/自然到期两组 45 项基本 SQL 用例；实际同一预编译 handle 跨期、多语句、过程 SELECT、HTTP Query、Flight 1024、新 `_query_plan`、普通本地 OUTFILE/EXPORT，以及到期后内部写入和续期数据核对均有通过记录。JDBC 外部表与远端 SQL TVF 的读取/外部写出被拒绝，外部 VALUES 和导入内部表继续成功，并由独立 PostgreSQL 快照及续期后的完整结果核对。记录不宣称服务端点查快速分支已被运行时观测，也不宣称零规划外部访问。原始失败、46 份证据摘要和剩余范围见[本轮审计](/data/project/massdb-sql/.build-records/license-p3-20260925/runtime-v1-audit.json)。

真实额度测试发现超额 ADD 已拒绝，但 Nereids 包装将约定 6202 变成 1105。已在许可 SQL 异常桥接中保留专用额度/未就绪错误，普通 DDL 错误不转换。`tests-8` 执行 290 项，唯一失败是新增 FE 额度测试未把模拟管理器写入 Env 字段；修复夹具后，`package-2` 构建及两个相关测试类的 **9 项全部通过**。保留前一轮失败，不写成一次 290 项全绿；见[新包记录](/data/project/massdb-sql/.build-records/license-p3-20260925/package-2-evidence/summary.json)。与实际运行的 package-1 比较，10,396 个产品 class 仅许可异常桥接及四个构建信息使用类不同。

`runtime-v2` 已用 package-2 在全新元数据下复验：批量超额 ADD 返回 6202 且无部分登记；两个真实并发连接争用一个名额时仅一个成功；离线 Observer/计算节点仍占额；DECOMMISSION 和失败 DROP 不释放，成功 DROP 后 ADD 可复用；实际停止/重启 BE 后原 BackendId 不变且不重复占额。三台运行 FE 已同步相同许可与 3 FE / 1 BE 成员计数，再加入离线 Observer 达到 4 FE 后继续受限。前五轮结果见[额度检查点](/data/project/massdb-sql/.build-records/license-p3-20260925/runtime-v2-quota-checkpoint.json)。首轮因 BE 尚未报告 Alive 的前提失败另行保留，没有算入产品拒绝通过。

随后在 runtime-v2 自然到期后，额度内 ADD 成功、超额仍返回 6202；已命中的 PhysicalSqlCache 保留且新执行被拒绝，缓存命中由同连接 queryId 对应 Profile 和精确三行结果证明。字典函数在 BE 常量折叠开/关、可折叠参数和混合表达式下均拒绝；已刷新 MV 的直接读取及有实际选中 MV 计划的源表查询拒绝。到期期间完整 MV 刷新和异步统计任务成功，续期后字典/MV/源表精确数据再次核对通过。三 FE 原连接及重连均拒绝，当前这项仅证明直接接入，未宣称强制转发已验收。

M12 实际导入未来 4 FE / 3 BE 证书：未生效前按旧 2 BE 基础额度拒绝第三节点；到 not_before 后两次观察到查询权益已为 3 BE、基础额度仍为 2 BE，并实际拒绝 ADD；基础额度提交后第三节点成功、第四节点拒绝。未注入 journal 暂停或故障；自然时间窗口与已有受控故障测试分开记录。自有假成员均已删除。以上 14 份记录绑定见[第二轮进展审计](/data/project/massdb-sql/.build-records/license-p3-20260925/runtime-v2-progress-audit.json)，该审计明确集群仍在运行、P3 尚未完整验收。

第二次自然到期窗口补齐 S3 TVF 和带 `delete_existing_files=true` 的 S3 EXPORT：V 下实际导出完成并替换哨兵，E 下返回 6200/45000 且 SHOW EXPORT 完整任务信息、哨兵及对象字节摘要不变；自有前缀已清理。到期后普通 Stream Load、同步 Group Commit、带业务子查询的 UPDATE/DELETE、BEGIN/COMMIT 写入均成功，续期后完整行模型核对通过。补充 partitions 元数据 TVF、括号探测和 HAVING/JOIN/UNION/函数/窗口探测反例的 V/E 对照也通过。

新增实际 `StmtExecutor` 两层重试循环和 `NereidsCoordinator` 首次派发边界的受控测试，规划、RPC 和时间仍用替身；覆盖首次派发前/后跨期、后续新执行、取消、超时、重试耗尽和 finally 清理。`tests-9` Maven 定向执行新旧两个执行测试类 **18 项全部通过**，不宣称真实网络故障或完整测试集重跑。第二次窗口的 14 份证据及两项夹具失败见[补充审计](/data/project/massdb-sql/.build-records/license-p3-20260925/runtime-v2-additional-progress-audit.json)：Stream Load 首次缺原有 Expect 头，在 BE 重定向前失败；Q18 首次因可选 BE 任务遥测为空而在目标排队请求前停止，保留 FAIL，SQL/FE 清理已证明，BE 遥测清理证明标为不可用。

第三次自然到期窗口完成真实 Nereids 排队跨期：目标请求先处于 WAIT_IN_QUEUE，出队后返回 6200/45000，运行/等待槽归零，自有 workload group 删除；BE 任务遥测仍不可用，未据此宣称观测到 BE 任务全部终止。纯元数据、窄式探测和 LIMIT 0 查询各有有效/到期两态的实际 PhysicalSqlCache 命中及 Profile 证明。FE3 临时使用原版 `force_forward_all_queries` 配置，六次业务查询通过入口审计、转发日志、FE1 接收日志及 Profile 关联证明实际跨 FE；有效返回正确行，到期的新执行拒绝，配置已还原。接收侧新 context 由源码和接收 trace 推断，未做堆内探针。

真实 hdfs/local/file/http TVF 的读取及伪探测在 V 成功、E 拒绝，连同先前 s3/query 已覆盖六类数据 TVF。S3-backed Broker Load 在 V/E 均 FINISHED，续期后六行完整数据核对通过。以上 12 份记录见[第三轮审计](/data/project/massdb-sql/.build-records/license-p3-20260925/runtime-v2-third-window-audit.json)。原 Q16 旧 handler 缓存直返在本分支不可达，已按源码纠正为不适用，不能作为运行通过；Nereids 缓存和缺分类/schema 失效仍须按原要求验证。

第四次自然到期窗口已完成 root/只读/无 SELECT 权限账号的 HTTP Query 和 Flight 1024 对照，保留各协议原错误映射及原权限错误。Hive/Iceberg 的实际查询、内部/外部源向外部 INSERT、外部源 OVERWRITE、外部 CTAS 已有 V 成功和 E 拒绝，独立 PG/REST、manifest、Parquet 及对象摘要证明拒绝未改变目标；VALUES、导入内部表、内部 CTAS 继续允许。Q23 内部源 OVERWRITE/VALUES 及续期后完整数据核对还在补测，不能据此把 Q23 或 P3 整组记为通过。

`tests-10` 在精确 JDK 17.0.4 上完成 EXPORT 两个测试类 **5 项全部通过**：新增真实 transient scheduler 排队跨期取消与资源清理验证；环境、存储删除和时钟仍受控。全部自有 worker 退出，受控测试不冒充真实远端故障。结果见[测试记录](/data/project/massdb-sql/.build-records/license-p3-20260925/tests-10-evidence/summary.json)。[P3 逐组验收记录](license-p3-acceptance-20260925.md)已建立，待收口项仍明确保留，不以分轮测试计数宣称统一全绿或性能通过。

第五轮已补齐 Hive/Iceberg 内部源 OVERWRITE、外部 VALUES 及续期完整数据核对；prepared Group Commit 两模式跨期共八次写入、Routine Load 有效/到期共六行、系统 audit_log 的实际 V/E、队列超时/KILL 和内部写入对照均完成。旧包过程拒绝保留 6200/45000 与正确 reason，但附带结果收尾空指针；已限定为许可异常做最小修复。`package-3` 的新测试因 Java 8 API 编译目标不支持 String.lines 而失败；修正测试后，`package-4` 在 JDK 17.0.4 构建成功，过程/执行/重试三个类 **22 项全部通过**。

前两轮自有 FE/BE、外部服务、账号、SQL 对象和输出目录均已清理，原基准 FE/BE 生命周期不变。自有 BE 在优雅停止超时后使用 SIGKILL，清理记录如实保留。第二轮 590 个日志/Profile 扫描条目没有证书/JWS/签发私钥命中；联合扫描仍为 FAIL，三个已删除测试账号的口令出现在 CREATE USER 审计及控制台副本。源码核查确认该替换缺口已存在于原基线，未运行原基线复现，也未扩大本次范围修复一般账号审计；不将证书脱敏通过写成所有敏感材料扫描全绿。详见[P3 验收记录](license-p3-acceptance-20260925.md)。

最终 `runtime-v3-v2` 已在 package-4 上完成自然到期对照：显式 ADMIN/无 SELECT 账号的文本及实际 ServerPreparedStatement 查询符合许可和原权限规则；direct/INTO 过程均在 V 成功、E 返回干净的 6200/45000 与 LICENSE_EXPIRED。首次改用 JDBC 读取过程结果的协议解析失败保留，复验使用此前验证过的原协议客户端，不修改服务器协议。自有对象、账号、客户端及整个第三轮 FE/BE 环境已清理，原基准身份未变；最终证书材料扫描无命中，原 CREATE USER 测试口令命中仍单列 FAIL。见[最终证据汇总](/data/project/massdb-sql/.build-records/license-p3-20260925/p3-completion-audit.json)。

**P0、P1、P2、P3 已完成约定阶段；证书页面（P2U）和完整性能验收（P4）仍未完成。** 本次五出口、额度功能验证不等于性能零回退或完整产品交付。当前不再将全部旧基线或平台矩阵完成作为开发的前置条件。以下按日期保留的旧契约、待办和基线状态只描述历史阶段，不覆盖本节当前结论。

历史阶段状态见[逐项完成清单](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/completion-audit-inventory.json)和
[证据索引](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/results.json)；后文按时间保留的“尚未执行”“正在运行”只描述当时状态。原版页面 actual-v4 已结束，以下终态回执优先于旧索引中的 RUNNING，不据此更新为新范围通过。
LP026 各入口已有分轮实际前提证据，Parquet 原版 reader 未关闭保留为用户接受的 FAIL；未合并成完整用例通过。
原版页面18格的规定导航、权限、查询和注销已完成，额外结果深链限制保留原PARTIAL；完整54窗并发矩阵前三轮失败及独立清理记录保留。actual-v4 于 11:51 UTC 以真实父进程 wait 退出码 2 结束：1/10 context 两窗通过，50 context 在准备期客户端进程 RSS 合计 6963.9375 MiB 超过 6144 MiB 上限而失败，尚未进入背景业务窗口，剩余 51 窗未执行。该值是工具/浏览器等进程 RSS 求和，非 PSS，排除 FE/BE；不解释成数据库授权性能失败。见[终态回执](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp021-ui-concurrent-actual-v4-control/terminal-receipt.json)：独立清理确认 164 个所属进程生命周期已消失、4 个账号和 3 个背景表已移除，原始服务 pin 不变。完整矩阵仍未通过；本轮只读取既有终态证据，没有重新运行窗口或重做 SQL 清理。
复杂查询事件、Stream Load和Kafka各完成一个完整原版功能窗口及清理；实际并发、样本和指标边界分别记录，完整矩阵及A/A精度仍未通过。
可选RPC/已有GC日志采集通过56项离线检查及60秒实际smoke；GC记录时间映射模块另经28项检查提升，但尚未接入实际采集窗口。分配量12阶段实验已完成，现有JFR采样与已知worker分配存在明显差异，估计器仍待校准。原计划要求既有网络指标，不额外要求全RPC抓取或逐进程网络总量归因。
原 LP023 长测量已停止，确认 156/420 窗，退出原因未知；新的42组合、10对共840窗计划尚未开始测量，不拼接旧结果。实际本机24MHz时钟的量化范围已纳入微基准工具；旧840窗计划的源码绑定须更新，几十纳秒操作的2%检测精度不能仅靠增加窗口解决。

## 1. 已确认范围

只改 FE、FE 页面和独立离线签发工具，BE 源码、协议、端口和执行流程保持原状。10:59 从 FE 拿到的计划在 11:00 到期后仍可能在 BE 执行或重新打开；下一次向 FE 申请新业务查询或新计划必须受限，这是后续接入的验收要求。用户已接受这一边界，实际发生概率未测量。

FE 仍按权威成员表管理 FE/BE 注册额度；离线不释放，实际 DROP 提交才释放。旧 BE 进程是否还能使用原接口不属于额度释放保证。原 BE 身份、内部执行凭证、租约、撤权和传输改造均退出本版。

## 2. P0 设计与原版路径

[P0 契约](/data/project/massdb-sql/docs/license-p0-contract-20260922.md)及机器 JSON 冻结 26 组 FE 挂点、用途/副作用顺序、缓存/转发/出队生命周期、API/错误、额度/恢复/混合 FE 格式和测试映射。保留 1,423 项历史源码审计与 1,171 份源码哈希；修正 207 项范围调整后缺少当前 C 编号的映射，历史引用单独保留。

新增 [check_p0_contract.py](/data/project/massdb-sql/tools/license-checks/check_p0_contract.py) 独立重新发现 Command、TVF、HTTP、FE Thrift 和五类内置函数注册，检查新增未覆盖入口与源码漂移。82 项行为测试定义是后续接入的输入，不是已通过的集成测试。 新补82项输入/身份/结果/副作用/清理断言及26份直接前提引用，经源码跨类型复核修正后，静态检查和29项变异/引用自检通过；见[检查报告](/data/project/massdb-sql/.build-records/license-p0-contract-20260924/cross-type-release-evidence-report.json)。

已用原 ARM64 发行包建立 checkout 内的全新测试安装，使用独立网络 namespace、合成数据和 CPU 绑定；没有操作仓库外的已有 FE/BE，没有改宿主时间、内核参数或交换区。发行包源码提交 `59329855b4e62497d927f3ccd547b866a190a0fc` 与当前基线的 `fe/`、`be/`、`gensrc/` 无源码差异，包及二进制哈希留档。此环境仍共享宿主资源，不代表独占硬件或所有发行 OS 已验证。

真实路径证据见[可达性说明](/data/project/massdb-sql/docs/license-baseline-reachability-20260922.md)及[原始报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260922/path-probes/reachability-report.json)：

- 百万行数据校验：ID 0–999999，`SUM(v)=49999500000`。初版测试 DDL 缺 row-store 导致普通扫描；已补 row-store/MoW/light-schema 属性并重建合成表。早期 smoke 保留为诊断记录，不能作为短路性能证据。
- LP001：实际 EXPLAIN 出现 `SHORT-CIRCUIT`，结果正确；该路径按设计不生成普通 Profile。
- LP002：真实 `ServerPreparedStatement` 多参数执行正确；快速执行方法分支仍需独立观察，协议可达不等于所有复用条件已验证。
- LP003：`PhysicalSqlCache`、`Is Cached: Yes`，本例缓存值来自 BE；不能写成纯 FE 零 BE。
- LP004：16 个 tablet 的 `CACHE_SOURCE_OPERATOR / HitCache: 1`；与 SQL 缓存标志分开记录。
- LP006/007：固定16 UNION ALL、4次JOIN、33列结果与独立模型相符；真实view在180秒变更后缓存失效、新值生效并再次命中，最后恢复原view。事件实际延迟约7.96ms，属于静止等待下低频可达验证，未证明并发压测行为。
- 工具现有27项统计/泊松序列/连接生命周期与有界测量屏障测试通过；[工具记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/baseline-tool-repair-unit.json)。原100键循环已补充为完整百万键范围的确定序列：text/reuse、prepared/reuse、prepared/per_request共2940次实际请求成功，CSV键值与归档序列逐一一致，CPU边界有效；[真实小规模记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/uniform-smoke-audit.json)。这些短窗不具备性能验收资格，原记录仍保留。
- LP011：真实 FE 取计划后，两个tablet正常open/get_next/close；关闭后复用相同计划又能open并返回相同行，context各不相同。见[原协议观察](/data/project/massdb-sql/.build-records/license-p0-p1-20260922/direct-read-probe/report.json)。原版没有许可准入，不能把此结果称为到期拦截测试通过。
- LP010：原短路点查Flight没有生成Endpoint而失败；改为显式关闭短路/缓存的两行普通扫描后，FE返回BE端点，BE DoGet取数成功。见[Flight普通路径](/data/project/massdb-sql/.build-records/license-p0-p1-20260922/direct-read-probe/flight-scan-report.json)。随后[完整批次/连接fixture](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp010-flight-be4g-v4/report.json)中，1024/8192两档新建/复用连接的8次百万行完整校验通过；65535四次均出现首行id正确但payload为空，整体FAIL。65536按原参数错误拒绝。失败保留，未修改BE、移除档位或将部分成功标为LP010通过；见[说明](/data/project/massdb-sql/tools/license-checks/flight-fixture.md)。

LP012 新增[可复现 fixture](/data/project/massdb-sql/tools/license-checks/stream-load-fixture.md)：1000万行、每行128字节输入已生成并独立逐行校验；实际装载10000行经过 FE307→BE200，零过滤且内容校验通过。重复同一label返回已完成且 DUPLICATE KEY 表仍为10000行。见[真实结果](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp012-probe-10000-v2/report.json)。该早期记录仅为小样。后续[完整输入验证](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp012-full-be4g-v1/completion-audit.json)已实际装载1000批共1000万行/1.28GB：全部FE307→BE200、零过滤，独立重读1000份原始回执及逐块输入摘要；全量ID/字段/payload正确，重复label为FINISHED且行数/内容不变。独立临时表已删除并确认，客户端退出；持续并发与许可状态性能仍未验证。

LP005 在精确17.0.4原版环境完成认证fixture：SQL与同步非流式HTTP的四请求混合结果一致，reader原权限允许、无权限用户的SQL/元数据GET按原行为拒绝或过滤。临时开启的HTTP认证已恢复原值false，两临时账号已删除；[实际结果](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp005-probe-jdk1704-v3/report.json)。前两次因配置展示前缀和原版DESCRIBE错误包装的假设不符而失败，保留各自记录；成功仅指fixture与原权限可达，不是许可证无效状态或性能验收。

LP008 的100个Parquet文件、共100万确定性行已生成（56,184,742字节），独立reader逐文件全读并与Python模型校验一致；首文件重写字节一致，截断及payload摘要篡改负例被拒绝。见[输入准备记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp008-parquet-v3/fixture-report.json)及[使用说明](/data/project/massdb-sql/tools/license-checks/parquet-fixture.md)。输入准备使用现有发行依赖、断网完成。

随后在新4GiB BE测试环境通过原版S3 TVF执行真实 `DESC FUNCTION`、百万行外部SELECT和INSERT SELECT，内部全字段模型与行数/去重/聚合均一致。每次外部SELECT/INSERT均记录3次List和101次Range GET，覆盖全部100文件；schema探测本身也读取了一个完整小Parquet对象，不能假设元数据探测没有外部取数。独立临时表已删除，私有namespace中的只读S3测试服务已关闭。见[真实记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp008-s3-be4g-v1/report.json)及[S3工具说明](/data/project/massdb-sql/tools/license-checks/s3-readonly-fixture.md)。测试服务提供真实文件字节但不验证AWS签名；这是原版功能前提证据，未证明许可证拦截或持续性能，LP008完整状态仍为not_run。

LP014 在新环境完成16批真实Group Commit：批量1/100/1000/10000、full-prepare开/关、同一server-prepared语句各执行两次，共44,404行。OK回执、SHOW LAST INSERT、独立连接可见性、全字段模型及CSV摘要一致；开启full-prepare时四次重复执行均返回真实 `reuse_group_commit_plan=true`，关闭时不出现快路径标记。会话恢复和独立表删除已确认。见[实际结果](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp014-probe-jdk1704-be4g-v3/report.json)及[说明](/data/project/massdb-sql/tools/license-checks/group-commit-fixture.md)。前两轮驱动ADMIN结果分类、原版OK长度前缀解析失败记录保留；未修改数据库协议。ACK与轮询观察到可见的上界分别记录；这不是持续并发/许可证状态或性能通过。

LP015 的[10阶段fixture](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp015-probe-jdk1704-be4g-v2/report.json)通过：独立INSERT SELECT/UPDATE/DELETE各100行，同一BEGIN会话内三种100行DML的COMMIT/ROLLBACK均由独立连接核对完整内容及VISIBLE/ABORTED，未提交不可见。三种不支持的组合保留原拒绝；原版START TRANSACTION仅ACK、未建立事务，明确不当作BEGIN同义能力。临时表已删除、会话恢复、源数据600行前后hash一致；首次驱动自动只读探测导致的失败保留，后按原回归配置 `useLocalSessionState=true`。见[支持边界与说明](/data/project/massdb-sql/tools/license-checks/dml-transaction-fixture.md)，未证明1000事务/持续并发或许可状态测试。

LP010的65535问题另用[JDBC对照](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp010-jdbc-batch-diagnostic/result.json)核对：同一完整ORDER BY查询、各档新连接、真实StreamingResult，8192和65535前10行均正确。该对照没有校验剩余999990行，只将现象收窄至Flight特有路径，尚不能断定BE输出、传输或客户端解码的具体根因；不修改BE。

后续[v5真实诊断](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp010-flight-be4g-v5/report.json)再次完成固定12组矩阵：低两档8×百万行全过，65535四次仍失败。失败批为Utf8/VarCharVector、65535行，offset容量524288B，前16字节按32位读为[0,0,32,0]、按64位读为[0,32]；data原始前32字节是正确id0的MD5，客户端writer index却为0。实际schema与offset布局错配已由运行时证据确认，对应原版 `row_batch.h` 的2MiB阈值及 `block_convertor.cpp` 切large_utf8 builder而保留原schema。用户于2026-09-24明确接受保留该原版缺陷并继续授权开发；BE不改，65535失败不计通过，其他档位及许可准入要求不变。

LP011的[完整scanner验证](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp011-external-scanner-be4g-v1/report.json)通过：一次FE取计划覆盖16tablet，1024/8192各初次及同计划关闭后重开，共4×百万行，逐行ID/payload、全局去重和完整摘要一致。64个独立context全部关闭；19项离线测试及10项Java内存自检通过。原始计划仅保存在0600配置中，公开报告只存摘要；原版无许可证，仍不冒充到期拒绝或持续性能通过。

## 3. P1 已实现代码

| 模块 | 实际能力与边界 |
| --- | --- |
| `LicenseVerifier` / `LicenseDocument` | JDK 17 JCA Ed25519 验证原始 JWS 字节，复用现有 Jackson；固定算法/用途/版本，严格重复字段、UTF-8、规范 base64url、深度、大小、字段类型和额度范围；验签成功不等于可用或已导入 |
| `LicenseText` | 固定 Unicode scalar 范围、空白和 UTF-16 长度规则，不依赖 Python/JDK 各自的 Unicode 数据版本；全码点互通探针可复现 |
| `LicenseTrustStore` | 严格公开 SPKI 清单，license/time_repair 用途隔离；禁止同公钥跨用途，包含跨轮换换 kid；保护 active/pending/过期基础额度及实际需复验归档的公钥依赖 |
| `LicenseImportState` / `LicenseImportPolicy` | 验签恢复槽位、不可变导入候选、最高序号/幂等回执、1,024 条有界历史、续期覆盖保护、已接受额度不降低、显式 pending 基础额度提升、提交前重新校验；只产出候选，P2 负责真实原子持久化 |
| `LicenseSnapshot` | 原子发布所需的不可变事实；到期/待生效/功能/部署/FE与BE超额分别评估，管理原因集与查询判断分开；热路径不解析证书或分配原因集合 |
| `LicenseClock` | 可注入墙钟/单调时钟、不会回退的可信 UTC、粘滞异常、版本化提交水位、新 epoch 修复；同 epoch 超前复制水位及先前跳后回拨也检测异常；查询读取无 I/O/管理锁 |
| `LicenseClockRepairVerifier` / `LicenseClockRepair` | 独立用途签名，部署/进程任期/nonce/epoch/修复权限版本绑定、24h 单调挑战、提交前复核、防重放及未知提交确认；Store 是 P2 适配接口，内存测试不冒充真实 journal/切主 |
| [离线发行工具](/data/project/massdb-sql/tools/license-issuer/README.md) | 部署申请 DTO 到 claims、显式时区、keygen/sign/verify、续期预检、公开信任清单导出、修复票据签发与验证；Python 标准库和 OpenSSL 3，不随数据库安装私钥或默认测试信任根 |

固定默认值：5 秒回拨容差、300 秒显著前跳阈值、24 小时修复挑战；容差不延长证书到期时间。P2 已接入 60 秒水位保存任务并验证实际持久恢复。普通已准入查询冻结原会话执行超时，后续内部重试不能延长，不新增独立产品执行硬上限。

恢复/导入与时间接口细节见[导入核心](/data/project/massdb-sql/docs/license-import-core-20260922.md)和[时间核心](/data/project/massdb-sql/docs/license-clock-core-20260922.md)。生产公钥由签发方显式提供；测试只证明配置/密码能力，未替用户生成或安装生产信任集。

用户此前提到麒麟/openEuler、ARM64 或 x86，随后明确这些暂不作为目标，本轮是自用版本。当前不再建立对应发行矩阵；JDK 17.0.4 要求保留，已有实际环境记录继续有效，不外推为其他系统通过。实际部署公钥配置随 P2 接入验证，不作为功能开发前置等待项。

## 4. 真实验证记录

| 验证 | 实际结果与证据 |
| --- | --- |
| FE 定向测试 | `bash run-fe-ut.sh --run 'org.apache.doris.massdb.license.*Test'`：**104/104**，0失败/错误/跳过；Verifier17、Trust6、Text3、Snapshot14、Import22、Clock15、Repair23、固定向量4；[JUnit汇总](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/fe-ut-results.json) |
| Python/OpenSSL 工具 | **25/25**；[实际日志及源码摘要](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/issuer-tests-25-results.json)；含真实签发、篡改/错误公钥拒绝、续期、时区、用途隔离和修复票据；独立工具测试不替代 FE API 测试 |
| 发行依赖互通源码探针 | JDK17/实际 ARM64 包内 Jackson：**42/42**；另有 JRE21 兼容探针42/42，仅作额外观察；[JDK17记录](/data/project/massdb-sql/.build-records/license-p1-release-20260922/jdk17-source-report.json) |
| 精确 JDK 17.0.4 | 官方 Temurin 17.0.4+8 Linux aarch64 包通过官方 SHA-256 校验；最新实际 JAR 断网发行探针 **42/42**、核心 JUnit **104/104**。本机 Fedora42，不外推至目标 OS；[环境与记录](/data/project/massdb-sql/tools/license-checks/jdk17.0.4-validation.md) |
| Unicode 互通 | JDK/Python 对 U+000000–U+10FFFF 的三类文本接受序列摘要一致，含全部1,112,064个scalar与2,048个单独surrogate拒绝；不是抽查几个汉字 |
| 实际 FE 离线构建 | 新断网namespace内执行 `mvn -o -pl fe-core -am package -DskipTests`，JDK17、release8，**BUILD SUCCESS**；[最新构建日志](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/offline-fe-package.log)，产物 `fe/fe-core/target/doris-fe.jar` |
| Java规范 | `(cd fe && mvn -o checkstyle:check)`：**BUILD SUCCESS**；[最新日志](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/checkstyle.log) |
| 源码头 | `python3 build-support/check-source-headers.py`：新增验证工具登记后检查通过，0 pending、4 independent Apache、115 company commercial、75 upstream；[当前检查](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/final-source-checks-v1/report.json)同时保存 `git diff --check` 和 Kafka 最终源码/依赖/class 核对，不代表实际性能通过 |

2026-09-22 构建的实际 JAR 与同批 target/lib 的互通验证 **42/42通过**，见[实际字节码报告](/data/project/massdb-sql/.build-records/license-p1-release-20260922/jdk17-built-jar-report.json)。该历史 JAR SHA-256：`860c4d178861ea6be8974b4865dcbec698aaa57248de6c43ca626cc8642971fa`。源代码探针报告保留各次源码快照，不把旧发行 tar 写成已包含新核心。测试私钥仅用于临时测试，不进入产品。

2026-09-24统一测试后重新完成断网package；最新 JAR SHA-256为 `4281b01d3fea1c2b83145e5e64d9bfd401da6620381cc44fa3a666904881f2f5`。39个核心class包含在产品内，固定向量资源与许可测试类不进入产品；[产物隔离检查](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/product-artifact-test-isolation.json)。不同构建的产物分别留证，不混用摘要。

新增[固定向量](/data/project/massdb-sql/fe/fe-core/src/test/resources/license/ed25519-fixed-vectors.json)包含 RFC 8032 的两个公开测试用例和项目自有许可/时间修复 JWS 字节串，Java与Python/OpenSSL分别验证已知签名、原始编码、篡改及用途隔离。公开测试种子仅位于测试资源，不作为生产信任根。

上述2026-09-22实际 JAR 的[核心成本报告](/data/project/massdb-sql/.build-records/license-p1-release-20260922/core-cost-report.json)完成3个独立JVM、每项7个样本：普通状态判断中位5.48ns/op，可信时钟32.41ns/op，状态判断含动态时钟36.52ns/op；正常路径无操作级分配、无GC，计量器本身每样本有48字节固定成本。管理验签约264.43µs/op、78,970B/op，信任清单解析约11.74µs/op、14,008B/op。简单单线程探针包含循环/调度测量成本，不是JMH、SQL端到端A/B、分类器或LP023整体通过。

首次统一测试曾因修复测试夹具在同 epoch 降低水位而失败，已修正夹具并保留生产防回拨约束；之后发现的真实时钟边界已修复；原100项与本轮新增4项固定向量统一通过。失败日志与最终结果分别留档，不用独立小测试替代统一成功记录。

## 5. 性能进度及剩余门槛

容量校准工具另有21项完整性/原始数据重算/信号退出/孤儿客户端清理测试通过；[结果](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/capacity-calibration-unit.json)。客户端还须与声明的FE/BE处于同一网络namespace，端口须匹配owned FE配置；误在宿主调用会在启动JVM或发送SQL前被拒绝。

新增 [JDBC基线程序](/data/project/massdb-sql/tools/license-checks/run_performance_baseline.py) 固定种子的开环泊松到达、原始请求时刻/排队/错误、CPU/RSS与独立窗口bootstrap。短窗口、样本不足、漂移或精度不够都保留 `inconclusive`，不改写成性能通过。

补充[只读资源时序工具](/data/project/massdb-sql/tools/license-checks/resource-observer.md)：进程CPU/RSS/IO、namespace独立RX/TX、现有FE JVM/BE嵌入JVM GC及jemalloc指标。22项离线检查、真实20秒5样本零错误的[smoke](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/resource-observer-smoke20s/summary.json)通过。监测有开销；namespace流量不按进程归因，GC累计时间不冒充单次pause，正式测量须冻结同一采样方案。

LP023明确载荷单位为decoded canonical JSON字节，合法档改为512/4096/16384，原256保留为独立拒绝负例；其余线程、样本、时长和精度要求不变。[真实发行/生产Java验证](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-payload-fixture/report.json)确认295字节schema下界、三档VALID和256字节签名正确但INVALID_CLAIMS，6项单测及更新后的P0契约检查通过。这是输入定义纠错与前提证明，不是微基准性能通过。

当前实际FE JAR（SHA256 `4281b01d3fea1c2b83145e5e64d9bfd401da6620381cc44fa3a666904881f2f5`）已在精确Temurin17.0.4+8重测有界单线程成本：3个JVM、每项21个样本，固定时间快照判断中位数5.34ns、含可信时钟判断35.71ns、管理验签258.74µs。见[当前产物记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/core-cost-current-jdk1704.json)。它与历史17.0.2结果分开；简单harness及循环/观测开销包含在内，不外推为SQL无回退或完整LP023通过。

已在真实短路路径完成 250/500/1000/2000 请求/秒四级诊断，共 **8窗、151,014次请求**，零错误/丢样，实际结果一致。全部满足事先冻结的诊断标准（P99≤100ms、drain≤1s、零错误/丢样）；全量CSV最大排队83.55ms。记录见[校准报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260922/point-calibration/calibration-note.md)。各窗仅20秒、每速率一对，不能证明持续容量、1%/2%检测精度或无性能回退。

[性能清单](/data/project/massdb-sql/docs/license-performance-cases-20260922.json)的 **26个完整主用例仍为 `not_run`**，独立的路径/诊断记录没有冒充主用例通过。正式 A/A 每场景至少5对、每窗P99至少10,000成功样本，LP001–005至少120秒预热/300秒计时；先冻结噪声与1%吞吐/CPU、2%P95/P99检测精度，再评估完整候选 B。长短连接、复杂冷/热计划和依赖失效、4BE扇出、Flight/scanner、持续导入/Kafka、管理/页面及4小时压力各有独立前提。

当前剩余工作：完成 P0 的精确fixture与原版可达性、合格 A/A 基线和检测能力；P1 核心、实际JAR互通和成本记录已交付；生产实际信任公钥交付审核、其他支持平台验证分别按发行范围落实，不伪称已安装生产信任集。P2/P3/P3Q/P2U 的持久化/运行入口/页面接入和 P5 的完整集群、升级、故障及 A/B 对照另按[执行计划](/data/project/massdb-sql/docs/license-certificate-execution-plan-20260922.md)实施，不以核心单测或 BE 不改动替代。

2026-09-24核对：正式时长A/A已经完成，10窗共 **3,006,060** 次成功请求，零错误/丢样。该子场景结果为 **inconclusive**：P99的95%区间半宽2.239%，超过原定2%；BE每成功请求CPU半宽1.348%，超过原定1%。不放宽门槛，也不把固定到达率下成功QPS稳定写成容量已验证。原runner/monitor及测试集群PID目前均已不存在，不能继续称“测试运行中”；接下来须校核测量边界并在可复现环境补足证据。见[完成审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260922/point-aa-1000-c16-reuse/completion-audit.json)及[本轮总记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260922/results.json)。

2026-09-24新环境校准：已使用官方Temurin17.0.4+8重建原版隔离环境，重新验证百万行及SHORT-CIRCUIT路径。均匀百万键、c16复用连接、250/500/1000/2000请求每秒的预声明pilot共8窗、**151,014**次成功，零错误/丢样；P99约2.9–5.9ms，原始CSV/键/到达/CPU边界复核通过，全部客户端已退出。见[完成记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/uniform-capacity-pilot-jdk1704/completion-audit.json)。每窗预热10秒/计时20秒；没有观察到容量上界，不冻结30%/60%/85%速率，不宣称容量精度、正式A/A或候选B通过。旧17.0.2/100键子场景结果保持单独记录。

后续预声明4000/8000/16000诊断中，前两档完整但16000第二窗预热因BE `MEM_LIMIT_EXCEEDED` 失败，保留为 `invalid_trial`，不能充当容量上界；所有客户端已退出。旧2GiB进程限额还触发了审计写入失败与缓存收缩，4000/8000也不构成健康稳态容量证明。见[失败与清理记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/uniform-capacity-upper-pilot-jdk1704/completion-audit.json)。旧集群已停止，日志和结果保留。

隔离环境工具新增显式 `--be-memory-mib`，默认仍2048；本轮以4096建立全新metadata/storage，FE仍2GiB堆、审计及原协议保持原配置，未改BE代码。新环境[启动验证](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/baseline-jdk1704-be4g/readiness/report.json)确认百万行及短路计划；[实际配置与初始资源](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/baseline-jdk1704-be4g/readiness/resource-startup.json)确认BE限额4294967296字节。4GiB只是下一轮实测起点，持续内存余量、审计批次和缓存稳定性仍须验证，不合并旧2GiB结果。

新4GiB配置的预声明4000/5000/6000/7000/8000诊断已完成：120秒预热、60秒计时、每档一对，共10窗、**3,606,688次成功请求**，零查询错误/丢样，所有客户端退出。4000/5000两档P99分别约10.68–11.04ms、13.26–14.84ms；6000、7000、8000超过冻结的20ms门槛。观察区间5000–6000相距20%，不能称正式容量或A/A通过。[完整审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/be4g-pilot-completion-audit.json)绑定原始CSV复算记录及35分钟421次零错误采样。FE INFO日志轮转1GiB，按原始前缀摘要重建到观察结束的日志范围；未发现本轮内存超限/审计丢弃。BE仍发生85次缓存容量调整、169项约6.37MiB清理，不能称无内存压力；监测到FE/BE最高RSS约2788/2718MiB。

该历史客户端逐次读取字段但只核对行数，完整fixture验证不能冒充每请求值正确。现已补点查payload预计算及计时内比较，原始记录增加oracle覆盖；错误值/空值/类型/额外列不计成功。最新基线工具32项、容量工具24项检查通过（编译运行工具测试为本机JDK17.0.2）；精确17.0.4的[四组合真实smoke](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/point-payload-oracle-smoke/completion.json)完成8窗、1,248次计时请求，全值校验成功，客户端退出。每窗仅3秒，没有精度结论；prepared/per_request有一窗超20ms门槛，保留为outside_slo而不混淆功能正确与性能通过。后续正式测量使用新摘要，不混合旧版本结果。

容量工具的≤1%观察括区表示速率网格宽度，不是95%容量置信区间；固定到达率成功QPS也不替代容量精度。下一轮先完成原版功能fixture并清理，冻结新profile和采样计划，再做覆盖默认60秒审计周期的诊断；正式confirmation和A/A仍须满足原时长、样本及统计门槛。

上述新profile诊断已完成，原[启动与进程身份记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/be4g-diagnostic-start.json)只保留历史启动事实。controller和35分钟observer均已退出；原窗口内暂停了其他编译、微基准和功能请求，窗口结束后再恢复工具验证。

新增[42组合P1原语测量工具](/data/project/massdb-sql/tools/license-checks/license-primitive-cost.md)，默认只生成计划，完整测量预计超过10小时。最终版本20项测试通过，并以实际JDK17.0.4/CPU0–4完成5种各两窗smoke：256B拒绝、32线程live-clock快照、32线程16KiB验签、8线程4KiB固定时间快照、单线程16KiB可信时钟；编译class冻结、实际亲和性、CPU边界及清理回执均核对。另实际绑定CPU0的负例被拒绝。见[最终工具证据](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-primitive-development.json)。旧24组合11项结果单独保留；短smoke不证明正式精度。完整42组合/420窗口测量已于2026-09-24 06:43（UTC+8）启动，原测试FE/BE均已停止，没有并行SQL基线；[启动身份和参数](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-primitive-formal-start.json)已冻结，尚无全矩阵精度结论。P3分类器/队列与完整LP023不在该子集内。

[逐项完成审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/completion-audit-inventory.json)保留原始P0/P1边界：已有核心和功能子项证据不能替代全部适用原版A前提、合格A/A精度、实际目标发行环境或生产公钥验收。3FE/4BE工具离线13项通过；实际三投票FE、四BE的加入/远端心跳/日志回放及1484项冻结摘要已核对。首次启动因BE注册前使用常量SELECT失败，完整错误和清理记录保留，修正为本地FE元数据后通过。LP009的64/256/1024三档分桶各完成1000万行核对，真实profile确认四BE各扫描250万行，全部分组结果正确；21项工具检查及[89份原始回执独立审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp009-fanout-v2/completion-audit.json)通过。全表DISTINCT原先触发512MiB限额，后用20段完整ID核对控制oracle内存，原始失败保留。三临时表及全部测试服务已清理，停止前manifest字节保留；这是同机功能前提，完整LP009性能仍未通过。Kafka工具16项离线检查通过，初次官方3.9.2包下载TLS失败/其他入口404的证据保留；随后同一archive入口恢复，完整122,473,776字节归档与冻结及官方SHA-512一致，见[恢复记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp013-kafka-archive-recovery-20260923T224842Z/recovery-receipt.json)。尚未解包、编译3.9.2依赖或启动broker，真实Routine Load仍待独立窗口验证。

本轮只读P1复核确认当前14个核心类、签发工具及实际FE/Jackson产物与既有104/25/42通过记录相符，未发现有依据的新P1缺陷；[源码与产物审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/p1-current-source-completion-audit.json)没有重跑测试或替代目标发行环境验证。LP026的[具体准备规格](/data/project/massdb-sql/tools/license-checks/background-http-fixture.md)及LP021/022的[真实浏览器规格](/data/project/massdb-sql/tools/license-checks/ui-baseline-fixture.md)已补齐源码入口、账号/任务来源、独立内容核对与清理要求，实际执行仍为not_run。

随后新增上述两组的controller、原Thrift协议只读broker、独立CSV/Parquet准备与读取核对、真实浏览器helper及离线测试源码；正式原语测量尚在运行，因此这些新代码只进行静态复核/语法检查，没有启动浏览器、SQL服务或执行测试。LP026保留自然字典刷新、实际后台MV任务、自然SYSTEM/AUTOMATIC统计任务，以及真实ES/文件预览路径；UI保留真实cookie认证、3种路径前缀、2种语言和角色/节点组合。完整持续读写背景、并发/窗口/精度矩阵及后续候选B页面仍为未完成，不能将这些工具源码称为P0/P1验收通过。

LP006/007的[新结果核对模块及驱动](/data/project/massdb-sql/tools/license-checks/complex-planning-oracle.md)独立重算全部33列，绑定原冻结SQL/区间，拒绝协调替换期望值、混合快照和错误/拼接Profile。事件重叠请求只允许完整旧或新结果，提交确认后新请求必须为新结果；原版Optimize时间戳缺失仍保留N/A。已补同JVM并发事件adapter、冻结开环到达、逐请求完整回执、Profile/EXPLAIN关联及有界清理源码；新增Python反例和Java自检尚未编译/运行，真实并发窗口及完整正式矩阵仍待执行。

正式原语矩阵的首个控制组合已完成10窗，但吞吐/CPU每操作的95%区间半宽约1.257%/1.236%，超过1%门槛，保留precision_insufficient；其余组合继续。P95/P99在该组均量化为42ns，退化区间不能证明亚纳秒检测能力或产品调用成本。见[首组记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-primitive-formal-first-control.json)。期间CPU5的只读摘要核查和限速归档下载单独记录，不删除重叠窗口、不推断波动归因，不放宽精度门槛。

继续补齐测试工具源码：LP026的全生命周期资源采样、helper输出限额及独立清理；原版UI的显式持续读写背景、完整百万行源数据与每批实际写入的独立内容/可见性核对。页面读取与写入、浏览器操作必须处于同一个声明窗口，未启用背景的旧计划继续只代表页面子集。静态复核还补上进程身份、编译输入摘要、未知DDL提交和清理回执失败处理；上述新增功能均没有运行验证。[本轮源码与静态检查记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/p0-fixture-tool-extensions-20260924.json)独立保留当前摘要，旧实现记录继续代表其原始版本。正式测量期间未启动额外SQL服务、浏览器、Java编译或测试，原冻结测量输入保持不变。

随后继续增加执行能力：原版UI新增显式10秒刷新子用例，固定29次刷新及2次导航并独立核对串行排队；Kafka在执行前重新核对官方归档及每个解包文件，不能靠同步改写准备清单掩盖依赖变化。新增[实际公钥只读验收工具](/data/project/massdb-sql/tools/license-checks/public-trust-review.md)绑定交付JAR/JDK、用途指纹及显式保留依赖，生产公钥未提供、目标OS未确定的状态保持不变。以上新增代码及负例仍只完成静态检查，尚未编译或运行。

2026-09-24 12:41（UTC+8）复核已确认原LP023 controller和相关probe均不存在，原会话也不可查询；退出原因没有权威记录。
该轮确认156/420个完整窗口、15个完整组合，另1窗仅有raw，不能补作成功。原报告的PLANNED值没有被当成运行状态；
独立[停止审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-primitive-formal-stopped-audit.json)保留全部失败/不足结果，
21项固定输入和5个编译class摘要无漂移。未重启或拼接窗口，完整LP023与性能发布门槛保持未通过。

确认计时进程已退出后，执行了此前待运行的工具验证。页面23项、页面背景16项、复杂oracle18项、复杂controller24项、
后台36项、资源15项及Kafka20项Python检查通过；页面CJS10项、精确17.0.4的复杂Java自检28场景/43断言及无socket broker自检通过。
实际修复了复杂测试缺失导入、Stream Load批次无界读取和Parquet格式类被旧fe-common副本遮蔽的问题，原始失败日志均保留。
新的[持续Stream Load工具](/data/project/massdb-sql/tools/license-checks/stream-load-baseline.md)仍待真实完整10M窗口验证；
CSV/Parquet输入已实际生成并以独立reader逐行核对，但这不代表FE文件预览已经通过。
[本轮工具验证目录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924)分别保存源码摘要、命令、退出码和结果，
不将这些离线检查替代实际FE/BE、浏览器、持续负载或完整A/A精度。

实际公钥只读验收工具完成19项Python和12项实际JDK/JAR正负例，修复Temurin的FULL_VERSION字段兼容及
退出中Java进程RSS消失导致的误拒绝；见[公钥工具验证](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/public-trust/completion-audit.json)。
仅使用公开测试公钥，未生成/安装信任集；生产实际公钥、麒麟/openEuler版本和各架构发行机验证仍待交付。
Kafka真实3.9.2归档已安全解包，100k完整功能输入及233个发行文件与原归档一致，精确17.0.4下实际3.9.2客户端helper编译通过；
见[准备与编译回执](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/kafka/validation-receipt.json)。
该100k子集不替代原10M及全并发/批次/窗口矩阵，真实Routine Load验证继续单列。

本轮定向工具检查合计209项Python和10项CJS通过（按不同测试去重，失败后重跑不重复计数），包括持续Stream Load的38项和公钥验收19项。
[汇总与源码快照](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/p0-p1-tool-validation-20260924.json)将初始失败、修复、实际Java检查及剩余真实矩阵分开。
旧“仅静态检查”记录保持其当时含义；本轮通过不能追溯升级旧版本，后续工具改动也须绑定各自证据。

新隔离原版FE/BE环境已重新通过百万行完整模型和SHORT-CIRCUIT就绪检查；未复用旧metadata、未操作仓库外服务。
LP013随后完成真实Kafka3.9.2→Routine Load的100k功能子集：100000条生产ACK、独立消费和完整数据库内容一致，
8分区last committed均为12499（exclusive end12500），错误/过滤行0，提交任务8。即时SHOW TASK的BeId均为-1，
不能据此声称实测8个并行BE任务。首次CREATE ROUTINE LOAD缺少属性分隔逗号的错误保留，修复后20项测试及真实重测通过。
最终job STOPPED、任务0、临时表缺席、broker及全部自有helper退出，原FE/BE身份不变。
见[完整运行及清理审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp013-kafka-actual-100k-audit.json)；
完整10M、全部并发/批次/时间窗口及性能精度仍为待验，接下来继续使用新隔离环境顺序补LP026真实路径。

LP026首轮真实probe在字典阶段中止：资源记录为sql-0005的`registration_ValueError`，对应actor尚未取得pin，
并非已记录的RSS预算超限；现有首轮日志不足以证明具体退出/exec竞态。其余MV、统计、ES及两种预览均保留not_run。
controller已确认退出，工具报告并独立确认自有数据库清理；原服务保留供修复后的独立新轮次使用。
[首轮失败](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp026-background-http-actual-v1/report.json)保持FAILED，
正补充启动身份稳定检查、早退出负例与安全诊断信息；此前209项离线通过不能替代这一实际运行失败。

2026-09-24 后续更新：LP026第二轮暴露字典成功信息格式与工具假设不符，第三轮按用户暂停取消，
原始失败/取消均保留。第四轮已通过自然600秒字典刷新：版本2→3、三行源数据与`dict_get`结果、全部自有BE分布
及调度日志一致，没有显式REFRESH；两个MV后台任务均SUCCESS，变更前后完整内容一致。
统计阶段实际返回1105，原因是测试工具将仅支持ALTER的`auto_analyze_policy`放入CREATE；已改为
CREATE→ALTER本轮临时表→INSERT，42项离线检查通过。随后第五轮在已登记helper退出期间发生资源采样竞态，
仍记FAILED，资源证据不完整；控制器和自有helper均退出、字典与数据库清理完成。正在修复采样/停止竞态，
没有改变数据库源码或资源门槛。各轮及源码绑定测试见[第四/五轮审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp026-v4-v5-terminal-audit.json)。
此前209项汇总加上后台测试36→42，按各自源码版本共215项不同Python检查；不代表后续改动自动通过或完整LP026通过。

原版UI构建清单已从保留的发行审计归档恢复：打包后保留的131个静态文件全部与实际FE JAR一致，
当前UI源码与该构建提交无差异；实际Node/Chrome版本命令通过。18格原版导航计划已准备，尚未创建测试账号或启动浏览器。
见[产物核对](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/ui-original-prerequisites-v1/provenance.json)与
[计划回执](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/ui-original-prerequisites-v1/plan-receipt.json)。
原版可达、允许业务背景和A/A仍属P0；License Tab、导入/回执及有限轮询由P2U/P2接入，完整B对照属P5。
用户已确认区分业务背景与页面指标：业务样本量、1% CPU/吞吐和2% P95/P99精度要求不变；页面保持300秒/10秒刷新及
原并发矩阵，独立记录请求、延迟和资源，样本不足不宣称页面P99达标。机器清单的新版本已在LP026第六轮终止并清理后应用，
契约检查及29项自检通过，不改写历史轮次的冻结输入；不把少量页面样本、跨角色/窗口混样或后台SQL样本当作页面P99达标。

LP026退出竞态修复通过45项后台、18项资源测试及100个真实短命helper压力，后者明确记录33次退出中的末次资源样本缺失，
均有真实退出回执，没有填补RSS。第六轮再次通过自然字典刷新和两次MV任务，自动统计job及两个列任务也实际FINISHED；
列统计值正确，但原版默认`SAMPLE`与工具错误的`FULL`假设不符，因此该轮仍FAILED。
修正为预先确认原global阈值0、固定期待SAMPLE（不修改global）后，47项后台+18项资源检查通过。
第七轮仅选择统计、ES、CSV、Parquet四阶段，未选字典/MV明确not_run，不将多轮拼成一轮成功。
统计自然SYSTEM/AUTOMATIC及SAMPLE完整值、真实ES请求、CSV预览均通过；Parquet内容正确，但原版FE未关闭reader，严格检查失败。
其报告保持FAILED且`cleanup.complete=false`；[独立物理清理](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp026-background-http-actual-v7-control/cleanup-audit/report.json)
已确认本轮DB/catalog/broker缺席、端口可绑定、全部自有进程退出，原FE/BE身份不变。
用户已明确选择保留该原版缺陷、继续授权开发，详见[接受记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp026-parquet-defect-accepted/acceptance.json)；
不修改产品或BE，不把测试工具强制关reader当作原FE正常关闭。

另补充独立并发页面执行器，真实context、共同窗口、原请求节奏与单份业务背景分开记录，
已通过16项Python和12项Node离线检查，[源码/命令/结果](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/ui-concurrent-validation-v1/receipt.json)
保留首轮失败。该工具尚未实际启动浏览器；既有18格导航先接续执行，完整并发矩阵及业务A/A仍待验证。
LP023控制器的窗口检查点改动通过20项原有检查和两窗短smoke，
[记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/primitive-progress-checkpoints-v1/smoke-receipt.json)
只验证工具路径与清理，未重启正式长测量、未升级原156/420窗的未完成结论。

Kafka 完整持续窗口工具已完成最终离线复核：新增39项和既有20项Python检查通过，
实际Temurin17.0.4+8/原Kafka3.9.2依赖编译及17个Java自检场景通过。
后两轮修复来自静态复核发现的中断清理、首错保留和回执交叉绑定问题；初版没有实际测试失败，不虚构失败记录。
[最终回执](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/kafka-baseline-v3/validation.json)
和独立核对确认14个绑定文件、5个class一致；没有生成13M物理输入或运行真实持续窗。
计时10M与额外3M预热使用不同ID域，生产并发与Routine Load消费任务数分开，未将8分区的单job称为32个并行消费任务。

已生成[后续原版功能窗口计划](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/next-original-functional-plans-v1.json)：
LP007使用8并发、2请求/秒、180秒预热及600秒计时，冻结365个预热/1175个计时到达和中途视图事件；
LP012使用完整10M既有输入、8并发、每批1000行、180秒预热及600秒计时。
此处仅计划生成成功，没有发送SQL/HTTP；待页面环境释放后顺序运行。
这些功能窗口不替代容量、至少五对A/A、数值精度或完整原矩阵要求。

原版UI首轮18格全部失败，原因定位与工具修复分开保存；修复中文双字按钮空格、带图标按钮定位及异步等待后，
新轮完成18格规定导航/权限/查询/注销，18格浏览器正常关闭，三个专有账号独立查询确认缺席。
原报告保持6 PASS、12 PARTIAL和exit2；12格的额外结果页新窗口深链观察依赖原`history.state`，不修改产品或改写原状态。
[范围审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp021-ui-navigation-actual-v2/required-navigation-audit.json)
明确该项不是LP021规定的原导航动作，且没有宣称并发/背景/P2U通过。
并发工具随后补齐真实背景token与时间回执、物理清理失败后停止矩阵，以及32MiB有界浏览器报告兼容；
[最新20项Python/13项Node检查](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/ui-concurrent-validation-v3/receipt.json)通过，54个真实并发窗口仍未运行。

共享负载排他检查补入新Python控制器、孤立Kafka Java和UI Node入口，按实际argv/cwd绑定本checkout，
59项后台+18项资源检查通过。旧复杂/Stream计划因输入源码变化而保留不用，新计划另行冻结。
复杂查询第一次实际准备被原语法拒绝，工具已改成`EXPLAIN ALL PLAN`，24项既有检查通过；
第二次实际取得冷规划和缓存命中Profile，但工具错误拒绝正常缓存查询的`EOF`状态，仍记FAIL。
[两轮原始失败与清理](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp007-v2-v3-terminal-audit.json)
确认自有视图删除、所有辅助进程退出；没有计时窗口完成，也未放宽结果模型或性能门槛。

原FE源码进一步确认Profile将`OK`和`EOF`都视为正常，oracle已精确接受两者并保留原始状态；
22项oracle+24项controller检查通过，真实冷/热两份Profile及同请求33列结果均独立核对，22个变异负例被拒绝。
[真实Profile核对](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/complex-profile-eof-v1/actual-profile-audit.json)
没有改写v3失败。v4已按原365个预热/1175个计时到达、180/600秒和8并发重新开始，当前运行状态必须结合真实进程核对。

Stream工具复核发现实际原FE的307响应带三条合法`Vary`，旧工具错误拒绝重复头；已只对这一列表字段合并，
关键单值字段仍严格校验。新增独立`timeout: 60`原协议请求头，成功提交、未向BE提交、服务端终止未证实分别记录；
超时、socket关闭和DROP回执均不清除未知事务状态。[48项检查与真实存档响应回放](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/stream-load-vary-timeout-v3/validation.json)
通过，保留此前新增测试mock失败；没有真实Stream请求。
[当前冻结计划](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/next-original-functional-plans-v2.json)
分别绑定复杂v4和Stream v2，旧计划/失败均保留。源码头、差异格式检查及36项最新源码/原始输入摘要核对通过，
见[当前绑定审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/final-source-checks-v2/current-binding-audit.json)。

复杂v4现已完成，控制器真实exit0；[独立完整审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp007-concurrent-actual-v4-control/v4-completion-audit.json)
确认365次预热和1175次计时请求逐一对应全部1540份意图/结果，33列全部正确（原模型708、变更模型832）。
161份Profile包含变更前后各1份冷规划、73/86份缓存命中，均绑定实际请求；原与重建缓存EXPLAIN都有。
180秒事件晚2.525020ms开始并成功ACK；视图恢复、删除后缺席、14个helper退出和781次资源采样清理均确认。
实测目标SQL同时执行峰值2，含观察开销的完整请求峰值3；DDL重叠样本0，该分支仍只有离线正负例。
1175次计时请求不满足正式10000样本门槛，不将365次预热混入，完整LP007及性能仍未通过。
环境已顺序移交完整10M的Stream v2；后者已完成输入核对并开始实际预热，尚无终态结论。

Stream v2随后自然结束为FAIL：180秒预热的3000批中2958批取得成功回执、42批因测试队列满未发送，
没有进入测量阶段，未知提交0。原BE回执记录了约2–3秒写入停顿，其原因尚未证实；
工具每worker仅2个待执行引用，只能容纳约0.96秒到达，提前丢弃了仍在原60秒期限内的请求。
[原失败及清理审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp012-sustained-actual-v2/failure-audit.json)
保留该轮失败，确认29个helper退出、自有DB缺席、原服务身份不变。
工具现按冻结到达序列和原60秒绝对期限推导有界引用队列，本档每worker125个引用，活动上传仍最多8个；
过期请求明确失败，仅活动且未过期请求读取body。新增7项边界/停顿检查后，
[55项源码绑定测试](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/stream-load-queue-v4/validation.json)通过。
新v3计划与v2的完整输入、到达序列、速率、180/600秒窗口及资源/超时要求一致，独立核对进程身份后运行；
截至08:04 UTC已通过3000批预热及独立内容校验，600秒测量尚在进行，不能提前记为完成。

[资源指标只读核查](/data/project/massdb-sql/.build-records/read-only-metrics-gap-review-v1.json)
发现原FE已有fragment RPC尝试数/序列化请求大小、Thrift handler次数和GC暂停日志，当前采集器未保存前两项。
后续可按其原定义增量采集，不能倒补当前窗口，也不能称为全部RPC、线上字节或完整进程网络归因。
实际JDK17.0.4的逐线程分配轮询会遗漏退出线程，不能代替FE总分配量；这些指标缺口和测量成本仍待验证。
当前真实窗口的采集器和冻结输入保持原版本，增量采集须另起计划。

Stream v3于08:10 UTC自然完成，控制器实际exit0；
[独立完整回执审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp012-sustained-actual-v3/root-completion-audit.json)
逐一核对13000个不同事务的原始ACK、摘要、到达/期限、两跳协议、全部3M预热及10M测量内容和统计。
180秒预热3000批、600秒测量10000批均在各自窗口内成功，失败/未知提交/尾部drain批次均0；
实测客户端请求区间并发峰值8，待执行引用峰值7，未增加活动上传或改动原超时。
161次现有指标采样无错误/跳过，报告清理无错误。测量批次端到端P50为44.256217ms、P95为542.794917ms、
P99为2004.825469ms，均含排队；它们是本轮描述值，没有多对窗口的检测精度，也没有候选B对照。
本轮状态保持`FUNCTIONAL_WINDOW_COMPLETE_PERFORMANCE_INCONCLUSIVE`，完整LP012矩阵和性能验收未通过。

后续清理审计及root复核确认37个helper真实exit0且进程缺席、DROP ACK与独立SHOW DATABASES中本轮DB缺席，
原supervisor/FE/BE身份不变，owner锁已释放；见[清理复核](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp012-sustained-actual-v3/root-cleanup-recheck.json)。
root首个复核脚本错误要求整个SHOW DATABASES结果为空，已按原SQL语义改为检查本轮DB缺席；这次审计脚本失败另记，
没有改变实际probe的成功/清理结果。

Kafka完整输入现已准备并[独立逐字节重建核对](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp013-sustained-prepared-13m-v1-control/validation.json)通过：
额外3M预热384,000,000字节、计时10M共1,280,000,000字节，233个发行文件与9个冻结源码一致。
准备阶段的默认1 producer不参与输入生成；实际窗口另冻结8 producer、requested8 consumer、batch1000、CPU5及原180/600秒。
准备过程未启动broker、编译或访问服务，不能替代实际Kafka持续窗。

LP023另生成[新的完整原语测量计划](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-primitive-formal-v2-plan/planning-receipt.json)，
原42组合不变，预先选定每组合10对独立窗口，共840窗；每窗仍至少60秒且100万次，预热15秒。
旧5对control约1.25%的CPU/吞吐置信区间半宽未满足1%，因此新计划增加独立窗口数，未降低门槛；
增加样本不保证通过，也不按结果逐窗追加至通过。旧中止记录不拼接，新计划尚未开始测量，须在其他实际负载结束后另排独立时段。

资源采集增量已完成：保持默认调用接口不变，可选采集原有fragment/Thrift计数及FE已有GC日志，
[56项离线检查与存档对账](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/resource-observer-increment-v1/report-v2.json)通过。
首轮轮转检查发现共享目录游标问题，原失败保留，修复后用独立目录描述符扫描；读游标与已确认归档游标分开，
归档失败、flush超时和进程身份变化均保留真实边界及采集开销。35条存档GC事件完整值一致，138个RPC候选中14个存在、124个仍为空。
只读复核未发现当前增量范围内的新缺陷；60秒实际smoke已冻结、尚未运行。完整GC窗口映射、FE总分配、全RPC和进程网络归因仍未解决，
该增量不追认此前窗口，也不证明1%的端到端资源开销门槛。

Kafka完整窗口于08:39 UTC自然结束，真实父进程wait为0，
[最终审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp013-sustained-actual-v1-control/completion-audit.json)
确认180秒额外3M预热、600秒10M测量均全部ACK，独立消费13M的ID、逐行字节和连续offset一致，
预热3M及最终13M的完整SQL模型通过；没有未知提交或测量尾部drain。
8个持久生产客户端分别发送1,625,000行，但固定60ms批到达下实测send/ACK区间重叠峰值为1；
不能把配置并发或Routine Load的8个任务数当成8个同时执行请求的证据。
10,000批生产端排队至ACK的P95/P99为19.658107/22.8633ms，不是数据库提交可见性延迟，且没有A/A精度。
状态保持`FULL_INPUT_WINDOW_COMPLETE_NOT_QUALIFIED`，完整LP013并发、批次和性能矩阵仍未通过。

STOP后的任务数0、报告中的runningTxns为空，本轮表缺席；285个自有进程全部退出、端口及owner锁释放。
[root终态复核](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp013-sustained-actual-v1-control/root-completion-recheck.json)
重验原3个服务身份和285个进程缺席，核对报告/计划/清理摘要，未重复运行13M遍历或重发清理SQL。
首个root临时断言误把SQL total_count对象当整数，修正为读取原JDBC的n字段后通过；发生于索引写入前，原实际结果未变。
清理前采到输出7,601,681,467字节、broker关闭索引收缩后6,367,154,269字节，均在原8GiB限制内；
初始空间预估漏算内部offset索引的说明单独保留，未提高预算，采样值不宣称绝对瞬时峰值。

资源采集增量60秒实际smoke现已完成：
[完整回执](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/resource-observer-increment-smoke60s-v2-control/completion-audit.json)
记录13次采样、26个HTTP200、0错误/0跳过，真实wait0、进程退出、原服务身份和9份冻结小文件保持一致。
采样窗口CPU0.117242秒，含准备/结束的进程CPU0.119741秒，峰值RSS24,662,016字节；这些是本次采集器观测值，不是服务1%成本通过。
138个RPC候选每次16个存在、122个仍为空；report handler增加14次、累计5ms，fragment计数/大小未增加。
本轮新增GC事件0，原日志游标一致并全部关闭，不能从空事件归档推导新的暂停分布。
root核对7份回执摘要和观察进程缺席；没有再发服务请求。环境释放后将按既定顺序进行页面并发验证。

页面并发工具增加可选失败后停止，并保留完整54格计划、已尝试失败窗口及未执行窗口；26项工具检查通过。
[外层账号/进程控制器验证](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/ui-concurrent-owner-preparation-v1/validation-v4/receipt.json)
另通过26项离线检查和本地输入核验，628项绑定包含实际HotSpot libjvm；旧配置与回执保持原样。
复核发现的证据写入失败和终止异常现不会跳过独立安全清理、真实wait或管道关闭，最先失败不被后续异常覆盖。
实际执行将先检查账号名称缺席，按CREATE ACK与唯一comment记录归属，核验真实权限，结束后按归属清理背景表/账号/进程；
尚未启动54窗，离线26+26有不同范围，不能相加冒充实际页面矩阵通过。

上述54窗随后于08:55 UTC实际启动，4个合成账号均收到CREATE ACK并通过原权限位图核验；
[root启动核对](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp021-ui-concurrent-actual-v1-control/root-start-observation.json)
确认活控制器身份、11份工具源码及冻结计划：3路径前缀×2语言×3角色×1/10/50上下文，共54窗，
各300秒、10秒刷新，单份背景每秒10读和1批10行写入。原协议和服务身份不变，真正父进程wait仍待终态。
完整有效窗口时长下界4.5小时，不含准备/校验/清理；运行中不宣称页面矩阵、业务性能或完整P0/P1通过。

页面并发v1随后停止：1与10个上下文各完成300秒，分别31/310次页面动作，背景完整读写模型及当窗清理通过；
第3格在javac准备阶段出现`ValueError`，尚未启动后台主程序或50个浏览器上下文，后51格明确未执行。
[原失败观察](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp021-ui-concurrent-actual-v1-control/root-failure-observation.json)
保留原`WINDOW_CLEANUP_UNCONFIRMED`，不能因后续外层恢复成功把原格改成通过。
只读比对确认编译初始pin及命令与冻结输入一致，产生的class与前两格相同，但没有编译器真实exit回执；
退出过渡是待核查候选，不声称已确证，也不归因为50并发容量、90秒barrier或6GiB预算。
父控制器实际wait为exit2，外层已报告对象/账号/进程清理完成，独立最终清理审计另行收口。

页面v1的[root终态复核](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp021-ui-concurrent-actual-v1-control/root-terminal-recheck.json)
现已完成：66份原始证据摘要匹配，104个记录过的自有进程生命周期均已结束，原3个服务身份未变。
外层独立SQL清理审计确认4个合成账号和3张背景表缺席，源点查表仍在；root未重复发清理SQL。
该回执只确认物理清理和证据完整，原第3格失败及后51格未执行保持不变。

新的完整payload点查容量pilot已完成[准备与8项控制器检查](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/point-payload-capacity-pilot-v1-control/preparation-receipt-v2.json)，
尚未运行：固定4000/5000/6000/7000/8000次每秒、16并发、每档1对窗口，共10窗，预热120秒、测量60秒，
P99不超过20ms、drain不超过1秒的原门槛不变。客户端新增64–512MiB堆限制，属于新冻结条件，
不能把与历史pilot的差异全归因为payload校验。该pilot仅用于容量诊断，不替代完整容量标定或A/A精度验收。

LP023的[新840窗控制器准备回执](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-primitive-formal-v2-control-preparation/validation-v3/receipt.json)
记录15项短Python检查及默认本地输入核验通过；其中两个真实被接管子进程分别exit7和SIGTERM，
原始wait status被保留并计入失败，后续清理成功不会覆盖原失败。控制器运行在CPU5，测量仍使用CPU0–4；
实际执行前须完成原自有服务的正常停止和真实wait，并核验独占交接，当前未停止服务、未启动测量。
42组合×10对、每窗至少60秒且100万次的计划不变；仅测量/预热的时长下界为17.5小时，48小时为停止预算，非预计完成时间。

页面背景helper退出观察修复已完成[最终33项背景、27项并发检查和owner本地核验](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/ui-background-exit-handshake-v1/validation-final/receipt.json)。
身份明确变化仍立即失败；仅对退出候选在原阶段期限内执行有界父进程wait，资源字段缺失而仍存活时不能放行，
真实退出码、最先失败和独立清理均保留。精确Temurin17.0.4+8下，中间版本12次javac检查有2次真实退出过渡，
最终源码另3次编译均真实wait0；这些支持修复边界，但不补造原v1第3格缺失的编译退出码或确定归因。
[root启动前核对](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/ui-background-exit-handshake-v1/root-prelaunch-recheck.json)
确认628份冻结输入、最终源码及回执匹配，3个原服务身份未变。新v4配置使用独立actual-v2目录和合成账号，
按原54格、300秒/10秒刷新、6144MiB限制重新运行；v1两个成功窗不拼入新一轮，也不提高原门槛。

新一轮于09:28 UTC实际启动，4个新合成账号的CREATE ACK及权限核验完成。
[root启动复核](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp021-ui-concurrent-actual-v2-control/root-start-observation.json)
确认控制器活身份、11份工具输入和全部54格与原矩阵一致，实际session88724的父进程wait仍待终态。
root首个临时矩阵断言误把英文locale写成en-US，实际冻结值一直为en；仅修正审计预期，未改变运行输入或产品代码。

页面v2于09:39 UTC终止，真实父进程wait为exit2。1/10上下文分别完成31/310次页面操作，
各自3045次背景读、326批写及完整模型/重叠验证通过；第3格已越过旧编译失败点，但准备期采样RSS峰值
7684.0546875MiB超过冻结的6144MiB，尚无browser-ready或业务window-start，50个proxy的请求数均为0。
[失败分析](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp021-ui-concurrent-actual-v2-control/failure-analysis.md)
确认只有一个浏览器实例，OS子进程数不能代表实际创建的BrowserContext数；本次精确创建数未知。
RSS是各进程之和，可能重复计算共享页，不能改称物理私有内存或OS OOM，也不能归因为FE授权回归。
原始每秒资源记录未覆盖亚秒峰值的各进程分解，峰值只由当次控制器计数保留，不补造缺失样本。

[独立终态复核](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp021-ui-concurrent-actual-v2-control/root-terminal-recheck.json)
重验87份原始文件摘要、147个自有生命周期缺席及原3个服务身份；外层新只读SQL审计确认4账号/3背景表缺席，
源表仍在，物理清理完成。第3格FAIL和后51格未执行保持原样。
[准备并发评估](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp021-ui-concurrent-actual-v2-control/preparation-concurrency-assessment.md)
确认原要求没有规定准备期同时登录，可单独限制准备并发为4，并在全部50个隔离上下文就绪后统一开始原300秒窗口。
该方案只进入独立工具草稿，尚未验证，不提高6GiB/90秒限制、不串行化计时操作，也不保证解决50上下文的稳态内存需求。

点查完整payload容量pilot于09:47 UTC启动，
[root启动复核](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/point-payload-capacity-pilot-v1-control/root-start-observation.json)
确认owner/calibrator真实活身份及CPU绑定，原10窗、120秒预热/60秒测量、16并发、速率4000–8000、
P99 20ms/drain 1秒和64–512MiB客户端堆限制不变。session17331父进程wait仍待终态；这是容量诊断，
不能代替完整容量或A/A精度。同期其他工作仅静态源码读取及独立小文件草稿，不运行测试、构建或其他服务负载。

[资源要求口径核对](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/resource-metrics-requirement-reconciliation-v1.json)
逐项核对原26用例与执行计划：要求既有CPU/RSS/GC/IO/网络序列及existing_rpc_count_bytes，
并未要求新增全RPC/wire追踪或逐进程物理网络总字节；既有指标的namespace、attempt/handler及serialized-byte范围仍须披露。
此前采集器结果中的全覆盖为false等限制保持原样，不能把它们自行提升为新增发布条件，也不将缺失值补零。
真正尚需实施的是正式窗口显式接线、FE分配量估计及误差校准、GC记录与业务窗口的时钟对应。
[具体接线诊断](/data/project/massdb-sql/.build-records/resource-measurement-minimum-scope-v1/diagnostic.md)
提出在下一次原FE启动时使用同配置的timenanos日志装饰器，并先用独立JDK helper验证分配估计；
当前只读证据和草稿不构成这些能力的实际验收，不改本轮运行配置、不回填历史缺失数据。


点查完整payload容量pilot已于10:19 UTC完成原10窗，真实parent wait为0；
[终态复核](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/point-payload-capacity-pilot-v1-control/root-terminal-audit.json)
核对437份实际输出、23个自有进程生命周期缺席及原3服务身份不变。
3,606,688次测量请求逐值成功，4000/s两窗满足20ms P99/1s drain；5000–8000/s未满足。
4000–5000/s区间宽25%，不是1%容量确认或A/A通过；不将原客户端堆与payload校验不同的旧试跑拼入。

页面准备并发上限4已通过[35项Python和21项Node检查并提升到工具源码](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/ui-bounded-preparation-draft-v1/validation-v1/promotion-receipt.json)。
全部页面就绪后仍同时执行原计时操作，90秒准备期限、6GiB客户端RSS、300秒/10秒节奏不变；
新增实际创建/就绪计数、同一资源采样帧的超限证据，以及独立保留首错和最终保存失败。
这只是工具验证，尚无新50上下文实测通过记录，原v1/v2失败均保留。

[实际时钟能力探针](/data/project/massdb-sql/.build-records/primitive-clock-capability-v1/actual-v1/receipt.json)
编译及执行真实退出0：本机clocksource为arch_sys_counter，计数器24MHz，周期约41.67ns；
clock_getres虽返回1ns，不能当成物理分辨率。测量工具现在绑定本机时钟回执和原始输出，
保留直方图桶误差，并按一个计数周期加1ns整数舍入扩展延迟区间；缺少回执时不能宣称延迟精度通过。
[25项定向检查](/data/project/massdb-sql/.build-records/primitive-clock-capability-v1/guard-validation-v1/receipt.json)
覆盖未知时钟、量化误差不能靠增加配对消除、较长延迟仍可达标、原始证据与本机身份不符拒绝等场景。
历史报告不重写；旧840窗配置所冻结的工具已变化，必须重新绑定。没有降低1%/2%门槛，也没有将批次平均耗时改称单操作P99。


分配量能力实验已一次完成[12个固定阶段、独立核对和真实退出清理](/data/project/massdb-sql/.build-records/allocation-capability-draft-v1/actual-v1-parent/completion-audit.json)。
精确JDK17.0.4+8下记录292个worker回执，owner及4子进程均真实退出0，原FE/BE/supervisor身份未变；
采样helper RSS峰约181MiB，控制器CPU约1.15秒，均只是这次实验的观测。
现有300/s JFR采样权重与已知worker MXBean之差分别为stable1 −3.10%、stable8 −62.44%、short64 −92.87%；
short64中58/64无分配样本，全部64个短线程缺少periodic观测。
这些是单次差异，不是误差置信界，不能将采样权重直接称为FE总分配量；后续估计器仍须校准，当前FE没有启用新录制。

有界证据归档工具另完成[37项临时夹具检查](/data/project/massdb-sql/.build-records/evidence-archive-draft-v1/review-receipt.json)，
保留损坏/替换/中断的首次失败和修复记录。它要求解压逐字节核验、原文件身份不变及持久恢复映射后才移除选定原文；
当前没有选取或压缩删除真实历史证据。下一容量细化仅形成4500/s两窗的独立建议，尚未运行，不拼接旧pilot制造正式容量通过。


页面actual-v3已于10:46 UTC启动，原54格完整矩阵、新4账号CREATE ACK和权限核对已完成。
[root启动观察](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp021-ui-concurrent-actual-v3-control/root-start-observation.json)
确认正式plan与离线预览的全部cells、时长、资源及背景配置一致，controller真实活身份与原3服务身份匹配；
session68156的终态parent wait仍待实际完成。固定prepare4不是降低计时并发，50上下文运行和内存要求尚待实测。
其他工作仅CPU5小型静态读稿/草稿写入，无测试、构建、压缩或其他业务负载；该运行是功能共存前提，不构成业务A/A通过。


页面actual-v3真实parent wait为exit2，前两窗PASS，第3窗在background Java身份检查失败，后51窗未执行。
初始pin的command SHA是空字节摘要；后续同PID/start的非空摘要与实际预期Java argv相符，不能归因于50上下文或RSS。
本轮第3格尚未创建浏览器/准备回执。原内层cleanup=false保留；外层完成清理后，
[独立终态复核](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp021-ui-concurrent-actual-v3-control/root-terminal-recheck.json)
确认108个自有生命周期缺席、原3服务身份不变，另一个只读SQL审计确认4账号/3候选表缺席且源表存在。
空命令行出现的底层精确机制未实测；修复必须在原启动期限内匹配预期exe/argv后再冻结身份，不放宽后续真实变更检查。

[GC记录时间映射模块](/data/project/massdb-sql/tools/license-checks/gc-window-mapping.md)已在28项离线测试通过后提升到工具源码，
原装饰器选择/路径、进程和时钟域必须完整匹配；只按日志记录时刻分配半开窗口，终态drain另列，不推算STW起止。
当前observer/运行FE仍未接线、没有改日志配置或用此模块回填旧数据；历史退役generation缺少最终cursor证明时继续拒绝。


点查4500/s独立细化已完成两窗、541,074次逐值成功，P99分别26.96/648.55ms，均超冻结20ms；
[终态复核](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/point-payload-capacity-midpoint4500-v1-control/root-terminal-audit.json)
确认真实parent wait0、6个自有生命周期缺席、原3服务身份不变及89份原始输出摘要。
该单点诊断没有建立容量区间或A/A精度；窗间波动原因未知，不归因于尚未接入的授权核心，不拼接旧端点。

分配量300/s与off参数化草稿经37项纯Python检查及精确JDK编译、两种仅plan、owner默认校验通过，
尚未执行新的10个JVM校准矩阵。Kafka大样本独立消费校验草稿另通过40项32行小夹具检查，
此前回收决策30项通过；实际producer/consumer接线、103M吞吐与8GiB存储边界仍未验证。


固定300/s与off校准已实际完成全部10个独立JVM、120阶段、2,920个worker回执；
[最终清理与完整性核对](/data/project/massdb-sql/.build-records/allocation-calibration-draft-v1/actual-matrix-v1-parent/completion-audit.json)
确认10次owner真实wait0、50个自有生命周期缺席、原3服务不变及490份实际文件摘要。
5对顺序、原工作负载、每轮预算和35分钟总停止预算未改，没有补跑或拼接旧结果；采样误差仍待统一汇总，未证明完整FE分配量或1%服务开销。

页面启动身份修复合并测试初轮因测试别名遗漏失败，原日志/快照保留；修正测试别名后48项通过，运行源码与已复核、精确JDK短测版本一致。
[提升回执](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/ui-startup-pin-draft-v1/promotion-v1/receipt.json)
和[新完整54格准备](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/ui-concurrent-owner-preparation-v1/validation-v6/receipt.json)
均已登记。root重验628份输入、矩阵与原参数、原3服务身份及新目录缺席后，独立授权actual-v4；此前v1/v2/v3失败保持原样。


[10次分配实验的统一派生报告](/data/project/massdb-sql/.build-records/allocation-calibration-analysis-v1/README.md)
已完成固定5对描述性校准：off的stable1/stable8/short64 allocate平均相对差为−0.503%/−0.926%/−5.417%；
300/s对应−0.964%/−65.462%/−92.052%。分母均为同run已知worker自己的MXBean参照，非精确FE总量。
off的一个short64 control出现263040B sample weight对4096B参照，保留跨窗/低分配不稳现象；不扣除control或推导未来误差保证。
只将off作为附限制的采样估计候选，后续仍需实际FE接线及原同配置A/A开销和精度；不额外要求全量逐对象追踪。

页面actual-v4已于11:38 UTC实际启动，4个新账号CREATE ACK及原权限oracle通过；
[root启动复核](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp021-ui-concurrent-actual-v4-control/root-start-observation.json)
确认实际plan全部54格与离线预览相同、原参数和3服务身份不变。session1290由启动owner继续等待终态；当前不把运行中记录计为通过。
