<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# P3 五出口与节点额度验收记录

日期：2026-09-25。**当前状态：已完成约定 FE 范围的 P3 实现与分层功能验收。**
本记录按[当前 P0 契约](license-p0-contract-20260922.md)区分源码测试、受控执行和实际网络入口。
P0/P1/P2 已完成的结论不变；P2U 证书页面和 P4 完整性能验收不属于本次 P3 完成判定。

## 范围与运行产物

本次只修改 FE。五出口为 SQL 查询结果、复用的 prepared 点查、受保护数据写到外部表、EXPORT、
新 `_query_plan`。写入内部表、元数据和真实服务器维护用途继续允许；严格原始形状
`SELECT 1 FROM t LIMIT 1` 和可证明整个最终结果为空且不取数的计划按契约放行。
外部真实表和内部系统实际数据表属于受保护数据；六类文件/远端 SQL TVF 不享有窄式探测例外。

BE 二进制、源代码和通信协议保持原状，不引入 SSL/mTLS 或跨节点执行凭证。
有效期内保存的 BE 计划仍可能在到期后继续使用；BACKUP/RESTORE、CCR、BE 下载等已接受通道不纳入封堵。
正常许可路径读取已发布快照和可信时钟，不做验签、文件 I/O 或成员表扫描；规划绑定顺便保存少量分类事实。
这描述实现结构，**不等于端到端性能零回退或 P4 通过**。

真实测试使用精确 Temurin 17.0.4+8、隔离网络中的三 FE 和未修改的原版 BE，以及独立 PostgreSQL、
MinIO、HDFS、Hive Metastore、Iceberg REST、Kafka 小数据夹具。麒麟/openEuler 和架构发行矩阵不列为本次目标。
原基准 FE/BE 生命周期另行固定，不作为测试集群操作对象；共享宿主上的功能运行不冒充性能测量。

| 产物 | SHA-256 / 用途 |
| --- | --- |
| runtime-v1 FE / package-1 | 初轮查询、HTTP/Flight/连接器、prepared、JDBC 和写入兼容；真实额度测试发现错误码桥接缺陷 |
| runtime-v2 FE / package-2 | `bb72e73fa8c3619e29ba4c3cb984e6cd3269619ab10ca8f4573159c72f8ce0a6`；修复额度错误码后重验 |
| runtime-v2 fe-common | `a0d000535b201fb5906b0e389af67bb59357131b3994dd42f28fecbbe68ca4d2` |
| runtime-v3 FE / package-4 | `324bf6fd77978441c04ebb13b4d3853a51c7301c0520f317b1c363c190655ed3`；仅补过程许可拒绝的结果收尾保护 |
| runtime-v3 fe-common | `9835a66671dfaf18b6e080bc8d1f4d1c8c4ea1f509e64a23154b72a88a1efdc3` |

tests-10 编译产物与 runtime-v2 JAR 的 10,396 个产品 class 比较，仅四个构建版本信息使用类不同。
最终 package-4 与 runtime-v2 比较，另有 `Exec.class` 和其生成类 `Exec$1.class` 不同；
前者包含过程拒绝修复，后者的 `javap -c -p -s -constants` 输出一致，未将字节不同写成逐字相同。
其他许可/准入产品 class 一致。原始日志、请求、独立数据模型、产物和源码摘要位于忽略目录
`.build-records/license-p3-20260925/`，不提交私钥、证书字节、运行配置和测试安装。

## 源码及受控执行测试

| 轮次 | 实际结果与边界 |
| --- | --- |
| tests-7 | 288 项通过，0 失败/错误/跳过：246 项许可相关、42 项选定原功能回归 |
| tests-8 | 290 项中 1 项失败：新增 FE 额度测试的 Env 模拟字段缺失；原始失败保留 |
| package-2 | 修正测试夹具后，额度 SQL/管理相关两个类 9 项通过，FE package 成功；不是一次 290 项全绿 |
| tests-9 | 实际 StmtExecutor 两层重试和 Coordinator 首次派发边界两个类 18 项通过；规划/RPC/时间受控 |
| tests-10 | EXPORT 准入及真实 transient scheduler 两个类 5 项通过；环境、存储删除和时钟受控 |
| package-3 | 新测试使用 String.lines，超过项目 Java 8 API 编译目标；在测试编译阶段失败，未执行测试。运行 JDK 仍为 17.0.4，已改用兼容的测试计数方式，产品代码不受此修正影响 |
| package-4 | FE package 成功；过程准入、查询执行和实际重试循环三个测试类共 22 项通过，0 失败/错误/跳过。不是全量测试集重跑 |

tests-10 使用真实调度队列、TaskHandler、ExportMgr、ExportJob 和 ExportTaskExecutor：
先占满实际 worker，再合法提交、切到期并释放；任务取消、内存登记删除，所有自有 worker 退出。
提交前已经发生的登记和目录删除不回滚。该测试不冒称真实远端 EXPORT 故障注入。
tests-9 验证已经首次派发的同次内部重试可继续，首次派发前不能沿用准入，新执行重新检查，
取消/超时/重试耗尽后清除执行事实；不在客户端 session 或 prepared handle 上永久保存许可。
过程修复的受控反例在旧代码下 4 项中 2 项因附带空指针异常失败，修复后 4 项通过；
package-4 再以项目正式构建运行这 4 项及 18 项执行/重试回归。各轮记录保留其实际源码绑定，
不能累加成一次完整测试集全绿。

## 查询用例及当前证据

本表是逐组索引，明确每个变体的实际网络、受控执行及不适用边界；不把受控故障写成实际集群故障。

| 用例 | 已有证据 | 尚待收口或适用边界 |
| --- | --- | --- |
| Q01 协议/权限 | MySQL/JDBC 文本及非点查 prepared、HTTP Query、Flight 1024 的 V/E；root、ADMIN、普通 SELECT 用户；HTTP/Flight 无 SELECT 用户原错误保持；全部 D 状态受控决策测试 | 最终包显式绑定 ADMIN/无 SELECT 账号，text 和实际 ServerPreparedStatement 的 V/E 均通过；HTTP/Flight 保留原错误外壳，不虚构 SQLSTATE |
| Q02 多语句 | E 包逐句处理；实际 V 写入 ACK 后跨自然到期，下一业务句 6200/45000、零行 | 实际首 ACK 和前后时间证明每句重判；使用自然到期，没有注入产品 latch |
| Q03 过程 | 真实过程 SELECT 的 V/E、先内部写再读取跨期；原语法和权限保留 | 最终 package-4 的 direct/INTO 在独立原协议连接中 V 成功、E 返回 6200/45000 和 LICENSE_EXPIRED，零行且无附带 NPE/Unhandled。旧包错误及最终夹具首次 JDBC 解析失败保留 |
| Q04 一般业务依赖 | 聚合、DISTINCT、常量带条件、EXISTS、JOIN、CTE、UNION 的实际 V/E；原始形状受控测试 | 无新增范围 |
| Q05 视图/MV | 视图、直接 MV、源表实际选中 MV 改写的 V/E；EXPLAIN 和完成刷新记录 | 不能把未命中改写的查询当作该变体 |
| Q06 混合元数据 | information_schema 纯查询允许、混业务子查询拒绝；backends/partitions 元数据实测 | 保留原权限 |
| Q07 系统/外部表 | JDBC/Hive/Iceberg 独立实际数据源 V/E；当前 audit_log 实际存在，V 读取/EXPLAIN 成功，E 返回 6200/45000、零行 | 审计行仅保存摘要；不创建或修改原系统表 |
| Q08 数据 TVF | s3/hdfs/local/file/http/query 六类均实际 V/E；TVF 伪探测拒绝，numbers/元数据允许 | 正常规划仍可能读取 schema，不宣称规划零 I/O |
| Q09 管理/元数据 | 探活、版本/数据库/时间、SHOW/DESC、列统计及 EXPLAIN 实测 | min/max 等已接受元数据不裁剪 |
| Q10 最终零行 | LIMIT 0、常假条件实际允许；完整空证明和未知证明受控测试 | 不把估计零行或空 scan list 当作证明 |
| Q11 分区空 | 完整分区裁剪空允许；外层 COUNT、含非空业务分支 UNION 拒绝 | 保留完整根计划证明 |
| Q12 窄式探测 | 内部非空/空表、别名/OFFSET 0、括号和 JDBC 外部真实表实际 V/E | Hive/Iceberg 严格探测、别名/OFFSET 0 和空外部表实际 V/E 均通过 |
| Q13 探测反例 | OFFSET、LIMIT、WHERE/HAVING/JOIN/CTE/UNION/DISTINCT/ORDER/窗口/函数/CAST/OUTFILE 实际对照和分类测试 | 原优化不能扩大原始形状 |
| Q14 字典 | dict_get/dict_get_many；BE 折叠开/关、折叠参数和混合表达式 V/E | 不扩展到 SET 等既定范围外通道 |
| Q15 缓存 | 业务缓存实际命中后 E 拒绝；元数据/窄式探测/LIMIT 0 各实际命中，E 继续允许 | Profile 以精确 queryId/SQL 对应；未清全局缓存掩盖路径 |
| Q16 旧缓存/缺分类 | 缺分类重新规划、schema 失效受控测试；Nereids 真命中见 Q15 | 旧 handleCacheStmt 禁止 fetch，分区 cache 入口关闭；直接回送子项原版不适用，非运行通过 |
| Q17 prepared 点查 | 实际同 handle 跨期拒绝；ExecuteCommand 短路复用和 schema 回退受控调用验证；prepared 内部写入对照 | prepared Group Commit 两模式 V/E 共八次写入、续期完整八行和清理通过；真实快分支观测与受控 spy 分开 |
| Q18 出队 | 实际 1 运行/1 等待排队后跨期拒绝并释放槽位；两类 coordinator 受控出队和执行锁等待验证；专组内部写入正确，实际排队超时/KILL 保留原错误、槽位归零且对象已清理 | BE 活跃任务遥测不可用，FE 队列/拒绝/清理有证据 |
| Q19 重试 | 实际产品两层重试循环受控测试，首次派发前/后、后续新执行、取消/超时/耗尽及清理 | 不是实际网络故障注入 |
| Q20 跨 FE | 原版 force_forward_all_queries 配置下完整入口→RPC→接收→Profile 链；E 新执行拒绝，配置还原 | 新 context 由源码+trace 推断；internal=true 注释不是一个受支持的内部用途 Hint |
| Q21 OUTFILE | 普通读取与窄式探测 OUTFILE 实际 V 成功/E 拒绝；拒绝后文件/哨兵不变 | 仅清理独占路径 |
| Q22 外部 INSERT | JDBC/Hive/Iceberg 内部源和外部源写出拒绝；VALUES/外部导入内部允许 | 独立源数据/外部事务及文件、续期内部行模型分别核验 |
| Q23 OVERWRITE | Hive/Iceberg 外部源 V/E、完整空计划允许；内部目标不误拦 | 内部源向外部 OVERWRITE 拒绝、外部 VALUES 允许；外部完整 bucket/事务 oracle 与续期内部三行核对通过 |
| Q24 CTAS | 内部 CTAS、TVF/外部源向内部允许；Hive/Iceberg 外部 CTAS 原版实际支持，V 成功/E 建表前拒绝 | 独立外部 tableExists 及续期内部行模型核验 |
| Q25 EXPORT 提交 | 本地与 S3 实际 V/E；delete_existing_files 的 V 删除/导出完成和 E 哨兵/文件不变；登记前守卫 spy | 不由 SHOW EXPORT 推断私有 task map 总数 |
| Q26 EXPORT 异步 | 真实调度队列跨期及取消清理 tests-10；已开始执行生命周期见 Q19 | 环境/时间/存储操作替身与真实调度明确区分 |
| Q27 新连接器计划 | HTTP GET/POST V 返回计划、E 真 HTTP 403 且无 opaque plan/tablet 参数；畸形 body 和权限错误对照 | 不执行旧 BE 计划撤权测试，不改变已接受边界 |
| Q28 写入/维护 | 内部 DML/事务/CTAS/OVERWRITE、外部导入、Stream/Broker Load/同步 Group Commit V/E及续期行模型；真实字典/MV/统计任务 | Routine Load 三行 V+三行 E、最终 offset=5、续期完整六行通过；prepared Group Commit 八行通过；新 SELECT 拒绝另有同连接 DML 证据 |

## 节点额度

M09–M12 的实际集群记录覆盖三运行 FE、离线 Observer/计算节点计数、真实 BE 离线/重启不重复占额、
恰好到限、超额批量 ADD 无部分登记、两客户端争一个名额仅一个成功、到期后继续使用已提交基础额度。
DECOMMISSION、失败 DROP 不释放；成功 DROP 后名额可复用，原副本/WAL/quorum 检查保留。

M12 实际未来证书从 2 BE 提升为 3 BE：到 not_before 后两次观察到查询权益已更新而基础额度仍旧，
ADD 仍拒绝；基础额度提交后允许第三节点、拒绝第四节点。这里是自然观察窗口，没有注入实际 journal 暂停。
注册持久化故障、中途批量失败、重复重放 DROP、同地址新身份及与证书提交交错由受控测试验证，
不冒称真实 BDB 故障压测；不新增整批注册事务保证。

## 失败保留、证据及清理

原始 FAIL 均保留：真实额度错误码被包装成 1105 的产品问题已修复并实测重验；
测试 Env 字段、Stream Load Expect 头、可选 BE 遥测、HTTP 无权限常量、Hive4 元数据 oracle 等
夹具问题各保存首次记录及纠正后的验证。原版 Flight 65535 与 Parquet reader 未关闭问题仍按用户确认保留，
不因本次 Flight 1024 或其他功能通过而改写。

可复核入口：

- [runtime-v1 审计](/data/project/massdb-sql/.build-records/license-p3-20260925/runtime-v1-audit.json)
- [额度检查点](/data/project/massdb-sql/.build-records/license-p3-20260925/runtime-v2-quota-checkpoint.json)
- [第二轮审计](/data/project/massdb-sql/.build-records/license-p3-20260925/runtime-v2-progress-audit.json)
- [补充审计](/data/project/massdb-sql/.build-records/license-p3-20260925/runtime-v2-additional-progress-audit.json)
- [第三轮审计](/data/project/massdb-sql/.build-records/license-p3-20260925/runtime-v2-third-window-audit.json)
- [实际重试循环测试](/data/project/massdb-sql/.build-records/license-p3-20260925/tests-9-evidence/summary.json)
- [第五轮审计](/data/project/massdb-sql/.build-records/license-p3-20260925/runtime-v2-fifth-window-audit.json)
- [Prepared Group Commit](/data/project/massdb-sql/.build-records/license-p3-20260925/group-commit-expiry/runtime-v2-seq5-v1/audit.json)
- [Routine Load](/data/project/massdb-sql/.build-records/license-p3-20260925/routine-runtime-v2/functional-audit.json)
- [实际 EXPORT 调度测试](/data/project/massdb-sql/.build-records/license-p3-20260925/tests-10-evidence/summary.json)
- [最终构建及 22 项定向测试](/data/project/massdb-sql/.build-records/license-p3-20260925/package-4-evidence/summary.json)
- [最终包实际 Q01/Q03 复验](/data/project/massdb-sql/.build-records/license-p3-20260925/final-runtime/runtime-v3-v2/completion.json)
- [32 组分层覆盖索引](/data/project/massdb-sql/.build-records/license-p3-20260925/p3-coverage-audit.md)
- [最终证据与清理汇总](/data/project/massdb-sql/.build-records/license-p3-20260925/p3-completion-audit.json)

runtime-v1 已完成自有 SQL 对象、账号、文件和服务清理；BE 优雅关闭超时后的 SIGKILL 如实记录。
runtime-v2 的所有自有 SQL 对象、账号、外部路径/服务和 FE/BE 已清理；BE 优雅关闭超时后的 SIGKILL 保留记录，
原基准生命周期不变。590 个日志/Profile 扫描条目（含 281 个解压成员）未命中证书、JWS 或签发私钥材料。
联合扫描仍保留 FAIL：三个已删除的测试账号口令出现在 CREATE USER 审计及控制台副本中。
[源码核查](/data/project/massdb-sql/.build-records/license-p3-20260925/create-user-audit-source-review.json)
确认该密码替换缺口已存在于原基线 `23e39e6`，不是 P2/P3 证书脱敏回归；未另跑原基线复现，
也未扩大本次范围修复一般用户管理。不把证书材料零命中改写成所有敏感字节扫描全绿。

最终小回归 `runtime-v3-v2` 已通过 Q03 无附带异常响应，以及 SQL 无 SELECT 权限和 ADMIN 身份对照，
自有数据库、过程、账号和客户端清理通过。首次 `runtime-v3-v1` 使用 MariaDB 驱动读取过程结果，
在有效态触发结果协议解析异常；该失败与清理保留。复验采用此前已验证的原协议客户端并为两种过程
各建独立连接，显式记录服务器未宣告 multi 能力而客户端请求 multi/multi-results；没有修改服务器协议，
也不宣称修复 MariaDB 驱动的过程结果兼容性。

runtime-v3 控制器真实退出码为 0，所有自有服务/keeper 生命周期已结束，原基准 FE/BE 身份保持不变。
FE 收到 SIGTERM 后退出，BE 在优雅停止超时后使用 SIGKILL；未省略该停止边界。
最终 12 个日志条目没有证书/JWS/私钥命中，本轮没有生成可解压 Profile 成员。
两次夹具使用的四个已删除测试账号口令仍在 CREATE USER 审计及控制台副本命中共八次，
联合扫描保持 FAIL，证书材料扫描与原版一般账号审计问题分别记录。

Q01–Q28 与 M09–M12 的约定功能缺口已收口；P0/P1/P2 已有验收继续保留。
页面 U01–U04、完整 A/A 与 A/B 性能矩阵及交付性能结论仍待 P2U/P4，不能由本次功能验收替代。
