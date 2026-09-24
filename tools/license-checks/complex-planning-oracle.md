<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP006/007 并发查询、事件驱动与独立核对

`complex_planning_oracle.py` 是无数据库、无网络副作用的结果核对模块。新增
`complex_planning_fixture.py` controller 与 `LicenseComplexPlanningFixture.java` 驱动连接原版 FE，
在同一 JVM 中记录并发查询和独立 ADMIN 会话的事件。早期已通过42项Python离线检查、精确JDK17.0.4+8编译及28场景Java无网络自检。
真实FE功能窗口已开始尝试，LP007 v3在预热阶段完成3条查询后因Profile状态oracle错误终止，尚未完成完整窗口。现有原版低频验证仍是
180 秒静止等待后的变更，不能提升为并发查询、完整 Profile 或正式性能矩阵通过。

模块绑定原冻结 SQL 的 SHA-256 `df4655191fb71a17d4a7c19baa84f7cf4cd350ea9ab44418baef885a9c545a37`
及 16 个固定的 64-ID 区间，从源数据 `grp=id%1024, v=id%100000` 逐 ID 重算 33 列结果。
它重建完整 16 UNION ALL、4 JOIN、32 SUM 的 SQL，再核对契约中的 SQL、摘要与期望值。
视图在五个位置使用，因此 `v+1` 后第 n 个 SUM 增加 `5120*n`；只检查行数或只改变一个视图引用均不充分。

结果输入要求完整 JDBC 列名、列类型、顺序及一行 33 个整数原始字符串。NULL、浮点转换、额外/缺失列、
重复别名和任何单列差异均拒绝。新 JDBC adapter 通过列元数据及原始 `getString` 按顺序归档，
Python 独立核对每条请求；其他 SQL helper 的行对象不能直接代替此格式。

事件与每个请求的时间必须由同一 adapter JVM 的单调时钟记录：

| 与 DDL 的关系 | 允许的完整结果 |
| --- | --- |
| 完整结果读取结束严格早于 DDL 开始 | 原视图结果 |
| 请求执行开始严格晚于成功提交确认 | 新视图结果 |
| 请求与 DDL 重叠或时间边界相等 | 完整原结果或完整新结果 |

所有分支都拒绝把两种模型按列混合。边界相等时，量化时钟不能证明先后顺序；模块不推断 FE 内部快照时间。
`nanoTime` 的任意原点可以为负，禁止混用墙钟、不同 JVM 的 `nanoTime` 或不同机器的值。
仅提供这些字段不证明真实请求发生。驱动源码已归档执行意图和完整结果回执、实际 180 秒调度偏差、
同 JVM 身份、会话/query ID、SHOW CREATE VIEW 与恢复结果；完整事件窗口的实际运行证据仍待生成。

Profile 核对要求唯一的 Summary/Execution Summary、唯一且匹配的 query ID、成功状态、Nereids 和
缓存标志，以及完整 SQL。冷查询需有实际解析/计划/分析/重写/翻译耗时；拼接两份 Profile、重复冲突字段、
错误 query ID 或任意伪造时长文本均拒绝。保留原 `TIME_MS` 字符串，不推算未记录的时间。

成功状态精确允许 `OK` 和 `EOF`，核对结果中的 `task_state` 保留原值。
[StmtExecutor的Summary构建](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:317)
在执行结束后，有coordinator时使用其状态，否则使用`QueryState`。
[Nereids缓存路径](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:1240)
发送完整缓存结果后调用[setEof](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/StmtExecutor.java:1171)，
[QueryState](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/qe/QueryState.java:84)记录并输出枚举`EOF`；
[Profile健康判断](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/profile/Profile.java:796)
也明确识别`OK`和`EOF`。`ERR`、`ERROR`、`RUNNING`、`NOOP`、`UNKNOWN`及重复/错位状态仍拒绝。
合法状态不替代query ID、完整SQL、缓存标志、规划字段或独立33列结果核对。

原版v3已取得[冷查询OK Profile](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp007-concurrent-actual-v3/profile-f92e9f7aa54148d6-9f155cda2e1e20eb-0.txt)
及[缓存命中EOF Profile](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp007-concurrent-actual-v3/profile-5efb83866708436b-943487373871d818-0.txt)。
原oracle只接受`OK`导致后者被误拒绝。本次离线正反核对以原始文件SHA、同query ID完整结果和当前源码摘要绑定，
见[验证回执](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/complex-profile-eof-v1/report.json)。
v3原FAIL及`profile_collector_stop`错误保持不变，不把离线修复或3条预热查询提升为完整功能窗口通过。

原版 `SummaryProfile` 的 Optimize 耗时依赖 pre-MV rewrite 的时间戳；没有该时间戳时，即使真实冷规划
完成也可能显示 `N/A`。已存在的 LP009 实际 Profile 显示这一情况。本模块允许该项不可用并明确报告
`all_stage_timings_available=false`，不会补零或称所有规划阶段耗时完整。缓存结果允许规划耗时不可用。

CLI 只在新的 checkout `.build-records` 子目录输出核对定义，不执行 SQL：

```bash
python3 -B tools/license-checks/complex_planning_oracle.py \
  --output .build-records/license-complex-oracle-definition
```

## 显式运行边界

controller 默认 `--mode plan`，只生成计划。需要新的 checkout `.build-records` 输出目录、原版隔离
集群记录、原 FE/BE SHA256 和显式原版到达率；计划冻结两种查询模式、两种连接模式、1/8/32 并发中的
一个组合，不能混合旧工具摘要。`--mode probe --plan /absolute/path/to/plan.json` 才会连接 FE。
必须在该 checkout 自有网络 namespace 内运行，实际 JDK 为声明的 17.0.4 构建，原版服务及 supervisor
PID/start ticks/executable/command digest 均持续复核；检测到已运行的正式测量则拒绝 probe。

源码实现包含以下边界；离线检查已执行，真实FE边界尚未完整验证：

- 到达序列以种子 20260922 预生成完整开环泊松序列；默认预热180秒、计时600秒，功能诊断允许
  0–180秒预热和240–600秒计时，最多20,000次请求。窗口结束不再开始新请求，120秒 drain
  只收已开始的请求；漏掉计划请求则失败，不取成功子集。
- 每条请求保留到达、排队、连接/初始化/prepare、完整执行和取数、query ID 查询、EXPLAIN 及关闭成本。
  复用连接的初始化另记 `worker-setup-*`。`SELECT last_query_id()` 紧接目标查询并使用同一连接；
  Profile 获取和 EXPLAIN 都有观察开销，不做基线相减或性能达标声明。
- LP006关闭 SQL cache；LP007在计时开始后180秒由独立 ADMIN 会话提交固定 `ALTER VIEW ... v+1`。
  未知提交、变更失败或恢复失败均不能通过。Profile 覆盖原冷/热及变更后冷/热阶段，并保留真实
  `PhysicalSqlCache` EXPLAIN；无法取得某一阶段时保留失败。
- 首条、固定周期、EXPLAIN、提交后前四条及事件重叠请求采样。事件重叠最多64条，超限终止并失败，
  不跳过多余请求。单份 Profile 16MiB、总量256MiB、最多512份，原始每次 HTTP 响应独立归档；
  查询 ID 和完整 SQL 必须一致，HTTP 认证 session 需要确认登出。
- 开始及结束完整核对百万行源表模型与定义。固定视图必须原先不存在，只有 CREATE 成功 ACK 才取得
  所有权；不使用 `CREATE OR REPLACE` 接管已有视图。未知 CREATE 结果保留清理不完整，不能按名称
  删除。正常结束确认恢复原定义，然后删除本次拥有的视图。
- 全生命周期资源观察覆盖编译、SQL helper、驱动、Profile、独立结果核对及清理：controller 512MiB、
  单 helper 768MiB、辅助进程合计2048MiB采样预算；FE/BE单独记录。RSS/高水位仍可能遗漏短命进程，
  namespace网络计数不按进程归因。输出每流2MiB、资源证据64MiB，所有上限失败都保留为失败。
- Java清理预算60秒，Python另有180秒清理预算及进程终止宽限；分步骤执行，不让回执写入失败跳过
  后续清理。线程、连接句柄、Profile collector、输出流EOF、子进程及自有视图均须确认完成。

完整真实并发窗口、所有连接/并发/速率矩阵、完整规定时长、A/A 精度及候选 B 比较仍待执行。
功能窗口即便通过也只记 `FUNCTIONAL_WINDOW_PASS`；`LP006_complete`、`LP007_complete`、
`release_performance_pass` 和 `runtime_license_enforcement_proven` 保持 false。

2026-09-24 实际离线验证：18项独立oracle、24项controller检查通过；controller测试最初有4项
因缺少测试模块的`copy`导入报错，修复后完整24项通过，原始失败日志保留。
精确Temurin17.0.4+8编译及Java自检28场景/43断言通过，未连接数据库或执行DDL。
见[Python重测](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/root-retest/receipt.json)
及[Java自检](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/java-helpers/complex-selfcheck/self-check.json)。
