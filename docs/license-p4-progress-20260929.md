<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# P4 性能与自用交付进展

当前状态：**P4 已完成约定的快速验收、自用包交付验证及最终清理。**
六项 A/B 共 55080 次计时请求正确；自然到期/续期、写入与额度、页面、独立包启动/重启和数据保持均已有实际回执。
初次 CPU 增幅及温热复测结果、夹具失败和显式恢复见[P4 验收记录](license-p4-acceptance-20260929.md)，不据短测声明零性能回退。
2026-09-29 用户明确要求“完全实现 P4，不需要长时间测试，需要快速验收”。
以[执行计划第 6、7 节](license-certificate-execution-plan-20260922.md)和
[P0 契约第 5 节开头](license-p0-contract-20260922.md)的最新范围为准。
P2/P3/P2U 的已有分层功能证据按包/class/源码和页面资源绑定复用；不能把它们改称短窗或长期性能通过。

## 当前快速验收范围

| 原组 | 复用证据与本次必须补齐的最小闭环 |
| --- | --- |
| G1 | 原版真实短路/prepared/缓存/元数据路径已核对；四类六项各补 A/B 一窗（每侧 10 秒预热、30 秒计时）：text/reuse/c1、prepared/reuse/c16、text/per_request/c1、prepared/per_request/c1、metadata/reuse/c16、cache/reuse/c1；复用点查及元数据 250rps，其余 50rps，种子 20260922，逐值核对。HTTP/Flight 协议及缓存/同 handle 跨期以 P3 证据加候选抽查验证。 |
| G2 | 复用 P3 复杂/视图/MV/六类 TVF 等功能和本轮原版 33 列、分组、catalog/S3、Flight 1024/8192 全结果实证；在候选五出口抽查中保留普通/外部读取与新 Flight 查询。不再复制全并发长窗。 |
| G3 | 复用 P3 拒绝副作用边界和原版百万行 scanner、外部写入/完整 EXPORT/OUTFILE 输出；候选实际 V/E/续期覆盖新计划 403、外部 INSERT SELECT、EXPORT、OUTFILE，核独占目标并清理。 |
| G4 | 复用 P3 跨期各入库/维护路径及本轮原版 Stream Load/DML 真结果；候选到期期间内部 INSERT SELECT/UPDATE/DELETE、Stream Load 与元数据继续可用，续期核提交后的完整数据。 |
| G5 | 复用 P2/P3 的 pending、排队、切主/恢复、时钟修复与回收上限分层证据；本次自然到期/续期、节点用量和超额拒绝、成功 DROP 释放额度、最终包重启恢复。 |
| G6 | 复用 P2/P3 限流/队列/坏证/重复导入/脱敏与允许业务证据；候选抽查坏证保旧、无权管理拒绝及到期读拒绝时写入/元数据可用。原 1/8/32 与 100/1000/10000 长压测不再前置。 |
| G7 | 复用 P2U 精确候选 JAR/135 件资源的 40 个浏览器功能组与真实双 FE；最终候选实际查看详情、预检确认导入、回执和到期/续期展示，核其他 Tab 无请求和权限。原页面全并发矩阵不再前置。 |
| 自用交付 | 展开依赖为独立包，公钥显式安装、私钥及测试数据不入包；在解包目录启动并按真实部署 ID 导入，重启后身份/许可/数据保持。最终记录包和 BE 摘要、文档、版权检查及所属进程/对象清理。 |

候选 FE/common 当前复用 P2U package3：`e5e05b1489d0e007a3d5aa097db15d99500c578e4241fdcb1c4c1ad197b8f4c2` /
`29a9fa69e68b0b88a44f3495c1827dbb61ffc7551beee17228c29ac7f43bd9fb`。
既有 P3 到该包的产品 class 差异只涉及构建版本常量；已有包层级及受控/真实区别继续保留。
若后续产品字节改变，则核对影响并补定向验证，不能自动沿用旧通过。

原容量 R、30%/60%/85% 速率、5 对 A/A 加 5 对 A/B、每窗 10000 次、长预热/窗口及
1% CPU/吞吐、2% 延迟置信门槛自本次范围调整起不再是完成条件；不再继续长期容量适配。
短窗仍保存实际结果、端到端排队/错误、CPU/RSS、配置和退出清理，只能给出本环境有限成本结论。
不新增 BE、协议或 mTLS 改造，不要求麒麟/openEuler 和跨架构矩阵。

下文按时间保留调整前的工具、窗口及结果原文，其中“正式仍待”“门槛不变”等描述是当时状态。
历史 FAIL/INCONCLUSIVE/NOT_QUALIFIED 原样保留；目标调整不将旧窗口升级为原长测 PASS。

## 已执行的本轮原版预检

原版 FE/BE 及监督进程的 PID、启动代次、命令、隔离网络和包身份与已有记录一致；没有重启服务。
使用精确 Temurin JDK 17.0.4+8，FE/BE 保持 CPU 6–9、原 FE 2 GiB 堆与 BE 4 GiB 配置。
本机为共享资源环境，尚未证明满足 1%/2% 检测精度。

- 原 FE JAR：`ea66013d3ffc8c7baff96c0538aa12251217c7f06f5577e22eefc8cdeb3238db`。
- 原 BE：`a9480210dbf70f6d00b3aea5ea8bb039e135d45ab5e1e4697fdef1ea03a36163`。
- `license_perf.point_rows` 完整核对 1,000,000 行、全部 ID 唯一、范围 0–999999，
  `SUM(v)=49999500000`，grp/v/payload 公式不匹配行数为 0。
- 实际 EXPLAIN 确认 `SHORT-CIRCUIT`。

原始预检：`.build-records/license-p4-20260929/baseline-health-v1/report.json`。
这是路径和数据前提通过，不是正式性能通过。

## 第一轮 A-only 短窗诊断

预声明 500/1000/2000 请求/秒，单连接文本点查、复用连接、固定种子和百万键均匀分布；
每档 10 秒预热、两个 30 秒窗口。使用提交 `23f065163e434090f729ddd387474f5b740f0835`
中的冻结 runner/helper 副本；本轮并行开发的新工具没有混入运行输入。
预声明诊断 SLO 为端到端 P99 ≤20ms、drain ≤1s；未根据结果放宽。

| 请求/秒 | 两窗成功数合计 | 两窗端到端 P99（ms） | 两窗 drain（s） | 诊断 SLO |
| --- | ---: | --- | --- | --- |
| 500 | 30,550 | 30.21 / 6.89 | 0 / 0 | 未通过 |
| 1000 | 60,474 | 62.57 / 15.89 | 0.00458 / 0.00028 | 未通过 |
| 2000 | 120,368 | 13,586.54 / 19,130.27 | 13.87 / 19.31 | 未通过 |

六窗共 211,392 次逐值校验成功，零 SQL 错误、零缺失请求；监督进程实际 wait 返回 0。
独立重读所有逐请求 CSV、到达/键二进制、JVM CPU 边界和清理回执，复算结果与原报告一致。
本轮客户端已退出，原服务启动代次未变。
`timeout_seconds=10` 是实际 JDBC SQL/socket 超时，不是 scheduled 到完成的总截止；
排队包含在端到端延迟中，因此 SQL 成功数不表示 SLO 合格。

原始计划、日志和失败指标保存在 `.build-records/license-p4-20260929/a-only-point-pilot-v1*`；
独立复算在 `a-only-point-pilot-v1/raw-audit.json`。
本轮没有完整资源时序采样，窗口和 pair 数不足；不能用于冻结正式容量、A/A 噪声或 A/B 等效性。
授权版本 B 尚未进行本轮性能测量。

## 当前工具和剩余工作

查询 runner 已补齐当前契约绑定、静态 SQL 完整列/值 oracle、真实 JDBC 句柄复用证据和
SQL/连接超时边界说明。JDK 17.0.4 上 80 项离线测试通过；首次 CSV 字段断言和短预热无到达的
测试夹具失败分别保留，没有改写历史记录。整数速率改为支持精确小数后，三个既有种子/速率序列逐字节一致。

新 runner 已在原版 A 完成 8 组真实 smoke：文本/预编译点查各含 reuse/per_request，
元数据两种连接方式，以及 16 并发的 prepared 和元数据。共 16 个短窗、3,232 次计时查询，
完整结果、实际 JDBC 类/句柄次数和原始回执核对通过，客户端真实 exit 0。
服务端预编译实际使用 `org.mariadb.jdbc.ServerPreparedStatement`；这不单独证明 FE 内部快方法分支。
证据：`.build-records/license-p4-20260929/current-runner-smoke-v1/completion.json`。

随后独立执行计时外 JFR 诊断：同一 prepared 句柄完成 1,539 次预热和 6,109 次计时执行，
结果与原始回执全部通过。实际采到 129 份同时含
`PointQueryExecutor.directExecuteShortCircuitQuery` 和 `ExecuteCommand.run` 的 FE 栈，
证明本测试范围内实际进入快方法；不声称逐请求都取得分支样本。
`JFR.stop` 返回 0，随后 `JFR.check` 确认无活动录制，服务启动代次未变。
该次采样有诊断开销，其时延/CPU 不进入正式性能结论。
证据：`.build-records/license-p4-20260929/runner/prepared-jfr/actual-v1/completion.json`。

A-only 冻结/配对 A/B 统计层 38 项、JDBC 证据转换层 14 项离线测试通过，修复了原始文件跨阶段复用、符号/硬链接重复、
冻结后改顺序、错误时间分母及容量原始证据未绑定的问题；这些是工具反例，不是实际性能结果。
页面驱动 12 项离线测试通过，真实页面并发窗口尚未开始。外部调度、跨进程时间映射、
正式预热生命周期回执仍在接入。当前写入/元数据背景驱动完成 58 项离线测试、
JDK 17.0.4 编译及三组 Java/Python 到达序列逐值核对；该离线交付时尚未运行实际背景窗口。
工具离线测试与数据库窗口分开记录，工具通过不将 G1–G7 自动改为通过。

随后单独完成当前 allowed-business 背景真实短窗：12 秒、总 20rps、8 个写入与 8 个元数据复用连接。
238 次计时操作全部成功，含 119 次完整元数据结果和 119 批写入；每个 worker 均有实际完成操作。
独立核对全部 11900 行目标值、每批原始 ACK 和前后百万行源模型，临时表删除确认。
helper 实际 exit 0、observer 按计划 exit 143，root session 97691 实际 wait 返回 0；
独立复扫两进程组无残留，原 FE/BE/supervisor 启动代次与执行源码摘要未变。
证据：`current-background/real-smoke-v1/results-v1/completion.json`、`root-terminal-recheck.json`。
该窗仅验证背景本身，没有状态事件、管理请求或页面；资源记录以控制器 release 到实际 quiescence
作因果包围，不声称已有精确 Java/Python 时钟握手。正式背景容量、分流样本、时间映射与 A/A、A/B 仍须完成。
控制器首次纯文件校验因复用的 DML preflight 要求另一驱动依赖而拒绝，未触发 SQL；
修正其文件校验输入后重跑，实际背景依赖仍由原 FE 包独立冻结，旧控制器副本保留。

随后为该背景工具接入可选的 JVM/控制器时钟握手、窗口外真实连接复用回执及
独立 G5/G6/G7 适配器。旧默认行为和逐请求计时计算保持不变；实际安装目录、
服务代次、状态切换前后屏障、各业务流样本数由适配器核对。
新增离线检查在修正包内 JAR 路径核验后增至 22 项，精确 JDK 17.0.4 编译及五个无网络 JVM 正反例完成，
root 应用最小 Java 补丁后重新运行新旧共 79 项相关检查，实际 exit 0。
600 秒/40rps 的离线反例确认 Python 与 Java 排程可差 1ns，因此正式输入
绑定预先生成的真实 Java 到达文件摘要，Python 仅独立逐项参考，不混用两者摘要。
证据：`current-background/p4-adapter-v1/README.md`、`root-application.json`、
`root-applied-regression.json`；旧 238 操作记录不升级。

新的带时钟握手背景短窗随后实际完成：12 秒、总 20rps，119 次元数据操作和
119 批写入全部成功；11,900 行目标数据、前后百万行源模型、16 条真实复用连接及
两次实际原版状态屏障通过独立复核。JVM/控制器时钟映射不确定度约 51.15ms，
处于预声明 150ms 界限内；同 JVM 请求延迟不依赖跨进程偏移估计。
root session 65158 实际 wait 返回 0，helper exit 0、observer exit 143；
纯读 normalize 的实际 exit 0，重算结果与原 audit 完全相同。
独立进程组复核无残留，原 FE/BE/supervisor 和两外部服务启动代次未变。
证据：`current-background/clocked-real-smoke-v1/results-v1/completion.json`、
`root-terminal-recheck.json` 和上层 `recheck-v1.json`。
本轮只验证业务背景与时间映射，没有 B、状态事件、管理或页面性能通过结论。

当前产品路径的源码复查确认：有效态守卫不逐次验签、解析证书、枚举成员、写日志或发许可 RPC，
但仍读取时钟、快照及少量标量；正常规划也会保留来源事实并生成分类，空结果证明有结构遍历。
因此不能将“有效态提前返回”解释为整条查询链没有新增工作。
规划成本、排队后的再次检查、时钟原子操作和管理后台成本仍须由实际对照测量。
只读复查记录：`.build-records/license-p4-20260929/static-path-review-v1.json`。

完整时长的下一轮 A-only 诊断已结束：750/1000/1250 请求/秒、单连接文本点查，
每窗 120 秒预热和 300 秒计时，各一对；保持 P99≤20ms/drain≤1s，每 5 秒采集已有资源指标。
计划位于 `.build-records/license-p4-20260929/a-only-long-pilot-v1-plan.json`，
运行输出为 `a-only-long-pilot-v1/`，独立复算为其中的 `raw-audit.json`。
同期允许其他 CPU 上离线开发/测试，因此这轮仍只选校准输入，不能证明正式 A/A 精度；
正式精度窗口前须停止编译与测试干扰。首次在宿主 namespace 生成输入被安全检查拒绝，
未执行 SQL，改在现有私有 namespace 预检后通过；原失败单列保留。

| 请求/秒 | 两窗成功数合计 | 两窗端到端 P99（ms） | 诊断 SLO |
| --- | ---: | --- | --- |
| 750 | 450,676 | 6.5765 / 6.4625 | 满足 |
| 1000 | 601,212 | 7.7824 / 10.6886 | 满足 |
| 1250 | 751,386 | 17.2463 / 23.4488 | 未通过：第二窗超过 20ms |

共 1,803,274 次成功查询，原始请求、到达序列、结果和 CPU 边界复算通过；
508 次资源采样无采样错误，覆盖实际客户端启动至退出。
客户端实际 wait 返回 0、无残留进程，原版服务启动代次不变。
观察器在客户端退出后由控制器按计划 SIGTERM 结束，原始状态 `INTERRUPTED`/143 保留；
不冒称其执行完预设最长 5,400 秒。每档仅一对，未证明 1% 容量区间或 A/A 精度。
执行过的源码字节保存于 `a-only-long-pilot-v1/executed-source/`。

该轮终态与复算确认后，才应用新的 JDBC 预热/退出/时间映射补丁。
候选补丁的 70 项离线检查及应用后的 80 项原 runner 回归检查均通过；
新的生命周期已完成三组真实短窗：文本/reuse/c1、prepared/reuse/c16、元数据/per_request/c1，
每组 202 次，共 606 次成功请求。原始回执独立转换通过，JVM 实际 wait 返回 0、无残留进程，
实际跨进程时间映射不确定度约 5.45–5.51ms，处于预声明的 50ms 上限内。
三组均明确 `formal_shape_met=false`；不将工具测试数量换算为性能通过比例。
证据：`.build-records/license-p4-20260929/contract/real-lifecycle-smoke-v1/run-01/completion.json`。

HTTP Query keep-alive 已完成实际短窗工具验证：c1/50rps/2秒预热+4秒计时共 202 次成功，
c16/5rps/4秒预热+12秒计时共 68 次成功；逐值 oracle、请求总数、原始回执与客户端退出核对通过。
首次输入错误地预期 `VARCHAR`，而实际原 FE 元数据为 `CHAR`，工具拒绝该窗口，失败记录保留。
随后 c16/50rps 窗口发生 4 次预热和 2 次计时业务错误：原版 HTTP SQL 提交线程池仅有 2 个工作线程，
实际日志确认拒绝请求。低速重跑不覆盖该容量观察，也不改变服务线程配置。
证据分别为 `http-real-smoke-v1/`、`http-real-smoke-v2/` 和 `http-real-smoke-v3/`，
均位于 `.build-records/license-p4-20260929/`。
这些短窗尚无正式容量、完整资源时序或独立配对证据，不能判定 HTTP 性能达标。

SQL 缓存计时外预检也已完成：同一真实 JDBC 会话的两次百万行 `SUM(v)` 均为 49999500000，
第二次实际 Profile 为 `Is Cached: Yes`，物理计划含 `PhysicalSqlCache` 和原 BE 地址。
仅诊断会话开启 Profile，连接结束后不保留会话设置；服务 PID/启动代次保持一致。
证据：`.build-records/license-p4-20260929/sql-cache-path-v1/completion.json`。
这证明该 SQL 的实际缓存路径，不能代替正式窗口内的性能结论。

随后静态 JDBC 六个短窗完成：SQL 缓存的 c1/c16 × reuse/per_request 四档，
普通百万行分组的 c1/c8 两档。每窗 4 秒预热、6 秒计时、39 次成功，共 234 次；
分组结果逐项核对全部 1,024 组的 grp/SUM/COUNT，CPU/时钟边界及窗口顺序复算通过。
root 实际 wait 返回 0、所有 JVM 已退出；六档均保持 `formal_shape_met=false`。
证据：`.build-records/license-p4-20260929/static-jdbc-smoke-v1/run-01/completion.json`。

G4 三类 DML 单窗工具完成 18 项离线检查、JDK 17.0.4 编译与五组到达序列交叉核对；
Stream Load 当前模式完成旧、新共 75 项离线检查，保留原 transport、完整入库 oracle 和清理。
三类 DML 每操作使用独立的 100 行范围，Stream Load 使用一个带偏移和摘要的输入文件；
有效/过期切换由外部控制器在实际窗口边界执行，工具不会自行改证书或服务器时钟。
真实写入短窗正在接入，离线测试和模拟单窗不计入 G4 通过数。
首个实际 DML 尝试在准备阶段因工具使用 `SHOW DATA FROM license_perf` 被原版拒绝：
该语法将名称解析为表；选定数据库后使用 `SHOW DATA` 才返回数据库配额。
实际正确语法和四列配额结果已另行核对，失败记录及执行源码保存在
`dml/real-smoke-v1/results/`，正确语法预检在 `dml/quota-preflight-v1/`。
此次尚未创建目标、未进入计时或写入阶段；helper 实际退出且清理确认，不计入性能通过。

Stream Load 随后完成四个真实短窗：每批 1000/10000 行 × c1/c8，每窗 8 秒预热、10 秒计时。
各档 11 批预热、22 批计时全部成功；计时共 88 批、484000 行，逐列公式、完整 ID 集合、
原始 FE307/BE200 回执、唯一事务及临时数据库清理均通过独立复算。
四个 probe 实际 exit 0，四个观察器按预定 SIGTERM 实际 exit 143，原始采样覆盖预热至最终完成；
root 最终 wait 返回 0，无残留子进程。只有一个 51.2MB 输入文件，没有批次全量副本。
证据：`.build-records/license-p4-20260929/g4-stream/real-smoke-v1/actual-v1/completion.json`。
四档均为 `DIAGNOSTIC_VERIFIED_NOT_QUALIFIED`，没有替代正式 10000 批样本、A/A、A/B 或过期态窗口。

DML 配额语法修正后，第二次首档 INSERT SELECT 实际完成 11 次预热、22 次计时，
所有 3300 行目标模型及前后百万行源模型正确，helper/observer 和目标清理均完成。
随后汇总在时钟约束检查处拒绝：桥接的保守上界超出已记录的进程退出时间约 16.9ms。
原始 `RAW_WINDOW_COMPLETE` 与整体失败分开保留于 `dml/real-smoke-v1/results-v2/`；
已使用同进程实际 parent-wait 的因果约束与原桥区间求交，保留原映射、退出约束和收紧后的区间；
原时钟不确定度上限仍先检查，矛盾区间和退出/清理倒序均拒绝，不修改原始时间、请求延迟或 CPU 数据，
也不覆盖第二次失败结论。此修复及原回归共 20 项离线检查通过。

第三次真实 DML 运行完成全部六档：INSERT SELECT/UPDATE/DELETE × c1/c8，
每档 2 秒预热、4 秒计时，11 次预热与 22 次计时全部成功；计时共 132 次、13200 行变更。
各档前后百万行源模型、完整目标数据、原始 ACK、独立 ID 范围和临时表清理均通过，
六个 helper 实际 exit 0、六个观察器按计划 exit 143，root 最终 wait 返回 0，无残留进程。
证据：`.build-records/license-p4-20260929/dml/real-smoke-v1/results-v3/completion.json`，
执行过的源码字节另存该目录的 `executed-source/`。
六档明确为 `DIAGNOSTIC_VERIFIED_NOT_QUALIFIED`；B/过期态、正式容量及独立 A/A、A/B 尚未执行。

容量 CLI 补齐有限正小数速率，允许低速业务以小于 1% 的间隔选档；整数输入保留原目录命名。
35 项相关离线检查通过，样本量、SLO、独立 pair 数及已有判定门槛没有变化。
证据：`.build-records/license-p4-20260929/capacity-fractional-cli-receipt.json`。

Flight 单窗工具已完成 36 项离线检查、精确 JDK 17.0.4 编译及 9 个无网络 JVM 检查，
覆盖原 fixture 接口、实际进程信息和八组小到达计划；Java/Python 序列逐字节一致。
保留原完整百万行 oracle、每操作新 FE ticket、复用 channel 和原 65535 失败记录；
原 Flight fixture 未修改。该工具离线交付时尚无真实窗口。
证据：`.build-records/license-p4-20260929/contract/flight-v1/completion.json`。

随后 Flight 完成原版四个真实诊断窗口：batch 1024/8192 × c1/c8，
各窗 8 秒预热、12 秒计时、每秒 1 次完整查询；每窗 9 次预热和 13 次计时均成功。
四窗共 88 次完整百万行读取，其中计时 52 次，所有 worker 在两个阶段均有完整查询。
每次重新取得 FE ticket，全部 ID/payload、实际批次、channel 复用和关闭均通过原始记录复算。
四个 helper 实际 exit 0，四个观察器按计划 exit 143，root 的 session 45438 实际 wait 返回 0；
另行核对各进程组为空。证据：`flight/real-smoke-v1/results-v1/completion.json` 和
`root-terminal-recheck.json`，位于同一 P4 构建记录目录。
四档均为 `DIAGNOSTIC_VERIFIED_NOT_QUALIFIED`，没有替代完整 180/600 秒或 10000 次操作。

G3 scanner 新工具完成 62 项离线检查、精确 JDK 17.0.4 编译和 10 个无网络 JVM 检查，
旧 Java 只提取共享扫描核心并改为每 worker 独立句柄登记；旧 Python 入口和 BE 未修改。
随后四档 batch 1024/8192 × c1/c8 实际运行，每窗 16 秒预热、24 秒计时、每秒 0.5 次完整查询，
各 9 次预热和 13 次计时成功，共 88 次完整百万行读取，其中计时 52 次。
每次实际新 POST 到 FE，读取返回计划的全部 16 个 tablet，完整 ID/payload 和所有 close ACK 均已核对。
四个 helper exit 0、四个 observer 按计划 exit 143；root session 46006 实际 wait 返回 0，
进程组复核无残留。证据：`g3-scanner/real-smoke-v1/results-v1/completion.json` 和
`root-terminal-recheck.json`；私有原始计划文件仅限 0600 的隔离记录，不能随公共报告发布。
本轮同样只是诊断；没有把 tablet、Arrow batch 或返回行数当成业务操作样本。

G2 复杂 SQL 单窗工具完成 62 项离线检查（含既有回归、精确 JDK 编译和无网 JDBC proxy），
另有 8 项独立只读反例复核通过。
保留 33 列完整模型、冷热连接方式和 t=180 秒 view 变更，补齐 FE/BE 角色、
业务回执与真实 launch/boot/clock、预检 reader/catalog/database/session 的直接关联。
证据：`complex/offline-v1/handoff.json`、`contract/complex-readonly-review-v1.json`。

首轮实际冷规划 c1 完成 16 次预热和 26 次计时查询，JVM exit 0，源模型和视图清理正确，
但控制器在完成标记刚写入、JVM 随即退出的交界处误判失败；该次整体结果仍保留为失败。
证据：`complex/real-smoke-v1/results-v1/completion.json`，root session 5734 实际 wait 返回 1。
仅在新的 v2 控制器中修正等待逻辑：观察到进程退出后重新检查完成标记，随后仍要求完整原始回执、
真实退出与清理核对。缺失标记、超时和资源守卫失败仍拒绝；10 项离线反例及纯输入校验通过。
旧控制器和失败原始记录未修改。修复交付见 `complex/real-smoke-v2/handoff.json`。

v2 随后完成冷/热规划 × c1/c8 四个真实窗口，各预热 8 秒，冷计时 12 秒、热计时 200 秒，均为 2rps。
每档 16 次预热；冷档各 26 次、热档各 408 次计时成功，共 64 次预热和 868 次计时查询。
33 列完整结果通过独立 oracle；两个热窗均在第 180 秒实际修改视图，
每个 worker 在 DDL 前后分别取得旧、新完整模型，视图恢复和最终源模型检查通过。
四个 helper 实际 exit 0、四个 observer 按计划 exit 143，root session 49533 实际 wait 返回 0；
原服务启动代次和执行源码摘要未变，独立重扫所有 helper/observer 进程组无残留。
证据：`complex/real-smoke-v2/results-v2/completion.json`、`root-terminal-recheck.json`。
四档仍为 `DIAGNOSTIC_VERIFIED_NOT_QUALIFIED`，不代替正式样本数、容量、A/A 或 A/B。

低速完整读取达到每窗 10000 次操作可能超过观察器原 4 小时上限，已增加显式长窗选项，
默认时长及已有采样指标不变。长窗最大 102000 秒，调用方必须声明样本数、原始日志字节和磁盘余量上限；
资源不足时明确失败，不截断后报告通过。原回归和长窗边界共 63 项离线检查实际 exit 0；
长时间推演使用模拟时钟，不当作真实长窗记录。证据：`contract/long-observer-v1/completion.json`。

Flight/scanner 的原版 A 容量调度器已接通实际单窗接口和观察器生命周期，完成 24 项离线检查；
另用既有已编译 JVM 的纯 plan 模式核对 600/21600/86400 秒到达计划，六段 Java/Python 序列摘要完全一致。
三个 JVM 均实际 exit 0，没有发起数据查询；证据：`contract/protocol-capacity-v1/completion-v1.json`。
调度器修正客户端采样覆盖与间隔、取消信号传递、派生 SLO 重建、实际窗口绑定完整冻结摘要等问题。
短 pilot 可用诊断窗口，但只能用于调度接入与后续选档；正式 confirm 仍要求完整时长、每窗至少 10000 次
成功查询、每档至少 5 对和原 1% 容量括区，独立 A/A、A/B 精度另验。
该入口最初仅覆盖 Flight/scanner；外部读取接入进展见下文，其他协议仍需接入。

随后通过该调度器实际运行 Flight batch1024/c1 的两档短 pilot：0.5/1rps，各 1 对独立窗口，
每窗 16 秒预热、24 秒计时，预声明诊断 P99≤20秒、drain≤30秒。四窗共 54 次预热和 78 次计时，
132 次完整百万行读取全部成功；两档均处于所声明的诊断 SLO 内，没有找到容量上界。
root session 31569 实际 wait 返回 0，状态 `PILOT_COMPLETE_NOT_QUALIFIED`。
独立纯读 verify 再核对冻结输入、四窗原始记录、资源区间和独立性，通过诊断复算；
其 session 56254 实际返回 2，原因是该命令对未确认正式容量的 pilot 固定保留非资格退出码，
不是将一次失败重标为通过。四个 helper exit 0、四个 observer exit 143，独立进程组复核无残留。
全部冻结摘要、原版及外部服务启动代次保持不变，实际执行的 23 份源码另行归档。
证据：`contract/protocol-capacity-flight-pilot-v1/results-v1/report.json`、
`results-v1/root-terminal-recheck.json` 和同目录上层的 `recheck-v1.json`。
该轮没有正式容量 R、30%/60%/85% 速率或 A/A 精度结论，后续正式确认要求不变。

同一容量调度器随后完成 scanner batch1024/c1 两档短 pilot：0.5/1rps，各 1 对窗口，
每窗 16 秒预热、24 秒计时，预声明诊断 SLO 与上述 Flight 相同。
四窗共 54 次预热、78 次计时，132 次完整百万行操作全部成功；每次重新请求 FE 计划，
并完成 BE scanner 的完整读取和关闭。两档均处于诊断 SLO 内，仍未找到容量上界。
root session 55481 实际 wait 返回 0；纯读 verify session 54880 返回 2，
二者均为 `PILOT_COMPLETE_NOT_QUALIFIED`，独立复算没有错误。
四个 helper exit 0、四个 observer exit 143，root 独立重扫进程组无残留，
原版及外部服务启动代次保持不变，13 份实际执行源码已归档。
证据：`contract/protocol-capacity-scanner-pilot-v1/results-v1/report.json`、
`results-v1/root-terminal-recheck.json` 和上层 `recheck-v1.json`。
该短轮只验证容量调度和真实协议证据链，不产生正式 R 或性能通过结论。

容量调度器已进一步接入既有 catalog/S3 单窗驱动，复用同一执行、观测和复算循环。
每档在执行前绑定原 Java `--plan` 生成的真实到达文件及实际 wait 回执，
Python 只作允许 1ns 数值差异的独立参考；执行窗口须与预先声明的真实文件逐字匹配。
现有客户端采样增加外部 PG/MinIO 的整个 cgroup 内存、CPU、OOM 及完整时段核验。
37 项离线检查包含原 Flight/scanner 24 项及新增 13 项；root 已审阅应用相同源码。
证据：`contract/external-read-capacity-staged-v1/completion-v1.json`、`root-application.json`。
此处仅证明工具接线；真实 external-read 容量 pilot 与正式 confirm 尚待执行。

## 外部数据源和独立输出预检

已从本地固定镜像新建专用 PostgreSQL 16 和 MinIO 测试服务，两者各限制 CPU5、512 MiB、128 PIDs，
无宿主端口发布和默认路由。MinIO 是包含官方版本化二进制的本地 scratch 镜像，
不将本地镜像摘要称作官方发行镜像摘要。两条 veth 均在原 A 的私有 namespace 内创建；
没有修改宿主路由、FE/BE 配置或产品通信协议，原 FE/BE/supervisor 启动代次保持一致。
原 A namespace 的测试网络拓扑已增加这两条连接，后续正式环境冻结须记录；
不能将增加前后的诊断记录混为同一正式环境。

PostgreSQL 原生客户端按 ID 排序逐行核对全部百万行 id/grp/v/payload。
对象存储上传既有 100 × 10000 行 Parquet，逐文件完整读回并核对 56,184,742 字节的 SHA-256 和全部对象集合。
随后原 A FE 的 JDBC catalog 和 S3 TVF 均成功完成百万行数量、唯一 ID、范围、汇总及所有行公式检查，
其中错误行数为 0。此处 FE 返回的是完整源模型的聚合校验，不能冒称客户端百万行拉流的性能样本。
证据：`external-services-v1/plan.json`、各服务 `receipts/initial-data.json` 和
`external-sql-preflight-v1/completion.json`；SQL 预检 session 88837 实际 wait 返回 0。

随后使用实际 MariaDB 3.0.9 JDBC 驱动执行两个来源的 LIMIT 0 元数据预检，
两者四列均为 BIGINT/INTEGER/BIGINT/VARCHAR；payload 的 JDBC type 为 12。
结果用于冻结完整拉流工具的类型 oracle，本次没有返回数据行，不计入读取性能样本。
证据：`external-read-metadata-v1/completion.json`，实际客户端 exit 0，原服务启动代次未变。

外部 catalog/S3 完整拉流工具随后完成 43 项 Python 离线检查、精确 JDK 编译和 9 个无网络 JVM 进程检查，
含逆序百万行的四列 oracle、错误模型拒绝及八组跨语言到达计划；初次属性解析失败记录仍保留。
读取使用实际流式 ResultSet、每 worker 复用连接；核对全部 ID/grp/v/payload 和规范排序摘要，
同时绑定真实 reader、私有 SQL 摘要、来源及 CPU 采样前后覆盖。超时仅关闭自有 socket，不新建取消连接。
只读复核提出的来源绑定、资源区间和隐藏 JVM 选项问题已修正。
证据：`external-read/completion-v1.json`；该离线交付时尚未执行真实四档窗口。

随后 catalog/S3 × c1/c8 四个真实短窗全部完成：每窗 16 秒预热、24 秒计时、每秒 0.5 次完整查询，
各 9 次预热与 13 次计时成功，总共 88 次百万行完整读取，其中 52 次计时。
实际 JDBC 流式结果、每 worker 两阶段复用同一连接、全部四列模型和完整百万 ID 集合均通过原始记录复算。
FE/BE、客户端以及实际 PostgreSQL/MinIO 的资源观测保留，外部服务 cgroup 包含其子进程，未增加 OOM kill。
四个 helper 实际 exit 0、四个 observer 按计划 exit 143，root session 74578 实际 wait 返回 0；
独立重扫全部进程组无残留，原 FE/BE/supervisor 和两个外部服务的启动代次未变。
证据：`external-read/real-smoke-v1/results-v1/completion.json`、`root-terminal-recheck.json`。
四档仍是 `DIAGNOSTIC_VERIFIED_NOT_QUALIFIED`；查询使用与原预检相同的 root 账户，未改变已有读写账户权限。
样本数和时长不足以替代正式容量、A/A、A/B，也没有把返回行数当作查询操作样本。

实际外部输出预检已完成三个出口：

- 外部 JDBC `INSERT SELECT` 从内部表读取固定 100 行，原生 PostgreSQL 客户端核对所有 run/request/id 和列值。
- `OUTFILE` 完成 10 个文件、1000000 行输出，原生 S3 客户端逐行核对全 ID 集合及所有值。
- `EXPORT` 作业到达 `FINISHED`，同样独立核对 10 个文件、1000000 行完整结果。

原始 SQL ACK、作业状态、文件记录数和摘要均保留；测试目标表和本次 20 个输出对象清理完成。
root session 96062 实际 wait 返回 0，证据：`external-write-preflight-v1/completion.json`。

外部 JDBC `INSERT SELECT` 单窗工具已完成 20 项离线检查、精确 JDK 17.0.4 编译，
以及四组无网络 Java 计划的八段独立排程对照。独立审查的 22 项用例覆盖完整原生结果、
UNKNOWN 保留、实际 FE 端点及事务锁内核对表归属后 DROP；最后加入的正式 Java 排程摘要绑定
由工具自身离线用例另行覆盖，不冒称早先审查已运行这项新增代码。
证据：`external-write/offline-v1/handoff.json` 与 `contract/external-write-readonly-v1/review-v4.json`。
该离线交付时尚未执行真实短窗。

真实外部写入保留两次失败。v1 在原生身份准备阶段将 PostgreSQL `inet::text`
返回的 `/32` 掩码误当作端点不符；root 原生只读复核确认本次随机表尚未创建。
工具改用 `host(inet_server_addr())`，继续严格比较用户、数据库、IP 和端口。
v2 已完成 c1 的 33 个 ACK、3,300 行原生全值及源模型校验、DROP 和关闭，
但校验器将 MariaDB 驱动的原始 autocommit 标志当作 SQL 会话值而拒绝该窗。
同 JDK/驱动的实际探针确认驱动标志为 false、服务器 `@@autocommit=1`；
工具保留原始驱动标志，另外采集并严格要求 SQL 会话值为 1。
两个失败整体仍未通过：root sessions 32941、58386 均实际 exit 1；
原始回执、独立诊断、实际模型检查和清理证据分别保存在 `real-smoke-v1/results-v1`、`results-v2`。
修正后 24 项离线检查通过，包含精确 JDK 编译和 13 个无网络 Java 身份/诊断正反例。

v3 的 c1/c8 两个真实短窗全部完成：各 2 秒预热、4 秒计时、5rps，
各 11 次预热和 22 次计时，共 66 个完整 100 行操作、6,600 行原生 PG 全值核对。
源数据前后不变，UNKNOWN 未升级，两个自有表均取得真实 DROP ACK 并确认不存在。
每个 helper 实际 exit 0、observer exit 143；root session 43805 实际 wait 返回 0。
root 重新 normalize 两窗，结果与原 audit 相同；独立进程组复核无残留，原版及外部服务代次未变。
证据：`external-write/real-smoke-v1/results-v3/completion.json`、`root-terminal-recheck.json`，
以及上层 `root-recheck-v3-c1.json`、`root-recheck-v3-c8.json`。
该结果仍为诊断通过，不代替正式容量、A/A、A/B 或 1%/2% 精度验收。

服务、固定源数据和已创建的专用 catalog 暂时保留给后续性能窗口，最终清理按 owner 记录执行。
凭据及含凭据 SQL 只保存在隔离目录的 0600 私有记录，不进入公共报告。
这些是实际路径与独立 oracle 预检，尚未形成 G2/G3 的正式容量、A/A 或 A/B 通过记录。

EXPORT/OUTFILE 的正式每操作行数仍待确认：当前百万行预检每次约 50 MB，
10000 次操作且窗口末统一清理需要约 500 GB；本机检查时仅余约 27 GB。
已向用户说明固定 100 行片段与提供足量对象存储两种选择，尚未据此缩小正式负载或宣称完成。

## 自用包准备

已将 P2U 验证过的 FE 主 JAR、common JAR 和内嵌页面组成候选运行目录，
重新核对 6,287 个产品源文件和 135 个页面资源，BE 二进制摘要与原版一致。
两个候选 JAR 已放入原发行目录对应的 `doris-fe.jar` 和 `fe-common-1.2-SNAPSHOT.jar` 槽位，
运行时数据目录为空；未启动 B，也未进行 B 性能观测。
证据为 `.build-records/license-p4-20260929/candidate-stage-v3/report.json`。
前两次准备分别被运行目录检查和 common JAR 文件名检查拒绝，失败回执保留。

此目录的未修改依赖仍指向本地原包，尚不是可移交的独立归档。
实际配置、信任公钥、独立数据准备、启动验证和最终独立打包仍须完成。

A/B 对照的 B 隔离安装目录已另行准备，实际 FE/BE 配置从 A 当前配置生成，
只映射独立 metadata/storage 根路径并显式增加 B 的许可公钥配置。
共同配置文本、两侧原始文件摘要和这项差异保存在
`paired-hosting-v1/comparison-configuration.json`；每个实际窗口仍须复核配置、进程和数据。
此次公钥仅为 P3 已验证测试根的显式复用，不作为最终自用包默认信任根。
尚未启动该目录；计时对照将只运行其中一组 FE/BE，不以暂停进程冒充退出。

另已生成相互独立的自用候选证书签发与时钟修复密钥，没有复用 P3 性能测试根。
私钥仅保存在隔离的 0700 目录、0600 文件中，不进入数据库安装目录或交付归档。
公钥清单通过精确 JDK 17.0.4+8 与候选 FE JAR 的实际解析检查，root session 18839 实际 wait 返回 0。
清单摘要为 `b7b7e54f5197d753dd319619ecd5ff15d1387d9b7705f62756cf4e5ecbd45f7b`；
证据：`self-use-issuer-v1/preparation.json` 和 `self-use-issuer-v1/public-review-v1/report.json`。
这是尚未安装的候选公钥验证，没有签发最终证书、伪造部署标识或完成自用部署验收。

本页开头的快速运行范围现已完成：四类六项 A/B 短窗、候选五出口/写入/状态/额度与页面抽查，
以及独立自用包的启动、导入和重启恢复。所属服务、外部夹具及私有网络已退出，
旧测试安装按授权清理，output 仅保留最新目录、归档和校验文件；
容量确认、原长窗统计以及全并发页面矩阵不再前置。
EXPORT/OUTFILE 保留完整结果的少量独立输出抽查；不再为旧 10000 次窗口申请 500 GB 空间，
上文尚待选择的缩小每操作行数/扩存方案不再阻塞当前范围，也不回写原百万行预检结果。
实际运行结果、证据绑定和最终清理见[P4 验收记录](license-p4-acceptance-20260929.md)；
完成结论仅适用于约定的快速范围，不表示旧长测或精细性能等效验证通过。
原版 Flight 65535、Parquet reader 和账号审计问题继续保留在各自历史记录；
不把用户接受的既有缺陷改写为通过，也不将其扩展为本轮 BE 修复任务。
