<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# P2 证书管理与持久化验收

日期：2026-09-25；范围为自用环境的 FE 管理闭环。操作步骤见[管理说明](license-management-p2.md)，需求编号来自[P0 契约](license-p0-contract-20260922.md)。

**状态：P2 管理与持久化已完成，按下述单测、受控故障和真实集群层级验收。** 五出口查询拦截、ADD/DROP 额度准入、页面和业务性能分别属于 P3、P2U、P4，不计入本阶段完成范围。状态中的节点额度已用于导入策略和展示，尚不表示新增节点已受拦截。

## 构建和证据范围

使用 Temurin 17.0.4+8，断网执行 `mvn -o -pl fe-core -am package -Dtest=License*Test -DfailIfNoTests=false`：16 个测试类、**183 项通过，零失败、错误或跳过**；其中包括原 P1 的 104 项。SQL 文件导入辅助工具另有 4 项测试通过。完整 FE reactor Checkstyle、源码头和差异空白检查通过。

最终 FE JAR SHA-256 为 `812cfadf2437dd6acfb6cb7cfebe181e67dded9b669fd97d472c75ab0743fb2d`，fe-common 为 `a0d000535b201fb5906b0e389af67bb59357131b3994dd42f28fecbbe68ca4d2`。构建、XML 和源码绑定见[package-6 记录](../.build-records/license-p2-20260925/package-6-evidence/summary.json)。

真实集群使用独立网络 namespace、三个 FE 和临时第四个 Observer，无 BE；显式安装测试公钥，不将测试根或私钥装入产品。经过启动、导入、自然到期、重启和切主，部署标识保持一致。没有修改宿主时间。管理功能测试不能证明业务查询拦截、写入兼容或性能达标。

运行记录分包保留：v1 使用最初管理实现，v2 使用 package-4，v3 使用 package-5。package-4 到 package-5 的 55 个许可 class 中仅 `LicenseManagementResult.class` 改变，用于修正 202 的 `message`；其余 54 个逐字一致。最终 package-6 修正本地应用失败时 `LicenseManagementException` 的 `retryable`，重跑全部 183 项并在既有故障测试中核对完整回执一致。与 package-5 比较全部 10,391 个 class：除该异常类外，仅四个构建信息类的内联构建时间变化，其余字节相同，反汇编差异已留档。没有另行重启集群运行 package-6，不把旧包所有用例写成最终包已全部重跑。

## 按需求核对

“单测/注入”表示实际执行产品类，但以可控 Host、时钟或传输替身制造故障；“真实 FE”表示运行中的 FE、真实 journal/image、客户端或网络故障。两类证据分别保留，不把断言数量相加为集成用例数。

| 需求 | 单测/受控故障 | 真实 FE 验证 |
| --- | --- | --- |
| M01 部署身份 | Master 独占初始化、GET 无写入、缺失或错误信任配置 | 三 FE 同 UUID，重启和切主后保持；初始并发 GET 未单独压测 |
| M02 管理入口 | SQL/HTTP 共享候选策略、权限与最小 DTO | SQL 和 HTTP 导入/验证/回执，匿名与普通用户拒绝；Cookie 同源/CSRF |
| M03 拒绝保旧 | 低序号等十类候选、字节限制在验签排队前拒绝 | 篡改、未知 kid、错误用途/部署、同序号冲突、覆盖与额度降低；SQL/HTTP 超限后原事实不变 |
| M04 幂等与提交状态 | 1,026 次签名导入验证 1,024 条回执淘汰；并发冲突、取消、提交确认后本地失败 | 旧证在新证之后仍返回原回执；请求未到 Master 为 UNKNOWN；实际提交后丢响应，再确认和重试不重复提交 |
| M05 恢复与新 FE | 坏 pending/base 隔离、过期恢复、独立 checkpoint Env、原字节 round-trip | 实际 checkpoint image 与后续 journal、三 FE 完整重启恢复；空元数据的新 Observer 加入已激活集群并恢复同一事实和历史回执 |
| M06 格式兼容 | skip/缺模块/未知版本/超限保持未就绪；混合旧 FE 阻止首次激活 | 旧 FE 下载新版 image 后因 141 超出其支持的 140 而退出，未提供 SQL/HTTP/RPC 服务 |
| M07 P2 时间 | 回拨/前跳容差、粘滞异常和提交水位故障 | 自然到期前一秒/等号边界、SQL 时区不改授权；约 60 秒水位持久提交并在重启后恢复 |
| M08 时间修复 | 错 nonce/epoch/用途、24 小时单调挑战、重复和提交故障 | Follower 申请并提交签名票据，epoch 只增一次；重启/切主拒绝旧未提交票据，历史回执保留 |
| M12 P2 基础额度 | pending 提升暂停、失败、ACK 丢失后的唯一提交 | 三 FE 观察自然到期、未承诺的 20 秒空档和未来证书生效；基础额度由 5/2 提交为 6/3，并经重启保持 |
| M13 转发与应用进度 | 原主体转发、认证与错误保真、本地等待、既有 HTTPS 配置 | Master 已撤 ADMIN 而接入 FE 仍未同步时，转发 GET/POST 均被拒；真实复制延迟下 SQL/HTTP 返回 202，恢复后确认同一提交；修正文案后的 202/200 已实际复验 |
| M14 资源与脱敏 | 两 worker、32 队列、取消归还、每分钟/突发限流；解析/多语句/Profile/DEBUG 脱敏 | 实际 SQL 第四次突发被限流，状态查询可用；严格服务端 PREPARE 拒绝、原协议多语句、SQLSTATE、FE 日志及解码 Profile 核对 |

M07 的异常态业务兼容、M12 的 ADD 前后行为及 M09–M11 节点准入留给 P3。混合旧版集群首次激活、队列饱和、1,024 条回执淘汰、损坏元数据及时钟跳变使用单测/注入，未另外在真实集群破坏 BDB 或修改系统时间。真实网络窗口使用 HTTP；HTTPS 配置和转发由源码及单测验证。

主要原始记录均位于[本地证据目录](../.build-records/license-p2-20260925/)：

[最终逐项审计](../.build-records/license-p2-20260925/final-p2-audit.md)及其 [JSON](../.build-records/license-p2-20260925/final-p2-audit.json)绑定 72 份原始证据，分别记录 11 项当前 P2 要求的通过方法、真实请求和验证限制。

- `http-basic-v3/expiry-result.json`：三 FE 的到期、空档和基础额度提升，18 项边界断言与 1,083 个状态样本。
- `http-restart-v2/completion.json`：26 项 HTTP 恢复、大小限制和时间修复操作。
- `runtime-v2/failover-seq6/verification.json`：实际杀死 Master 后 29 项身份、事实及原回执核对；`sql-runtime/v2/after-failover-assertions.json` 另有 19 项 SQL 核对。
- `runtime-v2/fe3-stale-admin-window/verification.json`：12 项断言证明 Master 重验原权限，独立于接入 FE 的滞后权限。
- `http-transport-v2-retry/completion.json`：真实请求超时与响应丢失，原提交版本不变。
- `runtime-v2/old-fe4-rejection/verification.json`：旧版 FE 的 7 项拒绝验证。
- `runtime-v3/package5-restoration-verification.json`：package-5 实际重启的 39 项事实和历史回执核对。
- `http-final-v3/completion.json`：42 项断言通过，包括带实际请求字节数/摘要的大小拒绝，以及两次约 5 秒等待后 202、解除复制阻断后同一提交 200；`reason/message` 一致，原提交版本保持 54。
- `runtime-v3/new-observer-fe4/verification.json`：全新 FE 身份的 24 项加入、恢复和退出断言通过；明确以空元数据启动，恢复 seq7、epoch1、6/3 基础额度和五类历史回执，随后 DROP 并停止。
- `sql-runtime/v2/assertions.json`：43 项大小、SQL mode、错误、限流和多语句断言；`sql-runtime/canary-profile-final-v1.json` 包含 11 个原文标记零泄漏及 65 个脱敏标记。
- `final-canary-scan/verification.json`：集群停止后冻结 59 个实际 FE 日志和两个解码 Profile，79 个原文/片段/大字段标记零命中、零读取失败，观察到 200 个脱敏标记；不扫描正常保存证书的元数据和私有请求夹具。
- `runtime-v3/final-cleanup-verification.json`：38 项清理断言通过，三个运行环境的 27 个自有进程生命周期均已结束，无故障规则/私有 namespace 进程残留；原 FE/BE 进程、配置与原包保持不变。

## 修复与保留失败

真实 HTTP 验证发现大字段的具体错误被通用 JSON 异常覆盖，已修正为证书/修复票据分别按 64/16 KiB 拒绝并返回 `LICENSE_INPUT_TOO_LARGE`。原始失败 `http-basic-v3/completion.json` 保留，后续成功记录单独保存。

审查补齐了持久提交成功、本地发布失败的处理：返回可确认的 202，阻止后续新写入，维护任务重放同一已提交记录；并发重复请求仍查原回执。失败前先准备可失败的恢复/快照工作，避免部分事实提前发布。对应并发、恢复及修复票据测试已通过。

实际复制延迟暴露 202 的 `reason` 正确但 `message` 仍为 `LICENSE_APPLIED`，package-5 统一两字段并在 v3 复验通过。原 `http-delay-v2/requests.json` 保留这一显示失败，不能追改为完全通过。最后核对还统一首次本地应用失败与后续回执的 `retryable=true`；既有故障测试验证两次完整回执一致。

首轮签发 harness API 错误、首轮撤权窗口在断言前到期、首次网络故障预期不符、错误 SQL 测试主体等失败均保留。MariaDB 驱动默认多语句协商在原版元数据语句上也失败；使用显式协商的原 MySQL 协议验证多结果，不据此宣称该驱动组合已修好。原 BE Flight 大批次和 FE Parquet reader 缺陷继续按用户已接受的原版失败保留。

临时证书、签发私钥、账号配置、故障脚本和原始日志位于忽略目录，不提交到 Git。源码仓库保留实现、针对性测试、操作说明和本验收摘要。
