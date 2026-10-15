<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# 证书取代式续期执行计划

初稿：2026-10-15；同日按静态审核修订四处：validate 与 import 的版本绑定范围、页面提示与行为变更同轮交付、旧 FE 包回放按状态分别验收、补齐需改写的旧测试清单。状态：2026-10-15 已按本文实现，R1–R5 完成，验收见第 7 节；未构建新的完整发行包，未验证边界见 7.5。源码基线：`2.0.5-license` / `09d5d7af6e2`。

**本轮目标：** 允许导入到期更早的证书，允许在旧证未到期但集群已缩容时导入额度更低的证书。两条需求统一为一条规则：同一部署内 sequence 更高的合法证书一经导入，就完全取代当前 active 和 pending 的全部承诺。FE 不再比较新旧证书的到期时间、生效时间、额度和功能集，只保留"新证额度必须容纳当前实际用量"。

改动限于 FE 许可管理类、独立签发工具、测试与文档。不改查询准入热路径、BE、journal/image 外壳格式、通信协议、SQL 语法和 HTTP 参数。

## 1. 现行规则与本轮删除项

现行实现把续期视为对旧承诺的延续，由三处互为镜像的校验共同保证：

| 位置 | 现行规则 | 本轮处理 |
| --- | --- | --- |
| `LicenseImportPolicy.preserveCoverage` / `requireCoverage` | 新状态必须覆盖旧 active、pending 未结束的时间并集，不缩短、不留空档、功能集和额度不减，否则 `RENEWAL_REDUCTION` | 删除 |
| `LicenseImportPolicy.requireCapacity` | 额度下限取"已注册 + 预留"与未过期 active/pending/base 额度的最大值，否则 `NODE_LIMIT_TOO_SMALL` | 只保留"已注册 + 预留" |
| `LicenseImportPolicy.promotedBase` | base 未过期时拒绝更低额度的新 base | 删除额度比较，只按序号取新 |
| `LicenseImportState.requireNondecreasingCapacity` / `requirePendingCapacity` | journal 回放和 image 恢复时拒绝"额度跨槽下降" | 删除 |
| `tools/license-issuer/license_issuer.py` `check_renewal` | 带 `--previous` 预检时按同样规则拒绝 | 只保留身份、序号、license_id 检查，并输出变更提示 |
| [P0 契约](license-p0-contract-20260922.md)第 45 行、M15/M16；[到期后缩容续期](license-expired-renewal-20260930.md) | 把上述保护写成契约；2026-09-30 的"旧承诺到期后才能降额"为特例 | 改文；特例被统一规则吸收 |

`RENEWAL_REDUCTION` 不再产生。枚举值和 `ui/src/api/license.ts` 的映射保留，以兼容旧客户端和历史日志。

## 2. 目标规则

### 2.1 导入准入检查

按执行顺序列出；"不变"表示沿用现有实现。

| 序号 | 检查 | 失败结果 | 变化 |
| --- | --- | --- | --- |
| 1 | 指纹已有回执 | 幂等返回原回执，不改任何事实 | 不变 |
| 2 | 签名、信任集、格式、64 KiB 上限 | 对应验签错误 | 不变 |
| 3 | deployment_id 一致 | `DEPLOYMENT_MISMATCH` | 不变 |
| 4 | license_id / sequence 与已有槽位或回执冲突 | `IMPORT_CONFLICT` | 不变 |
| 5 | sequence 大于历史最高序号（含回执） | `IMPORT_HISTORY_UNAVAILABLE` | 不变 |
| 6 | 恢复完成、时钟可信 | `IMPORT_NOT_READY` / `CLOCK_SUSPECT` | 不变 |
| 7 | issued_at ≤ 可信时间 + 300 秒 | `ISSUED_IN_FUTURE` | 不变 |
| 8 | expires_at > 可信时间 | `CERTIFICATE_EXPIRED` | 不变 |
| 9 | 含 DATA_QUERY | `FEATURE_NOT_LICENSED` | 不变 |
| 10 | max_fe ≥ 已注册 FE + 预留，max_be ≥ 已注册 BE + 预留 | `NODE_LIMIT_TOO_SMALL` | 只看实际用量 |

通过后一次性原子提交；任何失败保持旧事实，不消费新序号。validate 与 import 使用同一纯策略，这部分不变。

**validate 与 import 之间不做版本绑定。** 现有实现在每次 import 请求内重新执行 `prepare`，再由 `recheckForCommit` 核对本次请求内部的许可版本、成员版本和 FE 版本是否变化，变化即 `STALE_IMPORT_DECISION`。validate 返回的 `expected_license_version`、`expected_membership_version` 只是提示，import 不接收它们。因此 validate 之后、import 之前成员发生变化时，import 按当时的成员数重新裁决：额度仍满足就成功，`changes` 按当时状态重新计算；不满足则 `NODE_LIMIT_TOO_SMALL`。本轮保持这一行为，不新增跨请求绑定，因为那需要 SQL 和 HTTP 增加版本参数，超出"不改语法和参数"的范围。操作人应在 validate 看到 `changes` 后尽快 import，并以 import 响应中的 `changes` 为准。

### 2.2 取代后的状态

- **新证已生效**（not_before ≤ 可信时间）：成为 active，pending 清空，base 同步更新为新证。旧 active 和旧 pending 的承诺一并终止。
- **新证未来生效**（not_before > 可信时间）：成为 pending，替换已有 pending；active 不变。旧 active 到期与新证生效之间允许空档，空档内查询按 EXPIRED 受限。
- 任何时候最多一个 active 加一个 pending；替换 pending 仍要求更高 sequence。
- 查询准入仍按 `not_before <= now < expires_at` 选择当前证书；新到期时刻一到，出队和新请求即按 EXPIRED 处理，30 天内到期照常出 EXPIRING 告警。

### 2.3 ADD 节点上限

沿用现有实现，不改：

- 无 pending 时按已提交 base 额度。
- 有 pending 时 FE、BE 分别取 min(base, pending)；较低 pending 立即约束新增，较高 pending 不提前放开。
- pending 到点后基础额度切换仍须重新核对用量并持久提交（`prepareBaseActivation`），不从时间推导。

### 2.4 变更提示

validate 和 import 成功响应新增 `changes` 数组，每项含固定 `code` 和相关数值；SQL 经现有 Key/Value 结果集以 JSON 字符串呈现，HTTP 与页面直接透传。

| code | 触发条件 | 附带字段 |
| --- | --- | --- |
| `EXPIRY_SHORTENED` | 新证 expires_at 早于当前 active 的 expires_at | `previous_expires_at`、`expires_at` |
| `COVERAGE_GAP` | 旧 active 到期早于新 pending 生效 | `gap_seconds`；现有 `coverage_gap_seconds` 字段保留并与之一致 |
| `FE_LIMIT_REDUCED` / `BE_LIMIT_REDUCED` | 新证额度低于当前 active 或 base | `previous_limit`、`limit` |
| `PENDING_DISCARDED` | 已有 pending 被新 active 或新 pending 替换 | `license_id`、`sequence` |
| `FEATURES_REMOVED` | 新证功能集少于当前 active | `features` |

有变更项不阻止导入。它只是 validate 阶段给操作人的事实陈述，不是第二套准入规则。

### 2.5 不变的前提

- expires_at 必须大于可信 UTC 时间；不认客户端本地时间，不允许手工改时绕过。
- 额度按真正除名后的已注册数量加进行中的 ADD 预留计算。停进程、离线不释放额度；BE 须 `DECOMMISSION BACKEND` 完成，FE 删除仍受角色、主节点和法定人数约束。
- 已消费序号不可回退。重新导入被取代的旧证只返回原回执，不恢复旧额度或旧期限；误导入只能由签发方签发更高序号的新证纠正。需要恢复更长期限或更高额度时同样只需一张新证，不存在死路。
- 导入前全部已注册 FE 必须通过相同包摘要门禁（`LicenseFeCompatibility`）。该门禁只在导入时检查，不阻止之后整集群回退二进制。回退到本轮之前的 FE 包属于**不支持的运维操作**，不是程序保证：旧包的恢复校验只拒绝"与未到期 active 或 base 重叠的更低额度 pending"这一种状态；立即生效的取代（active 与 base 同为新证）和单纯缩短到期的状态旧包能够回放，回放后旧包会按旧规则处理后续导入。实测补充见 7.5：旧包逐条回放最近 image 之后的 journal，判断的是该区间内出现过的每个状态；遇到重叠低额 pending 时 FE 进程退出。
- 回执上限、限流、脱敏、权限、转发等管理接口行为不变。

## 3. 改动清单

| 文件 | 改动 |
| --- | --- |
| `fe/fe-core/src/main/java/org/apache/doris/massdb/license/LicenseImportPolicy.java` | 删除 `preserveCoverage`、`requireCoverage`；`requireCapacity` 只算已注册 + 预留；`promotedBase` 只按序号取新；`Prepared` 增加 `changes` |
| `fe/fe-core/src/main/java/org/apache/doris/massdb/license/LicenseImportState.java` | 删除 `requireNondecreasingCapacity`、`requirePendingCapacity` 及其调用；保留槽位一致性、序号顺序、base 标记和回执身份校验 |
| `fe/fe-core/src/main/java/org/apache/doris/massdb/license/LicenseManager.java` | validate 和 import 响应写入 `changes`；`coverage_gap_seconds` 保留 |
| `fe/fe-core/src/main/java/org/apache/doris/massdb/license/LicenseController.java` | 不改；HTTP 直接透传 Manager 响应体，转发到 Master 的路径同样透传 |
| `tools/license-issuer/license_issuer.py` | `check_renewal` 改为身份、序号、license_id 检查并返回变更列表；CLI 输出变更提示 |
| `ui/src/api/license.ts`、`ui/src/pages/license/index.tsx` | 响应字段白名单加 `changes`（现有白名单会丢弃未列出的字段）；导入页 validate 和 import 结果展示变更列表。可以单独提交，但必须与 FE 行为变更同一轮交付 |
| `docs/license-p0-contract-20260922.md` | 第 45 行续期契约改为取代式规则；M15/M16 标注被本轮吸收；新增 M17 本轮用例 |
| `docs/license-expired-renewal-20260930.md` | 顶部注明 2026-10-15 起规则被取代，正文保留为历史 |
| `docs/license-certificate-execution-plan-20260922.md` | 头部追加本轮摘要，第 7 节增加一行 |
| `MODIFICATIONS.md` | 新增本轮条目 |
| `docs/license-renewal-replacement-plan-20261015.md` | 本文；实现完成后补验收章节 |

LicenseManager 的 ADD 校验、`LicenseSnapshot`、`LicenseQueryGuard`、持久化记录格式、`LicenseFeCompatibility` 不改。

## 4. 测试计划

### 4.1 需要反转或改写的现有测试

| 测试 | 处理 |
| --- | --- |
| `LicenseImportPolicyTest.currentImportMustPreserveActiveAndFuturePendingCoverageAndFeatures` | 改为接受并断言 `EXPIRY_SHORTENED` / `FEATURES_REMOVED` / `PENDING_DISCARDED` |
| `LicenseImportPolicyTest.futureReplacementCannotLosePendingStartButEquivalentActiveCanBridge` | 改为接受并断言 `COVERAGE_GAP` |
| `LicenseImportPolicyTest.pendingHigherCapacityCannotBeBridgedBySmallerActive` | 改为接受并断言 `FE_LIMIT_REDUCED` / `BE_LIMIT_REDUCED`（实际用量仍需满足） |
| `LicenseImportPolicyTest.unexpiredFutureCapsAndReservationsCountWithoutOverflow` | 去掉未过期额度作为下限的断言，保留预留计数和溢出断言 |
| `LicenseImportPolicyTest.reducedFeAndBeRenewalsBecomeAdmissibleExactlyAtExpiry` | 改为到期前即可接受，前提是用量已满足 |
| `LicenseImportPolicyTest.restorationRejectsMixedBaseOrderAndOverlappingQuotaReductionWithoutInferringReplacement` | 保留 base 顺序断言，删除重叠降额拒绝断言 |
| `LicenseImportPolicyTest.restorationAllowsLowerPendingAtExpiryWithoutInferringAnActivatedBase` | 扩展为任意时间的低额 pending 和低额 active 都能恢复 |
| `LicenseImportPolicyTest.expiredRenewalStillCountsRegisteredMembersAndReservations` | 保留四组实际用量超限和 `STALE_IMPORT_DECISION` 断言；删除"时间 1099 旧证未到期即拒绝提交"的那一条 `NODE_LIMIT_TOO_SMALL` 断言 |
| `LicenseImportPolicyTest.unexpiredPendingPromiseSurvivesActiveExpiryUntilItsOwnExpiry` | 原断言更高额度 pending 未到期时拒绝降额；改为四个时间点都接受，新证成为 active 和 base，旧 pending 被丢弃并出 `PENDING_DISCARDED` |
| `LicenseManagerTest.expiredRenewalCanLowerBothLimitsOnlyAfterMembershipShrinksAndPersistsTheNewBase` | 第 455 行"已缩容但旧证未到期"的拒绝改为接受；之后"重新扩容后拒绝"和"到期后再缩容接受"的步骤按新规则重排，并重命名 |
| `LicenseManagerTest.invalidCandidateMatrixUsesTheSamePolicyForValidateAndImportAndKeepsAllFacts` | 移出 `LICENSE_RENEWAL_REDUCTION` 两条和 `max_fe_nodes = 2` 一条，放进新的"接受并返回 `changes`"用例；`max_fe_nodes = 2` 是否仍拒绝取决于该测试实际注册的 FE 数，按实际用量重新推导 |
| `test_license_issuer.py` 中 `test_renewal_pending_coverage_and_expired_features`、`test_renewal_node_reduction_requires_previous_expiry` | 改为预检通过并输出变更提示 |
| `test_license_issuer.py` 中 `test_authenticated_reduced_renewal_and_following_renewal` | 原断言旧证到期前一秒签发降额证失败；改为成功并携带变更提示 |

以下测试经核对仍然成立，保留原样：`LicenseImportPolicyTest.recheckRejectsVersionMembershipClockExpiryQuotaAndTrustChangesBeforeCommit`（4 FE 超过 3 的额度，属实际用量）、`reducedFutureRenewalSurvivesRecoveryAndRequiresExplicitBaseActivation`（激活时 3/6 超过 pending 的 BE 5）、`LicenseManagerTest.memberGrowthBeforeLowerRenewalCommitRejectsTheStaleDecision`（单次 import 内的成员竞争）、`smallerPendingCapsAddsBeforeAndAfterRestartUntilLowerBaseCommitIsApplied`、`test_expired_renewal_keeps_identity_and_sequence_checks`。其余 Policy、Manager、恢复、Snapshot、Guard、Controller 测试按原样保留并必须继续通过。实施 R1 时对每一条 `NODE_LIMIT_TOO_SMALL` 断言逐一判断依据是实际用量还是旧承诺，不得整体放行。

### 4.2 本轮新增用例矩阵（M17）

| 编号 | 场景 | 期望 |
| --- | --- | --- |
| M17-01 | 到期更早、额度相同、立即生效 | 接受，`EXPIRY_SHORTENED`；查询在新到期时刻转 EXPIRED，EXPIRING 告警按新到期计算 |
| M17-02 | 旧证未到期、已真正缩容、额度降低、立即生效 | 接受，base 同步降低，超额 ADD 返回 `LICENSE_FE/BE_LIMIT_EXCEEDED` |
| M17-03 | 旧证未到期、未缩容、额度降低 | `NODE_LIMIT_TOO_SMALL`，保旧，最高序号不变 |
| M17-04 | 进行中的 ADD 预留占满额度时降额 | `NODE_LIMIT_TOO_SMALL` |
| M17-05 | 仅停进程或离线、未 DROP 的节点仍计数 | `NODE_LIMIT_TOO_SMALL` |
| M17-06 | 低额未来 pending | 接受；等待期 ADD 取 min(base, pending)；到点 `prepareBaseActivation` 重新核对用量后切换 base |
| M17-07 | 新 active 吞掉旧 pending | 接受，`PENDING_DISCARDED`；旧 pending 回执保留 |
| M17-08 | 新 pending 替换旧 pending，生效更晚 | 接受，`PENDING_DISCARDED` 加 `COVERAGE_GAP` |
| M17-09 | 旧 active 到期后新 pending 才生效 | 接受，`COVERAGE_GAP`；空档内查询 EXPIRED |
| M17-10 | 功能集减少但含 DATA_QUERY | 接受，`FEATURES_REMOVED` |
| M17-11 | 缩短或降额后再导入更长、更高额度的更高序号证书 | 接受，恢复长期限与高额度，base 随之提高 |
| M17-12 | 重新导入被取代的旧证 | 幂等回执，不恢复旧额度、旧期限，最高序号不变 |
| M17-13a | validate 后、import 前成员变化，额度仍满足 | import 成功，响应 `changes` 按 import 时状态计算，可与 validate 返回不同 |
| M17-13b | validate 后、import 前成员变化，额度不再满足 | `NODE_LIMIT_TOO_SMALL`，保旧 |
| M17-13c | 单次 import 内 prepare 与提交之间成员或 FE 版本变化 | `STALE_IMPORT_DECISION`，保旧（沿用现有用例） |
| M17-14 | 降额/缩短状态的 journal 回放、image 恢复、checkpoint | 恢复成功，事实与提交一致；`SHOW LICENSE` 和 HTTP 的 `max_*`、`base_max_*` 一致 |
| M17-15a | 旧 FE 包回放"立即取代"或"仅缩短到期"状态 | 回放成功；记录为"可回放但不支持"的运维边界，不宣称程序阻止 |
| M17-15b | 旧 FE 包回放"与未到期 active/base 重叠的更低额度 pending"状态 | 恢复校验拒绝，记录为程序保证的兼容边界 |
| M17-15c | 混包集群导入 | 包摘要门禁在导入前返回 `LICENSE_FE_UPGRADE_REQUIRED`；该门禁不覆盖导入后的整体回退 |
| M17-16 | expires_at ≤ 可信时间、issued_at 超前、时钟可疑 | 拒绝，不变 |
| M17-17 | validate 与 import 对同一候选返回相同 `changes` | 一致 |

### 4.3 验证层级

- 单元：Policy、ImportState、Manager、issuer 在 JDK 17 上离线跑全部 `License*Test` 和 issuer 测试，零失败、错误、跳过。
- 构建：Checkstyle、FE 构建、`python3 build-support/check-source-headers.py`、`git diff --check`。
- 真实运行：单 FE 隔离实例，用包内公钥和临时签发证书经 JDBC 和 HTTP 覆盖 M17-01、02、03、06、07、11、12、14，并对 ADD 超额和重启恢复截图留证；离线身份的 BE 按 `TabletNum=0` 核对后用 `DROPP` 清理。
- 不执行：线上 BE 数据迁移、真实多 FE 切主、混包部署、性能基线。按 2026-09-30 记录方式单列为未验证边界。

## 5. 实施顺序与完成条件

| 阶段 | 工作 | 完成证据 |
| --- | --- | --- |
| R0 规则冻结 | 本文第 2 节经用户确认 | 用户确认记录 |
| R1 策略与恢复 | Policy、ImportState 改动及 4.1 测试反转，先不加 `changes` | Policy/ImportState 测试通过 |
| R2 变更提示 | `Prepared.changes`、Manager 响应、issuer 工具 | Manager、Controller、issuer 测试通过，M17-17 一致性断言 |
| R3 文档 | P0 契约、到期续期文档、主计划、MODIFICATIONS.md | 文档链接与源码头检查通过 |
| R4 真实验证 | 4.3 真实运行项，证据存 `.build-records/license-renewal-replacement-20261015/` | 运行汇总 JSON 绑定 FE JAR 摘要、截图与各步返回码 |
| R5 页面 | 白名单加 `changes`，validate 和 import 结果展示变更列表；可单独提交 | 构建、`npm run check:notices`、`npm run test:legal` 通过，浏览器功能用例覆盖缩短、降额、丢弃 pending 三种提示 |

交付门槛：R1 到 R5 全部完成才能打包。R1 完成后 FE 行为即已改变；缺 R2 则没有 `changes`，缺 R5 则页面白名单会丢弃 `changes`，两种情况下操作人都会在看不到缩减事实的前提下确认导入。R5 可以是独立提交，但不能作为后续项延期。

## 6. 风险与应对

| 风险 | 应对 |
| --- | --- |
| 误导入短期或低额证书导致提前停服或无法扩容 | 不可回退是规则的一部分；靠 validate 的 `changes` 让操作人在提交前看到事实，文档明确写出"纠正只能签新证" |
| 恢复校验放宽后，损坏或篡改的槽位更难被结构校验发现 | 每个槽位仍独立验签；删除的只是跨槽额度比较，签名、序号顺序、base 标记、回执身份校验保留 |
| 整集群回退到旧 FE 包 | 多数取代状态旧包能回放，回退后旧包按旧规则处理后续导入，程序不阻止；只有重叠的低额 pending 会被旧包恢复校验拒绝。文档把回退列为不支持的运维操作，验收按 M17-15a/15b/15c 分别记录，不把门禁描述成回退保护 |
| validate 与 import 之间成员变化 | 不做跨请求绑定；import 重新裁决并返回当时的 `changes`，操作人以 import 响应为准。单次 import 内的竞争仍由 `STALE_IMPORT_DECISION` 保护 |
| 签发工具与 FE 规则再次分叉 | issuer 的 `check_renewal` 与 FE 共用同一张变更提示表，测试双向覆盖 |
| 现有验收记录被误读为仍然有效 | 2026-09-30 记录保留为历史并在顶部标注被取代，不回写其结论 |

## 7. 实施与验收（2026-10-15）

R0：2026-10-15 用户要求“完整实现这份执行计划”，按第 2 节规则执行。R1 与 R2 在同一轮改动中一起实现（未单独留存“只放宽、不带 `changes`”的中间版本），以下各层证据都针对最终源码；证据目录为 `.build-records/license-renewal-replacement-20261015/`，汇总见其中的 `runtime-v5/runtime-summary.json`。

### 7.1 实现

| 文件 | 实际改动 |
| --- | --- |
| `LicenseImportPolicy` | 删除 `preserveCoverage`/`requireCoverage`；`requireCapacity` 只算已注册+预留；`promotedBase` 只按序号取新；新增 `ChangeCode`、`Change` 与 `Prepared.getChanges()`，幂等确认和基础额度激活返回空列表 |
| `LicenseImportState` | 删除 `requireNondecreasingCapacity`、`requirePendingCapacity` 及调用；槽位验签、序号顺序、base 标记、回执身份校验不变 |
| `LicenseManager` | validate 与新提交 import 的成功响应写入 `changes`；import 另写 `coverage_gap_seconds`；幂等重试与回执查询不带 `changes`（未持久化，格式不变） |
| `LicenseErrorCode` | `RENEWAL_REDUCTION` 保留并注明不再产生 |
| `LicenseController`、`LicenseCommand` | 未改；HTTP 与转发透传，SQL 的 `changes` 行为 Gson JSON 字符串 |
| `license_issuer.py` | `check_renewal` 只查身份、序号、`license_id`，返回相对 `--previous` 的同名变更码；`sign` 结果带 `changes`，标准错误输出一行提示 |
| `ui/src/api/license.ts`、`ui/src/pages/license/` | 白名单接受经校验的 `changes`（最多 16 项，仅已知字段）；导入对话框和回执卡片展示中英文提示 |
| 文档 | P0 契约、导入核心、管理说明、主计划、实施记录、签发工具 README、UI README、MODIFICATIONS.md；2026-09-30 记录顶部标注被取代 |

计划第 3 节未列出的 `license-import-core-20260922.md`、`license-management-p2.md`、实施记录和 UI README 也写有旧规则或页面说明，一并改写，避免现行说明与代码矛盾。

### 7.2 测试结果

| 层级 | 结果 | 证据 |
| --- | --- | --- |
| FE 构建与 Checkstyle | `mvn -o -pl fe-common,fe-core package`（validate 阶段 Checkstyle 含测试源码），JDK 17.0.4+8 | `checks-v2/completion.json`；FE JAR `doris-fe.jar` sha256 `973cf0d2bf0a623afd89eb44088632400da34f2f94ff1cf58804aa9b7606283a` |
| FE 单元 | 33 个 `License*Test` 类 352 项，零失败、错误、跳过；其中 `LicenseImportPolicyTest` 30 项、`LicenseManagerTest` 54 项 | 同上，含各类 surefire XML |
| 签发工具 | `test_license_issuer` 28 项与 `test_license_sql_import` 4 项通过 | `issuer-tests-v1.json` |
| 页面 | Node 22.23.2 构建、`check:notices`、`test:legal`（1 项）、`test:license`（45 项，含新增 U05 三组）通过；FE JAR 内嵌同一构建产物 | `ui-v2/completion.json`、`ui-v2/browser/license-changes-*.png` |
| 源码检查 | `check-source-headers.py` 通过（0 pending）；`git diff --check` 无输出 | 本轮执行记录 |
| 真实单 FE | 见 7.4，状态 `REAL_FE_REPLACEMENT_RENEWAL_SQL_HTTP_UI_RESTART_AND_OLD_PACKAGE_PASS`；此前 4 次尝试因验证脚本问题中止，原样保留并在记录 README 说明 | `runtime-v5/runtime-summary.json` |

第 4.1 节列出的旧测试均已按表改写；列为“保留原样”的五个用例未改且通过。逐条复核 `NODE_LIMIT_TOO_SMALL` 断言后，保留的都以实际已注册/预留数量为依据。

### 7.3 M17 覆盖

单元测试名省略类名前缀：P = `LicenseImportPolicyTest`，M = `LicenseManagerTest`，I = `test_license_issuer.py`，U = `ui/scripts/license.test.cjs`；真实运行步骤见 7.4。

| 编号 | 单元 / 浏览器 | 真实运行 |
| --- | --- | --- |
| M17-01 | P `currentImportReplacesActiveAndFuturePendingAndReportsReductions`；M `shorterRenewalMovesExpiryAndExpiringWarningToTheNewCertificate`（新到期时刻 EXPIRED、EXPIRING 按新到期） | S05、S08 |
| M17-02 | P `reducedFeAndBeRenewalsAreAdmissibleBeforeExpiryWhenActualUsageFits`；M `lowerRenewalIsAcceptedBeforeExpiryOnlyAfterMembershipShrinksAndPersistsTheNewBase` | S05、S06 |
| M17-03 | M 同上（未缩容时 validate 与 import 均拒绝且镜像字节不变） | S03 |
| M17-04 | P `reservationsCountWithoutOverflowButUnexpiredAcceptedCapsDoNot`、`pendingReplacementAndLowerLimitsAreAcceptedWithinActualUsage`、`expiredRenewalStillCountsRegisteredMembersAndReservations` | 未覆盖（见 7.5） |
| M17-05 | P 以注册数计数的各用例 | S04（离线 BE 仍计数） |
| M17-06 | P `pendingReplacementAndLowerLimitsAreAcceptedWithinActualUsage`；M `lowerFuturePendingCapsAddsNowAndActivatesOnlyAfterRecheckingUsage`（用量超额时不激活） | S10、S11、S12 |
| M17-07 | P `currentImportReplacesActiveAndFuturePendingAndReportsReductions`、`lowerRenewalReplacesAnUnexpiredHigherPendingAtAnyTime`；M `formerReductionCandidatesAreAcceptedWithTheSameChangesFromValidateAndImport`（被丢弃 pending 的回执） | S15、S16（真实页面） |
| M17-08 | P `futureReplacementMayDelayPendingStartAndReportsTheGap`；M `formerReduction…`（`COVERAGE_GAP`+`PENDING_DISCARDED`） | — |
| M17-09 | P `gapIsExplicitAndDoesNotExtendOldCertificate`、`futureReplacementMayDelayPendingStartAndReportsTheGap`（空档内 EXPIRED） | — |
| M17-10 | P `currentImportReplacesActiveAndFuturePendingAndReportsReductions`；I `test_renewal_discards_pending_and_reports_gap_and_removed_features` | — |
| M17-11 | P `higherSequenceRestoresLongerAndLargerCoverageAfterReduction`；M `shorterRenewal…` | S09 |
| M17-12 | P `higherSequenceRestores…`、`reducedRenewalKeepsOldReceiptsWithoutRestoringOldCapacity`；M `lowerRenewalIsAccepted…` | S07 |
| M17-13a | M `membershipChangeBetweenValidateAndImportIsJudgedAgainAtImport`；P `changesAreFactsOfTheCommittedDecisionAndAreRecomputedAtCommit` | — |
| M17-13b | M `lowerRenewalIsAccepted…`（validate 后扩容再 import 被拒） | — |
| M17-13c | M `memberGrowthBeforeLowerRenewalCommitRejectsTheStaleDecision`、`acceptedMemberChangeInvalidatesAnImportPreparedBeforeItsCommit`（沿用） | — |
| M17-14 | M `replacementStatesSurviveJournalReplayImageAndCheckpointWithIdenticalStatus`；P `restorationAllowsLowerPendingOrActiveAtAnyTimeWithoutInferringAnActivatedBase` | S11、S17–S18 |
| M17-15a | — | S19–S20 |
| M17-15b | — | S21–S23 |
| M17-15c | M `duplicateImportReturnsOriginalVersionEvenWhenCompatibilityProbeFails`、`LicenseFeCompatibilityTest`（沿用） | S13（新加入且离线的 FE 使导入返回 503） |
| M17-16 | P `rejectsWrongDeploymentTimeCapabilityAndReadinessWithoutStateMutation`、`recheckRejects…`（沿用） | — |
| M17-17 | P `changesAreFacts…`；M `lowerRenewalIsAccepted…`、`formerReduction…` | S05（HTTP/SQL validate 与 SQL import 一致）、S15（页面 validate 与 import 一致） |
| 页面 | U `U05-replacement-changes-validate-and-import-en/zh-CN`（缩短、降额、丢弃 pending）、`U05-no-changes-and-untrusted-change-shapes` | S15 真实页面 |

### 7.4 真实运行

单 FE 隔离实例：2026-10-05 发行包 `massdb-sql-2.0.5-license-followup` 加 `checks-v2` 的 FE JAR（内嵌本轮 UI），JDK 17.0.4，端口 293xx，`edit_log_roll_num = 20` 以便短时间内产生真实 checkpoint image。证书用自用签名私钥为该临时部署签发，经签发工具 `--previous` 预检；其他 FE/BE 是无进程的注册身份。每步命令与结果在 `runtime-v5/transcripts/`，截图在 `runtime-v5/screenshots/` 与 `runtime-v5/ui/`。

| 步骤 | 操作 | 观测 |
| --- | --- | --- |
| S01–S02 | 导入 C1（40 天，FE 3/BE 3）；注册离线 Observer 1 个、BE 2 个 | FE 2/BE 2；BE `Alive=false`、`TabletNum=0` |
| S03 | 签 C2（180 秒后到期，FE 1/BE 1）：签发工具通过并提示缩短、双降额；SQL import、HTTP validate | 均 `LICENSE_NODE_LIMIT_TOO_SMALL`（6201/45000、HTTP 400），最高序号仍 1 |
| S04 | DROP Observer 后 HTTP import | 仍 400：离线 BE 仍计数 |
| S05 | DROPP 1 个 BE（FE 1/BE 1），C1 仍有 40 天：HTTP validate、SQL validate、SQL import | 三者 `changes` 相同：`EXPIRY_SHORTENED`、`FE_LIMIT_REDUCED 3→1`、`BE_LIMIT_REDUCED 3→1`；导入成功，状态 EXPIRING、到期为 C2，`max_*`/`base_max_*` 为 1，`SHOW LICENSE` 与 HTTP 一致 |
| S06–S07 | ADD Observer / BE；重新导入 C1 | 6202/45000 `LICENSE_FE/BE_LIMIT_EXCEEDED`；C1 只返回原回执（sequence 1），期限与额度不恢复 |
| S08 | 等到 C2 到期 | `trusted_utc == expires_at` 时状态转 EXPIRED |
| S09 | HTTP 导入 C3（60 天，3/3），再 ADD BE | `changes` 为空，基础额度回到 3/3，ADD 成功 |
| S10 | SQL 导入 C4（180 秒后生效，2/2） | `FE/BE_LIMIT_REDUCED 3→2`；基础额度仍 3/3，但 ADD 第 2 个 FE 成功、第 3 个 FE 和第 3 个 BE 被拒 |
| S11 | C4 生效前重启 | pending、基础额度与 ADD 上限恢复一致 |
| S12 | 等待 C4 生效 | 维护线程复核用量 2/2 后提交基础额度 2/2，pending 清空 |
| S13 | 离线 Observer 仍注册时 HTTP 导入 C5 | 既有包门禁返回 503 `LICENSE_FE_UPGRADE_REQUIRED`、未提交；缩容到 1/1 后导入 C5（1 天后生效）成功 |
| S15–S16 | 真实浏览器登录 FE 页面，预检并确认导入 C6（65 天，1/1） | 预检与导入结果都显示 `EXPIRY_SHORTENED`、`FE/BE_LIMIT_REDUCED 2→1`、`PENDING_DISCARDED`（C5）；刷新后 active 为 C6、pending 为空；C5 回执仍为 APPLIED |
| S17–S18 | 执行 45 条 DDL 使 journal 滚动，等待 checkpoint 生成覆盖全部许可记录的 image.166 后重启 | 从 image.166 恢复；状态和 `SHOW LICENSE` 与重启前相同，ADD 超额仍被拒 |
| S19–S20 | 导入 C7（仅缩短到期，记录留在 image 之后的 journal），换上一发行包 JAR 启动 | 旧包回放成功，状态与新包一致（不支持的回退，仅记录） |
| S21–S23 | 换回新包，导入 C8（2/2）与重叠的较低 pending C9（1/1），再换上一发行包启动；最后换回新包 | 旧包 FE 在回放 C9 记录时 `replay Operation Type 6201` 后进程退出；新包恢复同一元数据，pending C9 保留 |
| S24 | 清理离线身份 | BE 0，FE 1；安装已停止并删除 |

### 7.5 未验证边界与纠正

- 未执行：线上 BE 数据迁移、真实多 FE 切主、真实混包部署、性能基线；真实运行的其他 FE/BE 是无进程的注册身份，未运行业务查询，查询在空档/过期时被拒绝由单元测试覆盖，真实运行只观察到状态切换。
- M17-04（进行中的 ADD 预留）在 FE 内与导入串行于同一提交队列，外部无法制造“预留中”的窗口；由策略单测的预留计数和 Manager 的成员竞争用例覆盖。
- 未构建新的完整发行包，也未提交代码；真实运行使用 2026-10-05 发行包加本轮 `checks-v2` 的 FE JAR。R1–R5 已满足第 5 节的打包前提，打包与包内复核需另行执行。
- 第 2.5 节对旧包回放的表述需要补充：旧包逐条回放最近 image 之后的 journal，每条许可记录都携带完整状态，因此能否回放取决于“待回放区间内是否出现过重叠低额 pending 状态”，而不只是当前状态。旧包遇到该状态时 FE 进程退出，而不是带着未就绪状态继续运行。
