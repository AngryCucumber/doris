<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# 许可降级兼容、内置公钥与取消导入前 FE 检查执行计划

初稿：2026-10-15；2026-10-16 修订：按用户意见取消导入前的 FE 兼容检查，删除兼容版本号方案，只保留首次初始化时的许可模块检查。状态：R0 已于 2026-10-16 由用户确认（采用 D1；保留首次初始化时的许可模块检查；包名沿用 `massdb-sql-2.0.5-license` 并替换现有包）；R1–R5 已于 2026-10-16 完成，验收见第 7 节。R6 的打包要求干净的工作区，在本地提交之后进行，结果只记在 `.build-records/license-downgrade-trust-compat-20261015/package-v1/`，不回写本文。源码基线：`2.0.5-license` / `c9b69a9a6b0`（本地提交，未推送），对应发行包 `massdb-sql-2.0.5-license-bin-arm64`。前一轮见[取代式续期执行计划与验收记录](license-renewal-replacement-plan-20261015.md)。

**本轮目标：**

1. **降级不受证书影响。** 任何带许可的新版写入的许可元数据，所有已发布的带许可旧版都能原样恢复：FE 能启动，证书、额度、回执不变，查询正常。Doris 自身的降级流程不因许可功能多出限制。
2. **内置公钥。** FE 默认从 `doris-fe.jar` 内置的公钥清单加载验签公钥，不再因为缺少外部文件或 `fe.conf` 配置行而无法就绪。
3. **导入证书前不再检查其他 FE。** 不再要求各 FE 的 `doris-fe.jar` 或公钥清单文件一致，不再对 JAR 计算 SHA-256，离线 FE 也不再挡住导入；证书按取代式规则直接覆盖，提交结果不确定时用同一证书重复提交即可（已有指纹幂等）。只在许可首次初始化前确认所有 FE 都带有许可模块。
4. **补测此前列为未验证的项目。** 能在本机做的本轮做，做不了的写明原因和所需环境。

改动限于 FE 许可管理类、FE 资源文件、打包叠加脚本、测试与文档。不改查询准入热路径、BE、通信协议、SQL 语法、HTTP 参数，**不改许可持久化格式**。

## 1. 现状与问题

### 1.1 公钥依赖外部文件

- `massdb_license_trust_store_file` 默认值为空，全靠发行包 `fe/conf/fe.conf` 第 88 行指向 `conf/massdb-license-trust.json`。
- 缺少这行配置或这个文件时，FE 能启动，但许可一直未就绪，受保护查询返回 6200 `LICENSE_NOT_READY`。[升级验证 U8](/data/project/massdb-sql/.build-records/license-renewal-replacement-20261015/upgrade-v1/README.md) 已实测。升级时沿用旧 `fe.conf` 或漏拷文件就会踩到。
- 清单只含公钥（`kid`、`purpose`、`public_key_spki`），来自 2026-09-29 生成的自用密钥，各发行包字节相同（sha256 `b7b7e54f…`）。私钥不在包内。

### 1.2 导入前的 FE 兼容检查过严

- 首次初始化部署身份和导入证书前，Master 探测全部已注册 FE，要求 `doris-fe.jar` 文件 SHA-256（`package_sha256`）和公钥清单文件 SHA-256（`trust_sha256`）都与自己相同，并核对格式版本、操作码和节点身份（`LicenseFeCompatibility`）。
- 上次成功导入时的“Master JAR 哈希、清单哈希、FE 成员集合”记在持久化记录的 `rollout` 字段；三者不变则导入时不再探测。
- 问题：只改了无关代码的热修复包、同一源码重新编译的 JAR、只调整了清单 JSON 格式，都会被判为不一致而挡住导入；新加入的离线 FE 也会挡住（R4 S13 实测 503 `LICENSE_FE_UPGRADE_REQUIRED`）。
- 这个检查真正防的是“Master 提交成功后，其他 FE 回放不了这条记录而进程退出”。记录已经持久化，重复提交解决不了，只能升级那台 FE。只要新版不写旧版读不了的记录（第 2.1 节 D1、D2），这种退出就不会发生，检查也就没有必要。
- 旧版对 `rollout` 严格校验：为 `null`，或恰好是 `package_sha256`、`trust_sha256`、`frontend_version` 三个字段、前两个为 64 位十六进制。

### 1.3 降级风险只来自一种状态

旧版逐条回放最近 image 之后的 journal，每条许可记录都带完整状态；恢复校验失败时 `EditLog` 直接让 FE 进程退出。各版本恢复校验的差别：

| 版本 | 恢复时对额度的要求 | 示例 JAR |
| --- | --- | --- |
| 2026-09-30 之前（P2–P4，含 09-29） | 基础额度 ≤ active；active、基础额度 ≤ pending（任何较低 pending 都拒绝） | `.build-records/license-http-admission-20260929/checks-v3/doris-fe.jar` 等 |
| 2026-09-30 至 10-05 | 基础额度 ≤ active；仅当 active/基础额度的到期晚于 pending 生效时，要求 pending 不更低 | `runtime-v5/old-package-jars/`（10-05 发行包） |
| `c9b69a9a6b0`（本轮基线） | 不再比较跨槽额度 | 当前发行包 |

旧版都不检查到期时间和功能集。因此本轮基线允许的情况中，立即生效（含到期更早、额度更低）、丢弃 pending、移除功能、留空档，旧版都能读；**只有“额度低于当前 active/基础额度的未来生效证书”会让旧版退出**（R4 S20 回放成功、S22 退出）。

## 2. 规则设计

### 2.1 降级约束

| 编号 | 约束 | 做法 |
| --- | --- | --- |
| D1 | 只写所有带许可旧版都能恢复的状态 | 拒绝“未来生效（`not_before > 可信时间`）且 FE 或 BE 额度低于当前 active 与基础额度较大者”的候选，返回已有的 `LICENSE_RENEWAL_REDUCTION`（HTTP 400、SQL 6201），保旧、不消费序号。与 active、基础额度比较时都不看它们是否已到期，以覆盖 09-30 之前版本；比较对象是导入后仍会保留的 active 与基础额度（已到生效时间的旧 pending 按 active 计）。立即生效的降额、等额或更高的未来证书照常接受。**R0 已确认采用** |
| D2 | 许可持久化格式冻结 | journal/image 中许可记录的字段、操作码、取值格式不变；`changes` 等新信息只出现在响应中。加固定样本测试防止误改。取消导入检查后，D1、D2 是混版本集群与降级安全的唯一保障 |
| D3 | 外部公钥清单继续随包提供 | 旧版 JAR 只从外部文件读公钥，包里继续提供 `conf/massdb-license-trust.json` 和 `fe.conf` 配置行；新版内置清单与外部文件取并集 |
| D4 | 换钥纪律 | 新公钥先随一个版本发布（内置并写入外部文件），在可降级的时间窗口内仍用旧私钥签发；旧公钥在所有可能降级到的版本都不再需要后才移除 |

D1 取代上一轮的 M17-06（接受低额未来证书）。上一轮的等待期 ADD 取 base/pending 较小值的代码保留，但在 D1 下 pending 不会低于基础额度。若生产环境已用 `c9b69a9a6b0` 包导入过低额未来证书，新版仍能恢复该状态；该状态被立即生效证书替换并进入新 image 之前，降级仍不安全，运维文档写明处理步骤。

不在范围内：降级到完全没有许可模块的版本。那类版本不认识许可 journal 操作码和 image 模块，需另行配置 Doris 的 `ignore_unknown_metadata_module` 与 `skip_operation_types_on_replay_exception`，与证书规则无关。

### 2.2 内置公钥

- 把只含公钥的清单纳入仓库（位置在 R2 定，如 `fe/fe-core/src/main/resources/massdb/license/builtin-trust.json`），构建时打进 `doris-fe.jar`。内容与 `b7b7e54f…` 相同字节；单元测试固定其 SHA-256 和 kid 集合，防止误打进其他公钥。
- 加载顺序：内置公钥总是加载；若配置了外部文件且可读，按现有严格规则解析并合并。同一 `kid` 公钥或用途不一致视为冲突，拒绝外部文件并告警，内置公钥仍有效。外部文件缺失或损坏只告警，不再导致未就绪。
- `license` 与 `time_repair` 用途隔离不变；不内置任何私钥。
- `Config.massdb_license_trust_store_file` 说明改为“可选，追加公钥”；默认值仍为空。

### 2.3 取消导入前的 FE 检查

- **导入（SQL、HTTP、页面）**：Master 不再探测其他 FE，不比较 JAR 与公钥清单，不再对 JAR 计算 SHA-256；不再因 FE 离线、JAR 不同或公钥文件不同而返回 `LICENSE_FE_UPGRADE_REQUIRED`。取代式规则、实际用量检查、成员版本复核（`STALE_IMPORT_DECISION`）和指纹幂等不变。随探测一起去掉 FE 成员摘要（`frontendVersion`）的提交前复核；FE 数量变化仍由成员版本复核覆盖。
- **持久化**：新版导入时 `rollout` 写 `null`。格式不变，旧版本来就接受 `null`，读到后只会在它自己导入时重新探测。
- **首次初始化部署身份（每个集群只发生一次）**：保留探测，但只确认所有已注册 FE 都带有许可模块，即能通过管理端口返回许可能力信息，且模块名、格式版本、journal 操作码与节点身份一致；不再比较 JAR 与公钥清单摘要。用于保护“从不带许可模块的版本滚动升级到许可版本”：Master 先升级完时不会立即写入旧 FE 不认识的初始化记录。**R0 已确认保留**。
- **能力接口** `GET /api/license/capability`：继续提供，供首次初始化探测与诊断；`package_sha256` 字段不再计算，返回 `null`。旧版 Master 若仍在任，按旧规则比较该字段会不一致并拒绝导入，这是旧代码行为，文档写明“混版本时请在新版 Master 上导入”。
- **公钥不一致的 FE**：不再在导入时拦截。缺少某把公钥的 FE 在导入后会把对应证书视为无效、拒绝本机受保护查询，可从该 FE 的状态接口看出；内置公钥与 D3 使各版本拿到同一把公钥，正常情况下不会发生。
- **以后若有版本不得不改许可记录格式**：没有自动门禁，只能靠 D2 与发布流程；该版本须在发布说明中声明“不能与旧版混跑、不能降级”。

### 2.4 不变的部分

证书指纹（证书原文 SHA-256，用于回执与幂等）、证书声明中的 `schema_version`/`policy_version` 校验、取代式续期的其余规则与 `changes`、回执上限、限流、脱敏、权限、转发、查询准入、ADD 额度、时钟规则均不变。

## 3. 改动清单

| 文件 | 改动 |
| --- | --- |
| `LicenseImportPolicy` | D1 检查；`changes` 计算不变 |
| `LicenseTrustStore`、`LicenseManager.loadTrust` | 内置清单加载、外部文件合并与冲突处理；就绪条件只依赖“至少有一把可用的 license 用途公钥” |
| `fe-core` 资源 | 内置公钥清单；`LicenseTrustStoreTest` 固定摘要与 kid |
| `LicenseManager` | 导入路径去掉 `matchesRollout`、探测与 `frontendVersion` 复核；写入 `rollout = null`；首次初始化仍调用模块检查 |
| `LicenseFeCompatibility`、`EnvLicenseHost` | 只服务首次初始化：比较模块、格式版本、操作码与节点身份；删除 JAR 摘要计算；能力接口 `package_sha256` 返回 `null` |
| `LicensePersistRecord` | 保留读取与校验旧 `rollout`；新写入为 `null` |
| `Config`（fe-common） | 外部清单说明改为可选；`massdb_license_fe_management_ports` 说明改为仅用于首次初始化 |
| 打包叠加脚本（`package-v1/package_overlay.py` 的后续版本） | 继续放入外部清单和 `fe.conf` 配置行（D3），校验与内置清单同字节 |
| 签发工具 README | D4 换钥纪律；降额须签立即生效的证书（D1） |
| 文档 | P0 契约管理协议、导入核心（D1）、管理说明（升级、降级、混版本导入）、取代式续期计划第 2.5/7.5 节与 M17-15c、MODIFICATIONS.md |

## 4. 测试计划

### 4.1 单元测试

| 范围 | 用例 |
| --- | --- |
| D1 | 未来低额：仅 FE、仅 BE、两者都低；对 active；active 过期后对基础额度；与已有 pending 并存；等额与更高未来证书接受；立即降额接受；拒绝后状态、最高序号、回执不变；validate 与 import 一致 |
| 内置公钥 | 无外部文件即就绪；外部文件追加新公钥；kid 冲突拒绝外部文件但保持就绪；外部文件损坏、缺失只告警；用途隔离；内置清单摘要与 kid 固定 |
| 导入不再检查 FE | 其他 FE 离线、JAR 摘要不同、公钥清单不同时导入成功；`rollout` 写 `null`；旧 `rollout` 记录仍可恢复 |
| 首次初始化 | 有 FE 无许可模块（探测失败）时不初始化；全部带模块时初始化，不比较 JAR 与公钥摘要；初始化与成员变化、切主的现有用例保持通过 |
| 格式冻结 | 用 10-05 与 `c9b69a9a6b0` 写出的许可记录样本做固定样本测试，确认新代码写出的字段集、操作码与取值格式不变 |

需改写的现有测试：

- `LicenseManagerTest`：`duplicateImportReturnsOriginalVersionEvenWhenCompatibilityProbeFails`（原断言 FE 版本变化后返回 `LICENSE_FE_UPGRADE_REQUIRED`，改为导入成功）；以导入探测作为并发挂点的用例，如 `acceptedMemberChangeInvalidatesAnImportPreparedBeforeItsCommit`、`memberGrowthBeforeLowerRenewalCommitRejectsTheStaleDecision`、`differentConcurrentCandidatesRecheckTheCommittedVersionAndOnlyOneGetsAReceipt`、`concurrentIdenticalImportsConfirmOneDurableReceiptWhenPublicationFails`，改用新的挂点保持原有竞争断言；`lowerFuturePendingCapsAddsNowAndActivatesOnlyAfterRecheckingUsage` 改为断言 D1 拒绝。
- `LicenseFeCompatibilityTest`：删除 `package_sha256`、`trust_sha256` 比较用例，保留模块、操作码、节点身份与探测失败用例。
- 首次初始化相关用例（如 `initializationProbeDoesNotHoldMemberQueueAndCannotCommitAcrossMemberChanges`、`identityIsCommittedOnlyByCompatibleMasterAndSurvivesRecovery`）保留并继续通过。

全部 `License*Test`、签发工具测试、UI 构建与 `test:license` 须继续零失败。实施时逐条复核所有 `LICENSE_FE_UPGRADE_REQUIRED` 断言：属于导入路径的改写，属于首次初始化的保留。

### 4.2 真实运行（含此前未验证项）

“来源”指首次被列为未验证的记录。

| 编号 | 场景 | 来源 | 本轮处理 |
| --- | --- | --- | --- |
| V1 | 新版依次做立即缩短、立即降额、丢弃 pending、等额/更高未来 pending、空档后，换回 10-05 FE JAR；分别覆盖“记录在 journal 尾部”和“记录在 image 中”两种恢复路径 | R4 只测了立即缩短与重叠低额 | 执行 |
| V2 | 同 V1，换回 09-30 之前的 FE JAR（如 `license-http-admission-20260929/checks-v3`，需找到配套的 `fe-common`） | 新增 | 执行；若配套 JAR 不全则记录原因 |
| V3 | 低额未来证书经 SQL、HTTP、页面导入均被拒，状态不变 | 新增（D1） | 执行 |
| V4 | 删除外部清单与 `fe.conf` 配置行，新版用内置公钥正常就绪、查询正常（U8 反转）；同样条件下 10-05 版仍未就绪，记录为降级须保留文件的依据 | U8 | 执行 |
| V5 | 外部清单损坏、追加新公钥、kid 冲突 | 新增 | 执行 |
| V6 | 3 个 FE（Master、Follower、Observer，Docker 网络各占一个 IP）从 10-05 逐台滚动升级：每一步查询正常；新版 Master 加旧 FE 时导入直接成功，旧 FE 回放新记录正常；旧版 Master 在任时导入按旧规则被拒（记录） | P2/R4/打包均未覆盖多 FE 滚动升级 | 执行 |
| V7 | 切主：新版 Master 停止，Follower 接任；许可状态、额度、导入一致 | 2026-09-30、10-15 未覆盖真实切主 | 执行（在 V6 环境中） |
| V8 | 有 FE 离线、各 FE 的 JAR 字节不同（热修复或重新编译）时导入成功；离线 FE 恢复后回放正常 | R4 S13 为旧门禁行为 | 执行（在 V6 环境中） |
| V9 | 多 FE 整体降级回 10-05，含 Observer | 新增 | 执行 |
| V10 | 升级时沿用旧版 `fe.conf`（不含信任配置行的变体） | 升级验证只替换了 JAR | 执行 |
| V11 | 从不带许可模块的版本滚动升级：先升级 Master 时不初始化，全部 FE 升级后才初始化，旧 FE 不退出 | 新增（首次初始化检查） | 条件执行：在临时 worktree 编译无许可版本的 FE JAR（如 `9a5861f45af`）；编译不成则以单元测试覆盖并记录 |
| V12 | BE 二进制升级/降级 | 升级验证 BE 全程为新二进制 | 不执行：旧发行包已删除，未找到旧 BE 二进制；许可不涉及 BE。如需要，用户提供旧包 |
| V13 | 真实麒麟 / 64 KiB 页内核主机 | 打包验证 | 不执行：本机没有该环境，需用户提供主机 |
| V14 | Cloud Meta Service、Broker、Hive UDF、CDC 客户端实际运行 | 打包验证 | 不执行：与许可无关，只保留构建/版本检查；如需要另立任务 |
| V15 | 性能 | 各轮均未做 | 不执行：不改查询热路径；导入与启动路径的耗时随运行记录一并给出 |
| V16 | 降级到无许可模块的版本 | 新增 | 不执行：范围外，见 2.1 |

V1–V11 每个关键步骤保留命令、返回码和终端样式截图，证据存 `.build-records/license-downgrade-trust-compat-20261015/`；测试安装结束后删除。

## 5. 实施顺序与完成条件

| 阶段 | 工作 | 完成证据 |
| --- | --- | --- |
| R0 决策 | (1) 是否采用 D1，拒绝低额未来证书；(2) 是否保留首次初始化时的许可模块检查；(3) 新包名是否沿用 `massdb-sql-2.0.5-license` 并替换现有包 | 已完成：2026-10-16 用户确认三项均按推荐（采用、保留、沿用并替换） |
| R1 降级约束 | D1、D2 及单元测试 | Policy、Manager、格式样本测试通过 |
| R2 内置公钥 | 资源、加载与合并、测试 | TrustStore、Manager 测试通过 |
| R3 取消导入检查 | 2.3 的导入路径、`rollout`、首次初始化检查、能力接口 | Manager、FeCompatibility、Controller 测试通过 |
| R4 文档 | 第 3 节文档 | 链接、源码头、`git diff --check` 通过 |
| R5 真实验证 | V1–V11 | 运行汇总 JSON 绑定 JAR 摘要、截图与各步返回码 |
| R6 打包与提交 | 全量构建、包检查、冒烟、替换 `output/` 中的包；按 AGENTS.md 本地提交 | 包内 MANIFEST、冒烟记录、提交说明 |

交付门槛：R1–R5 全部完成才打包。R1 消除降级风险，且是 R3 取消导入检查的前提，二者必须同一轮交付；R2 消除“漏配公钥导致查询被拒”的升级风险。

## 6. 风险与应对

| 风险 | 应对 |
| --- | --- |
| D1 去掉了“提前导入低额未来证书”的能力 | 降额改为签发立即生效的证书，或到生效日再导入；文档与签发工具 README 写明 |
| 取消导入检查后，若将来某版本改了许可记录格式，混版本集群或降级时旧 FE 可能退出 | D2 冻结格式并以固定样本测试守护；确需改格式的版本须在发布说明中声明不能混跑、不能降级 |
| 公钥不一致的 FE 不再被导入拦截 | 内置公钥与 D3 使各版本公钥相同；不一致时只影响该 FE 的查询，可从其状态接口发现；换钥按 D4 |
| 混版本时旧版 Master 仍按旧规则拒绝导入 | 旧代码行为，无法改变；文档写明在新版 Master 上导入，或全部升级后导入 |
| 内置公钥后换钥需要发版 | 自用密钥长期不变；换钥按 D4，外部文件可临时追加公钥 |
| 外部清单被篡改追加公钥 | 与现状相同：能改 FE 配置目录者本就能替换 JAR；追加不能覆盖内置 kid（冲突即拒绝） |
| 生产已存在低额未来 pending（若已部署本轮基线包） | 降级前先导入立即生效证书替换，并等待覆盖该记录的新 image；运维文档给出检查步骤（[管理说明第 5.2 节](license-management-p2.md#52-降级前处理遗留的低额未来-pending)，实测见 7.6） |
| 多 FE 测试环境较重 | 沿用已验证的 Docker 网络方案（每个 FE 独立 IP），记录资源与耗时 |

## 7. 验收记录（2026-10-16）

证据目录 `.build-records/license-downgrade-trust-compat-20261015/`，汇总见其中的 `README.md`。证书原文不进入记录与截图，只记指纹前缀；测试安装在每次运行结束后删除。

### 7.1 实现

| 阶段 | 结果 |
| --- | --- |
| R1 | `LicenseImportPolicy` 拒绝未来生效且 FE 或 BE 额度低于导入后保留的 active 或基础额度的候选，返回 `LICENSE_RENEWAL_REDUCTION`（不看 active、基础额度是否到期）；`LicensePersistRecordTest` 用固定样本锁定持久化字段集与 `rollout` 形状 |
| R2 | 内置清单 `fe/fe-core/src/main/resources/massdb/license/builtin-trust.json`（sha256 `b7b7e54f…`，与外部文件同字节）；`LicenseTrustStore.builtIn()`、`merge()`；`LicenseManager.loadTrust` 总是加载内置公钥，外部文件可读且不冲突时合并，否则告警并忽略外部文件 |
| R3 | 导入路径不再探测其他 FE、不再计算 JAR 摘要、不再复核 `frontendVersion`，提交时写 `rollout = null`；首次初始化仍探测，只比较模块、格式版本、操作码与节点身份；能力接口 `package_sha256` 为 `null` |
| R4 | 第 3 节所列文档、Config 与 `conf/fe.conf` 注释、签发工具 README、`MODIFICATIONS.md`、页面中英文错误文案 |

### 7.2 自动化检查

| 检查 | 结果 |
| --- | --- |
| `checks-v3/` | `fe-common`、`fe-core` 打包含 Checkstyle 通过；33 个许可相关测试类 358 个用例零失败零跳过 |
| `ui-v1/` | UI 构建、`check:notices`、`test:legal`、`test:license`（含新增 U05 中英文用例）通过 |
| `issuer-tests-v1.log` | 签发工具 32 个用例通过 |
| 仓库检查 | `build-support/check-source-headers.py`、`git diff --check`、许可文档本地链接检查通过 |

### 7.3 真实运行

| 编号 | 结果 | 记录 |
| --- | --- | --- |
| V1、V2 | 新版写入立即缩短、立即降额、等额未来 pending、丢弃 pending、空档后，2026-10-05 与 2026-09-29 两个旧版 FE 都能从 journal 尾部和 image.120 恢复，许可事实不变，查询正常 | `single-v2/` |
| V3 | 1 天后生效、FE 额度更低的证书：SQL 返回 6201（45000），HTTP 400，页面显示拒绝说明且不能确认导入；状态不变 | `single-v2/`（含 `ui/v3-page-rejected.png`） |
| V4、V10 | 删除外部清单与 `fe.conf` 配置行后，新版用内置公钥就绪、查询正常；同样条件下 2026-10-05 版 `LICENSE_NOT_READY`、查询返回 6200，确认 D3 必要 | `single-v2/` |
| V5 | 外部清单损坏或 kid 冲突：告警并忽略，内置公钥照常可用；外部清单追加的新 kid 签的证书可导入 | `single-v2/` |
| V6 | 3 个 Follower + 1 个 Observer + 1 个 BE 从 2026-10-05 逐台升级，每步查询正常；旧版 Master 在任时导入按旧规则返回 503（记录）；旧版 FE 回放新版写入的记录并持续运行 | `multi-v2/` |
| V7 | 旧版 Master 停止后新版 Follower 当选，状态与额度一致，随后导入成功 | `multi-v2/` |
| V8 | 有 FE 离线、有 FE 使用字节不同的 JAR 时导入均成功；离线的旧版 FE 恢复后回放正常 | `multi-v2/` |
| V9 | 四个 FE 整体换回 2026-10-05 JAR，全部就绪，许可事实不变，经各 FE 查询正常 | `multi-v2/` |
| V11 | 用 `9a5861f45af` 编译的无许可 FE 组成两节点集群；先升级 Master 时不初始化（`CAPABILITY_MISMATCH`），旧 Observer 继续运行；升级 Observer 后初始化一次，两节点部署身份相同 | `prelicense-v2/` |

失败后修正重跑的尝试（`checks-v1`、`checks-v2`、`single-v1`、`prelicense-v1`、`multi-v1`）原样保留，原因都在测试代码或测试脚本，见证据目录 README。

### 7.4 与计划的差异

- 公钥合并的冲突条件比 2.2 节多一条：同一把公钥出现在两个用途下也视为冲突。
- 能力接口的 `trust_sha256` 改为按公钥集合计算的摘要（与清单 JSON 的排版无关），只用于诊断，不参与任何比较。
- `lowerFuturePendingCapsAddsNowAndActivatesOnlyAfterRecheckingUsage` 拆成两个用例：D1 拒绝新导入；另用恢复路径构造 `c9b69a9a6b0` 可能写下的低额 pending，确认新版仍能恢复并正确限制 ADD。
- V2 找到了配套的 `fe-common`（`license-http-admission-20260929/checks-v3/`），完整执行。V6 的拓扑比计划多两个节点（3 个 Follower + 1 个 Observer）。V11 在临时 worktree 编译成功，按真实运行执行。
- V9 没有强制先生成 image；journal 与 image 两条恢复路径由 V1、V2 分别覆盖。

### 7.5 未执行

V12（BE 二进制升级/降级，旧 BE 二进制不可得）、V13（麒麟 / 64 KiB 页内核，本机没有）、V14（Cloud Meta Service、Broker、Hive UDF、CDC 客户端实际运行，与许可无关）、V15（性能，未改查询热路径）、V16（降级到无许可模块的版本，范围外）。多 FE 场景都在同一主机的 Docker 网络中，未覆盖跨主机网络。

### 7.6 补充演练：遗留低额未来 pending 的降级（2026-10-16）

证据目录 `.build-records/license-legacy-pending-downgrade-20261016/`（README、转写、截图、各变体日志摘录）。写入方是 `c9b69a9a6b0` 发行包 FE JAR，替换在 `4f53a3e9585` 发行包或 `c9b69a9a6b0` 上进行，降级目标是 2026-10-05 与 2026-09-29 FE JAR；每个降级变体在元数据副本上运行。据此写出[管理说明第 5.2 节](license-management-p2.md#52-降级前处理遗留的低额未来-pending)的操作步骤。

| 场景 | 结果 | 记录 |
| --- | --- | --- |
| 写入与识别 | `c9b69a9a6b0` 导入 C1（FE 3/BE 3，40 天）后再导入 1 天后生效、FE 2/BE 2 的 P，APPLIED；换新版后正常恢复，`/api/license`、`SHOW LICENSE` 与页面都显示该 pending（未生效、额度低于 active 与基础额度）；同类证书 SQL 返回 6201、HTTP 400，状态不变 | `single-v3/` A、B |
| 直接降级 | P 只在 journal 中或已进入 image 时，2026-10-05、2026-09-29 FE 都在启动时退出（退出码 255，`replay Operation Type 6201` 或加载 image 时 `Invalid MassDB license metadata envelope`）；在真实元数据上失败后换回 `c9b69a9a6b0` JAR，状态与查询不变 | `single-v3/` N1–N4，`c9b-v1/` H1b |
| 替换但无新 image | 导入立即生效、序号更高的 R（`changes` 含 `PENDING_DISCARDED`）后马上降级，两个旧版仍退出 | `single-v3/` E、N5、N6 |
| 替换并生成 image | 替换后 150 秒内无覆盖 J 的 image；`edit_log_roll_num` 运行时设 1 并写一次元数据后约 20 秒出现 image.88 > J = 50；两个旧版从 image.88 恢复就绪，事实不变，查询正常。在 `c9b69a9a6b0` 上直接替换同样可行 | `single-v3/` F、N7、N8，`c9b-v1/` H2、H3 |
| 有空档的变体 | pending 晚于 active 到期才生效时，2026-09-29 退出、2026-10-05 就绪 | `gap-v1/` |
| 3 FE | 2 Follower + 1 Observer + BE 从 `c9b69a9a6b0` 逐台升级，各 FE 都显示该 pending；在 Master 上替换并 roll 时 Observer 离线，它没有收到 image.120（`push succeeded 1 nodes`），用 2026-10-05 JAR 启动即退出；换回新版重新加入、再 roll 一次后三台都持有 image.158 > J = 98；整体降级到 2026-10-05、再到 2026-09-29 均就绪，事实不变，经各 FE 查询正常 | `multi-v1/` |

脚本缺陷导致的重跑（`single-v1`、`single-v2`）和 `single-v3` 末尾的清理报错原样保留，原因见证据 README。未验证：生产规模元数据下 checkpoint 与推送的耗时、跨主机网络、2026-09-30 至 10-05 FE 自己写入的空档变体、pending 到点生效后再降级、滚动降级。
