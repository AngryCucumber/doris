<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# License 分支代码审查

本轮日期：2026-10-22；源码基线：`28f6484bfd6bc4ca6bea7feaef2b6d03fbc31057`（分支 `2.0.5-license`）。
审查对象是该分支相对 `2.0.5` 的全部 18 个提交，合并基 `59329855b4e62497d927f3ccd547b866a190a0fc`，范围覆盖 `fe/fe-core/src/main/java/org/apache/doris/massdb/license/` 全部 26 个类（约 6.7k 行）以及 Env、SystemInfoService、EditLog/JournalEntity/OperationType、MetaReader/MetaWriter、BDBJournalCursor、StmtExecutor、ConnectProcessor、Coordinator/NereidsCoordinator/PointQueryExecutor、NereidsPlanner/StatementContext、InsertIntoTableCommand、ExportTaskExecutor、AuditLogHelper、SummaryProfile、HttpServer、Config 的许可挂钩。UI、签发工具和 `tools/license-checks` 只作为意图参考，未逐行审查。

本轮是纯源码审查：没有构建、运行测试或启动集群，没有修改本记录以外的任何文件。每条问题都沿完整调用路径核对过；文中行号对应上述基线。除源码外还分三个独立方向（持久化与回放、查询准入与热路径、密码学与时钟）做了交叉复核，三方结论一致的条目才记为“确认”。

## 1. 结论摘要

密码学验签、导入策略、管理入口鉴权、journal/image 边界、锁序和查询热路径开销都经得起推敲，没有发现普通用户可以绕过准入的缺陷。问题集中在两类：信任根可以被运维方自行替换；几个“粘滞”状态一旦触发就让整个集群停止受保护读取，且没有自助恢复手段。其中第 3、4 项在 [2026-10-04](license-review-remediation-20261004.md) 和 [2026-10-05](license-followup-review-20261005.md) 两轮记录中已被定性为既定契约；本轮不推翻该定性，但按生产集群规模（600 BE、多 FE、离线站点、主机曾出现时钟偏差）重新评估其触发概率与后果，仍列为重大。

## 2. 重大问题

| 编号 | 问题 | 代码依据 | 触发场景与影响 | 建议 |
| --- | --- | --- | --- | --- |
| R1 | 外部公钥清单无需任何签名即成为信任根，许可实质上可自签 | `LicenseManager.java:894-940` 读取 `massdb_license_trust_store_file` 后在 920 行 `merge`；`LicenseTrustStore.java:158-188` 对任意新 kid 的 `license`/`time_repair` 密钥一律并入，仅拒绝与内置密钥冲突的 kid 或密钥值 | 仓库自带的 `tools/license-issuer` 可完成 keygen、导出清单、签发不限节点且永不过期的证书，并自签时钟修复票据；每台 FE 配置该文件并重启即可。内置公钥因此没有起到约束作用。[管理手册](license-management-p2.md) 与 [2026-10-15 计划](license-downgrade-trust-compat-plan-20261015.md) 把并集描述为密钥轮换便利，属有意设计 | 若产品定位是自用、运维方即签发方，可以接受但应在威胁模型中写明。否则外部清单应由内置密钥反签名（JWS），或只在没有内置清单时作为兼容模式生效并告警 |
| R2 | “内置”清单可被 `conf/` 下同名文件整体替换 | `LicenseTrustStore.java:137` 用 classpath 查找 `/massdb/license/builtin-trust.json`；`bin/start_fe.sh:384` 把 `${DORIS_HOME}/conf` 放在 classpath 最前；主代码中没有对两把 SPKI 或资源摘要的硬编码校验（kid 与 SHA-256 只出现在测试和文档） | 在 `conf/massdb/license/builtin-trust.json` 放入自定义密钥并重启，内置密钥被替换而非追加，jar 校验和不变；厂商签发的证书反而验签失败被隔离 | 把两把 SPKI 字节或资源字节的 SHA-256 写成 Java 常量，加载结果不一致时失败关闭；或显式从 `doris-fe.jar` 的 code source 打开资源 |
| R3 | 时钟异常粘滞且集群级，常见运维事件即可造成整集群停读 | `LicenseClock.java:299-331`：回拨超 5 s（307 行）或自锚点累计前跳超 300 s（321 行）置 suspect；Master 在 `LicenseManager.java:1123` 一秒内持久化，所有 FE 回放后恢复该标志；`LicenseSnapshot.java:138-153` 返回 `CLOCK_SUSPECT`，`LicenseQueryStatus.java:23` 仅放行 VALID/EXPIRING；`LicenseImportPolicy.java:324-332` 同时拒绝导入；挑战绑定进程任期（`LicenseClockRepair.java:255`），Master 重启或切主即作废 | FE 启动后 chrony 对错误 RTC 做 step 校正、虚拟机暂停或热迁移、运维手工改时都能触发。前跳会被吸收为永久的可信进度，之后把墙钟改回又构成回拨。Follower 墙钟落后 Master 水位超 5 s 也会本机 suspect（`LicenseClock.java:253`），重启后下一次水位重现。唯一出路是厂商签发修复票据 | 回拨容差放宽到 12 小时并改为配置项；容差不参与可信时间计算，放宽不削弱防回拨。前跳只告警不拒绝，经观察期或 ADMIN 确认后才接受并持久化；启动与重启时墙钟超出持久化水位的部分同样作为待确认前跳处理，不再直接接受。可疑状态改为墙钟恢复后自动解除。签发方票据只保留给可信时间跑在真实时间前面的情形。见 7.2 R3 与其决策说明 |
| R4 | “恢复不完整”标志永久、随 image 扩散且无任何命令可清除 | `Config.java:42` 默认不探测被跳过记录，`Env.java:3186-3193` 对任何 `force_skip_journal_id` 跳过的日志调用 `markLicenseRecoveryIncomplete`；`EditLog.java:1478` 对八类成员操作的异常跳过同样如此；`LicenseManager.java:978` 之后没有任何置 false 的路径；`ready()`（468）与 `requireInitialized()`（473）同时失效；`saveImage`/`loadImage`（970/962）把标志写入并从 image 读回 | checkpoint Env 共享同一份跳过配置，会把标志写进 image 并推送到全部 FE。之后所有受保护读返回 `LICENSE_NOT_READY`，导入、时钟修复、ADD BACKEND/FRONTEND 全部被拒。文档补救是“从健康 FE 或备份恢复完整元数据”，但所有回放过该日志的 FE 内存中都已带标志，推送的 image 会在各 FE 下一次加载时继承它（在线 FE 的内存状态不立即变化），此后已无干净的元数据来源，备份也要回放同一段坏日志。Doris 标准应急手段因此变为不可逆的集群停读。同一路径还会把 `Env.licenseImageFormatRequired` 置真（`Env.java:934`），滚动升级期间尚未初始化就写出 141 版 image（`Env.java:2654`），未升级 FE 重启时无法加载 | 提供带签名或 ADMIN 授权的清除指令（`OP_MASSDB_LICENSE_INTEGRITY` 操作码已存在），定义清除后需要重新核对的事实，以及缺成员 FE 重新加载镜像的流程。标志仍须写入 image，探测选项保持默认关闭，按既有条件启用 |
| R5 | 生产升级与新建集群都存在停读/停扩容窗口 | `deployment_id` 在全部 FE 升级并通过探测初始化后才随机生成（`LicenseManager.java:1120`），证书绑定该 ID；未导入前 `queryStatus` 为 `LICENSE_NOT_READY` 或 `MISSING`；新集群导入前 `requireCapacity` 固定 `maxFe=1、maxBe=0`（`LicenseManager.java:706-709`） | 升级后到导入证书前所有表查询返回 6200，窗口长度等于厂商签发往返时间，离线站点可能以天计；新集群一台 BE 也加不进去。[2026-10-04 记录](license-review-remediation-20261004.md) 已说明没有宽限期 | 上线方案必须明确停读窗口；或允许按运维预先指定的 deployment_id 签发，或随包提供限时宽限证书 |

## 3. 中等问题

| 编号 | 问题 | 代码依据 | 影响 | 建议 |
| --- | --- | --- | --- | --- |
| M1 | `/dump` 独占许可提交线程和 Env 监视器 | `Env.java:6560-6570` 把整个 dump 放入单线程 `license-commit` 队列（`LicenseManager.java:659`）并持有 Env monitor；`runMembershipMutation`/`runImageSnapshot` 的 `future.get()`（631/675）无超时；`replayJournal`（3157）与 dump 同一监视器 | Master 上 dump 期间所有 ADD/DROP 节点、导入和水位提交排队；Follower/Observer 上阻塞回放，2M tablet 规模可能超过 `meta_delay_toleration_second` 使 Observer 停止服务。2026-10-05 记录已承认此代价 | 至少在管理手册中标注 dump 必须在低峰执行；评估 Follower 上是否可用已回放边界的只读快照替代持有回放监视器 |
| M2 | 各 FE 信任配置不一致会造成单机 INVALID 且无明显告警 | `LicenseFeCompatibility.java:170-209` 的兼容证明不比较 `trust_sha256`；`LicenseManager.java:901-907` 内置清单加载失败只告警；`LicensePersistRecord.java:331-346` 本机重验失败只隔离槽 | Master 用合并后的密钥接受证书，某台 Follower 重验失败即对本机所有受保护读返回 `INVALID`，状态页只在该机可见 | 导入时记录证书的 kid，回放侧隔离槽时按 kid 告警；或把 `trust_sha256` 纳入定期健康检查 |
| M3 | 重启或回放追赶期间返回 `retryable:true` | FE 在 `onReplayComplete`（`LicenseManager.java:983`）前所有受保护读返回可重试的 `LICENSE_NOT_READY` | 大积压 Follower 可持续数分钟，遵守该提示的客户端形成重试风暴 | 返回体增加建议退避时间，或在负载均衡健康检查中纳入许可就绪状态 |
| M4 | 执行边界需确认 | BACKUP TO repository、CCR/binlog 不经准入；INSERT ... SELECT 写入内部表不受限 | 若边界是“受保护数据不得离开集群”，前两者是绕过；若只限交互读取则无问题。2026-10-04 记录已把 BACKUP/CCR 列为保留通道 | 在产品文档中明确写出受限与不受限出口清单 |

## 4. 轻微问题

- 每 60 s 一条携带完整信封的 WATERMARK 日志（`LicenseManager.java:1130`），每天约 1,440 条、每条数 KB，所有 FE 回放并被每次 checkpoint 重序列化。间隔放到 10 到 30 分钟不影响防回拨强度，只影响重启后可信时间最多回退的幅度。
- 每条 SQL 文本在连接线程上被线性扫描 4 到 5 次（`LicenseSqlRedactor.java:229`）；`AuditLogHelper.java:91` 对原始字符串再扫描一次，没有复用 `OriginStatement.getSafeSql()` 的缓存。1 KB 语句约 10 µs，MB 级语句约 10 ms，低于已有 md5 与 ANTLR 开销。
- 初始化被阻塞时（任一 FE 离线或旧版）Master 每秒探测全部 FE 的 HTTP 端点，没有退避；日志每 60 s 限频一条。
- 元数据版本 141 占用了上游下一个版本号，`MetaContext` 在加载时记为 141；未来合并上游需专门迁移。2026-10-04 记录已指出。
- `LicenseManager.replay()` 内检测到版本链断裂时只标记本机不完整、不置 `licenseImageFormatRequired`；`appliedVersion==0` 时下一次 image 以 140 版空模块写出，标志随之丢失。只在 journal 本身不一致时可达，但一旦出现就等同于“从未初始化”，重启后 Master 可能重新生成部署 ID 并使原许可历史作废，应与 Env 侧标记对齐并持久化。

## 5. 已确认无问题

- 验签：对签名原文做严格字段集、base64url 规范化、ASCII 限制、Ed25519 单算法、64 字节签名和精确 kid 查找；无算法或密钥回退；所有异常路径拒绝；声明只从签名负载读取；签发工具的文本与整数边界与 FE 一致。没有任何配置可关闭验签；无可信公钥时导入与查询均拒绝。
- 导入策略：deployment 绑定、序号严格递增、license_id 与序号冲突拒绝、过期与未来签发拒绝、注册节点容量检查、幂等按 compact 的 SHA-256；SQL 与 HTTP 并发导入在单线程串行化，提交前复核许可与成员版本。
- 管理入口：九个 HTTP 路由均鉴权，非 STATUS 要求 ADMIN；SQL 在接收 FE 与 Master 各检查一次；转发请求要求 cluster token 常量时间比较；cookie POST 需同源 Origin 与自定义头；请求体 96 KiB 上限；错误体固定原因码；证书正文在审计、日志、profile 中脱敏；禁止服务端 PREPARE。
- 持久化：信封每个解析/空指针路径都转为 IOException；image 模块按下一索引偏移限长（≤2 MiB）并校验尾部字节与 CRC；140 版空模块可被旧 FE 跳过；操作码 6200 到 6205 无冲突；BDBJournalCursor 的 `advanceDatabase` 与上游等价并修复跨库首键被跳过的卡死；回执、修复记录与提交版本表均有上限，无无界增长。
- 查询热路径：`queryStatus()` 只读 volatile 快照与无分配时钟，每查询最多三次、合计约 0.3 µs；拒绝响应体只在拒绝时构造；无每查询锁、日志或节点遍历。正常路径另有两项固定开销未计入上面的数字：绑定阶段每张表、每个 TVF 与字典函数各记录一次事实，规划结束时 `NereidsPlanner.java:269` 调用 `finish()` 遍历一次物理计划判断是否为空计划，量级为微秒、与计划节点数成正比。以上数字均按指令路径推算，未实测。维护线程每秒一次成员摘要约 100 µs，不与查询竞争。
- 锁序：只有 Env monitor 到 LicenseManager monitor 一个方向；`membership()` 只读 ConcurrentHashMap 与 volatile map；无反向路径，无死锁。
- 节点配额：等于上限时查询放行、新增拒绝；回放路径只发布快照不抛异常；并发 ADD 在单线程串行，批内重复 host:port 提前拒绝；DROP 不受配额与就绪限制。
- 到期行为：`LicenseSqlException` 不进入任何服务端重试；排队后被拒时工作组令牌与查询登记在 finally 释放，无 BE 片段下发；`uncertainCommit` 在本树不可达（journal 写失败即退出进程）。

## 6. 建议处理顺序

按第 7.3 节的三个批次推进：批次 1 只改进程内逻辑，可先出自用包验证；批次 2 引入新文件格式与配置；批次 3 需要持久化信封升版，先全量部署能读 v2 仍写 v1 的包，再经探测开启写入。R1 与 M4 需要产品决策，在决策前至少把“运维方可自签”和出口清单写进威胁模型与手册；R5 属于上线方案，应与客户确认停读窗口或签发流程。在批次 1 发布前，运维手册应把 `force_skip_journal_id` 与改时操作标为“先联系签发方”。

## 7. 解决方案

本节只是设计，尚未实现；各项验证步骤也未执行。容差、间隔等数值为建议值，需在计划评审时确定。

### 7.1 总约束：持久化信封不能随意加字段

`LicensePersistRecord.validateEnvelope`（`LicensePersistRecord.java:455-464`）要求字段集合精确匹配，多一个字段旧版带许可 FE 回放时抛 `IOException` 并退出进程。因此方案分两档：第一档只改进程内逻辑、配置或新文件格式，不动信封，可直接滚动发布；第二档把 `format_version` 升到 2，需要分两步：先全量部署“能读 v2、默认仍写 v1”的版本，它在能力接口中上报 `format_version=2`；然后复用现有全 FE 能力探测（`LicenseFeCompatibility.checkAll`）在首次写 v2 前再探测一次，全部 FE 都上报 2 才允许 Master 写出 v2 记录。该探测目前只在初始化前运行，需要增加这个触发点。只按安装批次判断会让旧 FE 回放 v2 时退出；只等不能读 v2 的包上线，探测永远不会通过。下文每项标明所属档位。

### 7.2 逐项方案

| 编号 | 档位 | 做法 | 兼容影响 | 验证方式 |
| --- | --- | --- | --- | --- |
| R2 | 一 | 把两把 SPKI、kid、purpose 写成 `LicenseTrustStore` 的 Java 常量，`builtIn()` 直接由常量构造，不再做 classpath 查找。`src/main/resources` 的 JSON 只保留给打包 `conf/massdb-license-trust.json` 使用，并加单元测试断言资源字节的 SHA-256 等于常量推导值 | 无持久化变化；旧 FE 继续读外部文件 | 在 `conf/massdb/license/` 放伪造清单启动 FE，`GET /api/license/capability` 的 `trust_sha256` 仍等于内置摘要 |
| R1 | 一，需产品决策 | 外部明文文件降为只读兼容件：新版 FE 只接受与内置密钥完全相同的条目，多出的密钥忽略并告警。新增 `massdb_license_trust_manifest_signed` 指向 JWS 清单，签名方必须是内置 `license` 密钥或新增的专用 `trust` purpose 内置密钥；清单声明含 `keys`、`issued_at`、`sequence`，验签后再 `merge`。密钥轮换变为：签发方用旧密钥签含新密钥的清单，各 FE 配置后重启，下一版包把新密钥编入常量。若产品定位为自用且签发方即运维方，可不做签名，但须在威胁模型写明“运维方可自签”，并仍完成 R2 | 旧 FE 需要的明文文件照常发布，不再扩展信任；新配置旧 FE 忽略 | 自造密钥导出明文清单后导入证书必须 `UNTRUSTED_KEY`；内置密钥签的清单加入新密钥后导入成功 |
| R3 | 一为主 | 1）回拨容差从 5 s 放宽到 12 小时并改为配置项；Follower 回放水位差使用同一容差。2）前跳只告警、不拒绝。前跳幅度以已确认可信时间为基准，不再相对锚点墙钟样本；前跳后的进度先作为“待确认偏移”：不超过容差的前跳持续 5 分钟仍成立即自动确认；超过容差的前跳由 ADMIN 用新增命令确认，或在 1 小时内既未被校正也未被确认时自动接受，避免使用方靠拒绝确认把可信时间冻在水位上。未确认期间墙钟校正回来就直接丢弃，不需要重启或票据。查询、导入和水位都只使用已确认的可信时间。3）启动与重启纳入同一状态机：锚点的已确认时间只取持久化水位，墙钟高于水位的部分作为待确认前跳按第 2 项处理，不再直接取墙钟与水位的较大值；墙钟低于水位的部分仍按回拨判定。4）存在待确认偏移或回拨可疑时 `prepareCheckpoint` 返回 null，不写水位。5）回拨可疑不再粘滞：每次读取重新判定，墙钟回到已确认可信时间的容差内即自动解除；Master 已持久化的可疑状态在解除后写一条 `clock_suspect=false` 的 INTEGRITY 记录（新增 `withClockCleared`，形状不变）。6）Master 连续 5 分钟仍可疑才持久化，期间只告警。7）挑战跨切主持久化属第二档：把 nonce 与签发时间写入 v2 信封 clock 子树 | 第 5 项记录在现有形状内；旧版 FE 回放后不再置 suspect，但本机标志到重启才清，需写入手册。第 2、3 项改变了“前跳立即生效”和“启动取较大值”的现有行为，对签发方无风险；对使用方，容差内前跳最多推迟到期 5 分钟，超过容差的前跳最多推迟 1 小时 | 注入时钟源的单测覆盖：回拨 1 小时不报警且可信时间不变；回拨 13 小时报警、期间不写水位、墙钟恢复后自动解除；开机墙钟为 2000 年时启动即可疑，NTP 校正后自动解除，无需 ADMIN 或票据；重启时墙钟快 3 天：启动后查询按水位推进的可信时间评估、不写水位，1 小时内校正则丢弃、否则接受；前跳 10 分钟后 3 分钟内校正回来，无水位写入、无后遗症；前跳 3 天时查询仍按原可信时间评估，ADMIN 确认后接受，不确认并校正回来则丢弃。单 FE 真实改时演练一次 |
| R4 | 一 + 二 | 一档：保持现有标记与持久化行为。不按 `appliedVersion == 0` 放弃持久化，因为该值也对应 INITIALIZE 被跳过、后续记录断链未应用的情形，丢弃标志会让“历史丢失”伪装成“从未初始化”，重启后 Master 可能重新生成部署 ID 并使原许可历史作废。`massdb_license_probe_skipped_journal_header` 保持默认关闭：同一 database 其他键可读不能证明目标记录未损坏，读取物理损坏记录可能使整个 JE 环境失效（`EnvironmentFailureException`），捕获异常后返回“未知”也无法恢复环境，只按既有条件显式启用。`LicenseManager.replay()` 的链断裂通过 host 回调同步置 `licenseImageFormatRequired`，与 Env 侧对齐。手册补充：滚动升级期间不得使用 `force_skip_journal_id`，须先完成全部 FE 升级。二档：新增 `ADMIN LICENSE RECOVERY CONFIRM`，Master 写一条 v2 的 RESYNC 记录，内容为完整当前状态加确认信息（被跳过 journal id 列表、操作者、Master 当时的成员摘要）；回放规则改为 RESYNC 只要 deployment 一致、bootstrap 不变、activated 不回退且版本高于本机已应用版本就接受、不要求链式连续；接受时本机重算成员摘要，与记录一致才清除标志，不一致则保持不完整。CONFIRM 因此只能直接清除 Master 以及成员事实完整的 FE；曾跳过成员操作的 FE 其摘要必然不同，须在 Master 清除后重新加载下一次 checkpoint 镜像，或以新节点重新加入，由镜像补齐成员事实，镜像中的标志此时已为假。许可槽仍按本机信任重验，运维方不能借此伪造证书。若被跳过的 journal 含许可操作码 6200 到 6205，Master 自身的事实也可能缺失，CONFIRM 须带 FORCE 并在回执中列出丢失的记录版本，由 ADMIN 明确接受以 Master 当前状态为准 | 一档无持久化变化；二档需 v2 能力门 | 三 FE 集群：Master 对 OP_TIMESTAMP 做 force skip 并标记后，CONFIRM 清除 Master，随后的 checkpoint 镜像不带标志；某 Follower 对 ADD BACKEND 做 force skip 后，CONFIRM 不清除该 Follower，它重新加载新镜像后 BE 数量与 Master 一致且标志清除；新 FE 加载新镜像不继承标志 |
| R5 | 一 | 主方案：新增 `massdb_license_deployment_id`，只在 INITIALIZE 时读取，为空则随机生成；签发方提前生成 UUID 并签好证书，升级完成初始化后立即导入。两套集群填同一 ID 的风险与复制元数据相同，不新增攻击面。备选：允许 `deployment_id` 全零的通配证书，约束为有效期不超过 30 天、`highest_sequence == 0` 时才可导入、不计入序号历史；新建集群先用它加 BE。旧版 FE 回放通配证书会隔离槽，须全 FE 升级后使用 | 不改信封；两者都不用时停读窗口仍等于签发往返时间，上线方案须写明 | 预指定 ID 初始化后导入即 VALID；通配证书到期后替换为正式证书不中断 |
| M1 | 一 | Master 保留现有做法：dump 在变更队列内执行，成员变更与许可提交在 dump 期间排队，手册标注 dump 须在低峰执行。Follower/Observer 把“建立一致边界”和“写盘”拆开：在回放监视器内只做微秒级操作，原子读取 `committed`、`recoveryIncomplete` 与 `replayedJournalId`，返回冻结快照；随后释放监视器，许可模块从冻结快照写出，回放继续推进。许可记录不含成员信息，`replayAddBackend`/`replayDropBackend` 幂等，所以 FE/BE 清单来自更晚的 Env 不影响许可事实的恢复；但这确实是不同时间点的混合镜像，与上游 dump 相同，须由验证证明可恢复，不能只凭推理 | 无持久化变化 | Follower 上 dump 期间并发 ADD/DROP BACKEND 并持续回放：导出文件可被新 FE 加载，随后从边界起回放 journal 不出现链断裂、成员数量与 Master 一致；Observer 回放延迟在 dump 期间不增长；Master 行为与现状一致 |
| M2 | 一 | 回放隔离槽时按证书 kid 告警，新增指标 `license_invalid_slots`；`SHOW LICENSE` 显示本机 `trust_sha256` 与隔离原因；Master 维护线程每小时用现有探测比较各 FE 的 `trust_sha256`，不一致只告警 | 无 | 一台 FE 删掉外部密钥后状态页与日志可定位 |
| M3 | 一 | `LICENSE_NOT_READY` 响应增加 `retry_after_seconds`，追赶期固定 30 s；新增只读 `GET /api/license/health`，未就绪时返回 503 供负载均衡摘除节点。不改 `GET /api/license` 的状态码，否则 UI 状态页在未就绪时无法展示原因 | 响应体新增字段，UI 白名单需同步 | 大积压 Follower 重启期间客户端重试次数下降 |
| M4 | 产品决策 | 手册列出受限与不受限出口清单；若收紧，`BackupJob` 提交处与 `getBinlog` RPC 入口各加一次 `checkProtectedRead()` | 无 | 过期状态下 BACKUP 与 CCR 行为与清单一致 |
| 轻微 | 一 | WATERMARK 间隔改为配置项，默认 10 分钟；`AuditLogHelper` 改用 `OriginStatement.getSafeSql()`；初始化探测失败后指数退避，上限 60 s；版本号 141 已发布不改，升级文档保留与上游合并需迁移的说明；`LicenseManager.replay()` 链断裂通过 host 回调同步置 `licenseImageFormatRequired` | 无 | 每天 WATERMARK 记录数下降一个数量级；审计路径少一次扫描 |

R3 的 12 小时容差决策说明（2026-10-23）：防回拨的真正防线不是容差，而是两条规则。进程内可信时间按单调时钟推进（`LicenseClock.java:299-331`），墙钟回拨不会让它倒退；重启时锚点取墙钟与已持久化水位的较大值（`LicenseClock.java:294`），其中“不低于水位”这一半是防回拨所需，“直接接受更快的墙钟”这一半则是方案第 3 项要改掉的绕过口：独立验证表明，用快 3 天的墙钟重新构造时钟会被直接接受且不置可疑。容差只决定何时置 suspect 并拒绝查询，不参与可信时间计算，放宽到 12 小时不改变任何可信时间结果，把时间往回调也占不到便宜。放宽后仍有两类情况需要配套：开机墙钟远早于水位（主板电池失效、FE 先于 NTP 启动）仍会触发，由第 5 项自动解除处理；可信时间因已确认的错误前跳跑到真实时间前面，只能由签发方票据往回拨，这是修复票保留的唯一必要场景。第 2、3 项把超过容差的前跳交给 ADMIN 确认或 1 小时观察期，正是为了把这种情形压缩到“管理员确认了错误时间”或“1 小时内无人处理”两种，启动时墙钟快 3 天也不再被直接接受。

### 7.3 实施批次

| 批次 | 内容 | 信封 | 主要改动文件 |
| --- | --- | --- | --- |
| 1 | R2 常量固定；R3 容差 12 小时、前跳待确认与 ADMIN 确认命令、启动锚点纳入状态机、自动解除、观察期；R4 链断裂标记与 Env 对齐、手册约束；轻微项 | 不变 | LicenseTrustStore、LicenseClock、LicenseClockRepair、LicenseManager、LicensePersistRecord（新增 `withClockCleared`）、Env、Config |
| 2 | R1 签名清单；R5 预指定部署 ID 与通配证书；M1 冻结快照；M2、M3 | 不变 | LicenseTrustStore、LicenseVerifier、LicenseImportPolicy、LicenseManager、EnvLicenseHost、MetaWriter、LicenseController |
| 3 | R4 RESYNC 清除；R3 挑战持久化 | v2，分两步：先全量部署能读 v2、默认写 v1 的包，再经 `format_version=2` 探测开启写入 | LicensePersistRecord、LicenseManager、LicenseFeCompatibility、LicenseCommand |

批次 1 全部是进程内逻辑，可先出一版自用包验证。批次 3 的包必须能读 v2 且默认仍写 v1；只有全部 FE 都升到批次 3 并通过 `format_version=2` 探测后，Master 才开始写 v2 记录。不能按安装批次判断，也不能等批次 1 的包上线就写：前者会让旧 FE 回放 v2 时退出，后者的探测永远不会通过。

## 验证记录

本轮没有构建、测试或集群运行，也没有新增 `.build-records` 归档。所有判断基于基线源码阅读与三方向独立交叉复核；R1、R2 的 classpath 顺序与合并逻辑、R3 的阈值与持久化路径、R4 的标志写入与读回路径均逐行核对。性能数字（0.3 µs、10 µs、100 µs）是按指令路径推算的量级，不是实测，不能作为验收依据；正常路径的绑定期事实收集与规划末尾一次计划树遍历未计入估算。实施前应补测：短查询 QPS、SQL 缓存命中、MB 级长 SQL 的连接线程耗时，以及 dump 期间 Follower 回放延迟与管理请求延迟。

2026-10-23 的外部复核指出 R3 启动锚点绕过、R4 两条一档方案会引入新故障、v2 发布门控与批次矛盾、RESYNC 不能补齐成员、M1 冻结范围不足、性能表述过强，以及“已无健康 FE”过于绝对；已据此修订第 2、4、5、6、7 节。
