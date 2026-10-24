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

密码学验签、导入策略、管理入口鉴权、journal/image 边界、锁序和查询热路径开销都经得起推敲，没有发现普通用户可以绕过准入的缺陷。问题集中在两类：信任根可以被运维方自行替换；几个“粘滞”状态一旦触发就让整个集群停止受保护读取，且没有自助恢复手段。其中第 3、4 项在 [2026-10-04](license-review-remediation-20261004.md) 和 [2026-10-05](license-followup-review-20261005.md) 两轮记录中已被定性为既定契约；本轮不推翻它们作为问题的定性，但按生产集群规模（600 BE、多 FE、离线站点、主机曾出现时钟偏差）重新评估其触发概率与后果，仍列为重大；第 7 节 R4 的方案方向与前两轮“不能随意清除标志”的结论不同，理由与前提在该处说明。

## 2. 重大问题

| 编号 | 问题 | 代码依据 | 触发场景与影响 | 建议 |
| --- | --- | --- | --- | --- |
| R1 | 外部公钥清单无需任何签名即成为信任根，许可实质上可自签 | `LicenseManager.java:894-940` 读取 `massdb_license_trust_store_file` 后在 920 行 `merge`；`LicenseTrustStore.java:158-188` 对任意新 kid 的 `license`/`time_repair` 密钥一律并入，仅拒绝与内置密钥冲突的 kid 或密钥值 | 仓库自带的 `tools/license-issuer` 可完成 keygen、导出清单、签发不限节点且永不过期的证书，并自签时钟修复票据；每台 FE 配置该文件并重启即可。内置公钥因此没有起到约束作用。[管理手册](license-management-p2.md) 与 [2026-10-15 计划](license-downgrade-trust-compat-plan-20261015.md) 把并集描述为密钥轮换便利，属有意设计 | 若产品定位是自用、运维方即签发方，可以接受但应在威胁模型中写明。否则外部清单应由内置密钥反签名（JWS），或只在没有内置清单时作为兼容模式生效并告警 |
| R2 | “内置”清单可被 `conf/` 下同名文件整体替换 | `LicenseTrustStore.java:137` 用 classpath 查找 `/massdb/license/builtin-trust.json`；`bin/start_fe.sh:384` 把 `${DORIS_HOME}/conf` 放在 classpath 最前；主代码中没有对两把 SPKI 或资源摘要的硬编码校验（kid 与 SHA-256 只出现在测试和文档） | 在 `conf/massdb/license/builtin-trust.json` 放入自定义密钥并重启，内置密钥被替换而非追加，jar 校验和不变；厂商签发的证书反而验签失败被隔离 | 把两把 SPKI 字节或资源字节的 SHA-256 写成 Java 常量，加载结果不一致时失败关闭；或显式从 `doris-fe.jar` 的 code source 打开资源 |
| R3 | 时钟异常粘滞且集群级，常见运维事件即可造成整集群停读 | `LicenseClock.java:299-331`：回拨超 5 s（307 行）或自锚点累计前跳超 300 s（321 行）置 suspect；Master 在 `LicenseManager.java:1123` 一秒内持久化，所有 FE 回放后恢复该标志；`LicenseSnapshot.java:138-153` 返回 `CLOCK_SUSPECT`，`LicenseQueryStatus.java:23` 仅放行 VALID/EXPIRING；`LicenseImportPolicy.java:324-332` 同时拒绝导入；挑战绑定进程任期（`LicenseClockRepair.java:255`），Master 重启或切主即作废 | FE 启动后 chrony 对错误 RTC 做 step 校正、虚拟机暂停或热迁移、运维手工改时都能触发。前跳会被吸收为永久的可信进度，之后把墙钟改回又构成回拨。Follower 墙钟落后 Master 水位超 5 s 也会本机 suspect（`LicenseClock.java:253`），重启后下一次水位重现。唯一出路是厂商签发修复票据 | 容差拆为两个配置项：进程内回拨检查从 5 s 放宽到 12 小时，启动锚点与 Follower 回放水位的检查保持小值（建议 5 分钟）。进程内容差不参与可信时间计算，放宽不削弱防回拨；启动容差则限制“停机后把墙钟设回停机前再启动”能跳过的时长，不能一起放宽。前跳只告警不拒绝，经观察期或 ADMIN 确认后才接受，期间水位继续写已确认时间；启动时墙钟快于水位仍立即接受。可疑状态改为墙钟恢复后自动解除。签发方票据只保留给可信时间跑在真实时间前面的情形。另加启动稳定期、可疑期间水位继续写已确认时间、多 FE 墙钟交叉验证和 Follower 可疑只告警，使单机时钟事故不再波及集群。见 7.2 R3 与其决策说明 |
| R4 | “恢复不完整”标志永久、随 image 扩散且无任何命令可清除 | `Config.java:42` 默认不探测被跳过记录，`Env.java:3186-3193` 对任何 `force_skip_journal_ids` 跳过的日志调用 `markLicenseRecoveryIncomplete`；`EditLog.java:1478` 对八类成员操作的异常跳过同样如此；`LicenseManager.java:978` 之后没有任何置 false 的路径；`ready()`（468）与 `requireInitialized()`（473）同时失效；`saveImage`/`loadImage`（970/962）把标志写入并从 image 读回 | checkpoint Env 共享同一份跳过配置，会把标志写进 image 并推送到全部 FE。之后所有受保护读返回 `LICENSE_NOT_READY`，导入、时钟修复、ADD BACKEND/FRONTEND 全部被拒。文档补救是“从健康 FE 或备份恢复完整元数据”，但配置了跳过的 FE 与 Master 的 checkpoint Env 内存中都已带标志；正常回放成功的 FE 虽不带标志，却会在下一次加载推送来的 image 时继承它（在线 FE 的内存状态不立即变化），此后已无干净的元数据来源，备份也要回放同一段坏日志。Doris 标准应急手段因此变为不可逆的集群停读。同一路径还会把 `Env.licenseImageFormatRequired` 置真（`Env.java:934`），滚动升级期间尚未初始化就写出 141 版 image（`Env.java:2654`），未升级 FE 重启时无法加载 | 放弃修补链式规则，改为缺口容忍：每条许可记录都是完整快照，后续记录到达即覆盖缺口，严格连续性只检测缺口而不保护事实。回放接受版本更高的记录而不要求连续，时钟版本与记录版本合一，跳过日志只告警不设标志，初始化探测以 BDBJE 复制组为准。不再需要清除指令、恢复代次和镜像边界流程。探测选项保持默认关闭。见 7.2 R4 |
| R5 | 生产升级与新建集群都存在停读/停扩容窗口 | `deployment_id` 在全部 FE 升级并通过探测初始化后才随机生成（`LicenseManager.java:1120`），证书绑定该 ID；未导入前 `queryStatus` 为 `LICENSE_NOT_READY` 或 `MISSING`；新集群导入前 `requireCapacity` 固定 `maxFe=1、maxBe=0`（`LicenseManager.java:706-709`） | 升级后到导入证书前所有表查询返回 6200，窗口长度等于厂商签发往返时间，离线站点可能以天计；新集群一台 BE 也加不进去。[2026-10-04 记录](license-review-remediation-20261004.md) 已说明没有宽限期 | 上线方案必须明确停读窗口；或允许按运维预先指定的 deployment_id 签发，或随包提供限时宽限证书 |

## 3. 中等问题

| 编号 | 问题 | 代码依据 | 影响 | 建议 |
| --- | --- | --- | --- | --- |
| M1 | `/dump` 独占许可提交线程和 Env 监视器 | `Env.java:6560-6570` 把整个 dump 放入单线程 `license-commit` 队列（`LicenseManager.java:659`）并持有 Env monitor；`runMembershipMutation`/`runImageSnapshot` 的 `future.get()`（631/675）无超时；`replayJournal`（3157）与 dump 同一监视器 | Master 上 dump 期间所有 ADD/DROP 节点、导入和水位提交排队；Follower/Observer 上阻塞回放，2M tablet 规模可能超过 `meta_delay_toleration_second` 使 Observer 停止服务。2026-10-05 记录已承认此代价 | 降为运维约束：在不对外服务的 Observer 上低峰执行，并写明对 `meta_delay_toleration_second` 的影响。Follower 侧没有低成本解法，原因见 7.2 M1 |
| M2 | 各 FE 信任配置不一致会造成单机 INVALID 且无明显告警 | `LicenseFeCompatibility.java:170-209` 的兼容证明不比较 `trust_sha256`；`LicenseManager.java:901-907` 内置清单加载失败只告警；`LicensePersistRecord.java:331-346` 本机重验失败只隔离槽 | Master 用合并后的密钥接受证书，某台 Follower 重验失败即对本机所有受保护读返回 `INVALID`，状态页只在该机可见 | 导入时记录证书的 kid，回放侧隔离槽时按 kid 告警；或把 `trust_sha256` 纳入定期健康检查 |
| M3 | 重启或回放追赶期间返回 `retryable:true` | FE 在 `onReplayComplete`（`LicenseManager.java:983`）前所有受保护读返回可重试的 `LICENSE_NOT_READY` | 大积压 Follower 可持续数分钟，遵守该提示的客户端形成重试风暴 | 返回体增加建议退避时间，或在负载均衡健康检查中纳入许可就绪状态 |
| M4 | 执行边界需确认 | BACKUP TO repository、CCR/binlog 不经准入；INSERT ... SELECT 写入内部表不受限 | 若边界是“受保护数据不得离开集群”，前两者是绕过；若只限交互读取则无问题。2026-10-04 记录已把 BACKUP/CCR 列为保留通道 | 在产品文档中明确写出受限与不受限出口清单 |

## 4. 轻微问题

- 每 60 s 一条携带完整信封的 WATERMARK 日志（`LicenseManager.java:1130`），每天约 1,440 条、每条数 KB，所有 FE 回放并被每次 checkpoint 重序列化。间隔放到 10 到 30 分钟不影响防回拨强度，只影响重启后可信时间最多回退的幅度。
- 每条 SQL 文本在连接线程上被线性扫描 4 到 5 次（`LicenseSqlRedactor.java:229`）；`AuditLogHelper.java:91` 对原始字符串再扫描一次，没有复用 `OriginStatement.getSafeSql()` 的缓存。1 KB 语句约 10 µs，MB 级语句约 10 ms，低于已有 md5 与 ANTLR 开销。
- 初始化被阻塞时（任一 FE 离线或旧版）Master 每秒探测全部 FE 的 HTTP 端点，没有退避；日志每 60 s 限频一条。
- 元数据版本 141 占用了上游下一个版本号，`MetaContext` 在加载时记为 141；未来合并上游需专门迁移。2026-10-04 记录已指出。
- `LicenseManager.replay()` 内检测到版本链断裂时只标记本机不完整、不置 `licenseImageFormatRequired`；`appliedVersion==0` 时下一次 image 以 140 版空模块写出，标志随之丢失。只在 journal 本身不一致时可达，但一旦出现就等同于“从未初始化”，重启后 Master 可能重新生成部署 ID 并使原许可历史作废。在 7.2 R4 的缺口容忍规则下，链断裂不再是状态，该路径改为告警即可。

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

按第 7.3 节的三个批次推进：批次 1 只改进程内逻辑与配置，含 R4 的缺口容忍，可先出自用包验证；批次 2 引入新文件格式与配置；批次 3 只剩挑战跨切主持久化，需要信封升版，可推迟或不做。R1 与 M4 需要产品决策，在决策前至少把“运维方可自签”和出口清单写进威胁模型与手册；R4 的方向调整推翻了前两轮记录的结论，需团队认可其完整快照前提；R5 属于上线方案，应与客户确认停读窗口或签发流程。在批次 1 发布前，运维手册应把 `force_skip_journal_ids` 与改时操作标为“先联系签发方”。

## 7. 解决方案

本节是设计。批次 1 已于 2026-10-23 在本分支实施，实施与验证情况见文末“批次 1 实施记录”；批次 2、3 仍未实现。容差、间隔等数值在实施时按本文建议值作为默认配置写入。

### 7.1 总约束：持久化信封不能随意加字段

`LicensePersistRecord.validateEnvelope`（`LicensePersistRecord.java:455-464`）要求字段集合精确匹配，多一个字段旧版带许可 FE 回放时抛 `IOException` 并退出进程。因此方案分两档：第一档只改进程内逻辑、配置或新文件格式，不动信封，可直接滚动发布；第二档把 `format_version` 升到 2，目前只有 R3 第 7 项的挑战持久化需要它，需要分两步：先全量部署“能读 v2、默认仍写 v1”的版本，它在能力接口中上报 `format_version=2`；然后复用现有全 FE 能力探测（`LicenseFeCompatibility.checkAll`）在首次写 v2 前再探测一次，全部 FE 都上报 2 才允许 Master 写出 v2 记录。该探测目前只在初始化前运行，需要增加这个触发点。只按安装批次判断会让旧 FE 回放 v2 时退出；只等不能读 v2 的包上线，探测永远不会通过。下文每项标明所属档位。

### 7.2 逐项方案

| 编号 | 档位 | 做法 | 兼容影响 | 验证方式 |
| --- | --- | --- | --- | --- |
| R2 | 一 | 把两把 SPKI、kid、purpose 写成 `LicenseTrustStore` 的 Java 常量，`builtIn()` 直接由常量构造，不再做 classpath 查找。`src/main/resources` 的 JSON 只保留给打包 `conf/massdb-license-trust.json` 使用，并加单元测试断言资源字节的 SHA-256 等于常量推导值 | 无持久化变化；旧 FE 继续读外部文件 | 在 `conf/massdb/license/` 放伪造清单启动 FE，`GET /api/license/capability` 的 `trust_sha256` 仍等于内置摘要 |
| R1 | 一，需产品决策。**2026-10-23 决策：按本方案实施（产品面向对外商用，运维方不可信）**，签名密钥为新增的专用 `trust` 用途内置密钥 | 外部明文文件降为只读兼容件：新版 FE 只接受与内置密钥完全相同的条目，多出的密钥忽略并告警。新增 `massdb_license_trust_manifest_signed` 指向 JWS 清单，签名方必须是内置 `license` 密钥或新增的专用 `trust` purpose 内置密钥；清单声明含 `keys`、`issued_at`、`sequence`，验签后再 `merge`。密钥轮换变为：签发方用旧密钥签含新密钥的清单，各 FE 配置后重启，下一版包把新密钥编入常量。若产品定位为自用且签发方即运维方，可不做签名，但须在威胁模型写明“运维方可自签”，并仍完成 R2 | 旧 FE 需要的明文文件照常发布，不再扩展信任；新配置旧 FE 忽略 | 自造密钥导出明文清单后导入证书必须 `UNTRUSTED_KEY`；内置密钥签的清单加入新密钥后导入成功 |
| R3 | 一为主 | 1）容差拆为两个配置项：进程内回拨检查从 5 s 放宽到 12 小时；启动锚点与 Follower 回放水位的检查保持小值，建议 5 分钟。进程内检查不参与可信时间计算，启动检查则决定停机后回拨墙钟最多能跳过多长时间，两者不能一起放宽。2）前跳只告警、不拒绝。前跳幅度以已确认可信时间为基准；前跳后的进度先作为“待确认偏移”：不超过进程内容差的前跳持续 5 分钟仍成立即自动确认，超过的由 ADMIN 用新增命令确认，或在 1 小时内既未被校正也未被确认时自动接受。未确认期间墙钟校正回来就直接丢弃。查询、导入和水位都只使用已确认的可信时间。3）水位始终写出已确认可信时间，即上次水位加本进程单调时钟走过的时长，或已确认的墙钟进度；待确认与回拨可疑期间都不停写。`prepareCheckpoint` 不再因可疑返回 null：现有注释“可疑时钟不能污染检查点”针对的是前跳被立即吸收进可信时间的旧行为，第 2 项把未确认前跳隔离后，已确认时间无论墙钟对错都是真实时间的下界，写出永远安全；停写反而让每隔几分钟重启一次就能把可信时间冻结在水位附近。4）启动与重启保持现有行为：锚点取墙钟与持久化水位的较大值，墙钟快于水位立即接受，不进入待确认。原因是待确认状态不跨重启，若启动只取水位，反复重启就能让可信时间停在水位附近；接受更快的墙钟对签发方无风险。残余风险是启动时错误的快墙钟会被接受：在首个水位写出前重启修正则不留痕迹，否则多出的时间需签发方票据回拨，写入手册。5）回拨可疑不再粘滞：每次读取重新判定，墙钟回到已确认可信时间的容差内即自动解除；Master 已持久化的可疑状态在解除后写一条 `clock_suspect=false` 的 INTEGRITY 记录（新增 `withClockCleared`，形状不变）。6）Master 连续 5 分钟仍可疑才持久化，期间只告警。7）挑战跨切主持久化属第二档，规则须完整：挑战写入 v2 信封 clock 子树，字段为 nonce、challenge_id、签发时的可信时间、有效期；票据改为绑定 challenge_id 而不是 `leader_term`，`LicenseClockRepair.java:378` 的任期校验改为核对 challenge_id 与记录中的当前挑战；有效期按可信时间判断，不再用进程内单调时钟起点；新 Master 从记录恢复当前挑战；提交后写回执并清除挑战，保证一次性消费；新挑战覆盖旧挑战。可推迟，不影响批次 1、2。8）启动稳定期：新增配置项，默认 10 分钟。期间准入仍取墙钟与水位的较大值，第 4 项不变；但墙钟高于水位的部分只作未确认进度，水位只写已确认下界，稳定期结束且墙钟仍一致才确认并写入。NTP 在稳定期内校正快钟即不留痕迹，第 4 项残余风险的窗口由“首个水位写出前”变为稳定期长度。反复重启得不到好处：准入未变，水位随运行时长推进，最多只能跳过停机时长，与已写入威胁模型的固有限制相同。9）稳定期内的回拨可疑只告警、不拒绝查询、不计入第 6 项的 5 分钟：启动时墙钟落后水位，可信时间取自水位加单调时钟，不受慢墙钟影响，对签发方无损失；配合第 3 项不停写水位，重启循环无法冻结可信时间。稳定期结束仍可疑才进入第 5、6 项流程。10）多 FE 墙钟交叉验证：`GET /api/license/capability` 返回体增加本机墙钟毫秒值，Master 每个维护周期复用 `LicenseFeCompatibility.probe` 读取各 FE 墙钟并与自己比较。自己与多数 FE 偏差超过启动容差（5 分钟；实施时由进程内容差改为启动容差，见文末实施记录），则本机前跳不确认、回拨按本机问题处理，不写墙钟进度、不持久化可疑；多数 FE 与自己一致的前跳立即确认，不等观察期。探测失败、单 FE 集群或无法形成多数时退回纯时间窗口规则；探测结果只缩短或延长等待，不单独触发拒绝。11）Follower 与 Observer 的本机可疑只告警、不拒绝查询：其可信时间来自 Master 水位加本机单调时钟，本机墙钟不参与计算，拒绝只伤使用方、不保护签发方；当选 Master 后自然改按 Master 规则。状态页与指标保留可疑标志供运维定位 | 第 5 项记录在现有形状内；旧版 FE 回放后不再置 suspect，但本机标志到重启才清，需写入手册。第 2 项改变了“前跳立即生效”的现有行为，对签发方无风险；对使用方，容差内前跳最多推迟到期 5 分钟，超过容差最多 1 小时。第 4 项不改变现有行为。第 8 至 11 项无持久化变化；第 10 项的能力接口新增字段，旧 FE 不返回该字段时按探测失败处理；第 11 项改变 Follower 现有的本机拒绝行为 | 注入时钟源的单测覆盖：进程内回拨 1 小时不报警且可信时间不变；回拨 13 小时报警、期间不写水位、墙钟恢复后自动解除；启动时墙钟落后水位 10 分钟即可疑，NTP 校正后自动解除，无需 ADMIN 或票据；每 4 分钟重启一次持续 24 小时，剩余 10 分钟的许可仍按真实时间在 10 分钟后过期；前跳 10 分钟后 3 分钟内校正回来，无后遗症且水位按已确认时间继续推进；前跳 3 天时查询仍按原可信时间评估，ADMIN 确认后接受，不确认并校正回来则丢弃；启动时墙钟快 2 小时、8 分钟后校正回来，journal 中没有高于真实时间的水位；启动时墙钟慢 2 天，查询全程放行、水位持续推进，NTP 校正后标志自动清除；每 4 分钟重启一次且每次启动前把墙钟设回上次水位，可信时间仍随运行时长推进；三 FE 集群中仅 Master 前跳 1 小时，墙钟进度不写入且本机告警，三台同时前跳则立即确认；Follower 墙钟慢 8 小时，查询放行、状态页显示可疑。单 FE 真实改时演练一次，三 FE 集群里 FE 先于 chronyd 启动、随后同步的演练一次 |
| R4 | 一，方向调整 | 放弃修补链式规则，改为缺口容忍。依据：每条许可记录都是完整快照，`withImports`、`withClock`、`withClockSuspect` 都深拷贝整个信封再改字段，三个槽、回执、时钟事实全部带上；跳过任意一条后只要后续记录到达，状态即被完整覆盖。严格的“版本等于本机加一”只检测缺口，不保护任何事实，却把一次缺口变成永久停读。运维方跳过记录只能让状态变旧，造不出 Master 没有过的状态；要维持旧状态须跳过之后全部记录，等同于不运行许可或恢复旧备份，已在威胁模型内。规则：1）回放：同一 deployment、bootstrap 不变、activated 只能 false 到 true，满足即接受版本高于本机的记录，不要求连续；版本不高于本机的记录整条忽略并计数告警；`sameAs` 的幂等短路保留。2）时钟内层：`clock.version` 与记录版本合一，每次写记录都把它设为新的记录版本，旧版 FE 只要求单调递增，兼容；`applyCommitted` 在回放路径不再抛异常，同 epoch 水位倒退或同版本内容不同一律忽略并告警，本机时钟只取最大值；退化过的 Master 写出的低水位被健康 FE 忽略，几分钟后其水位自然超过并重新对齐；切主时 `refresh()` 以本机时钟事实为准写出一条水位并对齐版本，不再返回 `STALE_PREPARATION`。3）跳过日志：成员操作或未知操作码被跳过时，只在本机状态页和日志记录“回放缺口”（journal id、已知操作码、时间），不设不完整标志、不抬镜像版本；镜像模块的布尔位固定写 false，读到 true 只作告警；`massdb_license_probe_skipped_journal_header` 保持默认关闭，读取物理损坏记录可能使 JE 环境失效。4）初始化探测以 BDBJE 复制组成员（electable 与 observer 节点）为准，而不只看 frontends 表：ADD FRONTEND 被跳过的 FE 仍在复制组里，探测仍覆盖它，旧版 FE 不会在初始化后因回放许可记录退出。5）删除 RESYNC、恢复代次、CONFIRM、FORCE 和镜像边界确认流程，R4 不再需要 v2。残余风险写入威胁模型：Master 自己跳过 ADD BACKEND 时，最多多准入与跳过条数相同的 BE，标准处理仍是从镜像重建该 FE；全部许可记录被跳过且镜像无模块时，Master 重新初始化并生成新部署 ID，证书需重新签发，这是元数据丢失应有的结果。本项与 2026-10-04、10-05 两轮“不能随意清除标志”的结论不同，前提是上述完整快照论证，需团队认可 | 无持久化形状变化，`clock.version` 取值变大但仍单调。旧版带许可 FE 在升级前仍按严格链式规则工作，混合版本期间遇到缺口仍会自行标记，手册注明先升级再处理缺口 | Follower 分别跳过 WATERMARK、ACCEPT、INTEGRITY 各一条后，状态与 Master 一致且无标志；Master 跳过最后一条记录后切主，写出的低水位被健康 FE 忽略、随后对齐、无退出，切主后水位与修复流程正常；跳过 ADD BACKEND 的 FE 状态页显示缺口，从镜像重建后消失；跳过 ADD FRONTEND 后初始化探测仍覆盖该 FE；旧版 FE 回放新版记录不退出；新 FE 加载镜像不继承任何标志 |
| R5 | 一 | 主方案：新增 `massdb_license_deployment_id`，只在 INITIALIZE 时读取，为空则随机生成；签发方提前生成 UUID 并签好证书，升级完成初始化后立即导入。两套集群填同一 ID 的风险与复制元数据相同，不新增攻击面。备选：允许 `deployment_id` 全零的通配证书，约束为有效期不超过 30 天、`highest_sequence == 0` 时才可导入、不计入序号历史；新建集群先用它加 BE。旧版 FE 回放通配证书会隔离槽，须全 FE 升级后使用。**2026-10-23 决策：两者都不做。** 预指定 ID 曾实现又撤回，因为它把"复制证书到另一套集群"从复制元数据简化为抄一行配置；部署 ID 仍由集群初始化时生成，通过复制元数据克隆集群的场景暂不考虑。商用防复用的方向（短期证书加续期时的谱系校验，不绑定机器身份）记在文末实施记录。**2026-10-24 决策：首张证书按合同期限正常发放、不缩短，续期谱系校验因此不做；残余风险（复制元数据克隆的集群在证书有效期内同样有效，续期证书也可复制）写入管理手册第 1 节** | 不改信封；停读窗口等于签发往返时间，上线方案须写明 | 不适用 |
| M1 | 运维约束 | 撤回 Follower 侧“只冻结许可边界、释放监视器”的方案，保留现有实现。原因有两点。其一，dump 持有的 Env 锁不只阻塞回放，还保证 FE 清单与 journal 边界一致：`replayAddFrontend`（`Env.java:4949`）遇到同地址不同角色会直接退出，若在边界 J 之后发生“添加 Observer、删除、同地址添加 Follower”而镜像保存了最终状态，从 J 重放第一条 ADD 就会退出，只有持锁才能排除；BE 的 ADD/DROP 幂等不能推出 FE 清单也安全。其二，就算只释放回放监视器，dump 仍持有全部库表读锁，回放一遇到 ADD/DROP PARTITION 等需要表写锁的日志仍会停住，后续日志也无法推进，收益很小。处理方式：手册规定 dump 在不对外服务的 Observer 上低峰执行，说明期间该 FE 回放停止、可能超过 `meta_delay_toleration_second`；Master 上 dump 期间成员 DDL、导入和水位排队也一并写明 | 无代码变化 | 若将来实施任何 dump 改动，测试须覆盖 dump 期间并发 ADD/DROP FRONTEND 的角色变化、ADD/DROP PARTITION 与表 DDL 日志、导出文件加载与后续回放，而不只是 ADD/DROP BACKEND |
| M2 | 一 | 回放隔离槽时按证书 kid 告警，新增指标 `license_invalid_slots`；`SHOW LICENSE` 显示本机 `trust_sha256` 与隔离原因；Master 维护线程每小时用现有探测比较各 FE 的 `trust_sha256`，不一致只告警 | 无 | 一台 FE 删掉外部密钥后状态页与日志可定位 |
| M3 | 一 | `LICENSE_NOT_READY` 响应增加 `retry_after_seconds`，追赶期固定 30 s；新增只读 `GET /api/license/health`，未就绪时返回 503 供负载均衡摘除节点。不改 `GET /api/license` 的状态码，否则 UI 状态页在未就绪时无法展示原因 | 响应体新增字段，UI 白名单需同步 | 大积压 Follower 重启期间客户端重试次数下降 |
| M4 | 产品决策 | 手册列出受限与不受限出口清单；若收紧，`BackupJob` 提交处与 `getBinlog` RPC 入口各加一次 `checkProtectedRead()` | 无 | 过期状态下 BACKUP 与 CCR 行为与清单一致 |
| 轻微 | 一 | WATERMARK 间隔改为配置项，默认 10 分钟；`AuditLogHelper` 改用 `OriginStatement.getSafeSql()`；初始化探测失败后指数退避，上限 60 s；版本号 141 已发布不改，升级文档保留与上游合并需迁移的说明；`LicenseManager.replay()` 的链断裂处理并入 R4 的缺口容忍规则 | 无 | 每天 WATERMARK 记录数下降一个数量级；审计路径少一次扫描 |

R3 的 12 小时容差决策说明（2026-10-23，经两轮外部复核修订）：这套时钟有两条真正的防线。其一，进程内可信时间按单调时钟推进（`LicenseClock.java:299-331`），墙钟回拨不会让它倒退，所以进程内回拨检查的容差只是警报阈值，放宽到 12 小时不改变任何可信时间结果，而 NTP 校正、虚拟机迁移这些事故都发生在这里。其二，重启时锚点取墙钟与已持久化水位的较大值（`LicenseClock.java:294`），它保证可信时间不低于水位，但只能度量“运行时间加墙钟前进”：停机 N 小时后把墙钟精确设回停机前的值再启动，这 N 小时就不计入可信时间。现有 5 秒容差只是要求设置精确，并不能阻止；若把启动容差也放到 12 小时，这个操作就不再需要精确。所以启动锚点与 Follower 回放水位的容差保持小值。这是方案的固有限制，应写入威胁模型；附带的缓解是 `issued_at` 检查会让可信时间落后的集群无法导入新签发的证书。放宽后仍有两类情况需要配套：开机墙钟远早于水位（主板电池失效、FE 先于 NTP 启动）仍会触发，由第 9 项在稳定期内放行、第 5 项自动解除处理；可信时间因已确认的错误前跳跑到真实时间前面，只能由签发方票据往回拨，这是修复票保留的唯一必要场景。上一轮把启动纳入待确认状态机的修订已撤回：待确认状态不跨重启，若启动只取水位且待确认期间不写水位，每 4 分钟重启一次就能让可信时间永远停在水位附近，剩余 10 分钟的许可 24 小时后仍未过期；启动时直接接受更快的墙钟对签发方无风险，其残余风险只落在使用方，已在第 4 项说明。同日第四轮讨论补充第 8 至 11 项，针对的是 FE 先启动、NTP 后同步，以及单台服务器时间与其他机器不一致的场景；纯时区差异不在其中，`System.currentTimeMillis()` 是 UTC 毫秒数，与时区设置无关。这套方案的固有限制是单台 FE 在没有同伴和可信外部时间源时无法区分墙钟错误与长时间停机，组件只能用其他 FE 做交叉验证，并把错误时钟的影响限制在可自愈的窗口内；全集群同时错钟且超过稳定期的情况仍需签发方票据，写入威胁模型。四项都不让可信时间比现在更慢：第 8、10 项只推迟把墙钟进度写入水位，准入不变；第 3、9 项让可疑期间水位继续推进，对签发方只有好处；第 11 项放开的 Follower 本来就不影响可信时间。操作系统的同步状态（`timedatectl` 的 NTPSynchronized、chrony 的 tracking）只能作为缩短或延长稳定期的提示，不能做门控，离线站点可能没有 NTP。

### 7.3 实施批次

| 批次 | 内容 | 信封 | 主要改动文件 |
| --- | --- | --- | --- |
| 1 | R2 常量固定；R3 两个容差配置、前跳待确认与 ADMIN 确认命令、可疑与待确认期间水位继续写已确认时间、自动解除、观察期、启动稳定期、多 FE 墙钟交叉验证、Follower 可疑只告警；R4 缺口容忍回放、时钟版本合一、跳过只告警、复制组探测、手册约束；M1 手册约束；轻微项 | 不变 | LicenseTrustStore、LicenseClock、LicenseClockRepair、LicenseManager、LicensePersistRecord（新增 `withClockCleared`、`clock.version` 合一）、LicenseFeCompatibility、LicenseController、LicenseSnapshot、EditLog、Env、Config |
| 2 | R1 签名清单；R5 预指定部署 ID 与通配证书；M2、M3 | 不变 | LicenseTrustStore、LicenseVerifier、LicenseImportPolicy、LicenseManager、EnvLicenseHost、LicenseController |
| 3，可选 | R3 挑战跨切主持久化 | v2，分两步：先全量部署能读 v2、默认写 v1 的包，再经 `format_version=2` 探测开启写入 | LicensePersistRecord、LicenseManager、LicenseClockRepair、LicenseClockRepairVerifier、LicenseFeCompatibility |

批次 1 全部是进程内逻辑，可先出一版自用包验证。批次 3 可推迟；若实施，其包必须能读 v2 且默认仍写 v1；只有全部 FE 都升到批次 3 并通过 `format_version=2` 探测后，Master 才开始写 v2 记录。不能按安装批次判断，也不能等批次 1 的包上线就写：前者会让旧 FE 回放 v2 时退出，后者的探测永远不会通过。

## 验证记录

本轮没有构建、测试或集群运行，也没有新增 `.build-records` 归档。所有判断基于基线源码阅读与三方向独立交叉复核；R1、R2 的 classpath 顺序与合并逻辑、R3 的阈值与持久化路径、R4 的标志写入与读回路径均逐行核对。性能数字（0.3 µs、10 µs、100 µs）是按指令路径推算的量级，不是实测，不能作为验收依据；正常路径的绑定期事实收集与规划末尾一次计划树遍历未计入估算。实施前应补测并给出对照结果：短查询与 SQL 缓存命中的 QPS、CPU、分配/GC 与 p99，MB 级长 SQL 的连接线程耗时，以及 dump 期间 Follower 回放延迟与管理请求延迟；微秒级估算不能替代这些对照。

2026-10-23 的外部复核指出 R3 启动锚点绕过、R4 两条一档方案会引入新故障、v2 发布门控与批次矛盾、RESYNC 不能补齐成员、M1 冻结范围不足、性能表述过强，以及“已无健康 FE”过于绝对；已据此修订第 2、4、5、6、7 节。同日第二轮复核指出上一轮的启动待确认可被反复重启重置、M1 混合镜像的 FE 角色重放退出与库表锁阻塞、RESYNC 缺少跨越丢失历史的版本规则、checkpoint 边界未必覆盖 RESYNC，以及第 28 行措辞；已据此再次修订第 2、3、7 节，撤回 M1 的 Follower 方案并拆分两个时钟容差。同日第三轮复核指出恢复代次未覆盖时钟内层版本、本机代次加一不保证高于其他 FE、FORCE 与 activated 不回退冲突、挑战持久化缺任期与有效期规则；前三条说明修补链式规则的方向本身不可行，R4 据此改为缺口容忍方案，第四条已补全规则，第 1、2、4、6、7 节同步修订。同日第四轮讨论针对“FE 先启动、NTP 后同步”与单机时钟不一致的场景，为 R3 补充第 8 至 11 项（启动稳定期、可疑期间水位继续、多 FE 墙钟交叉验证、Follower 可疑只告警），修订第 3 项撤回“可疑时停写水位”，第 2、7 节同步修订。

## 批次 1 实施记录（2026-10-23）

按 7.3 批次 1 实施了 R2、R3 第 1 至 6 与 8 至 11 项、R4、轻微项和 M1 手册约束，持久化信封形状不变。改动文件：LicenseTrustStore、LicenseClock（重写）、LicenseManager、LicensePersistRecord、LicenseFeCompatibility、LicenseController、EnvLicenseHost、Env、EditLog、AuditLogHelper、fe-common Config、DorisLexer/DorisParser 语法与 LogicalPlanBuilder（`ADMIN CONFIRM LICENSE CLOCK`）、`conf/fe.conf`、`MODIFICATIONS.md` 与管理手册第 4、5 节。与设计的差异和补充：

- 时钟内层版本与记录版本合一由 `LicensePersistRecord.next()`/`withClock()` 统一写入；初始记录的 `clock.version` 为 1。
- 回放对其他部署的后续记录只忽略计数，但对其他部署的 INITIALIZE 记录采纳为“Master 重新初始化”，避免 Follower 与重新初始化的 Master 永久分叉；这是 7.2 R4 残余风险的直接后果，写入手册。
- 可疑判定分为本机（回拨、启动）与已提交两类：本机可疑只在 Master 且稳定期结束后拒绝查询，已提交可疑在所有 FE 拒绝；Master 连续 5 分钟可疑且同伴未判定其为离群值才持久化，墙钟恢复后写 `withClockCleared`。
- 前跳候选取观察窗口内的最小值，被暂停拉长的一次样本不能单独确认；查询热路径每次读取仍只各采样一次单调时钟和墙钟，共享标志只在变化时写入。
- 同伴墙钟交叉验证只在 Master 上、存在待确认前跳或本机可疑时每分钟最多一次，在验证线程池执行；少于三台或无多数时为 UNKNOWN。
- 单调时钟倒退按异常处理：当次读取可疑，且不因此停留在稳定期内。
- 初始化探测失败后指数退避，上限 60 秒；WATERMARK 间隔可配置，默认 10 分钟。
- 真实演练（`.build-records/license-batch1-drill-20261023/`，三 FE 加一 BE 各在独立网络命名空间，许可墙钟由仅演练使用的 java agent 偏移）纠正了三处：小于 1 秒的前跳候选只是抖动，不进入待确认，否则回拨恢复时多出的几毫秒会以"0 秒前跳"挡住其后真正的跳变；同伴墙钟比较改用启动容差而不是 12 小时的进程内容差，否则单机 1 小时的前跳会被判成"与多数一致"而立即确认；启动候选被最小值跟踪下调时准入偏移必须跟着下调，否则快钟启动后被 NTP 校正，查询看到的时间仍停在校正前。演练覆盖的场景、每轮的发现与截图见该目录 README。

验证：`mvn test -pl fe-common,fe-core -Dtest='License*Test'` 33 个测试类 369 个用例全部通过，覆盖 7.2 R3、R4 验证栏中可在单测注入时钟源完成的用例（进程内回拨 1 小时不报警、回拨超容差自动解除、启动墙钟慢时稳定期内放行与同步后清除、启动墙钟快被 NTP 校正后不留痕迹、反复重启不冻结可信时间的前提即可疑期间水位继续写、前跳 5 分钟确认与 1 小时接受、ADMIN 确认、同伴 AGREE/OUTLIER、Follower 跳过 WATERMARK/ACCEPT/INTEGRITY 后状态一致且无标志、跳过 ADD BACKEND/ADD FRONTEND 只记缺口、旧版不完整标志被忽略、复制组成员探测、旧 FE 回放新记录所需的版本单调性）。`build-support/check-source-headers.py` 与 `git diff --check` 通过。未做：真实集群的单 FE 改时演练、三 FE 的 FE 先于 chronyd 启动演练、切主后低水位对齐与修复流程演练、性能对照，以及 UI 对新增状态字段的展示；这些留待自用包验证。

## 批次 2 实施记录（2026-10-23）

同日决策：产品面向对外商用、运维方不可信，R1 按原方案实施；R5 实现后撤回（见第 2 节 R5 行）；通过复制元数据克隆集群暂不考虑，商用防复用的方向（短期证书加续期时的谱系校验，不绑定机器身份）留作后续产品决策。M2、M3 按 7.2 实施，持久化信封不变。2026-10-24 补充决策：首张证书按合同期限正常发放，不缩短，所以不做续期谱系校验；“复制元数据克隆集群后证书在有效期内同样有效、续期证书可同样复制”作为接受的残余风险写入管理手册第 1 节。

- **R1**：`LicenseTrustStore` 新增 `trust` 用途，内置专用密钥 `self-use-trust-20261023`（私钥与 `license.pem`、`time-repair.pem` 同在签发机目录；为让更早的 FE 仍能解析，发行包的明文 `conf/massdb-license-trust.json` 不含它）。`verifySigned` 校验 compact JWS 清单（`typ` `massdb-trust+jws`，负载 `schema_version`、`issued_at`、`sequence`、`keys`，签名方必须是内置 `trust` 密钥；`issued_at`、`sequence` 仅做类型检查，是签发方的记账字段），`extraKeys` 列出明文清单相对内置公钥多出的条目。`loadTrust` 只从 `massdb_license_trust_manifest_signed` 合并公钥；`massdb_license_trust_store_file` 只与内置公钥比对，多出的忽略并告警一次，没有内置公钥（jar 损坏）时才退回明文文件并告警。签发工具新增 `trust-sign`、`trust-verify`，`export-trust` 接受 `trust` 用途。测试通过 `Host.builtInTrust()` 注入自己的信任根。
- **M2**：`LicensePersistRecord.restore` 把隔离槽记为 `{slot, key_id, reason}`，`key_id` 由 `LicenseConfirmationIds.keyIdHint` 从证书头读取（只作诊断），`reason` 为验签错误码或 `DEPLOYMENT_MISMATCH`、`SEQUENCE_ABOVE_HIGHEST`、`VERSION_ABOVE_LICENSE_VERSION`；Manager 在隔离集合变化时记一条 WARN 并带本机 `trust_sha256`，状态视图新增 `trust_sha256`、`invalid_slots`，指标 `license_invalid_slots`；Master 每小时通过能力探测比较各 FE 的 `trust_sha256`，不一致只告警。
- **M3**：`LICENSE_NOT_READY` 的管理响应与受保护读取拒绝体带 `retry_after_seconds = 30`（HTTP 同时带 `Retry-After`）；新增免认证 `GET /api/license/health`，就绪 200 `READY`，否则 503 `NOT_READY` 加 `Retry-After`，不含许可细节；`GET /api/license` 状态码不变。UI 客户端白名单加入 `retry_after_seconds`、`trust_sha256`。

验证：`License*Test` 33 类 376 个用例通过，签发工具 28 个测试通过，Checkstyle、源码头检查通过。签名清单、隔离槽与 health 路由的真实集群演练和 UI 展示见下一节（2026-10-24 完成）。

## 批次 2 演练与收尾（2026-10-24）

- **UI**：License 页新增“时钟”卡片（`confirmed_utc`、同伴判定、本机/启动/已提交可疑、是否执行拒绝、稳定期、待确认前跳及其时长与来源）与“本 FE 诊断”卡片（`trust_sha256`、`replay_gaps`、`ignored_records`、隔离槽列表含槽位/kid/原因、最近回放缺口）。`ui/src/api/license.ts` 白名单按固定形状过滤这些字段（枚举、64 位十六进制、`{slot,key_id,reason}`、`{journal_id,op_code,kind,wall_millis}`，形状不符的值替换为固定代码，不透传服务端字符串）；布尔值与同伴判定按语言显示。浏览器契约测试新增一例（48/48 通过），`npm run check:notices` 通过。
- **残余风险决策**：首张证书按合同期限正常发放、不缩短，续期谱系校验不做；“复制元数据克隆的集群在证书有效期内同样有效，续期证书可同样复制”写入管理手册第 1 节“安全边界与残余风险”。
- **真实集群演练**（`.build-records/license-batch2-drill-20261024/`，三 FE 加一 BE 各在独立网络命名空间，产品 JAR 未改动、无 agent；README 有结果表、每轮失败原因与截图）：运维方把自造公钥写入明文清单并配置在 Master 上，启动只告警一次、`trust_sha256` 与其他 FE 相同，用自造密钥签的 10 年 500 FE 证书在 validate/import/SQL 三个入口都是 `LICENSE_UNTRUSTED_KEY`；运维方用自造 trust 密钥签的清单在重启时被拒（`reason=UNTRUSTED_KEY`，内置公钥继续生效）；签发方用内置 trust 密钥签的轮换清单逐台配置后 `trust_sha256` 随之变化，没配清单的 Master 仍拒绝新钥证书，配好后导入 APPLIED；未配清单的 fe3 回放新钥证书后隔离 active 与 base 两个槽（C2 同时是生效证书与基础额度）、状态 INVALID、受保护读取 `6200 LICENSE_INVALID`、指标 `doris_fe_license_invalid_slots 2`、日志给出槽位/kid/原因/本机摘要，当选 Master 的首个维护周期记录“License trust differs between FEs”；fe3 配上签名清单重启后恢复 VALID、隔离清空、摘要一致。`GET /api/license/health` 免认证在各 FE 返回 200 READY；5 次重启中每 100 ms 轮询都在约 30 次连接拒绝后直接得到 200，因为 FE 在 `Env.waitForReady()` 之后才开 HTTP 端口、许可恢复随回放完成，所以 503 `NOT_READY` 窗口与 `retry_after_seconds` 响应体在本集群观察不到，只由单测覆盖。演练修正了两处驱动问题（安装目录创建、隔离槽数量应为 2），产品代码无改动。
- **验证**：`License*Test`、Checkstyle、源码头检查、`git diff --check` 通过（见提交说明）。当日剩下的三项（trust 密钥轮换与退役密钥、小时级摘要比较、性能对照）见下一节。

## 收尾演练：换钥、小时级比较、性能对照（2026-10-24 下午）

- **trust 密钥轮换与退役密钥**（`.build-records/license-trust-rotation-drill-20261024/`，三 FE 加一 BE；“下一版程序”用只改了 `LicenseTrustStore` 四个常量的 FE JAR 变体模拟，源码改动随即还原、未提交）：用内置 T1 签的清单 M1 同时带入新 license 密钥 K2 与新 trust 密钥 T2，逐台配置后三台摘要一致、VALID；T2 签的清单 M2 在现行程序上被拒（`UNTRUSTED_KEY`），即清单带入的 trust 密钥不能签下一份清单；一台 FE 在 K2 证书导入前先换到下一版（K1、T1 已退役）会隔离 active 与 base 两槽（kid `self-use-license-20260929`）、状态 INVALID，Master 导入 K2 证书后该 FE 随回放自动恢复、无需重启；其余两台逐台换版期间混合集群持续服务，M1 在新版上只告警（签名方 T1 不再内置）、发行包明文清单中的 K1 只告警“1 key not built in”不能复活；去掉 M1 配置后干净启动；K1 签的证书在新版返回 `LICENSE_UNTRUSTED_KEY`（HTTP 400 / SQL 6201）；新版上 T2 签的 M2 被接受并导入 K3 证书，信任链延续。换钥顺序写入管理手册第 1 节。三轮驱动修正（主节点重启的 helper、离群告警的时机、新版上明文清单固有告警）都是驱动问题，产品代码无改动。
- **小时级摘要比较**（同目录 `tools/hourly.py`，三 FE，fe2 配置签名清单使摘要持续不同）：fe1 于 11:14:28 启动，Master 在 12:14:30 与 13:14:31 各记一条 "License trust differs between FEs"（间隔 3601 秒），135 个逐分钟采样中 fe2 摘要始终不同；每小时比较一次、只告警不改状态，得到实测。首次比较发生在当选后的首个维护周期，当时 Follower 多半还没起来，所以可观察到的是整点重复。
- **性能对照**（`.build-records/license-perf-comparison-20261024/`）：同一主机、同一 BE，上一个包的 FE JAR（`28f6484bfd6`，批次 1 之前）与现行 JAR（`58e87e811db`）交替各跑两轮，8 线程闭环各 3000 次：`SELECT 1` 约 27k QPS、p50 0.22 至 0.25 ms、p99 0.88 至 0.96 ms；单 BE 点查 count 约 3.8k QPS、p50 0.48 至 0.51 ms、p99 9 至 11 ms；`SHOW FRONTENDS` 约 1.9k QPS、p50 4.0 ms、p99 9 至 10.5 ms。两组在每条语句上都落在彼此的轮间波动内（QPS 差 1% 至 3%，p50 差不到 0.03 ms，p99 区间重叠），重写后的时钟与缺口容忍回放在查询准入路径上没有可测量的开销。局限：单 FE 单 BE 十万行、客户端与服务同机，是相对比较，不是 600 BE 规模的生产画像。
