<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# FE 授权证书管理操作说明

本说明对应 P2 的证书管理、元数据持久化和恢复。阶段状态及实际验收记录见[实施记录](license-implementation-progress-20260922.md)。P3 负责查询与新增节点准入，P2U 负责页面；P2 状态显示的有效性和节点额度不代表这两个阶段已经交付。

## 1. 安装公钥并取得部署申请

在离线签发机按[签发工具说明](../tools/license-issuer/README.md)创建 Ed25519 密钥、导出信任清单。签发私钥留在签发机。`license` 与 `time_repair` 使用不同密钥和 `kid`，不附带任何测试根。

**2026-10-16 起，自用公钥内置在 `doris-fe.jar` 中**，FE 不配置外部文件也能加载公钥并就绪。发行包仍提供与内置清单同字节的 `conf/massdb-license-trust.json` 和下面这行配置，因为更早的 FE 版本只会从外部文件读公钥；升级和降级时都请保留。清单只在启动时加载，修改文件后需要重启：

```properties
massdb_license_trust_store_file = /etc/massdb/license-public-keys.json
```

**2026-10-23 起，明文清单不再扩展信任。** 本版本只把它与内置公钥比对：条目与内置公钥一致则无事，多出的或不同的公钥一律忽略并在 fe.log 记一条告警，运维方因此不能再通过改配置让 FE 认自己的签发密钥。追加公钥（换钥过渡期）改用签发方签过名的清单：签发方用 `license_issuer.py trust-sign` 以内置的 `trust` 用途密钥（`kid` `self-use-trust-20261023`）对公钥清单签名，得到 compact JWS（`typ` 为 `massdb-trust+jws`，负载含 `schema_version`、`issued_at`、`sequence`、`keys`）；各 FE 配置下面这行并重启，验签通过的公钥并入信任，验签失败只告警并忽略，内置公钥照常生效。换钥流程是：签发方用旧 `trust` 密钥签一份含新密钥的清单发给运维，各 FE 配置后重启，下一版程序再把新密钥编入常量。

```properties
massdb_license_trust_manifest_signed = /etc/massdb/license-trust.jws
```

**换钥与退役密钥的顺序（2026-10-24 真实演练验证）。** 1）签发方生成新的 `license` 密钥 K2 和新的 `trust` 密钥 T2，用当前内置的 trust 密钥 T1 对同时含 K2（`license`）与 T2（`trust`）的清单签名，得到 M1。2）运维在每台 FE 配置 `massdb_license_trust_manifest_signed` 指向 M1 并逐台重启，先 Follower 后 Master；各台 `trust_sha256` 随之变化且相同。3）签发方用 K2 签新证书，在 Master 导入；此时每台 FE 同时信任 K1 与 K2。4）下一版程序把 K2、T2 编入常量并去掉 K1、T1。升级到该版本必须在第 3 步之后：若某台 FE 先升级，它验不了 K1 签的现有证书，会隔离 active 与 base 两个槽并返回 `INVALID`，直到 K2 证书导入后随回放自动恢复，不需要再重启。5）升级后 M1 因签名方 T1 不再内置而验签失败，只告警不影响运行，可以从配置中删除；用 K1 签的证书从此导入返回 `LICENSE_UNTRUSTED_KEY`，发行包里明文清单仍列出的 K1 也不能让它复活。6）之后的换钥由 T2 签清单，只有把 T2 编入常量的程序才接受：清单里加进来的 trust 密钥不能用来签下一份清单。完整过程（三 FE，混合版本运行、错误顺序的后果与恢复）记录在 `.build-records/license-trust-rotation-drill-20261024/`。

**安全边界与残余风险（2026-10-24）。** 签名清单堵住的是“运维方改配置让 FE 认自己的签发密钥”这一条路。证书绑定的是集群初始化时生成的部署标识，不绑定机器身份：把一套 FE 的完整元数据（含部署标识与许可记录）复制到另一套集群，复制出来的集群在证书有效期内同样有效，续期证书也可以同样复制。本版本不防护这一场景，也不缩短首张证书的期限或在续期时校验集群谱系；首张证书按合同期限发放，由合同、`customer_id`、`license_id` 与签发台账约束，`SHOW LICENSE` 中的这些字段和部署标识便于现场核对。

已有 HTTP/HTTPS 及内部通信配置继续有效，无新增 BE 配置。若 FE 管理端口不同，可在各 FE 配置以下映射并重启；键必须匹配已注册的 `host:edit_log_port`，值为 HTTP(S) 管理端口：

```properties
massdb_license_fe_management_ports = fe-a:9010=8030,fe-b:9010=8130
```

IPv6 键使用方括号，例如 `[2001:db8::1]:9010=8030`。协议跟随现有 `enable_https`，未配置映射时能力检查使用本 FE 的 `http_port` 或 `https_port` 作为对端默认端口。映射也用于 HTTPS 下的 Follower 管理转发；HTTP 转发使用当前 Master 发布的 HTTP 端口。它不改变原 FE helper/心跳的端口假设，也不能改写目标主机或协议。

Master 在恢复完成、且确认全部已注册 FE 都带有许可模块后，持久生成部署 UUID（每个集群只发生一次）。这项检查不比较各 FE 的 JAR 和公钥清单，只防止从不带许可模块的旧版滚动升级时，旧 FE 回放到不认识的初始化记录。普通 GET 或 Follower 不生成 UUID。未就绪时先核对各 FE 是否都已升级、管理端口能否访问和恢复日志；不能自行填入一个 UUID 代替集群申请。

管理员通过以下任一入口取得申请：

```sql
SHOW LICENSE DEPLOYMENT;
```

```http
GET /api/license/deployment
```

HTTP 返回精确的 `schema_version`、`product`、`deployment_id`、`registered_fe_nodes`、`registered_be_nodes` 字段，可保存为签发工具 `prepare-claims --request` 的输入。SQL 返回 `Key/Value` 两列，应转换为相同类型的 JSON。离线节点仍包含在已注册用量中。

## 2. 验证、导入和查看

SQL 管理命令使用现有认证和 ADMIN 权限。除 `SHOW LICENSE` 的普通用户脱敏结果外，以下命令均要求 ADMIN：

```sql
SHOW LICENSE;
ADMIN VALIDATE LICENSE '<compact-JWS>';
ADMIN IMPORT LICENSE '<compact-JWS>';
SHOW LICENSE IMPORT '<sha256-fingerprint>';
```

VALIDATE 与 IMPORT 使用相同候选策略；VALIDATE 不生成身份、不写证书、最高序号或导入回执。实际导入在提交时重新检查状态和成员版本，预检成功不预留导入资格。

字面量是证书正文，不是服务器路径。管理语句明确拒绝服务端 PREPARE；某些 JDBC 驱动会自动改为客户端模拟。建议单独发送文本命令，或使用文件导入辅助工具：

```bash
python3 tools/license-issuer/license_sql_import.py /secure/customer-license.jws \
    --operation validate | mysql --defaults-extra-file=/secure/client.cnf
python3 tools/license-issuer/license_sql_import.py /secure/customer-license.jws \
    | mysql --defaults-extra-file=/secure/client.cnf
```

辅助工具读取不带尾随换行的原始 compact JWS，拒绝引号、转义、空白和超过 64 KiB 的输入。客户端凭据由权限受控的配置文件提供。

HTTP 使用相同认证和管理逻辑：

| 请求 | 输入 |
| --- | --- |
| `GET /api/license` | 管理员详情；普通用户仅 `status/expires_at/administrator` |
| `POST /api/license/validate` | `{"certificate":"<compact-JWS>"}` |
| `POST /api/license/import` | 同上 |
| `GET /api/license/imports/{fingerprint}` | 原证书字节的 SHA-256 小写十六进制 |

Basic 认证可用于接口调用。浏览器 Cookie POST 必须同时提供匹配 FE 请求来源的 `Origin` 和 `X-MassDB-License-CSRF: 1`。Basic 请求若携带 `Origin`，同样要满足同源检查。Follower 转发时 Master 重新检查原用户身份、密码和 ADMIN 权限。

管理员详情包含 active/pending、最高接受序号、FE/BE 注册用量、当前证书额度、已提交基础额度、可信 UTC 和本地应用版本。普通用户看不到客户信息、部署标识或完整证书详情。所有到期字段为 UTC Unix 秒；`SET time_zone` 不改变许可时间，`now == expires_at` 即到期。

### 2.1 取代式续期、缩短与降额

**2026-10-15 起的规则。** 同一部署内 sequence 更高的合法证书一经导入，就完全取代当前 active 和 pending 的全部承诺。FE 不再比较新旧证书的到期时间、生效时间、额度和功能集，只要求新证 FE、BE 额度分别容纳当前已注册+预留用量。因此可以导入到期更早的证书，也可以在旧证尚未到期、集群已真正缩容后导入额度更低的证书。该规则需要本轮更新后的 FE；验收结果见[执行计划与验收记录](license-renewal-replacement-plan-20261015.md)。

例如旧证允许 3 个 FE、10 个 BE 且还有 40 天到期；成功缩容至 2 个 FE、5 个 BE 后，可立即导入同一部署、更高 `sequence`、允许 2/5 的新证。当前已注册用量按全部成员计算，停进程、离线或处于 DECOMMISSION 中尚未除名的节点仍占额度；原副本、WAL、FE quorum 等安全限制保留，不强制删除线上节点。

生产 BE 缩容应沿用 `DECOMMISSION BACKEND`，等待数据迁移并确认成员真正除名；原版默认会拒绝直接 `DROP BACKEND`，本次不改变该保护。验收中的强制 `DROPP BACKEND` 仅清理自建、无 BE 进程且零 tablet 的离线测试身份，不作为线上缩容操作建议。

**未来生效的证书不能降低额度（2026-10-16 起）。** `not_before` 晚于当前可信时间、且 FE 或 BE 额度低于当前证书或基础额度的证书，导入时返回 `LICENSE_RENEWAL_REDUCTION`（SQL 6201、HTTP 400），保旧、不消费序号。原因是 2026-10-15 之前的带许可 FE 版本恢复时不接受这种待生效状态，会直接退出；拒绝它可以保证混版本运行和整集群降级都不受证书影响。降额请让证书立即生效，或等到生效时间到达后再导入。到期更早、立即降额、丢弃 pending 等其他情况不受影响。

**导入前先 VALIDATE，并核对返回的 `changes`。** validate 与 import 成功响应都有 `changes` 数组（SQL 结果集中为 `changes` 一行 JSON 字符串，HTTP 和页面直接展示）：

| code | 含义 | 字段 |
| --- | --- | --- |
| `EXPIRY_SHORTENED` | 新证到期早于当前 active | `previous_expires_at`、`expires_at` |
| `COVERAGE_GAP` | 旧 active 到期后新 pending 才生效，空档内查询按 EXPIRED 受限 | `gap_seconds`（与 `coverage_gap_seconds` 一致） |
| `FE_LIMIT_REDUCED` / `BE_LIMIT_REDUCED` | 新证额度低于当前 active 或基础额度 | `previous_limit`、`limit` |
| `PENDING_DISCARDED` | 已接受的 pending 被新证替换 | `license_id`、`sequence` |
| `FEATURES_REMOVED` | 新证功能少于当前 active | `features` |

`changes` 只是事实提示，不阻止导入。validate 不预留任何东西：import 会按当时的成员和时间重新裁决，额度仍满足就成功并返回当时重新计算的 `changes`，以 import 响应为准；不满足则拒绝。幂等重试和回执查询不携带 `changes`。

已消费的序号不可回退。重新导入被取代的旧证只返回原回执，不恢复旧期限或额度；误导入短期或低额证书时，只能由签发方签发更高序号的新证纠正，需要恢复更长期限或更高额度时同样导入一张新证即可。

新证任一节点额度小于实际已注册+预留用量时，以 `LICENSE_NODE_LIMIT_TOO_SMALL` 拒绝：SQL 6201 / SQLState 45000，HTTP 400，`retryable=false`、`submission_status=NOT_SUBMITTED`，原证书、基础额度、最高序号和成功回执不变。立即生效的新证成功提交时成为 active 并同步成为基础额度，旧 pending 被丢弃；导入失败不能恢复过期证书的读取资格。

若新证在未来生效，它替换已有 pending，active 不变。导入后至生效之间查询仍按当时许可状态决定。ADD 的 FE/BE 上限分别取已提交基础额度与已接受 pending 额度的较小值，较低 pending 立即约束新增，较高 pending 不提前开放扩容。到点重新检查注册+预留用量并持久提交新的基础额度，不能把预检、导入回执或到达生效时间本身当作基础额度已切换。

## 3. 超时、重试和错误

保存证书原始字节及其 SHA-256 指纹。相同指纹重试确认原提交，不会重新覆盖更新的证书，也不恢复被取代证书的期限或额度。最高序号单调不回退；拒绝的候选不改变已接受证书、最高序号、基础额度或成功回执。

| 结果 | 客户端处理 |
| --- | --- |
| HTTP 200，`APPLIED` | 已持久提交且当前 FE 已应用；记录 `committed_version` |
| HTTP 202，`COMMITTED` | 已提交但当前 FE 尚未应用；`retryable=true` 仅表示继续轮询回执，不能重新提交变更；保留原版本 |
| `UNKNOWN` | 当前无法确认结果，`retryable=false`；查询回执，不直接重提变更，不推断未提交或盲目签发替代证书 |
| HTTP 400 / SQL 6201、45000 | 候选或格式错误，按 `reason` 修正输入 |
| HTTP 409 / SQL 6202、45000 | 状态、序号或节点额度冲突；先重新查看已提交状态，不按事务序列化失败自动重试 |
| HTTP 429 / SQL 6203、HY000 | 用户速率或管理队列已满；HTTP 遵守 `Retry-After`，SQL 按 `reason` 退避重试 |
| HTTP 503 / SQL 6203、HY000 | 尚未就绪或提交不可确认；结合 `submission_status` 和回执处理，历史不可确认见下一行 |
| HTTP 503、`*_HISTORY_UNAVAILABLE` / SQL 6204、HY000 | 历史回执不可确认；不表示从未提交 |
| HTTP 401/403 | 原认证/权限或 CSRF 拒绝，修正调用身份和来源 |

SQL 使用结果行表达提交/应用状态，错误保留独立 errno 与 SQLSTATE；原认证/权限错误仍使用原错误码，不强制转换为 6201–6204。HTTP 错误正文包含稳定的 `reason`、脱敏 `message`、`retryable`、`submission_status` 和版本字段；能定位提交时包含指纹或 `repair_id`，尚不能确定的版本可为 `null`。

先判断 `submission_status`，再解释 `retryable`，不能仅根据 HTTP 409/503 或 SQL 错误码自动重试。`LICENSE_NOT_READY`（恢复或回放追赶期）的管理响应和受保护读取的拒绝体都带 `retry_after_seconds = 30`，HTTP 同时带 `Retry-After: 30`；客户端按它退避，不要以更短间隔重试。负载均衡的健康检查请使用无需认证的只读 `GET /api/license/health`：本 FE 能提供受保护读取时返回 200 `{"status":"READY"}`，否则 503 `{"status":"NOT_READY","retry_after_seconds":30}` 并带 `Retry-After`，不含任何许可细节；`GET /api/license` 在未就绪时仍返回 200，以便页面展示原因。`NOT_SUBMITTED` 只有明确的暂态原因返回 `retryable=true`：`LICENSE_NOT_READY`、`LICENSE_IMPORT_NOT_READY`、`LICENSE_NOT_LEADER`、`LICENSE_RATE_LIMITED`、`LICENSE_MANAGEMENT_BUSY`、`LICENSE_METADATA_UNAVAILABLE`、`LICENSE_STORE_UNAVAILABLE`、`LICENSE_STALE_IMPORT_DECISION`。这允许在状态重新就绪后退避重试，不保证无限重试能够恢复。永久证书/修复冲突、节点超额、FE 升级要求、时钟修复要求、验签不可用及历史不可确认均为 `false`，须按原因处理。`UNKNOWN` 必须先按指纹或 `repair_id` 确认；`COMMITTED` 只需等待原提交应用，不能将轮询建议解释为重新导入或再次修复。

内置页面在导入返回 `UNKNOWN` 或 `COMMITTED` 后，仅对原指纹执行只读回执查询，最多持续 120 秒，按 2/4/8/16/30 秒退避；不会自动重发导入请求。历史已经淘汰时，轮询不能重建回执，超时后需要人工确认。自建 Java 服务或代理也应区分“查询提交结果”和“再次提交证书”，不要只因 HTTP 503 就自动重发 POST。

当前协议将 6202 的 SQLSTATE 统一为 `45000`。旧验收记录中的 `40001` 是当时版本的真实返回，保留作为历史证据，不代表新版本协议。

轮询导入时使用 `GET /api/license/imports/{fingerprint}` 或 `SHOW LICENSE IMPORT`；修复时使用对应 `repair_id` 回执入口。需要确认某台 FE 已应用时，持续请求该 FE，直到回执为 `APPLIED` 且 `applied_version >= committed_version`。建议从 2 秒间隔逐步退避到 10 秒，并由客户端设置等待截止时间；超时后保留 `COMMITTED` 或 `UNKNOWN` 和原回执，不能改判为未提交。旧指纹返回的是那次提交的版本，并不表示它仍是当前有效证书。

原始证书上限 64 KiB、时间修复票据上限 16 KiB、HTTP body 上限 96 KiB，均按字节计算。HTTP 字段超限返回 400 / `LICENSE_INPUT_TOO_LARGE`，body 超限返回 400 / `LICENSE_BODY_TOO_LARGE`，均在进入验签队列前拒绝。验签使用两线程及 32 个排队位置，每用户每分钟最多 10 次、突发最多 3 次。Follower 取得已提交结果后等待本地应用最多 5 秒；这不是整个 HTTP 请求的超时上限。查询状态和历史回执不消耗验签速率额度。

导入与时间修复回执各最多保留 1,024 条，并保留当前证书槽位所需的定位信息。历史淘汰后不伪造成功结果；客户端应保留已经取得的提交回执。

## 4. 时间异常修复

正常运行按单调时钟推进可信 UTC，并每 `massdb_license_watermark_interval_seconds`（默认 600 秒，范围 60 到 3600）持久保存一次时间水位。可信时间等于已提交水位加本进程单调时钟走过的时长，再加已确认的墙钟前向修正；它永不倒退，墙钟回拨只是告警信号，不改变可信时间。水位在任何状态下都照常写出已确认时间，包括可疑期间。

**墙钟回拨（2026-10-23 起不再粘滞）。** 两个容差分开配置：进程内墙钟落后已确认可信时间超过 `massdb_license_clock_rollback_tolerance_seconds`（默认 12 小时）进入可疑；启动锚点与 Follower 回放的水位超前墙钟超过 `massdb_license_clock_startup_tolerance_seconds`（默认 5 分钟，上限 1 小时）进入可疑。启动容差限制“停机后把墙钟设回停机前再启动”能跳过的时长，不能跟着进程内容差一起放宽。可疑状态每次读取重新判定，墙钟回到容差内即自动解除，不需要重启、命令或票据。只有 Master 才因本机可疑拒绝查询；Follower/Observer 的可信时间来自 Master 水位加本机单调时钟，本机墙钟不参与计算，本机可疑只在 `SHOW LICENSE` 的 `clock_local_suspect` 和日志中体现。Master 的可疑持续 5 分钟以上（启动稳定期之后计）才作为 `clock_suspect` 持久化并随元数据传播到所有 FE；墙钟恢复后 Master 立刻写一条清除记录。

**墙钟前跳。** 前跳不再立即生效，也不再触发可疑：它先作为待确认修正，查询、导入和水位都只使用已确认的可信时间。不超过进程内容差的前跳持续 5 分钟仍成立即自动确认；超过的在 1 小时后自动接受，或由管理员提前确认；期间墙钟被校正回去就直接丢弃，不留痕迹。多 FE 集群中 Master 每分钟通过 `GET /api/license/capability` 比较各 FE 的墙钟，一致的标准是偏差不超过启动容差（默认 5 分钟）：多数 FE 与自己一致的前跳立即确认；自己是离群值时既不自动确认也不持久化可疑，直到同伴一致或管理员确认。少于三台 FE 或没有多数时不作判定，按时间窗口处理。`SHOW LICENSE` 的 `clock_pending_forward_seconds`、`clock_pending_age_seconds`、`clock_peer_verdict` 显示当前状态。

**启动稳定期。** 启动后 `massdb_license_clock_settling_seconds`（默认 10 分钟，上限 1 小时）内：墙钟快于水位的部分立即用于准入（反复重启得不到好处），但只在稳定期结束且墙钟仍一致后才写进水位，所以 NTP 在稳定期内校正开机错误的快钟不留痕迹；墙钟慢于水位的可疑只告警不拒绝，NTP 同步后自动解除。稳定期结束后仍可疑才拒绝并计入持久化等待。固有限制：单台 FE 没有同伴和可信外部时间源时无法区分“钟错了”和“真的停了很久”，全集群同时错钟且超过稳定期的快钟会被确认，多出的时间只能由签发方票据往回拨；这是修复票据保留的场景。

当前实现避免把单次采样期间的线程暂停直接当成墙钟跳变：每次许可时间读取各采样一次单调时钟和墙钟，不新增查询锁或对象分配；前跳的跟踪在管理线程每秒一次的观察中完成，候选值取观察窗口内的最小值，一次被暂停拉长的样本不能单独被确认。进程启动或修复时建立锚点，管理路径最多重采样 32 次，只接受两次单调时钟间隔不超过 1 ms 的墙钟样本；若连续 32 次都无法取得可靠配对，仍保守进入可疑，不会把采样失败作为异常抛给 image/journal 回放。

```sql
ADMIN LICENSE CLOCK CHALLENGE;
ADMIN REPAIR LICENSE CLOCK '<repair-compact-JWS>';
SHOW LICENSE CLOCK REPAIR '<repair-id>';
ADMIN CONFIRM LICENSE CLOCK;
```

`ADMIN CONFIRM LICENSE CLOCK`（HTTP `POST /api/license/clock/confirm`，空正文或 `{}`）在 Master 上确认当前待确认的前向修正，返回 `confirmed_forward_seconds` 与确认后的 `trusted_utc`；没有待确认修正时返回 0。确认前请核对该 FE 与其他 FE 的墙钟一致。

HTTP 对应 `POST /api/license/clock/challenge`（空正文或 `{}`）、`POST /api/license/clock/repair`（正文 `{"repair_certificate":"..."}`）、`GET /api/license/clock/repairs/{repair_id}`。仅使用成功返回的 `challenge` 对象，按签发工具的 `repair-sign` 说明在离线签发机生成票据。只收到 `COMMITTED` 而没有 `challenge` 时，等待本地恢复应用后重新申请，不自行补全挑战字段。

挑战绑定当前 Master 进程、任期、nonce、epoch 和修复授权版本，有效期为 24 小时单调时间；重启或切主后重新申请。成功修复只提交新的时间 epoch，保留证书有效期、最高序号和基础额度。相同票据重试只确认原回执，不再次降低水位。修复票据现在只用于可信时间已经跑到真实时间前面的情形（错误的前跳被确认、或启动时错误的快钟在稳定期后进入水位）；墙钟回拨造成的可疑不需要票据，校正墙钟即可。

## 5. 恢复与升级

部署身份、证书原文、激活事实、基础额度、序号、时间水位及回执通过 FE journal 和 image 保存。Checkpoint 使用独立 Env 历史截面，不生成新身份或追加授权日志。过期证书在恢复后正常显示 EXPIRED；可隔离的坏 pending/base 分别处理，未知格式和整体存储损坏遵循现有 FE 恢复机制。

首次初始化前，全部已注册 FE（含 Observer）都须带有许可模块，离线成员也须先恢复；此后导入证书不再探测其他 FE，FE 离线、各 FE 的 JAR 字节不同（热修复或重新编译）或外部公钥文件不同都不阻止导入，也不再返回 `LICENSE_FE_UPGRADE_REQUIRED`（混版本期间若旧版 FE 仍是 Master，它仍按旧规则拒绝导入，请在新版 Master 上导入或全部升级后导入）。管理员可访问各 FE 的只读 `GET /api/license/capability` 核对模块、格式版本、`trust_sha256`（实际加载的公钥集合摘要）和节点身份；`package_sha256` 不再计算，返回 `null`。普通用户不能访问。导入不再检查的前提是：新版只写所有带许可旧版都能回放的记录（见第 2.1 节“未来证书不能降额”），且许可持久化格式保持不变。

授权元数据采用 `massdbLicenseV1` 模块和 journal 6200–6205；包含新事实的 image 使用版本 141，旧 FE 不支持读取。不可用旧二进制直接加入已启用新格式的集群。

**回放缺口（2026-10-23 起）。** 每条许可记录都是完整快照：三个槽、回执、时钟事实全部带上，后一条记录到达就覆盖前面任何缺口。回放接受同一部署、bootstrap 不变、激活不回退的任何更高版本记录，不要求版本连续；版本不高于本机的记录、其他部署的后续记录整条忽略并计数，只有其他部署的 INITIALIZE 记录被当作 Master 重新初始化而采纳。`clock.version` 自此等于记录版本，旧版 FE 只要求它递增，回放新记录不受影响。被 `force_skip_journal_ids` 跳过的授权或成员日志、经 `skip_operation_types_on_replay_exception` 跳过的成员回放异常、以及 141 版 image 缺少许可模块，都只在本机记为“回放缺口”：`SHOW LICENSE` 的 `replay_gaps`、`recent_replay_gaps`（journal id、操作码、类型、时间）与 `ignored_records` 可见，fe.log 有 WARN，不再设置任何标志、不抬高 image 版本、不停止受保护读取。image 模块中的布尔位固定写 `false`；读到旧版写入的 `true` 只记一条缺口。跳过成员操作的 FE 可能少计成员，标准处理仍是从 Master 的 image 重建该 FE；全部许可记录被跳过且 image 无模块时 Master 会重新初始化并生成新的部署 ID，证书需要重新签发，这是元数据丢失应有的结果。`massdb_license_probe_skipped_journal_header` 保持默认 `false`，探测物理损坏记录可能使 JE 环境失效。首次初始化前的探测以 BDBJE 复制组成员为准，frontends 表中缺失的成员也会被探测。

混合版本期间，尚未升级的带许可 FE 仍按严格链式规则工作，遇到缺口会自行标记不完整；请先升级所有 FE 再处理缺口。做 `force_skip_journal_ids` 或改动服务器时间之前，先联系签发方确认影响。

**各 FE 信任配置不一致（2026-10-23 起）。** Master 用合并后的公钥接受证书，某台 FE 缺少对应公钥时只会在本机把该槽隔离，受保护读取在那台 FE 返回 `INVALID`。隔离时 fe.log 记一条 WARN，给出槽位、证书头中的 `kid`、原因（如 `UNTRUSTED_KEY`、`INVALID_SIGNATURE`、`DEPLOYMENT_MISMATCH`）和本机 `trust_sha256`；`SHOW LICENSE` / `GET /api/license` 的管理员视图新增 `trust_sha256`（本机实际加载的公钥集合摘要）与 `invalid_slots`（上述明细列表），指标 `license_invalid_slots` 给出隔离槽数量。页面“授权证书”的“本 FE 诊断”卡片显示本机 `trust_sha256`、回放缺口计数、隔离槽位（槽位、证书 `kid`、原因）与最近的回放缺口；“时钟”卡片显示第 4 节的 `confirmed_utc`、同伴判定、可疑标志与待确认前跳。2026-10-24 的三 FE 真实演练（`.build-records/license-batch2-drill-20261024/`）覆盖了明文清单自造公钥被忽略、自签证书 `LICENSE_UNTRUSTED_KEY`、签名清单换钥、缺公钥 FE 的隔离与恢复以及 health 路由。Master 每小时通过能力接口比较各 FE 的 `trust_sha256`，不一致只记一条 WARN 列出节点和摘要前缀，不阻止任何操作。处理方法是核对该 FE 的 `massdb_license_trust_store_file` 与 `conf/massdb-license-trust.json`，修正后重启。

升级后的 FE 在完成初始化和证书导入前会拒绝受保护读取，当前没有自动宽限期。应提前准备全部注册 FE 的升级和离线签发流程，以及旧格式回滚所需的升级前元数据备份；修复信任公钥文件后按配置要求重启生效。

初始化可在管理员导入首证书之前自动发生：Master 完成恢复、所有注册 FE 的程序包/信任/能力证明通过，且任期与成员版本仍一致后，就可能提交第一个授权操作码。全部 FE 均未配置公钥时，信任摘要均为空也可能通过一致性证明；不能把“尚未导入证书”或“尚未配置公钥”当作旧格式回滚保障。回滚边界看实际写入的新 journal/image，不以升级后经过固定几秒判断。

切主前固定 journal 目标并最多续读三次；仍未完整到达则按既有晋升失败流程退出。持续存储故障可能使多个候选晋升失败，也可能失去足够存活节点；不保证自动重选能够恢复。应先核对日志、存储/复制状态及健康副本，按完整元数据恢复流程处理，不能把 `force_skip_journal_ids` 当作必经修复步骤。

FE/BE 注册额度在 P2 显示和导入策略中校验；新增节点的权威准入由 P3 接入。未来 pending 到点可以改变有效证书状态，基础额度切换仍须单独持久提交；等待期 ADD 按第 2.1 节较小上限执行。

**升级、混版本与降级（2026-10-16 起）。** 许可持久化格式不变，新版写入的许可记录所有带许可的旧版都能回放，因此：滚动升级期间新旧 FE 可以混跑，新版 Master 上的导入直接成功，旧 FE 回放新记录正常；整集群降级到更早的带许可版本不受证书影响，降级后旧版按它自己的规则处理后续导入。降级时请保留 `conf/massdb-license-trust.json` 与 `fe.conf` 中的信任配置行（旧版只从外部文件读公钥）。例外是 2026-09-30 至 10-15 的版本可能已经写入过“低额未来 pending”；降级到 2026-10-05 及更早的版本前，先按[第 5.2 节](#52-降级前处理遗留的低额未来-pending)检查和处理。降级到不带许可模块的版本不在支持范围内。实际验证见[降级兼容、内置公钥与取消导入前 FE 检查执行计划](license-downgrade-trust-compat-plan-20261015.md)。

### 5.1 手工导出镜像

`GET /dump` 是手工诊断/运维操作，需安排维护窗口。为使授权事实与镜像日志边界一致，操作先进入授权变更队列，再获取 Env 监视器和原有全局、数据库、表读锁，最后写盘。

- 在 Master 上，从等待上述锁开始，证书导入、节点 ADD/DROP、授权基础额度切换和时钟水位持久化都会排队；不是只有实际写盘阶段才占用队列。长时间持有表写锁的 DDL 会延长等待。
- 在 Follower/Observer 上，持有 Env 监视器期间本机 journal 应用暂停，直到释放后才能继续追赶；这不等于底层 JE 复制线程必然停止。切勿将该节点当作此期间始终追上 Master 的副本。2M tablet 规模的 dump 可能让回放延迟超过 `meta_delay_toleration_second`，Observer 会因此停止服务；请在不对外服务的 Observer 上低峰执行。保留 Env 监视器是有意的：dump 期间若发生“添加 Observer、删除、同地址再添加 Follower”而镜像保存了最终状态，从边界重放第一条 ADD FRONTEND 就会因角色不一致退出，只有持锁才能排除。
- 镜像耗时取决于元数据量、锁竞争和存储，没有本实现保证的固定完成时限。避免与续期、扩缩容、长 DDL 同时进行，同一 FE 不并发提交手工 dump。
- HTTP 等待目前没有 dump 专用服务端完成超时。客户端超时或断开连接不能证明任务取消，也不能证明文件完整；先核对 FE 日志和原请求对应结果，不立即反复重试。仅给 `future.get()` 加超时不会停止已开始的锁等待或 I/O。

普通查询的授权状态检查不获取这条变更队列，但 dump 原有元数据锁、磁盘负载及副本回放滞后仍可能影响其他工作，不能据此承诺 dump 对业务毫无影响。当前 `LicenseManager.close()` 的排队取消仅在明确调用该方法时生效；生产 DorisFE 退出钩子尚未调用它，不能把该 API 的单测当作生产退出行为保证。

### 5.2 降级前处理遗留的低额未来 pending

只有一种许可状态会让更早的带许可 FE 无法启动：pending 中有一张**尚未生效、FE 或 BE 额度低于当前 active 或基础额度**的证书。2026-10-16 起的版本拒绝导入这种证书（第 2.1 节），但更早的版本可能已经写入过：`c9b69a9a6b0`（2026-10-15 发行包）接受任何低额未来证书；2026-09-30 至 10-05 的版本在当前证书已经到期之后，接受晚于其到期时间生效的低额证书。新版能正常恢复和显示这种状态。降级目标是下表中会退出的版本时，必须先按本节处理。

| 低额 pending 的生效时间 | 降级到 2026-09-29 及更早 | 降级到 2026-09-30 至 10-05 | 降级到 `c9b69a9a6b0` 及之后 |
| --- | --- | --- | --- |
| 早于 active（或基础额度证书）的到期时间，与当前证书重叠 | FE 启动时退出 | FE 启动时退出 | 正常 |
| 不早于该到期时间，中间有空档 | FE 启动时退出 | 正常 | 正常 |

旧版不看当前时间，只比较记录里的生效时间、到期时间和额度。旧 FE 先加载本机最新的 image，再回放其后的全部 journal，两处任何一处带有这种状态都会退出（退出码 255）：在 image 中时，`fe.log` 先有 `start load image from …/image.N`，随后是 `Caused by: java.io.IOException: Invalid MassDB license metadata envelope`；在 journal 中时是 `replay Operation Type 6201, log id: N` 加同一个异常。因此**只把 pending 替换掉还不够，必须等每台 FE 都有一个覆盖替换记录的新 image**。

**1. 判断是否存在。** 用管理员账号在任一 FE 执行 `SHOW LICENSE`，或 `curl -u <admin> http://<fe_host>:<http_port>/api/license`（两者字段相同），也可以看页面“授权证书”中的“续期证书（pending）”卡片。以下三条同时成立即为该状态：

- `pending` 不为 `null`；
- `pending.not_before` 大于 `trusted_utc`，即尚未生效；
- `pending.max_fe_nodes` 小于 `active.max_fe_nodes` 与 `base_max_fe_nodes` 中的较大者，或 `pending.max_be_nodes` 小于 `active.max_be_nodes` 与 `base_max_be_nodes` 中的较大者。

再按上表判断影响哪些目标：`pending.not_before` 早于 `active.expires_at` 时，降级到 2026-10-05 及更早都会退出；否则只影响 2026-09-29 及更早。集群在上述版本上导入过这种证书、但它已经到点生效或已被替换时，当前状态不再满足上面三条，最新 image 之后的 journal 里却可能仍有那条记录，降级前同样执行第 3–5 步。

**2. 替换。** 请签发方签发同一部署、`sequence` 大于当前 `highest_sequence`、**立即生效**（`not_before` 不晚于当前时间）的证书。额度可以保持当前值，到原定降额日期再导入一张立即生效的降额证书；也可以直接是降低后的额度，但须先完成缩容（第 2.1 节）。在 Master 上先 VALIDATE，确认 `changes` 包含 `PENDING_DISCARDED`，再 IMPORT；之后各 FE 的 `pending` 为 `null`。在新版或仍在运行的 `c9b69a9a6b0` 上导入都可以，两者都已实测；在 `c9b69a9a6b0` 上不要再导入未来生效的低额证书。

**3. 记下替换后的 journal 号 J。** 在 Master 上执行 `SHOW FRONTENDS`，取 `IsMaster` 为 `true` 那一行的 `ReplayedJournalId`，记为 J。J 不小于替换证书那条 journal 的编号。

**4. 生成覆盖 J 的 image。** Checkpoint 只处理已经切换（roll）的 journal 库：当前库写满 `edit_log_roll_num` 条（默认 50000），或 Master 重启、切主时才会 roll，之后约 1 分钟内 Master 写出 `image.N`（`fe.log`：`checkpoint finished save image.N`），再推送给其他 FE（`push image.N to other nodes. totally X nodes, push succeeded Y nodes`）。写入频繁的集群可以直接等待；写入很少的集群可能很久都没有新 image，演练中替换后等了 150 秒，最新 image 仍早于 J。这时在 Master 上临时调小阈值，再做一次元数据写入：

```sql
SHOW FRONTEND CONFIG LIKE 'edit_log_roll_num';             -- 记下原值，默认 50000
ADMIN SET FRONTEND CONFIG ("edit_log_roll_num" = "1");
CREATE DATABASE massdb_image_roll;                          -- 选一个不存在的库名；写入后立即 roll
ADMIN SET FRONTEND CONFIG ("edit_log_roll_num" = "50000");  -- 立即恢复为原值
DROP DATABASE massdb_image_roll;
```

`ADMIN SET FRONTEND CONFIG` 只改这台 FE 运行时的值，FE 重启后恢复为 `fe.conf` 中的值；阈值为 1 时每次写入都会 roll，所以要马上恢复。也可以用当前运行的版本（不是降级目标）重启 Master，让它在接任时 roll；多 FE 集群会因此切主。元数据越大，checkpoint 和推送越慢，以第 5 步的检查结果为准。

**5. 逐台确认 image。** 在每台 FE（Master、Follower、Observer）的主机上查看 `<meta_dir>/image/`，最新的 `image.N` 必须满足 N > J；Master 日志中这次推送的 `push succeeded` 数应等于其他 FE 的数量。推送时离线、正在启动或推送失败的 FE 拿不到这个 image，重新加入后也要等下一次 checkpoint 才会收到：演练中推送时停机的 Observer 重新加入 90 秒后仍只有旧 image，用 2026-10-05 版启动即退出；Master 切换后立即生成的 image 也没有推到当时正在启动的 FE。处理方法是先用当前版本把它启动并跟上，再在 Master 上重做第 4 步，直到每台 FE 都满足 N > J。

**6. 降级。** 停止全部 FE，换上目标版本的 JAR，保留 `conf/massdb-license-trust.json` 和 `fe.conf` 中的信任配置行，再启动。各 FE 的 `fe.log` 应显示从 `image.N`（N > J）加载；许可状态与降级前一致，`pending` 为 `null`，查询正常。

**已经尝试降级、FE 退出时。** 换回原来版本的 JAR 重新启动即可，许可状态不变；然后从第 2 步做起。演练中 2026-10-05 版在真实元数据上退出后，换回 `c9b69a9a6b0` 正常就绪，pending、额度和查询都与之前一致；多 FE 演练中一台旧版 Observer 退出时，其余 FE 照常运行。

上述步骤的单 FE 与 3 FE（2 Follower + 1 Observer）实测结果见[执行计划第 7.6 节](license-downgrade-trust-compat-plan-20261015.md#76-补充演练遗留低额未来-pending-的降级2026-10-16)。
