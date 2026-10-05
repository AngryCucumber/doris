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

在离线签发机按[签发工具说明](../tools/license-issuer/README.md)创建 Ed25519 密钥、导出信任清单。FE 只安装公钥清单；签发私钥留在签发机。`license` 与 `time_repair` 使用不同密钥和 `kid`，产品不附带默认信任根。

所有已注册 FE 安装相同程序包和字节完全相同的清单，在各 FE 的 `fe.conf` 中指定只读启动配置，再按已有流程重启。清单只在启动时加载，修改文件后也需要重启：

```properties
massdb_license_trust_store_file = /etc/massdb/license-public-keys.json
```

已有 HTTP/HTTPS 及内部通信配置继续有效，无新增 BE 配置。若 FE 管理端口不同，可在各 FE 配置以下映射并重启；键必须匹配已注册的 `host:edit_log_port`，值为 HTTP(S) 管理端口：

```properties
massdb_license_fe_management_ports = fe-a:9010=8030,fe-b:9010=8130
```

IPv6 键使用方括号，例如 `[2001:db8::1]:9010=8030`。协议跟随现有 `enable_https`，未配置映射时能力检查使用本 FE 的 `http_port` 或 `https_port` 作为对端默认端口。映射也用于 HTTPS 下的 Follower 管理转发；HTTP 转发使用当前 Master 发布的 HTTP 端口。它不改变原 FE helper/心跳的端口假设，也不能改写目标主机或协议。

Master 在恢复完成且已注册 FE 能力检查通过后持久生成部署 UUID。普通 GET 或 Follower 不生成 UUID。所有 FE 均未安装信任清单时也可初始化部署身份，但不能导入未受信任的证书。未就绪时先核对 FE 包、公钥清单和恢复日志；不能自行填入一个 UUID 代替集群申请。

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

### 2.1 到期后缩容续期

**2026-09-30 新增规则已实现。** 旧证到期不会禁止正常缩容与证书管理。按原安全流程完成 FE/BE 缩容、确认成员已成功 DROP 后，可以导入较低额度的新证书；旧证已经到期的历史额度不再是永久下限。该规则需要本轮更新后的 FE，之前交付的版本仍保留旧限制。定向回归与真实单 FE SQL/HTTP、注册身份缩容及重启结果见[验收记录](license-expired-renewal-20260930.md)；不以此代替线上 BE 数据迁移或真实多 FE 缩容验证。

例如旧证允许 3 个 FE、10 个 BE，授权覆盖已经结束；成功缩容至 2 个 FE、5 个 BE 后，可申请同一部署、更高 `sequence` 且允许 2 个 FE、5 个 BE 的续期证书，再执行 VALIDATE/IMPORT。仍然有效或尚未开始但未到期的已接受授权承诺不能被削减。当前已注册用量按全部成员计算，离线或处于 DECOMMISSION 中尚未 DROP 的节点仍占额度，原副本、WAL、FE quorum 等安全限制保留，不强制删除线上节点。

生产 BE 缩容应沿用 `DECOMMISSION BACKEND`，等待数据迁移并确认成员真正除名；原版默认会拒绝直接 `DROP BACKEND`，本次不改变该保护。验收中的强制 `DROPP BACKEND` 仅清理本轮自建、无 BE 进程且零 tablet 的离线测试身份，不作为线上缩容操作建议。

新证任一节点额度小于实际已注册+预留用量，或削减未过期 active/pending/base 额度承诺，仍以 `LICENSE_NODE_LIMIT_TOO_SMALL` 拒绝：SQL 6201 / SQLState 45000，HTTP 400，`retryable=false`、`submission_status=NOT_SUBMITTED`，原证书、基础额度、最高序号和成功回执不变。立即生效的新证成功提交时同步采用新的基础额度；导入失败不能恢复过期证书的读取资格。

若新证在未来生效，导入后至生效之间查询仍按当时许可状态决定。ADD 的 FE/BE 上限分别取已提交基础额度与已接受 pending 额度的较小值，防止缩容后再次扩容超过新额；这不会提前开放较高额度 pending 的扩容能力。到点重新检查注册+预留用量并持久提交新的基础额度，不能把预检、导入回执或到达生效时间本身当作基础额度已切换。

## 3. 超时、重试和错误

保存证书原始字节及其 SHA-256 指纹。相同指纹重试确认原提交，不会重新覆盖更新的证书。序号和已有授权覆盖受保护；拒绝的候选不改变已接受证书、最高序号、基础额度或成功回执。

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

先判断 `submission_status`，再解释 `retryable`，不能仅根据 HTTP 409/503 或 SQL 错误码自动重试。`NOT_SUBMITTED` 只有明确的暂态原因返回 `retryable=true`：`LICENSE_NOT_READY`、`LICENSE_IMPORT_NOT_READY`、`LICENSE_NOT_LEADER`、`LICENSE_RATE_LIMITED`、`LICENSE_MANAGEMENT_BUSY`、`LICENSE_METADATA_UNAVAILABLE`、`LICENSE_STORE_UNAVAILABLE`、`LICENSE_STALE_IMPORT_DECISION`。这允许在状态重新就绪后退避重试，不保证无限重试能够恢复。永久证书/修复冲突、节点超额、FE 升级要求、时钟修复要求、验签不可用及历史不可确认均为 `false`，须按原因处理。`UNKNOWN` 必须先按指纹或 `repair_id` 确认；`COMMITTED` 只需等待原提交应用，不能将轮询建议解释为重新导入或再次修复。

当前协议将 6202 的 SQLSTATE 统一为 `45000`。旧验收记录中的 `40001` 是当时版本的真实返回，保留作为历史证据，不代表新版本协议。

轮询导入时使用 `GET /api/license/imports/{fingerprint}` 或 `SHOW LICENSE IMPORT`；修复时使用对应 `repair_id` 回执入口。需要确认某台 FE 已应用时，持续请求该 FE，直到回执为 `APPLIED` 且 `applied_version >= committed_version`。建议从 2 秒间隔逐步退避到 10 秒，并由客户端设置等待截止时间；超时后保留 `COMMITTED` 或 `UNKNOWN` 和原回执，不能改判为未提交。旧指纹返回的是那次提交的版本，并不表示它仍是当前有效证书。

原始证书上限 64 KiB、时间修复票据上限 16 KiB、HTTP body 上限 96 KiB，均按字节计算。HTTP 字段超限返回 400 / `LICENSE_INPUT_TOO_LARGE`，body 超限返回 400 / `LICENSE_BODY_TOO_LARGE`，均在进入验签队列前拒绝。验签使用两线程及 32 个排队位置，每用户每分钟最多 10 次、突发最多 3 次。Follower 取得已提交结果后等待本地应用最多 5 秒；这不是整个 HTTP 请求的超时上限。查询状态和历史回执不消耗验签速率额度。

导入与时间修复回执各最多保留 1,024 条，并保留当前证书槽位所需的定位信息。历史淘汰后不伪造成功结果；客户端应保留已经取得的提交回执。

## 4. 时间异常修复

正常运行按单调时钟推进可信 UTC，并定期持久保存时间水位。超过容差的回拨或显著前跳进入粘滞的 `CLOCK_SUSPECT`；仅将墙钟调回不会清除已记录异常。先排查并确保服务器墙钟正确，再由签发方签发专用修复票据。

默认回拨容差为 5 秒、前向偏差上限为 300 秒，边界内允许、超过边界进入异常。偏差相对于同一进程/时间 epoch 的固定锚点和已观察到的可信进度计算，普通 checkpoint 不重置检测预算；多次小幅改时仍可能累计触发。使用渐进校时也不能保证任意长期偏差都被豁免。容差从不延长证书期限。

当前实现避免把单次采样期间的线程暂停直接当成墙钟跳变：正常的每次许可时间读取各采样一次单调时钟和墙钟，仅候选正向修正才补读单调时钟；不新增查询锁或对象分配。进程启动或修复时建立锚点，管理路径最多重采样 32 次，只接受两次单调时钟间隔不超过 1 ms 的墙钟样本；宽样本被丢弃，不成为后续额外的前跳容差。若连续 32 次都无法取得可靠配对，仍保守进入 `CLOCK_SUSPECT`，需要排查暂停原因并按修复流程恢复；不会将这个采样失败作为异常抛给 image/journal 回放。不能据此承诺所有冻结场景都能自愈。若真实改时恰与采样暂停重叠，一次读可能只能保守判断，后续稳定采样仍检查累计偏差。

Master 已提交的时钟异常会随元数据传播。Follower 若比已提交水位落后超过 5 秒，也会在本机进入异常；本机异常不会立即广播，但它之后成为 Master 时可能被提交并传播。

```sql
ADMIN LICENSE CLOCK CHALLENGE;
ADMIN REPAIR LICENSE CLOCK '<repair-compact-JWS>';
SHOW LICENSE CLOCK REPAIR '<repair-id>';
```

HTTP 对应 `POST /api/license/clock/challenge`（空正文或 `{}`）、`POST /api/license/clock/repair`（正文 `{"repair_certificate":"..."}`）、`GET /api/license/clock/repairs/{repair_id}`。仅使用成功返回的 `challenge` 对象，按签发工具的 `repair-sign` 说明在离线签发机生成票据。只收到 `COMMITTED` 而没有 `challenge` 时，等待本地恢复应用后重新申请，不自行补全挑战字段。

挑战绑定当前 Master 进程、任期、nonce、epoch 和修复授权版本，有效期为 24 小时单调时间；重启或切主后重新申请。成功修复只提交新的时间 epoch，保留证书有效期、最高序号和基础额度。相同票据重试只确认原回执，不再次降低水位。

## 5. 恢复与升级

部署身份、证书原文、激活事实、基础额度、序号、时间水位及回执通过 FE journal 和 image 保存。Checkpoint 使用独立 Env 历史截面，不生成新身份或追加授权日志。过期证书在恢复后正常显示 EXPIRED；可隔离的坏 pending/base 分别处理，未知格式和整体存储损坏遵循现有 FE 恢复机制。

先使全部已注册 FE（含 Observer）具备相同的新格式能力，再导入首证书；首次能力检查不能跳过离线成员。管理员可访问各 FE 的只读 `GET /api/license/capability` 核对 `package_sha256`、`trust_sha256`、`trust_ready` 和节点身份；普通用户不能访问。成功能力检查保存程序包、公钥清单和 FE 成员身份的绑定；任一绑定变化要重新检查。已确认绑定未变化时，个别 FE 暂时离线不单独阻止续期。

授权元数据采用 `massdbLicenseV1` 模块和 journal 6200–6205；包含新事实的 image 使用版本 141，旧 FE 不支持读取。不可用旧二进制直接加入已启用新格式的集群。跳过相关 journal、忽略模块或无法证明恢复完整性会保持 NOT_READY，不能把缺槽解释为未激活或免费额度。

恢复不完整标记首先作用于本台 FE，并保存在其 image 中；没有普通导入或时钟修复命令可清除。默认 `force_skip_journal_id` 不读取故障记录，跳过内容未知仍会设置该标记。仅确认记录物理可读、因业务回放问题需要跳过时，可显式配置 `massdb_license_probe_skipped_journal_header=true` 并重启，探测到不涉及授权/成员事实的已知普通操作码才避免新增标记；默认值为 `false`。探测物理损坏记录可能使 JE 环境失效，此选项不是坏块修复手段，也不会清除已有标记。授权及 FE/BE 成员操作被强制跳过、或经 `skip_operation_types_on_replay_exception` 跳过回放异常时，仍设置标记，防止漏计节点和兼容检查对象。已有不完整状态需从健康 FE 或可靠备份恢复同一部署的完整元数据；具体限制见[本轮恢复说明](license-review-remediation-20261004.md#3-元数据恢复操作边界)。

升级后的 FE 在完成初始化和证书导入前会拒绝受保护读取，当前没有自动宽限期。应提前准备全部注册 FE 的升级和离线签发流程，以及旧格式回滚所需的升级前元数据备份；修复信任公钥文件后按配置要求重启生效。

FE/BE 注册额度在 P2 显示和导入策略中校验；新增节点的权威准入由 P3 接入。未来 pending 到点可以改变有效证书状态，基础额度切换仍须单独持久提交；等待期 ADD 按第 2.1 节较小上限执行。

到期后降额续期沿用既有格式，不新增 BE 协议要求；导入前须将全部已注册 FE 升级到同一新包并通过原有严格包摘要/信任集门禁。新版本恢复仅允许不重叠 active/base→pending 的降额，不放宽 base→active 的校验。不得使用旧 FE 二进制恢复已经写入较低 pending 的元数据；本轮实际验证范围见[验收记录](license-expired-renewal-20260930.md)。
