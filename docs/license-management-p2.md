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

## 3. 超时、重试和错误

保存证书原始字节及其 SHA-256 指纹。相同指纹重试确认原提交，不会重新覆盖更新的证书。序号和已有授权覆盖受保护；拒绝的候选不改变已接受证书、最高序号、基础额度或成功回执。

| 结果 | 客户端处理 |
| --- | --- |
| HTTP 200，`APPLIED` | 已持久提交且当前 FE 已应用；记录 `committed_version` |
| HTTP 202，`COMMITTED` | 已提交但当前 FE 尚未应用；按导入指纹或修复 `repair_id` 查询回执，保留原版本 |
| `UNKNOWN` | 当前无法确认结果；查询回执，不推断未提交或盲目签发替代证书 |
| HTTP 400 / SQL 6201、45000 | 候选或格式错误，按 `reason` 修正输入 |
| HTTP 409 / SQL 6202、40001 | 状态、序号或并发冲突；先重新查看已提交状态 |
| HTTP 429 / SQL 6203、HY000 | 用户速率或管理队列已满；HTTP 遵守 `Retry-After`，SQL 按 `reason` 退避重试 |
| HTTP 503 / SQL 6203、HY000 | 尚未就绪或提交不可确认；结合 `submission_status` 和回执处理，历史不可确认见下一行 |
| HTTP 503、`*_HISTORY_UNAVAILABLE` / SQL 6204、HY000 | 历史回执不可确认；不表示从未提交 |
| HTTP 401/403 | 原认证/权限或 CSRF 拒绝，修正调用身份和来源 |

SQL 使用结果行表达提交/应用状态，错误保留独立 errno 与 SQLSTATE；原认证/权限错误仍使用原错误码，不强制转换为 6201–6204。HTTP 错误正文包含稳定的 `reason`、脱敏 `message`、`retryable`、`submission_status` 和版本字段；能定位提交时包含指纹或 `repair_id`，尚不能确定的版本可为 `null`。

轮询导入时使用 `GET /api/license/imports/{fingerprint}` 或 `SHOW LICENSE IMPORT`；修复时使用对应 `repair_id` 回执入口。需要确认某台 FE 已应用时，持续请求该 FE，直到回执为 `APPLIED` 且 `applied_version >= committed_version`。建议从 2 秒间隔逐步退避到 10 秒，并由客户端设置等待截止时间；超时后保留 `COMMITTED` 或 `UNKNOWN` 和原回执，不能改判为未提交。旧指纹返回的是那次提交的版本，并不表示它仍是当前有效证书。

原始证书上限 64 KiB、时间修复票据上限 16 KiB、HTTP body 上限 96 KiB，均按字节计算。HTTP 字段超限返回 400 / `LICENSE_INPUT_TOO_LARGE`，body 超限返回 400 / `LICENSE_BODY_TOO_LARGE`，均在进入验签队列前拒绝。验签使用两线程及 32 个排队位置，每用户每分钟最多 10 次、突发最多 3 次。Follower 取得已提交结果后等待本地应用最多 5 秒；这不是整个 HTTP 请求的超时上限。查询状态和历史回执不消耗验签速率额度。

导入与时间修复回执各最多保留 1,024 条，并保留当前证书槽位所需的定位信息。历史淘汰后不伪造成功结果；客户端应保留已经取得的提交回执。

## 4. 时间异常修复

正常运行按单调时钟推进可信 UTC，并定期持久保存时间水位。超过容差的回拨或显著前跳进入粘滞的 `CLOCK_SUSPECT`；仅将墙钟调回不会清除已记录异常。先纠正服务器墙钟，再由签发方签发专用修复票据。

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

FE/BE 注册额度在 P2 显示和导入策略中校验；新增节点的权威准入由 P3 接入。未来 pending 到点可以改变有效证书状态，基础额度提升仍须单独持久提交。
