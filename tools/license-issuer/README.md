<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# MassDB SQL 离线证书签发工具

这是签发方使用的独立工具，不接入 FE/BE 打包，不附带任何生产或测试密钥，也不会自动创建生产信任根。
它使用 Python 3 标准库和本机 OpenSSL 3，无 Python 第三方包、联网请求或远程公钥发现。
数据库的可信公钥安装、SQL/API 导入、集群序号、节点额度和运行时限制由数据库实现负责。P2 管理接入已通过构建和针对性测试，真实集群验收仍待完成；本工具本身不能启用查询和节点额度拦截。

配套 `license_sql_import.py` 将本地证书文件转换为文本 SQL，默认生成 `ADMIN IMPORT LICENSE`；`--operation validate` 或 `--operation clock-repair` 分别生成验证或时间修复语句。输出交给 MySQL 客户端标准输入执行，证书不是 FE 服务器路径，管理语句不支持服务端 PREPARE。例如：

```bash
python3 tools/license-issuer/license_sql_import.py /secure/vendor/customer-license.jws \
    | mysql --defaults-extra-file=/secure/client.cnf
```

该辅助工具只校验紧凑 JWS 的字符和长度，密码使用客户端配置，FE 仍负责验签与 ADMIN 权限检查。四项辅助工具测试通过不代表上述真实客户端链路已验收。

## 运行环境

先验证指定的可执行文件，命令均从仓库根目录执行：

```bash
python3 --version
/usr/bin/openssl version
python3 tools/license-issuer/license_issuer.py --help
```

以下示例显式使用 `--openssl /usr/bin/openssl`，避免 PATH 中旧版本或损坏的第三方 OpenSSL 覆盖系统版本。
工具启动时要求版本为 OpenSSL 3；每次 OpenSSL 调用最多 30 秒，不启用 shell，也不输出 OpenSSL 原始错误内容。
首次验证环境为 Python 3.13.5 / OpenSSL 3.2.4；其他签发机版本须运行下面的自测，不能仅根据版本号声称通过验证。

## 1. 显式生成密钥

先在签发机准备权限受控的目录，再指定两个尚不存在的输出文件：

```bash
python3 tools/license-issuer/license_issuer.py --openssl /usr/bin/openssl keygen \
    --private-key /secure/vendor/issuer-2026-private.pem \
    --public-key /secure/vendor/issuer-2026-public.pem
```

生成 Ed25519 密钥；私钥为未加密 PKCS8 PEM（权限 `0600`），公钥为 SPKI PEM（权限 `0644`）。
未加密私钥仅适合受控离线签发目录，私钥保管、备份和签发审批由签发方负责。
工具仅在明确执行 `keygen` 时生成密钥；`sign` 使用调用者明确提供的现有私钥，不代建或替换密钥。
不支持在命令行传入私钥正文、口令或证书正文；私钥不得复制到客户数据库、源码仓库或发行包。

输出已存在（包括符号链接）时安全失败，不覆盖文件。发布时以文件系统原子链接实现排他创建；异常时清理本次已创建输出和临时文件。
若进程或机器在两个密钥文件发布之间崩溃，可能只留下其中一个文件，下一次执行仍拒绝覆盖，须由签发方核实后选择新输出路径。
私钥输入文件的权限由签发方管理；工具不修改已有输入文件的权限。

## 2. 准备声明文件

将以下结构保存为签发目录下的 UTF-8 JSON 文件。示例 UUID、客户和期限仅用于说明，签发时必须替换为该客户集群的真实申请信息。

```json
{
  "schema_version": 1,
  "policy_version": 1,
  "license_id": "customer-a-2026-001",
  "issuer": "MassDB Issuer",
  "customer_id": "Customer A",
  "edition": "Enterprise",
  "product": "MassDB SQL",
  "deployment_id": "c9b82051-a34e-455b-bff3-2f09306c6aa8",
  "issued_at": 1767225600,
  "not_before": 1767225600,
  "expires_at": 1798761600,
  "sequence": 1,
  "features": ["DATA_QUERY"],
  "limits": {
    "max_fe_nodes": 3,
    "max_be_nodes": 10
  }
}
```

证书载荷中的所有时间均为 **UTC 整数秒**，不接受本地日期字符串、毫秒、浮点数或隐式字符串转换。
示例起止分别为 `2026-01-01T00:00:00Z` 和 `2027-01-01T00:00:00Z`；`now >= expires_at` 即到期。

正式签发优先用 `prepare-claims`，从实际集群导出的申请文件读取部署 UUID。申请 DTO 精确包含以下字段；这里的示例不是可代替真实集群申请的文件：

```json
{"schema_version":1,"product":"MassDB SQL","deployment_id":"c9b82051-a34e-455b-bff3-2f09306c6aa8","registered_fe_nodes":3,"registered_be_nodes":7}
```

注册数为 `[0, 2147483647]` 的整数，包括当前已注册但离线的节点；工具要求拟签发额度至少为 `1` 且不少于申请中的注册数。
申请是不含秘密的人工离线传递 DTO，本身没有签名；签发方仍须核实客户与申请来源，数据库导入阶段会重查实时注册数和部署标识。
工具不生成或替换部署 UUID，也不把 FE 业务 API 中尚未落地的申请导出误报为已实现。

```bash
python3 tools/license-issuer/license_issuer.py prepare-claims \
    --request /secure/vendor/customer-a-deployment.json \
    --license-id customer-a-2026-001 --issuer 'MassDB Issuer' \
    --customer-id 'Customer A' --edition Enterprise --sequence 1 \
    --issued-at 2026-01-01T08:00:00+08:00 \
    --not-before 2026-01-01T08:00:00+08:00 \
    --expires-at 2027-01-01T08:00:00+08:00 \
    --feature DATA_QUERY --max-fe-nodes 3 --max-be-nodes 10 \
    --output /secure/vendor/customer-a-claims.json
```

`--feature` 可重复；省略时明确生成空能力集合，不自动授予业务查询。
这些日期参数要求 `YYYY-MM-DDTHH:MM:SSZ` 或 `YYYY-MM-DDTHH:MM:SS±HH:MM`，拒绝无时区时间、未知偏移 `-00:00`、小数秒、闰秒和无效日期。
转换不读取主机默认时区，离线服务器也得到相同 UTC 秒。独立转换命令如下；日期转换和准备声明不需要 OpenSSL：

```bash
python3 tools/license-issuer/license_issuer.py date-to-epoch --date 2026-01-01T08:00:00+08:00
```

| 字段 | 协议 v1 约束 |
| --- | --- |
| `schema_version`、`policy_version` | 均为整数 `1` |
| `product` | 精确等于 `MassDB SQL` |
| `deployment_id` | 规范小写 UUID，必须来自目标集群；工具不自动创建部署 UUID |
| `license_id` | 非空、最多 256 个 UTF-16 代码单元，不含下述固定空白或禁用码点 |
| `issuer`、`customer_id`、`edition` | 非空、最多 256 个 UTF-16 代码单元；允许中间的非控制空白，首尾不允许，不含禁用码点 |
| `issued_at`、`not_before`、`expires_at` | 整数 `[0, 253402300799]`，且 `issued_at <= expires_at`、`not_before < expires_at` |
| `sequence` | 整数 `[1, 9223372036854775807]`；签发方另行登记同一部署的已签发序号，续期或扩容必须递增 |
| `features` | 最多 128 个不重复字符串，各最多 128 个 UTF-16 代码单元，无固定空白/禁用码点；未知能力或空数组可签名，但不自动获得查询权益 |
| `limits.max_fe_nodes`、`limits.max_be_nodes` | 都必填，整数 `[1, 2147483647]`；`0`、缺失或负数不表示无限制 |

所有声明字段、`limits` 字段及保护头字段均为白名单；拒绝未知字段、重复字段、布尔值冒充整数、浮点数、非有限数和无效 UTF-8/Unicode。
解析限制：JSON 最大深度 8、字段名最多 128 个 UTF-16 代码单元、字符串最多 4096 个 UTF-16 代码单元、数字词法最多 20 字符。
长度约束按 UTF-16 代码单元统一 Java 验证器，例如非 BMP 字符占两个单位。
文本规则已冻结为固定码点表，Python 与 Java 均不再依赖运行时 Unicode 分类数据库。普通中文、emoji、新分配字符及未分配的合法标量均可使用；不做 NFC/NFKC 归一化，字符串按实际码点精确比较。

- 固定空白：`0009–000D,0020,0085,00A0,1680,2000–200A,2028–2029,202F,205F,3000`。
- 禁用控制/格式/代理/私用范围：`0000–001F,007F–009F,00AD,0600–0605,061C,06DD,070F,0890–0891,08E2,180E,200B–200F,202A–202E,2060–2064,2066–206F,D800–DFFF,E000–F8FF,FEFF,FFF9–FFFB,110BD,110CD,13430–1343F,1BCA0–1BCA3,1D173–1D17A,E0001,E0020–E007F,F0000–FFFFD,100000–10FFFD`。
- 禁用 noncharacter：`FDD0–FDEF`，以及每个 Unicode 平面的末两个码点（低 16 位为 `FFFE` 或 `FFFF`）。

以上范围均用十六进制表示。重叠于禁用范围的空白（如 TAB、换行、`0085`）即使在客户名称中间也不允许。

## 3. 签发或续期

```bash
python3 tools/license-issuer/license_issuer.py --openssl /usr/bin/openssl sign \
    --claims /secure/vendor/customer-a-claims.json \
    --private-key /secure/vendor/issuer-2026-private.pem \
    --kid issuer-2026 \
    --output /secure/vendor/customer-a-2026.massdb-license
```

输出为无换行、无 padding 的 compact JWS，保护头只包含 `alg=Ed25519`、`typ=massdb-license+jws` 和指定的 `kid`。
`kid` 非空、最多 128 个 UTF-16 代码单元，不含固定空白或禁用码点；它必须与数据库安装的可信公钥标识一致。
签名覆盖原始 `base64url(header) + "." + base64url(payload)`；签名为 64 字节，完整证书不超过 64 KiB。
证书输出权限为 `0600`；标准输出仅包含操作状态、`kid` 和证书 SHA-256 指纹，不打印证书正文或客户声明。
证书不加密，接收方可读取载荷，因此声明中不要存放密码或非必要个人信息。

续期、扩容使用新的声明文件和新的输出文件，沿用部署 UUID，并提高 `sequence`。
续期可增加以下参数，在签发前用显式固定的旧公钥验证上一个证书；旧证的 `kid` 与新证可不同，支持公钥轮换：

```text
--previous /secure/vendor/customer-a-previous.massdb-license
--previous-public-key /secure/vendor/issuer-previous-public.pem
--previous-kid issuer-previous
--at 1767225600
```

前三项必须一起提供；`--at` 可省略而使用签发机当前 UTC 秒。工具要求部署、产品及客户匹配、序号严格增加，并使用新的 `license_id`；数据库拒绝已知 ID 对应不同内容。节点基础额度即使旧证已经过期也不得下降。
旧证未过期时，工具拒绝缩短截止时间或削减能力；若上一个证书尚未生效，还拒绝推迟其起始时间。
对于已开始生效的旧证，新证可以未来生效，数据库需要保留旧 active 直到生效切换；起止间隙不会自动延长旧证，签发结果的 `coverage_gap_seconds` 明示两张证书之间的空档。
本工具只预检传入的一张旧证，不能证明客户没有其他更高序号、active/pending 覆盖、注册节点变化或历史额度；数据库导入必须再检查全状态，签发方仍须维护签发登记。省略旧证参数仅执行单证检查，不意味着续期策略已通过。

## 4. 离线验证

```bash
python3 tools/license-issuer/license_issuer.py --openssl /usr/bin/openssl verify \
    --certificate /secure/vendor/customer-a-2026.massdb-license \
    --public-key /secure/vendor/issuer-2026-public.pem \
    --kid issuer-2026 \
    --deployment-id c9b82051-a34e-455b-bff3-2f09306c6aa8
```

公钥和 `kid` 都必须由调用者显式固定；拒绝证书内嵌公钥、`jku`、`crit`、`b64=false`、`alg=none`、`EdDSA` 等非本协议格式。
只接受规范、无 padding 的 base64url；验证时使用证书中的原始签名输入，不重新序列化声明。
可用 `--at 1767225600` 指定验证的 UTC 秒，默认取本机当前时间，与显示时区无关。

验签和声明检查成功返回退出码 `0`，并显示 `signature_valid: true` 及 `time_status`：`VALID`、`NOT_YET_VALID` 或 `EXPIRED`。
**返回 `0` 不是集群授权可用的结论**：过期证书仍可具有真实签名；工具另报 `data_query_feature`，但没有集群时钟保护、历史序号、导入状态、实时节点用量或权限上下文。
`--deployment-id` 可校验目标集群匹配；省略时工具只验证声明中的 UUID 格式。
格式、签名、密钥或输入输出错误返回 `2`，错误文本不回显密钥、声明或证书原文。

## 5. 生产公钥交付和轮换

向 FE 交付的信任清单只含公钥，格式如下：

```text
{"schema_version":1,"keys":[{"kid":"issuer-2026","purpose":"license","public_key_spki":"<44字节Ed25519 SPKI DER的规范base64url>"}]}
```

严格限制为 `schema_version`、`keys` 两个顶层字段，各 key 精确包含 `kid`、`purpose`、`public_key_spki`。
`keys` 为 1–32 项、`kid` 全局唯一；用途只能是 `license` 或 `time_repair`，同一公钥不能跨用途复用；清单最多 64 KiB，无未知或重复字段。
公钥编码无 padding，SPKI 必须为 Ed25519 的 44 字节结构，禁止私钥、证书自带公钥以及在线公钥发现。

```bash
python3 tools/license-issuer/license_issuer.py --openssl /usr/bin/openssl export-trust \
    --public-key /secure/vendor/issuer-2026-public.pem --kid issuer-2026 \
    --purpose license --output /secure/vendor/massdb-license-trust.json

python3 tools/license-issuer/license_issuer.py --openssl /usr/bin/openssl export-trust \
    --existing /secure/vendor/massdb-license-trust.json \
    --public-key /secure/vendor/repair-2026-public.pem --kid repair-2026 \
    --purpose time_repair --output /secure/vendor/massdb-license-trust-with-repair.json
```

修复密钥需用独立的 `keygen` 命令生成。`--existing` 先验证原清单再追加公钥，保留旧 key；输出文件不得已存在，权限 `0644`。
轮换时先将包含新旧公钥的清单安全交付到全部 FE，再开始使用新 key 签发。旧证、pending、历史基础额度或修复消费档案仍依赖的 key 不得提前移除；导入安装和 FE 同步由后续持久化/API 阶段接入。
清单本身不是自签认证根，须通过受控发行或管理员安装流程交付；任何有权替换该信任根的人都能改变被信任的签发方。

交付前可按[只读公钥验收说明](/data/project/massdb-sql/tools/license-checks/public-trust-review.md)使用实际 FE JAR/JDK 核对清单、指纹和声明的轮换依赖。该工具已完成19项Python及12项真实JDK/JAR正负例，仅使用公开测试向量，未验证实际生产公钥；受控来源、完整历史依赖和实际签发样本仍需分别验收。

## 6. 专用时钟修复票据

时钟修复使用独立 `time_repair` 密钥及 `typ=massdb-license-clock-repair+jws`；普通许可和修复票据互不接受。JWS 最多 16 KiB，签名和解析规则与许可一致。
签发方读取 FE 申请的 challenge 文件，精确字段如下：

```text
schema_version, product, deployment_id, nonce, clock_epoch,
repair_authorization_version, leader_term, observed_wall_at,
observed_high_water_at, valid_for_seconds
```

版本 `1`、产品 `MassDB SQL`；deployment/leader_term 均为规范小写 UUID；nonce 是 32 个随机字节的规范无 padding base64url（43 字符）。
`clock_epoch` 为 `[0, 9223372036854775806]`，`repair_authorization_version` 为 `[1, 9223372036854775806]`；观测时间范围与许可 UTC 秒一致；`valid_for_seconds` 固定 `86400`。
challenge 的单调时钟有效期、当前领导任期以及是否已消费只能由 FE 判定，离线文件不是新的时钟信任源。

```bash
python3 tools/license-issuer/license_issuer.py --openssl /usr/bin/openssl repair-sign \
    --challenge /secure/vendor/customer-a-clock-challenge.json \
    --repair-id 7c2aa6bc-078f-499e-bd31-b5874fcc5b05 \
    --issued-at 2026-09-22T08:00:00+08:00 \
    --not-before 2026-09-22T08:00:00+08:00 \
    --expires-at 2026-09-23T08:00:00+08:00 \
    --private-key /secure/vendor/repair-2026-private.pem --kid repair-2026 \
    --output /secure/vendor/customer-a-clock-repair.jws

python3 tools/license-issuer/license_issuer.py --openssl /usr/bin/openssl repair-verify \
    --certificate /secure/vendor/customer-a-clock-repair.jws \
    --challenge /secure/vendor/customer-a-clock-challenge.json \
    --public-key /secure/vendor/repair-2026-public.pem --kid repair-2026
```

`repair_id` 必须为此次授权新分配的唯一 UUID；工具不代生挑战或部署标识。
载荷精确包含 `schema_version,product,deployment_id,repair_id,nonce,clock_epoch,repair_authorization_version,leader_term,issued_at,not_before,expires_at`；绑定字段直接复制 challenge，不允许命令行覆盖。
`issued_at <= expires_at`，且 `0 < expires_at - not_before <= 86400`。`[not_before, expires_at)` 限定已经纠正的本地挂钟允许范围，不能用受污染的高水位去验证这个窗口。
离线验签返回 `VALID` 或 `OUTSIDE_REPAIR_WINDOW`；与许可验签相同，退出码 `0` 仅表示结构、签名及传入 challenge 匹配，不证明 FE 仍持有活跃挑战、提交成功或尚未消费。
成功修复不延长许可 `expires_at`，不重置许可最高序号，也不释放节点额度。FE 的挑战管理、持久提交、审计与并发控制是独立运行时职责。

## 自测与范围

```bash
MASSDB_TEST_OPENSSL=/usr/bin/openssl python3 tools/license-issuer/test_license_issuer.py -v
```

测试在临时目录动态生成密钥，结束后删除，不提交密钥 fixture。
覆盖额度/有效期/签名篡改、错误密钥和 `kid`、原始 JSON 签名输入、有效期边界、类型混淆、重复字段、未知头、编码与大小限制、固定 Unicode 规则、显式时区换算、真实申请字段准备、已验签续期、pending 起始保护、跨到期基础额度、信任清单及用途隔离、修复票据绑定/篡改/高水位独立验证，以及拒绝覆盖文件和失败后的输出清理。
运行本工具测试不代表数据库授权准入、发行包安装、节点通信或业务性能已完成验证。本机Java验证器/OpenSSL双向验证记录见[首批实施记录](/data/project/massdb-sql/docs/license-implementation-progress-20260922.md)，本次实际自用运行环境的集成验证仍待完成；麒麟/openEuler及多架构发行矩阵暂不属于本轮目标。
