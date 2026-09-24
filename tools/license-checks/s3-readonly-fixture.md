<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP008 原版 S3 TVF 外部读取夹具

`s3_readonly_fixture.py` 使用 Python 标准库，在已经验证归属的私有网络 namespace 内启动一个只绑定 `127.0.0.1`
随机端口的只读 S3 兼容服务。服务返回[已独立验证的 Parquet 夹具](/data/project/massdb-sql/tools/license-checks/parquet-fixture.md)
中的真实字节；SQL 解析、Parquet schema 推断、解码、计算与入库均由原版 FE/BE 执行。
它不伪造 SQL 行或许可状态，不修改 FE/BE 源码、协议及配置，也不请求公网。

## 为什么这一最小服务足够

当前 `S3TableValuedFunction` 在 FE 中初始化 `S3Properties`；`ExternalFileTableValuedFunction.parseFile`
先检查 endpoint 连通性，再通过 `S3ObjStorage` 调用 `ListObjectsV2`。`getTableColumns` 使用已有
`fetchTableStructure` RPC，让 BE 从真实文件推断 schema。BE 的 `S3ObjStorageClient` 使用 `HeadObject` 和带
`Range` 的 `GetObject`，随后既有 Parquet reader 解码；因此这条前提不需要下载或安装 MinIO。

服务仅提供固定 bucket `lp008-fixture` 与固定 100 个 `lp008/part-NNNNN.parquet` 对象：

- GET/HEAD 返回真实文件及其大小、MD5 ETag；单范围 GET 支持起止、开放结尾和 suffix，返回正确 206/Content-Range。
- ListObjectsV2 返回真实对象 XML，支持 prefix、delimiter、start-after、连续页 token；服务每页最多 37 项，验证真实 SDK 翻页。
- 缺失对象返回 404，无效范围返回 416，错误 If-Match 返回 412；PUT/POST/DELETE 等写操作拒绝，路径不能逃出固定对象集合。
- 请求日志只包含阶段、方法、固定对象键、范围、响应状态/字节及 SDK 家族，不记录 Authorization、签名、Cookie 或原始 URL/query。
  TCP 接入也单独计数，避免仅用 HTTP 请求数漏掉 endpoint 连通性阶段。

TVF 使用明确的 path style、region 与本地 endpoint，凭据是源码中的**公开测试字符串**；服务不实施 SigV4/IAM 权限验证。
此选择只用于观察现有 SDK 的真实数据流，不代表 AWS/MinIO 全接口兼容或生产鉴权通过。后续性能运行还须记录模拟器资源和
连接关闭策略，并证明模拟器没有成为未解释的瓶颈；这个顺序功能 probe 不提供吞吐结论。

## 操作和断言

程序先检查输入清单的 100×10000 行证明，并重新核对每个文件大小及 SHA-256。内置协议自检实际请求同一私有 endpoint，
验证完整文件、HEAD、三种 Range、分页，以及范围/ETag/写入/路径负例；这部分请求单列，不混入 FE/BE 路径证据。

然后使用当前发行包的 MariaDB/Jackson JAR 与既有 `LicenseFixtureSql` helper 依次执行：

1. `DESC FUNCTION S3(...)`：必须得到 id/grp/v/payload 四列及 BIGINT/INT/BIGINT/字符串类型，并观察列表和真实对象读取。
2. 外部聚合 SELECT：验证百万行数量、COUNT DISTINCT、ID 边界、三个 SUM；逐行检查 grp/v/完整 MD5 payload，坏行必须为 0。
3. 创建唯一的 `license_perf.lp008_external_<run-id>` DUPLICATE KEY 表，执行真实 `INSERT SELECT`。
4. 从内部目标表执行相同的完整数据模型 oracle；该步骤不应再访问 S3。
5. DROP 本次独立目标表并确认表不存在；停止并关闭本次本地服务。

每个 SQL 连接显式关闭 SQL/query/file cache，并设置有限 query/insert timeout。
外部 SELECT 与 INSERT SELECT 各自必须实际 GET 全部 100 个对象，所有响应成功，且 Range 请求至少 100 次。
各阶段切换和计数读取须等待活动 HTTP 请求归零；不能用下一阶段的请求补上前一步证据。
独立阶段报告、原始 JDBC 结果与脱敏 JSONL 请求日志全部归档。SQL/helper、输入或清理失败都使 probe 失败。

## 执行边界

只能在 root 确认没有基线计时负载、私有 FE/BE 健康且资源配置已冻结的窗口执行。
`validate_cluster` 核对当前 network namespace、实际 FE/BE PID 与 checkout 安装路径；宿主 namespace 或仓库外服务会被拒绝。
以下 `<supervisor-pid>` 和清单必须来自当前健康安装，不沿用已退出的历史实例：

```bash
nsenter -t <supervisor-pid> -n -- python3 tools/license-checks/s3_readonly_fixture.py \
  --cluster-record .build-records/license-p0-p1-20260924/<current-profile>/cluster.json \
  --parquet-report .build-records/license-p0-p1-20260924/lp008-parquet-v3/fixture-report.json \
  --output .build-records/license-p0-p1-20260924/lp008-s3-new \
  --cpu 0
```

SQL/helper 每次进程有 90 秒上限，JDBC/socket 和服务连接也有超时；服务与 Python helper 绑定 CPU0，FE/BE 保持原资源绑定。
输出目录必须全新。脚本不修改 `point_rows`，不修改生产或测试 FE 全局配置，结束只清理自己创建的表和服务。

成功报告标为 `ORIGINAL_S3_SCHEMA_SELECT_INSERT_REACHABLE`。LP008 主状态继续 `not_run`：此证据只证明原版 A 的
外部结构/读取/入库路径与请求观测可达，不证明候选 B 的到期拒绝、无外发副作用、合法写入背景或完整 A/A/A/B 性能。

## 2026-09-24 实际功能记录

在 `baseline-jdk1704-be4g` 私有环境完成一次真实 probe，BE 的实际 `mem_limit` 为 4 GiB。
运行时段为 UTC `2026-09-23T17:50:35.306073` 至 `17:50:38.479125`，对应北京时间 2026-09-24。
当时允许与 LP014 并行进行功能检查；这些耗时不具备性能隔离含义。旧 2 GiB 环境内存异常后没有在旧实例重试本项。

| 阶段 | 真实观察 |
| --- | --- |
| 协议自检 | 16 次 HTTP，验证真实文件/HEAD/Range/分页及 416/412/403/404 负例 |
| DESC FUNCTION | BIGINT/INT/BIGINT/TEXT；3 次 FE ListObjectsV2 + 1 次 BE Range GET |
| 外部 SELECT | 百万行完整模型一致、坏行 0；3 次 List + 101 次 Range GET，覆盖全部 100 个对象 |
| INSERT SELECT | update_count=1,000,000；3 次 List + 101 次 Range GET，覆盖全部 100 个对象 |
| 内部表验证 | 百万行 COUNT DISTINCT、范围、三个 SUM、逐行表达式及完整 payload 全部一致；外部请求 0 |
| 清理 | DROP 本次表、SHOW 确认不存在；server_stopped=true，随后独立 `ss` 检查确认 37299 端口没有监听 |

来自真实 FE/BE SDK 的请求共 212 次（Java 9，C++ 203），全部成功；协议自检独立计数。
schema 阶段实际 `Range: bytes=0-561845`，读取了首个小文件的完整 561,846 字节，**不能声称结构探测只取 footer**。
将来 FE 的禁止外发检查仍必须在相关规划副作用之前执行。SELECT 与 INSERT 阶段各发送 56,768,602 响应字节，包含列表 XML
和取样读取；TCP 比 HTTP 多出的每阶段 1 次连接来自实际 endpoint 连通性检查，另行保留。

[真实报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp008-s3-be4g-v1/report.json)
SHA-256：`c620a532c3b12c08f3127286c969c71f9733bd330614bd52dc52312949e6a8b2`。
同目录保存全部 SQL 原始结果、JDBC/helper 依赖摘要及 `requests.jsonl`；日志扫描未发现 Authorization、签名、Cookie 或测试
secret 文本。Python 语法编译、源文件头和 diff 检查通过。源码及原版 FE/BE 摘要已记录，许可拒绝和性能通过字段仍为 false。
