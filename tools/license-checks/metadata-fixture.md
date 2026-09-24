<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP005 原版 SQL / HTTP 元数据 fixture

`metadata_fixture.py` 验证原版发行包的探活、元数据返回和对象权限，不修改 FE/BE 源码或业务表数据。
入口沿用 `stream_load_fixture.validate_cluster`：当前网络 namespace 必须与 checkout 内的 cluster 记录一致、
不同于宿主 namespace；实际 FE/BE PID、namespace 和安装路径必须匹配。先完成保护检查，再编译 JDBC helper、
发送请求或建立报告目录。工具不启动服务、不自动重试，也不下载依赖。

SQL 使用发行包自带 MariaDB/Jackson、记录的 JDK 和 `LicenseFixtureSql.java`；HTTP 使用 Python 标准库，
只连该 namespace 的 `127.0.0.1` FE HTTP 端口，不跟随重定向，不读取代理配置。
默认 JDBC helper 遇首个 SQL 错误即中止，输出结构化结果并返回非零；只有显式 `continue_on_error=true`
才继续并保留每条语句的成功标记、SQL errno、SQLState 和错误消息。连接错误始终失败，不当作权限用例通过。
Stream Load 原有调用保持默认中止行为。

## 冻结输入与权限

ADM SQL 与 ADM HTTP SQL 分别执行同一序列，各自精确为 50% / 25% / 25%：

```sql
SELECT 1;
SELECT 1;
SHOW TABLES FROM license_perf;
DESCRIBE license_perf.point_rows;
```

默认冻结数据库仅有 `point_rows`，列顺序为 `id,grp,v,payload`；使用 `--expected-tables` 和
`--expected-columns` 可以预先明确其他 fixture 的表集合及列顺序，不能在失败后从返回值自动接受新期望。
工具逐一比较 SQL 与 HTTP 的全部列名、行顺序和单元格值；SQL 字符串形式与 JSON 数字形式只做显示值规范化。
报告保存原始 JDBC 类型和 HTTP metadata，以便检查返回结构。

HTTP SQL 固定如下：

```text
POST /api/query/default_cluster/license_perf
X-Doris-Stream: false
Content-Type: application/json
{"is_sync":true,"limit":1000,"stmt":"SELECT 1"}
```

全部 HTTP 请求使用 Basic，每次重新认证；不保存或复用响应 cookie。
这是有意冻结的认证方式：该原版的 Basic 和 cookie 检查路径并不完全相同，不能在 A/B 中混用。
HTTP 200 必须同时满足 JSON `code=0` 和具体结果 oracle 才是业务成功。

工具创建两个仅接受 `127.0.0.1` 的随机命名测试账号：reader 只授予 `license_perf.point_rows` 的 SELECT，
另一个不授予对象权限。二者仅存在于明确校验过的私有测试 namespace，使用空测试密码，finally 删除。
ADM 密码仅从 `MASSDB_BASELINE_PASSWORD`（或 `--password-env` 指定变量）读取，不写参数、SQL、报告或日志；
HTTP 认证头和 Set-Cookie 不归档，响应若反射凭据则拒绝归档。

| 身份与请求 | 冻结预期 |
| --- | --- |
| ADM SQL / HTTP SQL 四请求混合 | 结果精确等价，表数和 DESCRIBE 列数符合输入 |
| reader SQL 四请求混合 | 两次探活成功、只显示 point_rows、完整表结构与 ADM 一致 |
| 无对象权限 SQL 四请求混合 | 两次探活成功、SHOW TABLES 空集合、DESCRIBE 保持原权限错误 |
| ADM / reader GET tables | 分别返回冻结表集合 / point_rows |
| 无对象权限 GET tables | HTTP 200、code 0、空集合 |
| ADM / reader GET schema | HTTP 200、code 0，完整基础 schema 与 SQL DESCRIBE 一致 |
| 无对象权限 GET schema | HTTP 200、code 401、原 Access denied 原因 |
| reader / 无对象权限 HTTP SQL SELECT 1 | HTTP 200、code 401，保留接口原有 ADMIN 限制 |

元数据 GET 路径固定为：

```text
/api/meta/namespaces/default_cluster/databases/license_perf/tables
/api/meta/namespaces/default_cluster/databases/license_perf/tables/point_rows/schema?with_mv=0
```

该原版 JDBC 会把 DESCRIBE 的内部权限异常包装为 errno `1105`、SQLState `HY000`，消息包含
`errCode = 2, detailMessage = DESCRIBE command denied`。工具严格核对该包装形式、临时账号命名格式和目标表，
不会把任意 1105、连接失败、语法错误或未来许可错误当作权限成功；发行行为若变化，需要重新审查并冻结 oracle。
GET schema 中 SQL 显示值 `NULL` 对应 JSON null，除此之外完整比较字段与属性。

不使用数据库列表 GET 证明 DB 权限过滤：该原版 `getAllDatabases` 构造过滤集合后仍返回未过滤的原集合，
本 fixture 不把这一既有问题隐藏成授权模块结果。

## 运行和配置恢复

以下命令只能用于 `isolated_baseline_cluster.py` 创建的当前私有监督进程，必须与其他计时窗口错开。
每次使用新的报告目录：

```bash
nsenter -t <supervisor-pid> -n -- taskset -c 0-4 \
    python3 tools/license-checks/metadata_fixture.py \
    --cluster-record .build-records/license-p0-p1-20260924/baseline-jdk1704/cluster.json \
    --output .build-records/license-p0-p1-20260924/lp005-probe-new \
    --enable-http-auth-for-probe
```

默认要求实际运行值 `enable_all_http_auth=true`。显式 `--enable-http-auth-for-probe` 允许在此受控 FE 中临时
启用该配置：先查询并记录原值，执行 ADMIN SET，再查询确认；finally 恢复原值并再次查询确认。
SHOW CONFIG 的显示名可能为 `experimental_enable_all_http_auth`，工具只接受这两个已知名称且要求唯一返回。
该认证 fixture 配置必须在报告中明确，不能称为默认发行配置。若清理或恢复不能确认，结果为 FAIL，不能开启后续计时。

报告保存冻结混合序列/计数、请求与响应、SQL errno/SQLState、临时授权与删除、配置启用与恢复、
原版 JAR hash、cluster 记录 hash、工具源码 hash 和时间。请求耗时仅用于排障；SQL 语句计时不包含连接/JVM 初始化，
HTTP 每请求新连接，因此这里的延迟不能当成协议性能对比。

离线断言测试无需数据库：

```bash
python3 -m unittest discover -s tools/license-checks -p test_metadata_fixture.py -v
```

## 2026-09-24 实测记录

本机 Fedora 42 aarch64、Temurin 17.0.4+8、原版 rc02 JAR
`ea66013d3ffc8c7baff96c0538aa12251217c7f06f5577e22eefc8cdeb3238db` 的私有 1 FE / 1 BE 中，
`lp005-probe-jdk1704-v3/report.json` 为 `FIXTURE_PASS`，共 12 个真实 HTTP 请求。
ADM 的 SQL/HTTP 四请求等价、reader/无权限 SQL 和 GET 权限边界全部符合上述预期。
两临时账号删除成功，原 `enable_all_http_auth=false` 已恢复且 SQL 查询确认；唯一 point_rows 表及数据未更改。

完整证据保留于 checkout 忽略目录 `.build-records/license-p0-p1-20260924/`：

- `lp005-probe-jdk1704-v3/`：通过报告、12 个 HTTP 收据、SQL 输入/结果与 helper 编译依赖 hash。
- `lp005-probe-jdk1704/`：首个只读配置查询因实验性显示前缀未匹配而失败；未发生配置或账号变更。
- `lp005-probe-jdk1704-v2/`：初始 oracle 预期内部 1142/42000，实际 JDBC 为 1105/HY000；失败证据和完整恢复记录保留。

`FIXTURE_PASS` 只证明原版输入可执行、返回正确、原权限边界可观察；不证明 LP005 的并发 1/16/64、
开环到达/负载分档、连接模式、120 秒预热和 300 秒窗口、A/A/A/B、许可异常态或无性能回退已经通过。
