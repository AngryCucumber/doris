<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP014 原版 Group Commit 输入与路径验证

`group_commit_fixture.py` 与 `LicenseGroupCommitFixture.java` 验证原版 A 的 Group Commit 确认、实际快速分支与
后续数据可见性。此工具不接入许可状态，不改 FE/BE 产品代码或协议，不把成功 INSERT 自动解释为快速分支。
运行前沿用 `validate_cluster` 校验 checkout 安装、当前私有网络 namespace、FE/BE PID 与进程归属；
Java helper 也检查 namespace。只在原有 `license_perf` 数据库创建随机命名的 `gc_fixture_<12 hex>` 独立表，
不修改 `point_rows`、账号、全局参数或外部服务。

## 固定输入、驱动与配置

canonical LP014 的四个批量 **1 / 100 / 1000 / 10000 行全部保留**。冻结 `group_commit=async_mode`，
`enable_group_commit_full_prepare=true` 和 `false` 各一组；每个批量用同一个服务端预编译语句执行两次，
两次写不同的连续 ID 区间，用第二次验证缓存复用。共 16 次 INSERT、44,404 行，这是路径 fixture，
不是声明 canonical ingest_fixture 的 1000 万行已全部写入。

计时外生成独立 CSV 和 manifest：seed `20260922`，每记录包含 LF 精确 128 字节，
`id` 连续、`grp=id%1024`、`v=id%100000`；payload 为 `MD5(decimal id)` 加固定 seed 的 SHA-256 填充串。
manifest 保存每批和全输入 SHA-256、字节数、生成时间，以及独立闭式算术模型的 COUNT、ID 范围和三个数字字段总和。
其格式与 LP012 的固定 ingest 输入一致；MD5 只生成测试字符串。

使用本机已有 **MySQL Connector/J 8.0.33**，从 `--driver` 明确给定 JAR，保存其 SHA-256；不下载依赖。
Jackson 使用原发行包内的版本，JDK 使用 cluster 记录路径。
驱动冻结 `useServerPrepStmts=true`、`cachePrepStmts=false`、`rewriteBatchedStatements=false`、
`useSSL=false`、`serverTimezone=UTC`、10 秒连接超时和 60 秒 socket 超时。
这是隔离测试内的既有 SQL 协议，不引入 TLS 或 mTLS 要求。凭据只从环境传入 JDBC Properties，不保存密码。

每个请求明确是 **一个 N 行 VALUES、4N 个占位符的 `executeUpdate`**，不是 JDBC `executeBatch`，
也不是客户端把 N 次单行请求改写后推断。10000 行对应 40000 个参数。
记录实际 `ServerPreparedStatement` 类名、server statement ID、SQL 模板、prepare 和绑定时间；
如果驱动回退到客户端 prepare 或两次执行之间换 server statement ID，则失败。

独立表采用 DUPLICATE KEY(id)、16 buckets、1 副本、`light_schema_change=true`、
`group_commit_interval_ms=1000`、`group_commit_data_bytes=134217728`；保存实际 SHOW CREATE。
要求原 FE `wait_internal_group_commit_finish=false`，以免配置强制把声明的 async 行为改成 sync；
若不满足则失败，不自动修改全局参数。writer 会记录原会话变量，设置必要值，finally 恢复并 SHOW 验证。
observer 使用独立连接并关闭该连接的 SQL/query cache，连接结束后会话设置自然消失。

## 实际 Group Commit 和 full-prepare 证据

读取并完整保存真实 MySQL OK packet 的 server info，要求：

- `label` 以 `group_commit_` 开头、`status=PREPARE`、正 `txnId`、确认行数恰好为 N。
- 同一连接的 `SHOW LAST INSERT` 记录同一个 txnId、LoadedRows=N、FilteredRows=0。
- full-prepare=true：首次有 `query_id`，第二次同语句还必须有 `reuse_group_commit_plan=true`。
- full-prepare=false：仍必须证明实际 Group Commit，但不得出现 full-prepare 的 `query_id` 或复用标记。

对应原版源码路径为：`ExecuteCommand.run` 在 full-prepare 打开时调用
`GroupCommitPlanner.executeGroupCommitInsert`；已有 planner 时调用 `fastAnalyzeGroupCommit`，
`GroupCommitPlanner.setReturnInfo` 写入 `query_id` 和实际复用标记。
关闭 full-prepare 后落入普通执行器，`OlapGroupCommitInsertExecutor` 仍执行 Group Commit，
其继承的 `OlapInsertExecutor.setReturnInfo` 不提供这两个快速分支字段。
仅观察到 PREPARE 或 label 不能替代 full-prepare 证据。

rc02 的 MySQL OK writer 即使未协商 SESSION_TRACK 也写入长度编码字符串；Connector/J 8.0.33 的
`getServerInfo()` 会把单字节长度前缀保留在已解码字符串里。工具保存驱动返回的完整字符串，并只允许正文前有
零个或一个字符：ASCII 前缀必须等于 UTF-8 正文字节数；非 ASCII 单字节被解码成 U+FFFD 时，只接受正文长度
128..250 的兼容形式。随后严格解析整个 JSON，拒绝多字符前缀和尾随内容。U+FFFD 已丢失原字节，
因此这里不宣称归档了原始网络包或恢复了确切前缀字节；路径证明来自完整字段、当次独立 query_id、
SHOW LAST INSERT 和可见数据共同验证。该适配不修改产品协议。

## 确认与可见时间

`ack_elapsed_nanos` 从已绑定请求调用 executeUpdate 开始，到驱动收到确认返回为止；prepare、输入生成和参数绑定
单独记录，不混入该确认延迟。确认后另一个连接每 100 毫秒查询该批 ID 区间，按 ID 排序读取所有字段。
Java 独立重算每条行的确定性表达式，检查重复/越界，再重建 CSV SHA-256，并与 Python 模型和输入 hash 比较。
成功可见时间必须由完整字段、行数、总和和摘要共同证明，不能只看 ACK、PREPARE、行数或唯一键覆盖结果。

记录每次 poll 的起止时间和已观察行数，以及首个完整 oracle 通过时相对于发送/ACK 的时间。
这些是**轮询观察到可见的上界**，不是事务精确提交时刻；观察从 ACK 后开始，因此不能据此判断数据是否早于 ACK 已可见。
60 秒内未通过则失败。全部批次后再次完整核对 44,404 行和全输入摘要，额外无条件 COUNT 排除范围外多余行。

finally 删除本次创建的独立表并 SHOW TABLES 确认消失；创建失败时不会删除可能预先存在的同名表。
会话恢复或表清理未能确认则失败，不能把半完成导入算通过。

## 执行

与其他计时窗口错开，在当前仍存活且资源配置已冻结的 owned cluster 运行：

```bash
nsenter -t <supervisor-pid> -n -- taskset -c 0-4 \
    python3 tools/license-checks/group_commit_fixture.py \
    --cluster-record .build-records/<current-profile>/cluster.json \
    --output .build-records/<new-lp014-report-directory> \
    --driver /root/.m2/repository/com/mysql/mysql-connector-j/8.0.33/mysql-connector-j-8.0.33.jar
```

独立输入/model 离线检查：

```bash
python3 -m unittest discover -s tools/license-checks -p test_group_commit_fixture.py -v
```

报告包括实际 FE/BE 包 hash、JDK、驱动依赖、源码 hash、输入、DDL、每条 OK packet、参数数量和 statement ID、
ACK/visibility 时间、逐次数据 oracle、恢复与清理。客户端不自动重试失败 INSERT；原版服务内部重试行为属于原产品路径。

## 2026-09-24 实测

Fedora 42 aarch64、Temurin 17.0.4+8、原版 rc02、新建 4 GiB BE profile
`baseline-jdk1704-be4g/cluster.json` 下，`lp014-probe-jdk1704-be4g-v3/report.json` 为 **FIXTURE_PASS**：

- 16/16 批通过，覆盖四个批量、full-prepare 两种开关、每个语句两次执行。
- full-prepare=true 的四个重复执行都具有实际 `reuse_group_commit_plan=true`；八个 query_id 彼此不同。
- full-prepare=false 的八次仍有真实 Group Commit label/PREPARE/txn，均没有快速分支标记。
- 全部 ACK 行数正确、SHOW LAST INSERT 零过滤、每批独立 reader 完整 oracle 通过。
- 全表 44,404 行，ID 0..44403、SUM(id)=985835406、SUM(grp)=22591374、SUM(v)=985835406、bad_rows=0。
- 5,683,712 字节 CSV 与可见数据重建 SHA-256 相同：
  `207c6ae699a6035e75c5df1df016ecfeed3225bd5cb199df37823ab8b71f251b`。
- writer 原会话恢复并复核，独立表删除后 SHOW TABLES 返回空；point_rows、账号和全局设置均未更改。

所有原始记录位于 `.build-records/license-p0-p1-20260924/`。前两次失败证据保留：
`lp014-probe-jdk1704-be4g/` 在 Connector/J 对 ADMIN 的 executeQuery 分类限制处停止，尚未建表；
`...-v2/` 完成一个真实 full-prepare GC ACK 后遇到上述长度前缀解析问题，会话恢复和表删除均确认。
`...-v3/` 使用 Statement.execute 读取 ADMIN 结果和严格单字符前缀适配后完整通过。

3 项 Python 输入/model 离线测试通过，Java helper 编译通过；额外的
`LicenseGroupCommitReceiptTest.java` 检查合法前缀和错误前缀/尾随内容，不发送数据库请求。
本次同时有另一个功能 probe，因此逐批 ACK 和可见时间仅是诊断记录，不能用于性能对比或快速分支收益声明。

任何 `FIXTURE_PASS` 仅证明相应批量的原版路径和数据正确性；不代表并发 1/8/32、恒定输入率、180 秒预热、
600 秒窗口、五对 A/A/A/B、VALID/EXPIRED 候选行为或性能无回退通过。
