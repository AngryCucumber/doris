<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP015 原版 DML 与显式事务 fixture

`dml_transaction_fixture.py` 与 `LicenseDmlTransactionFixture.java` 实测原版 A 的三种 100 行 DML、
真正同会话 BEGIN/COMMIT/ROLLBACK，以及明确不支持的事务组合。
`FIXTURE_PASS` 表示支持边界与内容 oracle 都符合冻结预期，不表示那些被拒绝或仅返回 ACK 的语句获得事务支持。
工具不接入许可状态、不改 FE/BE 产品代码、全局配置、账号或 `point_rows` 数据。

## 源码确定的边界

本分支 `StmtExecutor.executeByNereids` 在事务模式下允许 INSERT、UPDATE、DELETE 和事务控制命令；
SELECT/SHOW 等其他命令不在允许集合。`UpdateCommand.run` 和 MOW 表的 `DeleteFromUsingCommand.run`
经 INSERT 执行器工作，`OlapTxnInsertExecutor` 将其加入显式事务。
`TransactionEntry.beginTransaction` 以及 VALUES 事务入口不允许在同一个事务中混用 INSERT SELECT 与 INSERT VALUES。
此外，不同表模型和 DELETE 路径存在顺序限制；本 fixture 固定 MOW 和 `enable_mow_light_delete=false`，
不从这套结果推广到其他模型或顺序。

`StartTransactionCommand.run` 实际执行的是空操作并返回 OK。因此这里以 **BEGIN** 打开受测事务；
另外实测 START TRANSACTION 的 ACK-only 行为，将其明确记录为没有事务语义，不能用它替代 BEGIN。
这些结论以实际发行响应再次核验，不只依据类名、注释或“SQL 执行成功”。

## 输入与独立数据模型

入口沿用 `validate_cluster`，校验当前私有 namespace、checkout 内安装、实际 FE/BE PID 与进程归属；
Java helper 也拒绝在宿主 namespace 执行。使用已存在的 `license_perf` 数据库，
创建随机命名的 `dml_fixture_<12 hex>` 独立表。表结构为 id/grp/v/payload、UNIQUE KEY(id)、16 buckets、1 副本、
MOW、row-store、light-schema-change，另明确 `enable_mow_light_delete=false`；实际 SHOW CREATE 归档。

source 只读 `license_perf.point_rows` 的 ID 0..599。Python 在执行前独立生成 600 行的数学模型：
`grp=id%1024`、`v=id%100000`、payload 为 `MD5(decimal id)`，与 bench_small 一致。
UPDATE 把对应 100 行的 v 加 1,000,000，payload 加 `u_` 前缀。
每个状态都冻结行数、唯一 ID 数、范围、三个数值总和、按 ID 排序的完整四字段 CSV SHA-256。
Java 从独立 reader 连接读取所有字段、重建摘要并核对该模型；不能只凭 affected_rows、数量或 SELECT 成功通过。

| 阶段 | 实际操作与期望 |
| --- | --- |
| 独立 INSERT SELECT | 复制 source ID 0..99，共 100 行；完整内容可见 |
| 独立 UPDATE | 修改上述 100 行的 v 和 payload；内容摘要变化符合模型 |
| 独立 DELETE | 删除上述 100 行；目标为空 |
| 事务前置数据 | 从 source 复制 ID 0..199，200 行已提交 |
| BEGIN → 三种 DML → ROLLBACK | DELETE 0..99、UPDATE 100..199、INSERT SELECT 200..299，各 100 行；每步 reader 仍见原 200 行；回滚后保持原内容，事务为 ABORTED |
| BEGIN → 同三种 DML → COMMIT | 每步 reader 仍见原内容；提交后 ID 100..299 共 200 行，其中 100 行被更新；事务为 VISIBLE |
| BEGIN → SELECT 1 | 原版 1105/HY000 拒绝，消息说明只允许 DML 和事务控制；回滚后内容不变 |
| BEGIN → INSERT SELECT → VALUES | 第二种入口被原版 1105/HY000 拒绝；回滚后内容不变、事务 ABORTED |
| BEGIN → VALUES → INSERT SELECT | 第二种入口被原版 1105/HY000 拒绝；回滚后内容不变、事务 ABORTED |
| START TRANSACTION → INSERT SELECT 100 → ROLLBACK | START 返回 ACK，SELECT 1 仍可执行；新 100 行在 ROLLBACK 前已可见，之后仍在，实际事务 VISIBLE；明确标为无事务语义 |

真正 BEGIN 的 OK info 必须包含 `txn_insert_` label 和 PREPARE；每条成功 DML 必须保留同一 label、
PREPARE 和准确 affected_rows。结束后以独立连接的 SHOW TRANSACTION 核对实际根事务 ID 及 VISIBLE/ABORTED，
同时验证完整数据。SQL 使用真实同一个 writer Connection，不能用每语句重连假装同一事务。

事务未结束时，以及回滚之后，reader 连续三次（间隔 100 ms）必须观察到预期不变的已提交状态；
提交后的内容最多轮询 30 秒。报告记录每次观察的实际模型、时间和 SQL 结果，这只是这些观察窗口的语义证据。
最后再次核对 source 600 行完整摘要，所有写 SQL 的目标始终是本次独立表。

## 驱动与恢复

冻结已有 MySQL Connector/J 8.0.33、text Statement / COM_QUERY，`useServerPrepStmts=false`、
`rewriteBatchedStatements=false`、**`useLocalSessionState=true`**、`useSSL=false`、UTC 驱动时区，
连接/读取超时分别为 10/60 秒。JDK 来自 cluster 记录，Jackson 来自该原版发行包；保存全部依赖 hash。

`useLocalSessionState=true` 是这里必要的驱动兼容设置，与原分支事务回归一致：否则 Connector/J 在 DML 前
会自动发送 `SELECT @@session.transaction_read_only`，该查询在真正 BEGIN 之后被原版事务限制拒绝，
导致 DML 尚未发出就失败。不能把这个驱动探测失败误报为 DELETE/UPDATE 不支持，也不能修改 FE 来绕过它。

只设置 writer 的 `group_commit=off_mode`、`enable_insert_strict=true`、
`enable_unique_key_partial_update=false`，记录原值并 finally 恢复、SHOW 复核。
reader 的 SQL/query cache 在该连接内关闭，连接最终关闭。
JDBC 的自动提交属性不代替显式 SQL 事务控制；BEGIN、COMMIT、ROLLBACK 均实际发送并记录响应。
凭据仅从环境读入 Properties，不写 SQL、参数或报告，异常文本先脱敏。

finally 先对 writer ROLLBACK，随后恢复会话；再使用独立 reader 删除本次创建的表，SHOW TABLES 确认空集合。
不会删除创建前已存在的同名表。任何恢复、回滚或清理不能确认都会使结果失败。

## 运行与真实结果

与性能窗口错开，每次使用新报告目录：

```bash
nsenter -t <supervisor-pid> -n -- taskset -c 0-4 \
    python3 tools/license-checks/dml_transaction_fixture.py \
    --cluster-record .build-records/<current-profile>/cluster.json \
    --output .build-records/<new-lp015-report-directory> \
    --driver /root/.m2/repository/com/mysql/mysql-connector-j/8.0.33/mysql-connector-j-8.0.33.jar
```

纯本地模型检查：

```bash
python3 -m unittest discover -s tools/license-checks -p test_dml_transaction_fixture.py -v
```

2026-09-24 北京时间，在 Fedora 42 aarch64、Temurin 17.0.4+8、原版 rc02、
`baseline-jdk1704-be4g/cluster.json` 记录的私有 1 FE / 1 BE 上，10 个阶段完整验证：

- `.build-records/license-p0-p1-20260924/lp015-probe-jdk1704-be4g-v2/report.json` 为 FIXTURE_PASS。
- 三种独立 100 行 DML 和两个真正 BEGIN 事务的完整数据/状态验证通过。
- ROLLBACK 根事务 43 为 ABORTED；COMMIT 根事务 46 为 VISIBLE。ID 100..299 的提交结果有 200 行，
  SUM(id)=39900、SUM(v)=100039900、完整摘要为
  `244b008b2bbfef326b9e952f20b63bf30e870b1b7325378fb70f5830696cca78`。
- 三种明确拒绝的结果分别标记 `UNSUPPORTED_REJECTED`，原 SQL errno/state/message 保留；两种混用回滚事务 49/50 均 ABORTED。
- START 的结果标记 `ACKNOWLEDGED_WITHOUT_TRANSACTION_SEMANTICS`；其 INSERT 事务 51 已 VISIBLE，ROLLBACK 后新增 100 行仍存在。
- source 600 行前后 SHA-256 均为 `12c08eb99ebce98c7579a05341e81547c1dee1996c678c110d7089041ad27b93`。
- cleanup ROLLBACK、会话原值恢复和独立表删除全部确认，所有客户端退出。

初次 `.build-records/license-p0-p1-20260924/lp015-probe-jdk1704-be4g/` 失败证据保留：
独立三种 DML 已通过，BEGIN 后被 Connector/J 的自动只读状态查询阻断；
`driver-readonly-audit.txt` 保存精确 BEGIN 和被拒查询的原版 FE audit 摘录，证明请求并非 DELETE。
该轮也完整恢复会话并删除独立表。`lp015-offline-checks/` 保存编译与三项模型/支持边界测试记录。

上述结果不包含并发 1/8/32、负载批量 1000/10000、每客户端 1000 事务、180 秒预热与 600 秒窗口、
五对 A/A/A/B、有效/缺证/过期/超额下的候选行为或性能无回退结论。
