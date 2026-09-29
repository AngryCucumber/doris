<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# G3 外部 JDBC INSERT SELECT 单窗性能入口

本入口只覆盖一个真实 PostgreSQL/JDBC sink：每操作读取
`internal.license_perf.point_rows` 的 `id=0..99`，写入全新的自有 PostgreSQL 表。
每个窗口使用一个随机 `run_id`，预热、计时请求使用不重叠的 `request_id`，
表主键为 `(run_id, request_id, id)`。原 source、catalog、PG 服务配置不修改。
EXPORT 和 OUTFILE 不在这个入口中。

使用 `external_write_performance.py`、`LicenseExternalWritePerformance.java` 和
`test_external_write_performance.py`。进程启动、代次、RSS、实际 wait、有限清理复用
`ui_background_fixture.Background`；两阶段释放和 nonce 时钟桥调用已经验证的 DML
生命周期方法。原生 PG 服务身份、原百万行 fixture 的来源绑定复用
`external_read_performance` 的文件/proc 核验，不再次部署服务。

## 成功边界与资源

固定 c1/c8、每 worker 复用一个 FE JDBC 连接、独立泊松开环序列，seed 为
20260922，算法为 Java Random/StrictMath log，每阶段从同 seed 开始。
每个 worker 顺序处理分配给自己的请求，不重叠请求、不自动重试写入。
Python `math.log` 与 Java `StrictMath.log` 在个别速率可能相差 1ns；`plan` 的
`reference_schedule_sha256` 是独立计算的参考值，不能冒充冻结的实际字节。
正式/AB launch 必须带 `arrival_schedule` 引用：其 JSON 包含 `schema_version=1`、
`workload_sha256`，以及 `warmup/measurement` 两个实际 Java `--plan` TSV 的 `{path,sha256}`。
逐偏移仍独立按 ≤1ns 核验，实际 helper ready 后、释放预热前再次核生成 TSV 的 SHA
与预声明字节完全一致；AB cell 和输出窗口使用这个实际 SHA。短诊断可不带预声明。
每阶段保留完整到达序列和每次请求的 ACK/UNKNOWN/NOT_SENT、实际 update count、
排队/执行/端到端时间、同 JVM FE/BE CPU 边界。500ms CPU 前导也必须被实际资源观察覆盖。

原版预检 `.build-records/license-p4-20260929/external-write-preflight-v1/` 已证明这个
外部 INSERT 返回成功 ACK、`update_count=0`，而 PG 原生读取恰有全部 100 行。
工具按实际返回值冻结为 0；不会虚构 JDBC affected rows=100。
只有原生 PG 最终独立读取全部六列并核对每个 ACK 的完整 100 行后，这些操作才可供统计层使用。
计时延迟是 SQL 完成的 ACK 延迟；最终原生读取在窗口外，不能声称测得在线可见性延迟。

原生读取按 `(run_id, request_id, id)` 排序，逐行检查全部字段、缺行、重复、额外键，
保留完整 `native-target.tsv`、逐请求 resolution 和全行 SHA，Python 再独立重算。
任何 UNKNOWN 即使后来有 100 行，也保持 UNKNOWN 并拒绝该窗口；没有行也不是回滚证明。
内部百万行 source 在准备前和结束后逐行完整核对，不以 COUNT 或聚合代替模型。

正式 profile 必须预热至少 180 秒、计时至少 600 秒且预生成至少 10,000 个完整操作。
样本不够必须延长声明的窗口；行数不是成功操作数。短窗只能 `diagnostic`。
该工具支持 DIAGNOSTIC/CAPACITY/AA/AB 单窗身份，但本身不建立 R、不完成 5 对 A/A、
5 对 A/B、置信区间和 1%/2% 性能验收。容量调度适配尚需消费这个相同业务单窗。

输入明确 `max_requests`、`max_rows`、`max_raw_ledger_bytes`、全部相关 storage_paths、
最低剩余磁盘、全程 controller/helper RSS 和外部 PG cgroup 预算。
外部 PG 不仅看主进程 RSS：真实 observer 必须证明固定 CPU、整个 cgroup 的峰值和零新增 OOM kill。
资源耗尽、客户端排队失控、原始回执截断、失败、缺样均不能算产品通过或容量上界。
CPU 指标只用同 JVM 采到的实际 FE/BE 计数，不把外部 PG 或 oracle 的开销虚假归给 FE。

## 精确依赖与凭据

运行时是实际 JDK 17.0.4，准确五个 jar：MariaDB 3.0.9、PostgreSQL 42.7.8，
Jackson core/databind/annotations 2.16.0。所有源码、编译 class、JDK 文件、jar、
输入和实际安装 FE/BE/configuration 均绑定摘要；依赖改变需要重新准备并冻结。
不使用宽 `fe/lib/*` classpath。

FE read/write/admin 使用现有 `{username, host: "%", password_env}` 格式。
`native_account` 使用 `{host, port, database, user, password_env}`，端点、用户名及
PG driver 必须与原 owned external source 描述一致。只传环境变量名，密码不放 SQL、
命令参数或公开日志。本轮可明确选择 root 作为 FE write_account；工具不硬编码 root，
后续更换账号属于客户端身份变化。read_account 需源 SELECT；admin 只在计时外
`REFRESH CATALOG` 以发现新表。工具不创建用户或自动授权。

FE 每连接设两类缓存关闭、group_commit=off_mode、冻结 query/insert timeout。
Statement 的驱动取消定时器为 0，避免驱动另外建立取消连接；FE timeout、65 秒 socket idle
及 120 秒绝对 dispatch watchdog 共同有界。watchdog 仅关闭该 worker 的实际 owned socket，
不改 FE/BE 原通信协议。正常关闭有 5 秒 owned-socket watchdog。
actual connection ID、本地端口和设置读回均进入原始回执。

## 调度 API

默认命令仅文件计算，不启动服务或 SQL：

```text
python3 external_write_performance.py plan PROFILE.json
python3 external_write_performance.py normalize MANIFEST.json
```

根调度器显式调用以下接口，负责 namespace/CPU 隔离、真实 observer 和许可状态证明：

```python
frozen = freeze(api, profile_path, cluster, resources, postgres_driver)
driver = ExternalWrite(api, {"external_write": frozen, "output": output, "resources": resources},
                       guard, target, cell, admin, whole_deadline, cpu_services, launch)
driver.start()                  # 全 source oracle、PG 自有表、FE 长连接准备；此时必须 VALID
# 启动真实观察器并确认其已覆盖 CPU 前导。
driver.release_warmup()         # nonce request/JVM sample/ack 三步时钟桥
# 等 measurement-ready.json；每次等待同时调用 driver.check()
driver.release_measurement()
# 等 verification-ready.json，确认 worker 已关闭。
driver.allow_verification()     # 原生 PG 完整 oracle、source_after、owner DROP；需 VALID
driver.finish()                # 实际 owned parent wait 后才开始下一窗
```

`launch` 包含 `schema_version/phase/variant/window_id/pair_id/launch_token/boot_id/created_monotonic_ns/utc_anchor`、
`max_clock_uncertainty_ns/identity/workload/bindings`，以及 `target`（name/127.0.0.1/query_port）、
`services`（实际 FE/BE pin）、`service_start_ticks/service_configs/external_source`。
`bindings` 精确包含模块 `SOURCES`、`IDENTITIES` 中的键及 `jdbc_driver/postgres_driver`。
configuration 身份文件显式包含 `service_configs`；client 文件包含三类业务账户、target 和
`connection_mode="reuse"`；environment/fixture 绑定实际 external_source，fixture 另含固定 source SHA 和100行口径。
AB 另外包含已经发表的 `freeze/publication`，每窗执行前核 G3、速率、连接、seed、100行业务摘要、
VALID 状态、实际到达序列及全部时间形状；不允许修改文件后沿用旧身份。

normalization manifest 为 `window_directory/launch/completion/resources/license_state`。
resources 和 license_state 使用现有 DML 窄 audit 格式：VERIFIED、实际 launch SHA/boot、
实际覆盖上下界、auditor/raw_artifacts；resources 的 FE/BE 服务各含 pin/artifact/configuration，
并含 external_source 的实际 PG pin/state/resources、采样数、cgroup 上限/峰值/OOM delta/CPU集合。
候选窗必须实测 VALID；原版 A 用同代次实际安装无 license 包的证据，不能伪造许可 API 或填裸 boolean。

## 对象归属和失败保留

PG 表严格 `public.p4_sink_<token>`，先确认不存在，随后原生事务 CREATE+COMMENT+COMMIT，
不使用 `IF NOT EXISTS`、不接管现有对象。owner 记录实际 OID、全部列、完整主键约束、
`massdb-p4-owned:<token>` 注释和配置 SHA。DROP 在有界原生事务中先锁住该表，再核同 OID/列/主键/注释，
保存 `native-drop.json` 的前后身份、真实 ACK 和不存在的确认；只删除这个自有表。

发生错误后先真实关闭/回收原 helper；只有原 `owner.json` 能证明创建 ACK 时，才能运行
独立、有界的 `--cleanup-only` 恢复。恢复仍核真实 PG 服务与对象 owner，保留新 PID/wait 回执，
不会把原失败窗口改为成功。CREATE/COMMIT 结果未知且缺少 owner 回执时不自动接管或删除对象，
保留目标名称/创建意图供根调度器核对。真实 observer/时钟/退出/完整模型缺证据一律拒绝。

测试中的合成 receipts、`--plan` 与 Java 编译只验证工具逻辑；它们不执行 SQL，不是性能通过记录。

首次原 A 诊断在准备阶段暴露原生 PG 地址表示差异：`inet_server_addr()::text`
返回 `10.254.29.2/32`，与声明裸 IP 严格比较失败；没有进入 CREATE，也没有计时。
根控制器另行真实只读确认该目标表不存在，失败记录保留。原生身份查询现使用
`host(inet_server_addr())`，继续同时精确核对 user、database、裸 host、port 和单行结果；
不接受错误地址、掩码字符串、缺行或多行。

准备/清理错误仅对工具自己的私有 `CheckFailure` 增加固定原因码，例如
`ACTUAL_NATIVE_SERVER`；外部异常只保留类名及经过字符约束的 SQLState/错误码，
不保存异常 message。可通过显式 `MASSDB_EXTERNAL_WRITE_JAVA_TEST_RUNTIME` 指向
已有 runtime freeze、`MASSDB_EXTERNAL_WRITE_JAVA_TEST_OUTPUT` 指向全新输出目录，
运行 `test_external_write_performance.py` 的实际 JDK 17 编译和无连接代理结果集检查。
该检查覆盖 13 个身份/诊断正负例，不构造数据库客户端，不替代随后真实两窗重跑。

第二次真实窗口已经完成 11 次预热及 22 次计时写入、完整原生模型和 owned DROP；
其离线审计因 MariaDB 3.0.9 的本地 `getAutoCommit()` 标志为 false 而拒绝，原失败记录不升级。
根控制器用同 JDK/driver 实测 `@@autocommit=1`，本地标志在 `setAutoCommit(true)`、SET 和 SELECT
之后均为 false。当前 session 证据保留原 `auto_commit` 布尔值，并在原有六列之外增加
第七列 `@@autocommit`；准备阶段和离线审计均要求其严格为 `"1"`，不再将 driver 本地标志
作为服务端提交状态。业务摘要明确绑定这一区别及独立原生完整模型要求，以防新旧证据混用于 A/B。
SQL 值为 0、缺失或非规范值时，即使 driver 标志为 true 也拒绝。
