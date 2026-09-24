<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP013 真实 Kafka 前提工具

`kafka_routine_fixture.py` 默认只生成计划，显式 `prepare` 才校验/解包/生成输入，显式 `probe` 才启动自己拥有的真实 broker、生产消息和创建 Routine Load。工具不替换 FE/BE 协议，不模拟消费进度，不修改产品源代码。10,000/100,000 行仅是功能前提子集；`LP013_complete`、`release_performance_pass` 始终为 false。

原 LP013 的 10,000,000 行、8 分区、1/8/32 并发、1,000/10,000 批次、180 秒预热、600 秒窗口、至少 5 对、1%/2% 精度及 VALID/EXPIRED/续期目标保留。本工具尚不提供固定送达率、许可状态切换或正式 A/B 指标，不能把功能 probe 吞吐当成容量或性能通过。

## 固定发行包与已有客户端

选择 Apache Kafka **3.9.2 / Scala 2.13**，归档包约 117 MiB。实际 SHA-512 必须等于官方发布的以下值，校验后才允许解包或执行脚本；并另存包 SHA-256、解包后每个文件摘要、来源 URL。没有执行 PGP 身份认证时，报告明确 `archive_pgp_signature_verified=false`。[官方版本目录](https://archive.apache.org/dist/kafka/3.9.2/)、[官方 SHA-512](https://archive.apache.org/dist/kafka/3.9.2/kafka_2.13-3.9.2.tgz.sha512)。

```text
01186a5086b5ae753811ee71808a797baec1303d4e0d4b1c0acf42c489654a7b8988136f8469d0b66f0be439f8e3e9b816171ea0b0d7a36462b07aa2d3ef0023
```

Kafka 3.9 文档支持 Java 17；这个私有测试 profile 固定为实际 Temurin **17.0.4+8**，检查 release 文件及 Java helper 的 `java.runtime.version`。KRaft 单节点使用静态 `controller.quorum.voters`、同进程 broker/controller，不另起 ZooKeeper。[官方 Java 支持说明](https://kafka.apache.org/39/operations/java-version/)、[KRaft 配置说明](https://kafka.apache.org/39/operations/kraft/)。

probe 前必须保留 `prepared.json` 所引用的 owned 归档文件。probe 会重新校验其固定 SHA-512 和记录的 SHA-256，
直接读取已校验归档中的文件摘要，并将实际解包目录及 manifest 分别与之比较，再允许编译或启动进程。
因此同时替换某个 JAR 与 manifest 中的对应摘要也不能改变实际发行包来源；缺少原归档时拒绝 probe。
这个步骤只校验已有内容，不下载或再次解包。

仓库 FE Maven 配置的 `kafka-clients.version` 是 3.4.0，BE `thirdparty/vars.sh` 固定 librdkafka 2.11.0。本机缓存的 clients/tools JAR 不包含可运行的完整 broker。新 producer/独立 consumer 使用所校验发行包中的 kafka-clients 3.9.2；与本仓库 FE/BE 端到端兼容性必须由实际 probe 建立，文档和编译不能代替。

## 私有生命周期与资源

probe 必须在已有 checkout 测试 FE/BE 的同一私有 network namespace 执行。发任何 SQL 前校验 namespace 不等于宿主、FE/BE PID/命令路径/namespace 归属及 FE `query_port`；结束再次检查 PID/start_ticks。Kafka 仅监听该 namespace 的 `127.0.0.1:39092` 与 controller `39093`，无宿主绑定、端口转发或 FE/BE 通信协议变化。

broker heap 固定 512 MiB、G1；客户端 helper heap 256 MiB，每 producer 的发送 buffer 2 MiB。broker、客户端、本地页缓存合计先预留约 **1–2 GiB**，这是待实测资源预算，不是保证。100k CSV 是 12.8 MB；每条 Kafka value 去除 CSV 的 LF，实际 127 B，另有 key 和协议开销。完整 10M CSV 为 1.28 GB，Kafka 日志、BE 副本/压缩及独立证据另计，不能仅按源文件大小估盘。

预期 100k 功能 probe 约数分钟，实际尚待运行。主工作 watchdog 20 分钟；单个 SQL helper 最长 90 秒；最后最多三个 SQL 清理 helper 合计 270 秒，自己的进程组 TERM/KILL 各等待 5 秒。所有子进程以独立 session 启动并保存清理回执，leader 已退出也检查子孙；只停止本工具创建的 broker/helper，不能停止 FE/BE。SIGINT/SIGTERM/SIGHUP 转为有界取消，finally 独立尝试 `STOP ROUTINE LOAD`、查询 `STOPPED`、`DROP TABLE`、停止自己的 broker，清理错误保留在失败报告。

下载本身有 20 秒 socket 超时、5 分钟总时限与 160 MiB 上限；tar 限 20,000 项/1 GiB 解包总量，拒绝绝对路径、目录穿越、符号链接、硬链接和设备。输出只能落在本 checkout `.build-records` 的新子目录，旧记录不覆盖。

## 并发与批次含义

`KafkaRoutineLoadJob.calculateCurrentConcurrentTaskNum()` 取 `min(分区数, desired_concurrent_number, FE 全局上限)`。本仓库 FE 默认上限为 256，但 **8 分区单 job 最多 8 个消费任务**。因此工具分别保存 producer workers（1/8/32）和 requested/observed Routine Load tasks（1或8）；32 个 producer 不等于 32 个消费者。正式矩阵的并发解释需在正式运行前冻结，本工具不擅自改写现有契约。

`CreateRoutineLoadInfo.MAX_BATCH_ROWS_PRED` 要求 Routine Load `max_batch_rows >= 200000`。本工具将 1,000/10,000 解释为生产源文件分组：每个全局分组内部按 worker 序号分摊，不增加/跳过行；各 producer 独立发送，无全局批次 barrier。真实 Kafka 网络 request 的字节批次也与该行分组不同。Routine Load 固定 `max_batch_rows=200000`、`max_batch_interval=5`、`max_batch_size=104857600`，不得把 1,000/10,000 非法填入该属性。

## 消息与完整入库 oracle

输入是固定 seed 20260922 的完整 affine ID 排列：`id=(index*a+b)%rows`，`a` 从 seed 确定并要求与 rows 互质，`b=seed%rows`。它保证每个 `0..rows-1` 恰好一次，明确不是独立均匀抽样。完整 CSV 及 SHA 保存；列为 id、id%1024、id%100000、MD5(decimal id) 加确定性补齐内容，固定每行含 LF 128 B。分区固定 `id%8`，与 Kafka 默认 partitioner 无关。

producer 使用真实 `send` Future，`acks=all`、idempotence=true、max.in.flight=1、delivery timeout 30s，并记录真实 retry/error/send metrics。8 分区副本数为1，因此 all 只证明单 leader 确认，不宣称副本容错或断电耐久性。[官方 producer 配置](https://kafka.apache.org/39/configuration/producer-configs/)。

每个输入保存 index/id/worker/partition/offset/ack timestamp/value SHA，独立核对完整 ID 域及每分区连续 offset。另开真实 KafkaConsumer 从每分区0读取到冻结的 exclusive end，保存完整 key/value Base64 与物理 offset；Python 重新比较原始内容和生产确认，缺失、重复、错误分区或错误内容都失败，不能依赖 helper 的 success 标志。

真实 `CREATE ROUTINE LOAD` 从8个分区显式 offset0开始，strict_mode=true、max_error_number=0、max_filter_ratio=0，SQL 原文归档。每次轮询保留 `Statistic`、`Progress`、`CurrentTaskNum`、task/BeId/TxnStatus。必须 loadedRows=预定行数、errorRows/unselectedRows=0、committedTaskNum>0，各分区进度到达最后一条。注意 `KafkaProgress.toJsonString()` 返回的是 **最后已提交 offset**，比 Kafka exclusive end 小1，不能混淆。

目标表用 **DUPLICATE KEY**，避免 Unique Key upsert 隐藏重复行。最终独立 SQL 对整表检查 count、count(distinct id)、ID 范围、各列总和，以及每行 grp/v/完整 payload 的表达式；N条不同ID均在0..N-1即证明没有漏数，payload逐行比较证明内容正确。oracle 查询不计为性能测量。finally 停止作业、确认 STOPPED、删除临时表并停止 broker；自己的 Kafka 数据和日志作为诊断证据留在 checkout 中，后续测试清理可以删除。

## 命令与当前证据

默认 plan 不需要集群记录、不下载、不编译、不连接网络：

```bash
python3 -B tools/license-checks/kafka_routine_fixture.py \
  --rows 100000 \
  --output .build-records/license-p0-p1-20260924/lp013-kafka-plan
```

有协调窗口后，显式下载并校验；如果已有官方归档包，可用 `--archive .build-records/.../kafka_2.13-3.9.2.tgz` 替代 `--download`，仍要求完全相同官方 SHA-512：

```bash
python3 -B tools/license-checks/kafka_routine_fixture.py --mode prepare --download \
  --rows 100000 \
  --output .build-records/license-p0-p1-20260924/lp013-kafka-prepared-100k-retry
```

后续重跑 probe 时，仅在协调到独占资源窗口后，替换为当时实际存活的 supervisor PID/cluster record，并使用新的输出目录，从已有 private namespace 执行：

```bash
nsenter --target ACTUAL_SUPERVISOR_PID --net \
  python3 -B tools/license-checks/kafka_routine_fixture.py --mode probe \
  --prepared .build-records/license-p0-p1-20260924/tool-validation-20260924/kafka/prepared-100k \
  --cluster-record .build-records/ACTUAL_CLUSTER/cluster-state.json \
  --rows 100000 --producer-workers 1 --consumer-tasks 8 --batch-rows 1000 \
  --output .build-records/license-p0-p1-20260924/lp013-kafka-probe-100k
```

2026-09-24 初次验证通过16项离线测试；Java helper 当时使用精确 Temurin 17.0.4+8 与本地缓存 kafka-clients **3.4.0** 完成编译检查。历史清单保留于 [初次工具验证记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp013-kafka-development.json)。初次官方下载在主机 TLS 握手时报 EOF，curl 复核相同；官方 downloads/dlcdn 的同版 URL 返回404。见 [下载诊断](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp013-kafka-download-failure.json)。该失败记录保留；没有关闭 TLS 校验、改用其他包、启动 broker 或伪造 reachability。

随后同一官方 archive 入口恢复访问，已通过有界 HTTPS range 下载恢复完整 **122,473,776 字节**归档。
完整文件 SHA-512 同时符合原冻结值与新下载的官方 checksum；传输中断、range 回执及全部实际时间保留在
[恢复记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp013-kafka-archive-recovery-20260923T224842Z/recovery-receipt.json)。
该准备活动限制 CPU5、nice19、idle I/O、512 KiB/s，并作为正式原语测量期间的旁路活动如实记录，
不声称主机完全空闲。该次恢复阶段未解包、生成输入、编译、启动 broker 或请求数据库。

2026-09-24 04:42–04:43 UTC，在确认正式原语 controller 与 probe 均已停止后，CPU5 上实际完成以下验证：

- **20 项离线测试全部通过**，包括新增的4个归档来源与协调篡改负例。
- 同一固定归档 SHA-512 校验通过并准备100,000行、12,800,000字节输入；重新读取固定归档核对全部233个发行文件和完整输入序列。
- `LicenseKafkaFixture.java`、`LicenseFixtureSql.java` 使用精确 Temurin **17.0.4+8** 和发行包中的 **kafka-clients-3.9.2.jar** 编译成功；`--release 8` 产出4个 major52 class。依赖、源码、class、日志摘要和实际 UTC 保存于 [本次验证回执](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/kafka/validation-receipt.json)。

实际 prepare 命令如下；输出目录已经存在，再次准备须使用新的 owned 目录：

```bash
taskset -c 5 python3 -B tools/license-checks/kafka_routine_fixture.py --mode prepare \
  --archive .build-records/license-p0-p1-20260924/lp013-kafka-archive-recovery-20260923T224842Z/kafka_2.13-3.9.2.tgz \
  --rows 100000 --output .build-records/license-p0-p1-20260924/tool-validation-20260924/kafka/prepared-100k
```

上述离线验证没有启动 broker 或请求数据库，编译成功本身不证明 broker 协议或 Routine Load 可用。

2026-09-24 04:49–04:53 UTC，在新建原版单 FE/BE 环境的独占窗口中，实际运行了100,000行功能 probe：

- 首轮 `lp013-kafka-actual-100k-v1` 的 broker/init 成功，但真实 FE 拒绝 Routine Load DDL：两个 `loadProperty` 间缺少逗号。依据原版 `DorisParser.g4` 修正 SQL 生成后，20项离线测试再次通过。首失败日志与原 `cleanup=false` 保留；独立后查确认该轮 job/table 均不存在、broker 已退出。
- 新目录 `lp013-kafka-actual-100k-v2` 在 CPU6–9、私有 namespace、精确 JDK17.0.4+8、Kafka3.9.2、BE4GiB 下返回 `FUNCTIONAL_SUBSET_COMPLETE`。producer workers=1、batch=1000，100,000条 ACK 与独立消费者的100,000条完整记录逐条通过；8个分区起始 offset0、exclusive end12500。
- Routine Load `loadedRows=100000`、`errorRows=0`、`unselectedRows=0`、`committedTaskNum=8`、`abortedTaskNum=0`，每分区 last committed12499。可见性独立模型核对100,000个不同 ID、ID范围0–99999、整数求和及 `bad_rows=0` 全部一致。
- `desired_concurrent_number=8`，轮询记录 `CurrentTaskNum=8`；即时 `SHOW ROUTINE LOAD TASK` 返回的是 `BeId=-1` 的待调度任务，不能据此声称观测到8个并行 BE 执行任务。
- 清理回执和独立后查确认本次 job 为 STOPPED/current tasks0、表缺席、所有20个已记录子进程组无幸存、broker 两端口可重新绑定；FE/BE/supervisor 身份不变，没有停止或修改共享数据库服务。

完整首失败、修复、重测、计数、oracle 和清理证据见 [真实100k功能审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp013-kafka-actual-100k-audit.json)。
100,000行仍是功能前提子集。完整10,000,000行、180秒warmup/600秒窗口、全部并发/批次及VALID/EXPIRED/renewal矩阵保持待验，`LP013_complete`、`release_performance_pass` 仍为 false。
