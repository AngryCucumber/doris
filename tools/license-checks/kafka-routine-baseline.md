<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP013 原版完整输入持续窗口

`kafka_routine_baseline.py` 与 `LicenseKafkaBaseline.java` 提供一个完整原版 A 窗口的执行路径。
默认 `plan` 只保存独立定义、源码摘要和到达序列；不读实际归档、不生成数据、不编译、不联系服务。
显式 `prepare` 才校验既有官方归档并准备完整输入；显式 `probe` 才编译并联系隔离的原版 FE/BE、启动自有 Kafka。
既有 `kafka_routine_fixture.py` 的 10k/100k 路径和已通过的真实 100k 证据保持独立。

完整单窗也始终保存 `LP013_complete=false`、`release_performance_pass=false`。
状态 `FULL_INPUT_WINDOW_COMPLETE_NOT_QUALIFIED` 只表示这一窗的输入、ACK、独立 consumer、SQL 内容和清理全部通过；
没有至少五对 AA/AB、所需精度、许可状态和完整矩阵，不能据此宣称 LP013 或性能通过。

## 冻结轴与时序

独立 plan 的 `definition_clarification` 明确将并发 **1/8/32 定义为生产客户端工作数**。
`KafkaRoutineLoadJob.calculateCurrentConcurrentTaskNum()` 实际计算
`min(partition_count, desired_concurrent_number, max_routine_load_task_concurrent_num)`。
因此 8 分区单 job 最多 8 个消费任务；`--consumer-tasks 1|8` 独立记录，另保存实际 `CurrentTaskNum`、task/BeId/事务状态。
采样看到 waiting task 或 BeId=-1 不能证明同时在 BE 执行。这里没有改写 canonical JSON。

生产批次为 1,000/10,000 行，一个完整批次分配给 `batch_index % producer_workers` 的客户端。
这与旧 100k 工具的批次内分摊定义不同，plan 明确冻结新定义。
Routine Load 自己的 `max_batch_rows=200000`、5 秒 interval、100MiB 大小上限保持合法且独立，不能把源批次当成消费事务大小。

同一个 JVM、同一组 KafkaProducer、同一 topic/job/table 顺序执行：

1. 额外 3,000,000 条预热记录，ID `[10,000,000,13,000,000)`，固定 180 秒。
2. 等待所有预热 ACK；实际 Kafka exclusive end 必须各为 375,000；Routine Load 已提交各 offset 374,999，独立 SQL 验证全部预热内容。
3. 控制器以本次 owner token、配置摘要、同 JVM clock domain 写入 visibility barrier；Java 收到后将计时起点设为 `nanoTime()+2s`。
4. 完整 10,000,000 条计时记录，ID `[0,10,000,000)`，固定 600 秒。不能压缩成短 probe。
5. 总物理输入 13,000,000 条；最终各 Kafka exclusive end 为 1,625,000，Routine 已提交 offset 为 1,624,999。完成全量内容 oracle 后清理。

预热与计时各自在自己的完整 ID 域作 seed 20260922 affine permutation，分区恒为 `id % 8`。
两阶段同为 `10,000,000 / 600` 行/秒。第 i 个批次的固定到达 offset 为
`floor(i * phase_duration_ns / phase_batch_count)`；计时不因 ACK 快慢移动预定到达序列。
每 worker 最多持有一个批次，积压体现在实际 dispatch delay；预定到达后 60 秒仍未成功即失败，不自动重放。
每条实际 callback ACK 记录 `sent_ns/ack_ns/partition/offset`；每批记录 scheduled/start/finished 和完整发送/确认计数。
未派发、部分 ACK、未知提交、工作线程或证据失败均不能变成成功样本。

所有生产时间在同 JVM `System.nanoTime` 域。主批次延迟是 **finished-scheduled，包含排队**；
另保存 service 和 dispatch 的分布，不能把两个分位数相加代替端到端分位数。
预热 barrier gap 独立报告，不算入 180/600 秒；计时窗口内 ACK 与 drain ACK 分开计数。
批次 1,000 有 10,000 个计时请求；批次 10,000 只有 **1,000 个请求**，因此后者抑制 P99（null）。
13M 行不是 13M 个批次延迟样本，即使前者达到样本下限也仍未建立 AA/AB 精度。

## 内容、原版绑定和资源

固定每条 CSV 含 LF 128B；Kafka value 去掉 LF，为 127B。准备时调用原生成器，probe 用独立表达式重建每条输入。
3M+10M 的输入分别保存并冻结 SHA-256。归档必须是已恢复的 Kafka 3.9.2/Scala 2.13；
再次核对旧工具固定的官方 SHA-512、SHA-256 及归档内每个实际文件，不接受同时改写 JAR 和 manifest。
PGP 身份验证仍为 false，不把 checksum 验证升级为发布者签名验证。

成功路径保存全部 producer ACK 和真实独立 KafkaConsumer 的原始 key/value Base64。
Python 用位图和 **104,000,000B 磁盘 offset→ID 索引**逐条交叉验证；不复制原 100k 工具的全行 dict/set 到 13M。
必须完整覆盖两个输入排列、全 13M ID、每分区连续 offset、正确 warmup/measurement offset 区间及全部实际字节。
SQL 用 DUPLICATE KEY 表避免 upsert 隐藏重复；每 250k ID 区间检查 count/distinct/min/max/整数 sum 和逐行完整 payload，
再检查整表总数，拒绝区间外多余行。SQL oracle、归档/input 验证、编译、独立消费者均在计时窗外。

probe 要求显式原版 FE/BE 摘要、实际 ADMIN 权限、私有 namespace、服务 PID/start_ticks/可执行文件归属和精确 Temurin **17.0.4+8**。
原包 FE 不得含候选许可实现。Java 再检查 namespace、JDK、真实 Kafka client 3.9.2 和 owned 路径。
JAR/JDK/源码/计划/到达序列/配置/输入/执行 class 保存摘要并在结束复核。
所有子进程直接执行已绑定 Java/Javac；不执行 shell 启动脚本，不继承额外 JVM/classpath 注入。

客户端默认固定 CPU0，可显式选择另一可用 CPU。broker heap 512MiB，生产 helper heap 512MiB，单客户端 buffer 2MiB。
沿用有界资源观察器：helper RSS 768MiB，controller RSS 512MiB，fixture 合计 RSS 2GiB，另要求 512MiB 可用内存储备。
CPU/RSS/线程/IO 和私有 namespace 网络计数独立保存，不把观察器或客户端 CPU 算成 FE CPU。
这些是采样上限，可能遗漏瞬时峰值；GC pause、总分配量、RPC 指标和进程级网络归因仍不足，明确保留为未满足项。
broker 与 producer 的 stdout/stderr 单流最多 2MiB，其他 helper 首次失败日志同样保留。

准备与 probe 要求至少 16GiB 可用磁盘；probe 输出、broker 数据和证据上限 8GiB（每 5 秒检查），保留 256MiB 磁盘储备。
主工作最多 3,600 秒；预热 180/计时 600 秒不缩短，ACK drain 最多 120 秒，visibility 最多 300 秒，
barrier 等待最多 600 秒，独立消费者最多 900 秒，最后 SQL 清理预算 180 秒；owned child TERM/KILL 各最多 3 秒。
数据不在计时窗口内重置：每窗从新的空 topic/table/job 开始，在全量验证后删除本次表并停止 job/broker。

## 归属和失败清理

输出只允许 checkout `.build-records` 中的新目录，复用已准备的输入时不覆盖它。
本工具独占锁失败即拒绝启动；检测已有同 checkout 测量进程，拒绝与其他业务驱动重叠。
真实任务还须由控制器协调独占环境，工具锁不替代跨工具协调。

CREATE 前检查准确的随机表/job 名不存在；成功 ACK 后绑定实际 DbId、TableId、8 个 TabletId 和 SHOW CREATE 摘要。
Routine 的实际字段是 SHOW 的 **`Id`**；同时绑定其创建时间、目标已确认 TableId、topic、broker。
`RoutineLoadJob.getShowInfo()` 用存储的 tableId 解析 TableName，不能发明一个不存在的 SHOW TableId 列。
STOP 前重新校验表与 job 身份，DROP 前再次核对表的数字身份；同定义重建也被拒绝。
未知 CREATE、缺少身份回执或身份变化不允许按名字接管，报告 manual residual 并失败，保留所有原始回执。

finally 先停止 sender，再独立尝试 STOP/确认 job STOPPED/task0、DROP/确认表缺席、停止自有 broker/helper，
记录 process group 无活成员、资源线程结束和 owned lock 删除。任何一步失败都不声称清理成功。
共享 `license_perf` 数据库、FE/BE 和 namespace supervisor 不会被本工具停止或删除。
保留输入、Kafka 日志、失败/成功回执；本次不删除证据来掩盖重试。

## 使用与当前验证

默认计划示例（不启动服务）：

```bash
taskset -c 0 python3 -B tools/license-checks/kafka_routine_baseline.py \
  --producer-workers 32 --consumer-tasks 8 --batch-rows 10000 \
  --output .build-records/license-p0-p1-20260924/lp013-full-plan-new
```

显式准备完整输入须提供 `--mode prepare --archive <owned-3.9.2.tgz>` 和新输出目录；不提供下载参数。
真实执行须在记录的私有 namespace 内，显式选择 `--mode probe --prepared <full-prepared-directory>`、
`--cluster-record <cluster.json>`、`--expected-fe-sha256 <sha>`、`--expected-be-sha256 <sha>`。
密码仅由已显式存在的 `MASSDB_KAFKA_*_PASSWORD` 环境变量读取，允许隔离空密码，不能写入回执。

2026-09-24 离线实现验证：CPU0 上 39 个新增 Python 反例/模型测试和旧工具 20 个测试通过；真实 Temurin17.0.4+8 与已校验实际 Kafka3.9.2/
原版 FE Jackson/JDBC 依赖，以 `--release 8 -proc:none` 编译通过。
Java 内置 `selfcheck` 17 个场景通过：完整遍历两个分离 ID 域的 13M 位图、8 分区计数、全部并发/批次到达边界，以及强制/中断时线程池的有界清理与关闭异常不覆盖首错。
验证期间未启动 broker/FE/BE/SQL/HTTP，没有准备全量数据，没有运行真实持续窗。
最终验证回执位于 `.build-records/license-p0-p1-20260924/tool-validation-20260924/kafka-baseline-v3/`；首轮 v1/v2 保留。
真实全量可执行性、资源预算和性能指标仍待环境释放后的显式运行验证。

随后实际全量准备已完成，仍未启动完整Kafka窗口：
[准备清单](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp013-sustained-prepared-13m-v1/prepared.json)
保存精确3.9.2归档SHA512、233个解压文件库存，以及独立的3M预热/10M计时CSV。
[独立复核](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp013-sustained-prepared-13m-v1-control/validation.json)
在CPU0逐字节重建完整13M模型并复核库存、SHA和9个冻结源码，真实退出0，无SQL/HTTP/编译/服务启动。
预热384,000,000字节SHA256为 `6b7e991f265f8310055697fa8efab5ced99c5031a669d52595e250e5f4c87def`；
计时1,280,000,000字节SHA256为 `7a69de7a4853c6b8da34dd0cbdb1dcb0a387358ee2342f7145100b5d29a84878`。
prepare历史计划中的1个producer不影响输入字节；输入仅由固定行数、ID域和置换决定。
首个实际窗口另行冻结8个producer、desired8消费者、batch1000、CPU5及原180/600秒。

实际 v1 [报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp013-sustained-actual-v1/report.json)
及[独立退出/清理审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp013-sustained-actual-v1-control/completion-audit.json)
为真实exit0、`FULL_INPUT_WINDOW_COMPLETE_NOT_QUALIFIED`：3M预热和10M计时全部ACK，独立SQL完整13M、
实际consumer字节/ID/连续offset交叉核验全部通过；每分区物理末尾1,625,000、提交offset1,624,999。
原FE实际消费任务数8；8个持久producer各发送1,625,000行，错误/重试为零。
固定60毫秒批次到达下，测量请求区间实际重叠峰值1，不能将8个客户端表述为8个同时执行请求。
10,000个生产批次P95/P99（含排队）为19.658107/22.8633毫秒，全部10M ACK在600秒窗内、drain0；
这些是producer send/ACK延迟，不是Routine提交延迟或A/A性能资格。

清理核实STOPPED/task0/报告中的runningTxns为空、表独立缺席、285个自有进程及进程组清空、
双broker端口释放、owner锁清除、原3服务身份未变；broker143为归属SIGTERM，其余helper退出0。
资源1,064次采样完整、零失败。清理前采到总输出7,601,681,467字节，小于原8GiB，非绝对峰值证明；
停止broker后索引截短，最终目录6,367,154,269字节。初始空间投影漏列内部50个offset分区索引，
运行期间补充[实际占用投影](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp013-sustained-actual-v1-control/output-projection-during-measurement.json)，
原始估计保留、8GiB预算没有增加。完整逐行交叉核验由本次runtime执行；退出后独立复核绑定SHA、
64个SQL整数range及13,000个batch时序，未重复遍历13M内容。完整LP013矩阵、许可状态和性能资格仍未完成。
