<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# P1 原语成本与 LP023 子集

`measure_license_primitives.py` 和 `LicensePrimitiveCostProbe.java` 只调用当前 P1 生产 JAR 中已经实现的许可快照、时钟及 JWS 验签代码。默认 `--mode plan` 只冻结输入，不启动 Java 测量。没有分类器替身、模拟管理队列、FE/BE 服务或 SQL 请求，也不把这个子集标为 LP023 全部通过。

## 已有实际产物记录

2026-09-24 使用未修改的 `measure_core_cost.py` 完成 3 fork、每项 21 个样本，请求 CPU 0–4 亲和性、Temurin 17.0.4+8、G1/512 MiB heap；当前 `fe/fe-core/target/doris-fe.jar` SHA-256 为 `4281b01d3fea1c2b83145e5e64d9bfd401da6620381cc44fa3a666904881f2f5`。见[原始报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/core-cost-current-jdk1704.json)。旧探针仅记录 taskset 请求，没有保存实际 cpuset；后述新工具补齐实际亲和性核对，这项新保证不能追溯添加到旧记录。

| 真实调用 | 本次中位成本 |
|---|---:|
| `snapshot.queryStatus(long)`，VALID | 5.344 ns/op |
| `clock.trustedNowSeconds()` | 31.755 ns/op |
| `snapshot.queryStatus(clock)`，VALID | 35.706 ns/op |
| `LicenseVerifier.verify`，真实临时签名 | 258.735 µs/op，约 78,488 B/op 分配 |
| `LicenseTrustStore.parse` | 9.955 µs/op |

这是现有小型成本探针的描述性记录，没有预定 512/4096/16384 B 或 1/8/32 线程矩阵，也没有 5 对正式独立窗口，不能作为 LP023 通过。原探针保留不变。

## 新工具覆盖和保留缺项

完整 P1 子集有 42 cells，每个固定窗口对使用同一已冻结输入，但启动独立 JVM：

- 固定时间 snapshot、live-clock snapshot、trusted clock：各使用 512/4096/16384 B 合法证书建快照 ×1/8/32 线程，共 27 cells，保留不同 feature 集合大小的对象布局。另有与证书无关的循环输入对照 1/8/32 线程，共 3 cells。
- 管理验签：真实 signed decoded JSON 512/4096/16384 B × 1/8/32 线程，共 9 cells。每次直接调用生产 verifier，不经过幂等提交或缓存。
- 管理拒绝：签名正确但缺 deployment_id 的 256 B payload × 1/8/32 线程，共 3 cells，必须精确抛出 INVALID_CLAIMS。拒绝数不计成功数。

分类摘要命中/失效与依赖数 1/64/4096、FE 准入、管理排队/提交、完整 FE/BE/RPC 指标仍未由本工具覆盖。`LP023_complete` 和 `release_performance_pass` 永远为 false。只读版本 getter 不被冒充为完整的分类依赖版本比较；trust-store parse 的已有诊断也不冒充证书大小矩阵。

## 计时与统计

正式子集默认每 cell **5 对、10 个独立 JVM 窗口**。每窗至少 1,000,000 次总操作，且每个 worker 必须持续到共同 epoch +60 秒；两个条件同时满足才结束。默认预热至少 15 秒及 10,000 次操作，固定 CPU 0–4、G1/512 MiB heap。Java 在启动/结束读取主线程 `/proc/self/status`，每个 worker 在各 phase 的开始/结束读取 `/proc/thread-self/status` 中实际 `Cpus_allowed_list`；Java 与控制器均要求实际集合等于 0–4。只请求 taskset 不算证据，cpuset 交集缩小也不合格。这里记录的是这些边界的观测，不宣称连续跟踪每次调度。线程数大于可用 CPU 是明确的并发竞争条件，不修改 CPU 绑定以美化结果。

所有测量调用均记录延迟进入完整有界直方图：4096 ns 以下每 ns 精确分桶，以上最多约 0.049% 桶宽；输出每桶上下界和计数，无采样、剔除慢请求或截断超时。分位数采用完整分布的 nearest rank。

延迟的精确边界是 `begin=System.nanoTime()` 到 `lastEnd=System.nanoTime()`：包含中间的 invoke 分派、真实原语、状态断言、checksum 及首次调用的 firstStart 赋值；**不包含** 随后的直方图更新、operations++、循环条件及下一次调用前的调度空隙。吞吐/elapsed ns per operation 使用共同 epoch 到最后一次 invoke 完成，包含调用间这些直方图、循环和调度成本，最后一次调用后的尾部更新则不在该吞吐区间内。进程 CPU 截止采样还覆盖最终直方图、亲和性读取、latch 通知与记录的边界填充；因此延迟与吞吐/CPU 的仪器开销范围不同，不能混为同一端到端口径。输入对照单独记录，**不做噪声相减**。逐操作计时会显著影响几十纳秒的热路径，不能与旧无逐调用计时探针的数字直接混算。

共同 barrier 释放 worker 前记录进程 CPU，最后实际调用完成后记录 CPU；线程保持存活，分配计数读取后才释放清理。原始记录包含 CPU 采样起止、请求 epoch/末次完成及清理时间；Python 重新核对各线程操作数、持续时间、全量直方图和边界。CPU 含该 JVM 的 GC/JIT/测量开销，线程分配来自真实 JVM counters，包含 worker 尾部的亲和性读取等测量开销；RSS 峰值是该进程生命周期峰值，不能冒称只属于测量窗口。

初始 `manifest.json` 冻结计划和源码/JAR/JDK/依赖；编译后另存 `runtime-manifest.json`，包含 classpath 首项 `probe-classes` 中全部 class 的目录清单和实际 SHA-256。每窗开始前、结束后（包括最后一窗）都核对文件摘要及 class 清单，内部 class 修改、删除、新增会遮蔽生产类的 class、未冻结或符号链接目标都不能通过；只有源码 hash 不足以绑定实际执行字节码。

这是闭环原语调用吞吐与成本，不是固定送达 SQL、管理排队或数据库容量。未测得的 `management_queue_wait_ms` 为 null，`client_end_to_end_including_queue_measured` 为 false，不用零值填补。发生错误、超时、输入 hash 漂移或无法清理客户端时保留原始失败并停止，不能据失败推断性能上界。每次编译/Java 子进程都持久化 `<log>.cleanup.json`，包含自身进程组、清理前后退出码、原始错误、TERM/KILL 动作、遗留 PID 及清理异常。超时/信号不绕过回执；清理发生次生异常不会覆盖原始错误，回执写入失败时证据随原异常进入顶层失败报告。只清理本工具启动的进程组，不触碰服务。

窗口结束后一次性计算配对 bootstrap 95% CI，吞吐/每操作 CPU 精度仍为 1%，P95/P99 仍为 2%，至少 5 对；延迟 CI 保留直方图桶和硬件计数量化的不确定性。方向性漂移单独阻断，精度失败不追加窗口直到通过。`P1_subset_precision_met` 仅描述这批有仪器开销的子集，缺少的正式场景和短查询绝对计时分辨能力仍须另外完成。

可通过 `--clock-capability` 提供本机硬件计时能力回执；目前支持实际观察到的 AArch64 `arch_sys_counter`，绑定原始探针输出、真实退出、当前 boot/time namespace/clocksource，并在窗口前后检查环境和文件摘要。不能将 `clock_getres=1ns`、Java 返回纳秒整数或最短观测耗时当成物理分辨率。缺少支持的回执时，统计区间本来达标的延迟会标为 `clock_resolution_unverified`，不会令整个子集精度通过。当前主机实际 counter 为24MHz，一跳约41.67ns；每个窗口延迟桶两侧保守扩展“一跳+1ns整数舍入”，下界不小于零。该系统性量化范围不会随着窗口增加而缩小，约42ns的操作不能靠增加配对证明2%延迟精度。这里仍不宣称界定了时钟频率准确度、调用开销或调度抖动，原始整数直方图和历史报告保持原样。

## 使用和运行预算

先用 `license_payload_fixture.py` 生成并验证证书；每次运行新输出目录。下面默认只生成完整计划：

```bash
python3 -B tools/license-checks/measure_license_primitives.py \
  --mode plan \
  --fixtures .build-records/license-p0-p1-20260924/lp023-payload-fixture \
  --java-home .build-records/license-p1-jdk17.0.4-20260924/jdk-17.0.4+8 \
  --fe-lib output/massdb-sql-2.0.5-rc02-bin-arm64/fe/lib \
  --artifact fe/fe-core/target/doris-fe.jar \
  --output .build-records/license-p0-p1-20260924/lp023-primitive-plan
```

在协调好的空闲窗口，将 `--mode` 改为 `measure` 并使用新的输出目录执行完整 P1 子集。诊断只允许显式 `--mode smoke --smoke-cell license_verification_management,32,16384` 等单一 cell，默认 1 对、0.05 秒/100 次下限；smoke 永远不能建立正式精度。

42 cells ×10 窗×60 秒仅测量下限已为 7 小时，加默认预热为 8.75 小时；单线程验签按已有约 259 µs/op 估算，1M 次至少约 259 秒，三个大档和拒绝路径还会延长，总预算应按 **10 小时以上** 安排，实际取决于大 payload 成本及竞争。每个子进程默认 1800 秒 watchdog，超时留下失败，不悄悄降低操作数。正式测量必须与 SQL 基线错开，不能同时运行。

## 工具验证进度

第一版控制器已通过 [11 项轻量检查](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-primitive-unit.log)；[32 线程/16384 B 真实验签 smoke](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-primitive-smoke-verify32-16k/report.json)完成独立两窗，全部调用进入直方图且 CPU 边界核对通过。该记录绑定当时源码摘要，仍为 insufficient_pairs。

最终版本已通过 [20 项检查](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-primitive-unit-final.log)，覆盖完整 42-cell 声明、全部直方图/CPU 边界、编译 class 漂移、真实子进程超时/SIGTERM 清理及次生清理异常。另以实际 `taskset --cpu-list 0` 运行已编译生产调用探针，确认 [CPU 集合缩小被拒绝](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-primitive-final-affinity-negative.json)，子进程退出 1 且无遗留 PID。

最终代码在 Temurin 17.0.4+8、实际 CPU 0–4 下完成五种各两窗短 smoke：拒绝 1线程/256 B 共 256 次精确 INVALID_CLAIMS（成功计数为零）；live-clock 快照 32线程/512 B；验签 32线程/16384 B；long 快照 8线程/4096 B；trusted clock 1线程/16384 B。各窗编译 class、亲和性、CPU 边界和清理回执核对通过。见[最终证据清单](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-primitive-development.json)。这些记录绑定运行时的原性能契约 SHA `733cdc6fc2d070d77ed9e0091071b998009f687e869924c68f5cec30edd45688`；后续 Flight 原版缺陷例外的契约更新不追溯覆盖原始记录，也不改变这些 smoke 的非性能结论。

2026-09-24 06:43（UTC+8），在单节点和多节点原版功能测试均结束、所有本次测试 FE/BE
停止并核验后，已启动完整 42-cell / 每 cell 10 窗正式 P1 子集测量。
实际参数仍为每窗至少 60 秒且 100 万次、15 秒预热、JDK 17.0.4+8、CPU 0–4、
512 MiB G1 heap，未缩减矩阵。输出目录为 `lp023-primitive-formal-v1/`，
[启动记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-primitive-formal-start.json)
冻结控制器身份、运行 manifest 与窗口数。预计超过 10 小时，运行期间不并行 SQL 基线或其他微基准。
该轮随后确认停止，controller与probe均不存在、旧会话不可查询，退出原因未知。
仅156/420窗有完整确认记录，另1窗只有raw，15个完整组合也包含精度不足/方向性漂移；
见[停止审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-primitive-formal-stopped-audit.json)。
保留原轮次，不重用输出目录或拼接残缺窗口；下一次完整测量仍须新的冻结计划和独立时段。

后续controller补充编译/窗口开始前的`RUNNING`检查点、当前窗口位置、配置摘要和已确认窗口数，
只有子进程清理及独立结果核对均成功才增加确认数，每个组合的精度结果及时落盘。
这些字段仅是最后一次持久化观察，不证明进程当前存活；仍须复核实际进程身份/会话。
无法捕获的强制终止仍可能没有终态回执，不从检查点推断退出原因。旧轮次与旧源码摘要继续保留。
