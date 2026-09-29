<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# A-only Flight / scanner / external read 容量调度

`p4_protocol_capacity.py` 直接调用已有 `flight_performance.run_window/normalize`
或 `external_scanner_performance.run_window/normalize`、`external_read_performance.run_window/normalize`，并启动、等待和回收每窗自己的
`resource_observer.py`。它不启动、停止或修改 FE/BE，不准备数据库 fixture，不编译
Java，不发 B 请求。Root 必须先独占实验环境，提供原版 A、已编译且来源一致的 runtime、
真实数据和稳定的环境/配置/fixture/client 身份文件。

当前可执行的范围是 G2 Flight 与 G3 `_query_plan` + 原 BE scanner，均保留
batch 1024/8192、并发 1/8 的独立子项，每次成功操作是一整个百万行查询。
另有 G2 catalog / S3 TVF 的四列完整百万行流式 JDBC 读取，复用连接、并发 1/8。
65535 原版失败保持不变。HTTP、DML、复杂 SQL、其他 G2/G3 出口尚未接入此容量调度；
输入这些协议会明确拒绝，不能因为本工具测试通过就算它们已完成。

## 阶段与门槛

| 输入模式 | 可接受的 profile | 窗口数 | 结果用途 |
| --- | --- | --- | --- |
| `pilot` | 可用显式 `diagnostic` 短窗，或完整 `formal` 窗 | 每档按输入 pairs，至少 1 对 | 全部实际操作仍须完整 oracle、CPU/资源和关闭回执；只能得到 `PILOT_COMPLETE_NOT_QUALIFIED` 或 `INCONCLUSIVE` |
| `confirm` | 必须 `formal`，预热至少 180 秒、计时至少 600 秒，按固定到达序列至少 10,000 次完整成功操作 | 每档至少 5 对、每对 2 个各自预热的独立 A 窗 | 按预冻结 P99/drain SLO，取得单调的通过/超界档，括区宽度不超过下界的 1% |

速率、SLO、样本计划、pair 数、顺序、环境身份及采样/资源限制全部在第一窗前落盘。
先运行每个升序速率的所有 pair；每一窗独立启动并实际等待自己的协议 helper，逐窗留档。
不把一段长窗切片为多个独立窗口，不复用上一窗原始记录。不完整、错误、超时、
漏样、清理失败、观测缺失均是无效试档，立即结束 sweep，不能充当容量上界。
完整且无错误、但 P99 或实际 backlog 超过 SLO 的档才是 `outside_slo`。

容量通过只表示该原版 A 环境和既定 SLO 下的已观测 offered-rate 括区。
后续 30%/85% R 的独立 A/A、95% bootstrap、CPU/成功吞吐 1%、P95/P99 2%
精度及发布后 A/B 门槛仍使用 `p4_statistics.py`，没有在本工具中放宽或宣称通过。
容量确认的 pair 不替代这些不同速率的 A/A 证据。

## 实际输入

所有引用均为 `{"path":"绝对路径","sha256":"实际文件SHA256"}`。输入不包含密码，
只使用原协议的环境变量名。`context_template` 是实际协议 context 的稳定部分，字段恰为：

```text
identity, bindings, services, service_configs, endpoints,
max_clock_uncertainty_ns, coordination_seconds
```

scanner 另有 `host_namespace`；external_read 另有 `host_namespace`、`external_source`、`private_query`。
后两项均为原外部读取协议的实际文件引用，私有 SQL 必须是原 0600 文件，容量 spec 不内联 SQL/凭据。
不保存 `phase`、`variant`、`window_id`、`pair_id`、
`workload`、runtime 或任何旧 launch/clock/freeze 字段；工具每窗重新产生这些值。
`identity` 的七项和 `bindings` 的精确字段集沿用该协议的真实规范。不要把旧 smoke
中注明 diagnostic、含每窗时间/路径的环境或 client 文件直接当作稳定的正式身份。
Root 应先生成一次实际正式环境、配置、数据和客户端文件，再把其摘要写入 context。

下面是短 pilot 的字段示意，数字是示例，必须在只观察 A 的阶段确定实际 SLO/预算。
`profile_template` 文件沿用该协议完整 schema；例如 Flight 的诊断 profile 可用
warmup 8、duration 12、rate 1、batch 1024、concurrency 1、seed 20260922。
scanner 还须声明已有原始 ledger/private-plan 大小界限。

```json
{
  "schema_version": 1,
  "run_id": "original-a-flight-b1024-c1-pilot1",
  "protocol": "flight",
  "mode": "pilot",
  "cell_id": "G2-flight-b1024-c1",
  "rates": [1, 1.005],
  "pairs": 1,
  "slo": {"p99_ms": 2000, "max_drain_seconds": 1, "max_error_rate": 0, "max_timeout_rate": 0},
  "profile_template": {"path": "/ABS/profile.json", "sha256": "ACTUAL_SHA256"},
  "context_template": {"path": "/ABS/context-template.json", "sha256": "ACTUAL_SHA256"},
  "runtime": {"path": "/ABS/runtime.json", "sha256": "ACTUAL_SHA256"},
  "deadline_seconds": 2400,
  "observer": {
    "cluster_record": {"path": "/ABS/cluster.json", "sha256": "ACTUAL_SHA256"},
    "client_cpus": [0, 1, 2, 3], "server_cpus": [6, 7, 8, 9],
    "interval_seconds": 1, "http_timeout_seconds": 1, "max_gap_seconds": 3,
    "start_timeout_seconds": 15, "finish_timeout_seconds": 15,
    "client_sample_seconds": 0.5, "client_max_gap_seconds": 2,
    "max_samples": 102001, "max_log_bytes": 1073741824,
    "min_free_disk_bytes": 1073741824,
    "rss_limits_bytes": {"fe": 4294967296, "be": 4294967296, "observer": 536870912, "client": 3758096384}
  }
}
```

`profile_template` 是带实际 rate 的完整协议 profile；每档只替换 rate，其他业务字段
保持一致。正式确认时将 mode 改成 confirm、pairs 至少 5，提供新的 formal profile，
并延长 duration，直到 **每档** 实际生成的到达数至少 10,000。`plan` 会输出准确计划数、
到达摘要和总计时下限；绝不把百万行或 Arrow batch 数当成查询数。

## 调用和接入

external_read 在容量 spec 中使用 `"protocol":"external_read"`，profile 的 `source_kind`
分别为 `catalog` 或 `s3_tvf`；两类分开建 spec。原 runtime 完整绑定四个 JAR、JDK、class、源码；
原 source 描述绑定原生数据、可达性、四列 JDBC metadata、实际 PG/MinIO 进程及资源。
不以历史 aggregate/metadata 预检代替计时内每个百万行操作的完整 oracle。

该分支还必须提供 `arrival_schedules`，顺序与 rates 完全相同，均为提前生成的实际 Java
计划 completion 引用。先用下列独立 schedule 输入（只有文件引用与数值）生成：

```json
{
  "runtime": {"path": "/ABS/runtime.json", "sha256": "ACTUAL_SHA256"},
  "profile_template": {"path": "/ABS/profile.json", "sha256": "ACTUAL_SHA256"},
  "rates": [0.5, 0.504],
  "timeout_seconds": 60
}
```

```bash
taskset -c 4 python3 -B tools/license-checks/p4_protocol_capacity.py schedule \
  --input /ABS/schedule-input.json --output /ABS/new-java-plans
```

**只有显式 `schedule` 会运行原 Java 的 `--plan PROFILE_JSON OUTPUT_DIR`，它不编译、不构造
数据库客户端、不读私有 SQL、不访问网络。** 将其 report.json 的 `arrival_schedules` 原样放入
容量 spec。每档保存 profile/runtime、实际 command/pin、父进程 wait、两份 TSV、plan-only
元数据；失败仍保存 completion，不能升级为有效计划。`plan` 本身依旧只读文件，不启动 JVM。
后续 freeze 绑定实际 Java TSV SHA；Python 序列仅独立检查逐偏移差值不超过 1ns。
每窗实际生成的 warmup/measurement TSV 必须与预声明文件逐字相同，任何差异使整档 INVALID；
现冻结的原读取 helper 不增加计时钩子，复核在完整单窗结束后执行。此 A-only 容量接口不接受 AB。

external_read 资源仍由同一 observer/controller 采集，追加的仅是现有 PG/MinIO 来源进程和整个
容器 cgroup：CPU5 与 client/server 不交叉、512MiB 上限、swap 0、单 CPU quota、实际 RSS、
memory.current/peak、OOM kill 与 CPU 计数器。PG 子进程计入 cgroup。源码绑定的同一 auditor
重读每条原始数据，核首尾覆盖、间隔、启动代次、计数器未重置/预算未漂移；资源缺失/超限
不能成为 SLO 容量上界。来源部署与数据准备仍由 root 负责；工具不启停外部服务。

先纯文件检查，不启动 compiler、client、observer 或网络请求：

```bash
taskset -c 4 python3 -B tools/license-checks/p4_protocol_capacity.py plan \
  --input /ABS/capacity-input.json --output /ABS/capacity-plan.json
```

Root 独占原 A 后进入已有 FE 的私有网络 namespace，以预声明 client CPUs 执行。
`FE_PID` 和路径必须来自该轮实际 ownership 记录，下面命令不会代为启停服务：

```bash
MASSDB_BASELINE_PASSWORD= nsenter --target FE_PID --net taskset -c 0-3 \
  python3 -B /data/project/massdb-sql/tools/license-checks/p4_protocol_capacity.py run \
  --input /ABS/capacity-input.json --output /ABS/new-capacity-output
```

也可由已进入正确 namespace 的 root controller 直接调用
`run(read_json(spec_path), new_output_directory)`；无需另外实现 adapter。
runtime 必须事先用现有对应协议的 `compile_helper` 构建。
工具检查实际 PID/启动代次、namespace/CPU、FE 实际 CLASSPATH 与 JAR、BE 可执行文件、
配置 slot，以及原 A JAR 没有授权实现类。所有业务的完整结果再次由原协议 normalizer 核对。
SQL/HTTP/Flight 的实际访问只发生在显式 `run`。

每窗内置 adapter 先取得至少两个完整 observer 样本和一个 client RSS 样本，再调用
原协议 `run_window`。后者保留原 JVM 时钟、CPU、文件握手、请求/关闭及 actual wait
语义。helper 实际等待后，adapter 再取得 FE/BE 与 client 的尾部样本，SIGTERM 自己的
observer 并实际 wait143。检查整个保守映射区间的首尾/间隔、真实服务归属、资源上限和
原 A 状态；JVM 端到端延迟和 CPU 时长仍以同 JVM 原始差值计算。
helper 自然结束的 Z/X 状态只表示退出已被观察，不能替代后续实际 wait。

SIGINT、SIGTERM、SIGHUP 通过安全 checkpoint 转成 own-client stop，运行目录的 `stop`
文件也可由 root 创建以终止剩余调度和当前协议 client。绑定变化、超时或审核失败后仍
回收自己的 observer/client；不向 FE/BE 发 stop。每窗的 `capacity-launch.json` 和实际
protocol `window_id` 都绑定第一窗前已发布的两个完整 freeze/publication SHA，不能在
测完后只修改报告的 SLO 或确认模式。

完整报告保存为 `report.json`；按原容量 schema 提供 frozen_inputs、trials、bracket、
逐档 artifact-audit 和全部原始引用，可直接传给 `p4_statistics.capacity_evidence`。
该函数拒绝 pilot。完成 pilot 的 CLI 可 exit0，但状态始终是
`PILOT_COMPLETE_NOT_QUALIFIED`，没有容量或性能通过含义。

```bash
taskset -c 4 python3 -B tools/license-checks/p4_protocol_capacity.py verify \
  --input /ABS/new-capacity-output/report.json --output /ABS/capacity-recheck.json
```

`verify` 从原 spec 重建派生计划，重读 observer 原记录，再调用原协议 normalize，
不访问数据库。源文件/依赖/原始记录变化、独立性或时钟域不成立时拒绝。

## 长窗观测与边界

原 `resource_observer.py` 默认仍最多 14,400 秒。本 adapter 显式使用
`--p4-long-window --max-samples N --max-log-bytes N --min-free-disk-bytes N`，
最多 102,000 秒：7200 预热 + 86400 计时 + 2×3600 drain + 480 原 runner 余量 + 720 首尾余量。
计划超过这个已有 helper/新 observer 的界限会拒绝，不能缩短正式要求来通过。

样本上限最多 102001，总原始样本日志最多 8 GiB；每条最大 8 MiB，磁盘终态回执 reserve
至少 1 MiB。每次采集前检查完整记录空间和磁盘余量，资源不足写
`FAILED_RESOURCE_BOUND`，保留此前完整记录。未知超大单条记录明确记未归档并使窗口失败，
不截断内容或生成通过。所有采样率和预算都固定于 A-only 输入；不能在看 B 后放宽。

RSS 是有间隔的真实样本，不能证明连续内存峰值；累积 GC/IO/namespace 网络指标保持
现有含义，不补造全分配量、全部 RPC 线速字节或独立进程网络归属。容量通过也不替代
P4 对这些指标和独立 A/A 精度的最终验收。
