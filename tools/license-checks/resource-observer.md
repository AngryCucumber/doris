<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# 原版 FE/BE 只读资源时序观察

`resource_observer.py` 是独立观察工具，不更改 JDBC runner、容量 controller、用例契约或服务配置。
它读取 `/proc` 和现有 FE/BE `/metrics`，默认每 5 秒采样；有限时长结束或 SIGINT/SIGTERM 后写入最终记录并退出。
**监测有开销**：HTTP 请求、计数刷新、解析、文件读取和归档均消耗资源。正式 A/A 与 A/B 必须使用相同采样计划、
CPU 绑定及指标集合；一个成功时序 smoke 不能证明统计精度或“没有性能影响”。

## 数据边界

- FE/BE PID 来自已验证归属的私有 checkout 安装。启动时固定 `/proc/<pid>/stat` 的 `start_ticks`；每个样本请求前后
  再检查 PID 和 network namespace。PID 重用、重启、退出或 namespace 改变会停止采样，并丢弃可能跨进程生命周期的数据。
- 每进程保留 user/system CPU ticks、CPU 秒、RSS、虚拟内存、线程数，以及 `VmRSS/VmHWM/VmSwap`。
  `/proc/<pid>/io` 只保留 rchar/wchar、syscr/syscw、read_bytes/write_bytes/cancelled_write_bytes。
  字符计数不等于物理磁盘流量，采样也不是跨来源原子快照。
- `/proc/net/dev` 属于整个当前 namespace，包含 FE、BE、客户端和观察者流量，**不能归因给某一个进程**。
  每接口保留 RX、TX 字节/包/错误/丢弃的独立值。loopback 同一数据会同时出现在 RX 和 TX 中；工具不计算 RX+TX 总流量。
- FE 只选取 4 个 G1 GC count/time、3 个 heap、2 个 non-heap 指标。BE 只选取 4 个嵌入 JVM 的 G1 GC 指标及
  12 个原生 jemalloc 内存/页计数。完整白名单和单位写入 summary，不保存其他 metric、label 或原始响应正文。
  GC time 是累计 collection time（毫秒），不是单次 pause 直方图；BE 本身是原生 C++，BE JVM GC 字段只描述嵌入 JVM。

当前白名单对应本分支实际 G1 指标（FE `Generation`、BE `generation` 大小写不同）。切换收集器、版本或指标名称后，
应审查并显式更新白名单；缺项、重复、NaN/Inf、负值或格式错误记录为错误，不能补成 0 或默认为通过。
同名指标携带非白名单 label（如表名）也会被忽略，不进入归档。响应中被忽略的 series 只记录数量。

## 安全和时序约束

只允许在记录的私有 network namespace 中运行；`validate_cluster` 检查实际 FE/BE PID、进程安装路径和 namespace。
FE HTTP 端口必须等于配置中唯一的显式 `http_port`，BE HTTP 端口取自同一 owned 安装的配置。
HTTPConnection 直接连接 `127.0.0.1` 的这两个端口，只 GET `/metrics`，不使用代理、不跟随重定向、不发送 SQL。
每个端点默认 2 秒绝对截止，响应最多 2 MiB；连接在成功/失败路径均关闭，错误只归档类型、范围和耗时。

时长参数必须在 `(0,14400]` 秒内，间隔在 `[1,60]` 秒内。样本包含 UTC 开始/结束、单调时钟开始/结束、耗时和错误。
样本按固定单调时钟计划调度；慢采样导致错过时隙时记录跳过数量，不积攒后补请求。20 秒、5 秒间隔正常产生
0/5/10/15/20 秒五个样本，末次采样完成时间可以略晚于 20 秒。SIGINT/SIGTERM 只标记停止并打断等待，
在有界请求返回后关闭文件、恢复原信号处理并写 summary；不向 FE/BE 发送信号。

## 运行

每次必须使用全新输出目录，监督 PID 和 cluster.json 来自当前健康的 owned 安装。以下为本次 20 秒 smoke 命令：

```bash
nsenter -t 2778998 -n -- taskset -c 0 python3 tools/license-checks/resource_observer.py \
  --cluster-record .build-records/license-p0-p1-20260924/baseline-jdk1704-be4g/cluster.json \
  --output .build-records/license-p0-p1-20260924/resource-observer-smoke20s \
  --duration-seconds 20
```

`samples.jsonl` 逐样本刷新；`summary.json` 记录固定 PID/start_ticks、端口/namespace、指标白名单、源文件摘要、
CPU 绑定、计划、样本数/错误/跳过、信号、观察者 CPU/峰值 RSS 及 samples SHA-256。
`statistical_precision_proven`、`performance_pass_proven` 始终为 false。采样完成、含错误完成和被信号中断分别记录；
被中断的输出不能当完整计划通过。

离线测试命令：

```bash
python3 -m unittest discover -s tools/license-checks -p test_resource_observer.py -v
```

测试不请求 FE/BE，覆盖 proc 字段定位、网络边界、敏感 label 过滤、严格 metric 解析、代理/重定向/限流读取边界、
PID/namespace 改变前后拒绝错归属、错误端口、固定调度超期跳过、错误终记录，以及向自有离线子进程发送真实 SIGINT/SIGTERM。

## 2026-09-24 实际验证

[离线记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/resource-observer-tests/report.json)：
22/22 测试通过，原始 unittest 输出另存 `unittest.log`，没有 FE/BE 请求。

[真实 20 秒 summary](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/resource-observer-smoke20s/summary.json)：
在 `baseline-jdk1704-be4g` 的 FE PID 2779642 / start_ticks 17208959 与 BE PID 2780636 / start_ticks 17208989 上
产生 5 个样本，0 错误、0 跳过，进程身份始终一致。实际持续 20.0176 秒，样本耗时 10.28–18.40 ms；
每次 FE 返回 9 个白名单 series、BE 返回 16 个。共 10 次已有 `/metrics` GET，程序完成后退出，没有新增后台服务。
观察者自身 CPU 增量为 0.02494 秒；这**不包含 FE/BE 为监测请求付出的全部成本**，不能拿来承诺正式性能零影响。
summary 中 `ru_maxrss` 是该进程的累计高水位，不能当本次采样的增量或稳态内存成本。

summary SHA-256：`4506508385a39a349c1ca3eda4ed5d9c19ce7096aed40188d425569059f41f90`；
samples SHA-256：`25f502a016b8c02f7c94462e281628963b5a8dd79727242bc341cf1c8585b8df`。
实测 observer 源码 SHA-256：`bf070b79e9378680c0a040e929ac6f4cd905dfa5822583aed08edd1614456295`。
Python 语法编译、源文件头检查及 `git diff --check` 通过。统计精度和性能通过字段继续为 false。

## 显式增加部分 RPC 与现有 GC 日志事件

新增 `--rpc-selection <owned-json>`、`--gc-pauses` 两个独立选项，默认关闭。原 CLI 和
`collect_sample(state,pins,timeout,stop)` 等旧调用保持原返回与 FE9/BE16 白名单；Stream 等已有调用方不会自动
启用扩展。本版只改 observer、其测试和本说明，没有修改 shared guard/support、调用方或产品。

启用任一选项时摘要为 schema2，base series 不变，扩展分别放在
`processes.fe.metrics.extensions.scoped_rpc`、样本 `extensions.gc_cursor_receipt` 与最终 `extension_summary`。
GC 事件另存 `gc-pauses.jsonl`。新字段完整不代表全部 P0/P1 资源要求已经满足；全服务成本精度和性能通过字段仍为 false。

RPC 选择文件必须是本 checkout `.build-records` 内已有、至多64KiB、无重复键的 JSON，例如：

```json
{
  "schema_version": 1,
  "be_hostnames": ["127.0.0.1"],
  "thrift_methods": ["finishTask", "loadTxnBegin", "loadTxnCommit", "report", "reportExecStatus", "streamLoadPut"]
}
```

两个列表必须排序、唯一、非空。首版 hostname 仅支持原单 FE/BE 的 `127.0.0.1`；方法必须来自当前
`FrontendService.thrift` 的68个静态方法名，不能根据响应添加任意标签。文件摘要在开始、每次采样、结束核对，
选择项及语义写入摘要。RPC 从同一次 FE `/metrics` 响应解析，没有第二个请求；BE 选择不变。

- `doris_fe_query_rpc_total` 是发送 fragment prepare/execute 前的**尝试数**；`query_rpc_size` 是 protobuf
  request 序列化字节。计入发送前失败，排除 phase2/start、cancel/cache/fetch、响应、协议头与重传。
- `doris_fe_thrift_rpc_total` 是 FE FrontendService handler 调用数，包括抛错的handler。
  `thrift_rpc_latency_ms` 是 wall-clock 耗时累加，可能因时钟变化下降；不是延迟直方图，也没有对应字节计数。
- lazy series 缺失不补0；中途出现没有起始baseline则delta为null。已出现后消失、计数回退、负latency保留明确错误。
  有效差分带两端非原子 scrape 时段，范围仅为 `observed_scrape_interval`；不插值为精确业务窗口。
  `scoped_rpc_delta_complete` 与 `all_rpc_coverage=false` 分开，绝不能将部分字段称为全部RPC或wire流量。

`--gc-pauses` 仅读已经启用的原 FE 日志。工具核对 FE PID/start/exe/namespace 和 cmdline摘要，从唯一实际
`-Xlog:gc*,classhisto*=trace:...:time,uptime:filecount=10,filesize=50M` 参数定位 owned FE log 文件族。
不接受任意路径、不选“最新日志”，不打开符号链接/FIFO/设备，不启动 JVM/JFR、不重配日志或主动GC。

reader 从当前已记录EOF起读，保留起始半行；按 dev/inode/generation/offset 保管旧轮转文件，记录字节区间摘要。
只解析完整顶层 `GC(n) Pause ... N.NNNms` 结束行；同一个GC ID的Remark/Cleanup是不同事件。
不记录任意class histogram或未知日志正文。事件保存原wall/uptime/duration、整数纳秒、源行位置和摘要。
本版不证明 JVM uptime 到业务单调窗口的误差界，故 `window_assignment=unmapped`，不硬配业务窗口。

`observed_retained_prefix_continuity` 只描述已观察前缀：普通轮询可能看不到两轮间的完整覆盖轮转、same-inode
truncate/regrow，因此 `all_jvm_gc_pauses_proven=false`、`window_mapping_complete=false` 始终保留。
已检测截断、未知轮转代次、非法Pause行、限额、取消或读/写失败不会静默丢弃后声称完整。停止时冻结有限文件size
前缀，不追着后续追加数据无限读取；半行使 `tail_complete=false`。

`read_offset` 与 `event_archive_confirmed_offset` 分开。解析/写入/flush失败时，最终cursor保留
`unconfirmed_read_range`，不得将推进的读取位置称为已确认归档；`events` 与 `events_flushed_confirmed` 也分开。
文件关闭、终记录和摘要计算相互独立，首错保留。失败、半行或未知轮转使扩展不完整；本地关闭成功不抹掉原错误。

GC固定预算：允许current加10个轮转名字；至多12个已保管日志FD，加目录FD、临时扫描FD及scandir内部副本、事件流，
**GC子系统瞬时至多16个FD**（不含原sample输出/HTTP连接；扫描结束后的临时候选FD不与scandir副本叠加）。
每轮读取1MiB、64KiB块、64KiB行、4KiB事件行，
整个观察读取256MiB、事件归档64MiB、100,000事件。每轮250ms合作式截止，终读/摘要1秒预算；本地内核阻塞I/O
没有硬实时保证，超时/未关闭仍按失败记录。新预算不降低原响应2MiB、端点绝对截止或取消规则。

成本回执增加 RPC parse 耗时、GC read/parse/archive耗时、字节与事件数、实际HTTP collector调用次数及成功解析数，
以及包含prepare/finally的observer自身CPU。collector调用数不是已经传输的包数。自身CPU与`ru_maxrss`不足以证明
FE生成metrics的全部费用；原metrics每次还会执行线程枚举等工作。真实扩展smoke仍待独占环境安排，不能沿用上节旧版
20秒回执声称本扩展实测通过。

修改 observer SHA 会使已有 Stream frozen plan 校验不匹配，即使其默认行为保持兼容。后续必须新plan/新目录，
保留旧plan/report；其他工具若以后显式集成也需另行冻结观察日程。全量RPC、FE总分配、进程级网络和精确窗口GC覆盖
仍列为缺口。只有正式同负载独立对照才能检验全服务1%/2%精度；smoke只记录真实成本与不足。

新增离线验证的原始失败与修复后回执存放在
[resource-observer-increment-v1](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/resource-observer-increment-v1)。
包括原接口兼容、真实原版RPC字面值、68方法完整对账、迟出现/消失/回退、同GCID多暂停、三块拆行、轮转、截断、
半行、有限终读、FD关闭、写入/flush错误、绝对截止及归档确认位置的反例；没有请求FE/BE或启动JVM。

本增量离线终轮56/56通过（原22项加34项，CPU0，RuntimeWarning/ResourceWarning提升错误，日志无警告）；
首轮49项的两项轮转失败及修复过程保留，根因是复用目录FD使`scandir`共享读取游标，现每轮使用独立目录描述。
另对存档35条真实GC Pause逐项核对duration/uptime/GC ID全部一致；原FE完整metrics存档按68方法选择得到
138个候选、14个实际存在、124个null缺失，未补0。它们是**存档离线解析**，不是本增量的真实collector运行或新暂停分布。
scrape后若目标身份改变，目标metrics全部废弃，但observer已经发起的调用计数独立保留，不能因此把实际观察成本抹成0。
