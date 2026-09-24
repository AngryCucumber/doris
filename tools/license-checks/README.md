<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# 授权发行环境验证

`verify_release.py` 在指定 JDK、OpenSSL 和实际 FE 发行目录上执行离线密码学互通检查。它不启动 FE/BE、不改服务器时间，不读取生产私钥，不安装依赖，也不把临时测试公钥加入产品默认信任集。

```bash
python3 tools/license-checks/verify_release.py \
  --java-home /usr/lib/jvm/jdk-17.0.2 \
  --fe-lib output/massdb-sql-2.0.5-rc02-bin-arm64/fe/lib \
  --openssl /usr/bin/openssl \
  --package output/massdb-sql-2.0.5-rc02-bin-arm64.tar.gz \
  --report .build-records/license-p1-release-20260922/jdk17-source-report.json
```

`--fe-lib` 必须指向真实发行依赖目录，分别只允许一个 Jackson core/databind/annotations JAR。可选 `--package` 进一步确认三个 JAR 与指定 tar 包中对应文件完全一致，并记录整包 SHA-256；验证大包需要扫描压缩包，但不会解压或修改安装目录。

默认模式将所需真实许可源码和小型探针在临时目录用 `javac --release 8` 编译，报告明确标记 `source_with_packaged_dependencies`。这证明源码与该发行依赖和 JDK 的兼容性，不代表尚未包含许可代码的旧 FE 包已经具有许可功能。

构建之后，指定 `--classes-from /absolute/path/to/doris-fe.jar` 或实际编译 classes 目录，并把 `--fe-lib` 指向同次构建的 `fe/fe-core/target/lib`，使用 `built_artifact` 模式验证真实字节码。若使用旧 tar 包证明依赖来源，不能据此声称新许可 JAR 已包含在旧 tar 内。该模式只编译探针，不重新编译或替换目标许可类。报告记录实际加载类的来源、SHA-256 和 class major version；源码哈希只作工作区参考，不冒充与外部 JAR 的源码对应关系。

每次验证包含：

- Java JCA Ed25519 provider、OpenSSL 版本、OS/CPU/JDK 实际信息；要求目标许可类 class major 为 52。
- JCA/OpenSSL 分别生成临时独立许可密钥和时间修复密钥，双方分别签发并交叉验签两种 JWS。
- 原文篡改、错误公钥、普通许可与修复 typ 混用、信任清单 purpose 错置以及错误修复挑战的拒绝。
- 通过发行工具导出信任清单，再由实际 Java 信任清单解析器按用途筛选公钥。
- 对 U+000000 至 U+10FFFF 的每个码点计算标识符、裸展示文本、包裹展示文本的接受位序列 SHA-256，并与 Python 签发工具实际文本校验函数逐一比较。覆盖全部 Unicode scalar，也检查非 scalar 的单独 surrogate 拒绝。
- 临时目录及全部私钥清理；输出 JSON 只包含命令路径、校验结果、哈希和运行环境，无私钥内容。

若某个可选兼容目标只安装了 JRE，可显式追加 `--compiler-java-home /usr/lib/jvm/jdk-17.0.2` 使用该 JDK 编译探针；`--java-home` 始终选择实际被测试的运行时，报告分别记录 javac 与 java 版本。

当前用户提供的运行版本为 JDK 17.0.4，具体供应商与构建号待确认。[精确版本验证记录](/data/project/massdb-sql/tools/license-checks/jdk17.0.4-validation.md)单独列出实际 Temurin 17.0.4+8 的结果；上面的17.0.2命令是历史环境示例，不能替代客户发行环境验证。在 JDK 21 上执行只记录兼容性探针结果；在 ARM64 上通过不代表 x86、其他 JDK 厂商或其他发行 OS 已通过。接口接入、真实 journal/故障切换、查询负载性能和生产发行公钥清单审核需各自提供证据，不能由本工具结果替代。

实际公钥交付使用新增[只读公钥清单验收工具](/data/project/massdb-sql/tools/license-checks/public-trust-review.md)：绑定显式清单摘要、实际 FE JAR/JDK/Jackson，比较 Java/Python 公钥用途和指纹，并按显式旧清单/保留依赖检查轮换。该工具已通过19项Python检查和12项精确17.0.4/实际JAR正负例；生产清单和目标环境仍待提供，验收工具不安装信任根，也不能证明操作者提供的历史依赖已经完整。

## P1 核心成本记录

```bash
python3 tools/license-checks/measure_core_cost.py \
  --java-home /usr/lib/jvm/jdk-17.0.2 \
  --fe-lib fe/fe-core/target/lib \
  --classes-from fe/fe-core/target/doris-fe.jar \
  --report .build-records/license-p1-release-20260922/core-cost-report.json
```

该工具只接受显式构建字节码，使用真实 JDK 17，在 CPU `0-4` 上执行有界的独立 JVM 测量。默认 3 个 JVM fork，每项 4 轮预热、7 个测量样本；正常路径每样本 100 万次，管理操作每样本 200 次，可通过具上限的参数调整。固定 512 MiB/G1，报告保留实际 JVM 参数、目标类和依赖哈希。

被测当前时钟核心已修正“观察前跳后再回拨”和“同 epoch 复制明显超前水位”的异常判定；`queryStatus(LicenseClock)` 使用 epoch 复核，不能把修复前后的时间与异常标志混用。对应行为由独立 JUnit 证明，成本测量只记录执行代价。

测量包括 `queryStatus(long)` 正常/混合状态、`queryStatus(LicenseClock)` 正常状态、可信时间读取、JCA 许可证验签、信任清单解析及循环输入对照。使用运行时创建的 16 组输入、volatile 数据入口、输入扰动和消费校验值，避免把常量表达式或未使用结果当作有效测量。每轮记录实际纳秒、当前线程分配字节和 GC 次数/耗时。

这是简单 harness，不是 JMH，也不是 SQL A/B 测试。接口派发、循环及少量测量开销均包含在原始数据中，不进行基线相减；后台编译、调度、JIT 和频率变化可能影响样本。正常路径的极小分配值可能来自每轮反射计数读取，不代表每次许可判断均分配对象。只把结果标为 `MEASURED`；不得据此把 LP023、P3 或产品端到端性能标为通过。

Connection modes are explicit. `reuse` is the default and retains the original timing/result columns, adds `point_key` (empty for static queries), and keeps the execute/fetch timing boundary: one worker connection is initialized and prepared before the window. `per_request` creates a new authenticated JDBC connection for every scheduled request, executes its session initialization, prepares/binds only that request, fetches the complete result and closes the client connection. All those costs are inside both start/end service time and scheduled/end end-to-end time; raw rows add connection_ns/session_init_ns/prepare_ns/execute_ns/close_ns and summaries report these separately. A prepared query on a new connection must prepare again; it is never labeled prepared-context reuse.

For short connections, zero-warmup smoke tests expose driver/class/JIT/first-connection costs and are intentionally not stable performance evidence. Reuse and per_request results cannot be pooled. Match connection mode and exact tool/JDBC hashes across comparisons; rate diagnostics from the earlier helper retain their original identity and are not interchangeable with later short-connection records.


## 百万键基线与容量校准

点查 workload 可用以下字段替代 `queries`，每次请求都从固定的百万行范围取键。`mode` 可选 `text` 或
`prepared`，后者在复用连接上复用预编译语句，并把逐请求参数绑定计入时间。完整计时/预热键序列在连接建立前生成，
以 big-endian int32 文件和 SHA-256 归档；不同窗使用相同序列，不再只循环100个键。

```json
"point_key_workload": {
  "table": "license_perf.point_rows",
  "mode": "text",
  "seed": 20260922
}
```

CPU起止计数由实际客户端JVM读取 `/proc`，采样与请求使用同一个单调时钟域。双向文件屏障隔开窗口启动、
测量结束和复用连接清理；资源报告保留请求epoch、最后请求、CPU采样padding和cleanup时间。
`coordination_timeout_seconds` 与 `drain_timeout_seconds` 均有上限；缺屏障、请求不结束或CPU边界不完整不能通过。
排队时间仍计入端到端P99，不删慢请求或把排队从结果中减去。

`calibrate_read_capacity.py` 要求事先声明升序 `--rates`、`--p99-slo-ms`、`--max-drain-seconds`，冻结输入和产物身份。
每个速率独立调用基线程序，原始CSV、到达/键序列和资源边界须能复算；报错或缺样不能充当容量上界。
`--mode pilot` 仅用于选择后续正式输入，不会建立容量或通过A/B。
`--mode confirm` 要求原场景规定的预热/窗口时长、至少5对完整窗口和每窗至少10000个成功样本；
只有整个预声明序列完成、无反常顺序且观察上下界距离不大于1%，才标记观察到的SLO容量区间。
返回的30%/60%/85%速率是该下界的候选测试输入；该区间不是理论极限，也不替代A/A检测精度或候选B的性能验收。
改变并发、连接模式、JDK、数据、负载或测量程序后需单独记录，不能合并旧结果。

测试安装由 `isolated_baseline_cluster.py` 建立在checkout的独立网络namespace内；显式使用对应namespace的
`nsenter` 调用程序。只允许连接明确记录的checkout测试服务，不改变宿主时间、全局JDK或内核参数。
`--be-memory-mib` 显式记录BE进程内存限额（默认2048，允许1024–65536）；调整时必须新建安装和独立基线，
不得拼接不同资源配置的结果。实际内存/缓存/审计健康仍需运行时验证，配置额度本身不表示负载足额。
容量报告的≤1%观察括区只表示速率网格宽度，不能当作95%容量置信区间。

点查客户端在所有连接建立前，按实测和预热的完整键序列预计算 `MD5(ASCII decimal id)` 的小写字符串期望值。
每个请求读取 payload 后，在同一计时边界内核对单列、非空 String、内容及行数；值不符记录 `-3/VALUE`，
不能计入成功吞吐。`point-result-oracle.json` 记录算法、唯一预计算键数和边界，容量工具独立重算键覆盖。
静态查询向量仍只按原配置核对行数，不能据此声称任意查询都做了内容 oracle。
早期仅核对行数的诊断结果保留为历史记录，不追加新保证；新旧客户端哈希不同，正式测量须重新冻结工具版本。
Stream Load 输入与可见性验证见 [fixture说明](/data/project/massdb-sql/tools/license-checks/stream-load-fixture.md)。
完整千万行的固定到达窗口见 [持续 Stream Load 工具](/data/project/massdb-sql/tools/license-checks/stream-load-baseline.md)；
最新55项源码绑定检查通过。实际v2预热因测试队列满失败，原始失败保留；队列模型修复后的v3完成
180秒预热、600秒测量、独立10M内容校验及清理。完整矩阵与性能精度仍待验，
见[实施记录](/data/project/massdb-sql/docs/license-implementation-progress-20260922.md)。

元数据与原权限基线见 [LP005说明](/data/project/massdb-sql/tools/license-checks/metadata-fixture.md)；外部读取输入准备见 [LP008说明](/data/project/massdb-sql/tools/license-checks/parquet-fixture.md)。两者分别记录功能前提和未完成的完整性能场景。

LP008真实schema探测、外部SELECT及INSERT SELECT使用[私有S3 fixture](/data/project/massdb-sql/tools/license-checks/s3-readonly-fixture.md)，返回真实Parquet字节并记录阶段外发；不实现生产AWS认证，也不将原版可达性标为许可拦截或性能通过。

LP014的[Group Commit fixture](/data/project/massdb-sql/tools/license-checks/group-commit-fixture.md)验证四档批量、full-prepare开关、同语句重复执行的实际回执与独立可见性；保留准备、ACK、轮询可见上界和完整数据模型，工具不将批次功能验证标为持续性能通过。

LP010的[Flight fixture](/data/project/massdb-sql/tools/license-checks/flight-fixture.md)逐行校验百万行和三档批次的新建/复用连接矩阵；当前65535档存在原版结果不一致，完整用例不能通过。
[资源观察工具](/data/project/massdb-sql/tools/license-checks/resource-observer.md)记录已有进程/网络/GC指标，并明确采样开销和归因边界。可选增量采集原有部分RPC计数和已有GC日志，56项离线检查通过；缺失计数不补零，GC事件尚不能完整归入业务窗口，也不能替代总分配或完整网络统计。
LP023的[精确载荷fixture](/data/project/massdb-sql/tools/license-checks/license-payload-fixture.md)区分合法512/4096/16384字节与256字节拒绝负例。

LP015的[DML/事务fixture](/data/project/massdb-sql/tools/license-checks/dml-transaction-fixture.md)核对同会话提交/回滚、独立连接可见性及原版不支持边界。
P1的[原语矩阵工具](/data/project/massdb-sql/tools/license-checks/license-primitive-cost.md)默认仅生成计划；已实现原语、诊断smoke、完整精度和缺失的P3分类器严格分开记录。

LP009使用[私有3FE/4BE集群](/data/project/massdb-sql/tools/license-checks/multinode-baseline-cluster.md)和[千万行三档分桶fixture](/data/project/massdb-sql/tools/license-checks/fanout-fixture.md)，分别核对真实成员与真实运行时扫描分布；同机功能记录不能替代正式多机性能。
LP013的[真实Kafka fixture](/data/project/massdb-sql/tools/license-checks/kafka-routine-fixture.md)固定发行包和8分区，独立核对生产确认、原始消费内容与Routine Load可见性；真实3.9.2 broker的100k功能子集、独立消费/数据库模型和清理已通过，未证明8个同时执行的BE任务。
[完整持续窗口工具](/data/project/massdb-sql/tools/license-checks/kafka-routine-baseline.md)另通过39项新检查、20项原有Python检查和17项Java自检；已完成180秒3M预热、600秒10M测量、13M生产/独立消费字节与SQL模型核对及清理。配置8个生产客户端，实测批请求重叠峰值1；该功能窗口不代表完整并发/批次矩阵或A/A精度通过。
LP026的[后台与HTTP工具说明](/data/project/massdb-sql/tools/license-checks/background-http-fixture.md)固定实际入口与内容模型。自然字典刷新、MV、自动统计、ES和CSV的原版功能前提已分轮观察；Parquet内容正确但原FE未关闭reader，原FAIL及用户接受的缺陷记录保留，不能将分轮结果合成完整LP026通过。
LP021/022的[原版浏览器工具说明](/data/project/massdb-sql/tools/license-checks/ui-baseline-fixture.md)记录规定18格导航、权限、完整结果及注销已观察通过；原报告6 PASS、12 PARTIAL保留，后者是额外新窗口结果深链的history.state限制。[并发窗口工具](/data/project/massdb-sql/tools/license-checks/ui-concurrent-fixture.md)两轮均完成1/10上下文的两个300秒窗口：v1第3格为背景编译退出观察失败，v2第3格为准备中RSS超过原6GiB；两轮各51格未执行，原始失败和清理回执保留。新工具固定四路准备，全部context保留并在ready后同时执行原300秒/10秒动作；新增实际created/ready回执和同次RSS超限分解，35项Python、21项Node离线检查通过。修复后真实54/108窗及性能矩阵仍待验证；失败后停止先完成当窗记录与清理，保留完整计划及未执行项。
LP006/007的[并发驱动与独立复杂查询核对](/data/project/massdb-sql/tools/license-checks/complex-planning-oracle.md)绑定冻结SQL、全部33列结果、Profile和EXPLAIN。修复原EXPLAIN语法及正常缓存Profile的EOF判定后，22项oracle和24项controller检查通过；新实际窗口完成365次预热、1175次测量及161份Profile的独立核对和清理。实测目标SQL并发峰值2、DDL重叠样本0，测量样本少于正式10000门槛；完整矩阵和性能精度仍待验。

LP026补充全生命周期资源、输出上限和取消清理；UI工具补充显式持续读写背景、完整百万行源模型及逐批写入可见性核对。
上述离线检查见[本轮工具验证目录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924)，不替代真实功能与性能验收。


## GC 记录时间映射

[gc-window-mapping.md](gc-window-mapping.md)说明纯解析/半开窗口映射模块。28项离线检查通过；
它核对真实时钟域、FE及日志绑定、confirmed prefix和drain分类，不将日志记录时间当STW边界。
当前observer/FE配置未接线，旧日志不会被补造单调时间；真实GC事件映射与同配置A/A开销仍待验证。
