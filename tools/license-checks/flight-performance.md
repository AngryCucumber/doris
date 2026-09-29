# G2 Flight 单窗证据工具

`flight_performance.py` / `LicenseFlightPerformance.java` 只运行一个实际窗口。它们不启动服务、不导入证书、不自动选择容量或宣称 A/A、A/B 性能通过。保留 G2 的 `LP-010`、批次参数 1024/8192、并发 1/8、FE/BE channel 复用；原 fixture 及 65535 的原版失败记录保持不变。

Java 通过本项目私有类的反射接口调用**原封不动**的 `LicenseFlightFixture.Session.read/close`，同时冻结、编译该 fixture 源码和类文件。每个 worker 建一个 Session；warmup 和 measurement 使用同一 Session。每次 read 都在原方法中执行 FE `FlightSqlClient.execute`，取得新 ticket 后读取 BE 的完整流。原实现逐行验证 id 顺序、非空、MD5 payload、百万行完整 SHA256；新层再要求精确的 `Int64/Utf8` schema、单 worker 的 channel 复用、跨两阶段 ticket 摘要不重复。每次成功 read 返回即证明原 try-with-resources stream close 已完成。异常和关闭失败保留在原始回执中，不能成为成功窗口。

一次读取**完整 1,000,000 行**才是一个业务操作。Arrow batch、行数、BE endpoint 数量不计为 P99 样本数。实际 record batch 行数全部记录，不把请求的 `batch_size` 当作实际分块大小。逐行 oracle 的成本包含在服务时间及端到端延迟里。端到端延迟从预定到达时刻计算，包含排队；另行提供 service/queue P95/P99。保持 FE execute 90 秒、BE stream 90 秒的两个 RPC 超时，不能把它们解释为整操作总计 90 秒；原 SQL 的 query_timeout 是 60 秒。外层绝对截止时间控制整个自有客户端，排空期限后未发出的请求明确记为失败，不重试。

## 最小 profile

```json
{
  "schema_version": 1,
  "profile": "g2_flight_v1",
  "qualification": "diagnostic",
  "seed": 20260922,
  "batch_size": 1024,
  "concurrency": 1,
  "rate": 5.5,
  "warmup_seconds": 2,
  "duration_seconds": 4,
  "drain_seconds": 30,
  "max_requests": 1000
}
```

`qualification=formal` 必须 warmup≥180 秒、measurement≥600 秒，而且实际生成的 measurement 到达数≥10,000；审计还要求≥10,000 个完整成功操作。若百万行查询容量较低，就延长窗口，不能减少样本门槛。本工具允许小数 rate；rate 必须由原版 A 校准后在外层锁定。独立 5 个 A/A 配对、5 个 A/B 配对、95% bootstrap、CPU/吞吐 1% 和延迟 2% 精度/方向性判定仍由 `p4_statistics.py` 执行，不能由单窗 PASS 替代。窗口最大 24 小时，worker 原始记录和到达表都有有限上界。

## 编译和不联网检查

```python
import flight_performance as flight
from pathlib import Path
runtime_ref = flight.compile_helper({
    "java_home": "/absolute/path/to/jdk-17.0.4+8",
    "jars": [str(path.resolve()) for path in sorted(Path("/actual/package/fe/lib").glob("*.jar"))],
}, Path("/new/compile-directory"))
```

固定实际 JDK 17.0.4 的 java/javac/modules/libjvm/release、全部安装包 JAR、工具源和实际生成类文件。`compile` 从不创建 Flight channel。也可用 CLI：

```text
python3 tools/license-checks/flight_performance.py compile --input compile-input.json --output new-compile-dir
python3 tools/license-checks/flight_performance.py plan --input profile.json --output new-plan.json
```

Java 的 `--plan profile.json new-directory` 生成真实 StrictMath/JavaRandom 到达表，解析原 fixture 私有 ABI，但不实例化 Session。`--self-test new-receipt.json` 验证实际 `/proc/self/stat`、JDK、namespace 和 ABI；同样不创建网络客户端。正常运行只接受一个 `config.json` 参数。Python 对计划使用独立 Java Random 模型，逐项复核至 1ns；正式 A/B 对实际到达文件的 SHA256 仍严格相同。发行环境变化或两种数学实现出现字节差异时，先解决计划一致性，不能改冻结的 B 输入绕过校验。

## 外层只需提供的 context

调用前，外层进入实际 FE/BE 所在的隔离 network namespace，确认只运行目标 A 或 B 服务组，并设置客户端 CPU/内存预算。`flight.pin(pid)` 只读 `/proc`，返回 `{pid,start_ticks,namespace,exe,command_sha256}`；调用者将实际 FE/BE pins 作为 `services`，工具会在运行期间核对，绝不启停这些服务。

Context 字段：

- `schema_version=1`、唯一 `window_id`、非负 `pair_id`、`phase=DIAGNOSTIC|CAPACITY|AA|AB`、`variant=A|B`。CAPACITY/AA 只允许 A。
- `identity` 使用统计层七项实际身份：source_commit、fe/be/environment/configuration/fixture/client 的 SHA256。
- `workload` 为 profile 文件 `{path,sha256}`；`bindings` 包含 `runner/java_helper/flight_fixture/clock_adapter/lifecycle/statistics` 六个实际源引用，以及 `fe_artifact/be_artifact/environment/configuration/fixture/client` 六个身份引用。
- `services={fe:pin,be:pin}`，`service_configs={fe:ref,be:ref}` 指向实际配置文件。配置里的唯一 `arrow_flight_sql_port` 必须等于 endpoint。
- `endpoints={fe_flight_port,be_flight_port,user,password_env}`；只连接当前 namespace 的 127.0.0.1，BE 返回位置也严格限制为该端点。密码只从所指定环境变量读取，不进入回执。
- `coordination_seconds`（1–300）、`context_deadline_monotonic_ns`（调用时未来≤300秒）、`max_clock_uncertainty_ns`（正数≤1秒）。建议真实诊断先用 30 秒和 50ms 映射上限。
- AB 额外提供 `freeze` 和 `publication` 引用；须在 launch 之前发表，身份、G2/LP-010、business SHA、rate、concurrency、seed、warmup/duration、实际到达数/SHA 和 `connection_mode=reuse_fe_and_be_channels` 精确匹配。

```python
# Outer controller fills the actual context above; it must not reuse an old launch manifest.
raw = flight.run_window(profile_ref, context, runtime_ref, new_raw_directory,
                        stop_file=owned_stop_file)
# raw contains launch/completion refs and window_directory, never a performance PASS.
result = flight.normalize({**raw, "observer": actual_observer_ref})
# Write result outside the raw directory, then set normalized_window["evidence"] to that audit file ref.
```

运行前，context、实际 jar/class/JDK 和源码必须仍与编译证据一致。Java 在实际 Session 准备好以后，与 Python 进行同 boot、nonce/launch 摘要绑定的有界文件握手；测量的 CPU/latency 用同 JVM 原始差值。跨 JVM 仅使用 offset 区间和不确定度，不能声称精确全局纳秒。实际 warmup 必须保守地位于 launch/AB publication 之后且未超过 context 期限。最终关闭全部 BE/FE channel/allocator，外层对自己创建的进程执行 wait；如果异常或输入漂移，finally 仍只回收自己的 Popen 进程组。强制终止使该窗口失败；外层应在下一窗口之前确认服务端已无残余工作，不能把 kill 当作已完成查询。

## 原始审计和正式 observer

每个窗口都有自己的到达 TSV、每 worker 的 warmup/measurement JSONL（含错误）、阶段起止及原始 `/proc` CPU 快照、Session open/close、clock handshake、实际进程完整 argv 摘要、lifecycle 和 parent-wait completion。归一化重新读取原始记录并检查前后 manifest 一致；class/JDK/JAR/源和共享输入作为 dependency bindings 交给统计层，不能只信一个派生 summary。归一化输出必须放在窗口目录外，避免自引用。缺失证据、失败、旧文件替用均拒绝，不能用 mtime 推算 warmup。

正式窗口另需外层真实 observer：`status=VERIFIED`、`launch_sha256`、`boot_id`、保守覆盖实际 warmup 至 measurement 结束的 `coverage_start_monotonic_ns/coverage_end_monotonic_ns`、`resource_failures=[]`、`budget_verified=true`、`observed_license_state=ORIGINAL_A_NO_LICENSE`（A）或 `VALID`（B）、`auditor` 引用、非空 `raw_artifacts`、`services`。每个 service 要有与 launch 一致的 `pin`、实际部署二进制 `artifact` 引用和实际 `configuration` 引用。此接口让既有外层观察器转入窄回执，不要求另起监控框架。诊断允许没有该 observer，但只返回 `DIAGNOSTIC_VERIFIED_NOT_QUALIFIED`，不能成为正式窗口。

容量搜索、SLO 预冻结、R 档位、A/A 顺序、正式 pair 调度由外层执行；本工具交出可复算的单窗原始结果。`audit_requests` 能保留失败/超时计数供容量失败档位分析；`normalize` 要求两阶段零错误，不会把失败容量试验转换成成功性能窗口。
