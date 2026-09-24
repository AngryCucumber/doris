<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP011 原版外部 scanner 完整数据与旧计划重开夹具

状态：**原版 A 功能夹具实际通过，Python 19/19 离线测试、Java 10/10 内存自检通过**。
canonical case 保持 `not_run`；本次只交付 LP011 的原版 A 功能前提，
不代表过期拦截、正式 A/B 性能或目标发行环境通过。

`external_scanner_fixture.py` 在记录的 owned 私有网络 namespace 内校验 FE/BE 进程归属、PID start_ticks，
并从私有安装配置读取唯一 FE HTTP/BE Thrift 端口。FE/BE namespace 及 start_ticks 在请求前后固定，
Java 在打开 scanner、get_next 和独立 close 连接前重新校验。所有网络连接固定 `127.0.0.1`，
拒绝 FE 返回的外部地址、其他端口、多个 route 或非 16 个 tablet。

原版接口与输入冻结为：

- FE：一次 `POST /api/license_perf/point_rows/_query_plan`，Basic 认证，JSON `sql` 为
  `SELECT id,payload FROM license_perf.point_rows`。该入口只支持单表 filter/project/scan，不能加入排序。
  请求不使用代理、不跟随重定向、不重试；响应上限 2 MiB，读取总预算 15 秒、单次 socket 超时 5 秒。
- BE：发行包生成的 `TDorisExternalService.Client.openScanner/getNext/closeScanner`，
  原 Thrift binary protocol，无新增认证/票据字段。一个 scanner 只读一个 FE 返回的 tablet。
  `TScanOpenParams` 使用 `batch_size=1024/8192`、`keep_alive_min=1`、`execution_timeout=60`、
  `mem_limit=256 MiB`，不设置 limit、不修改表、会话全局配置、BE 源码或协议。
- 每档先打开并读完全部 16 个 tablet，再使用**完全相同的 FE 计划**重新打开 16 个 scanner。
  合计四次独立完整读取、400 万行、64 个独立 context；整个矩阵只向 FE 申请一次计划。
  每个 context 只归档 SHA-256，跨初次/重开和档位检查其唯一性。

每次完整读取各自重新分配 coverage bitmap 和 32 MB 的实际 payload 字节数组。逐行检查 id 是非 NULL
64 位整数，范围 `0..999999`，跨所有批次和 tablet 不重复；payload 必须是非 NULL
`MD5(ASCII decimal id)` 的 32 位小写十六进制字符串。结束要求百万个 id 无缺口、计数和总和正确，
再按 id 从实际 payload 数组生成完整 CSV SHA-256，与 Python 独立模型相比。
因此完整摘要来自真实返回的字节，不是直接将模型摘要复制为结果；不依赖 tablet/批次返回顺序。
同一计划重开使用新的 coverage、实际字节数组和摘要，不能继承第一次扫描的通过状态。

每个 get_next 记录请求 offset、实际 Arrow 行数、IPC 字节数、schema、该批 id min/max/sum、
响应状态、EOS 和下一 offset。原 `DorisExternalService.thrift` 约定单批行数不超过请求 batch_size，
`backend_service.cpp` 每次序列化一个 Arrow RecordBatch，并在独立的无数据 EOS 响应结束。
工具保留这些原约束：非 EOS 必须有一批有效数据、`0 < rows <= batch_size`，累计实际行数推进 offset；
EOS 必须明确设置且不含未消费数据；每 tablet 最多 4096 次 get_next、每 IPC 最多 16 MiB。
若实际发行包违反这些约束，保存失败，不自动放宽为通过。

获得 context ID 后，成功或异常都会进入 finally，并用新的 owned loopback 连接执行 close，
这样读取连接损坏时仍可尝试释放 context。close 有 5 秒超时，关闭结果必须为 OK 才能通过；
close 失败单独保留，不覆盖原读取异常。若 open 在返回 context ID 前断线，只能记录
“未取得 ID，无法确认主动 close”，不得伪称已清理；原执行期限/keepalive 仍适用。
JVM 总执行期限 300 秒；Python 等待上限 340 秒，终止时先留 10 秒给有界 shutdown hook 尝试 close，
再强制结束。强制结束/未确认 close 不能算通过。JVM 堆 256 MiB、Arrow allocator 128 MiB。

不落盘 FE 响应正文、账号密码、Authorization、票据正文或 context 正文。
`scanner-config.private.json` 包含唯一一次取得的 opaque plan，以独占创建方式写入、权限必须为 `0600`；
仅在 checkout ignored `.build-records` 中保存，不发布此文件。公开 report 只保存计划 SHA-256、长度及 tablet 路由。
依赖使用 manifest 指定的实际发行包 `fe/lib/*.jar` 和 JDK；生成的 Thrift 客户端、Arrow、Jackson 均已在包内，
不下载库。报告记录源码、所有 classpath JAR、FE/BE 文件与 cluster manifest 的摘要。

执行前需 root 分配非性能测量窗口；以下为复现方式，输出目录必须全新：

```bash
nsenter -t <owned-supervisor-pid> -n -- taskset -c 0 \
  python3 tools/license-checks/external_scanner_fixture.py \
  --cluster-record .build-records/<current-profile>/cluster.json \
  --output .build-records/<new-external-scanner-fixture-directory>
```

Python 离线测试只检查输入/记录，不连接任何端点：

```bash
PYTHONPATH=tools/license-checks python3 -m unittest -v test_external_scanner_fixture
```

Java `--self-test <report-path>` 在编译后、任何 FE/BE 请求之前自动执行十项纯内存 oracle 测试：
乱序完整集合、跨批重复、缺失、负数/越界 id、NULL/错位/空 payload、拒绝后 coverage 不被污染、
重开创建独立空 coverage。Python 离线测试覆盖 route/状态/计划文件保护、真实模型 CSV 字节约定、
HTTP 无重定向与敏感信息不归档，以及对缺失矩阵、错误摘要、未确认 close、context 重用、offset 跳跃、
EOS 错误和超大批次记录的拒绝。真实通过记录如下。

## 2026-09-24 实际通过记录

运行环境为原版 ARM64 FE/BE 包、Temurin17.0.4+8、Fedora 42 aarch64，
cluster manifest 为 `.build-records/license-p0-p1-20260924/baseline-jdk1704-be4g/cluster.json`，
private namespace `net:[4026532515]`，FE/BE 仍为原 supervisor 2778998 所属服务；客户端绑定 CPU 0。
本次没有正式性能计时，不把功能耗时当吞吐或尾延迟结果，也不是麒麟/openEuler 发行机验证。

- [Python 离线报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp011-offline-tests-v1/report.json)：
  19 项、0 failure、0 error、0 网络请求；SHA-256
  `1f0be306d50d6ac7c4bf232b36772e9aa973147fad1c68ec1c3a989172b93e03`。
- [Java 自检报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp011-external-scanner-be4g-v1/java-offline-tests.json)：
  10 项全部通过、0 网络请求；SHA-256
  `fb5aeaf056d85a41ec9a77efc421174cd95f9cb81b4bf36486ab21dc5a708253`。
- [功能总报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp011-external-scanner-be4g-v1/report.json)：
  `FIXTURE_PASS`、Java 退出码 0；SHA-256
  `19bd746f783ac326da70acc1d3678d41fd10563798c1ed8eb5adac106b67813c`。
- [逐 scanner / batch 记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp011-external-scanner-be4g-v1/scanner-result.json)：
  SHA-256 `9305536980b91f350459ffa53599f0ed7082de96829d7f31035ae617d42cf979`。

UTC 实际执行区间为 `2026-09-23T22:03:30.774271+00:00` 至 `22:03:37.788287+00:00`。
FE 只收到一次计划 POST，HTTP 200、响应 6653 字节、16 个 tablet，opaque plan 为 5340 字节；
原计划 SHA-256 为 `75b519abe54d66d05e36c300a2f123589ee7bd6624601dbd513acd74920b6b0e`。
私有配置文件实测权限为 `0600`；公开报告没有原计划或 context 正文。

| batch_size | 读取 | 验证行数 | get_next 次数 | 非 EOS 批次 | EOS 次数 |
| --- | --- | --- | --- | --- | --- |
| 1024 | 初次 | 1000000 | 1008 | 976 × 1024 + 16 × 36 | 16 |
| 1024 | 同旧计划重开 | 1000000 | 1008 | 976 × 1024 + 16 × 36 | 16 |
| 8192 | 初次 | 1000000 | 144 | 112 × 8192 + 16 × 5156 | 16 |
| 8192 | 同旧计划重开 | 1000000 | 144 | 112 × 8192 + 16 × 5156 | 16 |

每轮每个 tablet 实际返回 62500 行。四轮均验证 id 范围 `0..999999`、100 万唯一值、
`SUM(id)=499999500000`、每行 MD5 正确，实际响应字节按 id 排列的完整 CSV SHA-256 均为
`d07f615ccea4c0f21cc4a7505c400a0b47d454eaa06521092e607aa646c21a68`，与 Python 独立模型一致。
64 个 context 的摘要全部不同，64 次 close 均返回 OK；工具正常退出，功能请求已停止。

实际使用发行包 Arrow 17.0.0、libthrift 0.16.0、Jackson 2.16.0 及生成的 Doris Thrift 类；
所有 JAR 的准确路径/摘要见总报告的 `dependencies`，没有额外下载。
验证源码为 Java `9b355faeba0d8c6fc5fba7f80cdcca7b35ab73fcd9bc464989306b26dbd51473`、
Python 包装 `f9584fab3d53d2e9ae9ad8091f3f7576c17d4ccd4214404231e9b5ece794312d`、
Python 测试 `88cd2f33f342db63edb43f5f95d8fd093a06050b6bcc2d300f3c281e5e978874`。

实际功能报告应保留每次读取的局部结果和错误；任何组合失败都使矩阵整体 FAIL。
耗时包含逐行 MD5、实际 payload 排序索引、完整摘要及日志记录，不能作为吞吐或尾延迟性能通过记录。
现阶段没有许可接入，也没有制造“到期后向 FE 申请新计划”的负例，因此不能宣称跨期拦截通过。
旧计划重开只观察原有 BE 行为，符合用户已接受的 FE-only 边界。
