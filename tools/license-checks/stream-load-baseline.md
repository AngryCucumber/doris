<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP012 原版 A 持续 Stream Load 窗口

`stream_load_baseline.py` 实现一个完整、固定输入速率的原版 A 窗口。默认只生成计划；
`--mode probe --plan <owned-plan.json>` 才编译 SQL helper、发送请求并创建新测试数据库。
**已完成离线验证：最新CPU0 Stream Load 55项；先前CPU5共享background fixture 34项、资源边界15项通过。**
原版 v3 已完成完整180秒预热和600秒计时窗、10M独立内容核验及归属清理，真实退出码0。
结论为单窗功能完成、性能结论不足。此前 v2 因旧工具队列满导致42批未发送而失败；完整失败证据保留。

## 输入与计划

- 必须给出已有 `stream_load_fixture.py` 格式的完整 CSV 和相邻 `.csv.json`：seed 20260922、
  10,000,000 行、每行128字节，`id/grp/v/payload` 固定表达式。计划检查 manifest 和大小；
  probe 在计时外逐字节重建全部行、检查完整 SHA，再写只读用途的分批副本。工具没有生成输入或截短输入的模式。
- 并发只能选1/8/32，batch只能选1000/10000。测量窗600至3600秒，默认600秒；
  rows/s 精确为10,000,000除以窗长，bytes/s为该值乘128。到达偏移使用整数纳秒固定间隔，
  全部请求预生成并冻结，确定性 worker 分配为 `batch_index % concurrency`。不是容量校准结果。
- 180秒预热用同一输入的前缀及独立空表，速率与测量一致；测量表保持空表，完整10M输入只上传一次。
  两个窗口分别记录边界。预热内容核验产生的间隔可见于记录，尚未验证其正式性能影响。
- 计划绑定 `.build-records` 下 cluster record/输出/输入，原版 FE/BE SHA、全部 FE jars、配置、
  JDK17.0.4精确runtime build、java/javac/modules/libjvm、实际PID/start ticks/exe/cmd摘要/network namespace、
  controller及所有所用辅助源码和 canonical性能JSON。只记录命令摘要，不记录原始argv或环境。
  probe 重新核对全部绑定；拒绝候选 license-core JAR、服务重启、namespace变化和重复执行计划。
  实际Temurin17.0.4+8使用`FULL_VERSION`字段；复用共享校验器接受它或`JAVA_RUNTIME_VERSION`，
  至少存在一个精确build字段，所有已声明字段必须一致匹配。缺失、错误或相互矛盾的build不能降级接受；不修改JDK的release文件。
- 账号须为显式隔离 ADMIN，密码只来自 `MASSDB_STREAM_*_PASSWORD` 环境变量。原版认证仍有效。
  编译及各次 SQL helper 启动核对实际class/JDK/依赖；不安装证书、不创建许可实现，不更改BE。

参数示意（所有路径和SHA均须取自实际原版安装；示意命令**没有执行**）：

```bash
python3 tools/license-checks/stream_load_baseline.py \
  --cluster-record <owned-cluster.json> --input <owned-full-10m.csv> \
  --output <new-owned-window-directory> \
  --expected-fe-sha256 <original-fe-sha256> --expected-be-sha256 <original-be-sha256> \
  --jdk-runtime-version 17.0.4+8 --cpu 5 --concurrency 8 --batch-rows 1000

# 仅在正式测量结束、工具验证后，在相同 owned 私有 namespace 中显式运行：
python3 tools/license-checks/stream_load_baseline.py --mode probe --plan <owned-window-directory>/plan.json
```

## 实际协议与独立结果

每个请求发送原有 `PUT /api/{db}/{table}/_stream_load` 和 `Expect: 100-continue`、CSV/列/
strict_mode/max_filter_ratio/label认证头。FE必须直接307到已绑定的原BE loopback端口及完全相同路径；
userinfo只能与本次认证一致，不能重定向到其他主机、端口、路径或query。BE收到100后才上传完整body，随后必须200。

该顺序有现有源码和既有原版探测依据：
[LoadAction.java](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/rest/LoadAction.java:267)
只读headers、认证并返回redirect；真实
[FE响应头](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp012-full-be4g-v1/batch-000000-0.headers)
直接307，而同批
[BE响应头](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp012-full-be4g-v1/batch-000000-1.headers)
先100再200。v2 新异步客户端已取得2,958批真实有效回执；若FE意外返回100，明确报协议不匹配，不等待一个永远未发送的body。
真实FE的307还含三条合法 `Vary`，读取器按HTTP列表语义合并它们；`Vary: *` 保留通配含义。
这个例外仅适用于 `Vary`；Content-Length、Transfer-Encoding、Location、认证字段及未知字段仍拒绝重复。

请求显式发送原协议 `timeout: 60`，对应独立冻结的 `server_timeout_seconds=60`，不修改任何FE/BE全局配置。
服务端60秒从其处理请求/创建事务时计算；客户端 `request_seconds_from_arrival=60` 从预定到达计算，两个边界不等价。
仅等待60秒、关闭本地socket或取得DROP ACK，都不能证明未知服务端事务已经结束。
原BE只在有该header时传递timeout；未提供时FE源码默认是三天，见
[StreamLoadAction](/data/project/massdb-sql/be/src/http/action/stream_load.cpp:337)、
[StreamLoadExecutor](/data/project/massdb-sql/be/src/runtime/stream_load/stream_load_executor.cpp:170)、
[FrontendServiceImpl](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/service/FrontendServiceImpl.java:1289)。
这里没有通过SQL查询或改变运行实例的动态默认值。

每批标签含唯一数据库前缀、phase、window、client和batch。保留原始BE响应正文及SHA；
不归档带userinfo的Location、认证header、cookie或环境。要求精确label、正整数TxnId、
全部批次行数、零filtered/unselected和`Status=Success`。`Publish Timeout`、错误响应、失联或取消
保持失败/提交未知；不重试、不复用标签掩盖失败，也不把ACK直接当独立可见性证据。
完整Success回执若超过绝对期限，保留TxnId与原正文并标为`ACK_LATE`，不能算成功吞吐或整窗完成。
部分失败保留每跳开始、连接、header/body交给本地writer的字节数、drain完成字节数、HTTP状态及关闭结果。
这些字节数是本地传输进度，不能证明远端已收取或提交。

每窗完成后用独立SQL逐批扫描全部目标数据：完整ID区间、每批COUNT与COUNT DISTINCT、
四列NULL、grp/v算式、完整payload及字节长度。完整batch的唯一ID数量与其ID范围共同证明没有缺行；
额外ID、重复ID和任一错误列使校验失败。SQL helper原始结构化结果单独保存。
可见时间是后置扫描首次观测到完整批次的**上界**，不输出虚构的实际commit时间或commit延迟P99。

## 并发、资源与清理

asyncio每worker待执行队列仅保留预生成请求的引用，容量从完整冻结到达序列和原60秒绝对期限独立推导：
取该worker在所有 `(t-60秒,t]` 区间内的最大到达数，至少1；与在执行的请求分开，作为保守容量上界。
本次8并发、batch1000、600秒模型为每worker125个引用。plan保存各phase/worker精确容量，probe重新计算核对；
不改变到达时间或worker归属。只有活动且未过期的请求读取body，活动上传最多所选并发数。
调度和worker均检查 `scheduled_ns+60秒 <= now_ns`，相等即过期；移除过期积压并保存
`DEADLINE_EXPIRED_NOT_SENT`，不能作为成功。其他满队列仍记录 `QUEUE_FULL_NOT_SENT`，不能阻塞到达调度来隐藏排队。
pending实际峰值独立记录；fixture原RSS/线程/证据预算保持不变。
端到端延迟从预定到达时间开始；请求绝对期限60秒包含排队与两跳传输，窗口后drain最多65秒。
I/O返回时再次检查绝对期限，避免event loop延迟误接收晚到结果。关闭连接的waiter用shield保护；
正常关闭超时后显式abort，再有界等待同一个close任务。`is_closing`不能证明关闭；无法确认时停止负载并保留清理失败。
关闭期间收到取消时，先完成有界本地回收再重新传播取消；完整响应已到达则保留ACK及原正文，标为
`ACK_CANCELLED_AFTER_RESPONSE`。刚连接成功却越过deadline或资源预算时，连接句柄也先交给所有者再报错，不能遗失socket。
worker另有独立停止标记和5秒加3秒的结束等待，不能在取消后回到空队列永久等待。
过载、取消和异常仍为全部预生成请求生成结果记录；已开始请求与未发送请求分开。
完整HTTP响应最多64KiB，headers最多16KiB，原始回执和请求记录合计最多64MiB；字节预算写前预留。
每批输入最多读取其预期长度加1字节，再核对长度和SHA；准备后文件扩大或被同长度内容替换均在HTTP开始前拒绝。

复用未修改的 `background_http_resources.py`：每秒采样controller与所有编译/SQL子进程RSS/CPU/IO、
原FE/BE独立资源和namespace网络；controller512MiB、单helper768MiB、fixture合计2048MiB，
controller线程32、helper线程128。32个上传worker是异步任务，不额外创建32条线程。
RSS是实际采样/HWM预算，JVM heap另有256MiB限制；采样可能漏掉瞬时峰，不能当硬隔离。
辅助stdout/stderr有各2MiB边界，resource证据最多64MiB。启动要求额外512MiB可用内存余量和输入副本加512MiB磁盘余量。

另以固定5秒计划调用现有 `resource_observer` 的只读 `/proc` 和 `/metrics` 采样函数，
每端点绝对2秒，记录阶段及非原子进程边界；原有GC仅累计collection time，不是pause直方图。
network属于整个私有namespace，不按进程归因，不相加loopback RX+TX。观察器、客户端及SQL验证的成本明确存在。
缺少FE总分配字节、单次GC暂停、原有RPC计数/字节定义及进程网络归因，继续列入`missing_metrics`。
采样错误、跳过、失去原进程身份、证据失败或helper未退出均阻止功能完成。

新数据库和两张表都须有创建ACK及实际ID收据。使用原版
[DbsProcDir](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/proc/DbsProcDir.java:46)、
[TablesProcDir](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/common/proc/TablesProcDir.java:52)
提供的DbId/TableId，加SHOW CREATE及16个tablet ID，负载前后和DROP前重新核对。
数据库同名替换、表/定义/tablet变化、出现未归属对象或CREATE结果未知均禁止按名称DROP，记录manual residual。
同安装有独占owner锁；该锁不代替数据库身份核对。

取消后给SQL清理独立180秒预算；原进程身份丢失则禁止SQL清理。无论SQL失败、资源超限或证据写入失败，
仍独立停止本地metrics线程、回收自有helper及ResourceGuard。保留完整输入、批次和证据，不删除外部服务或文件。
SQL元数据核验使用有限次helper调用；正常工作上限64次，清理另预留10次。

每请求另记 `server_transaction_state`：未尝试向BE写请求头为 `NOT_SUBMITTED_TO_BE`；
只有已经验证原始Success、精确label/行数和正整数TxnId才为 `ACKNOWLEDGED_SUCCESS`；
已尝试BE请求头写入、没有上述ACK则为 `TERMINATION_NOT_PROVEN`。
ACK_LATE/取消后已获得完整有效ACK保留已确认提交事实，但仍不转为窗口成功。
请求intent在网络await前登记，并保持可被cleanup读取，即使phase归档失败也不会丢失未知提交分类。
窗口和cleanup均聚合此证据，未知项设置 `server_transaction_termination_not_proven=true` 并保持FAIL；
本地helper结束、数据库缺席与事务证据分别报告，不因本地清理成功抹除unknown。
该增量不增加SQL/事务轮询，也不放宽任何总时限。

## 结论边界与待验证

成功完成一个实际负载窗口也仅可报告 `FUNCTIONAL_WINDOW_COMPLETE_PERFORMANCE_INCONCLUSIVE`。
`LP012_complete`、`release_performance_pass`、`AA_precision_proven`始终false。
测量batch1000最多10,000次操作；batch10000只有1,000次操作，P99字段必须为空并记
`inconclusive_release_blocked`。行数不能充作操作数；延长窗长也不会偷偷重放输入补样本。
吞吐分开记录窗口内完成与drain完成，失败/未知请求不能进入成功统计。

canonical的1/8/32×1000/10000、180/600秒、至少5对A/A及5对A/B、1%CPU/吞吐与2%尾延迟精度、
所有指定许可状态仍完整保留。本工具尚无多窗口配对控制器；不会将六个单窗或一个资源guard汇总成性能通过。
需要今后明确冻结输入重放/独立目标轮换模型才能解决大batch的P99样本不足，本工具不自行作出该决定。

待独立验证：真实断连取消与清理失败分支、完整矩阵及精度测量。
v2已验证精确JDK/helper编译、原HTTP两跳协议、原SHOW PROC/SHOW TABLETS身份和本次归属清理；
这些成功路径证据不替代尚未完成的完整测量。
本说明与新增测试源码不替代这些真实证据。

2026-09-24离线记录：
[首轮命令/日志/源码摘要/退出码](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/stream-load/report-run1.json)
保留34+34+15项的原始结果，包括Stream Load测试mock未等待协程的RuntimeWarning。
修复该mock并增加批次文件扩大/替换两个反例后，仅重跑Stream Load；
[重跑记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/stream-load/report-run2.json)
为36/36、退出0，RuntimeWarning和ResourceWarning提升为错误，日志未检出警告。
共享34+15项没有无理由重复执行。
随后新建原版隔离环境时发现实际Temurin release文件的`FULL_VERSION`兼容性，复用共享校验器修复后增加
完整JDK绑定及缺失/错误/矛盾build两个反例；[第三轮记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/stream-load/report-run3.json)
为38/38、退出0、无警告。这个增量只有CPU5离线测试，没有并行访问新环境。

只读执行前复核发现新读取器会错误拒绝原FE307的重复Vary。
[修前离线复现](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/stream-load-vary-v1/before-fix.json)
记录真实已存头部的SHA及 `Ambiguous duplicate HTTP header`，没有执行真实probe。
[Vary修后记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/stream-load-vary-v1/after-vary-fix.json)
为CPU0上42/42、真实307头离线重放通过；存档文本的LF仅恢复为HTTP CRLF，字段内容不变。
随后加入显式服务端timeout和独立事务证据状态，
[首轮timeout增量记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/stream-load-vary-timeout-v2/validation.json)
保留一个新测试mock缺少实际SQL helper的success/columns字段所致失败；只修正该mock后，
[最终源码绑定记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/stream-load-vary-timeout-v3/validation.json)
为CPU0上48/48、真实307重放通过，RuntimeWarning/ResourceWarning提升为错误；不含SQL、HTTP连接、服务或大输入生成。
原 `lp012-sustained-actual-v1` 计划未运行且保留；源码/界限变化后须新建冻结计划，不能接着执行旧计划。

2026-09-24实际 v2 [失败审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp012-sustained-actual-v2/failure-audit.json)
保留完整180秒预热的3,000条结果：2,958 ACK、42 QUEUE_FULL_NOT_SENT、零未知提交。
原BE在首组拥塞前报告WriteDataTimeMs约3,005毫秒，客户端对应服务耗时3.037秒；
第二组约2.1秒。旧工具queue2只能容纳每worker约0.96秒到达，提前丢弃仍在原60秒期限内的请求。
未据此推断BE内部停顿原因，也未通过重跑碰运气或降低输入速率掩盖失败。
新模型只修正这项工具排队定义，保留8个活动请求、完整10M、180/600秒、原绝对60秒和全部成功门槛。
新增反例覆盖纳秒边界相等、不同batch/window整数取整、原3秒停顿、过期引用清除、活动请求drain和过期前禁止读body。
v2原数据库DROP ACK及独立absence、29个helper退出、资源/metrics完整性、原FE/BE/supervisor身份均已核实。

新冻结 v3 [原始报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp012-sustained-actual-v3/report.json)
与[退出/清理审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp012-sustained-actual-v3/completion-cleanup-audit.json)
记录完整180秒预热3,000批和600秒计时10,000批全部ACK，分别独立验证3M/10M完整行及全部四列，
无丢批、超期、未知提交或drain补成批次；请求引用峰值预热各worker5、计时最大7，容量125。
单窗端到端批次P50/P95/P99为44.256217/542.794917/2004.825469毫秒；这不是A/A精度或发布性能通过。
资源800次、现有metrics161次采样完整且零错误/跳过；37个helper真实exit0且/proc缺席，
原数据库DROP ACK及独立absence、owner锁清除、原3服务身份、611个冻结项及1.28GB输入终态SHA全部核实。
v3使用与v2完全相同的业务到达序列，只修订工具待处理引用容量定义；不替换旧FAIL，也不代表完整LP012矩阵完成。
