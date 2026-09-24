<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP010 原版 Flight 完整数据校验

`flight_fixture.py` 与 `LicenseFlightFixture.java` 在 owned 私有网络namespace运行，使用原版FE认证和FE返回的BE票据。
只读百万行 `point_rows`，不改变表或服务配置。JDK使用cluster manifest中的实际版本；Java工具按release17编译，
依赖全部来自同一原版发行包，不下载或增加产品依赖。账号密码从环境变量读取，不归档token或票据正文。

固定查询为 `SELECT id,payload FROM license_perf.point_rows ORDER BY id`，用每次查询的SET_VAR设置
`batch_size=1024/8192/65535`，关闭短路/SQL/query cache，query_timeout=60。
另发送65536负例，要求原版参数拒绝；Flight的实际错误为INTERNAL包装的
`Can not set session variable 'batch_size' = '65536'`，不把其他连接/认证错误当负例通过。

正向矩阵共12条独立查询：三个batch_size × 新建/复用FE及BE客户端连接 × 两次执行。
每条要求唯一且显式的owned BE endpoint，遍历全部record batch，核对列名、schema一致性、非NULL、
严格升序且连续的ID、每行payload等于MD5(decimal id)，最后与Python独立生成的完整CSV SHA-256相符。
客户端的连接模式表示新建或复用FlightClient channel对象，不把它等同于未经抓包确认的物理TCP连接数。
请求的session batch_size不是Flight record batch的实测行数：实际可能合并，逐批行数单独记录。

固定矩阵中的失败会逐项保留，其他预定组合继续执行，最终任何一项失败都使整个fixture失败。
每个case直接持有查询过程中写入的结果，失败也保留endpoint、票据摘要、已收到的逐批行数、schema、
`rows_verified`和含校验/诊断的耗时。`rows_verified`只计已经通过原有逐行oracle的行；
完整行数与摘要仍必须全部通过才能获得`READ_PASS`，诊断信息本身不产生通过结论。
首个record batch会保存行数、schema、各列的vector class、Arrow type与valueCount；批内校验或解码失败时，
在关闭stream之前另保存失败批次及行号（`-1`表示尚未进入逐行校验）。
仅对固定合成MD5 payload保存offset buffer前16字节及32位无符号/64位有符号小端解释、
data buffer前32字节的十六进制，以及两种buffer的capacity、reader/writer index和readable bytes。
这些前缀从绝对位置0读取，长度受capacity约束，**不以writer index裁剪**，便于检查错误offset导致
writer index为0的情况；capacity或前缀不等于已验证的有效数据长度。诊断读取异常单独记类型，不覆盖原oracle异常。
首批及失败批次之外不逐批复制buffer；若请求或`stream.next()`在批次可用前失败，只保留当时已取得的证据。
每个Flight请求有有界超时，整个JVM最长300秒、堆512MiB、Arrow allocator256MiB；退出关闭stream/channel/allocator。
失败查询按原query_timeout收尾；工具不声称向BE新增取消或许可协议。客户端逐行MD5及完整摘要包含在耗时内，
此工具用于正确性和可达性，记录的耗时不能作为吞吐、尾延迟或性能通过证据。

```bash
nsenter -t <owned-supervisor-pid> -n -- taskset -c 0-4 \
  python3 tools/license-checks/flight_fixture.py \
  --cluster-record .build-records/<current-profile>/cluster.json \
  --output .build-records/<new-flight-fixture-directory>
```

## 2026-09-24 真实结果

[固定矩阵报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp010-flight-be4g-v4/report.json)
来自Temurin17.0.4+8、原ARM64 FE/BE包、新4GiB BE profile。1024/8192各连接模式共8条查询通过，
合计完整校验800万行；SHA-256均为 `d07f615ccea4c0f21cc4a7505c400a0b47d454eaa06521092e607aa646c21a68`。
65536按原参数错误拒绝。65535的四条查询均在第一批第一行发现id=0但非NULL payload为空，
期望值为 `cfcd208495d565ef66e7dff9f98764da`，因此整个fixture是FAIL，LP010仍未通过。

v1保留错误包装假设不符的失败；v2/v3保留大批次校验首次失败及定位信息。
这些运行没有许可入口接入，不能证明过期拒绝。65535问题还须独立协议/源码定位；
不移除该档、降低数据规模或将原版失败改为通过，也不擅自修改BE。

另以独立MariaDB JDBC StreamingResult执行相同完整ORDER BY查询：8192和65535各新连接的前10行均正确，
随后关闭连接；见[对照记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp010-jdbc-batch-diagnostic/result.json)。
该诊断未检查其余999990行，只收窄到Flight特有路径，尚未证明具体BE/传输/客户端根因。

## v5：实际失败buffer证据与已接受的原版缺陷

新增保留局部结果、首批和失败批buffer的 helper 已在相同原版发行包、Temurin17.0.4+8 上编译并运行。
[v5 完整报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp010-flight-be4g-v5/report.json)
的 SHA-256 为 `c32419f427d6203133e3b49c6ef6757d4b30a6ce7a0b6c46c6569375383a0522`，
所用 Java 源码 SHA-256 为 `12754998c07a15128a114811f503997bf05c81e63f7424aab47954255a1bc59b`。
UTC 实际执行区间为 `2026-09-23T22:01:56.638289+00:00` 至 `22:02:06.077659+00:00`。
固定 12 项全部执行：1024/8192 新建及复用连接的 8 次查询再次完整校验 800 万行通过；
65536 保留原参数拒绝；65535 的 4 次查询仍在第一批第 0 行失败，整体退出码 1、报告状态 FAIL。

四次 65535 失败的首批证据完全一致：

| 字段 | 实际值 |
| --- | --- |
| 首批行数、payload valueCount | 65535 |
| payload schema / vector | `Utf8` / `org.apache.arrow.vector.VarCharVector` |
| offset capacity / writer / readable bytes | 524288 / 262144 / 262144 |
| offset 前 16 字节 | `00000000000000002000000000000000` |
| 按 32 位小端解释 | `[0, 0, 32, 0]` |
| 按 64 位小端解释 | `[0, 32]` |
| data capacity / writer / readable bytes | 2097120 / 0 / 0 |
| data 前 32 字节 ASCII | `cfcd208495d565ef66e7dff9f98764da` |

这直接确认客户端 `Utf8` 的 32 位偏移解释与所收 buffer 的 64 位布局不一致，
首行真实字符仍在原始 data buffer 中，按前两个 32 位 offset `[0,0]` 读取时得到空串。
65535 次数/连接模式和完整原始字段见
[v5 逐项结果](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp010-flight-be4g-v5/flight-result.json)，
其 SHA-256 为 `acfcfc08d081bbd9fbaae21c4b847f036e1687078dc99da2af5175965977113e`。

只读源码审查发现候选：`be/src/util/arrow/row_batch.h`的`MAX_ARROW_UTF8=(1ULL<<21)`实际为2MiB，
而`block_convertor.cpp`超过该阈值时只将局部builder类型改为`large_utf8`，创建RecordBatch仍传原`utf8` schema。
`ColumnString::byte_size()`包含字符和偏移数组，65535个32字节字符串加普通32位偏移已超过此阈值。
v5 的实际 buffer 与该类型/偏移不一致路径吻合；尚未通过修改 BE 后的回归验证修复，也未观察 BE 内部 builder 对象。
触发条件应按结果块总字节数分析，实际批次可能合并，不能归结为行数的16位溢出。

用户已明确选择“保留原版缺陷，继续授权开发”。据此保留原版 BE 和该失败证据，继续 FE-only 授权开发；
不删除 65535 档、不降低矩阵要求、不把它改成通过，也不宣称这一档的性能通过。
这一接受边界不是根因修复或 LP010 全部验收通过；后续许可逻辑仍需按冻结范围单独验证。
