# MassDB SQL 新增修改后的同分支复测报告（2026-11-04，R2）

**结论：已完成本文列明的功能、故障、边界和性能测试；本候选仍不建议验收。** 最新修复已经解决已测 STRUCT 恢复、VARIANT 混合类型 WAL 和 chunked 标签去重问题，但本轮扩展输入又发现 3 类新旧版共有的数据完整性问题，以及新版退避引入的短超时恢复问题。普通查询、单位测试通过不能抵消这些失败。

“完整”限于下述明确矩阵，不代表执行全仓库每个用例或穷尽所有条件。测试输入持续变化；固定复现、新随机种子、首轮完成后生成的保留轮、独立字节/数值预期共同使用。没有修改产品代码以迎合测试。

## 版本及构建身份

| 角色 | 提交 | 本轮口径 |
| --- | --- | --- |
| 旧版 | `49f67bdbb94b941574dbd6b9463eefdd163a84bd` | 用户确认的同分支最早状态；复用上一轮已封存、重新核验哈希的 FE/BE |
| 上一轮候选 | `b31b5da06ac740e18a2f7c38d6678875495d7904` | 修复效果的历史参照；不是本轮性能表的新版本 |
| 本轮新候选 | `2f21ee3907045c73bba8c8d0e5c59856beda7e1a` | Claude 的 fix/gpt-retest-2.1.5 提交；本轮重新构建 FE/BE 和 ASAN 测试二进制 |

本轮候选是上一轮提交的直接子提交；相对上一轮变更 15 个文件，相对确认的旧版变更 69 个文件。测试开始时主工作目录 `/data/project/massdb-sql` 仍在 `b31b5da06ac`，新修复尚未合入；本报告的新版结果来自固定在 `2f21ee39070` 的隔离构建。两个比较版本都采用 4.1.5 内核，不使用先前错误选择的许可证分支，也不据此推断所有 4.0.5 部署的 STRUCT 行为。

旧证据包及其中 3,013 个清单文件已逐项核验，均未变化；见 [上一轮证据完整性核验](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/prior-evidence-integrity.json)。旧 FE 单测、上一轮 UI/打包测试为历史结果复用，明确不计作本轮新执行。

环境为 ARM64、10 vCPU、19.47 GiB 内存、8 GiB swap、4 KiB 页，JDK 17.0.2、Clang 20.1.8；FE 堆 1536 MiB、单 BE 上限 4 GiB。所有性能阶段等待编译结束，旧新实例串行运行；功能探测部分曾与编译重叠，其耗时不作性能结论。主机还有其他服务，不能将这些数据当作独占机器或生产容量上限。

| 二进制 | 旧版 SHA-256 前 12 位 | 新候选 SHA-256 前 12 位 |
| --- | --- | --- |
| doris-fe.jar | 1ae1c0f45a49 | dc596a164c90 |
| fe-common JAR | d34ed022b65c | 0ef18ea84432 |
| doris_be | f65898bbf66b | e47d92fb1ee0 |

完整构建参数、源码身份与哈希见 [构建来源](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/provenance) 和 [二进制清单](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/provenance/binary-identity.json)。新核心为 headless 构建；未变化的扩展依赖按上一轮方式复用并替换匹配的 fe-common，不将其冒称本轮重新构建的全部发行包。

## 结果概览

| 检查 | 旧版 | 新候选 |
| --- | --- | --- |
| 首轮与新种子功能断言 | 718 项，0 失败 | 724 项，0 失败 |
| 独立类型预期 | 24 项通过 | 24 项通过 |
| FE 所选单位测试 | 历史复用：516 项，513 通过 / 3 跳过 | 本轮：569 项，566 通过 / 3 跳过 |
| BE ASAN 所选单位测试 | 未新增执行 | 38 个不同用例，8 组；两组起始种子各 3 轮，每轮打乱顺序，228 次通过 |
| 真实简单 STRUCT WAL 恢复 | 5 项 / 1 失败 | 5 项 / 0 失败 |
| 嵌套类型 SQL 构造输入 + WAL 恢复 | 63 项 / 6 失败 | 63 项 / 0 失败 |
| 13 种 NULL 类型 × 两种块顺序 VARIANT WAL | 26 组：2 正确 / 23 报错保留 / 1 崩溃保留 | 26 组全部逐值正确 |
| chunked 两阶段提交 | 28 项 / 4 失败 | 28 项 / 0 失败 |
| 两种部分更新设置 × 传输/提交模式 | 40 项 / 8 失败 | 40 项 / 0 失败 |
| 真实 IPv6 网络与表名 URL | 16 项 / 0 失败 | 16 项 / 0 失败 |
| 嵌套 JSON 转义 | 28 项 / 20 失败 | 28 项 / 20 失败 |
| 列式文件固定长度 / chunked 双 scanner 对照 | 16 项 / 4 失败 | 16 项 / 4 失败 |
| gzip 完整性与前缀提交 | 16 项 / 12 失败 | 16 项 / 12 失败 |
| 规划失败、超时与恢复 | 28 项 / 0 失败 | 36 项 / 2 失败 |
| 所选 SQL 回归 | 60/60 框架任务成功，实际 56 主体 | 59/60 成功、1 失败，实际 56 主体；另有隔离复测 |
| 已落表数据升级 | 14 表、2,150 行输入 | 67 项 / 0 失败 |
| 真实待重放 WAL 升级 | BIGINT / ARRAY / MAP / STRUCT / VARIANT | 27 项 / 0 失败 |
| 独立查询预期核对 | 6 组负载、48 查询组合 | 96 个版本结果核对，0 不符 |
| 文件导入性能逐字段与副本数核对 | 2 个 ABBA 实例，另加 3 个 gzip 实例 | 2 个 ABBA 实例，另加 3 个 gzip 实例；全部逐字段核对 |

表中“项”是断言执行数，不是独立缺陷数；重复执行 ASAN 不称为 228 个不同用例。初始 HTTP 2PC 检查器误报、复杂类型输入已损坏与 WAL 额外损坏分别核对，不能直接相加所有原始失败数。完整结果见 [主结果汇总](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/final-summary.json)、[复杂场景汇总](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/complex-summary.json)、[运行期汇总](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/runtime-summary.json)。


## 已确认的数据与边界问题

以下优先级按验收影响划分：P1 影响数据完整性，P2 影响恢复、兼容性或服务行为。问题按原因/现象归并，不按失败样例数量拆分。前三项在旧版与本轮候选均复现，属于本轮新发现的共有问题，不能归为 Claude 此次提交新引入。

### P1-1：嵌套 JSON 字符转义改变实际存储字节

对 ARRAY、STRUCT、MAP 中的字符串，Tab `09` 变成字符 `t` 的 `74`，CRLF `0D0A` 变成 `rn` 的 `726E`，NUL `00` 变成 `u0000` 的 `7530303030`。使用 `ensure_ascii=true` 时，部分中文和 emoji 的 Unicode 转义也作为普通文字保留下来。返回成功，但值已变化。

已执行的最小 SQL（UNHEX 避免 SQL 字面量再次处理转义）：

```sql
SELECT HEX(element_at(CAST(UNHEX('5b225c74225d') AS ARRAY<STRING>),1));
-- JSON 文本为包含 Tab 转义的数组；预期 09，两版实际均为 74。
```

两种 scanner、两种 JSON 编码各检查 15 行：UTF-8 字面编码有 5 行嵌套值错误，ASCII 转义编码有 11 行错误；顶层 STRING 对照字节全部保留。另有 12 个从 UNHEX 还原 JSON 文本后直接 CAST 为复杂类型的控制全部复现，排除了仅仅是 HTTP 分块或显示格式的问题。使用 `named_struct/array/map + UNHEX` 的类型构造输入则保存正确，新版随后 WAL 恢复也正确。

代码审查中，[嵌套字符串反序列化](/root/.codex/worktrees/same-branch-baseline/massdb-sql/be/src/core/data_type_serde/data_type_string_serde.cpp:365) 调用的 [escape_string](/root/.codex/worktrees/same-branch-baseline/massdb-sql/be/src/core/data_type_serde/data_type_string_serde.h:40) 去除转义字符但不进行完整 JSON 转义解码，与直接 CAST 对照的字节结果一致。本轮未修改实现，也未以修复后结果验证完整调用链。证据：[逐字节输入/实际值](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/nested-escape-new/escape-results.json)、[直接 CAST 控制](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/nested-escape-new/cast-results.json)。

### P1-2：chunked Parquet/ORC 返回 Success，但写入 0 行

同一份 257 行文件，在带 Content-Length 时行数与所有字段准确；改为 HTTP chunked 后，Snappy/Zstd Parquet 和 ORC 均返回 Success、NumberLoadedRows=0，实际表也是 0 行。独立切换 V2/legacy scanner，Parquet 与 ORC 的 4 个 chunked 组合都复现；相应固定长度组合全部正确。后续保留轮重新生成 131 行、不同字节数据，再次检查该边界。

处理链中，[缺少 Content-Length 时 body_bytes 为 0](/root/.codex/worktrees/same-branch-baseline/massdb-sql/be/src/service/http/action/stream_load.cpp:289)，列式格式走本地文件路径，[file_size 仍使用 body_bytes](/root/.codex/worktrees/same-branch-baseline/massdb-sql/be/src/service/http/action/stream_load.cpp:465)；FE 再将此值放入 [fileStatus](/root/.codex/worktrees/same-branch-baseline/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/load/NereidsStreamLoadPlanner.java:229) 和 [扫描范围](/root/.codex/worktrees/same-branch-baseline/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/nereids/load/NereidsFileGroupInfo.java:450)。源码路径与同文件、双 scanner 控制一致。即使该组合不被支持，也应明确拒绝，不能把非空输入作为成功的空导入。

证据：[双 scanner 控制](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/columnar-new/columnar-results.json)、[首轮七格式传输](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/wire-new/file-results.json)、[新数据保留轮](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/wire-holdout-new/file-results.json)。

### P1-3：gzip 不完整时仍成功提交有效前缀

从 257 行原始数据生成 gzip，在第 17 行完整结束处执行 Z_SYNC_FLUSH 后截断，缺少压缩流结束和 trailer。独立 `gzip.decompress` 报 EOFError；数据库在 `strict_mode=true,max_filter_ratio=0` 下返回 Success，并提交 17 行。固定长度、chunked 以及两个版本均复现。删除完整文件末尾 4 字节 ISIZE 或 8 字节 trailer 也被接受；坏 CRC 控制会被拒绝。

这些请求的 HTTP 长度与实际发送字节一致，错误发生在压缩容器内部；普通 HTTP 短体测试则未提交数据，二者不能混为一谈。[NewPlainTextLineReader::read_line](/root/.codex/worktrees/same-branch-baseline/massdb-sql/be/src/format/file_reader/new_plain_text_line_reader.cpp:455) 每次调用将局部 stream_end 重置为 true，EOF 校验依赖这一局部值；此前调用已返回完整行时，未完成的压缩流状态可能未被保留。该路径与实测吻合，尚未通过产品补丁作最终根因验证。

证据：[gzip 完整性、响应及实际前缀](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/gzip-prefix-new/gzip-results.json)。原始压缩文件与 Python 独立解压结果一并保留。

### P2-1：新退避减少重试放大，但短超时恢复有回退

注入 FE 事务启动失败，同时让 4 个异步 INSERT 进入同一表，另查 SELECT 1；去掉故障后立刻写入新键。每次重试用独立键，逐值确认成功数据，避免重试重复写入被掩盖。


| 规划超时 ms | 旧版失败尝试 | 新版失败尝试 | 旧版最慢返回 ms | 新版最慢返回 ms | 旧版恢复总时长 ms | 新版故障解除后恢复 |
| --- | --- | --- | --- | --- | --- | --- |
| 97 | 28 | 3 | 166.7 | 247.0 | 22.3 | 首个失败，第二个成功；208.7 ms |
| 784 | 387 | 6 | 794.9 | 1,583.2 | 12.3 | 首个失败，第二个成功；1,045.5 ms |
| 1634 | 1552 | 7 | 1,641.4 | 2,585.7 | 7.9 | 首个成功；996.2 ms |
| 3500 | 5733 | 8 | 3,505.9 | 3,584.0 | 6.9 | 首个成功；995.8 ms |


新版的失败放大明显降低，但 97/784 ms 配置下首次健康写入仍失败，1634/3500 ms 下约等待 1 秒后成功。超时97ms的初次独立运行也出现相同现象，失败记录保留。[超时清理](/root/.codex/worktrees/same-branch-baseline/massdb-sql/be/src/load/group_commit/group_commit_mgr.cpp:361) 没有同时清除 `_create_plan_retry_at_ms`，[退避等待](/root/.codex/worktrees/same-branch-baseline/massdb-sql/be/src/load/group_commit/group_commit_mgr.cpp:380) 可延续到下一批请求；定时 worker 也使超时返回超过配置值。

本轮观察到最终能恢复、无未确认行混入；不能称为持续卡死。默认配置为 120000 ms，此处特意改变为非整齐边界值，不能将短超时首次失败直接外推到默认配置。仓库 20 秒故障路径通过，FE 同类规划错误从旧版 39,136 次降至新版 25 次；该计数来自相同主动注入原因。应同时验收重试速率、超时上界和故障解除后的恢复延迟，而不是只检查“有退避”。证据：[旧版重试记录](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/plan-retry-old/retry-results.json)、[新版重试记录](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/plan-retry-new/retry-results.json)。

### P2-2：HTTP/1.1 解析与连接边界问题，两版共有

19 组原始报文加 7 组语法变化和同连接后续请求控制，确认：特定顺序的冲突 Content-Length 被接受并写入 1 行；带空格的非法字段名 `Bad Name` 被接受；`ChUnKeD`/`CHUNKED` 被拒绝，合法 chunk 扩展被 413 拒绝；TE+CL 组合虽在应用层返回 Fail，连接仍可处理下一请求。重复相同长度、逗号列表/反序冲突和 trailer-only 分别保留结果，没有把单一报文的结果推广到所有组合。

RFC 要求对无法一致解释的 Content-Length 报错并关闭连接，且收到 TE+CL 后无论如何处理都应关闭连接；Transfer-Encoding 名称不区分大小写，chunk 扩展属于语法的一部分。见 [RFC 9112 §6–7](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3)。字段名应符合 token 语法，见 [RFC 9110 §5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1)。这些原始边界报文直连 BE；本轮没有验证代理链或请求走私利用，不能报告为已证实可利用漏洞。

证据：[原始报文结果](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/wire-new/framing-results.json)、[变化语法控制](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/http-boundary-new/framing-followup.json)、[拒绝后同 TCP 连接继续请求](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/http-boundary-new/connection-reuse.json)。invalid UTF-8 JSON、裸 NUL、截断 JSON、缺失授权、非法 chunk 长度和不完整 HTTP 请求没有写入数据，后续 SELECT 1 正常。 其中非法 UTF-8 输入的错误响应会在 FirstErrorMsg 中原样回显 `C0 AF`，两版均无法按 UTF-8 JSON 解码；响应头为 `text/html; charset=ISO-8859-1`。这是错误响应兼容性观察，数据仍为 0 行，见 [原始字节核对](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/invalid-utf8-response-observation.json)。


## 修复效果、复杂数据和反拟合方法

新版真实简单 STRUCT 恢复通过；SQL 类型构造方式的 9 组嵌套恢复（ARRAY<STRUCT>、MAP<STRING,STRUCT>、外层 STRUCT，NULL 在前/有值在前/全 NULL）全部 63 项通过。旧版相同 SQL 输入控制正确，但有 6 组恢复丢子字段。JSON 输入的同类测试还受 P1-1 影响：先比较普通写入控制，再比较 WAL 恢复，避免把输入时损坏误归为 WAL 修复失败。新候选的 9 组恢复均与普通写入控制一致；后续另抽种子重复该矩阵。

VARIANT 的 13 种全 NULL 前置类型、两种块顺序使用两版哈希相同的 WAL；新候选 26 组均恢复原始值。进一步在新候选上测试 31/1021 个 NULL 块、匹配/异类型前缀、有值在前、全 NULL，以及长前缀后 CRC 损坏。结果为 33 项 / 0 失败；损坏案例检查 0 行提交、WAL 保留，正确案例检查行数、NULL 数、键和所有有值对象。该数据属于有意拼接的故障注入，不冒称全部来自自然业务 WAL。时间记录包含启动与恢复，不把它当作纯 WAL 解码吞吐。 本组最大输入 394,618 字节。修复中的异型全 NULL 首块查找会额外顺序读取后续块；本轮未量化大体积生产 WAL 的额外 I/O 成本。

chunked 标签修复还通过普通重试、2PC prepare/commit/abort 以及两种部分更新标记的组合；新候选同 label 重试被拒绝，prepare 前不可见、commit 后逐值正确、abort 后无数据。旧版对应 chunked 分支仍丢失调用方 label。WAL 重放失败退避的 CRC 风暴探测两版均通过，和上面的“创建规划失败”是两条不同路径。

| 维度 | 本轮实际输入与变化 |
| --- | --- |
| 地址 | 随机 IPv4/IPv6，0/全 1 边界，IPv4-mapped IPv6，::/::1/link-local；另使用全 IPv6 FE/BE 的真实 ::1 TCP/MySQL/HTTP |
| 字符 | 中文、组合字符与预组字符、emoji、肤色/ZWJ/旗帜序列、引号/反斜杠/分隔符、Unicode 最大码点 |
| 隐藏字符 | NUL、Tab、CR/LF、ZWSP/ZWNJ/ZWJ、BOM、NBSP、WORD JOINER、行/段分隔、双向控制和其他控制字节 |
| 字节与文件 | 完整 0x00–0xFF、随机 0/1/2/31/255/257/4095 字节；JSON 中 Base64、Parquet/ORC 中原生 binary；逐字段 HEX 比较 |
| 格式 | UTF-8 JSONL、ASCII 转义 JSONL、gzip JSONL、引号 CSV、Snappy/Zstd Parquet、ORC；生成后 PyArrow 独立读回列式文件 |
| HTTP | Content-Length/chunked、FE 307/直连 BE、真实 Expect:100-continue、跨 CRLF/UTF-8 字节边界分块、文件流、标签重试、2PC、部分更新、中文/emoji 表名 URL |
| 畸形输入 | 非法 IP、整数溢出、损坏 CRC/压缩流/文件尾、非法/冲突长度、chunk 扩展/截断/尾部、无授权、非法方法 |
| SQL/恢复 | 独立 Python/Decimal/集合预期、变换等价性、NULL/空值/数值边界、真实异步 WAL 杀 BE 恢复、三节点故障及版本升级 |
| 性能 | 均匀键、热点、宽字符串；交替及反序版本顺序；新热点保留轮；文件性能 ABBA、1/4 并发，所有结果保留长尾 |

首轮文件为 257 行，保留轮为 131 行，性能文件为 4099 行；改变随机值、NULL/字节长度、IP、文件布局和数据量，不只改变测试执行顺序。HTTP 中的 `[::1]` Host 字面值与真实 IPv6 连接分别验证。最初 IPv4 FE/IPv6 BE 混合配置因地址族解析不能完成磁盘汇报，留作配置局限记录；全 IPv6 对照两版各 16 项通过，不把混合初始化失败当作全 IPv6 功能失败。


| 计划/数据 | 种子 | 实际参数 |
| --- | --- | --- |
| wire-primary | 696345 | 257 行，生成七种文件 |
| wire-holdout | 473977 | 131 行，生成七种文件 |
| wire-performance | 898416 | 4099 行，生成七种文件 |
| wire-performance-gzip-holdout | 102249 | 8191 行，生成七种文件；本追加仅测 gzip |
| initial-1 | 336387 | 400003 行；4093 组；热点 None；宽字符串重复 None |
| initial-2 | 398923 | 400003 行；4093 组；热点 0.9；宽字符串重复 None |
| initial-3 | 570980 | 150007 行；5003 组；热点 None；宽字符串重复 32 |
| wide-holdout | 372773 | 250013 行；15013 组；热点 None；宽字符串重复 73 |
| skew-repeat | 398923 | 400003 行；4093 组；热点 0.9；宽字符串重复 None |
| skew-holdout | 588127 | 600011 行；4093 组；热点 0.9；宽字符串重复 None |
| 首轮功能 / 第二组数据 | 842426 / 850345 | 每组 2053 行；独立数值与集合预期 |
| 嵌套恢复 / 类型矩阵 | 585010 / 560224 | 首批 NULL 位置、类型与块大小变化 |
| 扩展缺陷控制 | 368938 | SQL 构造、gzip 前缀、转义、部分更新、HTTP 语法 |
| 规划重试 | 619862 | 97 / 784 / 1634 / 3500 ms |
| ASAN 起始种子 | 47403 / 96731 | 各跑 3 轮、种子逐轮递增；仅改变执行顺序，不称新用例 |


两轮热点负载都实际抽到 90% 热点、4093 组；本轮改变的是 400003→600011 行和查询参数，不宣称覆盖了多个热点比例或热点组数。宽字符串则实际由 32 次重复变为 73 次，并改变行数和分组数。

所有功能保留轮、性能追加轮、待重放升级及嵌套保留轮的完整种子见 [主执行计划](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/pipeline-plan.json)、[保留轮计划](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/holdout-plan.json)、[扩展计划](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/extended-plan.json)。保留轮种子在前轮完成后生成；性能热点形状按预先声明的行数/热点比例抽取，不根据测得快慢筛选种子。发现失败后继续保留原样例，再改变数据/路径做控制，没有用能通过的新输入替换失败记录。

## 查询性能

共 6,496 次计时查询、960 次预热，6 组成对负载、48 个查询组合。SQL/query cache 关闭，查询顺序随机；前四组每查询 10 轮预热、51 轮计时，后两组 10/101。结果不仅新旧哈希相同，还用 Python 整数、集合、UTF-8 字节数和 ROW_NUMBER 求和恒等式核对 96 个版本结果，0 不符。

下表为新候选相对旧版的中位延迟变化，正值为变慢。不同数据形状不能跨列直接比较绝对时间；绝对 p50/p95、全部样本与统计区间保留在 CSV/JSON。


| 查询 | 均匀键 | 初轮热点 | 宽字符串 | 宽表保留轮 | 同热点反序 | 新 90% 热点 |
| --- | --- | --- | --- | --- | --- | --- |
| distinct | +2.1% | +0.3% | +0.3% | -0.1% | +1.5% | +0.9% |
| group | +1.0% | +3.4% | +0.0% | -0.7% | +0.5% | +0.5% |
| join | +1.0% | +2.8% | +0.4% | -2.8% | +0.1% | +0.2% |
| scan_sum | +3.5% | +2.3% | -0.5% | -2.3% | +1.1% | +0.9% |
| selective | +1.0% | +2.0% | +0.0% | -1.0% | +0.3% | +0.1% |
| string | +1.6% | -1.3% | +0.1% | -4.5% | +2.5% | -0.0% |
| topn | +0.0% | +0.7% | +1.7% | -3.7% | -0.1% | +0.8% |
| window | +2.8% | +2.2% | -3.8% | -1.3% | +0.7% | +0.0% |


前四组成对负载的中位延迟变化约为 −4.5%～+3.5%；同一热点种子反转版本顺序后为 −0.1%～+2.5%，新增 600011 行负载约为 0%～+0.9%。本轮未观察到大幅、并在追加轮保持的查询慢化；测到的小幅差异仍如实保留，不能在共享主机上直接归因于代码变化。新旧结果一致并通过独立预期校验，因此这些查询时间属于有效样本。

统计区间为单轮样本自助法区间，不包括共享主机漂移、轮次相关性和有限实例次数的不确定性。没有剔除慢样本，也未测独占机器、冷页缓存、长期饱和负载或生产分布；小幅差异不等同稳定产品回退。

![查询延迟比较](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/query-performance.png)

数据：[查询比较 CSV](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/benchmark-comparison.csv)、[p50/p95、区间、CPU/内存/负载](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/benchmark-comparison.json)、[独立预期核对](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/benchmark-independent-oracle.json)；[可导出 SVG](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/query-performance.svg)。

## 文件导入与 HTTP 性能

文件性能使用首轮结束后生成的 4099 行相同输入，旧→新→新→旧四次独立实例，三种格式/传输组合、1/4 并发、每组合 2 轮预热和 9 轮计时。共 540 个计时请求、120 个预热请求，所有返回行数及最终六列值、副本数准确核对。MiB/s 使用线上文件实际字节，压缩与未压缩格式不能直接跨行比较。


| 文件 / 并发 | 旧版中位 MiB/s | 新版中位 MiB/s | 变化 | 旧/新含全部停顿 MiB/s | 旧/新请求 p95 ms |
| --- | --- | --- | --- | --- | --- |
| gzip-json-fixed / 1 | 53.6 | 38.2 | -28.8% | 53.9 / 40.3 | 50.9 / 98.5 |
| gzip-json-fixed / 4 | 163.8 | 169.0 | +3.2% | 143.1 / 141.6 | 103.5 / 121.0 |
| json-chunked / 1 | 80.0 | 73.3 | -8.4% | 68.6 / 65.1 | 82.6 / 98.2 |
| json-chunked / 4 | 196.3 | 261.0 | +32.9% | 165.0 / 220.5 | 102.8 / 112.8 |
| parquet-zstd-fixed / 1 | 66.4 | 75.6 | +13.9% | 61.9 / 68.5 | 61.1 / 61.0 |
| parquet-zstd-fixed / 4 | 133.5 | 165.5 | +24.0% | 133.3 / 168.9 | 119.5 / 86.5 |


首轮 ABBA 中，四并发 JSON 与 Parquet 的中位吞吐分别高约 32.9% 和 24.0%，单并发 gzip 则低 28.8%。各实例存在明显波动：单并发 JSON 的旧版两轮约 53.4/95.5 MiB/s，新版约 99.2/51.9；不能只根据合并中位数声称普遍提升或退化。gzip 单并发慢化因此追加复测，见下表。


针对首轮单并发 gzip 慢化追加：相同 4099 行文件按新→旧→旧→新复测，再用新种子的 8191 行文件作旧→新对照；每实例 10 轮预热、51 轮计时。追加 306 个计时请求、60 个预热请求，全部逐字节/副本数核对通过。原来的慢样本保留。

| gzip 单并发追加组 | 旧版中位 MiB/s | 新版中位 MiB/s | 中位变化 | 旧/新总体 MiB/s | 旧/新 p95 ms |
| --- | --- | --- | --- | --- | --- |
| same-file-BAAB | 53.1 | 43.5 | -18.0% | 46.6 / 42.0 | 84.4 / 87.4 |
| fresh-8191-rows | 72.2 | 66.9 | -7.3% | 66.0 / 65.3 | 110.4 / 106.4 |

**P2-4：gzip 单并发保留慢化疑点，尚未定位为稳定代码回退。** 加长预热、反序同文件复测后，新版合并中位吞吐仍低 18.0%，含全部停顿的总体吞吐低 10.0%；新 8191 行文件分别低 7.3% 和 1.0%。同文件单实例中位数旧版为 44.7/53.5 MiB/s，新版 40.5/53.0，轮次间差异很大。新数据对照的服务端 WriteDataTimeMs 中位数为 48→51 ms、CommitAndPublishTimeMs 为 19→18 ms，仅能提供定位线索，不能据此确认瓶颈。全部数据正确。该信号不能被首轮其他格式提速抵消，也不能把共享主机和少量独立实例的结果直接外推为生产退化比例；后续归因需独占环境与更长持续负载。


每个版本只有两个独立实例、同一台共享主机，表中中位批次吞吐与“计时总字节/总耗时”一起报告，避免掩盖停顿。chunked 列式输入受 P1-2 影响，未把其“成功零行”的速度作为有效导入性能。另有 1536 次 8 并发小批写入，直连 BE 和经 FE 分开记录；该部分每实例批次数少，只作为容量观察，不能代替 ABBA 文件测量。

**P2-3（两版共有）**：requests 客户端的 FE 重定向 drain 延迟仍存在，两版都约 1 秒；drain 上限设 0 的定位控制显著缩短延迟；该控制不表示已验证所有慢客户端和连接复用下关闭 drain 都安全。FE 只收 307、不跟随至 BE 的容量结果如下（每种并发三轮中位数；不是数据库写入吞吐）：


| 并发 | 旧版请求/s | 新版请求/s | 旧版 p95 ms | 新版 p95 ms |
| --- | --- | --- | --- | --- |
| 64 | 63.0 | 63.0 | 1,009.4 | 1,009.1 |
| 192 | 185.5 | 185.8 | 1,013.1 | 1,015.6 |
| 384 | 152.3 | 361.7 | 2,976.0 | 1,025.0 |


384 并发时，新版中位处理能力为 361.7 请求/秒，旧版 152.3，提高 137.4%；p95 从 2976.0 ms 降至 1025.0 ms。64/192 并发差异较小。此项对应旧基线到此前候选已包含的 Jetty 线程配置修复，不是本次 2f 提交新增的吞吐优化。请求没有跟随重定向，目标表仍为空。



## 并发、故障、升级与其他模块

| 观察 | 旧版 | 新候选 |
| --- | --- | --- |
| 180 秒混合压力已确认写入 | 20857 | 22292 |
| 混合压力返回错误数 | 0 | 0 |
| 三 BE 故障检查 | 48 项 / 0 失败 | 48 项 / 0 失败 |
| 三 FE 选主检查 | 3 项 / 0 失败 | 3 项 / 0 失败 |
| FE 选主恢复秒数 | 1.9 | 2.0 |
| 空 INSERT 后 PENDING 指标 | {'before': 0, 'after_empty': 150, 'after_http': 166, 'after_clean': 166} | {'before': 0, 'after_empty': 0, 'after_http': 0, 'after_clean': 0} |
| 真实旧 WAL 升级 | 五类输入、异步成功后尚未可见 | 全部类型叶子字段准确恢复，剩余 WAL 数 0 |
| Python SQL 端到端 | 此旧版尚无新增运行环境 | 18 项 / 0 失败 |

压力覆盖 8 写入线程、CLEAN LABEL/SHOW LOAD 和 metrics 并行，再逐行核对确认写入；有循环建删表与事务错误路径。节点故障保留切换瞬间失败和“错误响应后实际可见”的不明确提交记录，不能把它们算成成功写入后丢失。180 秒及资源采样不足以证明不存在长期泄漏。

已落表升级的 14 表、2,150 行逐值相同；真实待重放升级另用新种子，在旧版异步写入成功、数据尚未落表时终止 BE，再替换新 FE/BE，逐叶子字段检查五种类型。该升级通过使 STRUCT 修复得到实际升级窗口的验证。

Python SQL 在本轮新构建 BE 上复测标量/pandas UDF、UDAF、UDTF、窗口、异常及异常后服务恢复，以及环境变量清理。UI、Python 打包脚本、回归框架源码在 `b31→2f` 未变化；上一轮 UI 生产构建/浏览器、35+1 打包辅助、17 项 Python 脚本及 7 项框架测试仅作为已封存历史证据，本轮没有将它们重新计数。整个 UI 业务和外部系统联调不是本轮覆盖范围。

## 执行口径、未覆盖范围与证据

FE 单位测试有 3 个既有 @Ignore：ShowExecutorTest.testDescribe、CopyLoadPendingTaskTest.testContinuationToken、CopyIntoTest.testUpload。SQL 回归选择 insert_p0、load_p0/http_stream、load_p0/clean_label；旧版框架 60/60 成功；新版初次整组 59 成功、1 失败。3 个 Docker 主体及 1 个 cloud 主体条件未执行，每版实际 56 个主体。单 BE 框架强制单副本；三副本故障由独立三 BE 探测覆盖。详见 [回归主体核对](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/regression-reconciliation.json)。

新版初次整组失败为 `test_group_commit_replay_wal` 的全局 `wal_total_count=0` 断言。该用例本身的 WAL 在 20:44:12 已重放并删除、8 行恢复；残留计数来自前序 `test_group_commit_timeout` 的 300000 ms 提交间隔。日志定位该独立表的 WAL 事务 207：20:41:29 创建，20:46:29 按 5 分钟间隔结束，后续发布故障注入解除后于 20:46:37 删除，指标归零；原断言的 100 秒等待在 20:45:55 已结束。旧版同一断言也等待约 94 秒才归零，说明边界与整组执行时序相关。

在干净实例中不改原用例进行单独复测，1/1 通过；结果见 [隔离复测与原失败核对](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/regression-followup-reconciliation.json)。这是前后用例共享全局状态导致的测试干扰，不是该重放文件未恢复；整组 59/60 的原结果保留，不将重跑结果回填为初次全绿。文件/表 ID 和逐条日志证据见 [失败现场与其他表 WAL 时间线](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/regress-new/wal-count-failure-snapshot)。

压力与回归的 WARN/ERROR 按来源保留并统计，见 [FE 日志分类](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/fe-log-triage.json) 和 [规划错误原因/时间段](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/repeated-plan-error-causes.json)。发布失败来自主动事务故障注入；还有进度元信息和 SHOW LOAD 读取不到表等警告，不能把框架通过写成‘日志无错误’，也不按警告行数计作缺陷数。

本轮初始失败原样保留，并作以下核对：

- 初始工具复制的记录路径指向上一轮，FE 单测准备在旧日志位置写入后立即停止；恢复上一轮原封存日志并重新核验全部旧清单与归档哈希。当前 R2 路径单独固定。
- 首次列式 chunked 导入等待预期行数超时，保留后改为同时检查返回行数和实际行数，继续矩阵；零行数据问题没有被改为通过。
- Python http.client 未真正等待 Expect:100-continue，在早期重复标签响应后继续发体导致 BrokenPipe；改用真正握手并保留原运行。该修正不改变已观测的零行或标签问题。
- 首次 2PC 检查器误读大小写 status，后续独立控制修正并验证 commit/abort；原检查的这部分断言标记为被替代，而非产品失败。
- IPv4 FE/IPv6 BE 初始化失败单独保留，随后全 IPv6 配置通过；不能用前者报告全 IPv6 不支持。
- 为追加隔离回归而重启调度器时，WAL 长前缀子进程已经启动并继续完成；重复启动被既有实例保护拒绝，未并发启动数据库。9 个案例、33 项检查与实例清理均核对通过后接续执行，原子进程退出码未捕获，验证器退出状态与原始退出状态明确区分，见 extended-controller-correction.json。
- update_config 返回列表，初始检查器按字典读取而退出；在任何故障注入前修正。新版首次健康写入失败则是产品观察，已保留并通过相同种子测量最终恢复，未放宽配置隐藏结果。

没有运行全量 FE/BE/SQL 库存；未覆盖外部 S3/HDFS/JDBC/cloud 真实服务、跨主机网络分区、磁盘耗尽/掉电、24 小时以上稳定性、x86/64 KiB 页、TLS/HTTP2 和反向代理安全链。本文报错、校验失败和配置局限的归属仅限已验证输入及环境。

本轮只新增测试报告和审计工具/记录，未修复、提交、合并或部署产品。优先处理三项数据问题，再修正短超时退避与 HTTP 协议边界；修复验收需保留本轮失败文件，新增未见种子，并对存储字节、实际行数、NULL/子字段、重试语义和已确认 WAL 逐项校验。性能也必须以结果正确为前提。

报告：[本报告](/data/project/massdb-sql/docs/massdb-sql-comparison-test-20261104-r2.md)。证据索引：[按缺陷归并的证据](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/findings.json)、[复杂场景汇总](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results/complex-summary.json)、[原始工具与每轮快照](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/tools)、[原始结果与服务日志](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/results)。

复现应复制工具到新的记录目录并修改 cluster.py 的 RECORD，继续固定两版包路径和输入文件哈希，每次仅启动一个隔离集群。既有运行目录拒绝覆盖；封存目录不得重跑写入。每轮实际命令在 pipeline/extended/performance-followup 的 plan 与 progress JSON 中，原输入与期望字节在 manifest/case JSON 中。

封存包包含本报告快照、测试工具、输入/预期/输出、WAL、日志、性能 CSV/SVG、源码与二进制身份，不包含大型产品二进制或临时数据库安装。旧包位于上一轮 artifacts/old，新包位于本轮 artifacts/new。临时实例已停止并删除；构建工作树保留用于按提交查阅代码。

[证据包](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/evidence-http-complex-20261104-r2.tar.zst) · [SHA-256](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/evidence-http-complex-20261104-r2.tar.zst.sha256) · [逐文件封存核验](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r2/evidence-verification.json)。

