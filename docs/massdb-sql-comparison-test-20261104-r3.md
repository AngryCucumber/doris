# MassDB SQL 同分支新旧版复测报告（2026-11-04～05，R3）

**结论：已完成本报告列明的功能、边界、故障恢复、并发、升级及性能矩阵；当前候选仍不建议按“无数据完整性问题”验收。** 本轮修复有效：chunked 列式文件空导入、已测 gzip 等压缩流截断提交、上一轮短超时恢复回归已修复。仍确认两类 P1 数据问题：嵌套 JSON 转义改变存储字节、LZO 在完整块边界截断后被当成完整文件。另有阻塞 RPC 超时、HTTP 协议兼容问题；gzip 文件吞吐/尾延迟仍有未排除的退化信号。

“完整”指下面明确列出的矩阵，不能理解为穷尽全部输入、执行全仓库测试或达到生产长稳验收。结果包含通过和失败；没有修改产品实现来迎合测试。旧新比较始终使用用户确认的同一分支基线。

## 版本、构建及环境

| 角色 | 固定提交 | 证据口径 |
| --- | --- | --- |
| 旧版 | `49f67bdbb94b941574dbd6b9463eefdd163a84bd` | 用户确认的同分支最早状态；复用封存发行核心，运行前后重新核验哈希 |
| 上轮候选 R2 | `2f21ee3907045c73bba8c8d0e5c59856beda7e1a` | 仅用于说明历史问题是否修复，不混入本轮性能表 |
| 新版 R3 | `ea1b8daffa9f8646563fef5e44d8572c2e4e0763` | 主分支已合入的新修复；本轮重新构建 FE/BE Release 核心 |
| 修复及 ASAN 构建源 | `69c1dc307f0d96ab9701b5d35718c01c82d5d201` | 与 R3 的 be/fe/common/gensrc/cloud/thirdparty 源码一致，差别为合并及文档；构建后再次核验 |

相对 R2 共变动 15 个文件，其中 6 个产品源文件，集中于规划重试、Stream Load 文件长度及压缩流结束状态；本次没有新增 FE 产品实现变化。两个比较版本均来自这个 4.1.5 内核分支；本报告不推断其他 4.0.5 部署行为。

环境：ARM64、10 vCPU、19.47 GiB RAM、8 GiB swap、4 KiB 页；JDK 17.0.2、Clang 20.1.8；FE 堆 1536 MiB，单 BE 配置内存上限 4 GiB。数据库测试实例串行使用独立目录和测试端口。计时阶段等待编译完成；早期功能阶段与编译重叠，其耗时不作为性能结果。主机还有其他服务及审计活动，因此统计区间不能覆盖所有主机负载漂移。

Release 使用 headless 构建，未重建 UI 和未变化的 Java 扩展依赖；不将核心构建冒称完整安装包的全部组件重建。旧 FE 单测及此前 UI/打包结果为历史证据，本轮没有把它们再次计数。

| 二进制 | 旧版 SHA-256 前 16 位 | 新版 SHA-256 前 16 位 |
| --- | --- | --- |
| fe/lib/doris-fe.jar | 1ae1c0f45a497060 | 6b7413bba140a513 |
| fe/lib/fe-common-1.2-SNAPSHOT.jar | d34ed022b65c3faf | 0ef18ea844320f09 |
| be/lib/doris_be | f65898bbf66b98cb | 739ab3346fb4bc74 |

完整哈希及构建身份：[二进制清单](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/provenance/binary-identity.json)、[ASAN 源码一致性](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/provenance/native-build-source-verified.json)。本轮 98 个带运行身份记录的实例均与固定包匹配。R1/R2 已封存档案哈希未变，见 [历史证据核验](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/provenance/previous-sealed-archives-verified.json)。

## 仍存在的问题及影响

| 编号 | 级别 | 触发条件与实际影响 | 旧版 | R3 新版 |
| --- | --- | --- | --- | --- |
| D1 | P1 | 嵌套 ARRAY/STRUCT/MAP 的 JSON 字符串转义被错误还原，返回成功但存储字节变化 | 复现 | 复现，历史问题未修复 |
| D2 | P1 | LZO 流恰好停在完整块边界、缺少结束标记，返回成功并导入前缀 | 复现 | 复现，本轮扩展输入发现 |
| T1 | P2 | FE 规划 RPC 阻塞时，短规划超时不能中断正在执行的 RPC | 复现 | 复现，与已修复的退避恢复问题不同 |
| H1 | P2 | 部分非法 HTTP 首部/长度组合被接受，部分合法 chunked 形式被拒绝 | 复现 | 复现 |
| H2 | P2 | 非法 UTF-8 输入虽被拒绝，错误响应却含原始非法字节，严格 JSON 客户端无法解析 | 复现 | 复现 |
| F1 | 待归因的性能风险 | gzip 首轮单并发及大文件保留轮出现吞吐下降、尾延迟变差 | 对照 | 尚不能排除退化，不声称已证实由某个提交引入 |

优先级按影响划分；原始失败断言数不是独立缺陷数。未发现上述数据问题由本轮 69c1/ea1b 修复新增：D1、D2、T1、H1、H2 都有相同输入的旧版对照。

### D1：嵌套 JSON 的字节保真仍失败

28 项定向转义断言每版均有 20 项失败。Tab 的 `09` 变为文字 `t` 的 `74`；CRLF 的 `0D0A` 变为 `rn` 的 `726E`；NUL 的 `00` 变为 `u0000` 的 `7530303030`。ASCII 转义形式的部分中文、emoji 也不能正确还原。顶层 STRING 对照正确，嵌套字符串受影响。

最小 SQL，使用 UNHEX 避免 SQL 字面量先处理转义：

```sql
SELECT HEX(element_at(CAST(UNHEX('5b225c74225d') AS ARRAY<STRING>),1));
-- 输入 JSON 为 ["\t"]；预期 09，两个版本实际均为 74。
```

新旧版的嵌套 JSON + WAL 两轮各有 12/63 个失败断言，其中导入对照本身已经损坏。另用 SQL 的 UNHEX/named_struct 直接构造正确叶子值：旧版仍有 6/63 个 WAL 恢复失败，新版 63/63 通过。由此区分“输入解析已损坏”与“WAL 再次丢字段”；不能把前者全部归给 WAL，也不能因为新版回放与输入一致就说字节正确。

证据：[旧版转义](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/nested-escape-old/checks.json)、[新版转义](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/nested-escape-new/checks.json)、[SQL 构造恢复对照](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/nested-sql-new/checks.json)。相关 JSON 字符串反序列化路径：[DataTypeStringSerDe](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/provenance/source/be/src/core/data_type_serde/data_type_string_serde.cpp:365)。

### D2：LZO 完整块边界的截断仍可静默提交

测试从同一个 463 行文件产生完整控制和截断输入。将每行对齐到 32 KiB 后，在两个 256 KiB 解压块结束处截断，得到 55,559 字节的残缺 LZO；HTTP Content-Length 与实际上传字节一致，排除了 HTTP 本身少收字节。

| LZO 输入 | 独立 `lzop -t` | 旧版结果 | 新版结果 |
| --- | --- | --- | --- |
| 完整文件 / 对齐后的完整文件 | 成功 | Success，463 行准确 | Success，463 行准确 |
| 去掉最后 4 字节结束标记 | unexpected end of file | Success，463 行 | Success，463 行 |
| 两个完整块后截断 | unexpected end of file | Success，16 行 | Success，16 行 |

固定长度与 chunked 两种传输都复现。第二种残缺输入只含原始数据的 16/463 行，却被当作成功导入，后续 447 行没有出现。正确行为应是识别残缺压缩流并失败，而不是给出完整成功语义。新版 8 个失败断言对应这 4 次错误接受。

独立验证与原始响应：[lzop 检查](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/lzo-standard-validator.json)、[LZO 块布局](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/artifacts/codec-primary/lzo-block-layout.json)、[新版压缩矩阵](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/codec-matrix-new/codec-results.json)。定位依据：[LzoDecompressor](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/provenance/source/be/src/util/lzo_decompressor.cpp:194)在解出每个完整块后设置 `stream_end=true`；[文本行读取器](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/provenance/source/be/src/format/file_reader/new_plain_text_line_reader.cpp:520)在输入 EOF 处依赖这一状态。因此“块结束”会被当作“流结束”。这是结合实测和源码的原因判断。

### T1：要区分两种“短超时问题”

**上一轮的退避恢复问题已经通过复测。** 在 FE 快速拒绝规划时，旧版密集重试，新版执行退避。R2 曾残留退避状态，导致故障解除后的首个短超时写入失败；R3 已重置新等待者的退避状态，并将等待任务的检查时间限制到其超时点。新随机超时与原失败超时均重新执行。

| 配置超时 ms | 旧版规划次数 | 新版规划次数 | 旧/新最慢失败返回 ms | 新版故障解除后首写 |
| --- | --- | --- | --- | --- |
| 125 | 39 | 3 | 187.6 / 198.8 | 21.4，成功 |
| 815 | 423 | 5 | 827.3 / 826.9 | 8.4，成功 |
| 1656 | 1805 | 7 | 1664.1 / 1665.4 | 10.3，成功 |
| 3500 | 5946 | 8 | 3507.1 / 3508.5 | 9.7，成功 |

每档有 4 个并发等待者。保留的 97/784/1634/3500 ms 原问题档位在新版 36/36 断言通过，首个恢复写入均成功；默认 120000 ms、禁用该超时（0）、KILL QUERY 后恢复也有单独控制。

**仍有另一种共有问题：超时不约束正在阻塞的 FE RPC。** 配置 `group_commit_create_plan_timeout_ms=363`，通过 `FE.FrontendServiceImpl.initHttpStreamPlan.block` 阻塞规划；超过 363+350 ms 后请求仍未返回。解除阻塞后，旧版约 2010.2 ms、新版约 2013.4 ms 返回成功，数据与成功响应一致；期间 SELECT 1 正常。每版 13 个模式断言仅这一项失败。

影响是配置不能作为这个路径的严格请求截止时间；调用方若用自己的超时进行重试，需要注意原请求可能随后成功。该结果并不表示全服务卡死，也不是 R2 的“故障恢复后退避未清除”。

证据：[新随机超时](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/plan-retry-new/retry-results.json)、[原超时档位](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/retry-retained-new/retry-results.json)、[阻塞/取消/默认设置](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/retry-modes-new/retry-modes.json)。源码中 [正在规划时的提前返回](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/provenance/source/be/src/load/group_commit/group_commit_mgr.cpp:371)位于超时检查之前，[FE RPC 调用](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/provenance/source/be/src/load/group_commit/group_commit_mgr.cpp:557)仍使用 10000 ms RPC 超时；这解释了短配置无法及时唤醒当前等待者。

### H1/H2：HTTP 兼容及错误响应

本轮通过原始 TCP 报文验证分帧与连接状态，而非只通过高级 HTTP 客户端。新旧版均出现：带空格的首部名、冲突 Content-Length 可被接受；Transfer-Encoding 与 Content-Length 同时存在时连接未按预期关闭，继续请求的控制也保留；合法 chunk extension/trailer、大小写混合 `ChUnKeD` 不能正常处理。新版主 wire 矩阵 9 个失败、定向边界矩阵 5 个失败属于这些协议断言，不应误读为 14 种独立数据问题。没有据此证明真实代理链中的请求走私利用。

判定依据是 HTTP/1.1 的分帧和连接要求、chunk 扩展规则及首部名规则：[RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3)、[RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1)。

非法 UTF-8 JSON 输入被两版拒绝，表内保持 0 行；但错误正文原样包含非法 `C0` 字节，严格 UTF-8/JSON 解码失败，旧版失败偏移 825、新版 824。HTTP 状态仍为 200，Content-Type 为 text/html;charset=ISO-8859-1。这里是错误接口的编码问题，不是错误记录成功入库。

原始请求与响应：[主 HTTP 矩阵](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/wire-new)、[协议边界](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/http-boundary-new)、[非法 UTF-8 字节证据](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/invalid-utf8-response-observation.json)。本轮所查响应集合未再观察到负数 ReceiveDataTimeMs，见 [计时字段审计](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/response-counter-anomalies.json)；该结论限于所查记录。

## 已修复行为及压缩完整性覆盖

| 行为 | 旧版 | R3 新版 |
| --- | --- | --- |
| Parquet Snappy/Zstd、ORC 的 chunked 文件导入 | 可 Success 但 0 行 | 521 行首轮、193 行新种子轮均逐字段准确 |
| chunked SNAPPY_BLOCK CSV | 合法输入可空导入 | 完整及无末尾换行输入均准确 |
| chunked 标签重复、两阶段提交、部分更新 | 存在重复写入/语义丢失 | 本轮相应定向断言通过 |
| gzip 少尾部 ISIZE/CRC、完整记录前缀后截断 | 可成功写入 521 或 127 行 | 拒绝，0 行 |
| 简单 STRUCT 及 SQL 构造的嵌套 WAL | 子字段恢复异常 | 已测叶子值准确 |
| VARIANT：13 种 NULL 类型 × 两种块顺序 | 2 正确、23 报错保留 WAL、1 BE 崩溃保留 WAL | 26 组均逐值正确；布尔与整数按类型核对 |
| 空 INSERT / HTTP 导入的 PENDING job 计数 | 0→150→166，清理后仍 166 | 0→0→0，清理后 0 |

文件长度修复位于保存非流式文件后、提交执行前，使用真实 receive_bytes 更新扫描范围。它解决的是实际文件长度为 0 的扫描问题。恢复修复仍通过实际杀进程和 WAL 重放验证，不只靠单元测试或序列化往返。

定位及证据：[保存后文件长度](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/provenance/source/be/src/service/http/action/stream_load.cpp:851)、[复杂文件首轮/保留轮](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/complex-summary.json)、[VARIANT 逐值核对](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/wal-matrix-reconciliation.json)。

8 种压缩格式、53 个物理文件，每版固定长度/chunked 共 106 次上传、318 个断言。输入含完整文件、无末尾换行、短头、截尾、随机中间截断；支持拼接的格式另测多成员及末成员截断。每个合法输入逐字节核对；非法输入同时检查拒绝和表内为空。

| 压缩格式 | 旧版合法准确/总数 | 旧版错误接受/非法总数 | 新版合法准确/总数 | 新版错误接受/非法总数 |
| --- | --- | --- | --- | --- |
| BZ2 | 6/6 | 4/8 | 6/6 | 0/8 |
| DEFLATE | 4/4 | 4/8 | 4/4 | 0/8 |
| GZ | 6/6 | 6/10 | 6/6 | 0/10 |
| LZ4FRAME | 6/6 | 4/8 | 6/6 | 0/8 |
| LZ4_BLOCK | 4/4 | 0/6 | 4/4 | 0/6 |
| LZO | 6/6 | 8/10 | 6/6 | 4/10 |
| SNAPPY_BLOCK | 2/4 | 3/6 | 4/4 | 0/6 |
| ZSTD | 6/6 | 2/8 | 6/6 | 0/8 |

这张表体现修复范围：新版压缩矩阵只剩 LZO 的 4 次错误接受，不能笼统写成“所有压缩完整性已修复”。独立标准解码器、文件哈希及生产端预期全部保留。

另有大批量失败原子性控制：8197 行完整输入/6007 行残缺前缀，以及 45007 行完整输入/24593 行残缺前缀；分别覆盖 off/sync/async 三种模式，并将最后 16 字节延迟 350 ms。sync/async 响应带 GroupCommit=true。新版 36/36 断言通过：完整文件全量准确，6 个残缺输入均失败、0 行，BE 突然重启后仍为 0 行；旧版 18/36 断言失败，残缺前缀被成功写入。这里覆盖了 10000 行配置阈值上下的输入，不据此证明所有调度时序、所有更大输入均具有同样行为。

证据：[压缩文件与标准控制](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/artifacts/codec-primary)、[大批量失败与重启](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/compressed-atomicity-new/atomicity.json)、[有效缓冲配置](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/compressed-atomicity-new/buffering-config.json)。

## 测试范围、变化策略及原始失败归因

输入覆盖真正 IPv4/IPv6 地址类型和 ::1 网络连接；0.0.0.0、255.255.255.255、::、全 1 IPv6、随机地址；字节 00～FF、随机二进制、文件句柄上传；中文、emoji/肤色/ZWJ 组合、引号、反斜杠、Tab、CRLF、NUL、BOM、零宽字符、双向控制符、组合音标。既比较显示字符串，也比较 HEX/长度/类型、NULL 与空值、行数及重复副本数。

HTTP 覆盖 FE 307→BE、直连 BE、Expect:100-continue、Content-Length/chunked、跨 UTF-8 字节的随机分块、重复 label、提交/撤销、部分更新、截断、非法编码及畸形首部。JSON/转义 JSON/gzip/CSV/Parquet/ORC 使用相同逻辑预期。故障覆盖实际 BE 杀进程、待重放 WAL、FE 规划拒绝/阻塞、查询取消、BE 节点损失、FE 选主、已落表及待恢复数据升级。

随机参数在测试前记录，旧新复用完全相同输入；首轮后再生成未见过的保留输入。变化不止种子，还包括行数、倾斜度、基数、字符串长度、文件布局、NULL 形态和执行顺序。独立 Python 数值/字节预期和代数等价关系用于防止“两版一样错”。固定最小复现保留，新增输入不会覆盖旧失败。

| 输入组 | 本轮种子/规模变化 |
| --- | --- |
| 普通 SQL 首轮→保留轮 | 403916→528634，每轮另有内部派生种子 |
| HTTP 文件首轮→保留轮 | 559360 / 521 行→820460 / 193 行 |
| 压缩矩阵 | 607682 / 463 行，新增精确 LZO 块边界 |
| 嵌套列式文件 | 103967；0/1/263 行，多 row-group/page/dictionary/codec 组合 |
| SQL 宽字符串保留轮 | 494330 / 150007 行，重复长度改为 59 |
| SQL 倾斜保留轮 | 444034 / 600011 行、997 基数、80% 热点；首轮为 500009 行、509 基数、70% 热点 |
| 文件性能首轮→保留轮 | 275312 / 4099 行→939463 / 12289 行，ABBA→BAAB |
| ASAN 随机顺序 | 48186～48188、63157～63159；48 个不同用例各执行 6 次 |

主要执行结果如下。这里的“项”是断言数，可能一项检查所有行的多个字段；不能与单位测试数量相加得到统一覆盖率。

| 测试组 | 旧版 | R3 新版 |
| --- | --- | --- |
| 普通功能，首轮+保留轮 | 718，0 失败 | 724，0 失败 |
| 独立类型预期 | 24 通过 | 24 通过 |
| FE 所选单测 | 历史 516：513 通过、3 跳过 | 本轮 569：566 通过、3 跳过 |
| BE ASAN 所选单测 | 本轮未重跑旧版 | 48 个不同用例 × 6 轮 = 288 次通过，无 ASAN/LSAN 错误 |
| 主 HTTP 文件/协议 | 148 / 33 失败 | 148 / 9 失败，协议项见 H1 |
| 新种子 HTTP 文件 | 70 / 20 失败 | 70 / 0 失败 |
| 实际 IPv6 | 16 / 0 失败 | 16 / 0 失败 |
| 两阶段提交 | 28 / 4 失败 | 28 / 0 失败 |
| 部分更新矩阵 | 40 / 8 失败 | 40 / 0 失败 |
| 列式固定长度/chunked 开关组合 | 16 / 4 失败 | 16 / 0 失败 |
| 简单 STRUCT WAL | 5 / 1 失败 | 5 / 0 失败 |
| SQL 构造嵌套 WAL | 63 / 6 失败 | 63 / 0 失败 |
| 嵌套 JSON+WAL 两轮 | 126 / 24 失败 | 126 / 24 失败；输入转义归因 D1 |
| 新增长 NULL 块前缀 WAL | 未单独执行 | 31/1021 块前缀、9 场景、33 断言通过 |
| 已落表数据升级 | 作为来源 | 14 表、2150 行，67 断言通过 |
| 待重放 WAL 升级 | 作为来源 | BIGINT/ARRAY/MAP/STRUCT/VARIANT，27 断言通过 |
| Python 运行时端到端 | 未新增执行 | 18 断言通过 |
| 仓库 SQL 回归 | 59/60 框架任务成功，1 失败 | 59/60 框架任务成功，1 失败 |
| 原失败 WAL 套件隔离运行 | 1/1 通过 | 1/1 通过 |

完整检查名、输入、响应和失败项见 [总结果](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/final-summary.json)、[所有断言汇总](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/assertion-summary.json)、[原始失败索引](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/failed-assertions-index.json)。

### 原生嵌套 Parquet/ORC：接口限制与生成器错误分别保留

初始测试直接把 ARRAY<STRUCT>/MAP/STRUCT 列式文件送入 Stream Load，成功预期超出了该接口支持范围。源码明确拒绝该组合并建议 TVF。新版 36 次上传中 28 次明确拒绝复杂类型；旧版只有 14 次拒绝，另有 12 次非空 chunked 文件错误返回 Success/0 行。新版原始 52 个失败断言、旧版 38 个不能直接拿来断言新版更差：其中有不适用的成功预期，且旧版空扫描会掩盖接口不支持。

改用支持的 Local TVF 后，PyArrow 20 的特定 `list<struct<int64,...>>` NULL/空容器 + Page V2 文件仍让两版各 4 个执行断言失败。最小 1 行文件中，物理页有 4 字节 levels、没有数值，却声明 num_values=1、num_nulls=0，使按元数据计算的长度成为 12。PyArrow 和 DuckDB 能读回，不足以证明元数据有效。

这与上游 [Arrow #51097](https://github.com/apache/arrow/issues/51097) 及 [修复 #51357](https://github.com/apache/arrow/pull/51357) 一致。独立解码页头后确认：同种子、同逻辑数据换用 PyArrow 26 写出时 num_nulls=1，计算长度与实际同为 4；263 行文件也从 num_nulls=0 修正为 2。原文件和修复生产端的文件均保留。新生产端的 0/1/263 行、Parquet 1.0/2.6 与 ORC、直接查询/INSERT 后逐叶子核对，新旧版各 36/36 通过；另有平面 scalar/list/struct × Page V1/V2 × 字典开关 × NONE/Zstd 的 24 个控制文件，两版各 24/24 通过。

因此这些 Page V2 失败归入生产端元数据问题与历史文件兼容观察，不计为本次数据库新增缺陷。Page V1/V2 是文件页格式；enable_file_scanner_v2 是引擎开关，两者不同。测试包含开关组合，但 Parquet 时间语义可能强制选择原生扫描器，不能凭开关值宣称覆盖了两套解码器。

依据：[Stream Load 能力检查](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/provenance/source/be/src/exec/scan/file_scanner.cpp:632)、[Parquet 页长度检查](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/provenance/source/be/src/format_v2/parquet/reader/native/column_chunk_reader.cpp:92)、[扫描器选择](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/provenance/source/be/src/exec/operator/file_scan_operator.cpp:157)。数据与归因：[接口/生产端归因](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/nested-columnar-attribution.json)、[独立页头及外部读取器对照](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/parquet-external-writer-diagnosis.json)、[修复生产端后的新版本结果](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/nested-tvf-arrow26-new/checks.json)。

### 仓库回归：两版原始全组均有 1 项失败，隔离结果单独报告

实际执行 `insert_p0,load_p0/http_stream,load_p0/clean_label`。框架各列出 60 个任务，其中 4 个主体因条件不满足没有执行：3 个依赖 Docker/FE 重启编排，1 个 Cloud HTTP 2PC。实际主体为 56 个，不能称全仓库或 60 个主体全覆盖。

两版失败均为 `test_group_commit_replay_wal` 的全局 wal_total_count 期望 0、实际 1。本轮重新从 WAL 创建/删除、FE 表元数据和事务日志关联：断言时唯一剩余 WAL 属于另一个 `test_group_commit_timeout` 表，该套件设置 group_commit_interval_ms=300000。回放测试自己的表已达到 8 行。

| 版本 | 本次断言观察时间 | 仍待提交的无关事务 | 该 WAL 删除时间 |
| --- | --- | --- | --- |
| 旧版 | 11-05 01:11:09 | txn 211 / table 1793811872424 | 01:11:53.440 |
| 新版 | 11-05 01:20:21 | txn 210 / table 1793812424546 | 01:21:09.010 |

原版套件在新建隔离集群分别重跑，两版均 1/1 通过。原全组 59/60 的失败不会被改写成全绿；这里属于套件共享全局计数的干扰，未据此发现新版 WAL 丢数。

完整关联包含原文件与精确行号：[回归失败归因](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/regression-failure-attribution.json)；[原始框架结果](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/regression-reconciliation.json)和 [隔离结果](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/regression-followup-reconciliation.json)分别保留。

## 并发、故障恢复与资源观察

180 秒、8 个写线程并行查询元数据/指标，旧版确认 20235 次写入、新版 23815 次，均 0 写错误，确认写入与实际数据核对通过；包含 12 次建删表周期。该单轮写入数不作为容量提升百分比。

3-BE 节点损失测试：两版均 70 次确认写入/70 行实际数据，切换期及稳态无错误；没有出现“报错却额外可见”的记录。3-FE 选主恢复约旧 1.972 秒、新 2.002 秒。已落表数据与待重放 WAL 升级均通过，未测试降级回滚。

FE HTTP 重定向容量使用 64/192/384 并发，各 3 轮；每版 384+1152+2304=3840 个请求均返回 307。384 并发时旧/新中位轮吞吐约 152.1/362.0 requests/s，轮 p95 约 2987.9/1027.9 ms。这里测的是重定向接口，不是完成导入的端到端吞吐。需要 drain 响应的客户端仍有约 1 秒等待，两版都有；不 drain 的客户端首部处理明显更快，不能混为一种客户端路径。

短压测中新版 BE 采样峰值 RSS 约 3668.7 MiB，旧版 3572.2 MiB；FE 从约 0.93 GiB 增至约 1.8～1.9 GiB。没有将缓存/预热增长判为泄漏，也不能凭 3 分钟测试排除长期泄漏。资源采样、线程数、CPU 时间、主机负载及失败日志均保留。

证据：[运行期汇总](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/runtime-summary.json)、[FE 日志分类](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/fe-log-triage.json)。故障注入的错误日志不直接等同于未处理的产品异常；旧版 VARIANT 的真实崩溃另有明确记录。

## 性能结果

### SQL 查询

6 组配对负载、8 类查询，6496 次正式计时与 960 次预热；前 4 组每查询每版本 51 次，后 2 组 101 次。旧新交替顺序，统一输入、配置及缓存设置；SQL/查询结果缓存关闭，计时包含客户端取结果。48 个查询组合两版输出一致，另用独立数值/分组/UTF-8 字节长度/行号求和预期核对 96 个版本结果，全部通过。

下表为新版 p50 延迟相对旧版的变化，负值更快；不能跨不同数据规模混合计算统一加速比。

| 查询 | 均匀 60 万 | 倾斜 50 万 | 宽串 25 万 | 宽串保留 15 万 | 同倾斜反序 | 新倾斜 60 万 |
| --- | --- | --- | --- | --- | --- | --- |
| distinct | -2.87% | +1.09% | -8.10% | -0.44% | +0.61% | +0.31% |
| group | -3.70% | +3.42% | +0.75% | -2.25% | -0.97% | -3.16% |
| join | -5.40% | -4.27% | -3.70% | -3.74% | -1.06% | +0.07% |
| scan_sum | -2.94% | -3.24% | -1.03% | -3.83% | -0.65% | -1.04% |
| selective | -5.80% | -0.82% | -1.59% | +0.80% | -1.21% | -0.66% |
| string | -1.74% | +3.19% | -1.88% | -4.00% | -0.72% | -3.03% |
| topn | +0.63% | +5.31% | -3.89% | -1.17% | -1.71% | -2.67% |
| window | +0.72% | +1.53% | -3.39% | -2.34% | -0.11% | -0.53% |

本矩阵未发现可重复的 SQL 查询退化。首轮倾斜数据中 topn 的 +5.31% 在反序重跑变成 -1.71%，新倾斜保留轮为 -2.67%；没有挑选首轮有利值或丢弃慢样本。组内 bootstrap 区间只估计该轮样本不确定性，不包括独立实例之间或共享主机负载漂移，不能当成生产性能保证。

[完整 p50/p95/条件区间 CSV](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/benchmark-comparison.csv)、[查询结果独立预期](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/benchmark-independent-oracle.json)。

![SQL 配对性能](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/query-performance.png)

### HTTP 文件导入

首轮每文件 4099 行，按旧→新→新→旧运行 4 个独立实例；每格式/并发组合 10 次预热、51 次正式批次。所有上传都核对成功及每份输入的逐字段字节和副本数。下表 MiB/s 按实际 HTTP 文件字节计算，因此 gzip/JSON/Parquet 数值不能跨格式直接比较。

| 文件 | 并发 | 旧 p50 吞吐 MiB/s | 新 p50 吞吐 MiB/s | 吞吐变化 | 旧/新请求 p95 ms |
| --- | --- | --- | --- | --- | --- |
| gzip-json-fixed | 1 | 77.78 | 71.19 | -8.47% | 84.3 / 87.4 |
| gzip-json-fixed | 4 | 211.94 | 221.15 | +4.35% | 151.8 / 121.3 |
| json-chunked | 1 | 133.90 | 134.43 | +0.40% | 79.5 / 89.2 |
| json-chunked | 4 | 291.60 | 325.69 | +11.69% | 122.7 / 104.2 |
| parquet-zstd-fixed | 1 | 97.31 | 121.21 | +24.56% | 88.1 / 59.7 |
| parquet-zstd-fixed | 4 | 216.57 | 220.25 | +1.70% | 123.7 / 124.4 |

![首轮文件吞吐及轮次波动](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/file-performance.png)

gzip 单并发首轮中位吞吐 -8.47%，但两个新版实例分别为 76.82/67.77 MiB/s，存在轮次波动。因此首轮后再换种子、放大到 12289 行/16,056,415 字节 gzip，顺序改为新→旧→旧→新，仍每组 10 次预热+51 次正式批次。

| 并发 | 旧/新 p50 MiB/s | 中位吞吐变化 | 旧/新总量÷总时间 MiB/s | 总体变化 | 旧/新请求 p95 ms |
| --- | --- | --- | --- | --- | --- |
| 1 | 118.30 / 116.62 | -1.42% | 113.52 / 103.69 | -8.66% | 167.4 / 211.9 |
| 4 | 297.98 / 278.15 | -6.65% | 251.79 / 224.09 | -11.00% | 280.9 / 308.5 |

大文件轮的单并发中位差缩小，但总体吞吐下降 8.66%、请求 p95 从 167.4 增至 211.9 ms；四并发中位下降 6.65%、总体下降 11.00%。旧四并发两个实例为 306.58/283.20 MiB/s，新版为 279.07/278.09 MiB/s。慢批次保留，没有截尾删除。文件首轮 3060 次正式请求、600 次预热；大文件补测再加 1020/200 次，总计 4080 次正式请求、800 次预热，数据和副本数全部准确。

**性能判定：查询矩阵通过；gzip 吞吐与尾延迟仍是未排除的风险。** 当前数据不足以把共享主机上的差异归因到某个代码改动，也不足以宣告“没有性能退化”。正式容量验收应使用独占资源和实际部署的数据分布验证这一项；原始有利和不利轮次均可审计。Parquet 单并发在本轮有收益，也只限于所测文件与路径。

首轮数据：[文件性能汇总](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/complex-summary.json)；扩大输入的复测：[gzip 保留轮及 p95](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/gzip-performance-holdout-summary.json)、[变更触发及执行顺序](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/adaptive-plan.json)。

## 覆盖限制与复现方式

未执行全仓库 FE/BE 单测与全量 SQL 回归；本轮选择修改路径及相关功能，旧版 FE 单测沿用 R1。未变化的 UI、发行打包不在本轮重建验收范围。未进行生产级长时间稳定性、GB/TB 级文件/数据集、真实跨主机网络分区、磁盘故障/满盘、长时 OOM、TLS/HTTP2、多租户权限及所有外部湖/云系统组合。3-FE/3-BE 为单机多进程，不能替代多机失效测试。

对所测 HTTP 模式、文件格式、复杂类型、NULL/数值边界及故障时序提供了实际结果，不能将未覆盖项当作通过。吞吐是这台共享主机的观察值，不是生产容量上限。P1 数据完整性问题应先修复；之后保留本次最小失败样例，并继续产生新种子、不同边界和新文件布局复测。

复现所需每条命令、参数、版本顺序、种子、输入哈希和工具快照均保留。测试脚本会拒绝覆盖已有实例结果。重跑应复制工具到新的审计目录、更新统一 RECORD，并给独立实例使用新名称；不要在本封存记录内重新执行写入型测试。一次只启动一个测试集群，产品包路径和哈希必须与记录一致。

主要入口：[主计划](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/pipeline-plan.json)、[扩展计划](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/extended-plan.json)、[后续控制计划](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/adaptive-plan.json)、[PyArrow 26 控制](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/arrow26-plan.json)、[工具及执行清单](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/tool-inventory.json)。独立 `lzop -t` 可以直接对 [保存的残缺 LZO](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/artifacts/codec-primary/LZO-whole-block-prefix.bin) 复验，D1 最小 SQL 如前。

## 报告与证据位置

本报告固定路径：`/data/project/massdb-sql/docs/massdb-sql-comparison-test-20261104-r3.md`。

本轮审计目录：`/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/`。上一轮 R1/R2 目录及压缩包保持原样。证据包含报告副本、工具及运行时快照、生成输入、期望值、原始响应、计时样本、日志、源文件定位和版本身份；排除运行中安装目录、产品二进制大文件及 Python 缓存。重跑依赖清单中的本地产品包，证据包不是独立可部署发行包。

交付文件：[证据压缩包](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/evidence-http-complex-20261104-r3.tar.zst)、[压缩包 SHA-256](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/evidence-http-complex-20261104-r3.tar.zst.sha256)、[逐文件哈希验证结果](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/evidence-verification.json)、[最终链接/源码/二进制/执行完整性校验](/data/project/massdb-sql/.build-records/codex-http-complex-retest-20261104-r3/results/final-validation.json)。最终校验针对证据完整性，不代表将产品失败项改为通过。
