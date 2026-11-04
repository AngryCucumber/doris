# MassDB SQL 同分支新旧版本测试报告（2026-11-04）

> **结论：本轮测试已完成，当前候选不建议验收或用于承载生产写入。** 按用户确认的同一分支最早状态 `49f67bdbb94` 对比 `b31b5da06ac`，确认 1 类新增数据丢失、2 类两版共有的数据正确性问题，以及 HTTP 等待、失败时密集重试和小批导入性能疑点。已验证若干修复生效，但不能抵消数据完整性风险。这里的“完成”指本文明列的测试范围，不代表穷尽所有条件或执行全仓库测试库存。

先前错误选择了 `2.0.5-license` 分支；那份报告的性能、升级兼容性与缺陷归属结论全部撤回，不作为本次验收依据。原始报告与日志保留供审计，本报告完全以确认后的同分支 FE/BE 为比较对象。

## 已确认的版本身份

| 角色 | Git 提交 | 说明 |
| --- | --- | --- |
| 旧版 | `49f67bdbb94b941574dbd6b9463eefdd163a84bd` | 用户确认的同分支最早状态，已采用 4.1.5 内核 |
| 新版 | `b31b5da06ac740e18a2f7c38d6678875495d7904` | 当前 `2.1.5` 分支候选状态 |

旧提交是新提交的祖先，`git merge-base --is-ancestor` 返回 0。两者相差 63 个文件。分支改名记录与提交时间戳存在不一致，以用户确认的提交及祖先关系确定范围，不再通过日期跨分支挑选旧包。本轮不属于 4.0.5 → 4.1.5 跨内核比较，也不包含许可证分支升级。

两个 FE/BE 都从上述源码按相同参数构建。测试安装与数据隔离，版本和性能轮次串行运行，性能测量开始前结束编译。保留源码身份、构建日志、二进制 SHA-256、种子、逐项查询结果、原始 WAL 和服务日志。

## 测试结果概览

| 检查 | 旧版 | 新版 |
| --- | --- | --- |
| UI 锁文件与 `package.json` 一致性 | `npm ci --dry-run` 失败：axios 等依赖与锁文件不一致 | 通过 |
| 当前部署前缀测试对照模板 | 3 项中 2 通过、1 失败 | 3 项通过 |
| UI 构建、资源清单、浏览器检查 | 受原始锁文件不一致限制，未构建 | 通过 |
| 打包辅助单位测试 | 缺少旧版 UI 构建资源，未得出产品测试结论 | 重建 UI 后 35 项通过、1 项跳过 |
| Python runtime 脚本单位测试 | 旧提交尚无此功能 | 17 项通过 |
| FE/BE 源码构建 | 成功 | 成功；核对后的 native 构建参数与旧版相同 |
| 所选 FE 单位测试 | 516 项：513 通过、3 跳过、0 失败/错误 | 569 项：566 通过、3 跳过、0 失败/错误 |
| 首轮及新种子功能检查 | 两轮各 359 项通过 | 两轮各 362 项通过 |
| 独立类型值预期核对 | 24 项通过 | 24 项通过 |
| VARIANT 故障注入矩阵 | 26 组：2 组数据正确、23 组报错留 WAL、1 组 BE 崩溃留 WAL | 26 组：17 组数据正确、6 组成功但丢值、3 组报错留 WAL |
| 选定 SQL 回归 | 60 个框架任务成功；实际执行 56 个主体 | 同左；4 个条件主体未执行，详见覆盖边界 |
| 三 BE 故障 / 三 FE 选主 | 48 / 3 项检查通过 | 48 / 3 项检查通过；BE 切换瞬间 1 次 UNAVAILABLE |
| 已落表数据升级 | 14 表、2,150 行作为旧版输入 | 67 项检查通过，逐值保持一致 |
| 真实待重放 WAL 升级（独立新种子） | 5 种类型普通写入与异步确认通过 | 27 项中 1 项失败：STRUCT 子字段丢值；其余 4 类型准确恢复 |
| 成对查询性能及结果 | 合计 6 组负载、4,576 次计时、448 次预热 | 48 组查询结果与旧版一致，96 个版本结果均通过独立预期核对 |
| 小批导入追加复测 | 短轮与较长预热合计 3,328 个请求 | 同左；两版共 110 项响应/最终行数与键检查通过，性能差异见下文 |
| 本地大文件导入对照 | 4 次，每次 600,572 行；24 项检查中占 12 项，通过 | 4 次，同文件；其余 12 项通过 |
| Python SQL 端到端 | 不将新功能强加到旧版 | 18 项通过 |

首轮和独立保留轮合计 1,442 项功能断言全部通过，另有 48 项独立类型值检查通过。该统计与专门的故障注入结果分开，不能据此称“全部测试通过”。55 个运行记录中的初始 FE/BE 二进制身份均匹配目标版本；跨版本替换另有升级时的哈希核验。

首次辅助测试的环境错误保留在日志中：旧工作树缺少 `ui/dist`；当前工作树新增报告后，旧 UI 清单的 `sourceModified` 状态过期。后者在重新构建 UI 后消失，不计为产品缺陷。

## 已复现的问题及验收影响

**当前候选存在可复现的数据完整性问题，不能据普通查询或单位测试通过而判定可验收。** 以下 P1 表示影响数据正确性的高优先级问题，P2 表示需处理或进一步定位的性能问题，P3 为指标问题。编号按问题类型归并，不把失败的用例数当作缺陷数；尚未定位根因的性能疑点明确标出。

| 问题 | 旧版 | 新版 | 当前归属 |
| --- | --- | --- | --- |
| P1-1：跨类型 VARIANT WAL 丢值 | 相同 DATE/VARIANT 文件报 E-7412，0 行，保留 WAL | 返回成功，6 行 VARIANT 全为 NULL，删除 WAL；新种子矩阵扩展到 6 种前置类型 | 新版新增回退，阻断验收 |
| P1-2：真实异步 STRUCT 写入后终止 BE 并恢复 | 37 行仍在，但 71 个原本非 NULL 的子字段全部变为 NULL，WAL 被删除 | 相同现象 | 两版共有；普通写入与 legacy scanner 对照均保留原值 |
| P1-3：分块 HTTP 上传丢失调用方标签 | 不显式指定 group_commit 时，同 label 重试仍成功，19 行变成 38 行 | 相同现象 | 两版共有；固定长度与显式 off_mode 对照均拒绝重复标签 |
| P2-1：部分 HTTP 客户端重定向等待约 1 秒 | requests 中位重定向等待 1006.0 ms | 1005.9 ms | 两版共有；与 bounded drain 配置存在直接对照关系 |
| P2-2：8 并发小批导入的性能疑点 | 加长预热后批次吞吐中位数 253.9 请求/秒 | 216.4 请求/秒，约低 14.7%；请求 p95 也较高 | 慢化信号在重复轮仍存在，但包含全部停顿的总体吞吐方向相反；不能定性为稳定版本回退 |
| P2-3：事务启动失败时密集重试规划 | 注入失败约 20 秒内产生 36,706 次规划错误 | 同条件 38,169 次 | 两版共有；失败可按预期返回，但期间存在无退避重试和日志放大 |
| P3-1：ReceiveDataTimeMs 出现负数 | 已复现 | 已复现 | 两版共有的计量异常，不使用该值推导性能 |

STRUCT 输入种子为 `717713`，是实际异步写入产生的 WAL，没有拼接；将测试表 group_commit_interval_ms 设为 600000，以稳定保留“已确认但尚未提交”的窗口，在返回 Success 后终止 BE，再使用默认 scanner 启动恢复。VARIANT 文件则是保留原始块及校验信息的故障注入样例。两者的触发条件不能混为一谈。最小 DATE/VARIANT 文件 SHA-256 为 `90069ccf8024554f669c53e7314b61936ba90db7f7b2fd7effd34a561d1312a4`。证据见本轮 `results/struct-{old,new}/`、`results/variant-{old,new}/` 和 `results/chunked-{old,new}/`。

新增种子 `649919` 的 26 组矩阵已经完成严格值核对：使用 13 种全 NULL 列类型，改变 NULL 块大小为 1/3/17 行，组合独立生成的对象、嵌套数组、Unicode 和布尔值，并测试两种块顺序。新旧输入 WAL 的哈希逐一相同。比较使用规范化 JSON，保留布尔值和整数的类型差别。

- 新版在 INT、BIGINT、DOUBLE、DECIMAL、DATE、IPV6 全 NULL 块在前时，均返回成功，却将后续 3 个有值 VARIANT 全部转成 NULL，并删除 WAL。对应旧版均报错并保留 WAL。这 6 组属于同一类新增数据丢失，不能拆成 6 个独立缺陷。
- 有值 VARIANT 块在前的 13 组，新版全部保留原值；全 NULL STRING、CHAR、JSON、VARIANT 块在前的 4 组也保留原值。
- 全 NULL ARRAY、MAP、STRUCT 块在前的 3 组，新版报错并保留 WAL，未完成恢复；旧版其中 STRUCT 会 SIGSEGV。该崩溃在新版对应组合中未出现，但恢复能力仍有缺口。

P1-1 的代码路径：[文件 schema 初始化](/data/project/massdb-sql/be/src/format_v2/wal/wal_reader.cpp:267) 对嵌套目标保留首块类型，[后续块转换](/data/project/massdb-sql/be/src/format_v2/wal/wal_reader.cpp:317) 把有值块先转换成这个文件类型；[嵌套保护](/data/project/massdb-sql/be/src/load/group_commit/wal/wal_reader.cpp:79) 只看中间目标类型。重放在 [HTTP stream 规划后](/data/project/massdb-sql/be/src/service/http/action/http_stream.cpp:385) 关闭严格转换，有值 VARIANT 转为标量时出现 NULL，随后作为成功结果提交。这条新增路径来自本次范围内的 WAL 类型转换修复。应按最终表列语义处理，并确保无法无损转换时保留 WAL。

P1-2 的代码路径：[WAL 子字段构造](/data/project/massdb-sql/be/src/format_v2/wal/wal_reader.cpp:73) 没有设置子字段 ID，而 [表映射策略](/data/project/massdb-sql/be/src/format_v2/wal/wal_table_reader.h:33) 使用 `BY_FIELD_ID`，[子字段匹配](/data/project/massdb-sql/be/src/format_v2/column_mapper.cpp:1567) 失败后走 [缺失字段默认值](/data/project/massdb-sql/be/src/format_v2/column_mapper.cpp:2919)。相关路径在两版一致，真实异步写入重启及 legacy scanner 对照支持这一归属。修复必须覆盖 reader → mapper → 最终表列整条路径，不能仅验证读取的行数。

P1-3 的代码路径：[分块请求处理](/data/project/massdb-sql/be/src/service/http/action/stream_load.cpp:914) 在判断到 chunked 后清空 `ctx->label`；[显式 off_mode](/data/project/massdb-sql/be/src/service/http/action/stream_load.cpp:957) 提前返回，因此绕开该清空路径。即使没有 group_commit 请求头，后续 `ctx->group_commit` 保持 false，也会先丢失标签，不能把现象描述为“自动开启 group commit”。两版的这段代码没有变化。

| 分块/标签对照（两版一致） | 第一次行数 | 同 label 第二次状态 | 最终行数 |
| --- | ---: | --- | ---: |
| 固定长度，未指定 group_commit | 63 | Label Already Exists | 63 |
| chunked，未指定 group_commit | 19 | Success，返回新的自动标签 | 38 |
| 固定长度，显式 off_mode | 19 | Label Already Exists | 19 |
| chunked，显式 off_mode | 63 | Label Already Exists | 63 |

P2-1 的证据同时来自 `http.client` 和独立的 requests 客户端。requests 的 8 并发、32 次请求对照中，将 drain 上限设为 0 后，两版中位重定向等待分别降至约 3.0/3.1 ms，吞吐从约 7.5/7.4 提升到 118.5/131.5 请求每秒。相关代码先 [写重定向再处理请求体](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/rest/LoadAction.java:688)，[空闲等待上限](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/util/StreamLoadRedirectDrainUtil.java:99) 为约 1 秒。该结论针对先读取完整响应再跟随重定向的客户端；curl 的行为不同。配置切换是定位对照，不代表已验证关闭 drain 对所有大请求、慢客户端和连接复用情形都安全。

P2-3 来自 `test_group_commit_error`：用例在 [事务启动位置注入失败](/data/project/massdb-sql/regression-test/suites/insert_p0/group_commit/test_group_commit_error.groovy:79)，将创建计划超时设为 20 秒，然后只发起一次异步 INSERT。两版最终按预期报错，但该 20 秒内 FE 分别记录 36,706 / 38,169 次同类内部规划失败，约 1,835 / 1,909 次每秒。[失败后重新入队](/data/project/massdb-sql/be/src/load/group_commit/group_commit_mgr.cpp:430) 与 [创建计划 worker](/data/project/massdb-sql/be/src/load/group_commit/group_commit_mgr.cpp:842) 没有失败退避；这部分代码在两版相同。它是注入条件下已观察到的重试放大，不是实测生产事务限额耗尽后的集群容量结论，也不同于上文 WAL 重放退避修复。归类和时间范围见 [规划错误核对](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/results/repeated-plan-error-causes.json)。

## 重测方法与结果口径

- 用独立 Python 整数、Decimal、集合和排序计算 SQL 预期值，同时检查变换前后的等价关系。新旧结果相同不能单独证明正确。
- 首轮与保留轮使用不同随机种子；保留轮种子在首轮结束后生成。改变行值、NULL、Unicode、数值边界、查询参数、批量大小、数据量与热点比例；只将实际发生变化的维度计入覆盖。
- 性能覆盖均匀键、热键倾斜、宽字符串；首轮每条查询 2 轮预热、21 轮计时，随机查询顺序并交替版本顺序。针对首轮倾斜负载的慢化信号，追加反序同种子及更大热点比例的新种子，每条 10 轮预热、101 轮计时。保存延迟、吞吐、结果哈希、CPU、内存和主机负载。
- 故障恢复分别使用真实异步写入后重启、完全相同 WAL 对照、重新捕获并改变类型/NULL 块大小/块顺序的注入矩阵。人工拼接明确标为故障注入。
- 对并发写入、标签清理、metrics、重复标签、分块 HTTP 请求、BE 故障、FE 选主和同分支原地升级分别检查已确认写入的数据。
- 区分两版共有缺陷、新增回退、修复效果、测试环境错误和条件未执行的用例。不会把总运行数直接称为全部功能覆盖。

固定回归用例用于保留可重复基准，独立随机生成和保留轮用于扩展输入；没有修改产品代码来适配测试结果。失败样例保留原始输入及 WAL，不用换一个“能通过的种子”替代失败记录。

| 数据/顺序种子 | 实际用途 |
| --- | --- |
| `497789`、`505708` | 首轮每版两组 2,053 行随机逻辑数据 |
| `491073`、`498992` | 首轮完成后生成的独立保留轮 |
| `717713` | 真实 STRUCT 异步写入与恢复 |
| `649919` | 重新捕获 WAL；13 类型 × 2 块顺序，NULL 块 1/3/17 行 |
| `142305`、`297394` | chunked 重试、损坏 WAL/大退避间隔 |
| `512559` | 500,009 行均匀键，4,093 组 |
| `306259` | 500,009 行、70% 热点，4,093 组；后续反转版本顺序复测 |
| `335381`、`423326` | 150,007 / 350,017 行宽字符串，10,003 组 |
| `708799` | 新抽取的 600,011 行、90% 热点，997 组 |
| `282377`、`637249`、`202714` | 混合压力、三节点故障、已落表数据升级 |
| `119326`、`478139`、`615011` | 作业泄漏核对、HTTP 客户端、Jetty 并发顺序及请求体 |
| `882719`、`758195` | Python 端到端、真实待重放 WAL 跨版本升级 |
| `11477`、`15850` | 原生 ASAN 用例执行顺序；不是新增的 240 个用例 |

两个宽字符串种子恰好均抽到 56 次字符串重复，本轮改变了宽表数据量和查询参数，不能宣称已覆盖多个字符串宽度。倾斜保留轮则明确改变了行数、分组数和热点比例。

## 环境、构建与证据身份

运行主机为 ARM64、10 vCPU、约 19.47 GiB 内存、8 GiB swap、4 KiB 内存页，Linux 6.15.4。使用 JDK 17.0.2、同一 Clang/native 依赖与 Release 构建参数，FE 堆为 1536 MiB，单 BE 内存上限为 4 GiB。数据库仅监听本机测试端口，所有比较轮次串行。主机还有其他服务，因此保存每轮负载和资源采样，不把结果视作独占机器或生产集群容量上限。

两个版本的 FE/BE 核心从各自提交完整构建。为隔离 UI 旧锁文件问题，核心构建关闭 UI 打包，UI 独立验证。Java 扩展、HDFS/CDC 支持依赖复用已构建且源码在范围内未变化的依赖，并将其中 `fe-common` 替换为对应版本的新构建产物。新增的 Python 打包运行环境来自本分支 `0751a3baf24` 的现有包；打包脚本、锁文件与 Python server 源码到候选提交没有变化，身份单独记录，没有把该包作为旧 FE/BE 基线。

| 二进制 | 旧版 SHA-256 前 12 位 | 新版 SHA-256 前 12 位 |
| --- | --- | --- |
| doris-fe.jar | `1ae1c0f45a497` | `facb1c56a225` |
| fe-common JAR | `d34ed022b65c` | `a6fced6e54a8` |
| doris_be | `f65898bbf66b` | `d6023462f047` |

完整哈希见 [binary-identity.json](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/provenance/binary-identity.json)。每个临时实例再次核对实际使用的二进制。Git worktree 中部分内置版本字段为 Unknown，采用完整提交、干净源码状态、构建日志和外部 SHA-256 共同定位身份。实际运行参数可由每轮工具快照、配置文件和原始默认配置重建。

## 并发、故障恢复及已确认的修复效果

| 检查 | 旧版 | 新版 | 解释 |
| --- | --- | --- | --- |
| 8 写入线程 + CLEAN LABEL/SHOW LOAD + metrics，180 秒 | 20,266 次已确认写入，0 错误 | 22,166 次已确认写入，0 错误 | 两版逐行核对通过；额外完成 12 轮建库/删库 |
| 写入延迟 p50 / p95 / p99 | 30.16 / 90.73 / 136.52 ms | 32.33 / 95.39 / 138.23 ms | 单轮混合负载观察，不能只用总写入量宣布所有延迟改善 |
| 三 BE 终止一个节点并恢复 | 切换瞬间 0 次错误，70 行已确认数据完整 | 切换瞬间 1 次 UNAVAILABLE，69 行已确认数据完整 | 两版故障识别后均 30/30 写入成功；每版 48 项检查通过 |
| 三 FE 终止原主节点后选主 | 约 1.93 秒恢复写入 | 约 2.12 秒恢复写入 | 两版每版 3 项检查通过，已有数据和新写入均完整 |
| 已落表数据原地升级 | 保留旧 metadata/storage 后替换 FE/BE 为新构建 | 14 表、合计 2,150 行升级前后逐值相同，新写入成功 | 67 项检查通过；没有出现旧报告中跨许可证分支的 journal 问题 |
| 150 次空 INSERT + 48 次 HTTP SQL 导入后的 PENDING 作业 | 0 → 150 → 166；清理后仍 166 | 始终 0 | 新版修复生效；真实数据值也核对通过 |
| CRC 错误 WAL 与大退避间隔边界 | 24 秒窗口内观察到 2 次尝试，事务 PREPARE | 1 次尝试，事务 ABORTED 且保留错误原因 | 两版均保留坏 WAL、未落脏数据；不能由短窗口推断全天重试行为 |
| 冷 metrics 竞争：计算注入 2.5 秒延迟，锁等待设为 50 ms | 无本次新增机制对照 | 23 个请求约 52–60 ms 返回 503 + Retry-After，1 个约 2.52 秒返回 200 | 新版冷缓存退避通过；热缓存及多种输出格式另有功能/单位测试 |

三节点测试均为同主机、不同端口的独立进程，不是跨主机网络隔离测试。三 FE 引导仅复制本轮新建集群的身份信息以适配不同 HTTP 端口，未从其他安装拷贝业务元数据。节点切换期间返回错误的写入，按“提交结果不明”单独记录；不能把这类请求直接算作成功写入后丢失。

180 秒压力测试中，FE/BE RSS 随初始化、缓存和写入增长。该观察窗口不足以证明无长期内存泄漏；原始逐次内存、线程数与延迟保留于 `stress-{old,new}/stress.json`，没有只保留最后一个采样。

补测了真实待重放数据的跨版本升级：旧版对 BIGINT、ARRAY、MAP、STRUCT、VARIANT 五种表各确认 23 行异步写入，其中 VARIANT 分两批写入，首批全 NULL；检查这些行仍未落表后终止旧 BE，再替换为新 FE/BE。标量、ARRAY、MAP、VARIANT 逐字段恢复正确；STRUCT 的 20 个非 NULL 结构体共 40 个子字段值全部变成 NULL，WAL 最终被删除，再次确认 P1-2 影响升级窗口。相关数据为独立种子 `758195`，不是前一轮 37 行样例的复用。

首次核对误将复杂类型 CAST 的展示文本直接按 JSON 解码，反斜杠样本导致 ARRAY/MAP/STRUCT 普通写入对照误报。随后保持相同输入与版本，直接读取数组元素、map 键值和 STRUCT 子字段：普通写入控制全部通过，升级恢复仅 STRUCT 仍失败。首次 27 项中 6 个失败和改正读取方式后的 27 项中 1 个失败均保留，不能把首次误报删除后再称首次全通过。

## 查询与导入性能

六组成对查询负载共完成 **4,576 次计时查询、448 次预热查询**。48 个“负载 × 查询”组合的新旧结果均一致；另由独立 Python 整数运算、分组、排序、UTF-8 字节长度和 ROW_NUMBER 求和恒等式核对全部 48 组、96 个版本结果，0 不符。SQL/query cache 均关闭，每组查询顺序随机，版本顺序交替。

下表为候选相对旧版的中位延迟变化，正值表示变慢，负值表示变快。前四列每条查询 21 次计时；后两列各 101 次计时并增加到 10 次预热。不同数据形状不能跨列直接比较绝对时延。

| 查询 | 均匀键 | 首轮 70% 热点 | 宽表 | 宽表保留轮 | 70% 热点反序复测 | 新 90% 热点 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DISTINCT | −3.4% | +6.6% | −6.8% | +1.9% | −3.0% | −0.9% |
| GROUP BY | −0.5% | +2.5% | +3.1% | +3.7% | +0.1% | +1.0% |
| JOIN | +2.6% | +6.1% | −4.4% | −2.3% | +0.6% | −0.8% |
| SUM 全扫描 | −1.5% | +8.5% | +0.3% | −2.1% | +3.6% | −0.4% |
| 范围过滤 | −2.7% | +10.6% | 0.0% | +0.4% | +1.6% | +0.6% |
| 字符串 | −1.6% | +16.1% | +1.3% | +6.9% | −0.1% | −1.3% |
| TOP N | +5.4% | +10.4% | −1.4% | −0.4% | +0.7% | +0.3% |
| 窗口 | +2.2% | +4.1% | −5.4% | −3.6% | +0.7% | −2.2% |

首轮热点字符串查询从 7.47 ms 变为 8.67 ms；同数据反序并加长预热后为 5.97 → 5.96 ms，新热点数据为 5.99 → 5.91 ms。最初的 10%–16% 慢化未在追加测试中复现，不能定性为稳定回退。其余短样本差异也不代表所有 SQL 都无退化。原错误跨分支报告的宽表 JOIN 大幅回退结论撤回，本次同分支两组宽表 JOIN 未复现该现象。

较长的两个热点查询阶段，FE/BE CPU 秒分别为旧 10.49/13.99 → 新 10.83/14.10，以及旧 10.63/15.20 → 新 10.30/14.96，变化与延迟观察相符。全部查询/导入采样中，旧 FE/BE RSS 范围约为 908–1743 / 1782–3452 MiB，新版为 892–1748 / 1665–3406 MiB；测试进程 VmSwap 采样均为 0。RSS 范围包括加载、查询和随后导入阶段，不是单条查询的增量内存，也不是全系统无 swap。

每组额外进行 8 并发的小批导入，六组两版合计 1,536 个请求，均核对返回状态、载入数量和最终唯一键/行数。经过 FE 且读取完整重定向响应时，两版均约 7.4–7.7 请求/秒，与 P2-1 一致。直连 BE 的单批结果波动较大；其中新热点轮出现 189.9 → 120.1 请求/秒、p95 93.5 → 222.8 ms 的单次差异，追加重复对照单独记录，不将其从原始结果中剔除。

针对该小批导入信号，用相同的 64 种请求大小、8 并发、随机请求顺序和每批新标签/新键追加两套对照。每批共 25,039 行；短轮采用 old→new→new→old，每实例 1 批预热、5 批计时；最后采用 new→old，每实例 20 批预热、20 批计时。追加共 6,656 个请求（3,840 计时、2,816 预热），110 项响应与最终行数/唯一键/键求和检查全部通过。没有排除慢批次。

| 小批导入对照 | 旧版批次吞吐中位数 | 新版批次吞吐中位数 | 旧版整体吞吐 | 新版整体吞吐 |
| --- | ---: | ---: | ---: | ---: |
| 短轮第 1 对，old→new | 246.7 请求/秒 | 227.7 请求/秒 | 224.3 请求/秒 | 231.1 请求/秒 |
| 短轮第 2 对，new→old | 213.1 请求/秒 | 182.4 请求/秒 | 201.5 请求/秒 | 169.6 请求/秒 |
| 20 批预热后，20 批计时，new→old | 253.9 请求/秒 | 216.4 请求/秒 | 124.4 请求/秒 | 133.9 请求/秒 |

最后一对的请求 p50/p95/p99 为旧版 29.31/65.27/134.37 ms、新版 30.97/73.87/137.80 ms。两版都在从零计数的第 27 批出现长停顿，分别耗时 5.04/3.76 秒，采样到的主机 I/O wait 占比分别约 29.0%/35.9%。这些是同时发生的观察，不足以把根因归为磁盘或产品代码。新版常态批次慢化值得继续定位，但“批次中位数约低 14.7%”与“计入所有停顿的总体吞吐约高 7.7%”必须同时呈现；当前不能给出稳定回退比例或无回退的保证。原始批次、响应及资源采样见 [小批导入汇总](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/results/runtime-summary.json)。

回归中的大文件 HTTP 导入直接边下载远端对象边上传。旧版两次 LoadTime 为 10.38/14.39 秒，新版为 59.51/42.15 秒。为区分网络与数据库，下载一次相同的 19,362,295 字节 gzip 文件，保留哈希，采用 old→new→new→old 顺序从本地以 chunked 方式上传，每轮两次，每次 600,572 行；独立核对行数和两列求和。旧版四次为 1.133/1.109/1.172/1.099 秒，新版为 1.137/1.099/1.118/1.057 秒，全部通过。本地同文件未复现大幅慢化；远端输入耗时不能作为数据库自身回退的证据。

另外，两版 group commit 响应均观察到负的 `ReceiveDataTimeMs`，例如远端用例中旧版 −24/−26、新版 −32 ms。它由 [两个计时器相减](/data/project/massdb-sql/be/src/load/stream_load/stream_load_context.cpp:115) 生成，属于共有的指标计量异常；本报告使用客户端单调时钟和有效总耗时字段，不用该负值推导吞吐。

原始 p50/p95、样本数、配对结果和 2,000 次重采样的区间保留于 [性能 CSV](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/results/benchmark-comparison.csv)。重采样区间只反映同一轮样本内的不确定性，没有包含共享主机漂移、轮次之间差异或多重比较调整；不能将它当作生产性能保证。

![六组查询性能对照，正值表示新版延迟增加](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/results/query-performance.png)

可独立缩放或导出的图：[查询性能 SVG](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/results/query-performance.svg)。

## FE HTTP 容量与 Python、UI 验证

FE HTTP 测试每版运行 3 轮，打乱 64/192/384 并发的顺序，共 3,840 个请求；只接收 307，不跟随至 BE，并确认目标表仍为 0 行。因此下表反映 FE 重定向处理能力，不是导入吞吐或 BE 提交能力。数值为三轮吞吐/每轮 p95 的中位数。

| 并发 | 旧版请求/秒 | 新版请求/秒 | 旧版 p95 | 新版 p95 |
| ---: | ---: | ---: | ---: | ---: |
| 64 | 63.0 | 62.8 | 1010.7 ms | 1010.3 ms |
| 192 | 185.0 | 185.8 | 1016.5 ms | 1013.5 ms |
| 384 | 152.2 | 358.6 | 2972.5 ms | 1019.7 ms |

高并发下新版吞吐提升约 136%，对应本次 Jetty 线程参数绑定修复；低并发时约 1 秒的 drain 等待仍在。两者应分别判断。无效、超大线程参数及线程预算溢出另由 `HttpServerTest` 覆盖。

Python 3.12.15 打包环境的 116 个顶层模块全部导入成功，独立检查器的标量/pandas Arrow Flight 调用通过。随后在本轮新构建 BE 上完成 18 项端到端检查：1,027 行含 NULL/Unicode 的随机数据、5 种新抽取筛选模数下的标量及 pandas UDF、UDAF 分组与窗口、UDTF、主动抛错及抛错后查询、错误 PYTHONHOME/PYTHONPATH 的启动清理。均通过。这验证了当前 ARM64/4 KiB 主机上的实际运行，不替代 64 KiB 页或其他 CPU 平台的运行验证。

UI 使用 Node 22.23.2/npm 10.9.9。旧锁文件与 package.json 的 axios 等依赖不一致，干净安装预检失败；新版锁文件预检、生产构建、资源清单和浏览器检查通过。部署前缀测试对旧模板为 2/3，通过新版为 3/3。浏览器覆盖 6 种前缀，中/英文及 375/768/1440 宽度；这是静态 UI 产物及受控 API 的浏览器检查，未将其算作真实 FE 上所有业务页面的端到端覆盖。

## 单位测试与覆盖边界

FE 使用相同选择列表，旧版实际执行 98 个测试类、新版 103 个测试类；新增类在旧源码中不存在。旧版 516 项中 513 通过、3 跳过；新版 569 项中 566 通过、3 跳过，均 0 失败/错误。跳过的是源码中已有 `@Ignore` 的 `ShowExecutorTest.testDescribe`、`CopyLoadPendingTaskTest.testContinuationToken`、`CopyIntoTest.testUpload`。覆盖 LoadManager、InsertLoadJob、事务、JDBC 类型边界、HTTP/metrics、存储介质缓存、cooldown、副本/报告与调度等相关路径。

仓库 SQL 回归选择 `insert_p0`、`load_p0/http_stream`、`load_p0/clean_label`：两版均为框架 60/60 成功、0 失败。3 个 Docker 主体（`replay_wal_restart_fe`、`txn_insert_restart_fe`、`txn_insert_restart_fe_with_schema_change`）以及 cloud 主体 `test_cloud_http_stream_2pc_mow` 未执行，每版实际执行 56 个主体。部分主体中的环境分支也未覆盖，例如单 FE 环境下的 observer 分支。回归配置强制单副本，以匹配单 BE；三副本故障由上文独立三 BE 测试验证。

对回归及压力测试的 FE 警告日志另做了逐源统计，没有把“框架成功”写成“日志无错误”。事务发布中的 `genPublishTask failed` / `finishTransaction failed` 来自 `txn_insert_inject_case` 的主动故障注入；规划日志的大头则是上文 P2-3。还有进度元信息缺失、SHOW LOAD 读取不到表、启动时缺少可选插件/帮助资源等警告，详见 [日志分类](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/results/fe-log-triage.json)。这些记录全部封存，不按 WARN/ERROR 行数直接计算产品缺陷数。

额外运行：

- 新版打包辅助测试 35 通过、1 跳过；Python runtime 脚本 17 项通过。
- 回归框架 `SuiteSshExecTest` 7 项通过，涵盖主机别名、本地复制以及空格/引号/特殊字符路径。使用已核对源码身份的现有框架 JAR，没有进行外部 SSH 操作。
- WAL 原生 ASAN 选择 6 个测试组、24 个不同用例，两种随机顺序种子各重复 5 轮，共 240 次通过。该 ASAN 二进制是已有候选构建的复用，本轮未重新完整构建 BE 单位测试，不能将其表述为全量 BE 单测或 240 个不同用例。

初始环境失败全部保留：旧版缺少 UI dist；新版初次使用旧 UI 清单导致 sourceModified 不匹配，重建后通过。ASAN 首次隔离执行缺少两份仓库 WAL 夹具，4 个夹具构造失败，退出时还报告 MetricRegistry 清理路径 heap-use-after-free；补齐原始夹具后，同种子及新种子共 240 次未再出现。这个异常保留为测试初始化失败后的退出路径观察，既不删除，也不将其直接等同于已确认的生产查询内存错误。

本轮没有执行全部 FE/BE/SQL 测试库存，也未覆盖外部 S3/HDFS/JDBC/云服务真实部署、跨主机网络分区、磁盘耗尽/掉电、24 小时以上压力或 x86/64 KiB 内存页运行。JDBC、cloud 等被列入单位测试不代表已经完成对应外部系统联调。报告结论限于明列的构建、配置、数据分布与故障条件。

63 个变更文件包含文档、测试及头注释调整，并非 63 项运行行为变更。例如 `multi_segment_util.h` 在本次范围内仅删除修改声明，不是新的倒排索引算法变更。本轮按 WAL、导入生命周期、事务/任务/副本、HTTP/metrics、Python 打包、UI 和回归框架组织测试；外部 JDBC、cloud、冷却存储的真实部署仍属覆盖缺口。变更清单见 [changed-files.json](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/provenance/changed-files.json)。

## 复现与后续验收条件

核心复现工具：[STRUCT 真实恢复](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/tools/struct_repro.py)、[相同 WAL 对照](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/tools/replay_file.py)、[扩展类型矩阵](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/tools/variant_matrix.py)、[chunked 标签](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/tools/chunked_probe.py)。配置与版本选择集中在 [cluster.py](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/tools/cluster.py)，实际输入与期望值在各轮 JSON 中。

例如复现真实 STRUCT 问题：

```bash
python3 /data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/tools/struct_repro.py old struct-recheck-old --seed 717713
python3 /data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/tools/struct_repro.py new struct-recheck-new --seed 717713
```

工具会拒绝覆盖已有运行目录。正式的新一轮验收应使用新的记录目录，并在固定失败种子复现后抽取新种子；两版必须继续使用完全相同的输入、配置和文件。不能只把“返回成功”或“行数正确”当作通过标准，必须校验所有字段、NULL/类型、重复键、已确认写入和 WAL 留存状态。

本次只增加测试报告与记录，未修复产品源码。后续优先处理 P1-1/P1-2/P1-3，并对修复版重跑固定复现、独立新数据、两种块顺序及真实待重放 WAL 升级；为持续规划失败增加有界退避与速率验证。小批导入疑点需在独占主机、多轮较长运行下继续核实，并保留完整长尾。性能结论需与结果正确性一起验收。

## 证据位置

本轮记录：[同分支测试记录](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/)、[基线纠正记录](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/provenance/baseline-correction.json)、[UI 核验结果](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/results/ui-validation.json)。

结果索引：[功能/单位/回归/性能总表](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/results/final-summary.json)、[运行期汇总](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/results/runtime-summary.json)、[26 组 WAL 逐值核对](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/results/wal-matrix-reconciliation.json)。

已停止并清理本轮临时测试实例。封存包包括本文快照、测试工具、逐项输入/预期/输出、原始 WAL、原始日志、源码与二进制身份、性能 CSV/SVG；不包含数据库测试安装或大型产品二进制。产品二进制另保留在本轮 `artifacts/{old,new}/`，用于按哈希复现。封存时逐文件检查 SHA-256，随后解压数据流再次核对全部文件集合和哈希。

构建用 worktree 保留在 `/root/.codex/worktrees/same-branch-baseline/massdb-sql`；应用将其视为本任务主工作目录，归档操作返回“primary checkout cannot be removed”。该目录没有运行中的测试实例，也没有未提交的产品源码修改。

证据包：[evidence-same-branch-20261104.tar.zst](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/evidence-same-branch-20261104.tar.zst)、[校验和](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/evidence-same-branch-20261104.tar.zst.sha256)、[封存校验结果](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/evidence-verification.json)。

已撤回的原报告：[审计副本](/data/project/massdb-sql/.build-records/codex-same-branch-retest-20261104/provenance/withdrawn-baseline-report.md)。原证据包仍位于 `.build-records/codex-independent-retest-20261104/`，仅作审计，不作为当前基线的测试通过证明。
