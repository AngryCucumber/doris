<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# P4 快速验收记录

日期：2026-09-29。**P4 已完成约定的快速验收、自用包交付验证及最终清理。**
六项 JDBC A/B 短窗、候选有效/到期/续期与额度检查、真实页面，以及独立包启动和重启恢复均有实际记录。
各轮失败与后续恢复/复验分别保留；这一完成结论不表示历史长测或精细性能等效验证通过。

用户要求改为快速验收，范围以[执行计划第 6、7 节](license-certificate-execution-plan-20260922.md)为准。
原容量 R、5 对 A/A 加 5 对 A/B、每窗 10000 次及 1%/2% 置信精度不再作为完成前置。
已有 P2/P3/P2U 功能按其产品字节和实际/受控层级复用；不把短测结果写成零性能回退或长期稳定证明。

## 六项 A/B 短窗

同一机器、JDK 17.0.4+8、MariaDB JDBC 3.0.9 和未修改的原版 BE；FE/BE 使用 CPU 6–9，
采用独立存储中的百万行模型。A 先运行，随后 B 运行，每项每侧只有一个独立窗口，预热 10 秒、计时 30 秒。
固定种子 20260922；复用点查和元数据为 250rps，其余 50rps。准确输入及快速健康判据见
[实际计划](../.build-records/license-p4-20260929/quick-acceptance/jdbc-plan.json)。

| 产物 | SHA-256 |
| --- | --- |
| A FE | `ea66013d3ffc8c7baff96c0538aa12251217c7f06f5577e22eefc8cdeb3238db` |
| B FE | `e5e05b1489d0e007a3d5aa097db15d99500c578e4241fdcb1c4c1ad197b8f4c2` |
| B fe-common | `29a9fa69e68b0b88a44f3495c1827dbb61ffc7551beee17228c29ac7f43bd9fb` |
| A/B 相同 BE | `a9480210dbf70f6d00b3aea5ea8bb039e135d45ab5e1e4697fdef1ea03a36163` |

A、B 各 **27540 次计时请求**，共 **55080 次全部成功，零错误、零缺样**。
相同负载使用相同到达序列和点查键；十二个客户端窗口的退出码均为 0，CPU 边界核对通过。
原始汇总分别见 [A 回执](../.build-records/license-p4-20260929/quick-acceptance/jdbc-A-v1/completion.json)、
[B 回执](../.build-records/license-p4-20260929/quick-acceptance/jdbc-B-v1/completion.json)。

| 场景 | 每侧成功数 | P95 A→B（ms） | P99 A→B（ms） | FE CPU/成功请求变化 |
| --- | ---: | ---: | ---: | ---: |
| text / reuse / c1 | 7655 | 5.774 → 4.877 | 8.818 → 8.156 | +53.59% |
| prepared / reuse / c16 | 7655 | 4.062 → 4.064 | 5.703 → 5.835 | +10.40% |
| text / per_request / c1 | 1525 | 13.060 → 11.628 | 18.354 → 16.607 | +9.85% |
| prepared / per_request / c1 | 1525 | 12.911 → 12.619 | 18.840 → 19.232 | +59.81% |
| metadata / reuse / c16 | 7655 | 4.478 → 5.528 | 6.333 → 8.977 | +2.60% |
| cache / reuse / c1 | 1525 | 6.194 → 6.689 | 7.757 → 8.535 | +9.45% |

表中的 cache 窗口启用了 SQL cache，并重复执行 `SELECT SUM(v) FROM license_perf.point_rows`，
逐次核对结果；本轮未采集窗口内各请求的缓存命中 Profile，不能据此给出命中率或将该窗口全部归为命中路径。
实际缓存路径复用[原 A 的同 SQL 独立 Profile 记录](../.build-records/license-p4-20260929/sql-cache-path-v1/completion.json)，
许可到期后缓存命中仍被拒绝的功能证据复用 [P3 Q15](license-p3-acceptance-20260925.md)。
这些独立功能记录不替代本轮 B 窗口的命中率测量。

全部窗口满足预声明的快速健康界限：P95≤100ms、P99≤500ms、drain≤1s，且结果完整、无错误或缺样。
这表示上述短时负载可正常完成。成功吞吐约 255.13–255.17 或 50.83 次/秒，受固定到达负载限制，
不能据此推断最大容量。完整各项比率见[实际比较](../.build-records/license-p4-20260929/quick-acceptance/jdbc-comparison.json)。

**FE 每成功请求 CPU 在六项中均上升，范围 +2.60% 至 +59.81%。** 元数据的 P95/P99 分别增加
23.46%/41.74%，缓存分别增加 8.00%/10.03%；这些变化保留，不能因健康界限通过而称为“无退化”。
A 已运行较长时间，B 新启动；单次 A 后 B 的短窗无法分离 JIT、启动后工作及其他背景漂移，
不能把 CPU 差异全部归因于授权，也不能据此排除授权成本。未做置信等效检验，P99 是本次样本的描述值。

随后保持 B 运行，单独补测初次 CPU 增幅最大的两项，共 9180 次成功查询；
[温热复测回执](../.build-records/license-p4-20260929/quick-acceptance/jdbc-B-warm-followup-v1/completion.json)
状态为 `WARM_FOLLOWUP_RECORDED_NOT_EQUIVALENCE_PROOF`。text/reuse/c1 的 P95 为 6.019ms、
FE CPU/成功请求相对原 A 为 +2.42%；prepared/per_request/c1 的 P95 为 12.321ms、CPU 为 +4.53%。
相较初次的 +53.59% 和 +59.81%，差异随继续运行显著减小；这支持启动/热身状态会影响短窗，
仍不能区分全部原因或证明 1% 精度、零开销。复测继续引用原 A，未增加新的独立 A 对照；初次表格和结果完整保留。

## 候选有效态实际路径

[有效态完成回执](../.build-records/license-p4-20260929/quick-acceptance/functional-valid-v1/completion.json)
为 `B_VALID_FUNCTIONAL_PASS`，包含以下八项实际事件：

| 路径 | 本轮已取得的证据 |
| --- | --- |
| 普通 SQL | 业务数据查询完成 |
| HTTP Query | 实际查询完成 |
| 新 `_query_plan` | FE 返回新计划；此项不冒称本轮随后执行了完整 BE scanner |
| JDBC catalog | 百万行源模型核对完成 |
| S3 TVF | 百万行源模型核对完成；此两项不冒称客户端百万行拉流性能样本 |
| 外部 INSERT SELECT | 原生 PostgreSQL 核对全部 100 行 |
| OUTFILE | 原生对象存储完整核对 1000000 行、10 个文件及各文件摘要 |
| EXPORT | 原生对象存储完整核对 1000000 行、10 个文件及各文件摘要 |

两个完整输出的独立记录分别为
[OUTFILE oracle](../.build-records/license-p4-20260929/quick-acceptance/functional-valid-v1/outfile-native-oracle.json) 和
[EXPORT oracle](../.build-records/license-p4-20260929/quick-acceptance/functional-valid-v1/export-native-oracle.json)。
完成回执确认本次原生表已删除、20 个独占输出对象已清理，没有遗留本次占额的虚拟 FE/BE。
这一轮仅验证有效态；过期拒绝、副作用保持、续期恢复和 Flight 抽查由以下独立记录补充。

## 自然到期、续期、允许写入与额度

[首次到期轮](../.build-records/license-p4-20260929/quick-acceptance/functional-expiry-v1/completion.json)
整体状态仍为 `FAILED_PRESERVED`。失败前已有以下真实步骤和原始回执，未将该失败改写为整轮通过：

- 观察序号 1 自然到期；在到期态新建的真实 ServerPreparedStatement 执行和新 Flight 请求拒绝，SQL、HTTP Query、
  catalog、S3 TVF 拒绝，新 `_query_plan` 返回 403。
- 外部 INSERT 被拒且原生表无新增行；OUTFILE 无新对象；EXPORT 无新作业或对象。
- 到期期间内部 VALUES/UPDATE/DELETE/INSERT SELECT、元数据及 100 行 Stream Load 均取得成功回执。
  随后通过 SQL 导入序号 2 续期，完整核对到期写入结果；prepared 查询和完整百万行 Flight 读取恢复成功。
- BE 达到 3 节点额度后新增被拒，成功 DROP 释放额度并可再次 ADD；FE 达到 3 节点后超额新增被拒。

本轮协议工具在每个状态分别创建连接和 prepared handle；没有把同一 handle 从有效态保留到到期。
同 handle 跨期拒绝复用 [P3 Q17 的既有实际验证](license-p3-acceptance-20260925.md)，本轮新增的是
到期态 ServerPreparedStatement 执行拒绝和续期后的完整点查结果，两种证据不混称。

失败发生在额度夹具清理：同 IP、不同端口的占位 Observer 被 `SHOW FRONTENDS` 显示为 Alive，
工具原先据此拒绝清理。该字段的既有实现按本机 host 判断，没有同时比较 EditLogPort；
它不能证明占位端口实际有 FE 进程。没有据此忽略归属检查或修改产品实现。

[独立恢复轮](../.build-records/license-p4-20260929/quick-acceptance/functional-resume-v1/completion.json)
先核对内核中只有一个实际 FE、占位端口无监听，并关联原注册节点 ID，再删除两个占位 Observer 和两个空计算 BE。
已注册用量恢复为 1 FE、1 BE；坏证未改变已接受证书，普通账号管理调用被拒。
剩余自有 SQL/外部对象已清理，临时普通账号保留用于紧随其后的浏览器检查。
该轮状态为 `REMAINING_STEPS_PASS_AFTER_EXPLICIT_MEMBERSHIP_RECOVERY`，只补未完成步骤并引用首次已成功事件，
原始失败和当时未释放的四个占位成员记录均保留。

## 实际浏览器

[browser-v1](../.build-records/license-p4-20260929/quick-acceptance/browser-run-v1/completion.json)
整体仍为 `FAIL`：浏览器已完成序号 3 的实际导入，但工具使用 `request.headers()` 没有取得完整 Origin，
错误触发观测断言，随后因 POST 记录缺失报 `IMPORT_DUPLICATED`。这不是服务端重复提交的证明，
也没有将已提交的序号 3 回退或重发来掩盖失败；浏览器实际关闭。

[browser-v2](../.build-records/license-p4-20260929/quick-acceptance/browser-run-v2/completion.json)
改为 `request.allHeaders()` 并在断言前等待异步采集完成，使用新的序号 4，实际结果为 `PASS`。
两种角色共六项事件完成：管理员 Cookie 登录、真实详情/刷新、其他 Tab 10.5 秒零许可请求、
文件预检确认导入并查询回执、普通用户 Cookie 登录及只含 status/expires_at/administrator 的脱敏详情。
导入返回 HTTP 200，回执为 APPLIED，提交/应用版本均为 26；POST 的 Cookie、CSRF 和 Origin 检查通过。
没有 API 模拟，两个 context 均关闭，浏览器断连，待采集请求数为 0。
页面到期展示及其他语言/前缀/竞态边界继续按相同产品资源复用 P2U，不将本轮 VALID 状态检查冒称重新执行了全部页面矩阵。

## 独立包启动、重启与页面

[打包回执](../.build-records/license-p4-20260929/quick-acceptance/package-build-v1.json)
为 `INDEPENDENT_PACKAGE_BUILT_NOT_RUNTIME_ACCEPTED`。归档大小 2947126245 字节，SHA-256 为
`f560e56bae484d0706c5853d9476b7dbdd9d68b3afa52f295fd6532775ac867d`。
FE/common 和 BE 保持已验收摘要，自用公钥清单为
`b7b7e54f5197d753dd319619ecd5ff15d1387d9b7705f62756cf4e5ecbd45f7b`。

[实际解包准备](../.build-records/license-p4-20260929/quick-acceptance/package-runtime-v1/completion.json)
及[完整清单核对](../.build-records/license-p4-20260929/quick-acceptance/package-runtime-v1/distribution-verification.json)
确认 1435 个文件摘要全部匹配、无 checkout 依赖软链接，归档无符号链接或硬链接。
发行默认配置保持原样；独立运行目录的 FE/BE 配置另按已测资源与新目录映射，前后摘要单独记录。
准备回执当时状态为 `INDEPENDENT_PACKAGE_PREPARED_NOT_STARTED`；后续运行另行记录，不回写该准备状态。

首次 [package-start-v1](../.build-records/license-p4-20260929/quick-acceptance/package-start-v1/completion.json)
保留 `FAILED_PRESERVED_NO_AUTOMATIC_RECOVERY`，未将 FE 未就绪、BE 仍存活写成启动成功。
原因是测试部署配置指定的 `fe/meta` 未创建，FE 报 `NoSuchFileException: fe/meta/process.lock`；
归档自带的是默认 `fe/doris-meta`。恢复仅停止身份已核对的剩余 BE，并创建该测试目录，未修改产品、配置或归档。
[显式恢复](../.build-records/license-p4-20260929/paired-lifecycle-v1/runtime-journal/package-recovery-v1/completion.json)后的 [package-start-v2](../.build-records/license-p4-20260929/quick-acceptance/package-start-v2/completion.json)
实际就绪，并从包内公钥清单验签导入新部署的证书。新部署 ID 为
`b930fa71-313d-44b6-80c3-f77f3d843a7e`，与原候选测试集群分开。

[重启前验证](../.build-records/license-p4-20260929/quick-acceptance/package-proof-before-v1/completion.json)
通过 SQL/管理入口确认序号 2 的有效自用证书，并写入完整一行 `1 / survives-restart`。
随后实际[停止](../.build-records/license-p4-20260929/quick-acceptance/package-stop-before-restart-v1/completion.json)、
[重启](../.build-records/license-p4-20260929/quick-acceptance/package-restart-v1/completion.json)，
[重启后验证](../.build-records/license-p4-20260929/quick-acceptance/package-proof-after-v1/completion.json)
确认部署 ID、证书指纹/序号/额度和完整数据保持一致；原证书直接恢复，未重新导入，验证数据库已删除。
[独立包浏览器](../.build-records/license-p4-20260929/quick-acceptance/package-browser-v1/completion.json)
实际 Cookie 登录并核对重启后的证书详情与服务端响应，未模拟 API、未修改证书或账号；context 关闭、浏览器断连，父进程实际退出 0。

另补独立包 FE 额度释放检查。首次工具猜错拒绝 reason，
[原失败](../.build-records/license-p4-20260929/quick-acceptance/package-fe-quota-v1/completion.json)保留；
实际服务端返回 `6202 / 40001 / LICENSE_FE_LIMIT_EXCEEDED`。
[恢复复验](../.build-records/license-p4-20260929/quick-acceptance/package-fe-quota-resume-v1/completion.json)
关联同一 FE/BE 进程身份和原注册成员，实际验证超限拒绝、成功 DROP 释放额度及再次 ADD。
所有本次占位成员已清理，已注册用量为 1 FE、1 BE；证书上限仍为 3 FE、3 BE。

## 复用证据与工具检查

复用范围及具体文件摘要见[有限证据映射](../.build-records/license-p4-20260929/contract/quick-completion-audit-v1/evidence-map-v3.json)。
当前 43 个 P3 Java 来源与既有审计摘要一致，78 个 P2U UI 来源一致；P2U 构建绑定的 11 份记录、
P3 Q15/Q17 的 12 份直接记录摘要均匹配。P3 最终包到当前包的 10396 个 FE class 无增删，
10 个差异仅构建版本字符串，6398 个 common class 一致；135 件静态资源绑定到已验收 P2U 包。
P2 的 LicenseManager 后经 P3 扩展，P2 旧运行包与受控故障仍保持各自身份，不称为当前包完整重跑。

本轮工具回归实际发现 538 项，**536 项通过、2 项跳过**：

| 记录 | 实际结果 |
| --- | --- |
| [P4 工具](../.build-records/license-p4-20260929/quick-acceptance/p4-tool-tests.log) | Python 107 项通过 |
| [基线工具](../.build-records/license-p4-20260929/quick-acceptance/baseline-tool-tests.log) | Python 213 项通过 |
| [协议性能工具](../.build-records/license-p4-20260929/quick-acceptance/performance-tool-tests.log) | Python 206 项中 204 项通过、2 项跳过 |
| [页面工具](../.build-records/license-p4-20260929/quick-acceptance/ui-tool-tests.log) | JavaScript 12 项通过 |

两项跳过需要显式指定 JDK/依赖才能执行离线 Java 专项；相应当前源码已有独立真实编译和运行回执，
不将跳过写成通过，也不将这些工具测试算作新增产品运行用例。三组 Python 父进程均实际退出 0，Node 同步退出 0。

## 最终清理与交付边界

[最终停止](../.build-records/license-p4-20260929/quick-acceptance/package-final-stop-v1/completion.json)
为 `GROUP_EXIT_OBSERVED`，所属控制器实际退出 0。
[外部夹具清理](../.build-records/license-p4-20260929/quick-acceptance/external-cleanup-v1/completion.json)
确认 PostgreSQL、MinIO 的所属容器均停止并移除；
[私有网络清理](../.build-records/license-p4-20260929/quick-acceptance/keeper-cleanup-v1/completion.json)
在 namespace 为空后观察到 keeper 退出。非控制器子进程使用实际退出观察，不冒称进行了子进程 wait。

[文件清理](../.build-records/license-p4-20260929/quick-acceptance/file-cleanup-v1/completion.json)
在服务全部退出后按授权移除 12 处旧包、候选 stage、测试安装及数据/日志目录，没有备份旧测试安装。
`output` 仅保留最新的 `massdb-sql-2.0.5-license-bin-arm64`、对应 `.tar.gz` 和 `.sha256`。
归档摘要及 1435 文件清单保持上述身份；旧运行安装和配置已删除，规范化配置、执行摘要与原始回执保留，
不再将这些历史路径当作仍可读取的运行依赖。源码头最终检查为 0 pending、191 company commercial，差异空白检查通过。

独立包不包含本次授权/时间修复签发私钥及测试凭据；原发行包公开默认 TLS 示例按原样保留，
它们与本次授权私钥不同，未改变既有协议或要求开启 SSL/mTLS。

原版 Flight 65535、Parquet reader 和 CREATE USER 口令审计等历史失败保持原记录。
最终结论只适用于本次快速验收范围和实际自用环境，不构成长期稳定或零性能回退证明。
