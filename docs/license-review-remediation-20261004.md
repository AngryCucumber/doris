<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# License 分支审查复核与修复

本轮记录标识：2026-10-04；基线：`8d9c51e8d3a5b69ab33056ddb7da38bceeb8c558`。
针对用户提供的 Claude 审查核对当前源码并修复确认的问题。保留 FE-only、已启动查询不因到期取消、旧 BE 扫描计划可继续使用、注册节点计数和原授权到期规则。

## 1. 复核结论

审查指出了实际缺陷，但不能把所有条目都作为已证实的 bug，也不能据此承诺性能完全无影响。

| 审查项 | 源码核对与本轮处理 |
| --- | --- |
| 空闲 Follower/Observer 重复发布成员摘要 | 确认。`onReplayComplete()` 原来在每轮空闲回放重新发布。改为仅首次完成恢复时发布；真实 journal 应用、成员变动和原有每秒维护仍可发布。10,000 次空闲完成回调以调用计数验证没有额外成员读取。没有独立复测 Claude 的 30 µs、125 KB 或 120 MB/s 数值。 |
| 跳过普通 journal 也产生永久授权恢复标记 | 确认旧代码不区分内容。新增**默认关闭**的头部探测选项，可靠识别到不影响授权和成员事实的普通操作码才不新增标记；未知、授权、成员记录及不认识的操作码仍标记。已有标记不清除，完整元数据恢复要求见第 3 节。 |
| 升级后立即可用、无需停查询 | 原方案没有这个保证。升级后的 FE 在初始化及导入前拒绝受保护读取；混合版本阶段旧 FE 可能仍提供服务。初始化需要全部注册 FE 兼容，离线申请证书也需要时间。本轮没有引入自动宽限期或预置部署 ID。 |
| 时钟可疑扩散、修复绑定进程/任期 | 属于当前防回拨契约。Master 持久化可疑状态后复制到其他 FE；Follower 的本地可疑状态不立即广播，但晋升后可能持久化。未提交修复挑战遇切主/重启需重新申请；已提交结果按回执确认。 |
| 多次小幅校时累计超过阈值 | 前跳相对初始/修复锚点，回拨相对已吸收前向修正的可信进度；前后调整不能简单净抵消。这些约束有意防止拆分回拨，不能直接改为每次校时重置锚点。保留 5 s 回拨、300 s 前跳容差和修复 epoch；普通水位 checkpoint 不重置容差。渐进校时也不是无限偏移豁免。 |
| 两次读时钟之间暂停造成误判 | 确认并修复。稳态仍为一次 wall、一次 mono；正向修正候选补读 mono 验证；初始/修复锚点只接受紧配对样本。具体失败边界见第 4 节。 |
| 信任文件只在进程中加载一次 | 当前配置明确重启生效。修复启动时缺失/损坏的公钥文件后仍须重启；本轮没有增加热加载或削弱全 FE 信任一致性检查。 |
| 普通 SQL 中出现 license/admin/show 被整体脱敏 | 确认并修复。识别实际管理命令前缀，`SHOW CREATE TABLE license`、`SHOW FULL COLUMNS FROM license`、`WHERE creator='admin'` 保留诊断文本。`ADMIN IMPORT/VALIDATE/REPAIR LICENSE` 证书前缀出现在字符串/注释时仍保守脱敏，不承诺所有包含命令文本的普通 SQL 都原样展示。 |
| 不规范 hint 将普通语句中断 | 确认并修复。敏感 SQL 的 hint 错误关闭可能泄密的输出监听器，但不再安装抛错监听器，保留上游容错。 |
| 初始化 HTTP 探测堵塞节点变更队列 | 确认并修复。探测移至现有 verification 执行器；提交前重新核对任期代次与 FE 成员版本。探测期间成员 DROP 可以执行，过期探测结果不能初始化。真实持久化操作仍串行，元数据存储阻塞并未被消除。 |
| 任意一台离线 FE 都阻塞续期 | 表述过度。包、信任和成员绑定未变化且兼容证明仍有效时可复用；证明失效后需要重新探测，离线 FE 会阻止通过。 |
| 元数据升级只能单向 | 当前新 image 版本/操作码确实不能被旧 FE 安全回放。回滚需要升级前元数据备份。未来与上游版本 141 合并须专门迁移；不能盲改已发布格式来解决潜在编号冲突。 |
| 超额 SQLSTATE 40001、管理重试标记 | 确认并修复。6202 改为 `45000`；明确区分提交前可重试、202 已提交回执轮询及 UNKNOWN 查证。不会把 UNKNOWN 自动当成再次提交许可。 |
| 外表 INSERT 排队后被拒却返回 1105 | 确认并修复。保留 typed license 错误码和安全 JSON，并保留原回滚；其他错误继续原有 1105 路径。 |
| 普通转发错误行为变化 | 确认并修复。仅授权类型异常使用授权响应，其余恢复上游 WARN 和普通错误处理。 |
| 敏感多语句被错误切片后泄漏 | 确认并修复。真实 lexer 与独立分句器对嵌套注释、转义模式的差异可产生失去管理前缀但仍含证书的切片。敏感批次保留完整原始包和原 statement index；执行语句仍由真实 parser 决定。 |
| 许可无效时仍消耗规划 CPU | 为保留写入、元数据及空计划例外，部分拒绝只能在解析/规划后决定。客户端大量重试仍会消耗 FE CPU，本轮没有扩大早期拒绝范围，也不把这项开销称为零。 |
| 查询内部重试未再次检查到期 | 已获用户接受的在途查询边界。新 EXECUTE、多语句下一条、过程下一条和新的执行仍检查；本轮不取消已启动查询。 |
| dead/decommission 节点占额度、重复 ADD 错误优先级 | 前者按注册数计费，成功 DROP 才释放；后者是错误优先级，不导致超额准入，本轮未改。降额仍须等待旧额度承诺到期并完成安全缩容，不能承诺无过期窗口的提前降额续期。 |
| BACKUP/CCR/ADMIN COPY TABLET/旧 BE 计划/统计元数据仍可取数 | 当前 FE 出口范围保留这些通道；旧 BE 计划边界已获用户明确接受，`ADMIN COPY TABLET` 及 Iceberg `$files` 可能包含 min/max 的元数据通道在本轮明确记录，并非逐项新增用户确认。不能据此宣称阻止一切外传。ES search、file_review 的已有额外检查保留。 |
| 后台维护吞掉所有异常 | 原代码只捕获若干指定异常，并非所有异常。本轮为这些异常与初始化探测失败增加限频安全告警，不记录异常消息或证书材料。基础额度激活仍排在正常水位 checkpoint 前；持续失败仍须排障，未宣称所有故障下水位正常推进。 |

“BE、Stream Load、group commit 未修改”属实，但“任何入库路径都没有检查、性能绝对无影响”过强：向外表写入受保护来源是既定出口，SQL 写入也可能经过解析和诊断脱敏。35 ns 微基准不能替代完整查询对照。本轮没有新增长窗性能结论，历史性能失败和不确定项不回写。

## 2. 修改范围

产品修改集中于 14 个 FE 类（`Config` 位于 fe-common，其余位于 fe-core）：
`LicenseManager`、`LicenseClock`、`LicenseManagementException`、`LicenseSqlRedactor`、
`Env`、`OperationType`、`EditLog`、`JournalCursor`、`BDBJournalCursor`、`NereidsParser`、`ConnectProcessor`、
`BaseExternalTableInsertExecutor`、`ErrorCode`、`Config`。

没有修改 BE、网络协议、传输安全配置、证书签名格式、journal/image 格式、查询出口分类、有效期或额度政策。
`OriginStatement` 的前轮诊断缓存、验签槽复用继续保留。空闲回放优化不增加查询锁、I/O 或签名校验。

## 3. 元数据恢复操作边界

`recoveryIncomplete` 首先是本台 FE 的内存及 image 状态，不是一次设置后立即复制到所有 FE 的 journal 事件。它禁止使用不完整授权事实导入、修复时钟或读取业务数据。缺授权模块、版本断链、授权日志跳过或未知跳过仍需要保守处理。

新启动配置 `massdb_license_probe_skipped_journal_header=false` 默认保留原 `force_skip_journal_id` 的不读故障记录路径。**默认跳过内容未知，仍会设置授权恢复不完整。** 仅在确认记录物理可读、因为业务回放失败需要跳过且运维能够验证该条件时，可显式设为 `true` 后重启：以无等待只读事务探测两字节操作码，不解码业务正文，确认不涉及授权/成员的已知普通操作可不新增标记。探测本身没有业务重试/锁等待，不承诺存储 I/O 的硬时限。

这不是物理坏块修复手段：JE 即使只返回头部，读取物理损坏记录仍可能使整个环境失效。不能为绕过授权恢复检查而普遍开启。未知、授权类、节点成员类、探测失败或不认识的操作码保持保守拒绝，已有恢复标记不会因开启该选项被清除。

FE/BE 注册身份也是授权事实。`ADD/DROP/MODIFY BACKEND`、`BACKEND_STATE_CHANGE`、`ADD/ADD_FIRST/MODIFY/REMOVE FRONTEND` 八类操作即使头部可读也不能免除标记：漏掉 ADD 可能低估节点数或漏查 FE 兼容能力。此判定同时覆盖 `force_skip_journal_id` 与 `skip_operation_types_on_replay_exception`；后者在解码/业务回放失败后跳过成员操作时同样必须拒绝使用不完整授权事实。普通表 DDL/事务/心跳并未因此统统改为授权日志。

已标记的节点应按既有元数据恢复流程从健康 FE 或可靠备份取得**同一 deployment 的完整 image+journal**并重建该故障节点的元数据目录；需要保证源元数据本身完整、版本连续且与集群一致。该过程属于运维恢复，本轮没有承诺所有实际灾难场景已演练。若整个集群和所有备份均缺失授权历史，本轮没有新增 SQL/API 强制清标记入口；不能删除授权模块、重置 UUID 或用普通续期证书冒充历史恢复。

## 4. 时钟采样与运维

采样间线程暂停不能被直接当作人工改时间。本次补读校验避免将暂停计入正向偏移，读取前捕获修正偏移，防止并发修正把旧 wall 样本误判成回拨。初始化及签名修复建立锚点时，最多尝试 32 次 mono/wall/mono 配对，只接受跨度不超过 1 ms 的样本；丢弃宽样本，避免一次启动冻结永久扩大后续前跳容差。

**连续 32 次都无法紧配对仍保守进入 `CLOCK_SUSPECT`，不会通过抛异常破坏 image/journal 回放。** 因此不宣称任意调度暂停都能自动恢复。新建锚点重采样仅发生在初始化/新修复 epoch，常规读取不引入该循环。异常原因需排查调度暂停及系统时钟后，按签名修复流程处理。

系统时间以 UTC epoch 参与判断，本地显示时区不会改变证书到期瞬间。上线及离线部署前校准 FE 时钟，运行时优先渐进校时并监控相对偏移，避免周期性强制跳时；持续累计漂移仍可能超过容差。真正触发的 sticky 状态、Master 持久化传播和签名修复规则不变。已持久化的可疑状态不能通过普通重启解除。仅本机尚未持久化的标记，重启后会依据当时的时钟和已提交水位重新判定；不能保证重启即可恢复。

## 5. 验证与交付

构建、源码绑定和 JUnit XML 位于 `.build-records/license-review-20261004/`。最终 `checks-v5` 在 Temurin 17.0.4+8 上完成 32 个 FE 测试套件，共 **319 项全部通过**（含 5 项 BDB cursor 测试），零失败、错误、跳过，验证期间源码未变化；FE Maven package 与 Checkstyle 通过。源码头发布检查通过：0 pending、4 independent Apache、192 company commercial、108 modified upstream，`git diff --check` 通过。

已保留的开发验证：独立 JDK 17.0.4 Clock v2 共 23 项通过，旧实现可复现采样暂停问题；v1 宽采样窗口设计被同行复核否决，未作为交付版本。首次集中构建 `checks-v1` 因三项 Checkstyle 格式规则失败，保留原日志；其中陈旧 XML 不计作本轮成功测试。`checks-v2` 在测试编译时因 Mockito 泛型调用与 JE 重载方法歧义失败，修正显式参数类型。`checks-v3` 运行 318 项、317 项通过、1 项错误：新增 hint 测试未创建 `ConnectContext`，后续构建计划发生空指针；真实上下文下同一 SQL 可解析，修复测试夹具而未放宽产品校验。没有更改历史 P0/P1/P2/P3/P4 的包身份或性能通过状态。

当前 P0 JSON 已同步 6202/45000、重试分类和采样规则；历史真实 40001 结果保持原文。检查器 29 项自测通过，82 个用例规格结构与 26 个性能引用校验无错。完整初始前置检查仍报告 78 条旧源码绑定漂移/错误码和操作码已占用：与本轮修改前合同在同一源码上的结果逐条一致，没有新增；不是全量 P0 检查通过。最终再次校验结果仍相同，详见 `p0-contract-final-review.json` 和 `p0-contract-final-comparison.json`；前轮范围摘要及比较报告保留。

最终构建产物绑定：

| 产物 | SHA-256 |
| --- | --- |
| `doris-fe.jar` | `2fc6ab8b49f1a52659f9038548d6b8aa13819c62b70029dadd0792963093233b` |
| `doris-fe-common.jar` | `e2a9facc3cb0871e1762e9db19048765882615ced6249adca2c3c13141148a68` |

实际运行与最终包校验另按各自回执记录，不把单测等同于多 FE 故障切换或性能验收。

`checks-v4` 的 318 项全通过是加入成员日志保护前的阶段记录；最终 `checks-v5` 新增一项回放异常路径测试并补足两类跳过路径的成员参数矩阵，以该轮 319 项及产物绑定为准，不把轮次相加。

最终真实单 FE 验证为 `runtime-v4`，严格绑定 `checks-v5` 两个 JAR：20 条 SQL 均符合预期（15 条成功，1 条普通语法错误 1105，4 条额度拒绝 6202/45000）。完成 HTTP validate 与 SQL 导入、SQL/HTTP 状态、名为 `license` 的常量视图元数据、错误 hint 的 EXPLAIN 规划容错、普通语法错误定位、HTTP 导入冲突 409/false 和未知回执 503/UNKNOWN/false；审计日志保留三条普通 SQL 原文且未包含实际证书正文。使用同一所属元数据重启一次，许可、部署身份、注册额度和再次超额拒绝保持正确。离线 BE 测试身份没有进程或 tablet，最终已移除。

该运行没有启动 BE，hint 只验证规划而未派发业务查询，不宣称多 FE 切主、物理 JE 损坏恢复、全业务数据路径或新性能通过。两个所属 FE 进程组的全部 task 已退出、安装/元数据/日志已删除。`runtime-v1` 因无 BE 却期待执行视图查询失败；`runtime-v2` 因未等待原有异步审计队列落盘失败；均保留对应脚本和失败记录并完成清理。`runtime-v3` 是成员日志补丁前的同类验证通过，不能替代最终 v4 的产物绑定。

自用包：`output/massdb-sql-2.0.5-license-review-bin-arm64` 及同名 `.tar.gz`、`.sha256`。更新 FE core/common JAR 和当前文档，BE、公钥清单、签发工具及 135 项页面资源与前包逐字比较。包计划、构建、独立归档校验及最终提交/旧包清理分别由 `package-plan-v1.json`、`package-build-v1.json`、`archive-verification-v1.json`、`delivery-final-v1.json` 记录；内部清单验证不等同于将整个归档重新部署运行。完整审计归档位于 `.build-records/license-review-20261004/license-review-audit-20261004.tar.gz`，排除运行安装、签发私钥及临时签发材料。
