<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# License 后续审查复核

本轮日期：2026-10-05；源码基线：`be2437469566252e84a314553b9de64bcd62e972`。
逐项核对用户提供的后续 Claude 审查，修复可达缺陷，保留已有 FE 出口、额度、到期及防回拨约定。

## 审查结论与处理

| 条目 | 核对结果与本轮处理 |
| --- | --- |
| 强制跳过日志造成不可清除的恢复标记 | 默认不读取被跳过记录，无法证明其与授权无关，确实标记不完整。不能任意清除。前轮默认关闭的日志头探测配置仍仅适用于物理可读、且已确认非授权/成员事实的记录。checkpoint 独立 Env 可将标记写入 image；其他 FE 下载 image 不会立即加载并失效，但后续重启或新节点加载该 image 会受影响。不能只称它为本机风险，也不能称为立即广播至全部在线 FE。恢复需要同一 deployment 的完整可靠 image+journal；若所有副本和备份均缺失历史，本轮没有新增强制解锁。 |
| 切主回放提前结束后继续晋升 | 确认缺陷。固定已建立的 journal 目标，从已回放位置最多续读三次，必须完整到达才继续晋升；无法建立目标或仍不足则走既有晋升失败处理，不因一次暂态短读持久标记授权事实损坏。真正跳过/非法授权事实的标记仍保留。旧代码此处调用的标记可以写入 image，审查所称“不会持久化”不准确。 |
| 旧版本授权回放被拒 | 严格连续性本身不能随意取消，但手工 dump 的截面存在实际竞态。dump 原有 Env/db/table 锁不能隔离独立授权提交队列。本轮让 dump 先进入同一变更队列、再获取 Env 回放监视器与原有元数据锁；Master 取提交日志边界，Follower 取已回放边界。未确认或尚未应用的提交禁止导出。镜像头明确使用该边界，不再二次读取变化的 replay ID。没有把全部旧记录静默放行。 |
| checkpoint 与手工 dump 并发 | 复核额外发现 MetaWriter 的静态可变 delegate 会在两次写入间串用索引/偏移。本轮每次写入独立实例，保留原文件格式；受控并发测试核对两个实际文件的模块偏移、正文和各自 journal 边界。 |
| uncertainCommit 只能等待确认 | 实际持久化失败通常由原 editlog 退出进程；Host 仍有拒绝失效 leadership 的可抛异常路径，不能据此声称任何不确定提交都绝不可达。保留 UNKNOWN 和回放确认，不自动删除可能已提交的记录。新增 snapshot 队列等待在关闭时可取消，不遗留永不完成的排队 Future。 |
| 同一记录冷读后比较不同 | 回归额外复现真实缺陷：Jackson 内存 LongNode 与冷读 IntNode 可表示相同 JSON 整数，原 `data.equals` 误判。只对结构相同、整数值相等的节点作等价比较；真实字段变化、对象字段集合差异及数组顺序仍不相等。验证重复冷回放与不确定提交确认，未放宽版本、结构或内容校验。 |
| 静默诊断 | 确认。信任配置缺失/加载失败每个 Manager 首次加载安全告警；兼容检查输出失败 FE 身份、稳定原因及字段，整个进程限频；时钟状态变化在现有后台维护观察并告警，不在查询线程写日志。无证书正文、token、远端返回值或异常消息/堆栈。信任配置继续重启生效。没有新增指标系统。 |
| 旧序号返回 IMPORT_HISTORY_UNAVAILABLE | 不能按“查不到回执”认定从未导入。成功回执有 1,024 条上限，当前持久化事实没有完整无限导入史；旧序号且找不到匹配记录可能已提交后被淘汰。保留 6204/503、UNKNOWN、retryable=false，不建议客户端盲目重试导入。若产品需要区分“确认未导入”与“历史丢失”，须另设计可证明的历史覆盖信息，不能只换错误码。 |
| 每秒重复解析修复回执 | 确认。不可变记录在完整验证后缓存不可变 clock State，管理 checkpoint/getter 复用；新记录及冷读仍完整校验，坏记录不能进入缓存。消除同一记录内最多 1,024 条回执的反复重建。不是跨记录跳过校验，不改变持久化格式。 |
| 每秒成员摘要与每分钟完整信封 | 仍存在。本轮没有把所有成员变化改为事件驱动，也没有改 WATERMARK 为增量格式。原字节流只做一次 JSON readTree，后续 clock 子树结构重建不等于第二次完整 JSON 字节解析。典型及上限写放大仍须按部署规模评估。 |

## 时钟、升级与业务边界

5 秒回拨和 300 秒前跳阈值、累计偏移策略、Master 提交可疑状态及签名修复规则不变。签名票据绑定挑战、进程和任期；离线申请期间切主需要重新挑战。Follower 本地异常未必已持久化，重启后仍要依据新时钟和提交水位重新判定，不能承诺重启即正常。

JDK 17.0.4 的 Linux 实现将 `System.nanoTime()` 交给 `CLOCK_MONOTONIC`；Linux 系统 suspend 期间它不推进。系统恢复后相对墙钟超过前跳阈值确实可能触发，不能靠采样补读消除这种真实语义差异。仅 Java 线程/进程停顿不等于系统 suspend；虚拟机暂停、迁移取决于实际 guest 时钟源与 hypervisor，不能一概而论。来源：[OpenJDK 17.0.4 POSIX 时钟实现](https://github.com/openjdk/jdk17u/blob/jdk-17.0.4%2B8/src/hotspot/os/posix/os_posix.cpp)、[Linux 内核 timekeeping](https://docs.kernel.org/core-api/timekeeping.html)。本轮没有修改系统时间或在线环境。

未配置可信公钥、升级后尚未初始化/导入、格式能力不一致时拒绝受保护读取，仍无自动宽限期。初始化需全部已注册 FE 证明兼容；有效兼容证明可在原绑定不变时复用，不能说所有续期每次都强制探测离线 FE。新 opcode/image 的旧二进制回滚继续要求升级前备份。节点 DDL 与提交串行，慢 editlog 仍可能使运维排队。手工 dump 现在也占用该变更队列，镜像写盘期间导证书、时钟持久化和节点 DDL 会等待；普通查询状态读取不获取这个队列。关闭只保证取消未运行的排队 Future，不保证已运行且忽略中断的 I/O 立即停止；不引入把已提交误报未提交的超时。切主的三次回放是有限次立即续读，持续失败走既有退出流程，不能称为任意日志故障自愈。

入库与内部任务、元数据、BACKUP/CCR、旧 BE 扫描计划的范围继续按执行计划。写入 OLAP 的 INSERT SELECT/CTAS 放行；写外表且读取受保护来源仍是既定受控出口。`SELECT 1 FROM t LIMIT 1` 是已获允许、可能下发真实扫描的窄探测；`__internal_schema.audit_log` 属于受保护业务表。没有扩大 BE 或网络协议修改，也不宣称封堵所有数据外传。

## 性能判断

Claude 对证据不足的提醒成立。未修改 BE/Stream Load 等链路，并不等于所有 SQL 写入的 FE 公共解析、事实收集、脱敏开销为零。当前源码已有前轮 OriginStatement 诊断缓存、hint 循环外判定和验签槽复用，不能继续按所有出口固定重复扫描估算。36 ns 微基准不是完整 SQL、CPU/请求或吞吐验收。

历史 P4 无授权 A/授权 B 的预热条件不一致，短测上升既不能直接归因于授权，也不能排除；后续授权版对授权版的测量不能补成无授权对照。本轮通过操作计数验证后台重复解析确实减少，不将其写成整体性能零退化或新的 P4 通过。若需要正式等效结论，仍须同 JDK/GC/数据/资源、相同预热、多窗口交替 A/B/B/A，同时报告固定后台成本及置信范围；保留原失败、未执行和精度不足记录。

## 验证记录

本轮详细源码、独立复现、构建和运行记录保存在 `.build-records/license-followup-review-20261005/`。独立局部测试不能替代最终构建产物、多 FE 故障切换或性能证据。

独立操作计数：同一 1,024 回执记录冷读一次、再读取 clock State 三次，旧实现构造/验证 4,096 条回执，新实现 1,024 条；新实现再读取 10,000 次仍不重建。缓存保留有界 typed State 内存，减少反复临时分配，不宣称驻留内存为零。record-audit-v1 的冷读幂等失败，以及基线与仅缓存版均 `wire_identical=true/same_as=false` 的复现保留；修复后的 record-audit-v2 六项通过。

集中 checks-v1 因新增测试单行 lambda 违反 Checkstyle 失败；checks-v2 产品源码编译通过，但测试用了项目 Java 8 编译目标不支持的 `String.repeat/List.of`，测试编译失败。已改用现有 Guava/Arrays API；保留两轮失败日志，旧时间戳 XML 不计为本轮通过。构建/运行采用 JDK 17.0.4+8，编译目标兼容性仍按项目 POM，不混淆两者。

checks-v3 执行 34 个套件共 350 项，348 项通过、1 项新增并发测试失败及 1 项测试夹具错误：它错误期待成员变更前预验证、排在成员变更后提交的导入仍成功。产品正确返回 `LICENSE_STALE_IMPORT_DECISION`/409，阻止使用过期成员决定。测试改为断言拒绝且未提交，再基于新成员状态重新导入成功；未放宽该产品保护。

checks-v3 的另一个错误来自嵌套 Mockito stubbing，尚未调用回放逻辑；改为先建立两个 cursor，再设置返回值。checks-v4 在识别该遗漏错误后主动停止（Maven 143），相关进程已退出，未计为通过。

最终 checks-v5 在 Temurin 17.0.4+8 上完成 **34 个套件、350 项测试全部通过**，零失败、错误、跳过，参与构建的源码前后绑定一致。FE Maven package 与 Checkstyle 通过；源码头发布检查为 0 pending、4 independent Apache、194 commercial、109 modified upstream；`git diff --check` 通过。新增 31 项测试包含回放短读与目标边界、实际并发文件模块索引、队列/关闭/不确定提交的冷回放、数值节点幂等、安全诊断和有界状态复用。

最终 JAR 绑定：

| 产物 | SHA-256 |
| --- | --- |
| `doris-fe.jar` | `1294b5dc5ef2a114a0bfae05950abc872e2a50049c206880567cc6ca9f32004b` |
| `doris-fe-common.jar` | `e2a9facc3cb0871e1762e9db19048765882615ced6249adca2c3c13141148a68` |


实际 runtime-v1 严格使用 checks-v5 两个 JAR，在一个新建 FE 上完成 SQL/HTTP 导入、详情、额度拒绝、未知回执与普通 SQL 审计可见性；22 条 SQL 中 17 条成功、5 条为预期拒绝/普通语法错误。真实 GET /dump 生成 `image.14`，header、文件名及导出前后 Master journal 均为 14；授权模块 2,428 字节、record version 2，校验和及签名有效、恢复标记完整。停止 FE 全部任务后，将该文件放入此测试安装的 image 目录，保留正常 BDB journal 尾部；重启日志明确加载同一镜像路径，镜像 SHA 一致，部署身份、许可、时钟 epoch、节点用量与额度恢复正确，再次超额 ADD 仍拒绝。自动 checkpoint 仅在此测试 FE 关闭以避免竞争镜像。

这不是无 journal 的纯镜像灾难恢复，也不是实际多 FE 选举/JE 物理损坏演练。没有启动 BE 或业务数据负载，不新增性能结论。两次所属 FE 进程组的所有 task 已退出，测试安装、元数据及日志已删除；保留白名单加载标记、摘要和完整结果回执，不保留签发私钥或运行元数据。

自用包更新目标：`output/massdb-sql-2.0.5-license-followup-bin-arm64` 及同名 `.tar.gz`、`.sha256`。包计划、构建、独立归档校验、最终提交和旧包清理由本轮 `package-plan-v1.json`、`package-build-v1.json`、`archive-verification-v1.json`、`delivery-final-v1.json` 分别记录。FE common 与前包字节相同；BE、公钥、签发工具及 135 个页面资源继续逐字核对。该说明不将静态归档校验冒充整个安装包实际部署，也不改写历史性能结论。审计归档为 `.build-records/license-followup-review-20261005/license-followup-review-audit-20261005.tar.gz`，排除签发材料及已删除的运行安装。
