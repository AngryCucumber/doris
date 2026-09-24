<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# FE 许可导入核心与 P2 提交边界

本文冻结 P1 导入核心的实际 API、状态不变量和 P2 接入要求。范围是 FE 许可管理状态；BE 代码、扫描协议和已发计划的行为不变。
`LicenseImportPolicy` 已实现纯准入与候选事实计算，`LicenseImportState` 已实现不可变事实模型。这里没有 SQL/HTTP handler、EditLog 操作、image 格式注册、Master 转发、锁管理或多 FE 发布功能；这些仍由 P2 及后续阶段接入。

## 1. 对象与信任边界

| 类型 | 已实现职责 | 调用方必须提供的前提 |
| --- | --- | --- |
| `LicenseVerifier` | 严格解析和验证 compact JWS，返回不可变 `LicenseDocument` | 来自受控发行/管理员安装的可信许可公钥集 |
| `LicenseImportState.Slot` | 保存已验签声明、原始 compact JWS 和原始接受版本 | 恢复使用公开的 `Slot.verify(raw, committedVersion, verifier)`；不得把反序列化 JSON 字段直接当作已验签声明 |
| `LicenseImportState.Receipt` | 保存历史提交确认的四元组 | 来自已提交且可信的 FE 元数据，不能来自客户上传的请求体 |
| `LicenseImportState` | 保存部署、active/pending/base、最高序号、许可版本及至多 1,024 条回执；校验结构一致性 | 所有字段属于同一已提交元数据截面；坏槽先独立隔离 |
| `LicenseImportPolicy.Context` | 保存一次决策使用的时间、就绪状态、注册/预留节点数和成员版本 | 当前 Master 权限、账号权限、可信时钟及真实成员状态已由调用方建立 |
| `LicenseImportPolicy.Prepared` | 返回待持久化的新事实、前置版本、提交回执、幂等标识和覆盖间隙 | 该对象本身不是持久提交凭据；不能收到它便对外报告提交成功 |

这些对象不会读取服务器当前时间、数据库会话时区或浏览器时区。调用方统一提供 `LicenseClock` 确定的 UTC 秒以及其可疑状态。
`Slot.getCompact()` 仅供受控持久化和验签；不进入日志、异常、公开状态 DTO 或指标标签。相关类没有输出声明正文的 `toString()`。

## 2. 不可变状态与持久化字段

P2 将以下字段作为一条许可事实记录的载荷，并在 image 中保存同一结构。这里冻结字段语义，实际 journal opcode、序列化版本注册和 image 读写由 P2 实现：

```json
{
  "schema_version": 1,
  "deployment_id": "<canonical-lowercase-uuid>",
  "highest_sequence": 17,
  "license_version": 23,
  "active": {
    "certificate": "<original-compact-jws>",
    "committed_version": 21
  },
  "pending": {
    "certificate": "<original-compact-jws>",
    "committed_version": 23
  },
  "effective_base": {
    "certificate": "<original-compact-jws>",
    "committed_version": 21
  },
  "receipts": [
    {
      "fingerprint": "<64-lowercase-hex-sha256>",
      "license_id": "<signed-license-id>",
      "sequence": 16,
      "committed_version": 21
    },
    {
      "fingerprint": "<64-lowercase-hex-sha256>",
      "license_id": "<signed-license-id>",
      "sequence": 17,
      "committed_version": 23
    }
  ]
}
```

示意字符串占位符不是有效证书。三个槽位均可为 `null`；`null` 只表示没有可信可用的该槽位，不表示新集群或已获得默认额度。
`schema_version`、部署标识、全局计数器及回执来自 FE 提交事实；许可证签名不覆盖这些外部元数据。P2 不能将客户提交的同形 JSON 当成恢复记录。

状态不变量如下：

- `highestSequence` 和 `licenseVersion` 非负；最高序号不能低于任一保留槽/回执的序号。每次真正接受新证或显式激活 pending 基础额度，`licenseVersion` 加一；耗尽 `Long.MAX_VALUE` 时拒绝新提交，不绕回零。
- `Slot.committedVersion` 始终是这张证书原始接受版本，必须为正且不大于当前 `licenseVersion`。pending 晋升 active/base 时保留原始版本；激活事实的新版本只反映在状态的 `licenseVersion`。
- 所有槽位属于同一部署。保留顺序为 `base.sequence <= active.sequence < pending.sequence`；空槽不参与对应比较。若 active 被隔离而保留 base/pending，仍要求 `base.sequence < pending.sequence`。
- 已接受容量不倒退：base 到 active、active 到 pending、base 到 pending 的 FE/BE 上限均不下降。此约束不因证书已经过期而撤销。
- 同一 `fingerprint`、`license_id`、`sequence` 或原始提交版本，在不同槽/回执出现时，四元组必须完全相同。不同证书的序号顺序必须与原始提交版本顺序一致，不能混合不同 checkpoint 截面的事实。
- 回执最多 1,024 条，按成功提交顺序保存，序号和提交版本严格递增；新提交追加后仅淘汰最旧的一条。基础额度激活不新增导入回执。

`restore(...)` 只校验结构一致性，不是验签或磁盘真实性证明。它不会用当前时间重写 active/pending，不生成部署 UUID，不追加日志，不启动后台线程，也不会从 active 自动补造缺失的 base。

## 3. 恢复顺序与损坏隔离

恢复必须先读取可信的同一 image/journal 截面及其部署、计数器和提交版本，再分别执行：

```java
Slot active = Slot.verify(activeRaw, activeOriginalVersion, currentLicenseVerifier);
Slot pending = Slot.verify(pendingRaw, pendingOriginalVersion, currentLicenseVerifier);
Slot base = Slot.verify(baseRaw, baseOriginalVersion, currentLicenseVerifier);
LicenseImportState state = LicenseImportState.restore(deployment, active, pending, base,
        highestSequence, licenseVersion, committedReceipts);
```

这段代码只表示每个有效槽的调用方式，不能包在一个“任一失败就全部清空”的异常处理块中。P2 须逐槽处理验签/版本错误、记录隔离原因，再用可信剩余事实构建状态。例如 base 损坏可隔离为 `null`，独立验签成功的 active 仍可供 `LicenseSnapshot` 判断现有业务查询；新增成员不能据此推断基础额度。

`Slot.verify` 允许已经过期的真实证书恢复，因为历史幂等确认和永久保留的基础额度仍需要它；它不会根据恢复机器的当前时间拒绝该槽。未知 `kid`、签名失败、错误类型或原始字节被改动均拒绝。旧 key 仍被 active、pending、base 或恢复档案依赖时，不得提前退役。

恢复发现槽之间、槽与回执之间或全局计数器的矛盾时，`restore` 抛出内容安全的 `IllegalArgumentException`。P2 须依据该截面的提交证据定位并隔离坏事实；无法确定可信全局序号/版本时，导入保持 `IMPORT_NOT_READY`，不能用 `empty(deployment)` 重建零序号来放行旧证或成员 bootstrap。该故障不能升级成无条件停止整个 FE 的处理方式。

查询快照与导入全状态的可信要求不同：一个隔离坏 base 的有效查询槽可继续按 `LicenseSnapshot` 决策，但缺失的历史事实不能被导入代码解释为“从未接受过更高额度或序号”。是否允许恢复后的新导入，由 P2 对恢复就绪证据设置 `Context.recoveryReady`，不能仅根据某张证书验签通过就置为 `true`。

## 4. prepare 的精确语义

入口为：

```java
Prepared proposal = policy.prepare(compact, state, context, licenseVerifier);
```

`Context` 构造参数依次是：`trustedNowSeconds, clockSuspect, recoveryReady, registeredFe, registeredBe, reservedFe, reservedBe, membershipVersion`。注册和预留数量为非负 `int`，计算需求时先提升为 `long` 相加，避免 `Integer.MAX_VALUE + 1` 溢出后误放行。

决策顺序固定：

1. 检查原始 compact 的大小/ASCII 边界并计算 SHA-256。在当前三个槽和成功回执中查完全相同指纹。
2. 命中时直接返回幂等历史确认：`isIdempotent=true`、`requiresPersistence=false`，`toPersist` 就是原状态，回执保留原提交版本。即使证书已过期、已被覆盖、时钟可疑、成员现已超额或旧 key 已退休，也不重新应用历史证书、不推进 base。
3. 未命中才严格解析和验签；检查部署。同一已知 ID/序号对应不同指纹，返回 `IMPORT_CONFLICT`。已经没有精确回执/槽位、但序号不高于最高序号的真实候选返回 `IMPORT_HISTORY_UNAVAILABLE`。这一步不虚构过去是否提交成功；若旧 key 已退休而候选无法验签，只能报告当前验签错误，不能信任其未验证序号。
4. 要求恢复就绪和可信时间；`issued_at <= min(MAX_EPOCH_SECOND, now + 300)`、`expires_at > now`，且具备 `DATA_QUERY`。
5. 候选 FE/BE 上限必须覆盖注册数加预留数，以及所有已接受 active/pending/base 上限；已过期槽的上限仍参与比较。
6. 当前时间已到 pending 的 `not_before` 时，只在待提交事实中将它规范化为 active 并晋升 base；源状态不变。如果停机错过其整个有效期，这项基础额度事实仍可明确提交。
7. 候选已生效，则替换 active、清除 pending；候选未来生效，则保留规范化后的 active，替换唯一 pending。按下面的覆盖规则证明已接受权益没有被削减。
8. 新状态的许可版本加一，最高序号更新为候选序号；证书槽与新回执使用这次新版本，并放入同一 `toPersist` 事实。

幂等确认可以在旧 key 退休后工作，是因为命中的是已提交事实，不是把当前未验证输入认定为新可信证书。账号认证、ADMIN/导入权限、请求限流及 Master 路由在调用上述核心之前仍必须执行。

## 5. 两槽续期覆盖与空档

对旧 active 与旧 pending，分别保护其尚未结束的区间 `[max(now, old.not_before), old.expires_at)` 和全部已接受能力。
新状态按 `LicenseSnapshot` 相同规则选择证书：到新 pending 起点后优先使用 pending，之前使用 active。核心最多在这个起点将旧区间分为两段，逐段验证时间覆盖、能力包含和节点额度；不会因为证书内某能力暂时未知就允许删除已经接受的能力。

因此：

- 立即生效的新证必须完整覆盖尚未结束的旧 active 和已接受 pending 的未来权益；缩短 pending 截止时间或移除其能力均拒绝。
- 推迟新 pending 起点时，旧 active 只有在整个过渡区间的时间、能力、额度都足够时才能补足；否则拒绝。仅“active 还没到期”不足以证明它具有 pending 新授予的能力/额度。
- 如果旧 active 本身将在新证开始前到期，而且这个空档从未被其他已接受 pending 承诺覆盖，则允许形成空档；`getCoverageGapSeconds()` 返回两槽之间的秒数。它不自动延长旧证，空档中的新查询仍按过期状态受限。
- 任何失败均不更改源状态、最高序号或回执。`prepare` 无写盘、无状态发布、无消费副作用。

## 6. 提交前重查与 durable 后发布

P2 必须以同一许可/成员/信任配置串行化域协调导入、ADD 预留与提交、DROP 提交、基础额度激活和信任根更换。相同许可版本不能指代不同已提交事实；任何影响注册/预留数量的变更必须推进成员版本。

流程如下：

```java
Prepared preliminary = policy.prepare(compact, currentState, sampledContext, verifier);
// 进入当前 Master 的许可管理提交序列；重新读取状态、时间、成员计数和当前信任集。
Prepared finalProposal = policy.recheckForCommit(preliminary, currentState,
        currentContext, currentVerifier);
if (!finalProposal.requiresPersistence()) {
    return historicalAcknowledgement(finalProposal.getReceipt());
}
LicenseImportState exactFacts = finalProposal.getToPersist();
// P2: 将 exactFacts、槽的原始版本和成功回执原子追加为同一持久记录。
// 仅在 durable success 后原子发布 exactFacts，再从已应用状态构造提交回执。
```

示意中的 `historicalAcknowledgement` 及日志调用不是现有实现 API。`recheckForCommit` 校验预期许可版本、成员版本和部署；变化则返回 `STALE_IMPORT_DECISION`，调用方重新准备。版本相同仍会重查时间、就绪状态、实际数量和当前可信公钥；候选可能在预检时为未来证书、提交时已到生效时刻，最终事实按提交前的当前时间正确归入 active。

新证导入的最终重查会再次解析和验签；这是有界管理操作，不得在查询或入库的数据执行路径调用。P2 应使用有限并发和许可管理提交序列，不得在验签期间持有业务查询/入库执行锁。时钟、信任根与成员状态不能在最终重查到提交事实确定之间无协调变化。

**durable success 后不得再次按新时间或新版本运行准入，然后丢弃已经提交的事实。** replay/恢复应用的是已提交事实；时间状态由查询快照派生。持久化失败保留原状态、不产生成功回执；响应丢失则客户端按原证指纹重试，可能返回原始历史确认。P2 还须区分 Master 已提交、接入 FE 已应用及其他 FE 待应用，核心不假装这些阶段已经完成。

## 7. 基础额度激活

入口为：

```java
Prepared activation = policy.prepareBaseActivation(state, context);
Prepared finalActivation = policy.recheckForCommit(activation, currentState, currentContext, verifier);
```

未到 pending 起点或没有 pending 时返回无写盘的 no-op。已到起点且时间/恢复可信时，返回新许可版本的事实：pending 移为 active，base 晋升，pending 清空；保留这张证书原始提交版本和原回执，最高序号不变。`getReceipt()` 为 `null`，因为激活不是第二次导入。

即使当前时间已晚于 pending 的到期时间，明确提交仍可保留其基础额度；这不恢复已过期的查询权益。可疑时间不允许激活。`currentCertificate()`、状态页读取、checkpoint 和重复 replay 均不能调用该 API 追加事实；只有当前 Master 的显式管理流程在原有持久化顺序下执行。

缺失 base 且没有待激活 pending 时，该 API 不从 active 推断或修复基础额度。缺失事实的调查/恢复由 P2 管理路径处理，不能以“当前这张证书够用”为理由跳过恢复证据。

## 8. 错误与验证范围

| 错误 | 主要条件 |
| --- | --- |
| `DEPLOYMENT_MISMATCH` | 已验签候选属于其他部署 |
| `IMPORT_CONFLICT` | 已知 ID/序号不同内容，或许可版本已经耗尽 |
| `IMPORT_HISTORY_UNAVAILABLE` | 未命中的真实旧序号已超出保留范围 |
| `IMPORT_NOT_READY` / `CLOCK_SUSPECT` | 恢复证据不足或时间不可信 |
| `ISSUED_IN_FUTURE` / `CERTIFICATE_EXPIRED` | 签发时间超出 300 秒容差或候选已经到期 |
| `FEATURE_NOT_LICENSED` | 新导入候选没有 `DATA_QUERY` |
| `NODE_LIMIT_TOO_SMALL` | 候选不足以覆盖实际加预留数量或已接受上限 |
| `RENEWAL_REDUCTION` | 旧 active/pending 的尚未结束区间、能力或额度覆盖被破坏 |
| `STALE_IMPORT_DECISION` | 最终提交前许可/成员版本或部署发生变化 |

格式、算法、签名和信任集错误沿用验证器错误；恢复结构矛盾使用不含原文的异常。真实 SQL/HTTP 错误码映射、指标和审计由接入层统一完成。

当前核心回归包括原始字节重验、状态不可变、过期/被覆盖/旧 key 退休后的幂等确认、ID/序号冲突、回执淘汰与槽原始版本、恢复四元组矛盾、缩短授权拒绝、pending 过渡能力/额度不足、允许的期限空档、跨到期基础额度、注册加预留溢出、时钟/信任/版本提交前变化、未来证书在最终提交时生效、版本与序号上界、坏 base 隔离和停机错过整个 pending 有效期。
这证明 P1 纯核心规则，不等同于 journal 原子性、宕机恢复、多 FE 传播、SQL/API 或集群性能已经通过；P2 与集成阶段须对这些真实接入行为提供独立记录。

## 9. 查询主状态与管理详情的独立接口

`LicenseSnapshot.queryStatus(long)` 保持无分配的原有接口：由调用方提供可信秒，使用快照创建时采样的 `clockSuspect`。它适合受控测试或调用方已经保证同一时钟采样的一次判断，不能把一次采样布尔值永久当成动态时钟状态。

实际接入可使用 `queryStatus(LicenseClock)`：读取 epoch、原始秒和当前可疑标志，完成主状态计算后再核对 epoch；若修复在其间改变 epoch，最多再尝试一次，仍不稳定则返回 `CLOCK_SUSPECT`。该接口不构造 `Reading`、集合、证书或管理 DTO；即使旧快照采样的 `clockSuspect=true`，已经提交的新修复 epoch 也能作为当前时间依据。`licenseReady=false` 仍优先拒绝，时钟健康不能代替许可恢复就绪。修复不会修改签名的截止时间，真正到期仍返回 `EXPIRED`。

状态页等管理路径单独调用 `evaluate(long)` 或 `evaluate(LicenseClock)`，获取不可变 `Evaluation`：

- `getPrimaryStatus()` 与对应主状态路径一致。
- `getReasons()` 同时保留独立原因：例如 `EXPIRED`、`FEATURE_NOT_LICENSED`、`FE_LIMIT_EXCEEDED`、`BE_LIMIT_EXCEEDED` 可以同时出现，不因主状态优先级而丢失。
- `isFeLimitExceeded()`、`isBeLimitExceeded()` 分别比较当前所选的本部署证书与注册数量；没有当前证书、只有未来 pending 或证书属于其他部署时，不用这些声明推断当前额度。返回 `false` 不表示已经获得无限额度或查询授权。
- `getWarnings()` 的 `INVALID_SLOTS_ISOLATED`、`BASE_CAPACITY_UNAVAILABLE` 用于提示隔离和基础额度状态；它们不单独阻止一张可信有效 active 的查询。无有效查询槽时，主状态仍可为 `INVALID` 或 `MISSING`。

管理详情允许分配枚举集合，不能放到每条 SQL 或每个协议请求的准入路径。时间可疑时，详情中的时间派生原因仅描述该次时钟读数下的判断；`CLOCK_SUSPECT` 主状态仍控制拒绝，详情不是绕过时间修复的授权依据。
