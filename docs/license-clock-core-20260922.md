<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# P1：FE 可信时间与离线修复核心

本文件描述 `LicenseClock`、`LicenseClockRepairVerifier`、`LicenseClockRepair` 的核心接口和冻结语义。代码不改 BE，不接入 FE 查询、SQL/HTTP、journal/image 或领导选举；这些适配仍属于 P2/P3。单元测试中的内存 Store 只验证提交契约和故障语义，不能作为真实 FE 持久化或集群测试通过的证明。

## 时间与正常路径

- 时间单位：证书与修复票据用 UTC Unix 秒；本地水位用毫秒；单调绝对值只保存在当前进程，绝不放入复制记录。
- 默认回拨容差 5,000 毫秒、前跳检测阈值 300,000 毫秒，构造器可注入测试时钟及阈值。偏差等于阈值仍在容差内；超出后进入黏性的 `CLOCK_SUSPECT`，普通校时或 checkpoint 不能清除。
- 恢复基准为 `max(本地墙钟, 已提交水位)`。容差仅影响异常判定，不能从水位减去容差，也不能给证书截止时间追加宽限。
- 每次 `trustedNowMillis/Seconds()` 读取单调经过时间和墙钟；可信时间为 `max(当前墙钟, 已观察的最大 UTC 基准偏移 + 单调经过时间)`。正常稳定路径只采样时钟、原子读取及比较；墙钟正向推进时通过原子最大值更新偏移。后续回拨不降低可信时间，也不把时间冻结在前跳后的某一点，因此到期许可不能恢复为有效。回拨检测基准包含已观察的前跳进度：先前跳 20 秒再回退 6 秒，即使仍高于启动墙钟轨迹，也必须异常。
- 该路径不进行 I/O、验签、JSON 解析、内存分配或管理锁操作。正向修正使用 CAS，属于 lock-free，不承诺每次调用具有固定重试次数；真实性能必须用基准记录证明，不能把复杂度描述当作延迟结论。
- 查询适配必须先捕获 `getClockEpoch()`，再读取可信时间、检查 `isSuspect()`，最后用 `isCurrentEpoch(epoch)` 确認仍属同一 epoch；改变时重试或保守拒绝，不能混用修复前后的时间和异常标志。管理调用可使用一次返回时间、异常与 epoch 的 `read()` 不可变对象。异常只影响许可读取准入；核心没有停止写入的行为。
- 水位准备由管理路径 `prepareCheckpoint(minimumAdvanceMillis)` 执行。它只返回不可变候选，不提交、不发布；异常时返回空候选。Store 提交后才能 `applyCommitted()`，不能把本地候选当作 journal 已落盘。
- 同一 epoch 的提交保持已有原子进度对象，避免并发查询与 checkpoint 发布之间丢失已观察的前跳。相同版本同内容幂等、同版本异内容拒绝、旧版本忽略；同 epoch 不允许降低水位或修复权限版本。收到同 epoch 的已提交水位若领先本地墙钟超过 5 秒，也立即置为异常，和重启恢复规则一致；不能因运行中复制水位而默默激活远期 pending。
- 新 epoch 的提交才允许降低水位，并以各 FE 自己的墙钟和单调时钟重建基准。该 FE 的墙钟仍明显落后于修正水位时继续异常；不从其他 FE 复制 `nanoTime()`。

有限频率水位无法证明未落盘时间段的完整历史，也不能防止攻击者把整个磁盘状态与服务器时钟一起回滚。该限制保留为离线部署边界。

## 修复票据和挑战

挑战输出是以下 **10 个字段组成的严格对象**：

```json
{
  "schema_version": 1,
  "product": "MassDB SQL",
  "deployment_id": "003aaf16-b828-455a-8ce2-1bd393572102",
  "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "clock_epoch": 0,
  "repair_authorization_version": 1,
  "leader_term": "dc8c8126-1d8b-493d-aad8-eb8f1b2026fb",
  "observed_wall_at": 1800000000,
  "observed_high_water_at": 4070908800,
  "valid_for_seconds": 86400
}
```

示例 nonce 仅展示编码，实际由 `SecureRandom` 每次生成 32 字节并采用无 padding 的规范 base64url 编码。`leader_term` 每次本进程获得 Master 任期后重新随机生成；挑战只在这个进程与任期内有效。挑战寿命固定 24 小时，以单调经过时间判断，达到 24 小时即失效，不受墙钟或污染水位影响。

申请新挑战或撤销挑战会提交新的 `repair_authorization_version`；checkpoint、普通证书续期和无关成员变化不得推进这个专用版本。重启/切主会丢弃未消费挑战，必须重新申请；不恢复旧 nonce。API 适配仍须做 ADMIN、限流和审计。

修复为 compact JWS，最大 16 KiB，严格 header：

```json
{"typ":"massdb-license-clock-repair+jws","alg":"Ed25519","kid":"repair-1"}
```

只能使用信任清单中 `purpose=time_repair` 的公钥集合；没有普通许可 key 的后备搜索。`kid` 使用与许可证相同的固定 Unicode scalar 文本规则和 128 上限。`jku`、`x5u`、`crit`、额外字段或普通许可证 typ 不被接受。

签名载荷必须恰有以下 11 字段：`schema_version`、`product`、`deployment_id`、`repair_id`、`nonce`、`clock_epoch`、`repair_authorization_version`、`leader_term`、`issued_at`、`not_before`、`expires_at`。产品及 schema 固定为 `MassDB SQL`、`1`；所有 UUID 使用规范小写形式；nonce 规范编码且解码为 32 字节。epoch 在 `[0, Long.MAX_VALUE-1]`，修复权限版本在 `[1, Long.MAX_VALUE-1]`。三个时间字段为 `[0,253402300799]` 整数，`issued_at <= expires_at`，且 `0 < expires_at-not_before <= 86400`。

`[not_before,expires_at)` 表示修正后本地墙钟允许的区间，不使用污染水位验证它。前跳持久化为 2099 年、系统纠正为 2027 年后，可据新挑战签发覆盖纠正时刻的票据。重复键、未知字段、浮点数字、尾随 JSON、错误 UTF-8、非规范 base64url、错误签名和不受信 key 全部拒绝；异常消息只含固定错误码。

## 提交与确认

`Facts.version` 与回执 `committedVersion` 是本核心的时钟状态修订号，不是现有 Doris journal ID；P2 必须在统一元数据记录中明确映射并提供 FE 应用进度，不能拿本地修订号冒充全 FE 已应用。

`LicenseClockRepair.Store` 是后续真实 FE journal/image 适配必须满足的契约：

1. `load()` 只返回已提交状态。
2. `compareAndSet(expectedVersion, replacement)` 原子比较时钟记录版本并提交完整时钟事实与消费回执；不得覆盖证书槽位、许可最高序号、证书有效期、基础节点额度或其他 FE 元数据。
3. 提交必须置于既有 FE Master 领导权和 journal 写入屏障内；旧 Master 即使尚未收到本地失去领导权的通知，也必须由真实持久化适配拒绝。返回 `false` 表示已确定发生版本冲突；抛出 `StoreException` 表示提交结果未知。只有明确成功或随后读到已提交记录才能应用本地时钟。

`prepareRepair()` 先验签，再核对部署、nonce、任期、epoch、专用权限版本、单调期限和纠正后的本地时间，只返回不可变准备对象。`commitRepair()` 在实际提交点重新核对所有可变条件；普通 checkpoint 不会使离线挑战无效，但新挑战、撤销、切主、超时或已消费会使旧准备失效。

成功修复在同一条原子状态变化中提高 `clock_epoch`、`repair_authorization_version` 和记录版本，写入修正毫秒基准及带 `repair_id`、`keyId`、原始票据 SHA-256 fingerprint 的紧凑回执，再发布本地状态。它不改变许可序号、截止时间或基础额度。即使时钟修复成功，已经真实过期的许可证仍然过期。

`confirmRepair(repair_id)` 从已提交 Store 刷新状态后返回回执，可以在响应丢失、重启、票据到期后使用；它不再次降低水位。最多保留 1,024 条最近成功回执；返回 `null` 只表示当前保留记录中无法确认，**不能解释为从未提交或可重复使用旧票据**。即使回执已淘汰，旧票据的 epoch、专用权限版本、nonce 与任期仍不匹配新挑战，不能重放。

紧凑回执不保存票据原文，fingerprint 只能作审计关联，不能用于重新验签。时钟事实恢复依赖 P2 既有可信 journal/image；若运维另行保留需复验的原始修复票据，其 key 应加入 `archivedRepairKeys`，不能把仅存 fingerprint 的回执称为可复验签名证据。

所有修改方法在管理路径串行执行；正常时间读取不经过这些锁。持久化不确定时保持本地旧状态，调用者使用确认接口或重读权威状态解决不确定性，不能擅自回退已提交记录。

## 验证边界

`LicenseClockTest` 覆盖小幅回拨、到期边界前跳、前跳后继续单调推进、阈值、跨重启水位、候选与已提交隔离、版本冲突、新 epoch 传播、单调溢出及并发 checkpoint。`LicenseClockRepairTest` 覆盖签名解析、用途隔离、所有挑战绑定项、24 小时期限、切主/重启、提交前失败、提交后丢响应、确定冲突、消费防重放及有界回执。

统一 FE 测试已真实执行：Clock 15 项、Repair 23 项均通过，全部许可核心合计 100 项通过、0 失败/跳过。记录位于 [FE 测试汇总](/data/project/massdb-sql/.build-records/license-p0-p1-20260922/fe-ut-results.json) 及同目录 `junit-final` XML。这些测试包含注入时钟和内存 Store 故障模拟，不宣称真实 journal、API 或 Master 故障切换已经接入。发行互通另见 `tools/license-checks` 生成的独立报告。
