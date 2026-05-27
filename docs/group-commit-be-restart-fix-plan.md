# Group Commit BE 重启卡死问题：根因分析与修复计划

> 当前分支：tag `4.0.5`，HEAD = `59de8c4c524`（commit message: `4.0.5-rc01 (#61772)`）
> 适用范围：Apache Doris 4.0.x（含 4.0.5）标准模式（非 cloud），开启 group commit 写入
> 注：4.0.5 与 4.1.0-rc01 中本文涉及的所有代码位置、行号完全一致；同一份 patch 可同时应用

> **【v2 重大更正 2026-05-27】经代码追踪 + 现场行为比对，本文 v1 的根因判断（归因于 `MasterImpl.finishPublishVersion`）是错误的。**
> **真正的脏 task 产生者是 `AgentTaskCleanupDaemon`（BE 判死后标 finished 但不 set succTablets，并把 task 从队列删除）。**
> 关键判别证据：现场观测到「**挂掉的 BE 恢复后事务仍卡 COMMITTED、FE 持续打印 NPE**」——这只可能发生在 task 被移出 `AgentTaskQueue`（cleanup daemon 路径）、从而无法被 `ReportHandler` 重发的情况下；若按 v1 的 `finishPublishVersion` 路径（task 留在队列），BE 恢复后会被重发治好，与现场不符。
> 受影响章节：§2 根因、§2.3 时序、§3 Fix #2/#3、§5 缓解、§8/§9。触发条件是 **BE 服务器突然挂掉（硬故障，BE 从不回报）**，而非 v1 所说的优雅关机。

## 一、问题现象

| 现象 | 说明 |
| --- | --- |
| 触发条件 | **某台 BE 所在服务器突然挂掉 / 硬重启（断电、`kill -9`、宕机），BE 从不向 FE 回报 publish 结果** |
| 卡死 | 该 BE 上正在 group commit 提交的事务卡在 COMMITTED，无法 publish 转 VISIBLE |
| FE 报错 | FE master 周期性（每个 publish 周期）打印 `DatabaseTransactionMgr.java:1478` 的 NPE |
| 不可自愈（已实证） | **挂掉的 BE 恢复并重新加入集群后，事务仍卡 COMMITTED，FE 继续刷 NPE**，只能重启 FE master 才恢复 |

### FE 日志中的关键堆栈

```
2026-05-30 10:07:08,757 WARN (PUBLISH_VERSION_EXEC-30-0|156763)
  [PublishVersionDaemon.tryFinishTxnSync():279] error happens when finish transaction 2985277233
java.lang.NullPointerException: Cannot invoke "java.util.Map.containsKey(Object)"
  because the return value of "org.apache.doris.task.PublishVersionTask.getSuccTablets()" is null
  at org.apache.doris.transaction.DatabaseTransactionMgr.checkReplicaContinuousVersionSucc(DatabaseTransactionMgr.java:1478)
  at org.apache.doris.transaction.DatabaseTransactionMgr.finishCheckQuorumReplicas(DatabaseTransactionMgr.java:1431)
  at org.apache.doris.transaction.DatabaseTransactionMgr.finishTransaction(DatabaseTransactionMgr.java:1157)
  at org.apache.doris.transaction.GlobalTransactionMgr.finishTransaction(GlobalTransactionMgr.java:540)
  at org.apache.doris.transaction.PublishVersionDaemon.tryFinishTxnSync(PublishVersionDaemon.java:275)
  at org.apache.doris.transaction.PublishVersionDaemon.lambda$tryFinishTxnAsync$2(PublishVersionDaemon.java:250)
```

## 二、根因分析

### 2.1 核心 bug：`AgentTaskCleanupDaemon` 把 publish task 标成 `isFinished=true`，却不 set `succTablets`（保持 null）

#### 脏 task 的真正产生者：`AgentTaskCleanupDaemon.removeInactiveBeAgentTasks`

当一台 BE 服务器**突然挂掉**时，它上面的 `PublishVersionTask` 在创建时就是 `succTablets=null`（构造函数默认）、`isFinished=false`，且 BE 从不回报。FE 侧的 `AgentTaskCleanupDaemon` 周期性巡检：BE 连续 `MAX_FAILURE_TIMES=3` 次 `!isAlive()` 后，调用 `removeInactiveBeAgentTasks` 清理它的全部 agent task：

```44:82:fe/fe-core/src/main/java/org/apache/doris/task/AgentTaskCleanupDaemon.java
protected void runAfterCatalogReady() {
    infoService.getAllClusterBackends(false).forEach(backend -> {
        if (backend.isAlive()) {
            beInactiveCheckFailures.remove(id);
        } else {
            Integer failureTimes = beInactiveCheckFailures.compute(id, (beId, failures) -> {
                int updated = (failures == null ? 1 : failures + 1);
                if (updated >= MAX_FAILURE_TIMES) {       // 连续 3 次判死
                    removeInactiveBeAgentTasks(beId);
                }
                return updated;
            });
        }
    });
}

private void removeInactiveBeAgentTasks(Long beId) {
    AgentTaskQueue.removeTask(beId, (agentTask -> {       // ← 同时把 task 从队列删除
        ...
        agentTask.setFinished(true);                      // ← 标 finished，但【从不 set succTablets】
        agentTask.setErrorCode(TStatusCode.ABORTED);
        agentTask.setErrorMsg("BE down, this agent task is aborted");
    }));
}
```

`AgentTaskQueue.removeTask(beId, consumer)` 会遍历该 BE 的**所有任务**，逐个 `it.remove()`（移出队列）后再执行 consumer（`AgentTaskQueue.java:100-109`）。

关键缺陷：
1. `setFinished(true)` 被调用，但 `succTablets` **从未被赋值**，仍是构造函数里的 `null`（`PublishVersionTask.java:62`）。于是 task 进入 `isFinished=true && succTablets=null` 的"脏"状态。
2. task 同时被**从 `AgentTaskQueue` 删除**，但仍被 `transactionState.publishVersionTasks` 引用着 —— 这是后面"不可自愈"的根源（见 §2.2）。
3. errorCode 虽然被设为 `ABORTED`，但下游 `checkReplicaContinuousVersionSucc` **只看 `isFinished` + `succTablets`，不看 errorCode**，因此这层语义信息被丢弃。

> **为什么不是 `finishPublishVersion`（v1 的错误归因）**：BE 侧 `be/src/agent/task_worker_pool.cpp:2149` **无论 publish 成功失败都无条件 `__set_succ_tablets(succ_tablets)`**（失败时是空 map；该行自 2023 年 #24273 起就是无条件的，早于 4.0.5）。所以真实 4.0.5 BE 的回报里 `isSetSuccTablets()` 永远为 true，`finishPublishVersion` 拿到的是**空 map 而非 null**，空 map 在 1478 行 `containsKey()` 返回 false，**不会 NPE**。换言之，经 `finishPublishVersion` 根本产生不出 `succTablets=null` 的脏 task；null 的唯一来源就是上面这个 cleanup daemon。

#### 消费路径：`DatabaseTransactionMgr.checkReplicaContinuousVersionSucc`（NPE 发生处）

```1471:1503:fe/fe-core/src/main/java/org/apache/doris/transaction/DatabaseTransactionMgr.java
private void checkReplicaContinuousVersionSucc(...) {
    boolean success = true;
    for (int i = 0; i < subTxnIds.size(); i++) {
        PublishVersionTask task = replicaPublishTasks.get(i);
        success = (task != null && task.isFinished() && task.getSuccTablets().containsKey(tabletId)) || (
                replica.getState() == Replica.ReplicaState.ALTER && (...));
```

第 1478 行：`task != null && task.isFinished()` 通过后，直接 `task.getSuccTablets().containsKey(tabletId)`，**没有判断 `task.getSuccTablets() != null`**，于是 NPE。

### 2.2 为什么"卡死且不可自愈"

`PublishVersionDaemon.tryFinishOneTxn` 决定是否进入 finish 流程：

```186:236:fe/fe-core/src/main/java/org/apache/doris/transaction/PublishVersionDaemon.java
transactionState.getPublishVersionTasks().forEach((key, tasks) -> {
    long beId = key;
    for (PublishVersionTask task : tasks) {
        if (task.isFinished()) {
            calculateTaskUpdateRows(tableIdToTabletDeltaRows, task);
        } else {
            if (infoService.checkBackendAlive(task.getBackendId())) {
                hasBackendAliveAndUnfinishedTask.set(true);
            }
            notFinishTaskBe.add(beId);
        }
    }
});
...
boolean shouldFinishTxn = !hasBackendAliveAndUnfinishedTask.get() || transactionState.isPublishTimeout()
        || isPublishSlow ...;
if (shouldFinishTxn) {
    if (Config.enable_parallel_publish_version) {
        tryFinishTxnAsync(transactionState, globalTransactionMgr);
    } else {
        tryFinishTxnSync(transactionState, globalTransactionMgr);
    }
}
```

由于脏 task 的 `isFinished()=true`，循环既不会标 `hasBackendAliveAndUnfinishedTask`，也不会加入 `notFinishTaskBe`，于是 `shouldFinishTxn=true` 直接进入 `finishTransaction`，再次撞上 NPE。

NPE 在 `tryFinishTxnSync` 里被 `catch (Exception e)` 吞掉：

```266:280:fe/fe-core/src/main/java/org/apache/doris/transaction/PublishVersionDaemon.java
try {
    globalTransactionMgr.finishTransaction(transactionState.getDbId(),
            transactionState.getTransactionId(), partitionVisibleVersions, backendPartitions);
    addBackendVisibleVersions(partitionVisibleVersions, backendPartitions);
} catch (Exception e) {
    LOG.warn("error happens when finish transaction {}", transactionState.getTransactionId(), e);
}
```

事务始终走不到 `setTransactionStatus(VISIBLE)`（位于 `finishTransaction` 1176 行之后），永远停在 COMMITTED。

进一步阻塞链路：
1. `transactionState.hasSendTask()` 已经是 `true`，`PublishVersionDaemon.genPublishTask` 不会再为这个 txn 重新 dispatch publish task。
2. `transactionState.publishVersionTasks` 不持久化，但只要 FE 不重启，这个脏 task 就一直在内存里。
3. 上游 group commit 的 `loadTxnCommit` → `commitAndPublishTransaction` → `waitForTransactionFinished` 一直等，直到 `try_commit_lock_timeout_seconds` 超时返回错误。

#### 为什么"BE 恢复后仍然不可自愈"（已由现场行为实证）

这一点是区分真假根因的**判别性证据**。Doris 本来有一条 BE 恢复后的自愈路径：`ReportHandler.taskReport` → `AgentTaskQueue.getDiffTasks` 会把"仍在队列、但 BE 上没在跑"的 publish task **重新下发**，BE 重新 publish 并回报 OK 后回填 `succTablets`、治好脏 task。

**但 `AgentTaskCleanupDaemon` 在标脏的同时已经把 task 从 `AgentTaskQueue` 删除了**（§2.1，`removeTask` 第 106 行 `it.remove()`）。于是：

- BE 恢复后，`getDiffTasks` 里**根本没有这个 task** → 不会重发 → BE 没有机会重新 publish/回报 → 脏 task 永远不被治好。
- 脏 task 仍被 `transactionState.publishVersionTasks` 引用，`PublishVersionDaemon` 每个周期照样撞 NPE → **FE 持续刷 NPE，事务永久卡 COMMITTED**，与现场观测完全吻合。
- 只有重启 FE master 才恢复：`publishVersionTasks` / `hasSendTask` 都不持久化，重启后 `genPublishTask` 重新 dispatch 全新 publish task。

> **判别逻辑**：若按 v1 的 `finishPublishVersion` 归因（status != OK 时**不**删队列，注释 `be will retry`），脏 task 会留在队列，BE 恢复后会被重发治好 —— 那就应该"自愈"。现场观测到的恰恰是**不自愈**，正好证伪 v1、坐实 `AgentTaskCleanupDaemon`（删队列）路径。
>
> 此外：**打了 Fix #1 / Fix #3 后，事务根本不需要等 BE 回来或重发** —— 脏副本会立即进入 `errorReplicaIds` 并走 quorum 判断完成 publish。所以修复的正确性不依赖自愈路径。

### 2.3 BE 服务器突然挂掉场景的完整时序

```
T0  BE A 持有 txn 2985277233 的 publish task：isFinished=false, succTablets=null（默认）
T1  BE A 服务器突然挂掉（断电 / kill -9 / 宕机）——BE 进程消失，从不回报
T2  FE 心跳判定 BE A !isAlive()
    （此窗口内若其余副本满足 quorum，事务可正常转 VISIBLE，不触发本 bug；
      触发 bug 的前提是事务在 T3 之前还没凑齐 quorum 完成）
T3  AgentTaskCleanupDaemon 连续 3 次（MAX_FAILURE_TIMES）巡检到 BE A 死亡：
      removeInactiveBeAgentTasks(beId) →
        - AgentTaskQueue 中该 BE 的 publish task 被 it.remove() 删除
        - 对该 task 调 setFinished(true)，但【不 set succTablets】→ 仍为 null
      于是 task 变脏：isFinished=true && succTablets=null   ← bug 在此产生
T4  PublishVersionDaemon 周期性扫描 transactionState.publishVersionTasks:
      - task.isFinished()=true → shouldFinishTxn=true
      - tryFinishTxnSync → finishTransaction → checkReplicaContinuousVersionSucc:1478 → NPE
T5  catch (Exception) 吞掉 NPE，txn 仍然 COMMITTED
T6  循环重复 T4-T5，事务永久卡住，FE 持续刷 NPE
T7  BE A 服务器恢复，BE 重启、心跳恢复正常
T8  但 task 已在 T3 被移出 AgentTaskQueue → ReportHandler 无可重发 →
    BE A 不会被重新派发该 publish → 脏 task 依旧 → NPE 不止 → 仍卡 COMMITTED
T9  只有重启 FE master：publishVersionTasks/hasSendTask 不持久化，
    重启后 genPublishTask 重新 dispatch 全新 publish task → 事务才转 VISIBLE
```

## 三、修复计划

> **本卡死的最小修复 = Fix #1 + Fix #3**（两处 FE 侧小改动，互相独立）。Fix #2 是针对真正源头 `AgentTaskCleanupDaemon` 的可选修复，与 Fix #3 二选一即可。

### Fix #1 (必做)：`checkReplicaContinuousVersionSucc` 加 null 判断

**目的**：直接堵住 NPE，让事务进入正常的 errorReplica 流程，不再永久卡死。

**文件**：`fe/fe-core/src/main/java/org/apache/doris/transaction/DatabaseTransactionMgr.java`

**改动位置**：第 1478 行

```java
// 原代码：
success = (task != null && task.isFinished() && task.getSuccTablets().containsKey(tabletId)) || (
        replica.getState() == Replica.ReplicaState.ALTER && (!Config.publish_version_check_alter_replica
                || subTxnIds.get(i) < alterWaterschedTxnId || alterWaterschedTxnId == -1));

// 修改后：
success = (task != null && task.isFinished() && task.getSuccTablets() != null
            && task.getSuccTablets().containsKey(tabletId))
        || (replica.getState() == Replica.ReplicaState.ALTER && (!Config.publish_version_check_alter_replica
                || subTxnIds.get(i) < alterWaterschedTxnId || alterWaterschedTxnId == -1));
```

**预期效果**：脏 task 会被识别为该副本未成功，进入 `errorReplicaIds`，走原有的 quorum 副本判断 / 重试逻辑，不会再 NPE。

> 说明：若该 tablet 的**所有**副本都落在返回脏 task 的 BE 上（如滚动重启同时命中多台 BE），全部进入 `errorReplicaIds` 后 quorum 不满足，`finishCheckQuorumReplicas` 返回 `FAILED`，`finishTransaction` 在第 1158–1160 行提前 return，事务保持 COMMITTED 等待下个周期重试 —— 这是正确的"等副本恢复"行为，不是死锁。

### Fix #2 (推荐)：`AgentTaskCleanupDaemon` 清理 BE 任务时不要制造"脏 finished"

**目的**：从**真正的源头**（cleanup daemon）避免脏 task 的产生。

> **v1 勘误**：v1 的 Fix #2 改的是 `MasterImpl.finishPublishVersion`。经 §2.1 证实，本卡死的脏 task **不经过 `finishPublishVersion`**（4.0.5 BE 总会 set succTablets，该路径产生不出 null），因此 **v1 Fix #2 对本场景无效**，已废弃。下面是对症的新 Fix #2。

**文件**：`fe/fe-core/src/main/java/org/apache/doris/task/AgentTaskCleanupDaemon.java`

**改动位置**：`removeInactiveBeAgentTasks` 第 68-82 行

```java
// 问题：对所有类型 task 一律 setFinished(true)，但 PUBLISH_VERSION 的 succTablets 仍是 null，
//      下游 checkReplicaContinuousVersionSucc 只看 isFinished+succTablets，于是 NPE。

// 方案 A（推荐，最小且语义清晰）：清理 PUBLISH_VERSION 任务时，给 succTablets 兜底为空 map
private void removeInactiveBeAgentTasks(Long beId) {
    AgentTaskQueue.removeTask(beId, (agentTask -> {
        String errMsg = "BE down, this agent task is aborted";
        if (agentTask instanceof PushTask) {
            ((PushTask) agentTask).countDownLatchWithStatus(beId, agentTask.getTabletId(),
                    new Status(TStatusCode.ABORTED, errMsg));
        }
        if (agentTask instanceof PublishVersionTask
                && ((PublishVersionTask) agentTask).getSuccTablets() == null) {
            // BE 已死、该副本 publish 视为失败：置空 map，让下游判为该副本未成功 → 走 quorum，
            // 而不是留 null 触发 NPE
            ((PublishVersionTask) agentTask).setSuccTablets(Maps.newHashMap());
        }
        agentTask.setFinished(true);
        agentTask.setErrorCode(TStatusCode.ABORTED);
        agentTask.setErrorMsg(errMsg);
    }));
}

// 方案 B（备选）：PUBLISH_VERSION 不标 finished（留 isFinished=false）。
//   下游对 isFinished=false 的 task 直接判该副本未成功 → 走 quorum，同样不 NPE。
//   但 BE 死亡场景下 checkBackendAlive=false，不会阻塞 shouldFinishTxn，行为与方案 A 等价。
```

**预期效果**：cleanup daemon 标记死 BE 的 publish task 时不再留下 `succTablets=null` 的脏状态，下游正常判为该副本失败、走 quorum。

> 注：若同时打了 **Fix #3**（让 `succTablets` 构造默认即为空 map），本 Fix #2 其实就不再必要 —— Fix #3 已经在更底层堵死了 null。三者关系见 §九。

### Fix #3 (强烈推荐，实为本卡死的最干净源头修复)：`PublishVersionTask` 默认值与 setter 兜底

**目的**：让 `succTablets` 永远不为 null。**这恰好直接中和 §2.1 的 cleanup daemon 路径**（它 setFinished 但不碰 succTablets，只要默认值是空 map 就不会 NPE），是本卡死成本最低、最对症的源头修复。

**文件**：`fe/fe-core/src/main/java/org/apache/doris/task/PublishVersionTask.java`

```java
// 原代码：
public PublishVersionTask(long backendId, long transactionId, long dbId,
        List<TPartitionVersionInfo> partitionVersionInfos, long createTime) {
    super(...);
    ...
    this.succTablets = null;
    this.errorTablets = new ArrayList<>();
    this.isFinished = false;
}
...
public void setSuccTablets(Map<Long, Long> succTablets) {
    this.succTablets = succTablets;
}

// 修改后：
public PublishVersionTask(long backendId, long transactionId, long dbId,
        List<TPartitionVersionInfo> partitionVersionInfos, long createTime) {
    super(...);
    ...
    this.succTablets = Maps.newHashMap();
    this.errorTablets = new ArrayList<>();
    this.isFinished = false;
}
...
public void setSuccTablets(Map<Long, Long> succTablets) {
    this.succTablets = succTablets == null ? Maps.newHashMap() : succTablets;
}
```

> 安全性确认：全仓库范围内 `PublishVersionTask.getSuccTablets()` 的唯一消费点就是 `DatabaseTransactionMgr.java:1478`，**没有任何代码用 `succTablets == null` 区分"未上报"与"上报了空结果"**，因此把默认值改成空 map 不会破坏任何现有语义。

## 四、验证步骤

### 4.1 单元测试
- 新增 `DatabaseTransactionMgrTest`：构造 `PublishVersionTask` 设置 `isFinished=true && succTablets=null`，调用 `finishTransaction` 应该不抛 NPE，事务可以走完正常流程（覆盖 Fix #1）。
- 新增 `AgentTaskCleanupDaemonTest`：构造一台 `!isAlive()` 的 BE 与其 `PublishVersionTask`，连续触发 3 次巡检后调用 `removeInactiveBeAgentTasks`，验证被标 finished 的 publish task 的 `getSuccTablets()` **不为 null**（覆盖 Fix #2/#3）。
- 新增 `PublishVersionTaskTest`：`new PublishVersionTask(...)` 后 `getSuccTablets()` 应为非 null 空 map；`setSuccTablets(null)` 后仍为非 null 空 map（覆盖 Fix #3）。

### 4.2 集成回归（务必复现真实触发条件：硬挂，而非优雅关机）
1. 部署带 patch 的 FE。
2. 对一张开启 group commit、3 副本的表持续写入。
3. **`kill -9` 其中一台 BE（或直接断电/宕机），模拟服务器突然挂掉**；保持 BE 不启动，等待超过 `3 × agent_task_health_check_intervals_ms`，让 `AgentTaskCleanupDaemon` 触发清理。
4. 观察 FE 日志：**不应再出现 `DatabaseTransactionMgr.java:1478` 的 NPE**；`SHOW PROC '/transactions/<dbId>/running'` 不应有长期卡在 COMMITTED 的事务。
5. **再启动该 BE，等其重新加入集群**：验证事务能正常完成（patch 前的关键缺陷正是"BE 恢复后仍卡"，这里要确认已消除）。
6. 对照组（验证修复前能稳定复现）：在未打 patch 的环境重复 3-5，应能看到 NPE 持续刷屏 + 事务卡 COMMITTED + BE 恢复后不自愈。

### 4.3 故障演练
- 写入高峰期 `kill -9` 一台 BE，等 cleanup daemon 触发后再拉起，验证一致性与可用性。
- 可用 debug point 直接构造脏 task（`isFinished=true && succTablets=null`）注入 `transactionState.publishVersionTasks`，验证 `PublishVersionDaemon` 周期不再 NPE。

## 五、临时缓解方案（未打 patch 时）

| 场景 | 操作 | 说明 |
| --- | --- | --- |
| 已经卡死，需立即恢复 | 重启 master FE | `transactionState.publishVersionTasks`/`hasSendTask` 不持久化，重启后 `PublishVersionDaemon` 会重新 dispatch publish task。**这是已卡死事务唯一的现成恢复手段** |
| 计划内停机减少触发 | 停 BE 前先 `ALTER SYSTEM DECOMMISSION BACKEND` 迁走副本 | 仅对**计划内**运维有效；对突然宕机/断电无能为力（本 bug 的真实触发恰是非计划硬挂） |
| 流量重定向 | session 级 `SET group_commit = "off_mode"` | 让 group commit 流量走普通通道，绕过缓存的 BE 选择（缓解 §九②类问题） |

> **【v2 删除并纠正】v1 表中"用 `kill -9` 替代 `stop_be.sh` 可减少触发"是【完全反的】**：硬挂（导致 BE `!isAlive()`）正是触发 `AgentTaskCleanupDaemon` 标脏的**唯一条件**；而优雅关机时 BE 若还能回报，反而会 set 空 map、**不会** NPE。请勿采用该"缓解"。
>
> 另：本 bug 的脏 task 由 cleanup daemon（BE 判死）产生，与协调 BE 的 `abortTxnWhenCoordinateBeDown` 路径无关，故 v1 表中 `enable_abort_txn_by_checking_coordinator_be=false` 一项对本卡死无效，已移除。

## 六、关联的社区 PR（4.0.5 上的状态）

> 4.0.5 是 4.0.x 当前最新发布版本（commits 截止时间：2026-04 之前）。
> 下列 PR 全部仅合到了 master / branch-4.1，**未 backport 到 branch-4.0**，需要手动 cherry-pick。

| PR | 说明 | 4.0.5 是否包含 | branch-4.1 是否包含 |
| --- | --- | --- | --- |
| [#60652](https://github.com/apache/doris/pull/60652) | Fix NPE in group commit when backend belongs to a different cluster；补 cluster 一致性检查 | ❌ | ✅ (via #61953) |
| [#61555](https://github.com/apache/doris/pull/61555) | group commit select backend should consider isLoadAvailable；补 `isShutDown / isLoadDisabled` 检查 | ❌ | ✅ (via #61953) |
| [#61881](https://github.com/apache/doris/pull/61881) | Fix IllegalMonitorStateException in routine load afterAborted when coordinate BE restarts | ❌ | ❌ |
| [#61953](https://github.com/apache/doris/pull/61953) | branch-4.1 backport 集合（包含 #60652、#61555） | ❌ | ✅ |
| [#58676](https://github.com/apache/doris/pull/58676) | group commit skip decommissioning backend | ✅ (via #58712) | ✅ |

> 注：4.0.5 已经包含 [#58676](https://github.com/apache/doris/pull/58676)（"group commit skip decommissioning backend"）的 4.0 backport（commit `7e5f44c7a00`），但 4.0.5 仍然缺少其余三个关键 PR。
>
> 强烈建议把 #60652 / #61555 / #61881 cherry-pick 到内部 fork（4.0.5 base），连同本文档的三个 fix 一起打入。前三者解决 BE 选择缓存与 cluster 一致性；本文档的 fix 解决 publish 阶段的 NPE 卡死。
>
> 校验记录（2026-05-27，于 tag `4.0.5` / HEAD `59de8c4c524`）：`git merge-base --is-ancestor` 确认 `48894b90f61`(#60652)、`36311d42300`(#61555)、`1863fbf0e51`(#61881) 均**不是** HEAD 祖先（未包含）；`7e5f44c7a00`(#58676 via #58712) **是** HEAD 祖先（已包含）。三个待 cherry-pick 的 commit 哈希在本仓库均真实存在。

## 七、深度防御建议

1. **brpc 调用加超时**：`fe/fe-core/src/main/java/org/apache/doris/rpc/BackendServiceClient.java` 第 180-182 行的 `groupCommitInsert` 没有 `withDeadlineAfter`（直接 `stub.groupCommitInsert(request)`），BE 异常时 FE 线程会死等 `future.get()`。建议参考同文件 `getBeResource`（第 197 行 `stub.withDeadlineAfter(timeoutSec, TimeUnit.SECONDS).getBeResource(request)`）的写法加 deadline。
2. **`abortTxnWhenCoordinateBeRestart` 加 null 防御**（标准模式 `GlobalTransactionMgr.java` 第 656-672 行）：
   ```java
   TransactionState transactionState = dbTransactionMgr.getTransactionState(txnInfo.second);
   if (transactionState == null || transactionState.getCoordinator() == null) {
       continue;
   }
   long coordStartTime = transactionState.getCoordinator().startTime;
   ```
   注意：第 663 行 `transactionState.getCoordinator().startTime` 的 NPE 属于 `RuntimeException`，**当前的 `catch (UserException e)` 根本抓不住**，会向上抛出并中断整个 for 循环，导致这一批 PREPARE 事务后续的 abort 全部被跳过。除了加 null 判断，还应把 `catch (UserException e)` 加宽为 `catch (Throwable e)`，避免单个 txn 出问题中断整批 abort。
3. **`waitForTransactionFinished` 加 null 防御**（`DatabaseTransactionMgr.java` 第 891-922 行）：第 901 行的 `transactionState.getTransactionStatus()` 在 `unprotectedGetTransactionState` 返回 null 时会 NPE，应当先判断 null。

## 八、关键文件与行号速查

| 文件 | 行号 | 说明 |
| --- | --- | --- |
| `fe/fe-core/src/main/java/org/apache/doris/transaction/DatabaseTransactionMgr.java` | 1478 | **NPE 发生处** (Fix #1) |
| `fe/fe-core/src/main/java/org/apache/doris/task/AgentTaskCleanupDaemon.java` | 44-66, 68-82 | **脏 task 真正产生者**：BE 判死后 `setFinished(true)` 不 set succTablets (Fix #2) |
| `fe/fe-core/src/main/java/org/apache/doris/task/AgentTaskQueue.java` | 100-109 | `removeTask(beId, consumer)`：第 106 行 `it.remove()` 删队列 → BE 恢复后无法重发（不可自愈根源） |
| `fe/fe-core/src/main/java/org/apache/doris/task/PublishVersionTask.java` | 62, 86 | succTablets 构造默认 null、setter 无兜底 (Fix #3，最干净源头修复) |
| `be/src/agent/task_worker_pool.cpp` | 2149 | **反证**：BE 无条件 `__set_succ_tablets`（失败也 set 空 map）→ 真实回报不会产生 null，证明非 `finishPublishVersion` 所致 |
| `fe/fe-core/src/main/java/org/apache/doris/master/MasterImpl.java` | 543-574 | `finishPublishVersion`（v1 误判的源头；4.0.5 下不会产生 null 脏 task） |
| `fe/fe-core/src/main/java/org/apache/doris/transaction/PublishVersionDaemon.java` | 121-125, 186-237, 266-303 | `genPublishTask` 的 `hasSendTask` 门控 / `tryFinishOneTxn` / `tryFinishTxnSync` 吞 NPE |
| `fe/fe-core/src/main/java/org/apache/doris/master/ReportHandler.java` | 710-768 | `taskReport`→`getDiffTasks` 重发路径（task 已被删 → 不触发） |
| `fe/fe-core/src/main/java/org/apache/doris/load/GroupCommitManager.java` | 336-379 | BE 选择缓存（缺 isLoadAvailable，对应 #61555） |
| `fe/fe-core/src/main/java/org/apache/doris/rpc/BackendServiceClient.java` | 180-182 | brpc 调用未加 deadline |
| `fe/fe-core/src/main/java/org/apache/doris/transaction/GlobalTransactionMgr.java` | 656-672 | `abortTxnWhenCoordinateBeRestart` 的 NPE 路径 |

## 九、修复优先级总结

> **【评审结论 v2】①类修复（Fix #1 + Fix #3）只消除 FE 端的 NPE 永久死锁；"group commit + BE 异常"的完整场景还涉及 ② 写入打到将死 BE、③ hung BE 阻塞 FE 线程。下面先给「最小完整集」（已按 v2 根因更正），再给完整优先级表。**

### 9.1 最小完整集（要真正解决已报告的事故，三类问题缺一不可）

| 目标 | 必须包含的项 | 不打的后果 |
| --- | --- | --- |
| ① 止死锁：FE 不再永久卡 COMMITTED | **Fix #1（必做）+ Fix #3（源头，必做）**；Fix #2 与 #3 二选一 | BE 服务器突然挂掉 → `AgentTaskCleanupDaemon` 把 publish task 标脏（isFinished=true、succTablets=null）→ 1478 NPE 风暴、事务永久卡 COMMITTED，**且 BE 恢复也不自愈**（task 已被移出队列），只能重启 FE master |
| ② 止误派：写入不再打到正在关机的 BE | Cherry-pick #61555 + #60652 | 关机窗口内 group commit 持续写到 `isAlive=true` 但已拒绝 load 的 BE（`GroupCommitManager.java:352/370` 仅检查 `isAlive`/`isDecommissioned`，缺 `isLoadAvailable`/`isShutDown`），写入抖动/失败 —— group commit 特有的**写入可用性问题**（与①的卡死是两回事，但同属 BE 异常场景） |
| ③ 止阻塞：FE 线程不再死等 hung BE | brpc deadline（§7.1，**由 P2 提升为必做**） | BE 进程 hang（非干净失败）时 `groupCommitInsert` 的 `future.get()` 无超时，FE 线程无限阻塞 —— 独立于①的另一条路径 |

> 说明：**对你当前报告的"硬挂卡 COMMITTED、BE 恢复也不好、需重启 FE"事故，①（Fix #1 + Fix #3）即可根治**；②③是同一类 BE 异常场景下的其它问题，建议一并处理但不属于本卡死的必需项。

> - 只打 ① 不打 ②：卡死消失，但用户写入在 BE 重启窗口内仍会失败/重试。
> - 只打 ①② 不打 ③：干净失败的 BE 没问题，但遇到 hung（卡住不死）的 BE 仍会阻塞 FE 线程。
> - 三者同时具备，才能覆盖"BE 突然挂掉（①）/ 写入打到将死 BE（②）/ 进程 hang（③）"三类 BE 异常问题。

### 9.2 完整优先级表

| 优先级 | 项目 | 归属 | 影响 |
| --- | --- | --- | --- |
| P0 | Fix #1（1478 加 null 判断） | ① | 立即消除 NPE 卡死，必须打 |
| P0 | Fix #3（succTablets 默认空 map） | ① | **本卡死最干净的源头修复**：直接中和 `AgentTaskCleanupDaemon` 标脏路径。**由 v1 的 P1 提升为 P0** |
| P1 | Fix #2（改 `AgentTaskCleanupDaemon`） | ① | 在 cleanup daemon 处给 succTablets 兜底；**与 Fix #3 二选一**，打了 #3 则非必需（v1 改 `finishPublishVersion` 的方案已废弃，对本场景无效） |
| P0 | Cherry-pick #61555 + #60652 | ② | group commit 写入可用性；不打则写入仍打到将死 BE。4.1 已合并，4.0 需手动 cherry-pick |
| P0 | brpc deadline（§7.1） | ③ | hung BE 会让 FE 线程无限死等，独立于 NPE 的另一条卡死路径 |
| P1 | `abortTxnWhenCoordinateBeRestart` null 防御 + `catch(Throwable)`（§7.2） | 加固 | 第 663 行 NPE 属 `RuntimeException`，现有 `catch(UserException)` 抓不住，会中断整批 PREPARE 事务的 abort |
| P2 | Cherry-pick #61881 | 可选 | **不在最小完整集**：仅 cloud + routine load 场景需要（`afterAborted` lock-handoff），与标准模式 publish NPE 死锁无关 |
| P3 | `waitForTransactionFinished` null 防御（§7.3） | 加固 | 进一步降低边角 NPE 概率 |

> **本卡死的最小修复 = Fix #1 + Fix #3**（两处 FE 侧小改动）。Fix #2 可选（与 #3 二选一）。②③属同场景的其它问题，按需一并处理。

## 十、Cherry-pick 操作清单（4.0.5 → 4.0.5-fix）

> 假设新分支基于 `4.0.5` 创建，名为 `4.0.5-fix-group-commit`。

```bash
# 1. 创建修复分支
git checkout -b 4.0.5-fix-group-commit 4.0.5

# 2. 按依赖顺序 cherry-pick 社区已有 PR
git cherry-pick 48894b90f61   # #60652 cluster 一致性 + Coordinator NPE 防御
git cherry-pick 36311d42300   # #61555 isLoadAvailable 检查
git cherry-pick 1863fbf0e51   # #61881 cloud 模式下 abortTxn lock-handoff 修复
# 注：cherry-pick 过程中若有冲突，多半发生在 GroupCommitManager.java
#     和 CloudGlobalTransactionMgr.java，按 conflict 解决即可

# 3. 应用本文档的 FE 侧 patch（本卡死最小集 = Fix #1 + Fix #3）
#    - Fix #1: DatabaseTransactionMgr.java 第 1478 行加 null 判断
#    - Fix #3: PublishVersionTask.java 第 62/86 行改默认值（构造 + setter 兜底空 map）
#    - Fix #2(可选,与#3二选一): AgentTaskCleanupDaemon.removeInactiveBeAgentTasks 给 succTablets 兜底

# 4. 应用 brpc deadline（最小完整集 ③，必做）
#    - BackendServiceClient.groupCommitInsert 加 withDeadlineAfter（参考同文件 getBeResource）

# 5. （可选）其余深度防御
#    - GlobalTransactionMgr.abortTxnWhenCoordinateBeRestart 加 null 防御 + catch(Throwable)
#    - DatabaseTransactionMgr.waitForTransactionFinished 加 null 防御

# 6. 跑 fe 单元测试
cd fe && mvn test -pl fe-core -Dtest=DatabaseTransactionMgrTest,GlobalTransactionMgrTest

# 7. 打包
sh build.sh --fe
```

### 风险提示

- 4.1 上 #60652 与 #61555 的 cluster 检查依赖 `Backend.getCloudClusterName()` 等字段。4.0.5 已经具备该字段（4.0 的 cloud mode 是 GA 状态），cherry-pick 应该可以干净应用，但仍需确认 conflict。
- #61881 改动了 `CloudGlobalTransactionMgr.handleAfterAbort` 签名，cherry-pick 时若 4.0.5 上该函数签名略有差异，需手工对齐。
- 本文档的 Fix #1/#3 仅触碰 `DatabaseTransactionMgr.java`、`PublishVersionTask.java`（Fix #2 触碰 `AgentTaskCleanupDaemon.java`），均与 4.0/4.1 的 cloud 改造无依赖，可独立打。

---

## 附录：校验说明（2026-05-27）

本文档已在 tag `4.0.5`（HEAD `59de8c4c524`）的实际代码上逐条校验。

### v2 根因更正（2026-05-27，最重要）

经代码追踪 + 现场行为比对，**推翻 v1 关于脏 task 产生者的判断**：

- **真凶**：`AgentTaskCleanupDaemon.removeInactiveBeAgentTasks`（`AgentTaskCleanupDaemon.java:68-82`）。BE 服务器突然挂掉 → 连续 3 次判死 → 对其 publish task `setFinished(true)` 但不 set `succTablets`（仍为构造默认 null）→ 脏 task；同时 `AgentTaskQueue.removeTask` 第 106 行把 task 移出队列。
- **反证 v1**：BE 侧 `task_worker_pool.cpp:2149` 无条件 `__set_succ_tablets`（失败也 set 空 map，自 2023 #24273 起），故 `finishPublishVersion` 在 4.0.5 不可能产生 `succTablets=null` 的脏 task。v1 归因错误。
- **判别证据**：现场观测"BE 恢复后事务仍卡 COMMITTED、FE 持续刷 NPE"。task 已被移出队列 → `ReportHandler.getDiffTasks` 无可重发 → 无法自愈，与现场吻合；而 v1 路径（task 留队列）会被重发治好，与现场矛盾。
- **触发条件更正**：是 **BE 服务器突然挂掉（硬故障）**，不是 v1 所说的 `stop_be.sh` 优雅关机；v1 §5"kill -9 可减少触发"完全反了，已删除纠正。

受影响并已改写的章节：§1 现象表、§2.1 根因、§2.2 不可自愈机制、§2.3 时序、§3 Fix #2（改为 `AgentTaskCleanupDaemon`，旧 `finishPublishVersion` 方案废弃）、§3 Fix #3（提为 P0 源头修复）、§4 验证、§5 缓解、§8 速查、§9 优先级、§10 操作清单。

**本卡死的最小修复 = Fix #1（1478 加 null 判断）+ Fix #3（succTablets 默认空 map）**，两处 FE 侧小改动即可根治"硬挂卡 COMMITTED + BE 恢复不自愈 + 需重启 FE"。

### v1 已校验且仍有效的内容

- §6 PR backport 状态与 commit 哈希（`git merge-base --is-ancestor` 核对一致）。
- §7 深度防御：brpc deadline（`BackendServiceClient.java:182` 无 deadline）、`abortTxnWhenCoordinateBeRestart` 的 `catch(UserException)` 抓不住 663 行 NPE。
- §9 的「最小完整集」框架（①止死锁 / ②止误派 / ③止阻塞），其中①的具体修复项已按 v2 更正。

> 整体结论：①类卡死（你报告的事故）由 **Fix #1 + Fix #3** 根治，根因已闭合、无猜测成分；②③为同场景的写入可用性 / hung BE 问题，按需处理。仍待补：§4 集成回归未实测（建议按"kill -9 + 等 cleanup daemon 触发 + 再拉起 BE"复现验证），以及若能拿到现场 FE 日志中 `AgentTaskCleanupDaemon` 的清理记录（errorMsg `BE down, this agent task is aborted`）作为实锤更佳。
