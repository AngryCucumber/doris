# Tablet 级同节点异构存储分层（B 路线）总设计 v2（合并重写）

> 配套执行计划：`docs/tablet-tiering-b-route-execution-plan-v2.md`（带 file:line 落点、阶段、验收）。
> 本版把九轮评审（R1–R80）的定稿结论吸收进正文，以架构/语义形式呈现；本文回答 **what/why**，落点 **where/how** 见执行计划。R 编号仅留文末 §18 追溯。

## 1. 背景与结论（专利对齐）

专利要求系统依据**访问频率、最近访问时间、扫描字节数、点查次数、生命周期策略、租户策略**，决定数据在**同一 BE 节点内**的 SSD/HDD 放置。现有代码已具备本地 tablet 迁移底座：FE 可下发 `STORAGE_MEDIUM_MIGRATE`，BE 通过 `EngineStorageMigrationTask` 复制 rowset/索引、生成新 tablet meta、reload tablet、失败清理。

B 路线不重写迁移底座，而补齐：tablet 级热度采集与滑动窗口、tablet 级目标介质与迁移状态元数据、表/分区/租户三级策略、独立于 partition `DataProperty` 的 tablet tier 调度、与 report/repair/clone/disk balance/schema change/compaction 的兼容边界、完整可观测/回滚/灰度/测试。

**核心语义**：partition 是 SQL/数据组织逻辑对象；**tablet 是冷热放置最小决策单元**；**replica 是迁移执行对象**。

## 2. 范围边界（一句话）

作用对象是"单个 BE 节点内、仍驻留本地磁盘的 tablet 数据"，在本地 SSD↔HDD 间迁移。**cloud 模式、跨节点、远端/对象存储文件均在范围外**——遇到这些要么 gating 关闭整条链路（cloud），要么把对应 tablet 判 FROZEN 跳过（remote cooldown），**绝不触碰远端数据**。

## 3. 设计目标

**功能**：①同 partition 内 tablet 级 SSD/HDD 混合放置；②table/partition/tenant 三层策略（冲突优先级 tenant>partition>table，**首期只启用 table/partition，tenant 为 P2**）；③访问升温/生命周期降冷/SSD 压力驱逐/人工锁定；④迁移不改 tablet id/replica id/partition id/schema hash/查询入口/副本拓扑；⑤失败时旧目录继续服务、目标暂存清理；⑥FE/BE 重启、重复 report、重复任务均幂等；⑦灰度/dry-run/可观测/人工干预。

**非功能**：热路径开销可控（默认异步聚合）；调度器不阻塞 report/事务发布/clone/repair 主路径；迁移有全局与单 BE 并发限制；支持滚动升级（旧 BE 不上报热度时不触发 tablet 级自动迁移，由 capability bit 守卫）；所有新增 thrift 字段 optional、默认兼容旧版本。

**非目标**：rowset 级跨目录放置；改 SQL 路由/副本选择协议；跨节点复制式冷热迁移；SSD 作透明缓存；首期复杂 ML 热度预测；cloud 模式；远端文件放置。

## 4. 术语

| 名称 | 含义 |
| --- | --- |
| tablet target medium | FE 对一个 tablet 期望的介质（SSD/HDD），存于 `TabletTierState.target`，缺省回退 partition default |
| replica actual medium | 某 backend 上 replica 当前数据目录的实际介质，**唯一来源=tablet report** |
| effective target | `resolveEffectiveTarget(tabletId)` = `TabletTierState.target` ?? partition default；**不缓存于 `TabletMeta`** |
| isTieringOwned(tablet) | 该 tablet 的 table/partition 曾 effective-enable tiering 且未 detach；**唯一的 legacy 屏蔽判据** |
| HeatProfile | tablet 访问热度画像（FE 内存） |
| PROMOTE / DEMOTE | HDD→SSD / SSD→HDD |
| FROZEN | 因 txn/compaction/schema change/容量/人工/remote cooldown 暂不迁移 |

## 5. 总体架构

```
Query/PointLookup/Scan → BE TabletHeatCollector(分片+5m/1h/1d ring)
  → BE TabletHeatReporter(独立 worker, 30s, 绝对值快照, 周期主动 full)
  → FE TabletTieringMgr(ReportType.HEAT, 可累加, epoch/seq 去重)
  → TieringPolicyManager(字段级合并 + effective_revision)
  → 评分 → 状态机(温度→target) → TieringDecision(dry-run gate)
  → TabletTieringScheduler 产出 TabletSchedCtx(TIER_MIGRATION) → TabletScheduler(复用)
  → StorageMediaMigrationTask(dest_path_hash, attempt_id, strict) → BE check+execute
  → finish(copy stats/attempt/reason) → ReplicaTierProgress(AWAITING_REPORT 屏障)
  → 后续 tablet report reconcile actual medium/path（单一来源）
```

## 6. 元数据设计

### 6.1 TieringPolicy（字段级三态，scope=TABLE/PARTITION/TENANT）

字段：policy_id、scope_type、scope_id、enabled、hot_threshold、cold_threshold、cooldown_time_sec、min_hot/cold_residence_sec、max_ssd_bytes、point_lookup_weight、scan_bytes_weight、batch_scan_penalty、manual_hold、updated_time_ms。**所有可继承字段为 optional（三态：未设/设为值）**。

**解析（字段级合并，非 winner-takes-all）**：
```
resolvePolicy(tablet):
  eff = default policy                      // 所有字段有默认值
  for scope in [table, partition, tenant]:  // 低→高优先级
    p = policy of scope (if exists)
    if p == null: continue
    for each explicitly-set field f in p:   // enabled 也是字段
      eff[f] = p[f]                          // 未设字段继承父级
  if eff.enabled == false: return DISABLED  // 合并后再判，高优先级 scope 可重新 enable
  return eff
```
- partition 只设 hot/cold_threshold 时，其余（enabled/配额/权重）继承 table。
- **`enabled` 局部生效**：合并后判定，table enabled=false 不会短路挡住更高优先级 partition/tenant 重新 enable。
- **SSD quota 是层级约束、非简单覆盖**：table 级配额由所有 partition 共享，partition 自设配额取 min(自身, 剩余父级)。
- **版本**：单个 scope 的 epoch 无法表达字段级合并后的有效版本（父变而子 epoch 不变）。manager 维护 **派生式 `effective_revision`**（= 该 tablet 贡献 scope 的 epoch 组合，如 max/hash(table_epoch, partition_epoch, tenant_epoch)）；**不用全局单调**（否则任一表改策略会过度失效其他表的在途任务）。迁移任务携带它，finish 回传后 FE 用"当前重新解析的该 tablet effective_revision"比对判 stale——只有该 tablet 相关 scope 变更才失效。

### 6.2 TabletHeatProfile（FE 内存，key=tablet_id）

read_count_5m/1h/1d、scan_bytes_1h、point_lookup_count_5m/1h、full_scan_count_1h、last_access_time_ms、last_write_time_ms、current_score、temperature_state、last_eval_time_ms。访问计数不逐次写 edit log，低频 checkpoint。

### 6.3 TabletTierState（FE 持久化，key=tablet_id）

tablet_id、table_id、partition_id、target_medium（SSD/HDD）、previous_target_medium、`effective_revision`（产生该状态的策略版本）、reason_code、temperature_state（HOT/WARM/COLD/POLICY_FROZEN）、last_migration_time_ms、last_target_change_time_ms、frozen_reason、manual_override、version（幂等版本，手工改单 tablet 时 bump 此字段而非 scope 级 revision）。

**lazy state**：tablet 出生/add partition/restore **不预建 state**；仅首次产生非 WARM 决策时才写。无 state 时 `resolveEffectiveTarget` 回退 partition default。**legacy 屏蔽不依赖 state 是否存在，而依赖 `isTieringOwned`**。

### 6.4 ReplicaTierProgress（FE 内存，不逐条持久化）

tablet_id、replica_id、backend_id、current_path_hash、current_medium、target_path_hash、target_medium、task_signature、`migration_attempt_id`、**state**、last_error、retry_after_ms。

**state（replica 级，与 tablet 级温度分离）**：`PENDING / RUNNING / AWAITING_REPORT(+outcome: SUCCEEDED | UNKNOWN) / RETRY_WAIT / UNAVAILABLE`。`PARTIAL` 仅作聚合展示、不入此枚举（避免一个 replica UNAVAILABLE 阻塞其他 replica）。

**跨重启**：`AgentTaskQueue`/`runningTablets`/`ReplicaTierProgress` 均内存态、随进程清空；`STORAGE_MEDIUM_MIGRATE` 是 non-resend。**不承诺跨重启重建 in-flight**；恢复只靠持久化 `TabletTierState.target`（意图）+ tablet report 恢复的 actual——`actual != target` 时 scheduler 重评估补发（天然幂等）。

## 7. Thrift 协议（建议编码前由一人统一冻结字段号与枚举）

### 7.1 热度上报（绝对值模式）

`TReportRequest` 加 `17 tablet_heat_stats`、`18 tablet_heat_report_full`、`19 tablet_heat_report_epoch`、`20 tablet_heat_report_seq`。`TTabletHeatStat` 携带 **5m/1h/1d 绝对计数**（read/point_lookup/range_scan/full_scan/scan_bytes/scan_rows）+ last_access/last_write + current_medium/current_path_hash（**仅诊断**）。**BE 无 tenant，删 tenant_id**。

**语义（定稿）**：
- **绝对值**：每次上报携带 BE 当前窗口绝对值，FE 按 (BE,tablet) **覆盖**快照、跨 BE 求和（不再 delta/清零）。
- **ACK = 入队 only**：`TMasterResult` 不扩展（现 RPC 入队即返回、只有 status，无法同步 ACK）。
- **full = BE 周期主动**：BE 按 `tablet_heat_full_interval` 主动发 full snapshot（不依赖 FE 请求）；full 按 `snapshot_id`/`chunk_index`/`chunk_count` 分片暂存、到齐**原子替换**、加 TTL/tombstone（防 BE 淘汰 tablet 后 FE 永久残留旧热度）。
- **FE 接收**：`ReportHandler.ReportType` 加 `HEAT`，dispatch 识别 heat-only 请求；`reportTasks` 改**可累加队列**（现按 (be,type) 覆盖会丢报文），用 epoch/seq 去重/丢过期。

### 7.2 迁移任务与回执

`TStorageMediumMigrateReq` 1..10（tablet/schema_hash/storage_medium/data_dir/src_path_hash/dest_path_hash/policy_epoch→改 `effective_revision`/reason_code/tablet_tier_state_version/strict_check）+ `11 migration_attempt_id`。**TIER 任务只传 `dest_path_hash` 不设 data_dir**。

`TFinishTaskRequest` 复用 `copy_size`/`copy_time_ms`/`finish_tablet_infos`/`TTabletInfo.path_hash`/`storage_medium`，并加 optional `migration_attempt_id`、`policy_effective_revision`、`tablet_tier_state_version`、`migration_reason_code`（typed enum：OK/ALREADY_APPLIED/STALE/CAPACITY/SCHEMA_CHANGE/RETRYABLE/...）、`retryable`。

### 7.3 capability bit

BE 心跳上报 `TIER_MIGRATION_V1`（= src/dest path hash + strict check + attempt id + typed finish）。FE 缺能力位不下发；**BE 仅在这些能力真正实现（Phase 5）后才声明**，否则虚假声明使守卫失效。

## 8. BE 设计

### 8.1 采集与上报

新建 `tablet_heat_collector.{h,cpp}`（tablet 级、含 scan_bytes、热路径无锁/分片，借鉴 `cloud_tablet_hotspot.h` 的 ring/dot_point 但不复用其小时级/带锁/partition 汇总结构）+ `tablet_heat_reporter.{h,cpp}`（独立 ReportWorker，注册在 `start_workers` 天然 cloud-gated）。写入新鲜度取 rowset `newest_write_timestamp`（compaction 继承原时间），schema change/restore 不写"当前时间"。

### 8.2 迁移校验增强（`check_migrate_request`）

校验 tablet 存在、schema_hash、`src_path_hash`；**`dest_path_hash` 严格命中**，未命中即 reject、不回退随机 `stores[0]`；介质不同；目标目录属本 BE、可写、容量足。**strict 校验由 `req.strict_check=true`/tiering attempt 触发**——`tablet_tiering_strict_migration_check` 仅作总开关，**不得对未带 strict 的 legacy migration 生效**（否则破坏关闭态零差异）。**幂等结果**：当前 path/medium 已达目标 → 稳定 `ALREADY_APPLIED`（非硬错 already-on-medium，让超时补发幂等）；src path 已变且未达 → `STALE`；否则迁移。

### 8.3 迁移执行增强（`EngineStorageMigrationTask`）

显式处理 schema change/rollup/load；非 MOW compaction 安全证明；retryable/unrecoverable 分类；remote cooldown 拒绝（现仅拒已有 `cooldown_meta_id`）；仿 `EngineCloneTask` 累计 copy size/time 并加 getter，finish 回填 copy stats + attempt + typed reason；actual medium/path **不经 finish**。**修主干现存单位 bug**：`_is_rowsets_size_less_than_threshold` 累计字节却直接比 `migration_remaining_size_threshold_mb`（10MB 实为 ~10 字节），须 `*1024*1024`+边界 UT。

## 9. FE 设计

### 9.1 热度合并

`ReportHandler` → `TabletTieringMgr`：按 tablet_id 找 TabletMeta、校验 table/partition、sum 合并到 HeatProfile。**actual medium/path 唯一来源=tablet report**：heat 的 current_medium/path **仅诊断**，禁写 Replica、禁解 awaiting-report 屏障。**FE HeatProfile 老化**：对连续 `tablet_heat_fe_expire_sec` 未在 report 出现的 tablet 老化清理 HeatProfile，并清理 report 中已不存在的孤儿 profile（BE idle_expire 只管 BE 内存，FE 须自行老化，否则冷 tablet 累积）。

### 9.2 评分与状态机

评分（专利六因子全覆盖）：`read_5m*w + point_lookup*w + scan_bytes_1h/unit*w + freshness(last_write) + access_recency(now − last_access_time_ms) − low_prio_full_scan*penalty + tenant_weight`。其中 **`access_recency` 直接承载专利"最近访问时间"因子**（采集点 §8.1 在点查/scan 处更新 `last_access_time_ms`），既入 access_score 衰减，也作状态机 COLD/idle 判据。tenant_weight 首期为常量（tenant=P2）。

温度→target 映射：HOT→SSD、COLD→HDD、WARM=保持当前介质、POLICY_FROZEN=维持现状。迟滞强制 `hot−cold ≥ min_score_gap`；升到 SSD/降到 HDD 后须满足 min_hot/cold_residence 才反向。人工 hold 优先级最高。**FROZEN 前置**：分区 `storagePolicy!=""` 或 tablet 已有 `cooldown_meta_id` → 评估期即判 FROZEN(`REMOTE_COOLDOWN_DATA`)、不产生 target 变更（不靠 BE 兜底）。**初始 target**：lazy state，无 state 回退 partition default。

### 9.3 决策与 dry-run

只在 `new_target != old_target` 或 FROZEN 恢复时写 edit log。`tablet_tiering_dry_run=true` 只出 decision、不下发。**dry-run 接管语义**：表一旦 `tablet_tiering.enable=true` 即由 tiering 接管介质决策（与 dry-run 无关）；dry-run 期旧 cooldown 自动降冷对该表挂起、仅观察。

### 9.4 介质判定与 effective target（关键）

**严禁把 tablet target 写回 `TabletMeta.storageMedium`**：`TabletMeta` 建表时一个 index 全 tablet **共享一实例**（为省内存），改一个会连累兄弟 tablet；FE 重启重建又每 tablet 独立，前后语义不一致。

正解：`TabletMeta.storageMedium` 保持 partition default；新增 `resolveEffectiveTarget(tabletId)` = `TabletTierState.target` ?? partition default；**所有 rebalancer 消费方**（DiskRebalancer/BeLoadRebalancer/PartitionRebalancer/BackendLoadStatistic/`checkStorageMediumMigration`）凡读介质处改读它（实时解析、无同步窗口）。锁序：resolver 在 inverted-index 读锁内被调、deleteTablet 持写锁——规定锁序或用无锁快照。

**legacy 屏蔽**：`checkStorageMediumMigration` 对 `isTieringOwned(tablet)` 的 tablet 不加入 `tabletMigrationMap`，切断 `handleMigration` 的 report 驱动 fire-and-forget。屏蔽判据是 `isTieringOwned`（effective-enable 且未 detach），**与全局开关、与 state 是否存在均无关**——`enable=false`=pause（保 state、仍屏蔽、不搬回）。**detach**：`isTieringOwned` 读一个持久化的 per-table/partition `tiering_detached` 标志（默认 false）；`enable=false` 只 pause 不 detach；只有显式 admin `DETACH`/`normalize`（拍平介质到 partition default + 清 state + 置 `tiering_detached=true`）后 `isTieringOwned=false`、回 legacy。

### 9.5 调度（复用 TabletScheduler）

`TabletTieringScheduler` 只评估、产出 `TabletSchedCtx(TIER_MIGRATION)` 入队（不自建执行通道）。`doBalance` 加 `TIER_MIGRATION` 分支 + `completeTierMigrationCtx`（跨介质选 dest path、reserve src+dest slot、createStorageMediaMigrationTask）。`:648` 取介质改"先 tablet target 后 partition"。**多副本逐 replica 串行**（tabletId 级去重）；**pending 再验**完整决策快照（isTieringOwned/hold/FROZEN/target/effective_revision），关开关取消 pending TIER。

**在途生命周期**：唯一 `migration_attempt_id`；finish 条件删除（attempt 匹配才 removeTask）；SUCCEEDED/UNKNOWN_AWAITING_REPORT 屏障（report reconcile 前不重发，含超时兜底）；UNKNOWN/orphan 收口等 task report 不含旧 signature + tablet report；master 启动门 = per-BE readiness + orphan fence；epoch/version FE 比对；BE 错误码按 typed reason 映射 retry/frozen，非盲目 cancel。

### 9.6 与 clone/repair/balance/schema change 兼容

- **clone/repair**：取 effective target（缺则降级 partition + `TARGET_MEDIUM_UNAVAILABLE`），path hash 由 report 更新。
- **disk balance**：只同介质；**PathSlot 双池**（普通 `used`、balance/tiering `balanceUsed`），TIER 与 disk balance 同池互斥；不设单盘统一总上限。
- **仲裁**：REPAIR > TIER > DISK_BALANCE。`addTablet` 去重须区分 BalanceType（现只记 Type）。pending TIER 可被 REPAIR/更高优先级替换并清 tier progress+释放 slot；**running TIER 不本地取消**（无 BE cancel RPC），repair 进 `REPAIR_WAIT` 等其在途完成+report。`disable_balance` **不暂停 tiering**（只拦 DISK/BE_BALANCE、放行 TIER）。
- **schema change/rollup**：继承 base effective target；schema change in-place——`TabletTierState`(target/hold/version) 由 oldTabletId **原子转移**到 newTabletId、**嵌入 `AlterJobV2` 同一 journal payload**（删旧前完成）；rollup 派生 index 只继承初始 target。

## 10. 持久化与回放

持久化：TieringPolicy 增删改、TabletTierState target/manual/hold/frozen 变化、可选 heat checkpoint。不逐次持久化：访问事件、高频 delta、ReplicaTierProgress。

**新增 OP 全链路**：OperationType 连续号段 + EditLog logEdit/replay + **JournalEntity.readFields 反序列化 case**（与 replay 独立的第二个 switch）+ GsonUtils 注册 + image 模块（MODULE_NAMES 末尾追加 + MetaPersistMethod case，`saveTabletTiering` **checksum-neutral**）。

**原子性**：typed policy 嵌入 `CreateTableInfo`/ADD PARTITION payload 原子写（独立 policy OP 与 CREATE 非原子会产生孤儿/缺失）。**recycle bin**：非 force drop 进回收站可 recover——policy/state 保留到 erase，recover 缺失则按 effective policy 重初始化；replace/swap/temp partition 纳入。

## 11. SQL / 属性 / 运维

**策略唯一权威源 = TieringPolicy**：`tablet_tiering.*` ALTER 拦截后只写 TieringPolicy edit log、不落 TableProperty.properties；SHOW CREATE TABLE 从 TieringPolicy 渲染。人工 set target/hold/reset 经 admin/proc（ADMIN 权限、持久化、手工改 bump version、在途允许完成按 stale）。

**介质展示默认列集不变**：`SHOW PARTITIONS` 新列只进 VERBOSE；`SHOW TABLETS` 默认列不变、tiering 列走专用 `SHOW TABLET TIER`；`information_schema.partitions` 不加默认列。新增 `SHOW TIERING POLICY/TASKS/HISTORY`、`SHOW TABLET TIER/HEAT`（history 首期内存环形、重启丢失）。

## 12. 配置与开关（默认值）

**FE**：`enable_tablet_tiering=false`、`tablet_tiering_dry_run=true`、`tablet_tiering_scheduler_interval_sec=60`、`tablet_tiering_warmup_sec=600`、`tablet_tiering_max_running_tasks=100`、`..._max_tasks_per_backend=2`、`..._max_tasks_per_path=1`、`..._max_tasks_per_table=4`、`..._max_copy_bytes_per_round=1TB`、`..._default_hot_threshold=100`、`..._default_cold_threshold=10`、`..._min_score_gap=20`、`..._state_checkpoint_interval_sec=600`、`..._await_report_timeout_sec=300`、`..._history_capacity=10000`、`..._ssd_high_watermark=0.85`、`..._fresh_write_protect_sec=1800`、`..._fresh_write_score=50`、`tablet_heat_fe_expire_sec=172800`（FE HeatProfile 老化）。

**BE**：`enable_tablet_heat_report=false`、`tablet_heat_report_interval_sec=30`、`tablet_heat_full_interval=...`、`tablet_heat_max_report_items=10000`、`tablet_heat_idle_expire_sec=86400`、`tablet_heat_include_compaction_read=false`、`enable_tablet_heat_sampling=false`、`tablet_heat_sampling_ratio=1.0`、`tablet_tiering_strict_migration_check=true`（仅总开关，strict 由 req 触发）。BE 配置须 `config.cpp` DEFINE_ + `config.h` DECLARE_ 两处。

## 13. 故障与边界

- **旧任务**：BE 只校验 `src_path_hash`/`schema_hash`（无 FE 版本，不判 epoch）；`effective_revision`/version/attempt **finish 回传、FE 比对**，不一致标完成不改 state、下轮重评估。迟到 finish 靠 attempt 区分（条件删除）。手工 hold 在途允许完成、按 stale 处理（无 BE cancel RPC）。
- **容量不足**：PROMOTE/DEMOTE 容量不足→FROZEN（typed reason）；SSD 压力驱逐选 score 最低且超 min_hot_residence。
- **部分 replica**：允许短期 PARTIAL（聚合展示），逐 replica 收敛，全 healthy replica actual==target 才整体收敛。
- **schema change/rollup**：见 §9.6（state 原子转移/继承初始 target）。
- **compaction**：MOW 锁 base/cumulative；非 MOW 评估安全或加锁。
- **remote cooldown**：FE 评估期 FROZEN（主闸）+ BE `:72` 兜底。
- **BE 死/盘离线**：UNKNOWN 退出 + 释放 slot 规则。
- **master 切换/BE 重启**：见 §6.4（report 重评估 + orphan fence + per-BE 启动门）。

## 14. 降级与回滚

- **关 `enable_tablet_tiering`=pause**：停调度/新任务；保留 state；`isTieringOwned` 的 tablet 仍被屏蔽出 legacy migration、放置冻结不搬回。
- **恢复 partition 单一介质**：显式 admin bulk normalize（反向下发），不删源/目标目录。
- **降级到旧 FE**（旧 FE 无屏蔽，会经 report 把混合介质搬回）：降级前须 ① 旧 FE `disable_storage_medium_check=true` 或先 normalize；② 等在途迁移/finish 完全静默；③ `tabletTiering` image 模块 checksum-neutral + 旧 FE 设 `ignore_unknown_metadata_module=true`，并确认 image 的 replayedJournalId 已覆盖最后一个 tiering OP（未知 journal OP 也是降级障碍，`JournalEntity` 会抛异常）。

## 15. 调度协同总则（双/三调度器资源）

`TabletTieringScheduler` 是除 `TabletChecker`+`TabletScheduler` 外影响 replica 放置的第三生产者。通过复用 `TabletScheduler` 自然共享 PathSlot（注意双池）。冲突仲裁硬规则：REPAIR > TIER_MIGRATION > DISK_BALANCE；同 tablet 任一时刻一个迁移；去重须区分 BalanceType（防重复≠仲裁）。

## 16. 测试（要点）

开关全关零 diff；replay+image+JournalEntity round-trip；tablet/replica/scope-policy 清理 + recycle bin；heat 绝对值/full 分片/不丢；策略字段级合并/enabled=false/effective_revision；resolveEffectiveTarget 同介质均衡；多副本逐 replica 收敛；迟到 finish/orphan fence/UNKNOWN 收口；关开关不回迁 + 降级到旧 FE 不搬回；SC/rollup state 转移；strict 命中/ALREADY_APPLIED/STALE/BE 单位 bug 边界；capability bit 守卫；SHOW 默认列集不变。

## 17. 结论

补齐上述能力后，本设计在落点层面完整：覆盖 correctness 关键路径（cloud gating、介质语义不写回共享 TabletMeta、clone/repair/schema-change 继承与 state 转移、迁移在途生命周期与幂等、状态清理、与远端 storage policy 共存、降级双障碍）、调度协同（三调度器、PathSlot 双池、REPAIR>TIER>DISK_BALANCE）、控制面单一权威源、可运维路径（全部介质展示 SQL、history、冻结 thrift）。

仍显式列为首期非目标、需评审放行：rowset 级跨目录、restore 保留 tier、tenant 策略实际启用、colocate 表参与 tiering、`ALTER ... MODIFY TABLET` 新语法、tiering history 跨重启持久化。

## 18. 决策追溯附录（R 编号 → 主题）

见执行计划 v2 §13 同一映射。本文与执行计划 v2 共用一套 R1–R80 追溯；正文不再带 R 标注。
