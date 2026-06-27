# Tablet 级同节点异构存储分层（B 路线）执行计划 v2（合并重写）

> 配套设计：`docs/tablet-tiering-b-route-design-v2.md`
> 本版已把九轮评审（R1–R80）的全部**定稿结论吸收进正文**，不再保留 "RNN 修正/定稿" 补丁注释；R 编号仅保留在文末 §13 追溯附录，供审计回溯。
> 行号以当前主干为准，实现时以符号定位为准（重构后漂移）。

## 0. 范围与专利对齐

- **专利目标**：依据**访问频率、最近访问时间、扫描字节数、点查次数、生命周期策略、租户策略**，决定数据在**同一 BE 节点内**的 SSD/HDD 放置。**tablet 是冷热放置的最小决策单元，replica 是迁移执行单元**，partition 仍是 SQL/数据组织的逻辑对象。
- **适用范围**：local 存储模式，单 BE 节点本地 SSD↔HDD 数据目录间迁移 tablet。
- **明确不在范围**：cloud 存算分离模式（全链路 gating 旁路）、跨节点迁移、已 cooldown 到对象存储/远端的文件（只判 FROZEN，绝不读写远端数据）。
- **原则**：不在单个 patch 同时改采集/调度/迁移/SQL；开关默认关闭，**关闭态与现状逐字节一致**。

优先级：**P0** = 不做会 correctness 错误或功能不成立；**P1** = 可观测/可运维/性能必需；**P2** = 增强。

## 1. 阶段总览与真实依赖

```
P0 设计/开关/cloud-gating
  └─> P1 Thrift+元数据+持久化 (+最小策略输入链路: CREATE/ALTER typed policy、replay、effective-enable 查询)
        ├─> P2 BE 热度采集与上报(绝对值)
        └─> P3 FE 评估器(dry-run) + 控制面(策略字段级合并/isTieringOwned)
              └─> P4 迁移任务生成(复用 TabletScheduler)
                    └─> P5 BE 严格校验 ──(必须先于)──> G4 放量(关 dry-run/真发迁移)
                          └─> P6 运维/可观测/灰度
```

关键串行约束（含定稿修正）：
1. **T0.2（cloud gating）** 是所有阶段前置守卫。
2. **最小策略输入链路提前到 P1/P3**：T3/T4 依赖 `tablet_tiering.*` 策略与 effective-enable 查询，故 CREATE/ADD PARTITION typed policy、table/partition ALTER、replay、effective-enable 查询必须在 P1/P3 就绪；SHOW/HISTORY/完整运维命令留 P6。
3. **BE 严格校验前置于放量**：T5.1（及必要 T5.2 安全项）必须先于 G4 关 dry-run/真发迁移落地；G4 之前只验任务构造、不真发。
4. **T4.0（任务跟踪模型，已定稿）**：复用 `TabletScheduler`/`TabletSchedCtx`，新增 `BalanceType.TIER_MIGRATION`，自动获得 `AgentTaskQueue` 跟踪 / PathSlot 并发 / finish 回收 / tabletId 级去重。
5. **滚动升级**：BE 心跳上报 `TIER_MIGRATION_V1` capability bit，**仅在 P5（strict+typed finish）落地后才声明**；FE 缺能力位不下发 tiering 迁移。

## 2. Phase 0 —— 设计冻结、开关与全局 gating（P0）

| 任务 | 内容 | 落点 | 验收 |
| --- | --- | --- | --- |
| T0.1 | 新增 FE/BE 配置项，默认关闭 | FE `fe-common/.../common/Config.java`；BE **两处都加** `be/src/common/config.cpp`(`DEFINE_*`)+`be/src/common/config.h`(`DECLARE_*`)。完整默认值见设计 v2 §12 | 配置可加载、默认值一致 |
| T0.2 | **Cloud 模式全链路 gating** | `catalog/Env.java:1892-1907`(scheduler 仅非 cloud+非 follower 挂载)；`master/ReportHandler.java:584`(热度合并前短路)；BE 热度 worker 注册在 `agent/agent_server.cpp start_workers`(天然 cloud-gated，`cloud_start_workers` 不注册)；`PropertyAnalyzer` 对 cloud 报 not-supported | cloud 开全部开关=未实现本特性 |
| T0.3 | 空包/空 Manager + 评估 daemon + 基础 metrics | FE `tiering/` 类骨架；`Env` 挂 `getTabletTieringMgr()`；**`TabletTieringMgr`（或独立 `TabletTieringChecker`）是 `MasterDaemon`**（类比 `TabletChecker`），**仅在非 cloud + master 时 `start()`**（与 `tabletScheduler.start()` 同段 `Env.java:1892-1907`），每轮重评估 tablet→产出 `TieringDecision`→喂 `TabletScheduler`（评估周期 `tablet_tiering_scheduler_interval_sec`）；metrics 占位 | 编译通过、daemon 仅 master/非 cloud 起、metrics 暴露 0 |

**门 G0**：开关全关时全量回归（FE/BE UT + 现有 storage_medium/cooldown 回归）零 diff。

## 3. Phase 1 —— Thrift、元数据、持久化、最小策略输入链路（P0/P1）

| 任务 | 内容 | 落点 | 依赖 | 验收 |
| --- | --- | --- | --- | --- |
| T1.1 | 热度上报 thrift（**绝对值模式**） | `MasterService.thrift` `TReportRequest` 加 `17 tablet_heat_stats`/`18 tablet_heat_report_full`/`19 tablet_heat_report_epoch`/`20 tablet_heat_report_seq`；`TTabletHeatStat` 字段为 **5m/1h/1d 绝对计数**（非 delta）+ `last_access/last_write/current_medium/current_path_hash`（后两者**仅诊断**，删 tenant_id）。**ACK=入队 only**（不扩 `TMasterResult`）；**full 由 BE 周期主动发**（`tablet_heat_full_interval`），按 `snapshot_id`/`chunk_index`/`chunk_count` 暂存、到齐原子替换、加 TTL/tombstone | — | thrift 生成；旧 BE 忽略新字段；epoch/seq 去重 |
| T1.2 | 迁移 req/finish thrift（**冻结字段号**） | `AgentService.thrift` `TStorageMediumMigrateReq` 当前仅占 1..4，按设计 §7.2 扩展 5..10（src/dest_path_hash、effective_revision、reason_code、tablet_tier_state_version、strict_check），再新增 `11 migration_attempt_id`；`TFinishTaskRequest` 复用 `copy_size`/`copy_time_ms`/`finish_tablet_infos`，并加 optional `migration_attempt_id`/`policy_effective_revision`/`tablet_tier_state_version`/`migration_reason_code`(typed enum)/`retryable`。**冻结一份字段号+枚举草案**，避免实现期各自解释 | — | 旧 BE 兼容；finish 可回传 attempt/reason；FE 据此映射 | 
| T1.3 | `TieringPolicy`/`TabletTierState` 实体 | `tiering/TieringPolicy.java`(字段 optional 三态，支持字段级合并)、`tiering/TabletTierState.java`(target/previous_target/temperature/reason/version/manual_override/frozen_reason) | T0.3 | Gson round-trip |
| T1.4 | 持久化全链路 | `persist/OperationType.java`(连续新 OP 段)、`persist/EditLog.java`(logEdit+replay)、**`journal/JournalEntity.java:198 readFields` 加 case**（与 EditLog replay 独立的反序列化 switch，default 抛 IOException）、`persist/gson/GsonUtils.java`(注册)、image 模块驱动：`persist/meta/PersistMetaModules.java MODULE_NAMES` 末尾追加 + `MetaPersistMethod.java create()` 加 case 映射 `Env.saveTabletTiering/loadTabletTiering`。**`saveTabletTiering` 须 checksum-neutral**（`return checksum` 不折叠，遵循既有 Gson 模块惯例），保证旧 FE 跳过未知模块时 checksum 仍成立 | T1.3 | replay+image round-trip；checkpoint 后重启不丢 |
| T1.5 | 生命周期清理（tablet 级 + replica 级 + scope policy） | tablet 级钩子统一挂 `catalog/TabletInvertedIndex.java:810 deleteTablet`；**replica 级钩子统一挂 `TabletInvertedIndex.deleteReplica:854`**（`Tablet.deleteReplica:412` 与 `deleteReplicaByBackendId:418` 都汇此）。**hook 内只做内存清理（幂等、replay 安全）**；`CleanTabletTierStateInfo` 持久化只由 master 正常操作路径显式记，replay/checkpoint/父级已记录操作（如 OP_DROP_TABLE）内不写新 edit log。**scope policy**：drop/truncate/restore 清对应 `TieringPolicy`（scope=TABLE/PARTITION），随父级操作原子完成。**recycle bin**：非 force drop 进回收站可 recover——policy/state **保留到 erase**，recover 时缺失则按 effective policy 重初始化；replace/swap/temp partition 纳入 | T1.3 | 建删 1 万次后 state/heat/progress/scope-policy 均归零、无孤儿、image 不增长 |
| T1.6a | 升级守卫**框架**（P1） | 定义 `TIER_MIGRATION_V1` 能力位 + **FE 侧"缺能力即不下发"校验**（在 `completeTierMigrationCtx`/下发前）。框架无前向依赖；因无 BE 声明，下发天然被挡到 P5 | T1.2 | FE 校验生效；无能力位时不下发 |
| T1.6b | BE **声明**能力位（P5） | BE 心跳**仅在 strict 校验 + typed finish 真正实现（T5.1/T5.2）后**才置 `TIER_MIGRATION_V1`=true（否则虚假声明使守卫失效） | T5.1,T5.2 | 能力位 P5 后才报；旧 BE 不声明、不被下发 |
| T1.7 | **最小策略输入链路** | typed `TieringPolicy` 嵌入 `CreateTableInfo`/ADD PARTITION 的 persist payload **原子写**（避免独立 policy OP 与 CREATE 非原子）；table/partition `ALTER ... SET("tablet_tiering.*")` 拦截（`ModifyTablePropertiesOp.validate:79` 白名单放行）后**只写 `TieringPolicy` edit log、不落 `TableProperty.properties`**；replay；`effective-enable` 查询接口供 T3/T4 用 | T1.3,T1.4 | create/alter/replay 一致；策略单一权威源 |

**门 G1**：FE 重启后 policy/state 一致；旧 BE 兼容；image 不泄漏；策略仅一份权威源。

## 4. Phase 2 —— BE 热度采集与上报（P1）

| 任务 | 内容 | 落点 | 依赖 | 验收 |
| --- | --- | --- | --- | --- |
| T2.0 | 新建采集器（不复用 HotspotCounter） | `HotspotCounter` 是小时级/带锁/无 scan_bytes/partition 汇总，复用≈重写；新建 tablet 级、含 scan_bytes、热路径无锁/分片采集器，借鉴其 ring/dot_point 思路 | T0.x | 评审签字 |
| T2.1 | 采集器与环形桶 | `be/src/olap/tablet_heat_collector.{h,cpp}`：N 分片 + 5m(60×5s)/1h(60×60s)/1d(24×1h) ring，热路径仅原子累加；后台 roll bucket；空闲 `tablet_heat_idle_expire_sec` 淘汰 | T2.0 | bucket roll、丢弃 UT |
| T2.2 | 点查接入 | `be/src/service/point_query_executor.cpp:288`（`_tablet` 处记 POINT_LOOKUP，高权重；**同时更新 `last_access_time_ms`**，专利"最近访问时间"因子） | T2.1 | point lookup + last_access UT |
| T2.3 | OLAP scan 接入 | `be/src/vec/exec/scan/olap_scanner.cpp`（tablet reader 处记 read + scan bytes/rows/latency；**同时更新 `last_access_time_ms`**） | T2.1 | scan bytes + last_access UT |
| T2.4 | 写入新鲜度 | 统一钩子："rowset 对查询可见"处更新 `last_write_time_ms`，覆盖 stream/routine/bulk/insert overwrite/restore/schema change/rollup（compaction 不更新）。**取值用 rowset 自带 `newest_write_timestamp`**（compaction 已继承原写入时间，`compaction.cpp:452`），schema change/restore **不写"当前时间"**（`schema_change.cpp:612`），避免冷数据误判为新写 | T2.1 | freshness 反映真实写入 |
| T2.5 | 热度上报（独立 worker） | `be/src/olap/tablet_heat_reporter.{h,cpp}`：在 `agent/agent_server.cpp start_workers` 注册**独立** `ReportWorker`（天然 cloud-gated），按 `tablet_heat_report_interval_sec`(30) 调 `report()` 发只含 `tablet_heat_stats` 的请求；**不 piggyback** 到 60s 的 `report_tablet_callback`。**绝对值**上报、BE 周期主动 full（snapshot 分片）。FE 侧 `ReportHandler.ReportType` 加 `HEAT`、dispatch 识别 heat-only 请求，`reportTasks` 改**可累加队列**（按 (be,type) 覆盖会丢 delta），用 epoch/seq 去重 | T2.1,T1.1 | 压测开销可控；heat 不丢、节奏 30s 独立 |

**门 G2**：压测下 QPS 影响在阈值内；上报失败不影响查询。

## 5. Phase 3 —— FE 评估器、控制面与 dry-run（P1）

| 任务 | 内容 | 落点 | 依赖 | 验收 |
| --- | --- | --- | --- | --- |
| T3.1 | 热度合并 | `master/ReportHandler.java:584` → `TabletTieringMgr`（多副本 sum、时间窗去重）。**actual 单一来源=tablet report**：heat 的 `current_medium/path_hash` 仅诊断，**禁写 Replica、禁解 awaiting-report 屏障**。**FE HeatProfile 老化（闭环补漏）**：对长期不再被上报的 tablet（heat report 中连续 `tablet_heat_fe_expire_sec` 未出现）老化清理 HeatProfile，并清理 report 中不存在的孤儿 profile——BE 侧 idle_expire 只管 BE 内存，FE 侧须自行老化，否则冷 tablet 累积内存 | T1.1,T2.5 | 多副本 sum 正确；actual 不被 heat 改；FE 无 HeatProfile 泄漏 |
| T3.2 | 策略解析（**字段级合并**） | `tiering/TieringPolicyManager.java`：optional 三态，按 table→partition→tenant 低到高**逐字段覆盖**（非 winner-takes-all）；`enabled` 是字段，合并后再判，高优先级可重新 enable（不在 table 层短路）；**SSD quota 为层级约束**（partition 配额取 min(自身, 剩余父级)，非简单覆盖）。**首期只启用 table/partition 两层，tenant 降 P2**。manager 维护****派生式** `effective_revision`**（= 该 tablet 贡献 scope 的 epoch 组合，如 hash/max(table_epoch, partition_epoch, tenant_epoch)，**非全局单调**——否则任一表改策略会过度失效其他表的在途任务）；任务携带它，finish 回传后 FE 用"当前重新解析的该 tablet effective_revision"比对判 stale | T1.3,T1.7 | 字段级合并正确；enabled=false 局部禁用 |
| T3.3 | 评分模型 | `tiering/TabletHeatProfile.java` + 评分。**专利六因子全覆盖**：read_5m（频率）、point_lookup、scan_bytes_1h、freshness(last_write)、**access_recency(now − `last_access_time_ms`，专利"最近访问时间"——既入 access_score 衰减项，也作状态机 COLD/idle 判据)**、tenant_weight − batch_scan_penalty | T3.1 | score 含 access_recency；冷数据按最近访问降冷 |
| T3.4 | 状态机 + 温度→介质映射 + FROZEN 前置 | tablet 级温度 **HOT/WARM/COLD/POLICY_FROZEN**；映射 HOT→SSD、COLD→HDD、WARM=保持当前介质、FROZEN=维持现状；迟滞（强制 `hot−cold ≥ min_score_gap`）/最小驻留。**初始 target**：lazy state——无 `TabletTierState` 时 `resolveEffectiveTarget` 回退 partition default，仅首次非 WARM 决策才写 state。**FROZEN 前置**：分区 `storagePolicy!="" ` 或 tablet 已有 `cooldown_meta_id` → 直接 FROZEN(`REMOTE_COOLDOWN_DATA`)、评估期即跳过 | T3.3 | 状态机/防抖/storage policy 分区不产生 target 变更 |
| T3.5 | 决策输出 + dry-run | `tiering/TieringDecision.java`；`tablet_tiering_dry_run=true` 只出 decision、写 metric、不下发。**dry-run 接管语义**：表一旦 `tablet_tiering.enable=true` 即由 tiering 接管介质决策（与 dry-run 无关）——dry-run 期旧 `getPartitionIdToStorageMediumMap` 的 SSD→HDD 自动降冷对该表**挂起、仅观察** | T3.4 | dry-run 无迁移；启用表 dry-run 期不自动降冷 |

**门 G3**：构造访问模式，dry-run 判定符合预期；只在 target 变化时写 edit log。

## 6. Phase 4 —— 迁移任务生成（P0）

| 任务 | 内容 | 落点 | 依赖 | 验收 |
| --- | --- | --- | --- | --- |
| T4.1 | **介质判定改造 + isTieringOwned 屏蔽** | **(a)** `catalog/Env.java:4928 getPartitionIdToStorageMediumMap`：被 tiering 接管的分区不再在 report 路径 `setDataProperty`(SSD→HDD)+`logModifyPartition`，cooldown 只作 policy 输入。**(b)** `TabletInvertedIndex.java:435-451 checkStorageMediumMigration`：用 `resolveEffectiveTarget(tabletId)` 作比较基准（先 tablet target 后 partition 回退），**`:450` 不再 setStorageMedium(target)**（见 T4.2 R39）。**(c)** 被 tiering 接管的 tablet **不得加入 `tabletMigrationMap`**，切断 `ReportHandler:649→handleMigration:1259` 的 report 驱动 fire-and-forget。**屏蔽判据 = `isTieringOwned(tablet)`**（= table/partition 曾 effective-enable 且未 detach），**与全局 `enable_tablet_tiering` 开关和 state 是否存在均无关**——`enable=false`=pause（保 state、仍屏蔽），关全局开关亦不搬回（见 §10）。**detach 机制**：`isTieringOwned` 读一个**持久化的 per-table/partition `tiering_detached` 标志**（默认 false）——`enable=false` 只 pause 不 detach；只有显式 admin `DETACH`/`normalize` 命令置 `tiering_detached=true`（并把现有 tablet 介质拍平到 partition default、清 state）后才 `isTieringOwned=false`、回 legacy | T1.3 | 关闭态零 diff；接管 tablet 不被 legacy 迁回；lazy 无 state 也被屏蔽 |
| T4.2 | **effective target 解析（不写回共享 TabletMeta）** | `TabletMeta` 建表时一个 index 全 tablet **共享一实例**（`InternalCatalog:2073/3418`、`TabletInvertedIndex:86`），重启又每 tablet 独立（`:388`）——**严禁把 tablet target 写回 `TabletMeta.storageMedium`**。`TabletMeta.storageMedium` 保持 partition default；新增 `TabletTieringMgr.resolveEffectiveTarget(tabletId)`(= TabletTierState.target ?? partition default)，**所有 rebalancer 消费方**（DiskRebalancer/BeLoadRebalancer/PartitionRebalancer/BackendLoadStatistic）凡读 `getStorageMedium()` 处改读它（实时解析、无同步窗口）。**锁序**：resolver 在 inverted-index 读锁内被调，deleteTablet 持写锁——规定 tier-manager↔inverted-index 锁序或用无锁快照 | T4.1 | 同介质均衡不跨介质；副本计数正确；无锁反转 |
| T4.3 | 调度任务生成（复用 TabletScheduler） | `tiering/TabletTieringScheduler.java` **只评估并产出** `TabletSchedCtx`(type=BALANCE, balanceType=`TIER_MIGRATION`)+`setTempSrc`，调 `TabletScheduler.addTablet` 入队（不自建执行通道）。新增分支：① `TabletScheduler.java:1418 doBalance` 加 `TIER_MIGRATION`；② 新增 `completeTierMigrationCtx`——**不复用 `DiskRebalancer.completeSchedCtx`**（它同介质选 dest path），在**目标介质**目录 reserve src+dest slot、`setDest`/`destPathHash`、过滤 OFFLINE/高水位/只读盘，再 `createStorageMediaMigrationTask`（只传 `dest_path_hash`、**不设 data_dir**）；③ `:648` 无条件 `setStorageMedium(partition medium)` 会覆盖 target，配合 T4.7 改。**多副本**：scheduler 按 tabletId 去重，同 tablet 任一时刻一个 replica 在途、逐 replica 串行收敛。**pending 再验**：`completeTierMigrationCtx`/造 thrift 前重验完整决策快照（isTieringOwned/hold/FROZEN/当前 target/`effective_revision`），关全局或 scope 开关时取消 pending TIER | T4.0,T3.5 | 单 tablet 可迁；每轮每 tablet ≤1 eligible replica；全 healthy replica actual==target 才收敛 |
| T4.4 | **去重/跟踪/finish 回收 + 在途生命周期** | `TabletSchedCtx`(+`TIER_MIGRATION` 类型)、`TabletScheduler.java:1821 finishStorageMediaMigrationTask` 按 BalanceType 分支：`DISK_BALANCE` 旧行为；`TIER_MIGRATION` **不调 `updateDestPathHash`**，只写 copy stats/`last_migration_time_ms`/`ReplicaTierProgress.state`/history；**actual medium 与 path hash 一律不在 finish 写、只由 tablet report reconcile**。**迁移尝试 ID**：req+finish 带唯一 `migration_attempt_id`；**finish 删除契约**：在 `takeRunningTablets` 前比 attempt，handler 返回是否消费，`MasterImpl.finishStorageMediumMigrate:600` **仅 attempt 匹配时 removeTask**（防迟到 finish 串新任务）。**屏障**：finish 成功→`ReplicaTierProgress.state=SUCCEEDED_AWAITING_REPORT`，超时→`UNKNOWN_AWAITING_REPORT`（含 `tablet_tiering_await_report_timeout_sec` 兜底）；report reconcile 到目标前不重发。**UNKNOWN/orphan 收口**：等 BE task report（running signatures）不含旧 signature + 随后 tablet report 才解除；master 启动门 = per-BE readiness（等 tablet/disk/task report 本任期内处理完，非固定 warmup）；新任期把 task report 已有迁移 signature 入抑制表（orphan fence）。**epoch/version 在 FE 比对**（BE 无 FE 版本，只校验 path/schema）。**状态枚举拆分**：replica 级 PENDING/RUNNING/AWAITING_REPORT(+outcome SUCCEEDED/UNKNOWN)/RETRY_WAIT/UNAVAILABLE；tablet 级 HOT/WARM/COLD/POLICY_FROZEN；PARTIAL 仅聚合展示。**BE 错误码映射**：finish 非 OK 按 `migration_reason_code`/`retryable`（非解析 error_msgs）映射到 `retry_after_ms`/`frozen_reason`，非盲目 cancel | T4.3 | 重复轮不重发；窗口内不对已成功 replica 重发；FE 重启靠 report 重评估补发（non-resend）；迟到/孤儿不串任务 |
| T4.5 | 并发与配额 | 全局/perBE/perPath/perTable + copy bytes budget；**SSD 配额按实际 replica 物理字节累计**（在途计入，避免一轮超发），**层级约束**（partition ≤ 剩余 table）；**SSD pressure eviction**：阈值 `tablet_tiering_ssd_high_watermark`、候选排序（最冷/最大优先）、生成 DEMOTE，落点在此（不只在灰度步骤）；**触发主体**：tiering 评估 daemon 每轮扫 per-BE SSD used/容量，超 `ssd_high_watermark` 即按候选排序生成 DEMOTE（与超配额停 PROMOTE 是同一轮的两个动作） | T4.3 | 限额生效；超配额停 PROMOTE；驱逐有落点 |
| T4.6 | 调度器协同与仲裁 | **PathSlot 双池**：普通任务用 `slot.used`、balance/tiering 用 `slot.balanceUsed`（`:2194`/`:2249`）——TIER 走 balanceUsed 与 disk balance 同池（二者互斥），验收口径=「TIER 在 balanceUsed 池内不超 disk balance 既有上限」，**不设单盘统一总上限**。**仲裁去重**：`allTabletTypes:121` 只记 `Type` 不记 `BalanceType`——须扩为 `(Type,BalanceType)` 或加 `cancelPendingDiskBalanceForTablet`，规则 TIER>DISK_BALANCE（pending 可替换、running 等其完成后重评估）。**REPAIR>TIER**：`addTablet:261` 让 REPAIR 覆盖 BALANCE——pending TIER 被 REPAIR 替换时清 tier progress+释放 slot；**running TIER 不本地取消**（无 BE cancel RPC），repair 进 `REPAIR_WAIT` 等其在途完成+report 后再操作，repair 后重评估 | T4.4 | 单盘按池不超上限；同 tablet 不出现 balance/tiering 对冲；REPAIR 不被 TIER 阻塞过久 |
| T4.7 | 取介质通用规则 + schema change/rollup 继承 | `TabletScheduler.java:648` 改"先查 tablet target、为空回退 partition"，对 REPAIR/BALANCE/TIER 一并生效（含 §14.7 降级打 `TARGET_MEDIUM_UNAVAILABLE`）；`backup/RestoreJob.java:1200`（文档化不保留 tier）；`task/CreateReplicaTask.java:383`（出生取默认+纳入 state 初始化）。**schema change 继承 + state 转移**：`RollupJobV2:233`/`SchemaChangeJobV2:276` 现用 partition medium，须改为继承 base effective target；**schema change 是 in-place**——把 `TabletTierState`(target/hold/version) 由 oldTabletId **原子转移**到 newTabletId，**嵌入 `AlterJobV2` 同一 journal payload**（`logAlterJob` 实在 `pruneMeta→deleteTablet:763` 删旧之前，转移随之即原子），否则新 tablet 回退 partition default→反向迁移+hold 丢失；**rollup 是派生 index**，只继承初始 target、不带 hold/version | T4.1 | HOT tablet 补副本落 SSD；TIER 目标不被 :648 覆盖；SC/rollup 不丢 tier |
| T4.8 | dynamic partition/colocate 协同 | `DynamicPartitionScheduler`（partition 介质只作 policy 输入）；colocate 表首期关 tiering | T4.1 | colocate 均衡不破；无介质抖动 |

**门 G4**（关 dry-run 真发，**前提：T5.1/必要 T5.2 已落地**）：可迁移单 tablet；任务幂等；混合介质下 clone/balance 正确。

## 7. Phase 5 —— BE 迁移严格校验与执行增强（P0，**前置于 G4 放量**）

| 任务 | 内容 | 落点 | 依赖 | 验收 |
| --- | --- | --- | --- | --- |
| T5.1 | check 增强（**strict 由 req 触发**） | `be/src/agent/task_worker_pool.cpp:323 check_migrate_request`：校验 tablet/schema_hash/`src_path_hash`；**`dest_path_hash` 严格命中**，未命中即 reject、**不回退随机 `stores[0]`**；TIER 只传 `dest_path_hash` 不设 data_dir（若都传则校验 path_hash==dest_path_hash+medium）。**strict 校验由 `req.strict_check=true`/tiering attempt 触发，不靠全局 `tablet_tiering_strict_migration_check` 对 legacy 生效**（否则破坏关闭态零差异）。**幂等结果 `ALREADY_APPLIED`**：当前 path/medium 已达目标→稳定幂等成功（非硬错 already-on-medium）；src path 已变且未达→`STALE`；否则才迁移 | T1.2 | stale/已达目标可区分；目录精确命中；strict 不波及 legacy |
| T5.2 | 执行增强 + 单位 bug | `be/src/olap/task/engine_storage_migration_task.cpp`：schema change/rollup/load 处理（`:252`）、非 MOW compaction 安全（`:229`）、retryable/unrecoverable 分类、remote cooldown 拒绝（`:72`）。**修单位 bug**：`:198 _is_rowsets_size_less_than_threshold` 累计字节却直接比 `migration_remaining_size_threshold_mb`（10MB 实为 ~10 字节），须 `*1024*1024`+边界 UT | T5.1 | 故障分类正确；持续写入可进最终锁定复制 |
| T5.3 | copy stats 回传 | `EngineStorageMigrationTask` 仿 `EngineCloneTask` 累计 copy size/time 并加 getter；`storage_medium_migrate_callback:2354` 填 finish 的 `copy_size`/`copy_time_ms`+`migration_attempt_id`+typed `migration_reason_code`。actual medium/path 不经 finish、只由 report | T5.1,T1.2 | finish 落库统计；actual 来源单一 |
| T5.4 | storage policy 共存 BE 兜底 | FROZEN 决策已前移到 T3.4（FE 主闸）；`engine_storage_migration_task.cpp:72` 仅拒已有 `cooldown_meta_id`（已 cooldown 到远端），拦不住"配 storagePolicy 但数据在本地"——故 BE 兜底不替代 FE 前置，二者都要 | T3.4,T5.2 | storage policy 表 tablet 全 FROZEN |

**门 G5**：故障注入（copy/hdr/reload 失败）后旧路径正常服务、目标垃圾清理。

## 8. Phase 6 —— 运维接口、可观测与灰度（P1）

| 任务 | 内容 | 落点 | 依赖 | 验收 |
| --- | --- | --- | --- | --- |
| T6.1 | 完整运维命令 | 在 T1.7 最小链路之上补 admin/proc：set target / hold / reset（**ADMIN 权限校验**；写 edit log+进 image 持久化 `manual_override`/`frozen_reason`；手工改 target bump `TabletTierState.version`，旧在途按 stale 处理、在途允许完成不强加取消 RPC）。新语法 `ALTER ... MODIFY TABLET` 降 P2 | T1.7,T4.4 | 可锁定单 tablet 介质；hold 重启不丢 |
| T6.2 | 介质展示 SQL | **默认列集不变**：`SHOW PARTITIONS` 新列只进 `VERBOSE`；`SHOW TABLETS` 默认列不变、tiering 列走专用 `SHOW TABLET TIER`；`information_schema.partitions` 标准视图不加默认列；cluster_balance/SHOW BACKENDS 加注/验证（其数据源 `TabletMeta.storageMedium` 仍是 partition default，混合介质语义靠 SHOW TABLET TIER 体现） | T4.x | 开关开/关默认列集均不变 |
| T6.3 | SHOW TIERING POLICY/TASKS/HISTORY、TABLET TIER/HEAT | `tiering/` proc + commands；history 首期内存环形（`tablet_tiering_history_capacity`，重启丢失，help 注明） | T4.4 | 可解释每 tablet 介质/热度/原因 |
| T6.4 | 全量 metrics + 日志 + 文档/回滚手册 | §13；灰度顺序 + 回滚（§10） | 全部 | 关键事件可观测；回滚演练通过 |

**门 G6（最终验收）**：开关关=现状；开关开=同 partition 稳定混合介质；查询/写入/compaction/clone/repair 正确；迁移失败不致不可服务；FE/BE 重启可恢复；可解释；压测开销可接受。

## 9. 关键决策清单（实现前必须签字）

1. **任务跟踪**：复用 `TabletScheduler` + `BalanceType.TIER_MIGRATION`（方案 A）。
2. **effective target 不写回共享 TabletMeta**：`TabletMeta.storageMedium` 保持 partition default，消费方实时 `resolveEffectiveTarget(tabletId)`。
3. **策略字段级合并 + 全局 `effective_revision`**；首期只 table/partition，tenant=P2；SSD quota 层级约束。
4. **isTieringOwned 唯一屏蔽判据**；`enable=false`=pause（保 state、仍屏蔽 legacy、不搬回）；恢复 partition 介质走显式 admin/normalize。
5. **heat 绝对值 + 入队-ACK + BE 周期主动 full（snapshot 分片/TTL）**；actual 单一来源=tablet report，heat medium/path 仅诊断。
6. **迁移在途生命周期**：唯一 `migration_attempt_id` + finish 条件删除 + SUCCEEDED/UNKNOWN_AWAITING_REPORT 屏障 + orphan fence + per-BE 启动门；BE `ALREADY_APPLIED`/`STALE` 幂等；epoch/version FE 比对。
7. **REPAIR>TIER>DISK_BALANCE 仲裁**；running TIER 不本地取消（REPAIR_WAIT）；PathSlot 按池。
8. **schema change in-place 转移完整 state（嵌 AlterJobV2 payload）；rollup 只继承初始 target**。
9. **strict 由 req 触发**（不靠全局配置改 legacy）；capability bit 仅 P5 后声明。
10. **FROZEN 前置**：storage policy/cooldown 分区评估期判 FROZEN（FE 主闸）+ BE 兜底。
11. **降级回滚**：关开关=pause 不搬回；降级到旧 FE 须先 `disable_storage_medium_check=true`/normalize/静默在途；`tabletTiering` image module 须 checksum-neutral + 设 `ignore_unknown_metadata_module=true`，且确认 image replayedJournalId 已覆盖最后一个 tiering OP（journal OP 也是降级障碍）。
12. **阶段顺序**：最小策略链路前移 P1/P3；BE 严格校验前置于 G4 放量。
13. **colocate 表首期关 tiering**。

## 10. 灰度与回滚

灰度（每步独立门）：全集群升级开关全关 → 开 BE heat report/FE dry-run → 单表 dry-run → 开 DEMOTE→HDD 小并发 → 开 PROMOTE→SSD → 扩表与并发 → 开 SSD pressure eviction。

回滚：
- **关 `enable_tablet_tiering`=pause**：停调度/新任务；保留 `TabletTierState`；**凡 `isTieringOwned` 的 tablet 仍被 `checkStorageMediumMigration` 屏蔽出 legacy migration**，现有放置冻结、不搬回 partition medium。
- **恢复 partition 单一介质**：显式 admin bulk normalize（反向下发），不删源/目标目录。
- **降级到旧 FE**：旧 FE 无屏蔽会经 report 把混合介质搬回——降级前须 ① 旧 FE `disable_storage_medium_check=true` 或先 normalize；② 等在途迁移/finish 完全静默；③ image 含 `tabletTiering` 模块时设 `ignore_unknown_metadata_module=true` 且确认 replayedJournalId 已覆盖最后一个 tiering OP。
- **完全回滚元数据**：admin command 清 tablet tier state + scope policy。

## 11. 测试矩阵

| 阶段 | 必过 |
| --- | --- |
| P0 | 开关全关全回归零 diff |
| P1 | replay+image round-trip；JournalEntity 反序列化；旧 BE 兼容；tablet/replica/scope-policy 清理；recycle bin recover |
| P2 | 采集开销；heat 绝对值/full 分片/不丢；freshness 取值 |
| P3 | 策略字段级合并/enabled=false/effective_revision；score；状态机/防抖；dry-run 接管 cooldown |
| P4 | 单 tablet 迁移幂等；resolveEffectiveTarget 同介质均衡；混合介质 clone/balance；多副本逐 replica 收敛；REPAIR×TIER×DISK_BALANCE 仲裁 |
| P5 | strict 命中/ALREADY_APPLIED/STALE；BE 单位 bug 边界；故障注入旧路径服务 |
| 故障/边界 | 迟到 finish 串任务/orphan fence；UNKNOWN 收口；关开关不回迁；降级到旧 FE 不搬回；SC/rollup state 转移；capability bit 守卫；effective target 实时解析；epoch FE 比对 |
| P6 | SHOW 默认列集不变；重启/并发/容量；可解释 |

## 12. 风险与未决

- thrift 字段号/枚举（迁移 req/finish、heat、capability bit）建议**编码前由一人统一冻结一份草案**（避免实现期解释分歧）。
- `engine_storage_migration_task.cpp:198` 单位 bug 是**主干现存 bug**（非本特性引入），建议单独修复+UT。
- **tenant 策略是专利明列因子**：`TieringPolicy` 的 TENANT scope 框架已实现，但实际启用（workload group/user/resource group → tenant_id 映射）降为 **P2**——须向专利方明示"框架已留、P2 启用"，不可理解为永久不做。
- rowset 级跨目录、restore 保留 tier、`ALTER ... MODIFY TABLET` 新语法、history 跨重启持久化：均列**首期非目标**，评审放行。

## 13. 决策追溯附录（R 编号 → 主题，供审计回溯）

> 本附录仅供回溯九轮评审，正文不再带 R 标注。

R1/R19/R21/R32/R33/R40/R59 迁移在途生命周期（屏障/启动门/尝试 ID/删除契约/UNKNOWN/orphan fence）；R2/R39/R24 介质语义（切断 legacy fire-and-forget / effective target 不写回共享 TabletMeta，R39 取代 R24）；R3/R23.16/R61/R64/R72/R78 调度仲裁与 PathSlot；R4/R8/R13/R48/R70/R74 迁移任务字段/严格校验/幂等；R5/R23.6/R1.4 持久化全链路（含 JournalEntity）；R6/R49/R62/R75 生命周期清理（含 replica/recycle bin）；R7/R15/R53/R80 介质展示 SQL；R9/R25/R34/R69 降级与回滚；R10/R28/R36 状态枚举/收敛；R11/R44/R68 初始 target/lazy state/isTieringOwned；R12/R16 错误码映射与承载；R14 legacy 路径口径；R17/R26/R37/R46/R47/R56/R67/R79 heat 协议（独立 worker/绝对值/full/ACK）；R18 disable_balance 独立；R20/R30/R38/R52/R66 配置落点与默认值；R22/R71 epoch/effective_revision；R23/R35 策略单一权威源+原子持久化；R27 actual 单源；R29 freshness 取值；R31/R77 SSD quota 口径/层级；R41 pending 再验；R42/R43/R65 阶段顺序与依赖边；R45/R58/R76 schema change/rollup 继承与 state 转移；R50 BE 单位 bug；R51 tenant=P2；R54 追溯矩阵；R55 eviction 落点；R57 策略字段级合并；R60/R73 capability bit；R63 锁序。
