# Tablet 冷热分层（B 路线）伪代码

本文件给出与现有实现一致的访问频率采集、策略解析、温度判定与同节点迁移伪代码，
供专利正文 / 附录引用。提供**简化版**（正文/演示用）与**完整版**（权利要求支撑用）两份。

> 与早期手稿相比的修正：
> - **A**：`record_access` 不携带 `tenant_id` —— **BE 不感知租户**，租户在 FE 侧由对象所属数据库（`db_id`）推导。
> - **B**：`resolve_policy` 为**字段级合并**（表 < 分区 < 租户，逐字段，仅显式设过的字段覆盖父级），非整条策略先到先得。
> - **C**：事务 / 合并 / 结构变更期间不迁移的约束在**迁移执行层**强制（`wait_until_no_running_txn` + 加锁 + 严格校验）；
>   `FROZEN` 用于人工锁定与远端生命周期接管。

---

## 一、简化版（核心五步 + 评分）

```text
# 1. 访问采集（BE 侧，只用于冷热判定，不改查询结果；BE 不感知租户）
function record_access(event):
    key = (event.table_id, event.partition_id, event.tablet_id)
    p = heat_registry.get_or_create(key)
    p.last_access_time = event.event_time
    p.read_window.add(1)                                  # 访问频率
    p.scan_bytes_window.add(event.scan_bytes)            # 扫描字节
    if event.access_type == point_lookup:
        p.point_lookup_window.add(1)                     # 点查
    if event.is_write:
        p.last_write_time = event.event_time             # 写入新鲜度

# 2. 访问评分（频率 + 时间因子；时间/频率冲突在评分内消解）
function calc_access_score(heat, policy):
    score  = heat.read_count(5m)                                       # 频率
    score += heat.point_lookup_count(1h) * policy.point_lookup_weight  # 点查
    score += heat.scan_bytes(1h)/1MiB    * policy.scan_bytes_weight    # 扫描字节
    if now() - heat.last_write_time  < policy.fresh_protect_time:  score += policy.fresh_score   # 新鲜度
    if now() - heat.last_access_time < RECENCY_WINDOW:            score += heat.read_count(5m)   # 最近访问
    return score

# 3. 策略解析（字段级合并，优先级 表 < 分区 < 租户(=数据库)）
function resolve_policy(object):
    policy = default_policy()
    merge_set_fields(policy, find_by_table(object.table_id))
    merge_set_fields(policy, find_by_partition(object.partition_id))
    merge_set_fields(policy, find_by_tenant(object.db_id))    # 租户=库；只有显式设过的字段才覆盖父级
    return policy

# 4. 温度判定
function evaluate_temperature(object):
    policy = resolve_policy(object)
    if not policy.enabled:                                   return SKIP
    if policy.manual_hold or has_remote_lifecycle(object):   return FROZEN   # 人工锁定 / 远端生命周期接管
    score = calc_access_score(read_heat(object), policy)
    if score >= policy.hot_threshold:                                          return HOT
    if score <= policy.cold_threshold and idle_longer_than(object, policy.cooldown_time):  return COLD
    return WARM                                          # 冷却周期内或处于阈值之间：维持，防抖

# 5. 调度下发（目标≠当前介质才迁）
function schedule_tiering(object):
    state  = evaluate_temperature(object)
    target = SSD if state==HOT else (HDD if state==COLD else object.current_medium)
    if target == object.current_medium: return NOOP
    emit_migration_task(object, target_medium = target,
        reason_code = HIGH_QPS_PROMOTE if target==SSD else LOW_ACCESS_DEMOTE)

# 6. 同节点迁移执行（新目录装载成功才切换；失败旧目录继续服务）
function migrate_tablet_same_node(task):
    tablet = tablet_manager.get(task.tablet_id)
    dest   = choose_local_dir(local_node_id, task.target_medium)
    try:
        wait_until_no_running_txn(tablet)                # 事务/合并/结构变更期间不迁
        rowsets = capture_consistent_rowsets(tablet)
        copy_rowset_files(rowsets, dest.temp_path)
        while has_new_visible_rowsets(tablet):           # 追拷迁移期间新增版本
            copy_rowset_files(capture_tail_rowsets(tablet), dest.temp_path)
        reload_tablet_from_dest(dest.temp_path)          # 装载成功后才切换路径
        return OK
    catch error:
        remove_temp_path(dest.temp_path)                 # 失败清理暂存，旧目录继续服务
        return error
```

---

## 二、完整版（含工程细节，可支撑权利要求）

```text
# ============================================================
# 1. 访问/写入热度采集（BE 侧；BE 不感知 tenant）
# ============================================================
function record_access(event):
    key = (event.table_id, event.partition_id, event.tablet_id)   # 无 tenant_id
    profile = heat_registry.get_or_create(key)
    profile.last_access_time = event.event_time
    profile.read_window.add(1)                                    # 访问频率
    profile.scan_bytes_window.add(event.scan_bytes)              # 扫描字节
    if event.access_type == POINT_LOOKUP:
        profile.point_lookup_window.add(1)                       # 点查
    else if event.access_type == FULL_SCAN:
        profile.full_scan_window.add(1)                          # 大扫描（降权用）

function record_write(event):
    key = (event.table_id, event.partition_id, event.tablet_id)
    profile = heat_registry.get_or_create(key)                  # 不存在则创建（纯写入也保留新鲜度）
    profile.last_write_time = max(profile.last_write_time, event.newest_write_time)

# ============================================================
# 2. 热度上报与合并（BE→FE，绝对值快照；热度仅咨询，不影响正确性）
# ============================================================
function report_heat_periodic():                                # BE 独立 worker，cloud 模式天然不注册
    snapshot = []
    for profile in heat_registry.snapshot(drop_idle = true):
        snapshot.append(profile.absolute_counts())             # 5m/1h/1d 绝对计数 + last_access/last_write
    send_to_fe(REPORT_HEAT, be_id, snapshot, epoch, seq)

function merge_heat(be_id, snapshot, epoch, seq):              # FE 侧
    if is_cloud_mode(): return                                  # 本地 SSD/HDD 分层与 cloud 无关
    for stat in snapshot:
        p = heat_profiles.get_or_create(stat.tablet_id)
        if (epoch, seq) > p.per_be_seq[be_id]:                 # 同一 (BE,tablet) 仅取最新，跨 BE 求和
            p.per_be[be_id] = stat
            p.per_be_seq[be_id] = (epoch, seq)

# ============================================================
# 3. 策略解析（字段级合并；优先级 表 < 分区 < 租户=数据库 db_id）
# ============================================================
function resolve_policy(object):
    r = default_policy()                                        # 来自全局 Config 默认
    apply_set_fields(r, policy_registry.find_by_table(object.table_id))         # 低
    apply_set_fields(r, policy_registry.find_by_partition(object.partition_id))
    apply_set_fields(r, policy_registry.find_by_tenant(object.db_id))           # 高（租户=库）
    r.effective_revision = combine_epochs(table_epoch, partition_epoch, tenant_epoch)  # 派生版本，用于判旧
    return r

function apply_set_fields(r, p):
    # 三态：只有显式设置过的字段才覆盖父级；enabled 也是被合并字段
    if p is null: return
    for field in [enabled, hot_threshold, cold_threshold, cooldown_time,
                  min_hot_residence, min_cold_residence, max_ssd_bytes,
                  point_lookup_weight, scan_bytes_weight, batch_scan_penalty, manual_hold]:
        if p.has_set(field):
            r[field] = p[field]
    if p.has_set(max_ssd_bytes):                               # 配额取层级 min(self, parent)
        r.max_ssd_bytes = min_positive(r.max_ssd_bytes, p.max_ssd_bytes)

# ============================================================
# 4. 访问评分（专利六因子全覆盖）
# ============================================================
function calc_access_score(heat, policy):
    score  = heat.read_count(5m)                                          # 访问频率
    score += heat.point_lookup_count(1h) * policy.point_lookup_weight     # 点查
    score += (heat.scan_bytes(1h) / 1MiB) * policy.scan_bytes_weight      # 扫描字节
    if now() - heat.last_write_time < policy.fresh_write_protect_time:    # 写入新鲜度
        score += policy.fresh_write_score
    if now() - heat.last_access_time < RECENCY_WINDOW:                    # 最近访问时间
        score += heat.read_count(5m)
    score -= heat.full_scan_count(1h) * policy.batch_scan_penalty         # 大扫描降权
    return score

# ============================================================
# 5. 温度状态机（迟滞 + 最小驻留防抖 + FROZEN 前置）
# ============================================================
function evaluate_temperature(object):
    policy = resolve_policy(object)
    if not policy.enabled:        return SKIP
    if policy.manual_hold:        return FROZEN                # 人工锁定
    if has_storage_policy(object.partition) or object.has_cooldown_meta:
        return FROZEN                                          # 远端生命周期接管，本地不迁（绝不触碰远端）

    heat  = read_heat_profile(object)
    score = calc_access_score(heat, policy)
    cold_eff = min(policy.cold_threshold, policy.hot_threshold - MIN_SCORE_GAP)   # 迟滞
    cur        = object.current_target_medium
    last_change= object.last_target_change_time

    if score >= policy.hot_threshold:
        if cur == HDD and now() - last_change < policy.min_cold_residence:
            return WARM                                        # 刚降冷，最小冷驻留内不立刻升（防抖）
        return HOT
    if score <= cold_eff:
        idle_enough  = (heat.last_access_time == 0) or
                       (now() - heat.last_access_time > policy.cooldown_time)     # 最近访问 + 冷却周期
        residence_ok = (cur != SSD) or (now() - last_change >= policy.min_hot_residence)  # 最小热驻留
        if idle_enough and residence_ok:
            return COLD
    return WARM

function temperature_to_medium(state, cur):
    if state == HOT:  return SSD
    if state == COLD: return HDD
    return cur                                                 # WARM / FROZEN：维持现状

# ============================================================
# 6. 调度下发（目标≠实际才迁；tablet 级在途去重；await-report 屏障；灰度）
# ============================================================
function schedule_tiering(object):
    state  = evaluate_temperature(object)
    target = temperature_to_medium(state, object.current_target_medium)
    if target != object.persisted_target:
        reason = HIGH_QPS_PROMOTE if target == SSD else LOW_ACCESS_DEMOTE
        persist_target(object, target, reason)                # 写 edit log；bump version + effective_revision
    if dry_run: return                                        # 灰度：只决策不下发

    for replica in object.replicas:                           # 副本逐个、tablet 级去重
        if actual_medium(replica) == object.persisted_target: continue
        if now() - object.last_migration_time < await_report_timeout:
            continue                                          # 上次迁移未经 report 回填前不重发
        emit_migration_task(replica,
                            target_medium     = object.persisted_target,
                            migration_attempt_id = next_attempt_id(),
                            effective_revision   = object.effective_revision,
                            strict_dest_path_hash = true)
        break                                                 # 每轮每 tablet 至多一个副本在途

# ============================================================
# 7. SSD 容量压力驱逐（水位超限时，按最冷优先降冷）
# ============================================================
function evict_under_ssd_pressure(node):
    if ssd_used_ratio(node) < ssd_high_watermark: return
    candidates = sort_by_score_asc(ssd_target_tablets_on(node))     # 最冷优先
    for object in take(candidates, max_evict_per_round):
        if now() - object.last_target_change_time >= policy(object).min_hot_residence:
            persist_target(object, HDD, reason = SSD_PRESSURE_EVICT) # 下一轮 schedule 实际迁出

# ============================================================
# 8. 同节点迁移执行（复用现有迁移底座；新目录装载成功才切换；失败旧目录继续服务）
# ============================================================
function migrate_tablet_same_node(task):
    tablet = tablet_manager.get(task.tablet_id)
    # 严格校验：schema_hash 一致；源 path_hash 未变（否则判 STALE）；目标 path_hash 严格匹配、不回退
    if not strict_check(tablet, task): return STALE
    dest = choose_local_dir(local_node_id, task.target_medium, task.dest_path_hash)
    mark_transition(tablet.id)
    copied = []
    try:
        # 事务/合并/结构变更期间不迁：此处等事务静默；compaction/SC 由 strict_check + 加锁保证安全
        wait_until_no_running_txn(tablet)
        lock_migration_and_push(tablet)
        rowsets = capture_consistent_rowsets(tablet, start_version = 0)
        unlock_migration_and_push(tablet)
        copy_rowset_files(rowsets, dest.temp_path); copied.append(rowsets)
        while has_new_visible_rowsets(tablet):                # 增量尾部追拷；尾部够小则持锁收口
            tail = capture_tail_rowsets(tablet)
            if size(tail) <= small_tail_threshold:
                lock_migration_and_push(tablet)
            copy_rowset_files(tail, dest.temp_path); copied.append(tail)
        new_meta = build_meta_for_dest(tablet, dest, copied)
        save_meta(dest.temp_path, new_meta)
        reload_tablet_from_dest(dest.temp_path)               # 装载成功后才切换路径
        unlock_migration_and_push(tablet)
        return OK(copy_size, copy_time, migration_attempt_id, task.effective_revision)
    catch error:
        remove_temp_path(dest.temp_path)                      # 失败清理暂存，旧目录继续服务
        return classify(error)                                # RETRYABLE / CAPACITY / FROZEN / UNRECOVERABLE
    finally:
        unmark_transition(tablet.id)

# ============================================================
# 9. 迁移完成回收（幂等；严格判旧；实际介质经 report 回填，不经 finish）
# ============================================================
function on_migration_finish(task, result):
    object = lookup(task.tablet_id)
    if task.migration_attempt_id != object.pending_attempt_id: return   # 过期任务，忽略
    if task.effective_revision != resolve_policy(object).effective_revision:
        return                                                          # 该 tablet 相关策略已变 → 判旧丢弃
    if result == OK or result == ALREADY_APPLIED:
        object.last_migration_time = now()                              # 进入 await-report 屏障
        # 实际 medium / path_hash 由下一次 tablet report reconcile，不在此回写
    else if result == STALE:
        clear_pending(object)                                           # 等 report 后重判
    else if retryable(result):
        schedule_retry(object)
```
