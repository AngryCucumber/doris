// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package org.apache.doris.tiering;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.common.io.Text;
import org.apache.doris.common.util.MasterDaemon;
import org.apache.doris.metric.GaugeMetric;
import org.apache.doris.metric.Metric.MetricUnit;
import org.apache.doris.metric.MetricRepo;
import org.apache.doris.persist.gson.GsonUtils;
import org.apache.doris.thrift.TStorageMedium;
import org.apache.doris.thrift.TTabletHeatStat;

import com.google.gson.annotations.SerializedName;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Tablet-level same-node SSD/HDD tiering manager (B route).
 *
 * <p>This is the master-only evaluation daemon plus the owner of tiering metadata
 * ({@link TieringPolicy} via {@link TieringPolicyManager} and per-tablet
 * {@link TabletTierState}). Each cycle it (will) re-evaluate tablet heat, produce
 * decisions and feed migration tasks to the {@code TabletScheduler}. See
 * docs/tablet-tiering-b-route-design-v2.md / -execution-plan-v2.md.
 *
 * <p>It is mounted exclusively on a non-cloud master FE and is fully inert unless
 * {@code enable_tablet_tiering} is on (gate G0). Metadata persistence (edit log +
 * image) is always active so that policy/state survive restart regardless of the
 * runtime switch.
 */
public class TabletTieringMgr extends MasterDaemon {
    private static final Logger LOG = LogManager.getLogger(TabletTieringMgr.class);

    /** BE capability bit: only BEs declaring this get tiering migration tasks. */
    public static final String TIER_MIGRATION_V1 = "TIER_MIGRATION_V1";

    // Scan bytes normalization unit for scoring (1 MiB).
    private static final long SCAN_BYTES_UNIT = 1024L * 1024L;

    private final TieringPolicyManager policyManager = new TieringPolicyManager();
    // FE-persisted per-tablet tier state, key = tablet id. Lazily created.
    private final ConcurrentHashMap<Long, TabletTierState> tabletTierStates = new ConcurrentHashMap<>();
    // FE in-memory heat profiles, key = tablet id. Not persisted (optional checkpoint).
    private final ConcurrentHashMap<Long, TabletHeatProfile> heatProfiles = new ConcurrentHashMap<>();

    private final AtomicLong decisionTotal = new AtomicLong();
    private final AtomicLong dryRunDecisionTotal = new AtomicLong();
    private final AtomicBoolean metricsRegistered = new AtomicBoolean(false);

    private long countTemperature(TieringTemperature temp) {
        long n = 0;
        for (TabletTierState s : tabletTierStates.values()) {
            if (s.getTemperatureState() == temp) {
                n++;
            }
        }
        return n;
    }

    /** Register tiering gauges once. Done regardless of the switch so the feature
     * is observable even while disabled (values are 0 then). See design v2 §13. */
    private void registerMetricsOnce() {
        if (!metricsRegistered.compareAndSet(false, true)) {
            return;
        }
        MetricRepo.DORIS_METRIC_REGISTER.addMetrics(new GaugeMetric<Long>(
                "tablet_tiering_policy_count", MetricUnit.NOUNIT, "tiering policy count") {
            @Override
            public Long getValue() {
                return (long) policyManager.size();
            }
        });
        MetricRepo.DORIS_METRIC_REGISTER.addMetrics(new GaugeMetric<Long>(
                "tablet_tiering_state_count", MetricUnit.NOUNIT, "tiering tablet state count") {
            @Override
            public Long getValue() {
                return (long) tabletTierStates.size();
            }
        });
        MetricRepo.DORIS_METRIC_REGISTER.addMetrics(new GaugeMetric<Long>(
                "tablet_tiering_heat_profile_count", MetricUnit.NOUNIT, "tiering heat profile count") {
            @Override
            public Long getValue() {
                return (long) heatProfiles.size();
            }
        });
        MetricRepo.DORIS_METRIC_REGISTER.addMetrics(new GaugeMetric<Long>(
                "tablet_tiering_hot_tablet_count", MetricUnit.NOUNIT, "hot tablet count") {
            @Override
            public Long getValue() {
                return countTemperature(TieringTemperature.HOT);
            }
        });
        MetricRepo.DORIS_METRIC_REGISTER.addMetrics(new GaugeMetric<Long>(
                "tablet_tiering_cold_tablet_count", MetricUnit.NOUNIT, "cold tablet count") {
            @Override
            public Long getValue() {
                return countTemperature(TieringTemperature.COLD);
            }
        });
        MetricRepo.DORIS_METRIC_REGISTER.addMetrics(new GaugeMetric<Long>(
                "tablet_tiering_decision_total", MetricUnit.NOUNIT, "applied tiering decisions") {
            @Override
            public Long getValue() {
                return decisionTotal.get();
            }
        });
        MetricRepo.DORIS_METRIC_REGISTER.addMetrics(new GaugeMetric<Long>(
                "tablet_tiering_dry_run_decision_total", MetricUnit.NOUNIT, "dry-run tiering decisions") {
            @Override
            public Long getValue() {
                return dryRunDecisionTotal.get();
            }
        });
    }

    public TabletTieringMgr() {
        super("tablet tiering mgr",
                (long) Config.tablet_tiering_scheduler_interval_sec * 1000L);
    }

    public TieringPolicyManager getPolicyManager() {
        return policyManager;
    }

    public TabletTierState getTabletTierState(long tabletId) {
        return tabletTierStates.get(tabletId);
    }

    public int getTierStateCount() {
        return tabletTierStates.size();
    }

    /**
     * Whether the given tablet's table/partition is owned by tiering. Phase 1
     * bases this on effective-enable; the persistent {@code detach} flag that
     * keeps ownership across {@code enable=false} pause lands in P4.
     */
    public boolean isTieringOwned(long tableId, long partitionId) {
        return policyManager.resolveEffectiveEnabled(tableId, partitionId);
    }

    /**
     * Effective target medium for a tablet = persisted {@code TabletTierState}
     * target if present, else {@code null} (the caller falls back to the
     * partition default). The full resolver wiring into rebalancer consumers
     * lands in P4 (design v2 §9.4).
     */
    public TStorageMedium resolveEffectiveTarget(long tabletId) {
        TabletTierState state = tabletTierStates.get(tabletId);
        return state == null ? null : state.getTargetMedium();
    }

    /**
     * Effective medium for a tablet = persisted target if present, else the given
     * partition default. Rebalancer consumers and the scheduler read this instead
     * of {@code TabletMeta.storageMedium} (which must stay the partition default,
     * since one index's tablets share a TabletMeta instance). See design v2 §9.4.
     */
    public TStorageMedium resolveEffectiveMedium(long tabletId, TStorageMedium partitionDefault) {
        TStorageMedium target = resolveEffectiveTarget(tabletId);
        return target != null ? target : partitionDefault;
    }

    // ---------------------------------------------------------------------
    // Master-side mutations (write edit log + apply). Callers must be master.
    // ---------------------------------------------------------------------

    public void modifyTieringPolicy(TieringPolicy policy) {
        policyManager.putPolicy(policy);
        Env.getCurrentEnv().getEditLog().logModifyTieringPolicy(policy);
    }

    public void replayModifyTieringPolicy(TieringPolicy policy) {
        policyManager.putPolicy(policy);
    }

    public void removeTieringPolicy(TieringScopeType scopeType, long scopeId) {
        policyManager.removePolicy(scopeType, scopeId);
        Env.getCurrentEnv().getEditLog().logRemoveTieringPolicy(
                new DropTieringPolicyInfo(scopeType, scopeId));
    }

    public void replayRemoveTieringPolicy(DropTieringPolicyInfo info) {
        policyManager.removePolicy(info.getScopeType(), info.getScopeId());
    }

    public void modifyTabletTierState(TabletTierState state) {
        tabletTierStates.put(state.getTabletId(), state);
        Env.getCurrentEnv().getEditLog().logModifyTabletTierState(state);
    }

    public void replayModifyTabletTierState(TabletTierState state) {
        tabletTierStates.put(state.getTabletId(), state);
    }

    public void batchModifyTabletTierState(List<TabletTierState> states) {
        for (TabletTierState state : states) {
            tabletTierStates.put(state.getTabletId(), state);
        }
        Env.getCurrentEnv().getEditLog().logBatchModifyTabletTierState(
                new BatchModifyTabletTierStateInfo(states));
    }

    public void replayBatchModifyTabletTierState(BatchModifyTabletTierStateInfo info) {
        if (info.getStates() != null) {
            for (TabletTierState state : info.getStates()) {
                tabletTierStates.put(state.getTabletId(), state);
            }
        }
    }

    public void cleanTabletTierState(List<Long> tabletIds) {
        for (Long tabletId : tabletIds) {
            tabletTierStates.remove(tabletId);
        }
        Env.getCurrentEnv().getEditLog().logCleanTabletTierState(
                new CleanTabletTierStateInfo(tabletIds));
    }

    public void replayCleanTabletTierState(CleanTabletTierStateInfo info) {
        if (info.getTabletIds() != null) {
            for (Long tabletId : info.getTabletIds()) {
                tabletTierStates.remove(tabletId);
            }
        }
    }

    /**
     * Memory-only cleanup hook invoked from the tablet delete entry. It must be
     * idempotent and replay-safe (NO edit log here): {@code deleteTablet} is on
     * the replay path too, and persistent cleanup is recorded only by the master
     * operation path or folded into the parent op (design v2 §10, T1.5).
     */
    public void onTabletDeleted(long tabletId) {
        tabletTierStates.remove(tabletId);
        heatProfiles.remove(tabletId);
    }

    /**
     * Called from the scheduler finish path when a TIER_MIGRATION task succeeds.
     * Records the migration time on the tier state; actual medium/path are NOT
     * written here (reconciled by the next tablet report). The await-report
     * barrier (P4 ReplicaTierProgress) prevents re-send until reconciled.
     * See design v2 §9.5 / T4.4.
     */
    public void onTierMigrationFinished(long tabletId, long migrationAttemptId) {
        TabletTierState state = tabletTierStates.get(tabletId);
        if (state == null) {
            return;
        }
        state.setLastMigrationTimeMs(System.currentTimeMillis());
        modifyTabletTierState(state);
    }

    // ---------------------------------------------------------------------
    // Heat merge (BE -> FE), absolute-value mode. See design v2 §7.1 / §9.1.
    // ---------------------------------------------------------------------

    /**
     * Merge a BE's heat report into FE heat profiles. Absolute values per (BE,
     * tablet) are overwritten by the latest (deduped by epoch/seq) and summed
     * across BEs. Heat is advisory only and never affects correctness.
     */
    public void mergeHeatStats(long beId, List<TTabletHeatStat> stats, long epoch, long seq) {
        if (Config.isCloudMode() || stats == null) {
            return;
        }
        long nowMs = System.currentTimeMillis();
        for (TTabletHeatStat stat : stats) {
            long tabletId = stat.getTabletId();
            TabletHeatProfile profile = heatProfiles.computeIfAbsent(tabletId,
                    id -> new TabletHeatProfile(id, stat.getTableId(), stat.getPartitionId()));
            profile.mergeBe(beId, epoch, seq, stat.getReadCount5m(), stat.getReadCount1h(),
                    stat.getReadCount1d(), stat.getPointLookupCount5m(), stat.getPointLookupCount1h(),
                    stat.getRangeScanCount1h(), stat.getFullScanCount1h(), stat.getScanBytes1h(),
                    stat.getScanRows1h(), stat.getLastAccessTimeMs(), stat.getLastWriteTimeMs(),
                    stat.getTableId(), stat.getPartitionId(), nowMs);
        }
    }

    /** FE-side HeatProfile aging: drop profiles absent from reports for too long. */
    private void ageHeatProfiles(long nowMs) {
        long expireMs = (long) Config.tablet_heat_fe_expire_sec * 1000L;
        if (expireMs <= 0) {
            return;
        }
        Iterator<Map.Entry<Long, TabletHeatProfile>> it = heatProfiles.entrySet().iterator();
        while (it.hasNext()) {
            TabletHeatProfile p = it.next().getValue();
            if (p.getLastReportTimeMs() > 0 && nowMs - p.getLastReportTimeMs() > expireMs) {
                it.remove();
            }
        }
    }

    // ---------------------------------------------------------------------
    // Evaluation: scoring + state machine + decision (design v2 §9.2/§9.3).
    // ---------------------------------------------------------------------

    /** Patent six-factor access score (design v2 §9.2). */
    private double computeScore(TabletHeatProfile profile, ResolvedTieringPolicy policy, long nowMs) {
        double score = profile.getReadCount5m();
        score += profile.getPointLookupCount1h() * policy.pointLookupWeight;
        score += ((double) profile.getScanBytes1h() / SCAN_BYTES_UNIT) * policy.scanBytesWeight;
        // freshness: newly-written data is protected from demotion
        long lastWrite = profile.getLastWriteTimeMs();
        if (lastWrite > 0
                && nowMs - lastWrite < (long) Config.tablet_tiering_fresh_write_protect_sec * 1000L) {
            score += Config.tablet_tiering_fresh_write_score;
        }
        // access recency: recent access keeps it warm (patent "last access time")
        long lastAccess = profile.getLastAccessTimeMs();
        if (lastAccess > 0 && nowMs - lastAccess < 300_000L) {
            score += profile.getReadCount5m();
        }
        // batch scan penalty
        score -= profile.getFullScanCount1h() * policy.batchScanPenalty;
        return score;
    }

    /**
     * Temperature state machine with hysteresis + minimum residence. Returns the
     * new temperature; the caller maps it to a target medium.
     */
    private TieringTemperature evaluateTemperature(TabletHeatProfile profile,
            ResolvedTieringPolicy policy, TabletTierState state, double score, long nowMs) {
        if (policy.manualHold) {
            return TieringTemperature.POLICY_FROZEN;
        }
        // enforce hysteresis: cold must sit at least min_score_gap below hot
        double coldThreshold = Math.min(policy.coldThreshold,
                policy.hotThreshold - Config.tablet_tiering_min_score_gap);
        TStorageMedium curTarget = state == null ? null : state.getTargetMedium();
        long lastChange = state == null ? 0 : state.getLastTargetChangeTimeMs();

        if (score >= policy.hotThreshold) {
            // promote unless we just demoted and min cold residence not elapsed
            if (curTarget == TStorageMedium.HDD && lastChange > 0
                    && nowMs - lastChange < policy.minColdResidenceSec * 1000L) {
                return TieringTemperature.WARM;
            }
            return TieringTemperature.HOT;
        }
        if (score <= coldThreshold) {
            long idleMs = nowMs - profile.getLastAccessTimeMs();
            boolean idleEnough = profile.getLastAccessTimeMs() == 0
                    || idleMs > policy.cooldownTimeSec * 1000L;
            boolean residenceOk = curTarget != TStorageMedium.SSD || lastChange == 0
                    || nowMs - lastChange >= policy.minHotResidenceSec * 1000L;
            if (idleEnough && residenceOk) {
                return TieringTemperature.COLD;
            }
        }
        return TieringTemperature.WARM;
    }

    private TStorageMedium temperatureToTarget(TieringTemperature temp, TStorageMedium curTarget) {
        switch (temp) {
            case HOT:
                return TStorageMedium.SSD;
            case COLD:
                return TStorageMedium.HDD;
            default:
                return curTarget; // WARM / POLICY_FROZEN: keep current
        }
    }

    private void evaluateTablet(TabletHeatProfile profile, long nowMs) {
        long tableId = profile.getTableId();
        long partitionId = profile.getPartitionId();
        if (!isTieringOwned(tableId, partitionId)) {
            return;
        }
        ResolvedTieringPolicy policy = policyManager.resolve(tableId, partitionId);
        if (!policy.enabled) {
            return;
        }
        double score = computeScore(profile, policy, nowMs);
        profile.setCurrentScore(score);
        profile.setLastEvalTimeMs(nowMs);

        TabletTierState state = tabletTierStates.get(profile.getTabletId());
        TStorageMedium oldTarget = state == null ? null : state.getTargetMedium();
        TieringTemperature temp = evaluateTemperature(profile, policy, state, score, nowMs);
        profile.setTemperatureState(temp);
        TStorageMedium newTarget = temperatureToTarget(temp, oldTarget);

        TieringReasonCode reason = TieringReasonCode.NONE;
        if (temp == TieringTemperature.HOT) {
            reason = TieringReasonCode.HIGH_QPS_PROMOTE;
        } else if (temp == TieringTemperature.COLD) {
            reason = TieringReasonCode.LOW_ACCESS_DEMOTE;
        }

        TieringDecision decision = new TieringDecision(profile.getTabletId(), oldTarget, newTarget,
                temp, score, policy.effectiveRevision, reason,
                "temp=" + temp + " score=" + score);

        if (Config.tablet_tiering_dry_run) {
            dryRunDecisionTotal.incrementAndGet();
            if (decision.isTargetChanged() && LOG.isDebugEnabled()) {
                LOG.debug("[tiering dry-run] tablet {} {} -> {} ({})", profile.getTabletId(),
                        oldTarget, newTarget, decision.getExplain());
            }
            return;
        }

        if (decision.isTargetChanged()) {
            decisionTotal.incrementAndGet();
            applyDecision(profile, decision, nowMs);
        }
    }

    private void applyDecision(TabletHeatProfile profile, TieringDecision decision, long nowMs) {
        TabletTierState state = tabletTierStates.get(profile.getTabletId());
        if (state == null) {
            state = new TabletTierState(profile.getTabletId(), profile.getTableId(),
                    profile.getPartitionId());
        }
        state.setPreviousTargetMedium(state.getTargetMedium());
        state.setTargetMedium(decision.getNewTargetMedium());
        state.setTemperatureState(decision.getTemperature());
        state.setReasonCode(decision.getReasonCode());
        state.setEffectiveRevision(decision.getEffectiveRevision());
        state.setLastTargetChangeTimeMs(nowMs);
        state.setVersion(state.getVersion() + 1);
        // Persist only on target change (design v2 §9.3). P4 feeds the scheduler.
        modifyTabletTierState(state);
    }

    // ---------------------------------------------------------------------
    // Image (checksum-neutral, mirrors the "policy" module).
    // ---------------------------------------------------------------------

    public void writeImage(DataOutput out) throws IOException {
        TieringImage image = new TieringImage();
        image.policies = new HashMap<>(policyManager.getScopePolicies());
        image.tierStates = new HashMap<>(tabletTierStates);
        Text.writeString(out, GsonUtils.GSON.toJson(image));
    }

    public void readImage(DataInput in) throws IOException {
        String json = Text.readString(in);
        TieringImage image = GsonUtils.GSON.fromJson(json, TieringImage.class);
        if (image == null) {
            return;
        }
        policyManager.replaceAll(image.policies);
        tabletTierStates.clear();
        if (image.tierStates != null) {
            tabletTierStates.putAll(image.tierStates);
        }
    }

    /** Gson DTO for the tiering image module. */
    private static class TieringImage {
        @SerializedName(value = "policies")
        private Map<String, TieringPolicy> policies;
        @SerializedName(value = "tierStates")
        private Map<Long, TabletTierState> tierStates;
    }

    // ---------------------------------------------------------------------
    // Evaluation daemon (Phase 0 placeholder; real logic in P3/P4).
    // ---------------------------------------------------------------------

    @Override
    protected void runAfterCatalogReady() {
        // Register observability gauges once, regardless of the switch.
        registerMetricsOnce();
        // Defensive double-gate: the daemon is only started on a non-cloud master
        // (see Env#startMasterOnlyDaemonThreads), but cloud mode must never run any
        // local SSD/HDD tiering logic regardless of how it was started.
        if (Config.isCloudMode()) {
            return;
        }
        if (!Config.enable_tablet_tiering) {
            return;
        }
        try {
            runTieringCycle();
        } catch (Throwable t) {
            // Tiering must never disrupt the master's main scheduling loops.
            LOG.warn("tablet tiering cycle failed", t);
        }
    }

    private void runTieringCycle() {
        long nowMs = System.currentTimeMillis();
        ageHeatProfiles(nowMs);
        for (TabletHeatProfile profile : heatProfiles.values()) {
            try {
                evaluateTablet(profile, nowMs);
            } catch (Throwable t) {
                LOG.warn("evaluate tablet {} failed", profile.getTabletId(), t);
            }
        }
    }
}
