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
import org.apache.doris.persist.gson.GsonUtils;
import org.apache.doris.thrift.TStorageMedium;

import com.google.gson.annotations.SerializedName;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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

    private final TieringPolicyManager policyManager = new TieringPolicyManager();
    // FE-persisted per-tablet tier state, key = tablet id. Lazily created.
    private final ConcurrentHashMap<Long, TabletTierState> tabletTierStates = new ConcurrentHashMap<>();

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
        // Intentionally empty until the evaluator (P3) and scheduler (P4) land.
    }
}
