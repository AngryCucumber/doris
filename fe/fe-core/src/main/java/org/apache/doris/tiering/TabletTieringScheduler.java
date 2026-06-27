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

import org.apache.doris.catalog.DiskInfo;
import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.Replica;
import org.apache.doris.catalog.TabletInvertedIndex;
import org.apache.doris.catalog.TabletMeta;
import org.apache.doris.clone.TabletSchedCtx;
import org.apache.doris.clone.TabletScheduler;
import org.apache.doris.common.Config;
import org.apache.doris.system.Backend;
import org.apache.doris.system.SystemInfoService;
import org.apache.doris.thrift.TStorageMedium;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;

/**
 * Producer side of tablet tiering (B route): scans tablets whose persisted target
 * medium differs from a replica's actual medium and feeds {@code TIER_MIGRATION}
 * {@link TabletSchedCtx} into the existing {@link TabletScheduler}, which provides
 * AgentTaskQueue tracking, PathSlot concurrency and finish recovery. It does not
 * run its own execution channel. See design v2 §9.5 / T4.3.
 */
public class TabletTieringScheduler {
    private static final Logger LOG = LogManager.getLogger(TabletTieringScheduler.class);

    private final TabletTieringMgr mgr;

    public TabletTieringScheduler(TabletTieringMgr mgr) {
        this.mgr = mgr;
    }

    public void dispatchMigrations(long nowMs) {
        Env env = Env.getCurrentEnv();
        TabletScheduler scheduler = env.getTabletScheduler();
        TabletInvertedIndex invertedIndex = env.getTabletInvertedIndex();
        SystemInfoService infoService = env.getCurrentSystemInfo();
        if (scheduler == null || invertedIndex == null || infoService == null) {
            return;
        }

        long awaitMs = (long) Config.tablet_tiering_await_report_timeout_sec * 1000L;
        int maxPerRound = Config.tablet_tiering_max_running_tasks;
        long copyBudget = Config.tablet_tiering_max_copy_bytes_per_round;
        int maxPerTable = Config.tablet_tiering_max_tasks_per_table;
        int added = 0;
        long copyBytes = 0;
        java.util.Map<Long, Integer> perTableCount = new java.util.HashMap<>();

        for (TabletTierState state : mgr.getTabletTierStates()) {
            if (added >= maxPerRound || copyBytes >= copyBudget) {
                break;
            }
            int tableCount = perTableCount.getOrDefault(state.getTableId(), 0);
            if (maxPerTable > 0 && tableCount >= maxPerTable) {
                continue;
            }
            TStorageMedium target = state.getTargetMedium();
            if (target == null) {
                continue;
            }
            // Await-report barrier: after a finish, actual medium/path are only
            // reconciled by the next tablet report. Skip recently-migrated tablets
            // so we do not re-dispatch before reconciliation (idempotent at BE via
            // ALREADY_APPLIED, but this avoids churn). See design v2 §9.5 / T4.4.
            if (state.getLastMigrationTimeMs() > 0
                    && nowMs - state.getLastMigrationTimeMs() < awaitMs) {
                continue;
            }
            long tabletId = state.getTabletId();
            TabletMeta tabletMeta = invertedIndex.getTabletMeta(tabletId);
            if (tabletMeta == null) {
                continue;
            }
            List<Replica> replicas = invertedIndex.getReplicasByTabletId(tabletId);
            for (Replica replica : replicas) {
                if (replica.isBad()) {
                    continue;
                }
                Backend backend = infoService.getBackend(replica.getBackendIdWithoutException());
                if (backend == null || !backend.isScheduleAvailable()) {
                    continue;
                }
                TStorageMedium actual = mediumOfPath(backend, replica.getPathHash());
                if (actual == null || actual == target) {
                    continue;
                }
                TabletSchedCtx ctx = new TabletSchedCtx(TabletSchedCtx.Type.BALANCE,
                        tabletMeta.getDbId(), tabletMeta.getTableId(), tabletMeta.getPartitionId(),
                        tabletMeta.getIndexId(), tabletId, null /* replicaAlloc unused for balance */,
                        nowMs);
                ctx.setTempSrc(replica);
                ctx.setTag(backend.getLocationTag());
                ctx.setStorageMedium(target);
                ctx.setBalanceType(TabletSchedCtx.BalanceType.TIER_MIGRATION);
                ctx.setPriority(TabletSchedCtx.Priority.LOW);
                TabletScheduler.AddResult result = scheduler.addTablet(ctx, false);
                if (result == TabletScheduler.AddResult.ADDED) {
                    added++;
                    copyBytes += Math.max(0, replica.getDataSize());
                    perTableCount.merge(state.getTableId(), 1, Integer::sum);
                }
                // tabletId-level dedup: at most one replica per tablet in flight.
                break;
            }
        }
        if (added > 0 && LOG.isDebugEnabled()) {
            LOG.debug("dispatched {} tier migration ctx", added);
        }
    }

    private TStorageMedium mediumOfPath(Backend backend, long pathHash) {
        for (DiskInfo disk : backend.getDisks().values()) {
            if (disk.getPathHash() == pathHash) {
                return disk.getStorageMedium();
            }
        }
        return null;
    }
}
