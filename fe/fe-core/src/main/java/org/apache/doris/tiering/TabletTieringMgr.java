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

import org.apache.doris.common.Config;
import org.apache.doris.common.util.MasterDaemon;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Tablet-level same-node SSD/HDD tiering manager (B route).
 *
 * <p>This is the master-only evaluation daemon: each cycle it (will) re-evaluate
 * tablet heat, produce {@code TieringDecision}s and feed migration tasks to the
 * {@code TabletScheduler}. See docs/tablet-tiering-b-route-design-v2.md and
 * docs/tablet-tiering-b-route-execution-plan-v2.md.
 *
 * <p>Phase 0 (this commit) only wires the skeleton: it is mounted exclusively on
 * a non-cloud master FE, and is fully inert unless {@code enable_tablet_tiering}
 * is turned on. When the switch is off the daemon does nothing — gate G0 requires
 * switch-off behavior to be byte-for-byte identical to before this feature.
 */
public class TabletTieringMgr extends MasterDaemon {
    private static final Logger LOG = LogManager.getLogger(TabletTieringMgr.class);

    public TabletTieringMgr() {
        super("tablet tiering mgr",
                (long) Config.tablet_tiering_scheduler_interval_sec * 1000L);
    }

    @Override
    protected void runAfterCatalogReady() {
        // Defensive double-gate: the daemon is only started on a non-cloud master
        // (see Env#startMasterOnlyDaemonThreads), but cloud mode must never run any
        // local SSD/HDD tiering logic regardless of how it was started.
        if (Config.isCloudMode()) {
            return;
        }
        if (!Config.enable_tablet_tiering) {
            // Feature disabled: stay fully inert.
            return;
        }
        try {
            runTieringCycle();
        } catch (Throwable t) {
            // Tiering must never disrupt the master's main scheduling loops.
            LOG.warn("tablet tiering cycle failed", t);
        }
    }

    /**
     * One evaluation cycle. Phase 0 placeholder — real heat evaluation, decision
     * output and migration-task generation land in later phases (P3/P4).
     */
    private void runTieringCycle() {
        // Intentionally empty in Phase 0.
    }
}
