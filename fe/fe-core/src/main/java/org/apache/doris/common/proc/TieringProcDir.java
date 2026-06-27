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

package org.apache.doris.common.proc;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.AnalysisException;
import org.apache.doris.tiering.TabletTierState;
import org.apache.doris.tiering.TabletTieringMgr;
import org.apache.doris.tiering.TieringPolicy;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

/**
 * Tablet tiering (B route) observability via {@code SHOW PROC '/tiering'} and its
 * sub-views {@code /tiering/policies} and {@code /tiering/tablet_states}. Lets an
 * operator explain why each tablet targets SSD/HDD (design v2 §11 / §21.6 / T6.3).
 */
public class TieringProcDir implements ProcDirInterface {
    private static final ImmutableList<String> CHILDREN =
            ImmutableList.of("policies", "tablet_states");

    @Override
    public ProcResult fetchResult() throws AnalysisException {
        BaseProcResult result = new BaseProcResult();
        result.setNames(Lists.newArrayList("Name"));
        for (String child : CHILDREN) {
            result.addRow(Lists.newArrayList(child));
        }
        return result;
    }

    @Override
    public boolean register(String name, ProcNodeInterface node) {
        return false;
    }

    @Override
    public ProcNodeInterface lookup(String name) throws AnalysisException {
        TabletTieringMgr mgr = Env.getCurrentEnv().getTabletTieringMgr();
        if ("policies".equals(name)) {
            return new PoliciesNode(mgr);
        }
        if ("tablet_states".equals(name)) {
            return new StatesNode(mgr);
        }
        throw new AnalysisException("unknown tiering proc node: " + name);
    }

    private static class PoliciesNode implements ProcNodeInterface {
        private final TabletTieringMgr mgr;

        PoliciesNode(TabletTieringMgr mgr) {
            this.mgr = mgr;
        }

        @Override
        public ProcResult fetchResult() {
            BaseProcResult result = new BaseProcResult();
            result.setNames(Lists.newArrayList("ScopeType", "ScopeId", "Enabled", "HotThreshold",
                    "ColdThreshold", "MaxSsdBytes", "ManualHold", "Epoch"));
            if (mgr != null) {
                for (TieringPolicy p : mgr.getPolicyManager().getScopePolicies().values()) {
                    result.addRow(Lists.newArrayList(
                            String.valueOf(p.getScopeType()),
                            String.valueOf(p.getScopeId()),
                            String.valueOf(p.getEnabled()),
                            String.valueOf(p.getHotThreshold()),
                            String.valueOf(p.getColdThreshold()),
                            String.valueOf(p.getMaxSsdBytes()),
                            String.valueOf(p.getManualHold()),
                            String.valueOf(p.getEpoch())));
                }
            }
            return result;
        }
    }

    private static class StatesNode implements ProcNodeInterface {
        private final TabletTieringMgr mgr;

        StatesNode(TabletTieringMgr mgr) {
            this.mgr = mgr;
        }

        @Override
        public ProcResult fetchResult() {
            BaseProcResult result = new BaseProcResult();
            result.setNames(Lists.newArrayList("TabletId", "TableId", "PartitionId", "TargetMedium",
                    "PreviousTargetMedium", "Temperature", "Reason", "Score", "Version",
                    "LastMigrationTimeMs"));
            if (mgr != null) {
                for (TabletTierState s : mgr.getTabletTierStates()) {
                    result.addRow(Lists.newArrayList(
                            String.valueOf(s.getTabletId()),
                            String.valueOf(s.getTableId()),
                            String.valueOf(s.getPartitionId()),
                            String.valueOf(s.getTargetMedium()),
                            String.valueOf(s.getPreviousTargetMedium()),
                            String.valueOf(s.getTemperatureState()),
                            String.valueOf(s.getReasonCode()),
                            String.valueOf(mgr.getScoreOf(s.getTabletId())),
                            String.valueOf(s.getVersion()),
                            String.valueOf(s.getLastMigrationTimeMs())));
                }
            }
            return result;
        }
    }
}
