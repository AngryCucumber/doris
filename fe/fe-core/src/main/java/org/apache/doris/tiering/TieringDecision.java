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

import org.apache.doris.thrift.TStorageMedium;

/**
 * Output of one tablet evaluation (design v2 §9.3). In dry-run only decisions
 * and metrics are produced; otherwise a target change writes TabletTierState.
 */
public class TieringDecision {
    private final long tabletId;
    private final TStorageMedium oldTargetMedium;
    private final TStorageMedium newTargetMedium;
    private final TieringTemperature temperature;
    private final double score;
    private final long effectiveRevision;
    private final TieringReasonCode reasonCode;
    private final String explain;

    public TieringDecision(long tabletId, TStorageMedium oldTargetMedium,
            TStorageMedium newTargetMedium, TieringTemperature temperature, double score,
            long effectiveRevision, TieringReasonCode reasonCode, String explain) {
        this.tabletId = tabletId;
        this.oldTargetMedium = oldTargetMedium;
        this.newTargetMedium = newTargetMedium;
        this.temperature = temperature;
        this.score = score;
        this.effectiveRevision = effectiveRevision;
        this.reasonCode = reasonCode;
        this.explain = explain;
    }

    public long getTabletId() {
        return tabletId;
    }

    public TStorageMedium getOldTargetMedium() {
        return oldTargetMedium;
    }

    public TStorageMedium getNewTargetMedium() {
        return newTargetMedium;
    }

    public TieringTemperature getTemperature() {
        return temperature;
    }

    public double getScore() {
        return score;
    }

    public long getEffectiveRevision() {
        return effectiveRevision;
    }

    public TieringReasonCode getReasonCode() {
        return reasonCode;
    }

    public String getExplain() {
        return explain;
    }

    public boolean isTargetChanged() {
        return newTargetMedium != null && newTargetMedium != oldTargetMedium;
    }
}
