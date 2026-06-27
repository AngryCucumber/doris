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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Holds {@link TieringPolicy} by scope and resolves the effective policy via
 * field-level merge (table &lt; partition &lt; tenant, low to high; tenant
 * enablement is P2). Only fields explicitly set on a scope override the parent;
 * {@code enabled} is itself a merged field, judged after the full merge so a
 * higher-priority scope can re-enable. See design v2 §6.1.
 *
 * <p>Phase 1 implements the two pieces T3/T4 need first: the effective-enable
 * query and the derived per-tablet {@code effective_revision}. Full field-level
 * resolution of thresholds/weights lands with the evaluator (P3).
 */
public class TieringPolicyManager {
    // key = TieringPolicy.scopeKey(scopeType, scopeId)
    private final Map<String, TieringPolicy> scopePolicies = new ConcurrentHashMap<>();

    public TieringPolicy getPolicy(TieringScopeType scopeType, long scopeId) {
        return scopePolicies.get(TieringPolicy.scopeKey(scopeType, scopeId));
    }

    public void putPolicy(TieringPolicy policy) {
        scopePolicies.put(policy.scopeKey(), policy);
    }

    public void removePolicy(TieringScopeType scopeType, long scopeId) {
        scopePolicies.remove(TieringPolicy.scopeKey(scopeType, scopeId));
    }

    public int size() {
        return scopePolicies.size();
    }

    /** Live map, used by image dump. */
    public Map<String, TieringPolicy> getScopePolicies() {
        return scopePolicies;
    }

    /** Replace all policies, used by image load. */
    public void replaceAll(Map<String, TieringPolicy> policies) {
        scopePolicies.clear();
        if (policies != null) {
            scopePolicies.putAll(policies);
        }
    }

    /**
     * Effective {@code enabled} after table-then-partition field-level merge.
     * Default is {@code false} (feature off) when no scope sets it. A partition
     * setting overrides the table; a partition {@code enabled=false} locally
     * disables rather than falling back to the table value.
     */
    public boolean resolveEffectiveEnabled(long tableId, long partitionId) {
        boolean enabled = false;
        TieringPolicy table = getPolicy(TieringScopeType.TABLE, tableId);
        if (table != null && table.getEnabled() != null) {
            enabled = table.getEnabled();
        }
        TieringPolicy partition = getPolicy(TieringScopeType.PARTITION, partitionId);
        if (partition != null && partition.getEnabled() != null) {
            enabled = partition.getEnabled();
        }
        return enabled;
    }

    /**
     * Full field-level resolution for a tablet: table then partition override the
     * config defaults, field by field (only explicitly-set fields override).
     * {@code enabled} is judged after the merge. SSD quota uses the hierarchical
     * min(self, parent) rule. See design v2 §6.1.
     */
    public ResolvedTieringPolicy resolve(long tableId, long partitionId) {
        ResolvedTieringPolicy r = new ResolvedTieringPolicy();
        // defaults
        r.enabled = false;
        r.hotThreshold = Config.tablet_tiering_default_hot_threshold;
        r.coldThreshold = Config.tablet_tiering_default_cold_threshold;
        r.cooldownTimeSec = 0;
        r.minHotResidenceSec = 0;
        r.minColdResidenceSec = 0;
        r.maxSsdBytes = -1;
        r.pointLookupWeight = 1.0;
        r.scanBytesWeight = 1.0;
        r.batchScanPenalty = 0.0;
        r.manualHold = false;

        apply(r, getPolicy(TieringScopeType.TABLE, tableId));
        apply(r, getPolicy(TieringScopeType.PARTITION, partitionId));
        r.effectiveRevision = effectiveRevision(tableId, partitionId);
        return r;
    }

    private void apply(ResolvedTieringPolicy r, TieringPolicy p) {
        if (p == null) {
            return;
        }
        if (p.getEnabled() != null) {
            r.enabled = p.getEnabled();
        }
        if (p.getHotThreshold() != null) {
            r.hotThreshold = p.getHotThreshold();
        }
        if (p.getColdThreshold() != null) {
            r.coldThreshold = p.getColdThreshold();
        }
        if (p.getCooldownTimeSec() != null) {
            r.cooldownTimeSec = p.getCooldownTimeSec();
        }
        if (p.getMinHotResidenceSec() != null) {
            r.minHotResidenceSec = p.getMinHotResidenceSec();
        }
        if (p.getMinColdResidenceSec() != null) {
            r.minColdResidenceSec = p.getMinColdResidenceSec();
        }
        if (p.getMaxSsdBytes() != null) {
            // Hierarchical: a child quota cannot exceed the remaining parent quota.
            r.maxSsdBytes = (r.maxSsdBytes < 0) ? p.getMaxSsdBytes()
                    : Math.min(r.maxSsdBytes, p.getMaxSsdBytes());
        }
        if (p.getPointLookupWeight() != null) {
            r.pointLookupWeight = p.getPointLookupWeight();
        }
        if (p.getScanBytesWeight() != null) {
            r.scanBytesWeight = p.getScanBytesWeight();
        }
        if (p.getBatchScanPenalty() != null) {
            r.batchScanPenalty = p.getBatchScanPenalty();
        }
        if (p.getManualHold() != null) {
            r.manualHold = p.getManualHold();
        }
    }

    /**
     * Derived per-tablet effective revision = a stable combination of the epochs
     * of the contributing scopes (table, partition). It changes whenever any
     * contributing scope changes, but is intentionally NOT globally monotonic so
     * that changing one table's policy does not over-invalidate in-flight tasks
     * of unrelated tables. See design v2 §6.1.
     */
    public long effectiveRevision(long tableId, long partitionId) {
        long tableEpoch = 0L;
        TieringPolicy table = getPolicy(TieringScopeType.TABLE, tableId);
        if (table != null) {
            tableEpoch = table.getEpoch();
        }
        long partitionEpoch = 0L;
        TieringPolicy partition = getPolicy(TieringScopeType.PARTITION, partitionId);
        if (partition != null) {
            partitionEpoch = partition.getEpoch();
        }
        return tableEpoch * 1_000_003L + partitionEpoch;
    }
}
