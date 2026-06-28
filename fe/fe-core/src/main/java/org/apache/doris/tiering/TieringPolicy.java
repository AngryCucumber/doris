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

import org.apache.doris.common.io.Text;
import org.apache.doris.common.io.Writable;
import org.apache.doris.persist.gson.GsonUtils;

import com.google.gson.annotations.SerializedName;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A tablet tiering policy bound to a scope (TABLE / PARTITION / TENANT).
 *
 * <p>All inheritable fields are boxed and nullable: {@code null} means "not set"
 * for this scope and is inherited from the parent during field-level merge (see
 * {@link TieringPolicyManager} and design v2 §6.1). {@code enabled} is itself a
 * field — a higher-priority scope can re-enable what a lower scope disabled.
 */
public class TieringPolicy implements Writable {
    @SerializedName(value = "policyId")
    private long policyId;
    @SerializedName(value = "scopeType")
    private TieringScopeType scopeType;
    @SerializedName(value = "scopeId")
    private long scopeId;
    // Bumped on every change; contributes to the derived per-tablet
    // effective_revision (design v2 §6.1).
    @SerializedName(value = "epoch")
    private long epoch;

    @SerializedName(value = "enabled")
    private Boolean enabled;
    @SerializedName(value = "hotThreshold")
    private Double hotThreshold;
    @SerializedName(value = "coldThreshold")
    private Double coldThreshold;
    @SerializedName(value = "cooldownTimeSec")
    private Long cooldownTimeSec;
    @SerializedName(value = "minHotResidenceSec")
    private Long minHotResidenceSec;
    @SerializedName(value = "minColdResidenceSec")
    private Long minColdResidenceSec;
    @SerializedName(value = "maxSsdBytes")
    private Long maxSsdBytes;
    @SerializedName(value = "pointLookupWeight")
    private Double pointLookupWeight;
    @SerializedName(value = "scanBytesWeight")
    private Double scanBytesWeight;
    @SerializedName(value = "batchScanPenalty")
    private Double batchScanPenalty;
    @SerializedName(value = "manualHold")
    private Boolean manualHold;
    @SerializedName(value = "updatedTimeMs")
    private long updatedTimeMs;

    public TieringPolicy() {
    }

    public TieringPolicy(TieringScopeType scopeType, long scopeId) {
        this.scopeType = scopeType;
        this.scopeId = scopeId;
    }

    public static String scopeKey(TieringScopeType scopeType, long scopeId) {
        return scopeType.name() + ":" + scopeId;
    }

    public String scopeKey() {
        return scopeKey(scopeType, scopeId);
    }

    public long getPolicyId() {
        return policyId;
    }

    public void setPolicyId(long policyId) {
        this.policyId = policyId;
    }

    public TieringScopeType getScopeType() {
        return scopeType;
    }

    public long getScopeId() {
        return scopeId;
    }

    public long getEpoch() {
        return epoch;
    }

    public void setEpoch(long epoch) {
        this.epoch = epoch;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Double getHotThreshold() {
        return hotThreshold;
    }

    public void setHotThreshold(Double hotThreshold) {
        this.hotThreshold = hotThreshold;
    }

    public Double getColdThreshold() {
        return coldThreshold;
    }

    public void setColdThreshold(Double coldThreshold) {
        this.coldThreshold = coldThreshold;
    }

    public Long getCooldownTimeSec() {
        return cooldownTimeSec;
    }

    public void setCooldownTimeSec(Long cooldownTimeSec) {
        this.cooldownTimeSec = cooldownTimeSec;
    }

    public Long getMinHotResidenceSec() {
        return minHotResidenceSec;
    }

    public void setMinHotResidenceSec(Long minHotResidenceSec) {
        this.minHotResidenceSec = minHotResidenceSec;
    }

    public Long getMinColdResidenceSec() {
        return minColdResidenceSec;
    }

    public void setMinColdResidenceSec(Long minColdResidenceSec) {
        this.minColdResidenceSec = minColdResidenceSec;
    }

    public Long getMaxSsdBytes() {
        return maxSsdBytes;
    }

    public void setMaxSsdBytes(Long maxSsdBytes) {
        this.maxSsdBytes = maxSsdBytes;
    }

    public Double getPointLookupWeight() {
        return pointLookupWeight;
    }

    public void setPointLookupWeight(Double pointLookupWeight) {
        this.pointLookupWeight = pointLookupWeight;
    }

    public Double getScanBytesWeight() {
        return scanBytesWeight;
    }

    public void setScanBytesWeight(Double scanBytesWeight) {
        this.scanBytesWeight = scanBytesWeight;
    }

    public Double getBatchScanPenalty() {
        return batchScanPenalty;
    }

    public void setBatchScanPenalty(Double batchScanPenalty) {
        this.batchScanPenalty = batchScanPenalty;
    }

    public Boolean getManualHold() {
        return manualHold;
    }

    public void setManualHold(Boolean manualHold) {
        this.manualHold = manualHold;
    }

    public long getUpdatedTimeMs() {
        return updatedTimeMs;
    }

    public void setUpdatedTimeMs(long updatedTimeMs) {
        this.updatedTimeMs = updatedTimeMs;
    }

    /**
     * The explicitly-set fields rendered as user-facing {@code tablet_tiering.*}
     * properties, for compute-on-display in SHOW CREATE DATABASE/TABLE. Only set
     * (non-null) fields are emitted, preserving the three-state semantics. This is
     * derived from the single authoritative policy at query time -- it is NOT a
     * second stored copy, so there is no consistency risk. Keys mirror
     * {@code PropertyAnalyzer.PROPERTIES_TABLET_TIERING_*}.
     */
    public Map<String, String> displayProperties() {
        Map<String, String> m = new LinkedHashMap<>();
        if (enabled != null) {
            m.put("tablet_tiering.enable", String.valueOf(enabled));
        }
        if (manualHold != null) {
            m.put("tablet_tiering.hold", String.valueOf(manualHold));
        }
        if (hotThreshold != null) {
            m.put("tablet_tiering.hot_threshold", String.valueOf(hotThreshold));
        }
        if (coldThreshold != null) {
            m.put("tablet_tiering.cold_threshold", String.valueOf(coldThreshold));
        }
        if (cooldownTimeSec != null) {
            m.put("tablet_tiering.cooldown_time", cooldownTimeSec + "s");
        }
        if (minHotResidenceSec != null) {
            m.put("tablet_tiering.min_hot_residence", minHotResidenceSec + "s");
        }
        if (minColdResidenceSec != null) {
            m.put("tablet_tiering.min_cold_residence", minColdResidenceSec + "s");
        }
        if (maxSsdBytes != null) {
            m.put("tablet_tiering.max_ssd_quota", String.valueOf(maxSsdBytes));
        }
        if (batchScanPenalty != null) {
            m.put("tablet_tiering.batch_scan_penalty", String.valueOf(batchScanPenalty));
        }
        return m;
    }

    @Override
    public void write(DataOutput out) throws IOException {
        Text.writeString(out, GsonUtils.GSON.toJson(this));
    }

    public static TieringPolicy read(DataInput in) throws IOException {
        return GsonUtils.GSON.fromJson(Text.readString(in), TieringPolicy.class);
    }
}
