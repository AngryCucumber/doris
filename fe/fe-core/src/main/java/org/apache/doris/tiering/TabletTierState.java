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
import org.apache.doris.thrift.TStorageMedium;

import com.google.gson.annotations.SerializedName;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;

/**
 * FE-persisted per-tablet tiering state, keyed by tablet id. {@code targetMedium}
 * is the desired medium; the actual medium is reconciled from tablet report and
 * is NOT stored here (see design v2 §6.3). State is lazily created: a tablet has
 * no state until its first non-WARM decision.
 */
public class TabletTierState implements Writable {
    @SerializedName(value = "tabletId")
    private long tabletId;
    @SerializedName(value = "tableId")
    private long tableId;
    @SerializedName(value = "partitionId")
    private long partitionId;
    @SerializedName(value = "targetMedium")
    private TStorageMedium targetMedium;
    @SerializedName(value = "previousTargetMedium")
    private TStorageMedium previousTargetMedium;
    // Derived per-tablet effective revision of the contributing scope policies
    // (design v2 §6.1); used for finish-time stale detection, compared in FE.
    @SerializedName(value = "effectiveRevision")
    private long effectiveRevision;
    @SerializedName(value = "reasonCode")
    private TieringReasonCode reasonCode;
    @SerializedName(value = "temperatureState")
    private TieringTemperature temperatureState;
    @SerializedName(value = "lastMigrationTimeMs")
    private long lastMigrationTimeMs;
    @SerializedName(value = "lastTargetChangeTimeMs")
    private long lastTargetChangeTimeMs;
    @SerializedName(value = "frozenReason")
    private String frozenReason;
    @SerializedName(value = "manualOverride")
    private boolean manualOverride;
    // Idempotency version; bumped on manual single-tablet change (not scope epoch).
    @SerializedName(value = "version")
    private long version;

    public TabletTierState() {
    }

    public TabletTierState(long tabletId, long tableId, long partitionId) {
        this.tabletId = tabletId;
        this.tableId = tableId;
        this.partitionId = partitionId;
        this.reasonCode = TieringReasonCode.NONE;
    }

    public long getTabletId() {
        return tabletId;
    }

    public long getTableId() {
        return tableId;
    }

    public long getPartitionId() {
        return partitionId;
    }

    public TStorageMedium getTargetMedium() {
        return targetMedium;
    }

    public void setTargetMedium(TStorageMedium targetMedium) {
        this.targetMedium = targetMedium;
    }

    public TStorageMedium getPreviousTargetMedium() {
        return previousTargetMedium;
    }

    public void setPreviousTargetMedium(TStorageMedium previousTargetMedium) {
        this.previousTargetMedium = previousTargetMedium;
    }

    public long getEffectiveRevision() {
        return effectiveRevision;
    }

    public void setEffectiveRevision(long effectiveRevision) {
        this.effectiveRevision = effectiveRevision;
    }

    public TieringReasonCode getReasonCode() {
        return reasonCode;
    }

    public void setReasonCode(TieringReasonCode reasonCode) {
        this.reasonCode = reasonCode;
    }

    public TieringTemperature getTemperatureState() {
        return temperatureState;
    }

    public void setTemperatureState(TieringTemperature temperatureState) {
        this.temperatureState = temperatureState;
    }

    public long getLastMigrationTimeMs() {
        return lastMigrationTimeMs;
    }

    public void setLastMigrationTimeMs(long lastMigrationTimeMs) {
        this.lastMigrationTimeMs = lastMigrationTimeMs;
    }

    public long getLastTargetChangeTimeMs() {
        return lastTargetChangeTimeMs;
    }

    public void setLastTargetChangeTimeMs(long lastTargetChangeTimeMs) {
        this.lastTargetChangeTimeMs = lastTargetChangeTimeMs;
    }

    public String getFrozenReason() {
        return frozenReason;
    }

    public void setFrozenReason(String frozenReason) {
        this.frozenReason = frozenReason;
    }

    public boolean isManualOverride() {
        return manualOverride;
    }

    public void setManualOverride(boolean manualOverride) {
        this.manualOverride = manualOverride;
    }

    public long getVersion() {
        return version;
    }

    public void setVersion(long version) {
        this.version = version;
    }

    @Override
    public void write(DataOutput out) throws IOException {
        Text.writeString(out, GsonUtils.GSON.toJson(this));
    }

    public static TabletTierState read(DataInput in) throws IOException {
        return GsonUtils.GSON.fromJson(Text.readString(in), TabletTierState.class);
    }
}
