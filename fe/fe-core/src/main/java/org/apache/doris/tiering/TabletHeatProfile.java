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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * FE in-memory heat profile for one tablet, key = tablet id. Not persisted to
 * edit log (only optional low-frequency checkpoint). Heat is reported in
 * absolute-value mode: each BE reports its current 5m/1h/1d absolute counts; FE
 * keeps the latest per-BE snapshot (deduped by epoch/seq) and sums across BEs.
 * See design v2 §6.2 / §7.1.
 */
public class TabletHeatProfile {
    /** Latest absolute-value snapshot from a single BE. */
    private static class BeHeat {
        long epoch;
        long seq;
        long readCount5m;
        long readCount1h;
        long readCount1d;
        long pointLookupCount5m;
        long pointLookupCount1h;
        long rangeScanCount1h;
        long fullScanCount1h;
        long scanBytes1h;
        long scanRows1h;
        long lastAccessTimeMs;
        long lastWriteTimeMs;
    }

    private final long tabletId;
    private volatile long tableId;
    private volatile long partitionId;
    // key = backendId
    private final Map<Long, BeHeat> perBe = new ConcurrentHashMap<>();

    private volatile double currentScore;
    private volatile TieringTemperature temperatureState = TieringTemperature.WARM;
    private volatile long lastEvalTimeMs;
    private volatile long lastReportTimeMs;

    public TabletHeatProfile(long tabletId, long tableId, long partitionId) {
        this.tabletId = tabletId;
        this.tableId = tableId;
        this.partitionId = partitionId;
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

    public long getLastReportTimeMs() {
        return lastReportTimeMs;
    }

    public double getCurrentScore() {
        return currentScore;
    }

    public void setCurrentScore(double currentScore) {
        this.currentScore = currentScore;
    }

    public TieringTemperature getTemperatureState() {
        return temperatureState;
    }

    public void setTemperatureState(TieringTemperature temperatureState) {
        this.temperatureState = temperatureState;
    }

    public long getLastEvalTimeMs() {
        return lastEvalTimeMs;
    }

    public void setLastEvalTimeMs(long lastEvalTimeMs) {
        this.lastEvalTimeMs = lastEvalTimeMs;
    }

    /**
     * Merge one BE's absolute-value snapshot. Stale snapshots (older epoch, or
     * same epoch with seq not greater) are dropped. Returns true if applied.
     */
    public synchronized boolean mergeBe(long backendId, long epoch, long seq, long readCount5m,
            long readCount1h, long readCount1d, long pointLookupCount5m, long pointLookupCount1h,
            long rangeScanCount1h, long fullScanCount1h, long scanBytes1h, long scanRows1h,
            long lastAccessTimeMs, long lastWriteTimeMs, long tableId, long partitionId,
            long nowMs) {
        BeHeat prev = perBe.get(backendId);
        if (prev != null) {
            if (epoch < prev.epoch || (epoch == prev.epoch && seq <= prev.seq)) {
                return false; // stale or duplicate
            }
        }
        BeHeat be = new BeHeat();
        be.epoch = epoch;
        be.seq = seq;
        be.readCount5m = readCount5m;
        be.readCount1h = readCount1h;
        be.readCount1d = readCount1d;
        be.pointLookupCount5m = pointLookupCount5m;
        be.pointLookupCount1h = pointLookupCount1h;
        be.rangeScanCount1h = rangeScanCount1h;
        be.fullScanCount1h = fullScanCount1h;
        be.scanBytes1h = scanBytes1h;
        be.scanRows1h = scanRows1h;
        be.lastAccessTimeMs = lastAccessTimeMs;
        be.lastWriteTimeMs = lastWriteTimeMs;
        perBe.put(backendId, be);
        if (tableId > 0) {
            this.tableId = tableId;
        }
        if (partitionId > 0) {
            this.partitionId = partitionId;
        }
        this.lastReportTimeMs = nowMs;
        return true;
    }

    // Aggregated (summed across BEs) absolute values.
    public long getReadCount5m() {
        long sum = 0;
        for (BeHeat be : perBe.values()) {
            sum += be.readCount5m;
        }
        return sum;
    }

    public long getReadCount1h() {
        long sum = 0;
        for (BeHeat be : perBe.values()) {
            sum += be.readCount1h;
        }
        return sum;
    }

    public long getReadCount1d() {
        long sum = 0;
        for (BeHeat be : perBe.values()) {
            sum += be.readCount1d;
        }
        return sum;
    }

    public long getPointLookupCount5m() {
        long sum = 0;
        for (BeHeat be : perBe.values()) {
            sum += be.pointLookupCount5m;
        }
        return sum;
    }

    public long getPointLookupCount1h() {
        long sum = 0;
        for (BeHeat be : perBe.values()) {
            sum += be.pointLookupCount1h;
        }
        return sum;
    }

    public long getFullScanCount1h() {
        long sum = 0;
        for (BeHeat be : perBe.values()) {
            sum += be.fullScanCount1h;
        }
        return sum;
    }

    public long getScanBytes1h() {
        long sum = 0;
        for (BeHeat be : perBe.values()) {
            sum += be.scanBytes1h;
        }
        return sum;
    }

    public long getLastAccessTimeMs() {
        long max = 0;
        for (BeHeat be : perBe.values()) {
            max = Math.max(max, be.lastAccessTimeMs);
        }
        return max;
    }

    public long getLastWriteTimeMs() {
        long max = 0;
        for (BeHeat be : perBe.values()) {
            max = Math.max(max, be.lastWriteTimeMs);
        }
        return max;
    }
}
