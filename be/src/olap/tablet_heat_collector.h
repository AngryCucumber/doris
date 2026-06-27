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

#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace doris {

// Tablet-level same-node SSD/HDD tiering (B route): BE heat collector.
//
// Collects per-tablet access heat into sliding windows (5m / 1h / 1d) and
// produces an absolute-value snapshot for the reporter (design v2 §8.1). It is
// sharded by tablet id (like the cloud HotspotCounter) with a per-shard mutex;
// the hot path only does a shard lookup + a few integer adds. Bucketing is lazy:
// each window cell carries the time-bucket epoch it belongs to and is reset on
// first touch in a new epoch, so no background roll thread is needed.

enum class TabletAccessType {
    POINT_LOOKUP,
    RANGE_SCAN,
    FULL_SCAN,
    INDEX_SCAN,
    COMPACTION_READ,
    BACKGROUND_READ,
};

// Absolute-value snapshot for one tablet (design v2 §6.2 / §7.1).
struct TabletHeatSnapshot {
    int64_t tablet_id = 0;
    int64_t table_id = 0;
    int64_t partition_id = 0;
    int64_t replica_id = 0;
    int64_t read_count_5m = 0;
    int64_t read_count_1h = 0;
    int64_t read_count_1d = 0;
    int64_t point_lookup_count_5m = 0;
    int64_t point_lookup_count_1h = 0;
    int64_t range_scan_count_1h = 0;
    int64_t full_scan_count_1h = 0;
    int64_t scan_bytes_1h = 0;
    int64_t scan_rows_1h = 0;
    int64_t last_access_time_ms = 0;
    int64_t last_write_time_ms = 0;
};

// A single sliding window made of a ring of fixed-width time buckets.
class TabletHeatWindow {
public:
    TabletHeatWindow(int num_buckets, int bucket_width_sec);

    void add_read(int64_t now_sec, int64_t count);
    void add_point_lookup(int64_t now_sec, int64_t count);
    void add_range_scan(int64_t now_sec, int64_t count);
    void add_full_scan(int64_t now_sec, int64_t count);
    void add_scan_bytes(int64_t now_sec, int64_t bytes);
    void add_scan_rows(int64_t now_sec, int64_t rows);

    int64_t read_sum(int64_t now_sec) const;
    int64_t point_lookup_sum(int64_t now_sec) const;
    int64_t range_scan_sum(int64_t now_sec) const;
    int64_t full_scan_sum(int64_t now_sec) const;
    int64_t scan_bytes_sum(int64_t now_sec) const;
    int64_t scan_rows_sum(int64_t now_sec) const;

private:
    struct Cell {
        int64_t epoch = -1;
        int64_t read = 0;
        int64_t point_lookup = 0;
        int64_t range_scan = 0;
        int64_t full_scan = 0;
        int64_t scan_bytes = 0;
        int64_t scan_rows = 0;
    };

    Cell& touch(int64_t now_sec);
    int64_t sum(int64_t now_sec, int64_t Cell::*field) const;

    int _num_buckets;
    int _bucket_width_sec;
    std::vector<Cell> _cells;
};

// Per-tablet heat buckets across the 5m / 1h / 1d windows.
class TabletHeatBuckets {
public:
    TabletHeatBuckets(int64_t tablet_id, int64_t table_id, int64_t partition_id,
                      int64_t replica_id);

    void record(int64_t now_sec, TabletAccessType type, int64_t scan_bytes, int64_t scan_rows);
    void set_last_write_time_ms(int64_t write_ms);
    int64_t last_access_time_ms() const { return _last_access_time_ms; }

    TabletHeatSnapshot snapshot(int64_t now_sec) const;

private:
    int64_t _tablet_id;
    int64_t _table_id;
    int64_t _partition_id;
    int64_t _replica_id;
    int64_t _last_access_time_ms = 0;
    int64_t _last_write_time_ms = 0;

    TabletHeatWindow _w5m;
    TabletHeatWindow _w1h;
    TabletHeatWindow _w1d;
};

class TabletHeatCollector {
public:
    explicit TabletHeatCollector(int num_shards = 16);

    // Hot-path entry. Cheap when heat reporting is disabled.
    void record_access(int64_t tablet_id, int64_t table_id, int64_t partition_id,
                       int64_t replica_id, TabletAccessType type, int64_t scan_bytes = 0,
                       int64_t scan_rows = 0);

    // "rowset visible to query" freshness hook (design v2 §8.1 / T2.4).
    void update_write_time(int64_t tablet_id, int64_t write_time_ms);

    // Absolute-value snapshot of all live tablets; also evicts idle tablets that
    // have had no access for `tablet_heat_idle_expire_sec`.
    void snapshot(std::vector<TabletHeatSnapshot>* out);

    size_t tablet_count() const;

private:
    struct Shard {
        mutable std::mutex mu;
        std::unordered_map<int64_t, std::unique_ptr<TabletHeatBuckets>> map;
    };

    Shard& shard_of(int64_t tablet_id);

    std::vector<std::unique_ptr<Shard>> _shards;
};

} // namespace doris
