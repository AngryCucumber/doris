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

#include "olap/tablet_heat_collector.h"

#include <algorithm>

#include "common/config.h"

namespace doris {

TabletHeatWindow::TabletHeatWindow(int num_buckets, int bucket_width_sec)
        : _num_buckets(num_buckets), _bucket_width_sec(bucket_width_sec), _cells(num_buckets) {}

TabletHeatWindow::Cell& TabletHeatWindow::touch(int64_t now_sec) {
    int64_t epoch = now_sec / _bucket_width_sec;
    int idx = static_cast<int>(epoch % _num_buckets);
    Cell& cell = _cells[idx];
    if (cell.epoch != epoch) {
        cell = Cell();
        cell.epoch = epoch;
    }
    return cell;
}

void TabletHeatWindow::add_read(int64_t now_sec, int64_t count) {
    touch(now_sec).read += count;
}
void TabletHeatWindow::add_point_lookup(int64_t now_sec, int64_t count) {
    touch(now_sec).point_lookup += count;
}
void TabletHeatWindow::add_range_scan(int64_t now_sec, int64_t count) {
    touch(now_sec).range_scan += count;
}
void TabletHeatWindow::add_full_scan(int64_t now_sec, int64_t count) {
    touch(now_sec).full_scan += count;
}
void TabletHeatWindow::add_scan_bytes(int64_t now_sec, int64_t bytes) {
    touch(now_sec).scan_bytes += bytes;
}
void TabletHeatWindow::add_scan_rows(int64_t now_sec, int64_t rows) {
    touch(now_sec).scan_rows += rows;
}

int64_t TabletHeatWindow::sum(int64_t now_sec, int64_t Cell::*field) const {
    int64_t cur_epoch = now_sec / _bucket_width_sec;
    int64_t oldest = cur_epoch - _num_buckets + 1;
    int64_t total = 0;
    for (const Cell& cell : _cells) {
        if (cell.epoch >= oldest && cell.epoch <= cur_epoch) {
            total += cell.*field;
        }
    }
    return total;
}

int64_t TabletHeatWindow::read_sum(int64_t now_sec) const {
    return sum(now_sec, &Cell::read);
}
int64_t TabletHeatWindow::point_lookup_sum(int64_t now_sec) const {
    return sum(now_sec, &Cell::point_lookup);
}
int64_t TabletHeatWindow::range_scan_sum(int64_t now_sec) const {
    return sum(now_sec, &Cell::range_scan);
}
int64_t TabletHeatWindow::full_scan_sum(int64_t now_sec) const {
    return sum(now_sec, &Cell::full_scan);
}
int64_t TabletHeatWindow::scan_bytes_sum(int64_t now_sec) const {
    return sum(now_sec, &Cell::scan_bytes);
}
int64_t TabletHeatWindow::scan_rows_sum(int64_t now_sec) const {
    return sum(now_sec, &Cell::scan_rows);
}

TabletHeatBuckets::TabletHeatBuckets(int64_t tablet_id, int64_t table_id, int64_t partition_id,
                                     int64_t replica_id)
        : _tablet_id(tablet_id),
          _table_id(table_id),
          _partition_id(partition_id),
          _replica_id(replica_id),
          _w5m(60, 5),
          _w1h(60, 60),
          _w1d(24, 3600) {}

void TabletHeatBuckets::record(int64_t now_sec, TabletAccessType type, int64_t scan_bytes,
                               int64_t scan_rows) {
    _last_access_time_ms = now_sec * 1000;

    // Every read access bumps the read counters (frequency factor).
    _w5m.add_read(now_sec, 1);
    _w1h.add_read(now_sec, 1);
    _w1d.add_read(now_sec, 1);

    switch (type) {
    case TabletAccessType::POINT_LOOKUP:
        _w5m.add_point_lookup(now_sec, 1);
        _w1h.add_point_lookup(now_sec, 1);
        break;
    case TabletAccessType::RANGE_SCAN:
        _w1h.add_range_scan(now_sec, 1);
        break;
    case TabletAccessType::FULL_SCAN:
        _w1h.add_full_scan(now_sec, 1);
        break;
    default:
        break;
    }

    if (scan_bytes > 0) {
        _w1h.add_scan_bytes(now_sec, scan_bytes);
    }
    if (scan_rows > 0) {
        _w1h.add_scan_rows(now_sec, scan_rows);
    }
}

void TabletHeatBuckets::set_last_write_time_ms(int64_t write_ms) {
    // Keep the newest write time (do not regress on out-of-order events).
    _last_write_time_ms = std::max(_last_write_time_ms, write_ms);
}

TabletHeatSnapshot TabletHeatBuckets::snapshot(int64_t now_sec) const {
    TabletHeatSnapshot s;
    s.tablet_id = _tablet_id;
    s.table_id = _table_id;
    s.partition_id = _partition_id;
    s.replica_id = _replica_id;
    s.read_count_5m = _w5m.read_sum(now_sec);
    s.read_count_1h = _w1h.read_sum(now_sec);
    s.read_count_1d = _w1d.read_sum(now_sec);
    s.point_lookup_count_5m = _w5m.point_lookup_sum(now_sec);
    s.point_lookup_count_1h = _w1h.point_lookup_sum(now_sec);
    s.range_scan_count_1h = _w1h.range_scan_sum(now_sec);
    s.full_scan_count_1h = _w1h.full_scan_sum(now_sec);
    s.scan_bytes_1h = _w1h.scan_bytes_sum(now_sec);
    s.scan_rows_1h = _w1h.scan_rows_sum(now_sec);
    s.last_access_time_ms = _last_access_time_ms;
    s.last_write_time_ms = _last_write_time_ms;
    return s;
}

TabletHeatCollector::TabletHeatCollector(int num_shards) {
    if (num_shards < 1) {
        num_shards = 1;
    }
    _shards.reserve(num_shards);
    for (int i = 0; i < num_shards; ++i) {
        _shards.emplace_back(std::make_unique<Shard>());
    }
}

TabletHeatCollector::Shard& TabletHeatCollector::shard_of(int64_t tablet_id) {
    size_t h = static_cast<size_t>(tablet_id);
    h ^= h >> 33;
    return *_shards[h % _shards.size()];
}

void TabletHeatCollector::record_access(int64_t tablet_id, int64_t table_id, int64_t partition_id,
                                        int64_t replica_id, TabletAccessType type,
                                        int64_t scan_bytes, int64_t scan_rows) {
    if (!config::enable_tablet_heat_report) {
        return;
    }
    if (type == TabletAccessType::COMPACTION_READ && !config::tablet_heat_include_compaction_read) {
        return;
    }
    int64_t now_sec = time(nullptr);
    Shard& shard = shard_of(tablet_id);
    std::lock_guard<std::mutex> l(shard.mu);
    auto it = shard.map.find(tablet_id);
    if (it == shard.map.end()) {
        it = shard.map
                     .emplace(tablet_id, std::make_unique<TabletHeatBuckets>(
                                                 tablet_id, table_id, partition_id, replica_id))
                     .first;
    }
    it->second->record(now_sec, type, scan_bytes, scan_rows);
}

void TabletHeatCollector::update_write_time(int64_t tablet_id, int64_t write_time_ms) {
    if (!config::enable_tablet_heat_report) {
        return;
    }
    Shard& shard = shard_of(tablet_id);
    std::lock_guard<std::mutex> l(shard.mu);
    auto it = shard.map.find(tablet_id);
    if (it != shard.map.end()) {
        it->second->set_last_write_time_ms(write_time_ms);
    }
}

void TabletHeatCollector::snapshot(std::vector<TabletHeatSnapshot>* out) {
    int64_t now_sec = time(nullptr);
    int64_t idle_expire_ms = static_cast<int64_t>(config::tablet_heat_idle_expire_sec) * 1000;
    int64_t now_ms = now_sec * 1000;
    for (auto& shard_ptr : _shards) {
        Shard& shard = *shard_ptr;
        std::lock_guard<std::mutex> l(shard.mu);
        for (auto it = shard.map.begin(); it != shard.map.end();) {
            int64_t last_access = it->second->last_access_time_ms();
            if (idle_expire_ms > 0 && last_access > 0 && now_ms - last_access > idle_expire_ms) {
                it = shard.map.erase(it);
                continue;
            }
            out->push_back(it->second->snapshot(now_sec));
            ++it;
        }
    }
}

size_t TabletHeatCollector::tablet_count() const {
    size_t total = 0;
    for (const auto& shard_ptr : _shards) {
        Shard& shard = *shard_ptr;
        std::lock_guard<std::mutex> l(shard.mu);
        total += shard.map.size();
    }
    return total;
}

} // namespace doris
