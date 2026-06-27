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

#include "olap/tablet_heat_reporter.h"

#include <gen_cpp/MasterService_types.h>

#include <atomic>
#include <ctime>
#include <vector>

#include "agent/utils.h"
#include "common/config.h"
#include "common/logging.h"
#include "olap/storage_engine.h"
#include "olap/tablet_heat_collector.h"
#include "runtime/cluster_info.h"
#include "service/backend_options.h"

namespace doris {

void report_tablet_heat_callback(StorageEngine& engine, const ClusterInfo* cluster_info) {
    if (!config::enable_tablet_heat_report) {
        return;
    }
    TabletHeatCollector* collector = engine.tablet_heat_collector();
    if (collector == nullptr) {
        return;
    }

    // Reporter epoch = process/reporter start time (bumps on restart); seq is
    // monotonic within an epoch. FE uses (epoch, seq) to dedup / drop stale.
    static const int64_t s_report_epoch = static_cast<int64_t>(::time(nullptr));
    static std::atomic<int64_t> s_report_seq {0};

    std::vector<TabletHeatSnapshot> snapshots;
    collector->snapshot(&snapshots);

    int max_items = config::tablet_heat_max_report_items;
    if (max_items > 0 && static_cast<int>(snapshots.size()) > max_items) {
        snapshots.resize(max_items);
    }

    TReportRequest request;
    request.__set_backend(BackendOptions::get_local_backend());
    // BE actively sends a periodic full snapshot (absolute values); FE replaces
    // the (BE,tablet) snapshot and sums across BEs.
    request.__set_tablet_heat_report_full(true);
    request.__set_tablet_heat_report_epoch(s_report_epoch);
    request.__set_tablet_heat_report_seq(s_report_seq.fetch_add(1));

    std::vector<TTabletHeatStat> stats;
    stats.reserve(snapshots.size());
    for (const TabletHeatSnapshot& s : snapshots) {
        TTabletHeatStat stat;
        stat.__set_tablet_id(s.tablet_id);
        stat.__set_replica_id(s.replica_id);
        stat.__set_table_id(s.table_id);
        stat.__set_partition_id(s.partition_id);
        stat.__set_read_count_5m(s.read_count_5m);
        stat.__set_read_count_1h(s.read_count_1h);
        stat.__set_read_count_1d(s.read_count_1d);
        stat.__set_point_lookup_count_5m(s.point_lookup_count_5m);
        stat.__set_point_lookup_count_1h(s.point_lookup_count_1h);
        stat.__set_range_scan_count_1h(s.range_scan_count_1h);
        stat.__set_full_scan_count_1h(s.full_scan_count_1h);
        stat.__set_scan_bytes_1h(s.scan_bytes_1h);
        stat.__set_scan_rows_1h(s.scan_rows_1h);
        stat.__set_last_access_time_ms(s.last_access_time_ms);
        stat.__set_last_write_time_ms(s.last_write_time_ms);
        stats.push_back(std::move(stat));
    }
    request.__set_tablet_heat_stats(stats);

    TMasterResult result;
    Status status = MasterServerClient::instance()->report(request, &result);
    if (!status.ok()) {
        // Heat report failure must never affect queries or migration.
        LOG_WARNING("failed to report tablet heat")
                .tag("host", cluster_info->master_fe_addr.hostname)
                .tag("port", cluster_info->master_fe_addr.port)
                .tag("items", stats.size())
                .error(status);
    } else if (result.status.status_code != TStatusCode::OK) {
        LOG_WARNING("failed to report tablet heat")
                .tag("host", cluster_info->master_fe_addr.hostname)
                .tag("port", cluster_info->master_fe_addr.port)
                .error(result.status);
    }
}

} // namespace doris
