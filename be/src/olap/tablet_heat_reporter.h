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

namespace doris {

class StorageEngine;
class ClusterInfo;

// Tablet tiering (B route): heat report callback driven by a dedicated
// ReportWorker registered only in AgentServer::start_workers (local engine, so
// naturally cloud-gated). Sends a heat-only TReportRequest carrying the current
// absolute-value snapshot at `tablet_heat_report_interval_sec`. See design v2 §8.1.
void report_tablet_heat_callback(StorageEngine& engine, const ClusterInfo* cluster_info);

} // namespace doris
