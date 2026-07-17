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

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

#include "olap/rowset/segment_v2/geo_index/hasi_tree.h"

namespace doris::segment_v2 {

// GEO index property keys. lng_column/lat_column are filled by the FE at CREATE TABLE
// validation time from the __s2 generated column expression st_s2_cellid(lng, lat)
// (GeoIndexUtil.java); the BE matches pushed-down geo predicates against them instead
// of trusting column naming conventions.
inline constexpr const char* kGeoIndexPropLngColumn = "lng_column";
inline constexpr const char* kGeoIndexPropLatColumn = "lat_column";
inline constexpr const char* kGeoIndexPropLeafRows = "leaf_rows";
inline constexpr const char* kGeoIndexPropMeasures = "measures";

// The kNN pushdown disables itself above this per-segment leaf count (the upfront
// leaf-ranking pass is O(leaves); segment_iterator's gate). The compaction splice
// arming check must not produce output segments beyond it (HASI_POC.md §12.2).
inline constexpr uint32_t kGeoKnnMaxLeaves = 65536;

// Comma-separated measure column names from the index properties (v2b).
inline std::vector<std::string> geo_index_measures(
        const std::map<std::string, std::string>& properties) {
    std::vector<std::string> out;
    auto it = properties.find(kGeoIndexPropMeasures);
    if (it == properties.end()) {
        return out;
    }
    size_t pos = 0;
    const std::string& s = it->second;
    while (pos <= s.size()) {
        size_t comma = s.find(',', pos);
        if (comma == std::string::npos) {
            comma = s.size();
        }
        std::string name = s.substr(pos, comma - pos);
        // trim spaces
        size_t b = name.find_first_not_of(" \t");
        size_t e = name.find_last_not_of(" \t");
        if (b != std::string::npos) {
            out.push_back(name.substr(b, e - b + 1));
        }
        pos = comma + 1;
    }
    return out;
}

inline uint32_t geo_index_leaf_rows(const std::map<std::string, std::string>& properties) {
    auto it = properties.find(kGeoIndexPropLeafRows);
    if (it == properties.end()) {
        return HasiTreeBuilder::kDefaultLeafRows;
    }
    // FE validated the value; parse defensively anyway and fall back to the default.
    errno = 0;
    char* end = nullptr;
    long v = std::strtol(it->second.c_str(), &end, 10);
    if (errno != 0 || end == it->second.c_str() || *end != '\0') {
        return HasiTreeBuilder::kDefaultLeafRows;
    }
    return static_cast<uint32_t>(
            std::clamp<long>(v, HasiTreeBuilder::kMinLeafRows, HasiTreeBuilder::kMaxLeafRows));
}

inline std::string geo_index_property(const std::map<std::string, std::string>& properties,
                                      const char* key) {
    auto it = properties.find(key);
    return it == properties.end() ? std::string() : it->second;
}

} // namespace doris::segment_v2
