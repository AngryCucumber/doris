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

#include "olap/rowset/segment_v2/geo_index/s2_covering.h"

#include <s2/s2cell_id.h>
#include <s2/s2cell_union.h>
#include <s2/s2region.h>
#include <s2/s2region_coverer.h>

#include <algorithm>

namespace doris::segment_v2 {

namespace {

// An S2CellUnion is normalized: sorted in Hilbert order, non-overlapping. Converting
// each cell to its leaf-id interval therefore yields sorted disjoint ranges. Leaf cell
// ids are odd and spaced 2 apart (the level-30 marker is the trailing 1 bit), so two
// cells are exactly adjacent iff prev.range_max + 2 == next.range_min. No overflow
// guard needed: the largest valid leaf id is 0xBFFFFFFFFFFFFFFF (end of face 5).
void to_ranges(const S2CellUnion& cells, std::vector<CellRange>* out) {
    out->clear();
    out->reserve(cells.num_cells());
    for (S2CellId cell : cells) {
        uint64_t lo = cell.range_min().id();
        uint64_t hi = cell.range_max().id();
        if (!out->empty() && out->back().hi + 2 == lo) {
            out->back().hi = hi;
        } else {
            out->push_back({lo, hi});
        }
    }
}

} // namespace

bool cell_ranges_contain(const std::vector<CellRange>& ranges, uint64_t leaf_id) {
    auto it = std::lower_bound(ranges.begin(), ranges.end(), leaf_id,
                               [](const CellRange& r, uint64_t id) { return r.hi < id; });
    return it != ranges.end() && it->lo <= leaf_id;
}

void S2Covering::cover(const S2Region& region, std::vector<CellRange>* covering,
                       std::vector<CellRange>* interior) const {
    S2RegionCoverer::Options options;
    options.set_max_level(_max_level);
    options.set_max_cells(_max_cells);
    S2RegionCoverer coverer(options);
    if (covering != nullptr) {
        to_ranges(coverer.GetCovering(region), covering);
    }
    if (interior != nullptr) {
        to_ranges(coverer.GetInteriorCovering(region), interior);
    }
}

} // namespace doris::segment_v2
