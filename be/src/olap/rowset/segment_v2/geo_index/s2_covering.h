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
#include <vector>

class S2Region;

namespace doris::segment_v2 {

// A closed interval [lo, hi] of S2 *leaf* cell ids (Hilbert-order contiguous).
// All ranges produced here are normalized to the leaf keyspace via
// S2CellId::range_min()/range_max(), so they are directly comparable with the
// leaf ids stored in the __s2 column / geo index.
//
// The interval is closed on purpose: the last cell of face 5 has
// range_max().id() == 0xBFFFFFFFFFFFFFFF and the S2 headers warn that
// range_max().next() must not be used as an exclusive limit (uint64 wrap on
// the last face). Consumers must compare with `<= hi`.
struct CellRange {
    uint64_t lo;
    uint64_t hi;
};

// Domain transform between the raw uint64 cell-id keyspace (index internal) and
// the signed BIGINT __s2 column (see GeoPoint::ComputeS2CellKey): flipping the
// sign bit keeps int64 order identical to uint64 Hilbert order across all 6 faces.
inline int64_t s2_key_from_cell(uint64_t cell_id) {
    return static_cast<int64_t>(cell_id ^ (uint64_t(1) << 63));
}
inline uint64_t s2_cell_from_key(int64_t cell_key) {
    return static_cast<uint64_t>(cell_key) ^ (uint64_t(1) << 63);
}

// True if `leaf_id` falls into one of the sorted, disjoint `ranges`.
bool cell_ranges_contain(const std::vector<CellRange>& ranges, uint64_t leaf_id);

// Adaptive multi-resolution covering of a query region:
//   covering C = S2RegionCoverer::GetCovering  (C ⊇ region: outside C is a safe reject)
//   interior I = GetInteriorCovering           (I ⊆ region: inside I is a safe accept)
// Both outputs are normalized to the leaf keyspace, sorted, and adjacent ranges merged.
// Note: C and I are two independent approximations (I may be empty, and I's cells are
// not necessarily descendants of C's cells); the three-state classification of tree
// nodes / rows only relies on the C ⊇ region ⊇ I contracts, never on cell alignment.
class S2Covering {
public:
    S2Covering(int max_level, int max_cells) : _max_level(max_level), _max_cells(max_cells) {}

    void cover(const S2Region& region, std::vector<CellRange>* covering,
               std::vector<CellRange>* interior) const;

private:
    int _max_level;
    int _max_cells;
};

} // namespace doris::segment_v2
