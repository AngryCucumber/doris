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

#include "common/status.h"
#include "olap/rowset/segment_v2/geo_index/s2_covering.h"
#include "vec/exprs/vexpr.h"
#include "vec/exprs/vexpr_fwd.h"

namespace doris::segment_v2 {

// Recognition + covering computation for the v1 geo retrieval pushdown
// (HASI_POC.md §4.5). The circle predicate arrives at the BE as an ordinary
// pushed-down conjunct (same transport as ANN range search — no dedicated thrift);
// segment_iterator pattern-matches it here and narrows _row_bitmap with the index.
// The original predicate always stays in the plan as the exact residual filter, so
// the index result only needs to be a superset of the true rows (contract C1); the
// "skip the exact recheck for interior rows" optimization is v1.5 work.

// Parameters of a recognized `st_distance_sphere(lng_slot, lat_slot, lng0, lat0) < r`
// (or <=, or the mirrored `r > st_distance_sphere(...)`) conjunct.
struct GeoRangeSearchRuntime {
    bool valid = false;
    bool is_strict = true; // true: < ; false: <=  (irrelevant to the covering superset)
    double lng0 = 0;
    double lat0 = 0;
    double radius_m = 0;
    // VSlotRef::column_id() of the predicate's lng/lat args, i.e. positions in the
    // segment read schema; map to ColumnId via Schema::column_ids().
    int lng_idx_in_block = -1;
    int lat_idx_in_block = -1;
    // The st_distance_sphere call node: the key _calculate_expr_in_remaining_conjunct_root
    // registered the lng/lat slots under in _common_expr_index_exec_status, needed to mark
    // the expression index-answered after v1.5 exact filtering.
    const vectorized::VExpr* distance_expr = nullptr;
};

// Absolute conservative margin added to the covering cap / subtracted from the
// interior cap. Same value the v0 kernel and FE rewrite use: well above the ~10 cm
// haversine error floor at earth scale.
//
// The margin also carries the no-false-reject proof for leaf quantization: a row is
// rejected only when its *owning* leaf cell is not under any covering cell. For a
// point p with true distance <= r, the CENTER of leaf(p) is within ~2 cm of p, so it
// lies inside the (r + margin) cap and therefore inside some closed covering cell x.
// Leaf centers sit on half-grid (s,t) offsets while every cell boundary lies on the
// integer grid, so the center is in x's INTERIOR, which forces leaf(p) ⊆ x — i.e.
// leaf(p) is inside the covering ranges. Without the margin, a point exactly on a
// cell boundary could be owned by a leaf outside the covering.
inline constexpr double kGeoIndexMarginMeters = 1.0;
inline constexpr double kGeoEarthRadiusMeters = 6371010.0;
// S2RegionCoverer budget per query; ~2x region area overshoot at 8 cells, tightens
// as it grows (design doc §4.1 recommends 64-256 for v1).
inline constexpr int kGeoIndexCoveringMaxCells = 128;
// Cost gate: give up when the covering spans more than this fraction of the leaf
// keyspace -- the index cannot reject much and the walk is pure overhead.
inline constexpr double kGeoIndexMaxCoveringFraction = 0.5;

// Matches the conjunct tree rooted at `root`. Only inside-circle forms are
// recognized (outside-circle complements are not an envelope). Casts around the
// slots/literals are stripped; nullable literals are rejected.
bool extract_geo_range_search(const vectorized::VExpr* root, GeoRangeSearchRuntime* out);

// Builds covering C (superset, cap expanded by the margin) and interior I (subset,
// cap shrunk by the margin) for the recognized circle, normalized to the leaf
// keyspace. Returns false when the predicate cannot select anything (invalid
// center) -- the caller must then leave the bitmap untouched and let the residual
// predicate decide.
bool compute_circle_covering(const GeoRangeSearchRuntime& runtime,
                             std::vector<CellRange>* covering, std::vector<CellRange>* interior);

// Fraction of the leaf keyspace the covering spans, for the cost gate.
double covering_keyspace_fraction(const std::vector<CellRange>& covering);

// Upper bound on the distance between a point and the center of its own level-30
// leaf cell (max leaf diagonal is < 2 cm; 5 cm is comfortably conservative).
inline constexpr double kGeoCellQuantizationMeters = 0.05;

// v1.5 exact filtering: classify margin rows (cell ∈ C∖I) by their cell-derived
// position. Rows whose cell center is more than margin+quantization inside the
// circle are definite hits (added to `hit`); more than that outside are definite
// misses (dropped); the remaining ambiguity band -- typically empty, it is a
// ~2 m annulus around the circle boundary -- goes to `need_exact` for a
// true-coordinate recheck with the same scalar kernel the full scan runs.
void classify_margin_cells(const GeoRangeSearchRuntime& runtime,
                           const std::vector<std::pair<uint32_t, uint64_t>>& margin,
                           roaring::Roaring* hit, std::vector<uint32_t>* need_exact);

} // namespace doris::segment_v2
