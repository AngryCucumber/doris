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

#include <s2/s1angle.h>
#include <s2/s1chord_angle.h>
#include <s2/s2cell.h>
#include <s2/s2cell_id.h>
#include <s2/s2cell_union.h>
#include <s2/s2latlng.h>
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

namespace {

constexpr double kClassifierEarthRadiusMeters = 6371010.0;

struct MarginClassifier {
    const std::vector<std::pair<uint32_t, uint64_t>>& margin;
    S2Point center;
    // Group verdicts bound the TRUE point (it lies inside its ancestor cell), so the
    // only slack needed is the scalar-formula margin. The per-row fallback works on
    // the cell CENTER, so it additionally absorbs the leaf-quantization offset.
    S1ChordAngle group_accept;
    S1ChordAngle group_reject;
    double row_accept_m = 0;
    double row_reject_m = 0;
    roaring::Roaring* hit;
    std::vector<uint32_t>* need_exact;

    void classify_rows(size_t begin, size_t end) {
        for (size_t i = begin; i < end; ++i) {
            const S2Point p = S2CellId(margin[i].second).ToPoint();
            const double dist_m = S1Angle(p, center).radians() * kClassifierEarthRadiusMeters;
            if (dist_m < row_accept_m) {
                hit->add(margin[i].first);
            } else if (dist_m > row_reject_m) {
                // definite miss; conservative under both < and <= forms
            } else {
                need_exact->push_back(margin[i].first);
            }
        }
    }

    // Classify margin[begin, end) whose cells all share the level-`level` ancestor of
    // margin[begin]: one min/max cell-to-center distance decides the whole run; only
    // runs straddling the r±margin annulus split into finer sub-runs, so the per-row
    // work shrinks with the annulus instead of the covering band (HASI's aggregation
    // principle applied to its own margin resolution).
    void classify_run(size_t begin, size_t end, int level) {
        const S2Cell ancestor(S2CellId(margin[begin].second).parent(level));
        const S1ChordAngle min_dist = ancestor.GetDistance(center);
        if (min_dist > group_reject) {
            return; // whole run definitely outside
        }
        const S1ChordAngle max_dist = ancestor.GetMaxDistance(center);
        if (max_dist < group_accept) {
            for (size_t i = begin; i < end; ++i) {
                hit->add(margin[i].first);
            }
            return;
        }
        constexpr int kLevelStep = 4;
        constexpr size_t kMinRunForGrouping = 8;
        if (level + kLevelStep > S2CellId::kMaxLevel - 4 || end - begin < kMinRunForGrouping) {
            classify_rows(begin, end);
            return;
        }
        const int child_level = level + kLevelStep;
        size_t run_begin = begin;
        S2CellId run_parent = S2CellId(margin[begin].second).parent(child_level);
        for (size_t i = begin + 1; i < end; ++i) {
            S2CellId parent = S2CellId(margin[i].second).parent(child_level);
            if (parent != run_parent) {
                classify_run(run_begin, i, child_level);
                run_begin = i;
                run_parent = parent;
            }
        }
        classify_run(run_begin, end, child_level);
    }
};

} // namespace

void classify_margin_cells(double lng0, double lat0, double radius_m, double formula_margin_m,
                           double quantization_m,
                           const std::vector<std::pair<uint32_t, uint64_t>>& margin,
                           roaring::Roaring* hit, std::vector<uint32_t>* need_exact) {
    if (margin.empty()) {
        return;
    }
    MarginClassifier classifier {
            .margin = margin,
            .center = S2LatLng::FromDegrees(lat0, lng0).ToPoint(),
            .group_accept = S1ChordAngle::Radians(std::max(0.0, radius_m - formula_margin_m) /
                                                  kClassifierEarthRadiusMeters),
            .group_reject = S1ChordAngle::Radians((radius_m + formula_margin_m) /
                                                  kClassifierEarthRadiusMeters),
            .row_accept_m = radius_m - formula_margin_m - quantization_m,
            .row_reject_m = radius_m + formula_margin_m + quantization_m,
            .hit = hit,
            .need_exact = need_exact,
    };
    // Margin rows arrive leaf by leaf; on clustered tables cells are locally sorted,
    // so ancestor runs are long. Split the whole span at a coarse level first.
    constexpr int kTopLevel = 8;
    size_t run_begin = 0;
    S2CellId run_parent = S2CellId(margin[0].second).parent(kTopLevel);
    for (size_t i = 1; i < margin.size(); ++i) {
        S2CellId parent = S2CellId(margin[i].second).parent(kTopLevel);
        if (parent != run_parent) {
            classifier.classify_run(run_begin, i, kTopLevel);
            run_begin = i;
            run_parent = parent;
        }
    }
    classifier.classify_run(run_begin, margin.size(), kTopLevel);
}

} // namespace doris::segment_v2
