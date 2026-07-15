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

#include <gtest/gtest.h>
#include <s2/s1angle.h>
#include <s2/s1chord_angle.h>
#include <s2/s2cap.h>
#include <s2/s2cell.h>
#include <s2/s2cell_id.h>
#include <s2/s2latlng.h>
#include <s2/s2point.h>

#include <algorithm>
#include <cmath>
#include <limits>
#include <random>
#include <set>

#include "geo/geo_types.h"

namespace doris::segment_v2 {

namespace {

constexpr int kMaxLevel = 30;
constexpr int kMaxCells = 64;

// Structural invariants every range list must satisfy: sorted, disjoint, fully merged.
// Leaf ids are odd and spaced 2 apart, so "adjacent" (must-have-been-merged) means a
// gap of exactly 2; any survived gap must be strictly greater.
void check_normalized(const std::vector<CellRange>& ranges) {
    for (size_t i = 0; i < ranges.size(); ++i) {
        ASSERT_LE(ranges[i].lo, ranges[i].hi);
        if (i > 0) {
            ASSERT_GT(ranges[i].lo, ranges[i - 1].hi);
            ASSERT_GT(ranges[i].lo - ranges[i - 1].hi, uint64_t(2));
        }
    }
}

// Point at angular distance `theta` from `center` toward auxiliary direction `q`.
S2Point point_at_distance(const S2Point& center, const S2Point& q, S1Angle theta) {
    S2Point u = (q - center.DotProd(q) * center).Normalize();
    return (std::cos(theta.radians()) * center + std::sin(theta.radians()) * u).Normalize();
}

S2Point random_point(std::mt19937_64& rng) {
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    while (true) {
        S2Point p(dist(rng), dist(rng), dist(rng));
        if (p.Norm2() > 1e-6 && p.Norm2() <= 1.0) {
            return p.Normalize();
        }
    }
}

} // namespace

// C ⊇ region ⊇ I: a point inside I must be inside the cap, a point outside C must be
// outside the cap. Sampled with uniform random points plus points hugging the boundary.
TEST(S2CoveringTest, CapContracts) {
    std::mt19937_64 rng(20260714);
    S2Covering covering_builder(kMaxLevel, kMaxCells);

    std::uniform_real_distribution<double> radius_log(std::log(50.0), std::log(3000000.0));
    for (int iter = 0; iter < 50; ++iter) {
        S2Point center = random_point(rng);
        // radius from 50m to 3000km (in radians on the unit sphere, earth radius 6371010m)
        double radius_m = std::exp(radius_log(rng));
        S1Angle radius = S1Angle::Radians(radius_m / 6371010.0);
        S2Cap cap(center, radius);

        std::vector<CellRange> covering;
        std::vector<CellRange> interior;
        covering_builder.cover(cap, &covering, &interior);
        check_normalized(covering);
        check_normalized(interior);
        ASSERT_FALSE(covering.empty());

        // Every interior range must be contained in some covering range (I ⊆ C as point sets).
        for (const CellRange& r : interior) {
            ASSERT_TRUE(cell_ranges_contain(covering, r.lo));
            ASSERT_TRUE(cell_ranges_contain(covering, r.hi));
        }

        for (int i = 0; i < 200; ++i) {
            S2Point p;
            if (i % 2 == 0) {
                p = random_point(rng);
            } else {
                // hug the boundary: distance in [0.8r, 1.2r]
                std::uniform_real_distribution<double> f(0.8, 1.2);
                p = point_at_distance(center, random_point(rng), radius * f(rng));
            }
            uint64_t leaf = S2CellId(p).id();
            if (cell_ranges_contain(interior, leaf)) {
                ASSERT_TRUE(cap.Contains(p))
                        << "interior accepted a point outside the cap, iter=" << iter;
            }
            if (!cell_ranges_contain(covering, leaf)) {
                ASSERT_FALSE(cap.Contains(p))
                        << "covering rejected a point inside the cap, iter=" << iter;
            }
        }
    }
}

// The full cap covers all 6 faces; after normalization the covering must merge into the
// single range [face0.range_min, face5.range_max] — exercises the last-face upper bound
// (0xBFFFFFFFFFFFFFFF) that must never be computed via range_max().next().
TEST(S2CoveringTest, FullSphereMergesToOneRange) {
    S2Covering covering_builder(kMaxLevel, kMaxCells);
    std::vector<CellRange> covering;
    std::vector<CellRange> interior;
    covering_builder.cover(S2Cap::Full(), &covering, &interior);

    ASSERT_EQ(covering.size(), 1);
    EXPECT_EQ(covering[0].lo, S2CellId::FromFace(0).range_min().id());
    EXPECT_EQ(covering[0].hi, S2CellId::FromFace(5).range_max().id());
    EXPECT_EQ(covering[0].hi, uint64_t(0xBFFFFFFFFFFFFFFF));

    ASSERT_EQ(interior.size(), 1);
    EXPECT_EQ(interior[0].lo, covering[0].lo);
    EXPECT_EQ(interior[0].hi, covering[0].hi);
}

TEST(S2CoveringTest, EmptyCap) {
    S2Covering covering_builder(kMaxLevel, kMaxCells);
    std::vector<CellRange> covering;
    std::vector<CellRange> interior;
    covering_builder.cover(S2Cap::Empty(), &covering, &interior);
    EXPECT_TRUE(covering.empty());
    EXPECT_TRUE(interior.empty());
}

// A cap centered on a face boundary (equator, lon=45° is the edge between faces 0 and 1)
// produces covering cells on both faces; contracts must still hold across the face seam.
TEST(S2CoveringTest, FaceBoundaryCap) {
    std::mt19937_64 rng(42);
    S2Covering covering_builder(kMaxLevel, kMaxCells);
    S2Point center = S2LatLng::FromDegrees(0, 45).ToPoint();
    S1Angle radius = S1Angle::Radians(100000.0 / 6371010.0); // 100 km
    S2Cap cap(center, radius);

    std::vector<CellRange> covering;
    std::vector<CellRange> interior;
    covering_builder.cover(cap, &covering, &interior);
    check_normalized(covering);
    check_normalized(interior);
    ASSERT_FALSE(interior.empty());

    for (int i = 0; i < 500; ++i) {
        std::uniform_real_distribution<double> f(0.0, 1.5);
        S2Point p = point_at_distance(center, random_point(rng), radius * f(rng));
        uint64_t leaf = S2CellId(p).id();
        if (cell_ranges_contain(interior, leaf)) {
            ASSERT_TRUE(cap.Contains(p));
        }
        if (!cell_ranges_contain(covering, leaf)) {
            ASSERT_FALSE(cap.Contains(p));
        }
    }
}

// The BIGINT key transform must preserve order and roundtrip, and must agree with
// GeoPoint::ComputeS2CellKey (the st_s2_cellid implementation).
TEST(S2CoveringTest, SignedKeyTransform) {
    std::mt19937_64 rng(7);
    int64_t prev_key = std::numeric_limits<int64_t>::min();
    // Walk cells face by face in Hilbert order: keys must be strictly increasing.
    for (int face = 0; face < 6; ++face) {
        uint64_t id = S2CellId::FromFace(face).range_min().id();
        int64_t key = s2_key_from_cell(id);
        ASSERT_GT(key, prev_key) << "face " << face;
        ASSERT_EQ(s2_cell_from_key(key), id);
        prev_key = key;
    }

    for (int i = 0; i < 1000; ++i) {
        S2Point p = random_point(rng);
        S2LatLng ll(p);
        int64_t key_from_geo = 0;
        ASSERT_TRUE(GeoPoint::ComputeS2CellKey(ll.lng().degrees(), ll.lat().degrees(),
                                               &key_from_geo));
        EXPECT_EQ(key_from_geo, s2_key_from_cell(S2CellId(S2LatLng::FromDegrees(
                                                                  ll.lat().degrees(),
                                                                  ll.lng().degrees()))
                                                         .id()));
        EXPECT_EQ(s2_cell_from_key(key_from_geo),
                  S2CellId(S2LatLng::FromDegrees(ll.lat().degrees(), ll.lng().degrees())).id());
    }

    // Invalid coordinates -> NULL semantics.
    int64_t unused = 0;
    EXPECT_FALSE(GeoPoint::ComputeS2CellKey(0.0, 91.0, &unused));
    EXPECT_FALSE(GeoPoint::ComputeS2CellKey(181.0, 0.0, &unused));
}

// Hierarchical margin classification (v1.5): whatever grouping path decided a row,
// the verdict must be safe for ANY true point inside the row's leaf cell -- hits
// must satisfy leaf.GetMaxDistance < radius, drops leaf.GetDistance > radius, and
// the three outcome sets must partition the input. The ambiguity set must shrink to
// (roughly) the annulus around the circle boundary, not the whole margin band.
TEST(S2CoveringTest, MarginClassification) {
    std::mt19937_64 rng(20260717);
    constexpr double kEarth = 6371010.0;
    constexpr double kFormulaMargin = 1.0;
    constexpr double kQuant = 0.05;
    std::uniform_real_distribution<double> radius_log(std::log(2000.0), std::log(2000000.0));

    for (int iter = 0; iter < 20; ++iter) {
        S2Point center = random_point(rng);
        double radius_m = std::exp(radius_log(rng));
        S1Angle radius = S1Angle::Radians(radius_m / kEarth);

        // Margin rows: points hugging the circle boundary (the hard band) plus points
        // clearly inside/outside, all expressed as leaf cells like the index stores.
        std::vector<std::pair<uint32_t, uint64_t>> margin;
        std::uniform_real_distribution<double> f(0.0, 2.0);
        for (uint32_t rid = 0; rid < 4000; ++rid) {
            S2Point q = random_point(rng);
            S2Point p = point_at_distance(center, q, radius * f(rng));
            margin.emplace_back(rid, S2CellId(p).id());
        }
        std::sort(margin.begin(), margin.end(),
                  [](const auto& a, const auto& b) { return a.second < b.second; });

        roaring::Roaring hit;
        std::vector<uint32_t> need_exact;
        double lng0 = S2LatLng(center).lng().degrees();
        double lat0 = S2LatLng(center).lat().degrees();
        classify_margin_cells(lng0, lat0, radius_m, kFormulaMargin, kQuant, margin, &hit,
                              &need_exact);

        std::set<uint32_t> exact_set(need_exact.begin(), need_exact.end());
        ASSERT_EQ(need_exact.size(), exact_set.size());
        // The classifier recomputes the center from rounded degrees; bound the
        // resulting slack generously when checking verdict safety.
        S2Point used_center = S2LatLng::FromDegrees(lat0, lng0).ToPoint();
        size_t hits = 0;
        for (const auto& [rid, cell] : margin) {
            bool in_hit = hit.contains(rid);
            bool in_exact = exact_set.count(rid) > 0;
            ASSERT_FALSE(in_hit && in_exact) << "row in both sets, rid=" << rid;
            S2Cell leaf((S2CellId(cell)));
            double min_d = S1ChordAngle(leaf.GetDistance(used_center)).ToAngle().radians() * kEarth;
            double max_d =
                    S1ChordAngle(leaf.GetMaxDistance(used_center)).ToAngle().radians() * kEarth;
            if (in_hit) {
                ++hits;
                ASSERT_LT(max_d, radius_m + 0.01)
                        << "accepted a row whose leaf may lie outside, rid=" << rid;
            } else if (!in_exact) {
                ASSERT_GT(min_d, radius_m - 0.01)
                        << "dropped a row whose leaf may lie inside, rid=" << rid;
            }
        }
        ASSERT_GT(hits, 0u);
        // Rows sent to the exact recheck must hug the boundary: their leaf cells
        // intersect the annulus radius ± (margins + leaf size).
        for (uint32_t rid : need_exact) {
            auto it = std::find_if(margin.begin(), margin.end(),
                                   [rid](const auto& m) { return m.first == rid; });
            S2Cell leaf((S2CellId(it->second)));
            double min_d = S1ChordAngle(leaf.GetDistance(used_center)).ToAngle().radians() * kEarth;
            double max_d =
                    S1ChordAngle(leaf.GetMaxDistance(used_center)).ToAngle().radians() * kEarth;
            double slack = kFormulaMargin + kQuant + 0.5;
            ASSERT_TRUE(min_d < radius_m + slack && max_d > radius_m - slack)
                    << "need_exact row far from the boundary annulus, rid=" << rid
                    << " min_d=" << min_d << " max_d=" << max_d << " r=" << radius_m;
        }
    }
}

} // namespace doris::segment_v2
