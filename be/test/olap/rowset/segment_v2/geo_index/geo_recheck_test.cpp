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

#include "olap/rowset/segment_v2/geo_index/geo_recheck_simd.h"

#include <gtest/gtest.h>

#include <cmath>
#include <random>
#include <vector>

#include "geo/geo_types.h"

namespace doris::segment_v2 {

namespace {

// The reference oracle = exactly what the full-scan scalar path computes.
bool oracle(GeoCirclePredicate pred, double lng0, double lat0, double radius_m,
            const GeoCircle& circle, double lng, double lat) {
    switch (pred) {
    case GeoCirclePredicate::DISTANCE_LT:
    case GeoCirclePredicate::DISTANCE_LE: {
        double dist = 0;
        if (!GeoPoint::ComputeDistance(lng, lat, lng0, lat0, &dist)) {
            return false; // NULL -> filtered
        }
        return pred == GeoCirclePredicate::DISTANCE_LT ? dist < radius_m : dist <= radius_m;
    }
    case GeoCirclePredicate::CONTAINS_CIRCLE: {
        GeoPoint p;
        if (p.from_coord(lng, lat) != GEO_PARSE_OK) {
            return false;
        }
        return circle.contains(&p);
    }
    }
    return false;
}

// Destination point at bearing `brg` and angular distance `theta` from (lat0, lng0),
// classic great-circle formulas (only used to *generate* test points, not to judge).
void destination(double lat0_deg, double lng0_deg, double brg_rad, double theta,
                 double* lat_deg, double* lng_deg) {
    double lat0 = lat0_deg * M_PI / 180.0;
    double lng0 = lng0_deg * M_PI / 180.0;
    double lat = std::asin(std::sin(lat0) * std::cos(theta) +
                           std::cos(lat0) * std::sin(theta) * std::cos(brg_rad));
    double lng = lng0 + std::atan2(std::sin(brg_rad) * std::sin(theta) * std::cos(lat0),
                                   std::cos(theta) - std::sin(lat0) * std::sin(lat));
    *lat_deg = lat * 180.0 / M_PI;
    *lng_deg = std::remainder(lng * 180.0 / M_PI, 360.0);
}

struct Scenario {
    double lng0, lat0, radius_m;
    const char* name;
};

void run_scenario(const Scenario& sc, GeoCirclePredicate pred, uint64_t seed) {
    CircleRecheck kernel;
    ASSERT_TRUE(kernel.init(sc.lng0, sc.lat0, sc.radius_m, pred)) << sc.name;
    GeoCircle circle;
    ASSERT_EQ(circle.init(sc.lng0, sc.lat0, sc.radius_m), GEO_PARSE_OK);

    std::mt19937_64 rng(seed);
    std::uniform_real_distribution<double> unit(0.0, 1.0);
    const double theta = sc.radius_m / CircleRecheck::kEarthRadiusMeters;

    std::vector<double> lngs;
    std::vector<double> lats;
    // uniform-ish global points + dense boundary band + interior points
    for (int i = 0; i < 2000; ++i) {
        double lat_deg = 0;
        double lng_deg = 0;
        if (i % 4 == 0) {
            lat_deg = -90.0 + 180.0 * unit(rng);
            lng_deg = -180.0 + 360.0 * unit(rng);
        } else if (i % 4 == 1) { // boundary band: [0.99r, 1.01r]
            destination(sc.lat0, sc.lng0, 2 * M_PI * unit(rng), theta * (0.99 + 0.02 * unit(rng)),
                        &lat_deg, &lng_deg);
        } else if (i % 4 == 2) { // razor-thin band around the boundary
            destination(sc.lat0, sc.lng0, 2 * M_PI * unit(rng),
                        theta * (1.0 + 2e-7 * (unit(rng) - 0.5)), &lat_deg, &lng_deg);
        } else { // interior
            destination(sc.lat0, sc.lng0, 2 * M_PI * unit(rng), theta * unit(rng), &lat_deg,
                        &lng_deg);
        }
        lngs.push_back(lng_deg);
        lats.push_back(lat_deg);
    }
    // invalid coordinates must never be accepted (scalar path yields NULL -> filtered)
    lngs.push_back(200.0);
    lats.push_back(10.0);
    lngs.push_back(10.0);
    lats.push_back(95.0);

    std::vector<uint8_t> keep(lngs.size(), 0xAA);
    GeoRecheckStats stats;
    kernel.recheck(lngs.data(), lats.data(), lngs.size(), keep.data(), &stats);

    for (size_t i = 0; i < lngs.size(); ++i) {
        bool expected = oracle(pred, sc.lng0, sc.lat0, sc.radius_m, circle, lngs[i], lats[i]);
        ASSERT_EQ(keep[i] != 0, expected)
                << sc.name << " row " << i << " lng=" << lngs[i] << " lat=" << lats[i];
    }
    // The prefilter must actually do work on non-degenerate scenarios: everything
    // routed to band 3 would be correct but useless.
    EXPECT_GT(stats.fast_reject, size_t(0)) << sc.name;
    EXPECT_LT(stats.exact_calls, lngs.size()) << sc.name;
}

} // namespace

TEST(CircleRecheckTest, AllPredicatesAllScenarios) {
    const Scenario scenarios[] = {
            {116.40, 39.90, 5000.0, "beijing_5km"},
            {116.40, 39.90, 500000.0, "beijing_500km"},
            {0.0, 0.0, 100000.0, "equator_100km"},
            {179.95, 10.0, 50000.0, "antimeridian_50km"},
            {-179.99, -35.0, 200000.0, "antimeridian_south_200km"},
            {45.0, 0.0, 30000.0, "face_boundary_30km"},
            {12.0, 89.5, 200000.0, "near_north_pole_200km"},
            {30.0, -89.7, 100000.0, "near_south_pole_100km"},
            {60.0, 66.5, 2000000.0, "high_lat_2000km"},
            {7.0, 46.0, 60.0, "tiny_60m"},
    };
    const GeoCirclePredicate preds[] = {GeoCirclePredicate::DISTANCE_LT,
                                        GeoCirclePredicate::DISTANCE_LE,
                                        GeoCirclePredicate::CONTAINS_CIRCLE};
    uint64_t seed = 20260714;
    for (const auto& sc : scenarios) {
        for (auto pred : preds) {
            run_scenario(sc, pred, seed++);
        }
    }
}

// Antimeridian regression: points on the far side of ±180 with a tiny true delta must
// be accepted; the naive |lng - lng0| comparison would compute a 359.8° difference.
TEST(CircleRecheckTest, AntimeridianWrap) {
    CircleRecheck kernel;
    ASSERT_TRUE(kernel.init(179.9, 0.0, 50000.0, GeoCirclePredicate::DISTANCE_LT));
    double lng = -179.9; // true delta 0.2 deg ~ 22 km < 50 km
    double lat = 0.0;
    uint8_t keep = 0;
    kernel.recheck(&lng, &lat, 1, &keep, nullptr);
    EXPECT_EQ(keep, 1);
}

// A cap covering a pole has a full longitude interval; nothing may be rejected on lng.
TEST(CircleRecheckTest, PoleCoveringCap) {
    CircleRecheck kernel;
    ASSERT_TRUE(kernel.init(0.0, 89.9, 100000.0, GeoCirclePredicate::DISTANCE_LT));
    GeoCircle circle;
    ASSERT_EQ(circle.init(0.0, 89.9, 100000.0), GEO_PARSE_OK);
    // walk all longitudes at a latitude ring inside the cap
    for (int i = -180; i <= 180; i += 5) {
        double lng = i;
        double lat = 89.8;
        uint8_t keep = 0;
        kernel.recheck(&lng, &lat, 1, &keep, nullptr);
        bool expected = oracle(GeoCirclePredicate::DISTANCE_LT, 0.0, 89.9, 100000.0, circle,
                               lng, lat);
        ASSERT_EQ(keep != 0, expected) << "lng=" << lng;
    }
}

TEST(CircleRecheckTest, InvalidInit) {
    CircleRecheck kernel;
    EXPECT_FALSE(kernel.init(200.0, 0.0, 1000.0, GeoCirclePredicate::DISTANCE_LT));
    EXPECT_FALSE(kernel.init(0.0, 95.0, 1000.0, GeoCirclePredicate::DISTANCE_LT));
    EXPECT_FALSE(kernel.init(0.0, 0.0, 0.0, GeoCirclePredicate::DISTANCE_LT));
    EXPECT_FALSE(kernel.init(0.0, 0.0, -5.0, GeoCirclePredicate::DISTANCE_LT));
}

} // namespace doris::segment_v2
