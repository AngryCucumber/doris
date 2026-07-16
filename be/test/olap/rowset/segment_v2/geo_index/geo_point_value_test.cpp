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

#include "vec/runtime/geo_point_value.h"

#include <gtest/gtest.h>

#include <cmath>

#include "geo/geo_types.h"

namespace doris {

// GEO_POINT text codec guardrails (HASI_POC.md §10): "[lon, lat]" must round-trip
// bit-stably (a decoded center re-encodes to the same cell), the codec must agree
// with GeoPoint::ComputeS2CellKey (the st_s2_cellid kernel), and malformed or
// out-of-range text must be rejected.
TEST(GeoPointValueTest, RoundTrip) {
    const double points[][2] = {
            {116.40, 39.90}, {-73.99, 40.72}, {179.999, -85.0},
            {-180.0, 0.0},   {180.0, 0.0},    {0.0, 90.0},
            {0.0, -90.0},    {0.0, 0.0},      {45.0, 0.0},
    };
    for (const auto& p : points) {
        int64_t key = 0;
        ASSERT_TRUE(GeoPoint::ComputeS2CellKey(p[0], p[1], &key));
        std::string text = GeoPointValue::to_string(key);
        ASSERT_EQ('[', text.front()) << text;
        ASSERT_EQ(']', text.back()) << text;
        int64_t key2 = 0;
        ASSERT_TRUE(GeoPointValue::from_string(&key2, text)) << text;
        EXPECT_EQ(key, key2) << "text round trip changed the cell: " << text;
        // decoded center within ~1cm of the original point (lat always; lon blows
        // up near the poles where the small circle shrinks)
        double lng = 0;
        double lat = 0;
        ASSERT_TRUE(GeoPoint::DecodeS2CellKey(key, &lng, &lat));
        EXPECT_LT(std::abs(lat - p[1]), 2e-7) << text;
        if (std::abs(p[1]) < 89.0) {
            double dl = std::abs(lng - p[0]);
            EXPECT_TRUE(dl < 2e-7 || dl > 359.9) << text;
        }
    }
}

TEST(GeoPointValueTest, ParseMatrix) {
    int64_t key = 0;
    // whitespace tolerated
    EXPECT_TRUE(GeoPointValue::from_string(&key, "  [ 116.4 , 39.9 ]  "));
    int64_t key2 = 0;
    EXPECT_TRUE(GeoPointValue::from_string(&key2, "[116.4,39.9]"));
    EXPECT_EQ(key, key2);
    // rejects: bare pair (ES bare-string is lat,lon -- ambiguous), out-of-range,
    // wrong arity, garbage, non-finite
    const char* bad[] = {"116.4, 39.9", "[181.0, 0.0]",   "[-180.5, 0.0]", "[0.0, 91.0]",
                         "[0.0, -90.5]", "[1.0]",          "[1, 2, 3]",     "[a, b]",
                         "",             "[nan, 0]",       "[inf, 0]",      "[116.4, 39.9] x"};
    for (const char* s : bad) {
        int64_t k = 0;
        EXPECT_FALSE(GeoPointValue::from_string(&k, s, strlen(s))) << s;
    }
}

TEST(GeoPointValueTest, MatchesS2CellIdKernel) {
    // the text parse must produce EXACTLY what st_s2_cellid computes for the same
    // coordinates -- one shared kernel, no second quantization path
    int64_t parsed = 0;
    ASSERT_TRUE(GeoPointValue::from_string(&parsed, "[116.40, 39.90]"));
    int64_t computed = 0;
    ASSERT_TRUE(GeoPoint::ComputeS2CellKey(116.40, 39.90, &computed));
    EXPECT_EQ(computed, parsed);
}

TEST(GeoPointValueTest, InvalidKeyFormatsAsInvalid) {
    // raw cell 0 (the index NULL sentinel) is not a valid cell id
    const int64_t null_sentinel_key = static_cast<int64_t>(uint64_t(0) ^ (uint64_t(1) << 63));
    EXPECT_EQ("[invalid]", GeoPointValue::to_string(null_sentinel_key));
    int64_t k = 0;
    EXPECT_FALSE(GeoPointValue::from_string(&k, "[invalid]"));
}

} // namespace doris
