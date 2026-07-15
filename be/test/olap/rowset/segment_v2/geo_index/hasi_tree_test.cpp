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

#include "olap/rowset/segment_v2/geo_index/hasi_tree.h"

#include <gtest/gtest.h>
#include <s2/s1angle.h>
#include <s2/s2cap.h>
#include <s2/s2cell_id.h>
#include <s2/s2latlng.h>
#include <s2/s2point.h>

#include <algorithm>
#include <cmath>
#include <limits>
#include <optional>
#include <random>
#include <vector>

#include "olap/rowset/segment_v2/geo_index/s2_covering.h"

namespace doris::segment_v2 {

namespace {

constexpr int kMaxLevel = 30;
constexpr int kMaxCells = 64;

S2Point random_point(std::mt19937_64& rng) {
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    while (true) {
        S2Point p(dist(rng), dist(rng), dist(rng));
        if (p.Norm2() > 1e-6 && p.Norm2() <= 1.0) {
            return p.Normalize();
        }
    }
}

// A dataset row: nullopt = NULL cell. Values are __s2 keys (sign-flipped domain).
using Dataset = std::vector<std::optional<int64_t>>;

// Clustered dataset: null prefix + cell keys in ascending key order (the layout a
// DUP table with __s2 as first sort key produces).
Dataset make_clustered(std::mt19937_64& rng, size_t rows, size_t nulls) {
    std::vector<int64_t> keys;
    keys.reserve(rows - nulls);
    for (size_t i = 0; i + nulls < rows; ++i) {
        keys.push_back(s2_key_from_cell(S2CellId(random_point(rng)).id()));
    }
    std::sort(keys.begin(), keys.end());
    Dataset data;
    data.reserve(rows);
    for (size_t i = 0; i < nulls; ++i) {
        data.emplace_back(std::nullopt);
    }
    for (int64_t k : keys) {
        data.emplace_back(k);
    }
    return data;
}

// Non-key layout: random order, NULLs sprinkled anywhere.
Dataset make_unsorted(std::mt19937_64& rng, size_t rows, double null_ratio) {
    Dataset data;
    data.reserve(rows);
    std::uniform_real_distribution<double> coin(0.0, 1.0);
    for (size_t i = 0; i < rows; ++i) {
        if (coin(rng) < null_ratio) {
            data.emplace_back(std::nullopt);
        } else {
            data.emplace_back(s2_key_from_cell(S2CellId(random_point(rng)).id()));
        }
    }
    return data;
}

// Feed a dataset through the streaming builder exactly like ScalarColumnWriter would:
// consecutive NULLs arrive as one add_nulls(count), values one by one.
std::string build(const Dataset& data, uint32_t leaf_rows) {
    HasiTreeBuilder builder(leaf_rows);
    size_t i = 0;
    while (i < data.size()) {
        if (!data[i].has_value()) {
            uint32_t run = 0;
            while (i < data.size() && !data[i].has_value()) {
                ++run;
                ++i;
            }
            builder.add_nulls(run);
        } else {
            builder.add_value(*data[i]);
            ++i;
        }
    }
    EXPECT_EQ(data.size(), builder.num_rows());
    std::string out;
    EXPECT_TRUE(builder.finish(&out).ok());
    return out;
}

// Oracle: hit == { rid : cell != NULL && raw cell ∈ covering }.
roaring::Roaring oracle_hit(const Dataset& data, const std::vector<CellRange>& covering) {
    roaring::Roaring expected;
    for (size_t i = 0; i < data.size(); ++i) {
        if (data[i].has_value() &&
            cell_ranges_contain(covering, s2_cell_from_key(*data[i]))) {
            expected.add(static_cast<uint32_t>(i));
        }
    }
    return expected;
}

void check_against_oracle(const Dataset& data, uint32_t leaf_rows,
                          const std::vector<CellRange>& covering,
                          const std::vector<CellRange>& interior, HasiSearchStats* stats_out) {
    HasiTree tree;
    ASSERT_TRUE(tree.parse(build(data, leaf_rows)).ok());
    ASSERT_EQ(data.size(), tree.num_rows());

    roaring::Roaring hit;
    HasiSearchStats stats;
    ASSERT_TRUE(tree.search(covering, interior, &hit, &stats).ok());

    roaring::Roaring expected = oracle_hit(data, covering);
    ASSERT_EQ(expected, hit);

    // Every value row is attributed exactly once.
    size_t value_rows = 0;
    for (const auto& v : data) {
        value_rows += v.has_value() ? 1 : 0;
    }
    ASSERT_EQ(value_rows, stats.rows_inside + stats.rows_margin + stats.rows_rejected);
    ASSERT_EQ(hit.cardinality(), stats.rows_inside + stats.rows_margin);
    if (stats_out != nullptr) {
        *stats_out = stats;
    }
}

std::vector<CellRange> full_sphere_covering() {
    // All 6 faces in the leaf keyspace: [face0 range_min, face5 range_max].
    return {{S2CellId::FromFace(0).range_min().id(), S2CellId::FromFace(5).range_max().id()}};
}

} // namespace

// Random caps against random datasets, clustered and unsorted, hit must equal the
// brute-force oracle bit for bit.
TEST(HasiTreeTest, SearchMatchesOracle) {
    std::mt19937_64 rng(20260715);
    S2Covering coverer(kMaxLevel, kMaxCells);
    std::uniform_real_distribution<double> radius_log(std::log(500.0), std::log(5000000.0));

    for (int iter = 0; iter < 20; ++iter) {
        const uint32_t leaf_rows = (iter % 2 == 0) ? 64 : 257; // exercise partial leaves
        Dataset data = (iter % 3 == 0) ? make_unsorted(rng, 4000, 0.05)
                                       : make_clustered(rng, 4000, iter % 5 == 0 ? 100 : 0);

        S2Cap cap(random_point(rng), S1Angle::Radians(std::exp(radius_log(rng)) / 6371010.0));
        std::vector<CellRange> covering;
        std::vector<CellRange> interior;
        coverer.cover(cap, &covering, &interior);

        check_against_oracle(data, leaf_rows, covering, interior, nullptr);
    }
}

// Clustered data + a big cap must exercise the whole-leaf accept fast path; the cap
// is centered on an existing data point so the region is guaranteed populated.
TEST(HasiTreeTest, InsideFastPathFires) {
    std::mt19937_64 rng(42);
    Dataset data = make_clustered(rng, 20000, 0);
    S2Covering coverer(kMaxLevel, kMaxCells);

    S2Point center = S2CellId(s2_cell_from_key(*data[data.size() / 2])).ToPoint();
    S2Cap cap(center, S1Angle::Radians(2000000.0 / 6371010.0));
    std::vector<CellRange> covering;
    std::vector<CellRange> interior;
    coverer.cover(cap, &covering, &interior);
    ASSERT_FALSE(interior.empty());

    HasiSearchStats stats;
    check_against_oracle(data, 64, covering, interior, &stats);
    EXPECT_GT(stats.leaves_inside, 0) << "whole-leaf accept never fired on clustered data";
    EXPECT_GT(stats.leaves_skipped, 0) << "whole-leaf skip never fired on clustered data";
}

// Empty covering -> empty hit; full-sphere covering -> exactly all value rows.
TEST(HasiTreeTest, EmptyAndFullCovering) {
    std::mt19937_64 rng(7);
    Dataset data = make_unsorted(rng, 3000, 0.1);
    HasiTree tree;
    ASSERT_TRUE(tree.parse(build(data, 128)).ok());

    roaring::Roaring hit;
    HasiSearchStats stats;
    ASSERT_TRUE(tree.search({}, {}, &hit, &stats).ok());
    ASSERT_EQ(0, hit.cardinality());

    std::vector<CellRange> all = full_sphere_covering();
    ASSERT_TRUE(tree.search(all, all, &hit, &stats).ok());
    ASSERT_EQ(oracle_hit(data, all), hit);
    for (size_t i = 0; i < data.size(); ++i) {
        ASSERT_EQ(data[i].has_value(), hit.contains(static_cast<uint32_t>(i)));
    }
}

// NULL runs spanning leaf boundaries and an all-null dataset.
TEST(HasiTreeTest, NullHandling) {
    Dataset data;
    for (int i = 0; i < 100; ++i) {
        data.emplace_back(std::nullopt);
    }
    // one value row wedged between two null runs, crossing several 64-row leaves
    data.emplace_back(s2_key_from_cell(S2CellId(S2LatLng::FromDegrees(39.9, 116.4)).id()));
    for (int i = 0; i < 100; ++i) {
        data.emplace_back(std::nullopt);
    }
    HasiTree tree;
    ASSERT_TRUE(tree.parse(build(data, 64)).ok());

    std::vector<CellRange> all = full_sphere_covering();
    roaring::Roaring hit;
    HasiSearchStats stats;
    ASSERT_TRUE(tree.search(all, all, &hit, &stats).ok());
    ASSERT_EQ(1, hit.cardinality());
    ASSERT_TRUE(hit.contains(100));

    Dataset all_null(500, std::nullopt);
    HasiTree tree2;
    ASSERT_TRUE(tree2.parse(build(all_null, 64)).ok());
    ASSERT_TRUE(tree2.search(all, all, &hit, &stats).ok());
    ASSERT_EQ(0, hit.cardinality());
}

// Corrupted/truncated buffers must fail cleanly, never crash.
TEST(HasiTreeTest, ParseRejectsCorruption) {
    std::mt19937_64 rng(11);
    Dataset data = make_clustered(rng, 1000, 10);
    std::string good = build(data, 128);

    {
        HasiTree tree;
        ASSERT_FALSE(tree.parse(std::string()).ok());
    }
    {
        HasiTree tree;
        ASSERT_FALSE(tree.parse(good.substr(0, 10)).ok());
    }
    {
        // Truncate the directory.
        HasiTree tree;
        ASSERT_FALSE(tree.parse(good.substr(0, 24 + 5)).ok());
    }
    {
        // Truncate the cell stream: parse may succeed (directory intact) but search
        // must surface corruption instead of reading out of bounds. Interior is left
        // empty so every intersecting leaf is forced to decode its cell stream (a
        // full-sphere interior would whole-leaf accept and never touch the cut tail).
        HasiTree tree;
        std::string cut = good.substr(0, good.size() - 32);
        Status st = tree.parse(std::move(cut));
        if (st.ok()) {
            roaring::Roaring hit;
            HasiSearchStats stats;
            ASSERT_FALSE(tree.search(full_sphere_covering(), {}, &hit, &stats).ok());
        }
    }
    {
        // Bad magic.
        HasiTree tree;
        std::string bad = good;
        bad[0] = 'X';
        ASSERT_FALSE(tree.parse(std::move(bad)).ok());
    }
    {
        // Roundtrip sanity on the untouched buffer.
        HasiTree tree;
        ASSERT_TRUE(tree.parse(std::move(good)).ok());
        ASSERT_EQ(1000, tree.num_rows());
        ASSERT_EQ((1000 + 127) / 128, tree.num_leaves());
    }
}

} // namespace doris::segment_v2
