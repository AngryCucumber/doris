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
#include <set>
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

// Exact mode (margin_out non-null): definite hits carry only interior cells, margin
// rows carry exactly the covering-minus-interior cells, and their union equals the
// superset-mode hit bit for bit.
TEST(HasiTreeTest, MarginModeInvariants) {
    std::mt19937_64 rng(20260716);
    S2Covering coverer(kMaxLevel, kMaxCells);
    std::uniform_real_distribution<double> radius_log(std::log(500.0), std::log(5000000.0));

    for (int iter = 0; iter < 10; ++iter) {
        Dataset data = (iter % 2 == 0) ? make_clustered(rng, 3000, 60)
                                       : make_unsorted(rng, 3000, 0.05);
        HasiTree tree;
        ASSERT_TRUE(tree.parse(build(data, 128)).ok());

        S2Cap cap(random_point(rng), S1Angle::Radians(std::exp(radius_log(rng)) / 6371010.0));
        std::vector<CellRange> covering;
        std::vector<CellRange> interior;
        coverer.cover(cap, &covering, &interior);

        roaring::Roaring superset_hit;
        HasiSearchStats stats;
        ASSERT_TRUE(tree.search(covering, interior, &superset_hit, &stats).ok());

        roaring::Roaring definite_hit;
        std::vector<std::pair<uint32_t, uint64_t>> margin;
        HasiSearchStats stats2;
        ASSERT_TRUE(tree.search(covering, interior, &definite_hit, &stats2, &margin).ok());

        roaring::Roaring recombined = definite_hit;
        for (const auto& [rid, cell] : margin) {
            ASSERT_TRUE(data[rid].has_value());
            ASSERT_EQ(s2_cell_from_key(*data[rid]), cell) << "margin cell mismatch at rid " << rid;
            ASSERT_TRUE(cell_ranges_contain(covering, cell));
            ASSERT_FALSE(cell_ranges_contain(interior, cell));
            ASSERT_FALSE(definite_hit.contains(rid));
            recombined.add(rid);
        }
        ASSERT_EQ(superset_hit, recombined);
        ASSERT_EQ(stats.rows_margin, stats2.rows_margin);
    }
}

// v2b measure sketches: attach -> stream -> serialize -> parse roundtrip, and
// aggregate_inside + row-wise folding of boundary_rids must reproduce the brute-force
// aggregate over all rows whose cell lies in the interior, exactly (sum/min/max/count
// are plain double/int ops on both paths, so bit-exact equality is required).
TEST(HasiTreeTest, MeasureSketchAggregate) {
    std::mt19937_64 rng(20260718);
    S2Covering coverer(kMaxLevel, kMaxCells);
    std::uniform_real_distribution<double> radius_log(std::log(50000.0), std::log(5000000.0));

    for (int iter = 0; iter < 10; ++iter) {
        Dataset data = make_clustered(rng, 5000, iter % 2 == 0 ? 100 : 0);
        HasiTreeBuilder builder(iter % 2 == 0 ? 64 : 257);
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
        builder.finish_topology();
        ASSERT_TRUE(builder.attach_measures({"amount"}).ok());
        // measure = deterministic f(rid); every 7th row NULL. NULL-cell rows are fed
        // with NON-null values on purpose: the builder must drop them itself.
        auto measure_of = [](uint32_t rid) { return (rid % 1000) * 0.5 - 100.0; };
        auto measure_null = [&](uint32_t rid) { return rid % 7 == 0; };
        for (uint32_t rid = 0; rid < data.size(); ++rid) {
            double v = measure_of(rid);
            uint8_t is_null = measure_null(rid) ? 1 : 0;
            ASSERT_TRUE(builder.add_measure_row(rid, &v, &is_null).ok());
        }
        std::string blob;
        ASSERT_TRUE(builder.serialize(&blob).ok());

        HasiTree tree;
        ASSERT_TRUE(tree.parse(std::move(blob)).ok());
        ASSERT_TRUE(tree.has_measures());
        ASSERT_EQ(0, tree.measure_index("amount"));
        ASSERT_EQ(-1, tree.measure_index("nope"));

        S2Point center = S2CellId(s2_cell_from_key(*data[data.size() / 2])).ToPoint();
        S2Cap cap(center, S1Angle::Radians(std::exp(radius_log(rng)) / 6371010.0));
        std::vector<CellRange> covering;
        std::vector<CellRange> interior;
        coverer.cover(cap, &covering, &interior);

        HasiLeafMeasure inside;
        uint64_t inside_rows = 0;
        std::vector<uint32_t> boundary;
        HasiSearchStats stats;
        ASSERT_TRUE(tree.aggregate_inside(covering, interior, 0, &inside, &inside_rows,
                                          &boundary, &stats)
                            .ok());

        // Fold boundary rows the way the caller would (restricting to cell ∈ I so the
        // combined result is comparable to the brute-force interior aggregate).
        HasiLeafMeasure folded = inside;
        uint64_t folded_rows = inside_rows;
        for (uint32_t rid : boundary) {
            if (!cell_ranges_contain(interior, s2_cell_from_key(*data[rid]))) {
                continue;
            }
            ++folded_rows;
            if (!measure_null(rid)) {
                folded.sum += measure_of(rid);
                folded.min = std::min(folded.min, measure_of(rid));
                folded.max = std::max(folded.max, measure_of(rid));
                ++folded.non_null;
            }
        }
        // Brute force over all rows with cell in the interior.
        HasiLeafMeasure brute;
        uint64_t brute_rows = 0;
        for (uint32_t rid = 0; rid < data.size(); ++rid) {
            if (!data[rid].has_value() ||
                !cell_ranges_contain(interior, s2_cell_from_key(*data[rid]))) {
                continue;
            }
            // every interior row must be sketch-covered or listed as boundary
            ++brute_rows;
            if (!measure_null(rid)) {
                brute.sum += measure_of(rid);
                brute.min = std::min(brute.min, measure_of(rid));
                brute.max = std::max(brute.max, measure_of(rid));
                ++brute.non_null;
            }
        }
        ASSERT_EQ(brute_rows, folded_rows) << "iter " << iter;
        ASSERT_EQ(brute.non_null, folded.non_null) << "iter " << iter;
        ASSERT_DOUBLE_EQ(brute.sum, folded.sum) << "iter " << iter;
        if (brute.non_null > 0) {
            ASSERT_EQ(brute.min, folded.min) << "iter " << iter;
            ASSERT_EQ(brute.max, folded.max) << "iter " << iter;
        }
    }
}

// v2b query fold: fold_inside must select exactly the leaves that are (a) fully
// interior-contained, (b) free of NULL-cell rows and (c) fully present in the
// caller's bitmap; the merged sketch must equal the brute-force aggregate over the
// folded rows, and removing a single row from `present` must demote its leaf.
TEST(HasiTreeTest, FoldInside) {
    std::mt19937_64 rng(20260715);
    S2Covering coverer(kMaxLevel, kMaxCells);

    for (int iter = 0; iter < 6; ++iter) {
        const uint32_t leaf_rows = iter % 2 == 0 ? 64 : 257;
        Dataset data = make_clustered(rng, 5000, iter % 3 == 0 ? 100 : 0);
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
        builder.finish_topology();
        ASSERT_TRUE(builder.attach_measures({"amount"}).ok());
        auto measure_of = [](uint32_t rid) { return (rid % 1000) * 0.5 - 100.0; };
        auto measure_null = [&](uint32_t rid) { return rid % 7 == 0; };
        for (uint32_t rid = 0; rid < data.size(); ++rid) {
            double v = measure_of(rid);
            uint8_t is_null = measure_null(rid) ? 1 : 0;
            ASSERT_TRUE(builder.add_measure_row(rid, &v, &is_null).ok());
        }
        std::string blob;
        ASSERT_TRUE(builder.serialize(&blob).ok());
        HasiTree tree;
        ASSERT_TRUE(tree.parse(std::move(blob)).ok());

        S2Point center = S2CellId(s2_cell_from_key(*data[data.size() / 2])).ToPoint();
        S2Cap cap(center, S1Angle::Radians(1000000.0 / 6371010.0));
        std::vector<CellRange> covering;
        std::vector<CellRange> interior;
        coverer.cover(cap, &covering, &interior);

        roaring::Roaring full;
        full.addRange(0, data.size());
        HasiFoldResult fold;
        ASSERT_TRUE(tree.fold_inside(interior, {0}, full, &fold).ok());

        HasiLeafMeasure brute;
        uint64_t brute_rows = 0;
        for (const auto& [begin, end] : fold.folded_ranges) {
            for (uint32_t rid = begin; rid < end; ++rid) {
                // every row of a folded leaf has a valid cell inside the interior
                ASSERT_TRUE(data[rid].has_value()) << "iter " << iter << " rid " << rid;
                ASSERT_TRUE(cell_ranges_contain(interior, s2_cell_from_key(*data[rid])));
                ++brute_rows;
                if (!measure_null(rid)) {
                    brute.sum += measure_of(rid);
                    brute.min = std::min(brute.min, measure_of(rid));
                    brute.max = std::max(brute.max, measure_of(rid));
                    ++brute.non_null;
                }
            }
        }
        ASSERT_EQ(fold.folded_ranges.size(), fold.folded_leaves);
        ASSERT_EQ(brute_rows, fold.folded_rows) << "iter " << iter;
        ASSERT_EQ(1, fold.measures.size());
        ASSERT_EQ(brute.non_null, fold.measures[0].non_null) << "iter " << iter;
        ASSERT_DOUBLE_EQ(brute.sum, fold.measures[0].sum) << "iter " << iter;
        if (brute.non_null > 0) {
            ASSERT_EQ(brute.min, fold.measures[0].min) << "iter " << iter;
            ASSERT_EQ(brute.max, fold.measures[0].max) << "iter " << iter;
        }
        // completeness: no interior-contained, null-free leaf may be left unfolded
        // (reconstruct leaves from the fixed block size)
        {
            std::set<uint32_t> folded_begins;
            for (const auto& [begin, end] : fold.folded_ranges) {
                folded_begins.insert(begin);
            }
            const auto n = static_cast<uint32_t>(data.size());
            for (uint32_t begin = 0; begin < n; begin += leaf_rows) {
                const uint32_t end = std::min(begin + leaf_rows, n);
                bool eligible = true;
                for (uint32_t rid = begin; rid < end && eligible; ++rid) {
                    eligible = data[rid].has_value() &&
                               cell_ranges_contain(interior, s2_cell_from_key(*data[rid]));
                }
                // eligible-by-rows is necessary for folding; leaves whose [min,max]
                // cell span sticks outside the interior may still legitimately stay
                // unfolded, so only assert the reverse direction.
                if (folded_begins.contains(begin)) {
                    ASSERT_TRUE(eligible) << "iter " << iter << " leaf@" << begin;
                }
            }
        }
        // knocking one row out of `present` must demote exactly its leaf
        if (!fold.folded_ranges.empty()) {
            const auto [begin, end] = fold.folded_ranges.front();
            roaring::Roaring partial = full;
            partial.remove(begin + (end - begin) / 2);
            HasiFoldResult fold2;
            ASSERT_TRUE(tree.fold_inside(interior, {0}, partial, &fold2).ok());
            ASSERT_EQ(fold.folded_leaves - 1, fold2.folded_leaves);
            ASSERT_EQ(fold.folded_rows - (end - begin), fold2.folded_rows);
        }
        // empty measure list still folds the row count
        HasiFoldResult fold3;
        ASSERT_TRUE(tree.fold_inside(interior, {}, full, &fold3).ok());
        ASSERT_EQ(fold.folded_rows, fold3.folded_rows);
        ASSERT_TRUE(fold3.measures.empty());
        // unknown measure index is an error, not a silent wrong answer
        HasiFoldResult fold4;
        ASSERT_FALSE(tree.fold_inside(interior, {1}, full, &fold4).ok());
    }
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
