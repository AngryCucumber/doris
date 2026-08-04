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

#include "olap/rowset/segment_v2/geo_index/hasi_splice.h"

#include <gtest/gtest.h>
#include <s2/s2cell_id.h>
#include <s2/s2latlng.h>
#include <s2/s2point.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <optional>
#include <random>
#include <vector>

#include "olap/rowset/segment_v2/geo_index/geo_index_properties.h"
#include "olap/rowset/segment_v2/geo_index/hasi_tree.h"
#include "olap/rowset/segment_v2/geo_index/s2_covering.h"

namespace doris::segment_v2 {

namespace {

constexpr uint32_t kLeafRows = 64;
constexpr size_t kNumMeasures = 2;

S2Point random_point(std::mt19937_64& rng) {
    std::uniform_real_distribution<double> dist(-1.0, 1.0);
    while (true) {
        S2Point p(dist(rng), dist(rng), dist(rng));
        if (p.Norm2() > 1e-6 && p.Norm2() <= 1.0) {
            return p.Normalize();
        }
    }
}

// One input segment's rows: nullopt = NULL cell (leading, as a first-key-sorted
// DUP segment lays them out); measure values are integer-valued doubles so
// splice-vs-brute-force sums compare bit-exactly.
struct Input {
    std::vector<std::optional<int64_t>> keys;
    std::vector<std::array<double, kNumMeasures>> vals;
    std::vector<std::array<uint8_t, kNumMeasures>> val_nulls;
};

Input make_input(const std::vector<int64_t>& sorted_keys, size_t nulls, uint64_t salt) {
    Input in;
    const size_t rows = sorted_keys.size() + nulls;
    in.keys.reserve(rows);
    for (size_t i = 0; i < nulls; ++i) {
        in.keys.emplace_back(std::nullopt);
    }
    for (int64_t k : sorted_keys) {
        in.keys.emplace_back(k);
    }
    in.vals.resize(rows);
    in.val_nulls.resize(rows);
    for (size_t r = 0; r < rows; ++r) {
        in.vals[r] = {static_cast<double>((r * 7 + salt) % 97),
                      static_cast<double>((r * 3 + salt * 11) % 101)};
        in.val_nulls[r] = {static_cast<uint8_t>(r % 7 == 3 ? 1 : 0),
                           static_cast<uint8_t>(r % 11 == 5 ? 1 : 0)};
    }
    return in;
}

// Globally sorted distinct random leaf-cell keys, split into contiguous rank
// slices -> strictly disjoint per-input hulls by construction (the data layout
// the splice targets: Hilbert-range-sharded loads).
std::vector<std::vector<int64_t>> disjoint_key_slices(std::mt19937_64& rng,
                                                      const std::vector<size_t>& sizes) {
    size_t total = 0;
    for (size_t s : sizes) {
        total += s;
    }
    std::vector<int64_t> keys;
    keys.reserve(total);
    while (keys.size() < total) {
        keys.push_back(s2_key_from_cell(S2CellId(random_point(rng)).id()));
        std::sort(keys.begin(), keys.end());
        keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
    }
    std::vector<std::vector<int64_t>> slices;
    size_t pos = 0;
    for (size_t s : sizes) {
        slices.emplace_back(keys.begin() + pos, keys.begin() + pos + s);
        pos += s;
    }
    return slices;
}

std::string build_blob(const Input& in, uint32_t leaf_rows, bool with_measures) {
    HasiTreeBuilder builder(leaf_rows);
    size_t i = 0;
    while (i < in.keys.size()) {
        if (!in.keys[i].has_value()) {
            uint32_t run = 0;
            while (i < in.keys.size() && !in.keys[i].has_value()) {
                ++run;
                ++i;
            }
            builder.add_nulls(run);
        } else {
            builder.add_value(*in.keys[i]);
            ++i;
        }
    }
    EXPECT_EQ(in.keys.size(), builder.num_rows());
    builder.finish_topology();
    if (with_measures) {
        EXPECT_TRUE(builder.attach_measures({"m0", "m1"}).ok());
        for (size_t r = 0; r < in.keys.size(); ++r) {
            EXPECT_TRUE(builder
                                .add_measure_row(static_cast<uint32_t>(r), in.vals[r].data(),
                                                 in.val_nulls[r].data())
                                .ok());
        }
    }
    std::string out;
    EXPECT_TRUE(builder.serialize(&out).ok());
    return out;
}

HasiReadFn blob_read_fn(const std::string* blob) {
    return [blob](uint64_t offset, size_t len, uint8_t* out) -> Status {
        if (offset + len > blob->size()) {
            return Status::Corruption("read [{}, {}) beyond blob size {}", offset, offset + len,
                                      blob->size());
        }
        std::memcpy(out, blob->data() + offset, len);
        return Status::OK();
    };
}

HasiSinkFn string_sink(std::string* out) {
    return [out](const uint8_t* data, size_t len) -> Status {
        out->append(reinterpret_cast<const char*>(data), len);
        return Status::OK();
    };
}

Input concat_inputs(const std::vector<Input>& inputs, const std::vector<size_t>& order) {
    Input all;
    for (size_t idx : order) {
        const Input& in = inputs[idx];
        all.keys.insert(all.keys.end(), in.keys.begin(), in.keys.end());
        all.vals.insert(all.vals.end(), in.vals.begin(), in.vals.end());
        all.val_nulls.insert(all.val_nulls.end(), in.val_nulls.begin(), in.val_nulls.end());
    }
    return all;
}

struct Fixture {
    std::vector<Input> inputs;
    std::vector<std::string> blobs;
    std::vector<HasiDirView> views;
    std::vector<const HasiDirView*> view_ptrs;
    std::vector<HasiReadFn> readers;

    void init(const std::vector<Input>& ins, uint32_t leaf_rows, bool with_measures) {
        inputs = ins;
        for (const auto& in : inputs) {
            blobs.push_back(build_blob(in, leaf_rows, with_measures));
        }
        views.resize(blobs.size());
        for (size_t i = 0; i < blobs.size(); ++i) {
            ASSERT_TRUE(
                    hasi_parse_dir_view(blob_read_fn(&blobs[i]), blobs[i].size(), &views[i]).ok());
        }
        for (size_t i = 0; i < blobs.size(); ++i) {
            view_ptrs.push_back(&views[i]);
            readers.push_back(blob_read_fn(&blobs[i]));
        }
    }
};

std::vector<CellRange> full_sphere_covering() {
    return {{S2CellId::FromFace(0).range_min().id(), S2CellId::FromFace(5).range_max().id()}};
}

// Compares two trees' search results over a battery of coverings: full sphere,
// each input hull, and narrow slices. Both trees index the same logical rows,
// so hit bitmaps and margin sets must be bit-equal (leaf-boundary invariant).
void check_search_equal(const HasiTree& a, const HasiTree& b,
                        const std::vector<std::vector<CellRange>>& coverings) {
    for (const auto& cov : coverings) {
        roaring::Roaring hit_a;
        roaring::Roaring hit_b;
        HasiSearchStats stats;
        std::vector<std::pair<uint32_t, uint64_t>> margin_a;
        std::vector<std::pair<uint32_t, uint64_t>> margin_b;
        ASSERT_TRUE(a.search(cov, {}, &hit_a, &stats, &margin_a).ok());
        ASSERT_TRUE(b.search(cov, {}, &hit_b, &stats, &margin_b).ok());
        ASSERT_EQ(hit_a, hit_b);
        ASSERT_EQ(margin_a, margin_b);
    }
}

void check_knn_equal(const HasiTree& a, const HasiTree& b, uint64_t center_cell, uint32_t k) {
    const S2LatLng ll(S2CellId(center_cell).ToPoint());
    std::vector<std::pair<uint32_t, uint64_t>> out_a;
    std::vector<std::pair<uint32_t, uint64_t>> out_b;
    HasiKnnStats stats;
    const double kInf = std::numeric_limits<double>::infinity();
    double kth_l2 = kInf;
    bool pruned = false;
    ASSERT_TRUE(a.knn_candidates(ll.lng().degrees(), ll.lat().degrees(), k, nullptr, 1.0, kInf,
                                 &out_a, &stats, &kth_l2, &pruned)
                        .ok());
    ASSERT_TRUE(b.knn_candidates(ll.lng().degrees(), ll.lat().degrees(), k, nullptr, 1.0, kInf,
                                 &out_b, &stats, &kth_l2, &pruned)
                        .ok());
    std::sort(out_a.begin(), out_a.end());
    std::sort(out_b.begin(), out_b.end());
    ASSERT_EQ(out_a, out_b);
}

} // namespace

TEST(HasiSpliceTest, DirViewMatchesParse) {
    std::mt19937_64 rng(20260717);
    auto slices = disjoint_key_slices(rng, {200});
    Input in = make_input(slices[0], 13, 1);
    Fixture fx;
    fx.init({in}, kLeafRows, true);

    HasiTree tree;
    std::string copy = fx.blobs[0];
    ASSERT_TRUE(tree.parse(std::move(copy)).ok());
    const HasiDirView& v = fx.views[0];
    ASSERT_EQ(tree.num_rows(), v.num_rows);
    ASSERT_EQ(tree.num_leaves(), v.leaves.size());
    ASSERT_EQ(tree.num_nulls(), v.num_nulls);
    ASSERT_EQ(tree.leaf_rows(), v.leaf_rows);
    ASSERT_EQ(2, v.measure_names.size());
    ASSERT_EQ("m0", v.measure_names[0]);
    ASSERT_TRUE(v.has_values);
    ASSERT_EQ(s2_cell_from_key(slices[0].front()), v.hull_min);
    ASSERT_EQ(s2_cell_from_key(slices[0].back()), v.hull_max);

    // Truncated blob -> Corruption, not a crash.
    HasiDirView bad;
    ASSERT_FALSE(hasi_parse_dir_view(blob_read_fn(&fx.blobs[0]), 10, &bad).ok());
}

TEST(HasiSpliceTest, PlanAcceptsDisjointAndOrders) {
    std::mt19937_64 rng(1);
    auto slices = disjoint_key_slices(rng, {150, 100, 80});
    // Present the inputs out of cell order; nulls in the cell-first input only.
    std::vector<Input> ins = {make_input(slices[2], 0, 2), make_input(slices[0], 9, 0),
                              make_input(slices[1], 0, 1)};
    Fixture fx;
    fx.init(ins, kLeafRows, false);

    HasiSplicePlan plan;
    bool eligible = false;
    std::string reason;
    ASSERT_TRUE(hasi_plan_splice(fx.view_ptrs, kLeafRows, kGeoKnnMaxLeaves, &plan, &eligible,
                                 &reason)
                        .ok());
    ASSERT_TRUE(eligible) << reason;
    ASSERT_EQ((std::vector<size_t> {1, 2, 0}), plan.order);
    ASSERT_EQ(150 + 100 + 80 + 9, plan.total_rows);
    ASSERT_FALSE(plan.with_measures);
}

TEST(HasiSpliceTest, PlanRejections) {
    std::mt19937_64 rng(2);
    auto run_plan = [](const std::vector<const HasiDirView*>& views, uint32_t leaf_rows,
                       uint32_t max_leaves, std::string* reason) {
        HasiSplicePlan plan;
        bool eligible = false;
        EXPECT_TRUE(hasi_plan_splice(views, leaf_rows, max_leaves, &plan, &eligible, reason).ok());
        return eligible;
    };
    std::string reason;

    {
        // Overlapping hulls: interleaved key ranks.
        auto slices = disjoint_key_slices(rng, {100, 100});
        std::vector<int64_t> a;
        std::vector<int64_t> b;
        for (size_t i = 0; i < 100; ++i) {
            a.push_back(slices[i % 2][i]);
            b.push_back(slices[(i + 1) % 2][i]);
        }
        std::sort(a.begin(), a.end());
        std::sort(b.begin(), b.end());
        Fixture fx;
        fx.init({make_input(a, 0, 0), make_input(b, 0, 1)}, kLeafRows, false);
        ASSERT_FALSE(run_plan(fx.view_ptrs, kLeafRows, kGeoKnnMaxLeaves, &reason));
        ASSERT_NE(std::string::npos, reason.find("disjoint")) << reason;
    }
    {
        // Equal boundary cell: the merge heap would interleave by iterator order.
        auto slices = disjoint_key_slices(rng, {100, 100});
        std::vector<int64_t> b = slices[1];
        b.insert(b.begin(), slices[0].back());
        Fixture fx;
        fx.init({make_input(slices[0], 0, 0), make_input(b, 0, 1)}, kLeafRows, false);
        ASSERT_FALSE(run_plan(fx.view_ptrs, kLeafRows, kGeoKnnMaxLeaves, &reason));
    }
    {
        // Two NULL-bearing inputs.
        auto slices = disjoint_key_slices(rng, {100, 100});
        Fixture fx;
        fx.init({make_input(slices[0], 3, 0), make_input(slices[1], 2, 1)}, kLeafRows, false);
        ASSERT_FALSE(run_plan(fx.view_ptrs, kLeafRows, kGeoKnnMaxLeaves, &reason));
        ASSERT_NE(std::string::npos, reason.find("NULL")) << reason;
    }
    {
        // NULL-bearing input is not the cell-first input.
        auto slices = disjoint_key_slices(rng, {100, 100});
        Fixture fx;
        fx.init({make_input(slices[0], 0, 0), make_input(slices[1], 5, 1)}, kLeafRows, false);
        ASSERT_FALSE(run_plan(fx.view_ptrs, kLeafRows, kGeoKnnMaxLeaves, &reason));
        ASSERT_NE(std::string::npos, reason.find("first")) << reason;
    }
    {
        // Mixed v1/v2.
        auto slices = disjoint_key_slices(rng, {100, 100});
        std::vector<Input> ins = {make_input(slices[0], 0, 0), make_input(slices[1], 0, 1)};
        std::string blob_v1 = build_blob(ins[0], kLeafRows, false);
        std::string blob_v2 = build_blob(ins[1], kLeafRows, true);
        HasiDirView v1;
        HasiDirView v2;
        ASSERT_TRUE(hasi_parse_dir_view(blob_read_fn(&blob_v1), blob_v1.size(), &v1).ok());
        ASSERT_TRUE(hasi_parse_dir_view(blob_read_fn(&blob_v2), blob_v2.size(), &v2).ok());
        ASSERT_FALSE(run_plan({&v1, &v2}, kLeafRows, kGeoKnnMaxLeaves, &reason));
        ASSERT_NE(std::string::npos, reason.find("version")) << reason;
    }
    {
        // Same measure names, different order: the sketch section is positional.
        auto slices = disjoint_key_slices(rng, {100, 100});
        Fixture fx;
        fx.init({make_input(slices[0], 0, 0), make_input(slices[1], 0, 1)}, kLeafRows, true);
        std::swap(fx.views[1].measure_names[0], fx.views[1].measure_names[1]);
        ASSERT_FALSE(run_plan(fx.view_ptrs, kLeafRows, kGeoKnnMaxLeaves, &reason));
        ASSERT_NE(std::string::npos, reason.find("measure")) << reason;
    }
    {
        // Fragmentation ratchet: 40 tiny inputs at huge leaf_rows.
        std::vector<size_t> sizes(40, 10);
        auto slices = disjoint_key_slices(rng, sizes);
        std::vector<Input> ins;
        for (size_t i = 0; i < slices.size(); ++i) {
            ins.push_back(make_input(slices[i], 0, i));
        }
        Fixture fx;
        fx.init(ins, HasiTreeBuilder::kDefaultLeafRows, false);
        ASSERT_FALSE(run_plan(fx.view_ptrs, HasiTreeBuilder::kDefaultLeafRows, kGeoKnnMaxLeaves,
                              &reason));
        ASSERT_NE(std::string::npos, reason.find("fragmentation")) << reason;
    }
    {
        // kNN leaf cap.
        auto slices = disjoint_key_slices(rng, {100, 100, 100});
        std::vector<Input> ins = {make_input(slices[0], 0, 0), make_input(slices[1], 0, 1),
                                  make_input(slices[2], 0, 2)};
        Fixture fx;
        fx.init(ins, kLeafRows, false);
        ASSERT_FALSE(run_plan(fx.view_ptrs, kLeafRows, /*max_total_leaves=*/2, &reason));
        ASSERT_NE(std::string::npos, reason.find("cap")) << reason;
    }
    {
        // All-NULL input is accepted, forced first, and its rows count.
        auto slices = disjoint_key_slices(rng, {100});
        Input all_null = make_input({}, 17, 0);
        Fixture fx;
        fx.init({make_input(slices[0], 0, 1), all_null}, kLeafRows, false);
        HasiSplicePlan plan;
        bool eligible = false;
        ASSERT_TRUE(hasi_plan_splice(fx.view_ptrs, kLeafRows, kGeoKnnMaxLeaves, &plan, &eligible,
                                     &reason)
                            .ok());
        ASSERT_TRUE(eligible) << reason;
        ASSERT_EQ((std::vector<size_t> {1, 0}), plan.order);
        ASSERT_EQ(117, plan.total_rows);
    }
}

TEST(HasiSpliceTest, SpliceByteIdenticalWhenAligned) {
    // Row counts multiples of leaf_rows: the rebuilt tree's leaf blocks coincide
    // with the inputs', so splice output == full rebuild output byte for byte.
    std::mt19937_64 rng(3);
    auto slices = disjoint_key_slices(rng, {2 * kLeafRows, 3 * kLeafRows, kLeafRows});
    std::vector<Input> ins;
    for (size_t i = 0; i < slices.size(); ++i) {
        ins.push_back(make_input(slices[i], 0, i));
    }
    Fixture fx;
    fx.init(ins, kLeafRows, false);

    HasiSplicePlan plan;
    bool eligible = false;
    std::string reason;
    ASSERT_TRUE(hasi_plan_splice(fx.view_ptrs, kLeafRows, kGeoKnnMaxLeaves, &plan, &eligible,
                                 &reason)
                        .ok());
    ASSERT_TRUE(eligible) << reason;

    std::string spliced;
    ASSERT_TRUE(hasi_splice(plan, fx.view_ptrs, fx.readers, kLeafRows, string_sink(&spliced)).ok());
    const std::string rebuilt = build_blob(concat_inputs(fx.inputs, plan.order), kLeafRows, false);
    ASSERT_EQ(rebuilt, spliced);

    // Single-input splice is a verbatim copy.
    HasiSplicePlan single;
    single.order = {0};
    single.total_rows = fx.views[0].num_rows;
    single.total_leaves = fx.views[0].leaves.size();
    std::string copied;
    ASSERT_TRUE(hasi_splice(single, fx.view_ptrs, fx.readers, kLeafRows, string_sink(&copied)).ok());
    ASSERT_EQ(fx.blobs[0], copied);
}

TEST(HasiSpliceTest, SpliceGeneralTailsQueriesMatchRebuild) {
    // Partial tail leaves: blobs differ from a rebuild, every query result must not.
    std::mt19937_64 rng(4);
    auto slices = disjoint_key_slices(rng, {100, 73, 50});
    std::vector<Input> ins = {make_input(slices[0], 9, 0), make_input(slices[1], 0, 1),
                              make_input(slices[2], 0, 2)};
    Fixture fx;
    fx.init(ins, kLeafRows, false);

    HasiSplicePlan plan;
    bool eligible = false;
    std::string reason;
    ASSERT_TRUE(hasi_plan_splice(fx.view_ptrs, kLeafRows, kGeoKnnMaxLeaves, &plan, &eligible,
                                 &reason)
                        .ok());
    ASSERT_TRUE(eligible) << reason;
    ASSERT_EQ((std::vector<size_t> {0, 1, 2}), plan.order);

    std::string spliced;
    ASSERT_TRUE(hasi_splice(plan, fx.view_ptrs, fx.readers, kLeafRows, string_sink(&spliced)).ok());
    HasiTree spliced_tree;
    ASSERT_TRUE(spliced_tree.parse(std::move(spliced)).ok());
    ASSERT_EQ(plan.total_rows, spliced_tree.num_rows());
    ASSERT_EQ(9, spliced_tree.num_nulls());

    const Input all = concat_inputs(fx.inputs, plan.order);
    HasiTree rebuilt_tree;
    ASSERT_TRUE(rebuilt_tree.parse(build_blob(all, kLeafRows, false)).ok());

    std::vector<std::vector<CellRange>> coverings = {full_sphere_covering(),
                                                     {{fx.views[1].hull_min, fx.views[1].hull_max}},
                                                     {{0, 1}}};
    for (size_t i = 0; i < all.keys.size(); i += 37) {
        if (all.keys[i].has_value()) {
            const uint64_t c = s2_cell_from_key(*all.keys[i]);
            coverings.push_back({{c, c}});
        }
    }
    check_search_equal(spliced_tree, rebuilt_tree, coverings);
    for (size_t i = 9; i < all.keys.size(); i += 41) {
        if (all.keys[i].has_value()) {
            check_knn_equal(spliced_tree, rebuilt_tree, s2_cell_from_key(*all.keys[i]), 7);
        }
    }
}

TEST(HasiSpliceTest, SpliceMeasuresPreserved) {
    std::mt19937_64 rng(5);
    auto slices = disjoint_key_slices(rng, {100, 73, 128});
    std::vector<Input> ins = {make_input(slices[0], 6, 0), make_input(slices[1], 0, 1),
                              make_input(slices[2], 0, 2)};
    Fixture fx;
    fx.init(ins, kLeafRows, true);

    HasiSplicePlan plan;
    bool eligible = false;
    std::string reason;
    ASSERT_TRUE(hasi_plan_splice(fx.view_ptrs, kLeafRows, kGeoKnnMaxLeaves, &plan, &eligible,
                                 &reason)
                        .ok());
    ASSERT_TRUE(eligible) << reason;
    ASSERT_TRUE(plan.with_measures);

    std::string spliced;
    ASSERT_TRUE(hasi_splice(plan, fx.view_ptrs, fx.readers, kLeafRows, string_sink(&spliced)).ok());
    HasiTree tree;
    ASSERT_TRUE(tree.parse(std::move(spliced)).ok());
    ASSERT_EQ(0, tree.measure_index("m0"));
    ASSERT_EQ(1, tree.measure_index("m1"));

    // End-to-end fold over the whole sphere: folded sketches + nothing left over
    // must equal a brute force over the concatenated rows.
    const Input all = concat_inputs(fx.inputs, plan.order);
    roaring::Roaring present;
    present.addRange(0, all.keys.size());
    HasiFoldResult fold;
    ASSERT_TRUE(tree.fold_inside(full_sphere_covering(), {0, 1}, present, &fold).ok());
    roaring::Roaring folded_rows;
    for (const auto& [begin, end] : fold.folded_ranges) {
        folded_rows.addRange(begin, end);
    }
    for (size_t m = 0; m < kNumMeasures; ++m) {
        HasiLeafMeasure expect;
        for (size_t r = 0; r < all.keys.size(); ++r) {
            if (!all.keys[r].has_value() || !folded_rows.contains(static_cast<uint32_t>(r)) ||
                all.val_nulls[r][m] != 0) {
                continue;
            }
            expect.sum += all.vals[r][m];
            expect.min = std::min(expect.min, all.vals[r][m]);
            expect.max = std::max(expect.max, all.vals[r][m]);
            ++expect.non_null;
        }
        ASSERT_EQ(expect.sum, fold.measures[m].sum);
        ASSERT_EQ(expect.min, fold.measures[m].min);
        ASSERT_EQ(expect.max, fold.measures[m].max);
        ASSERT_EQ(expect.non_null, fold.measures[m].non_null);
    }
    // NULL-bearing leaves are never folded; everything else here is.
    ASSERT_GT(fold.folded_rows, 0);
}

TEST(HasiSpliceTest, StreamRebuildMatchesInlineBuildPerSegment) {
    std::mt19937_64 rng(6);
    auto slices = disjoint_key_slices(rng, {100, 73, 50});
    std::vector<Input> ins = {make_input(slices[0], 9, 0), make_input(slices[1], 0, 1),
                              make_input(slices[2], 0, 2)};
    Fixture fx;
    fx.init(ins, kLeafRows, true); // v2 inputs: rebuild output still drops to v1

    HasiSplicePlan plan;
    bool eligible = false;
    std::string reason;
    ASSERT_TRUE(hasi_plan_splice(fx.view_ptrs, kLeafRows, kGeoKnnMaxLeaves, &plan, &eligible,
                                 &reason)
                        .ok());
    ASSERT_TRUE(eligible) << reason;

    // Cuts deliberately misaligned with the input boundaries (109/73/50 rows).
    const std::vector<uint32_t> seg_rows = {90, 80, 62};
    std::vector<std::string> blobs(seg_rows.size());
    ASSERT_TRUE(hasi_stream_rebuild(plan, fx.view_ptrs, fx.readers, kLeafRows, seg_rows,
                                    [&](size_t seg, std::string&& blob) -> Status {
                                        blobs[seg] = std::move(blob);
                                        return Status::OK();
                                    })
                        .ok());

    // Each output segment must be byte-identical to an inline build over its
    // row slice of the concatenated stream (same rows, order, and leaf_rows).
    const Input all = concat_inputs(fx.inputs, plan.order);
    size_t pos = 0;
    for (size_t seg = 0; seg < seg_rows.size(); ++seg) {
        Input slice;
        slice.keys.assign(all.keys.begin() + pos, all.keys.begin() + pos + seg_rows[seg]);
        slice.vals.resize(slice.keys.size());
        slice.val_nulls.resize(slice.keys.size());
        pos += seg_rows[seg];
        ASSERT_EQ(build_blob(slice, kLeafRows, false), blobs[seg]) << "segment " << seg;
    }

    // Mismatched totals are refused outright.
    ASSERT_FALSE(hasi_stream_rebuild(plan, fx.view_ptrs, fx.readers, kLeafRows, {10, 10},
                                     [](size_t, std::string&&) { return Status::OK(); })
                         .ok());
}

TEST(HasiSpliceTest, ExecutionHonorsNonIdentityPlanOrder) {
    // Inputs presented in REVERSED hull order: every splice/rebuild copy loop
    // must follow plan.order, not input-index order. Multiples of leaf_rows so
    // the splice oracle is full byte identity.
    std::mt19937_64 rng(8);
    auto slices = disjoint_key_slices(rng, {2 * kLeafRows, kLeafRows, 3 * kLeafRows});
    std::vector<Input> ins = {make_input(slices[2], 0, 0), make_input(slices[1], 0, 1),
                              make_input(slices[0], 0, 2)};
    Fixture fx;
    fx.init(ins, kLeafRows, true);

    HasiSplicePlan plan;
    bool eligible = false;
    std::string reason;
    ASSERT_TRUE(hasi_plan_splice(fx.view_ptrs, kLeafRows, kGeoKnnMaxLeaves, &plan, &eligible,
                                 &reason)
                        .ok());
    ASSERT_TRUE(eligible) << reason;
    ASSERT_EQ((std::vector<size_t> {2, 1, 0}), plan.order);

    std::string spliced;
    ASSERT_TRUE(hasi_splice(plan, fx.view_ptrs, fx.readers, kLeafRows, string_sink(&spliced)).ok());
    const Input all = concat_inputs(fx.inputs, plan.order);
    ASSERT_EQ(build_blob(all, kLeafRows, true), spliced);

    // Stream-rebuild across a misaligned cut must decode in plan order too.
    const uint32_t total = static_cast<uint32_t>(all.keys.size());
    const std::vector<uint32_t> seg_rows = {total / 2 + 7, total - (total / 2 + 7)};
    std::vector<std::string> blobs(seg_rows.size());
    ASSERT_TRUE(hasi_stream_rebuild(plan, fx.view_ptrs, fx.readers, kLeafRows, seg_rows,
                                    [&](size_t seg, std::string&& blob) -> Status {
                                        blobs[seg] = std::move(blob);
                                        return Status::OK();
                                    })
                        .ok());
    size_t pos = 0;
    for (size_t seg = 0; seg < seg_rows.size(); ++seg) {
        Input slice;
        slice.keys.assign(all.keys.begin() + pos, all.keys.begin() + pos + seg_rows[seg]);
        slice.vals.resize(slice.keys.size());
        slice.val_nulls.resize(slice.keys.size());
        pos += seg_rows[seg];
        ASSERT_EQ(build_blob(slice, kLeafRows, false), blobs[seg]) << "segment " << seg;
    }
}

TEST(HasiSpliceTest, EmptyInputNextToNullBearingInputStillRejects) {
    // Regression for the null_bearing sentinel collision: with an empty input
    // dropped from the candidate set, a NULL-bearing input whose INDEX equals
    // the candidate count must still be forced to sort first.
    std::mt19937_64 rng(9);
    auto slices = disjoint_key_slices(rng, {80, 60, 50});
    Input empty;
    // inputs: [empty, hull0, hull1, NULL-bearing hull2] -> candidates {1,2,3},
    // null_bearing index 3 == candidates.size() with the buggy sentinel.
    std::vector<Input> ins = {empty, make_input(slices[0], 0, 0), make_input(slices[1], 0, 1),
                              make_input(slices[2], 5, 2)};
    Fixture fx;
    fx.init(ins, kLeafRows, false);

    HasiSplicePlan plan;
    bool eligible = false;
    std::string reason;
    ASSERT_TRUE(hasi_plan_splice(fx.view_ptrs, kLeafRows, kGeoKnnMaxLeaves, &plan, &eligible,
                                 &reason)
                        .ok());
    ASSERT_FALSE(eligible);
    ASSERT_NE(std::string::npos, reason.find("first")) << reason;

    // Same shape but the NULL-bearing input sorts first: accepted, empty dropped.
    std::vector<Input> ok_ins = {empty, make_input(slices[0], 5, 0), make_input(slices[1], 0, 1),
                                 make_input(slices[2], 0, 2)};
    Fixture fx2;
    fx2.init(ok_ins, kLeafRows, false);
    ASSERT_TRUE(hasi_plan_splice(fx2.view_ptrs, kLeafRows, kGeoKnnMaxLeaves, &plan, &eligible,
                                 &reason)
                        .ok());
    ASSERT_TRUE(eligible) << reason;
    ASSERT_EQ((std::vector<size_t> {1, 2, 3}), plan.order);
}

TEST(HasiSpliceTest, SentinelLeavesSurviveSplice) {
    // Enough leading NULLs to seal whole all-null leaves: their [UINT64_MAX, 0]
    // sentinel entries must pass through the splice untouched.
    std::mt19937_64 rng(7);
    auto slices = disjoint_key_slices(rng, {40, 60});
    std::vector<Input> ins = {make_input(slices[0], 2 * kLeafRows + 5, 0),
                              make_input(slices[1], 0, 1)};
    Fixture fx;
    fx.init(ins, kLeafRows, false);
    ASSERT_GT(fx.views[0].num_nulls, 0);
    ASSERT_TRUE(fx.views[0].leaves[0].min_cell > fx.views[0].leaves[0].max_cell);

    HasiSplicePlan plan;
    bool eligible = false;
    std::string reason;
    ASSERT_TRUE(hasi_plan_splice(fx.view_ptrs, kLeafRows, kGeoKnnMaxLeaves, &plan, &eligible,
                                 &reason)
                        .ok());
    ASSERT_TRUE(eligible) << reason;

    std::string spliced;
    ASSERT_TRUE(hasi_splice(plan, fx.view_ptrs, fx.readers, kLeafRows, string_sink(&spliced)).ok());
    HasiTree tree;
    ASSERT_TRUE(tree.parse(std::move(spliced)).ok());
    ASSERT_EQ(2 * kLeafRows + 5, tree.num_nulls());

    // kNN must skip the sentinels and still terminate with exact results.
    const Input all = concat_inputs(fx.inputs, plan.order);
    HasiTree rebuilt;
    ASSERT_TRUE(rebuilt.parse(build_blob(all, kLeafRows, false)).ok());
    check_knn_equal(tree, rebuilt, s2_cell_from_key(slices[1][30]), 5);
    check_search_equal(tree, rebuilt, {full_sphere_covering()});
}

} // namespace doris::segment_v2
