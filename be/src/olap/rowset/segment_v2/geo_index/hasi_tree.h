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
#include <limits>
#include <roaring/roaring.hh>
#include <string>
#include <vector>

#include "common/status.h"
#include "olap/rowset/segment_v2/geo_index/s2_covering.h"

namespace doris::segment_v2 {

// HASI v1 on-disk structure (design doc HASI_POC.md §4.2, v1 subset).
//
// A flat leaf directory over the segment's rows in rowid order: every leaf covers a
// fixed-size rowid block (`leaf_rows` rows, last block partial) and records the
// min/max raw S2 leaf-cell id of its rows plus a per-row cell stream
// (zigzag-varint deltas). This one format serves both layouts:
//   - clustered __s2 (DUP key prefix / MOW cluster key): leaves have tight, nearly
//     disjoint cell ranges -> whole-leaf skip (range ∩ C = ∅) and whole-leaf accept
//     (range ⊆ some I range) fire, so classification cost ∝ leaves, not rows;
//   - non-key __s2: leaf ranges are wide, every intersecting leaf degrades to a
//     per-row three-way test on the stored cells -- the pure predicate-filter form.
// The implicit F-ary pyramid of the design doc only pays off once sketches hang off
// internal nodes; it lands with v2a. Leaf blocks are NOT split at distinct-cell
// boundaries in v1 (that invariant is only needed for pyramid sketch disjointness):
// overlapping leaf ranges merely degrade a leaf to per-row testing, never break
// correctness.
//
// Search contract (contract C1: callers may only use the result to narrow bitmaps):
//   hit == { rid : cell(rid) != NULL && cell(rid) ∈ covering }
// Interior ranges only accelerate (whole-leaf accept) and attribute stats; because
// I ⊆ region ⊆ C as point sets in the leaf keyspace, they never change the result.
// NULL rows never hit: the caller guarantees (FE-side matching of the generated
// column expression) that a NULL cell implies the residual ST_* predicate evaluates
// to non-true for that row.

struct HasiSearchStats {
    uint64_t leaves_skipped = 0;  // leaf range ∩ covering = ∅, not decoded
    uint64_t leaves_inside = 0;   // whole leaf accepted without decoding
    uint64_t leaves_boundary = 0; // decoded and tested per row
    uint64_t rows_inside = 0;     // accepted because cell ∈ interior
    uint64_t rows_margin = 0;     // kept for the residual predicate to decide
    uint64_t rows_rejected = 0;   // dropped because cell ∉ covering
};

// Per-leaf fixed-size sketch of one numeric measure (v2b core, format version 2).
// NULL semantics follow NodeAgg (§4.2): sum/min/max skip NULL measure values,
// non_null counts the rest; rows whose GEO cell is NULL never enter the sketch
// (the builder tracks null-cell rids and drops their measures itself).
struct HasiLeafMeasure {
    double sum = 0;
    double min = std::numeric_limits<double>::infinity();
    double max = -std::numeric_limits<double>::infinity();
    uint32_t non_null = 0;
};

// Streaming single-pass builder (O(1) state per open leaf, no row buffering).
// Feed rows strictly in rowid order; add_value takes the __s2 column value
// (sign-flipped BIGINT domain, see s2_key_from_cell).
//
// v2b measure flow (default build site = compaction read-back, §3.5): after all
// cells are fed, finish_topology() seals the leaf directory in memory,
// attach_measures() declares the measure set, add_measure_row() streams measure
// values in rid order, and serialize() writes the whole structure once. The v1
// finish(out) remains as finish_topology()+serialize() and emits format version 1
// when no measures were attached (bit-identical to pre-v2b files).
class HasiTreeBuilder {
public:
    static constexpr uint32_t kMinLeafRows = 64;
    static constexpr uint32_t kMaxLeafRows = 1 << 22;
    static constexpr uint32_t kDefaultLeafRows = 65536;
    static constexpr uint32_t kMaxMeasures = 64;

    explicit HasiTreeBuilder(uint32_t leaf_rows);

    void add_value(int64_t cell_key);
    void add_nulls(uint32_t count);

    uint32_t num_rows() const { return _num_rows; }

    // Seals the last leaf; the topology stays in memory for measure attachment.
    void finish_topology();

    // Declares the measures that will be streamed; callable any time before the
    // first add_measure_row().
    Status attach_measures(const std::vector<std::string>& measure_names);

    // Streams one row's measure values (values[i] valid iff nulls[i] == 0), rid
    // strictly increasing; rids may be skipped (skipped rows count as all-NULL).
    // Because leaves are fixed-size rid blocks, this may interleave with the cell
    // feed -- but a given row's measures must arrive AFTER its cell (the NULL-cell
    // filter depends on it; segment writers append column data first, so this holds
    // naturally there).
    Status add_measure_row(uint32_t rid, const double* values, const uint8_t* nulls);

    // Rows fed through add_measure_row; the writer drops the measures section
    // (serializes as v1) unless this equals the indexed row count.
    uint32_t measure_rows_fed() const { return _measure_rows_fed; }
    bool has_measures_attached() const { return !_measure_names.empty(); }
    void drop_measures() {
        _measure_names.clear();
        _measures.clear();
    }

    // Serializes everything. The builder must not be reused afterwards.
    Status serialize(std::string* out);

    // v1 convenience: finish_topology() + serialize().
    Status finish(std::string* out);

private:
    void _seal_leaf();
    void _append_cell(uint64_t raw_cell);

    struct LeafAccum {
        uint64_t min_cell = 0;
        uint64_t max_cell = 0;
        uint32_t rows = 0;
        uint32_t null_count = 0;
        uint64_t prev_cell = 0; // delta base for the cell stream
        bool has_value = false;
    };

    uint32_t _leaf_rows;
    uint32_t _num_rows = 0;
    LeafAccum _cur;
    std::string _dir;   // serialized directory entries, appended per sealed leaf
    std::string _cells; // serialized per-row cell streams
    uint32_t _num_leaves = 0;
    uint64_t _cur_cells_offset = 0; // offset of the open leaf's stream within _cells
    bool _topology_done = false;
    roaring::Roaring _null_rids; // rows with NULL geo cell; their measures are ignored
    std::vector<std::string> _measure_names;
    std::vector<HasiLeafMeasure> _measures; // [leaf][measure], row-major per leaf
    uint32_t _last_measure_rid = 0;
    uint32_t _measure_rows_fed = 0;
    bool _measure_seen = false;
};

// Loaded, immutable index. parse() takes ownership of the serialized buffer; the
// leaf directory is decoded eagerly (36 B/leaf), cell streams decode lazily per
// boundary leaf during search.
class HasiTree {
public:
    Status parse(std::string&& data);

    // covering/interior: sorted, disjoint, closed ranges in the RAW uint64 leaf-cell
    // keyspace (S2Covering::cover output). hit is overwritten, not narrowed -- the
    // caller intersects it into its own bitmap (contract C1).
    //
    // margin_out selects the result mode (v1.5 exact filtering, HASI_POC.md §7 v1.5):
    //   nullptr:  hit == { rid : cell != NULL && cell ∈ C }  (superset; margin rows
    //             included, the residual predicate decides them)
    //   non-null: hit == { rid : cell ∈ I } (definite hits only); rows with
    //             cell ∈ C∖I are appended to margin_out as (rid, raw cell) for the
    //             caller to resolve with the exact kernel.
    Status search(const std::vector<CellRange>& covering, const std::vector<CellRange>& interior,
                  roaring::Roaring* hit, HasiSearchStats* stats,
                  std::vector<std::pair<uint32_t, uint64_t>>* margin_out = nullptr) const;

    uint32_t num_rows() const { return _num_rows; }
    uint32_t num_leaves() const { return static_cast<uint32_t>(_leaves.size()); }
    uint32_t leaf_rows() const { return _leaf_rows; }

    // ---- v2b measure sketches (format version 2) ----
    bool has_measures() const { return !_measure_names.empty(); }
    // Index of a measure by (case-sensitive) name, -1 if absent.
    int measure_index(const std::string& name) const;

    // Aggregates one measure over the region (contract C3 gates are the CALLER's
    // job -- delete bitmaps, residual predicates, table model):
    //   - leaves fully inside the interior contribute their sketch O(1) (all their
    //     value rows are provably in the region; leaf NULL-cell rows never entered
    //     the sketch);
    //   - value rows of leaves overlapping the covering but not fully inside are
    //     appended to boundary_rids (cells ∈ C; the caller folds them row-wise with
    //     exact geometry + real measure values);
    //   - rows outside the covering contribute nothing.
    // inside_rows counts the sketch-covered rows (count(*) contribution).
    Status aggregate_inside(const std::vector<CellRange>& covering,
                            const std::vector<CellRange>& interior, int measure_idx,
                            HasiLeafMeasure* inside_agg, uint64_t* inside_rows,
                            std::vector<uint32_t>* boundary_rids, HasiSearchStats* stats) const;

private:
    struct Leaf {
        uint64_t min_cell;
        uint64_t max_cell;
        uint32_t rid_begin;
        uint32_t rid_end; // exclusive
        uint32_t null_count;
        uint64_t cells_offset; // into the cells section
    };

    Status _decode_leaf_cells(const Leaf& leaf, std::vector<uint64_t>* cells) const;

    HasiLeafMeasure _leaf_measure(uint32_t leaf_idx, uint32_t measure_idx) const;

    std::string _data;
    uint32_t _leaf_rows = 0;
    uint32_t _num_rows = 0;
    std::vector<Leaf> _leaves;
    const uint8_t* _cells_base = nullptr;
    size_t _cells_len = 0;
    std::vector<std::string> _measure_names;
    const uint8_t* _leaf_measures = nullptr; // [leaf][measure], kLeafMeasureSize each
};

} // namespace doris::segment_v2
