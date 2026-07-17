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
#include <functional>
#include <string>
#include <vector>

#include "common/status.h"

namespace doris::segment_v2 {

// HASI v3 compaction splice (HASI_POC.md §12): when a compaction's input segments
// carry strictly disjoint cell ranges (plus the other arming conditions checked by
// hasi_plan_splice), the output segment's index is the byte-level concatenation of
// the input indexes -- leaf directory entries rebased by constant rid/offset
// deltas, per-leaf cell streams copied verbatim (each leaf's delta stream is
// self-contained), and v2 sketch rows concatenated in the same leaf order.
//
// Everything here is pure over two callback types so the same code runs against
// CLucene IndexInput/IndexOutput in compaction and plain strings in unit tests.

// Reads `len` bytes at `offset` of one serialized HASI blob into `out`.
using HasiReadFn = std::function<Status(uint64_t offset, size_t len, uint8_t* out)>;
// Appends `len` bytes to the output blob being built.
using HasiSinkFn = std::function<Status(const uint8_t* data, size_t len)>;

// Directory-only view of one input index: header + leaf directory + measure
// names. Cell-stream bytes stay behind the read callback until splice time, so
// arming a compaction never slurps the (row-proportional) cells section.
struct HasiDirView {
    struct Leaf {
        uint64_t min_cell;
        uint64_t max_cell;
        uint32_t rid_begin;
        uint32_t rid_end; // exclusive
        uint32_t null_count;
        uint64_t cells_offset; // into the cells section
    };

    uint32_t version = 0;
    uint32_t leaf_rows = 0;
    uint32_t num_rows = 0;
    std::vector<Leaf> leaves;
    std::vector<std::string> measure_names;
    uint64_t file_len = 0;
    uint64_t cells_begin = 0;  // file offset of the cells section
    uint64_t cells_len = 0;    // bytes of per-row cell streams
    uint64_t sketch_begin = 0; // file offset of the sketch rows (v2 only)

    // Derived at parse time.
    uint64_t num_nulls = 0;
    bool has_values = false; // any non-sentinel leaf
    uint64_t hull_min = 0;   // over value leaves only; valid iff has_values
    uint64_t hull_max = 0;
};

// Parses header + directory + (v2) measure trailer through ranged reads,
// enforcing the same invariants as HasiTree::parse.
Status hasi_parse_dir_view(const HasiReadFn& read, uint64_t file_len, HasiDirView* out);

struct HasiSplicePlan {
    // Indices into the caller's input vector, in concatenation (cell) order;
    // empty inputs are dropped.
    std::vector<size_t> order;
    uint64_t total_rows = 0;
    uint64_t total_leaves = 0;
    bool with_measures = false; // all inputs v2 with element-wise equal name lists
    std::vector<std::string> measure_names;
};

// Pure metadata eligibility check (HASI_POC.md §12.2 arming conditions that are
// decidable from the blobs alone; table-model/delete/overlap gates are the
// caller's job). A rejection is not an error: `*eligible` comes back false with
// a reason. Conditions enforced here:
//   - all non-empty inputs share one format version; v2 inputs must agree on the
//     ordered measure-name vector (per-blob trailer, not index properties);
//   - at most one input has NULL rows, and it must sort first (NULL keys sort
//     before every value globally); all-NULL inputs count as NULL-bearing and
//     have no hull;
//   - value hulls (over non-sentinel leaves) strictly disjoint in sorted order:
//     prev.hull_max < next.hull_min (equal boundary cells would be interleaved
//     by the merge heap's iterator-order tie-break);
//   - Σrows fits u32; Σleaves <= max_total_leaves (kNN pushdown cliff) and
//     <= 4 x ceil(Σrows / nominal_leaf_rows) (fragmentation ratchet).
Status hasi_plan_splice(const std::vector<const HasiDirView*>& inputs, uint32_t nominal_leaf_rows,
                        uint32_t max_total_leaves, HasiSplicePlan* plan, bool* eligible,
                        std::string* reject_reason);

// Byte-level splice of the planned inputs into ONE output blob (one output
// segment). Cell streams are copied in bounded chunks, never decoded.
// `out_leaf_rows_header` is advisory (no read path consumes it); pass the
// current index-property value.
Status hasi_splice(const HasiSplicePlan& plan, const std::vector<const HasiDirView*>& inputs,
                   const std::vector<HasiReadFn>& readers, uint32_t out_leaf_rows_header,
                   const HasiSinkFn& sink);

// Fallback when the merge cut the output at rows that do not align with input
// segment boundaries: decode the input cell streams in plan order and re-feed a
// fresh builder per output segment (fixed leaf_rows blocks, v1 output --
// sketches cannot be split, so they are dropped). Row order is still the plan
// concatenation (disjointness was proven), so the result is exactly what the
// inline build would have produced sans measures.
Status hasi_stream_rebuild(const HasiSplicePlan& plan,
                           const std::vector<const HasiDirView*>& inputs,
                           const std::vector<HasiReadFn>& readers, uint32_t leaf_rows,
                           const std::vector<uint32_t>& out_segment_rows,
                           const std::function<Status(size_t seg_idx, std::string&& blob)>& emit);

} // namespace doris::segment_v2
