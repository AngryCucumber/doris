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

#include <algorithm>
#include <limits>

#include "olap/rowset/segment_v2/geo_index/hasi_format.h"
#include "olap/rowset/segment_v2/geo_index/hasi_tree.h"
#include "olap/rowset/segment_v2/geo_index/s2_covering.h"

namespace doris::segment_v2 {

using namespace hasi_fmt; // NOLINT(google-build-using-namespace)

namespace {

constexpr size_t kCopyChunk = 1 << 20; // 1 MiB per read while streaming cell bytes

bool is_sentinel(const HasiDirView::Leaf& leaf) {
    // All-null leaves store the inverted range [UINT64_MAX, 0] (hasi_tree.cpp
    // _seal_leaf); keep it verbatim through every splice computation.
    return leaf.min_cell > leaf.max_cell;
}

Status copy_range(const HasiReadFn& read, uint64_t offset, uint64_t len, const HasiSinkFn& sink) {
    std::string buf;
    uint64_t done = 0;
    while (done < len) {
        const size_t chunk = static_cast<size_t>(std::min<uint64_t>(len - done, kCopyChunk));
        buf.resize(chunk);
        RETURN_IF_ERROR(read(offset + done, chunk, reinterpret_cast<uint8_t*>(buf.data())));
        RETURN_IF_ERROR(sink(reinterpret_cast<const uint8_t*>(buf.data()), chunk));
        done += chunk;
    }
    return Status::OK();
}

} // namespace

Status hasi_parse_dir_view(const HasiReadFn& read, uint64_t file_len, HasiDirView* out) {
    *out = HasiDirView();
    out->file_len = file_len;
    if (file_len < kHeaderSize) {
        return Status::Corruption("hasi index too small: {} bytes", file_len);
    }
    uint8_t header[kHeaderSize];
    RETURN_IF_ERROR(read(0, kHeaderSize, header));
    if (get_u32(header) != kMagic) {
        return Status::Corruption("hasi index bad magic");
    }
    out->version = get_u32(header + 4);
    if (out->version != kVersionV1 && out->version != kVersionV2) {
        return Status::Corruption("hasi index unsupported version {}", out->version);
    }
    out->leaf_rows = get_u32(header + 12);
    out->num_rows = get_u32(header + 16);
    const uint32_t num_leaves = get_u32(header + 20);
    const uint64_t dir_end = kHeaderSize + static_cast<uint64_t>(num_leaves) * kDirEntrySize;
    if (file_len < dir_end) {
        return Status::Corruption("hasi index truncated directory: {} leaves, {} bytes",
                                  num_leaves, file_len);
    }
    out->cells_begin = dir_end;
    out->cells_len = file_len - dir_end;
    if (out->version == kVersionV2) {
        // trailer: [u32 n][names][n*num_leaves sketch rows][u64 measures_offset]
        if (file_len < dir_end + 8) {
            return Status::Corruption("hasi v2 index missing measures trailer");
        }
        uint8_t tail[8];
        RETURN_IF_ERROR(read(file_len - 8, 8, tail));
        const uint64_t measures_offset = get_u64(tail);
        if (measures_offset < dir_end || measures_offset + 4 > file_len - 8) {
            return Status::Corruption("hasi v2 bad measures offset {}", measures_offset);
        }
        out->cells_len = measures_offset - dir_end;
        uint64_t pos = measures_offset;
        uint8_t u32buf[4];
        RETURN_IF_ERROR(read(pos, 4, u32buf));
        pos += 4;
        const uint32_t num_measures = get_u32(u32buf);
        if (num_measures == 0 || num_measures > HasiTreeBuilder::kMaxMeasures) {
            return Status::Corruption("hasi v2 bad measure count {}", num_measures);
        }
        for (uint32_t m = 0; m < num_measures; ++m) {
            if (pos + 4 > file_len - 8) {
                return Status::Corruption("hasi v2 truncated measure names");
            }
            RETURN_IF_ERROR(read(pos, 4, u32buf));
            pos += 4;
            const uint32_t len = get_u32(u32buf);
            if (len > 256 || pos + len > file_len - 8) {
                return Status::Corruption("hasi v2 bad measure name length {}", len);
            }
            std::string name(len, '\0');
            if (len > 0) {
                RETURN_IF_ERROR(read(pos, len, reinterpret_cast<uint8_t*>(name.data())));
            }
            pos += len;
            out->measure_names.push_back(std::move(name));
        }
        out->sketch_begin = pos;
        const uint64_t sketch_bytes =
                static_cast<uint64_t>(num_leaves) * num_measures * kLeafMeasureSize;
        if (pos + sketch_bytes != file_len - 8) {
            return Status::Corruption("hasi v2 sketch section size mismatch");
        }
    }
    // Directory entries, validated like HasiTree::parse.
    std::string dir_buf(static_cast<size_t>(num_leaves) * kDirEntrySize, '\0');
    if (!dir_buf.empty()) {
        RETURN_IF_ERROR(
                read(kHeaderSize, dir_buf.size(), reinterpret_cast<uint8_t*>(dir_buf.data())));
    }
    out->leaves.reserve(num_leaves);
    uint32_t expect_rid = 0;
    for (uint32_t i = 0; i < num_leaves; ++i) {
        const auto* p = reinterpret_cast<const uint8_t*>(dir_buf.data()) +
                        static_cast<size_t>(i) * kDirEntrySize;
        HasiDirView::Leaf leaf;
        leaf.min_cell = get_u64(p);
        leaf.max_cell = get_u64(p + 8);
        leaf.rid_begin = get_u32(p + 16);
        leaf.rid_end = get_u32(p + 20);
        leaf.null_count = get_u32(p + 24);
        leaf.cells_offset = get_u64(p + 28);
        if (leaf.rid_begin != expect_rid || leaf.rid_end <= leaf.rid_begin ||
            leaf.rid_end > out->num_rows || leaf.null_count > leaf.rid_end - leaf.rid_begin ||
            leaf.cells_offset > out->cells_len) {
            return Status::Corruption("hasi index bad leaf {}: rid [{}, {}), offset {}", i,
                                      leaf.rid_begin, leaf.rid_end, leaf.cells_offset);
        }
        expect_rid = leaf.rid_end;
        out->num_nulls += leaf.null_count;
        if (!is_sentinel(leaf)) {
            if (!out->has_values) {
                out->hull_min = leaf.min_cell;
                out->hull_max = leaf.max_cell;
                out->has_values = true;
            } else {
                out->hull_min = std::min(out->hull_min, leaf.min_cell);
                out->hull_max = std::max(out->hull_max, leaf.max_cell);
            }
        }
        out->leaves.push_back(leaf);
    }
    if (expect_rid != out->num_rows) {
        return Status::Corruption("hasi index leaf coverage {} != num_rows {}", expect_rid,
                                  out->num_rows);
    }
    return Status::OK();
}

Status hasi_plan_splice(const std::vector<const HasiDirView*>& inputs, uint32_t nominal_leaf_rows,
                        uint32_t max_total_leaves, HasiSplicePlan* plan, bool* eligible,
                        std::string* reject_reason) {
    *plan = HasiSplicePlan();
    *eligible = false;
    reject_reason->clear();
    if (nominal_leaf_rows == 0) {
        return Status::InvalidArgument("nominal_leaf_rows must be positive");
    }
    std::vector<size_t> candidates;
    for (size_t i = 0; i < inputs.size(); ++i) {
        if (inputs[i] == nullptr) {
            return Status::InvalidArgument("null dir view at input {}", i);
        }
        if (inputs[i]->num_rows > 0) {
            candidates.push_back(i);
        }
    }
    if (candidates.empty()) {
        *reject_reason = "no input rows";
        return Status::OK();
    }
    const uint32_t version = inputs[candidates[0]]->version;
    // Sentinel: none. Must be inputs.size(), NOT candidates.size() -- empty
    // inputs are dropped from `candidates`, so candidates.size() can equal a
    // real input index and silently disable the NULL-ordering gates below.
    size_t null_bearing = inputs.size();
    for (size_t idx : candidates) {
        const HasiDirView& v = *inputs[idx];
        if (v.version != version) {
            *reject_reason = "mixed format versions";
            return Status::OK();
        }
        if (version == kVersionV2 &&
            v.measure_names != inputs[candidates[0]]->measure_names) {
            // Element-wise ordered equality: the sketch section is positional.
            *reject_reason = "measure name lists differ";
            return Status::OK();
        }
        if (v.num_nulls > 0) {
            if (null_bearing != inputs.size()) {
                *reject_reason = "more than one input has NULL rows";
                return Status::OK();
            }
            null_bearing = idx;
        }
    }
    // Concat order: an all-NULL input (no value hull) sorts first -- its rows are
    // all NULL keys, globally smallest; value inputs sort by hull_min.
    std::sort(candidates.begin(), candidates.end(), [&](size_t a, size_t b) {
        const HasiDirView& va = *inputs[a];
        const HasiDirView& vb = *inputs[b];
        if (va.has_values != vb.has_values) {
            return !va.has_values;
        }
        if (!va.has_values) {
            return a < b;
        }
        return va.hull_min < vb.hull_min;
    });
    for (size_t i = 0; i + 1 < candidates.size(); ++i) {
        const HasiDirView& prev = *inputs[candidates[i]];
        const HasiDirView& next = *inputs[candidates[i + 1]];
        if (!prev.has_values) {
            if (!next.has_values) {
                // Two all-NULL inputs would both be NULL-bearing; unreachable
                // after the <=1 NULL-bearing check, kept for clarity.
                *reject_reason = "more than one all-NULL input";
                return Status::OK();
            }
            continue;
        }
        // Strict: equal boundary cells are interleaved by the merge heap's
        // iterator-order tie-break, which is version order, not cell order.
        if (prev.hull_max >= next.hull_min) {
            *reject_reason = "input cell hulls not strictly disjoint";
            return Status::OK();
        }
    }
    // NULL keys sort before every value key, so the NULL-bearing input's rows
    // lead the merged stream only if that input is the concat head.
    if (null_bearing != inputs.size() && candidates[0] != null_bearing) {
        *reject_reason = "NULL-bearing input does not sort first";
        return Status::OK();
    }
    uint64_t total_rows = 0;
    uint64_t total_leaves = 0;
    for (size_t idx : candidates) {
        total_rows += inputs[idx]->num_rows;
        total_leaves += inputs[idx]->leaves.size();
    }
    if (total_rows > std::numeric_limits<uint32_t>::max()) {
        *reject_reason = "total rows exceed u32";
        return Status::OK();
    }
    if (total_leaves > max_total_leaves) {
        *reject_reason = "total leaves exceed the kNN pushdown cap";
        return Status::OK();
    }
    const uint64_t packed_leaves = (total_rows + nominal_leaf_rows - 1) / nominal_leaf_rows;
    if (total_leaves > 4 * std::max<uint64_t>(packed_leaves, 1)) {
        // Fragmentation ratchet: repeated splices of small loads keep every
        // input's partial tail leaf; force a consolidating rebuild eventually.
        *reject_reason = "leaf fragmentation exceeds 4x the packed count";
        return Status::OK();
    }
    plan->order = std::move(candidates);
    plan->total_rows = total_rows;
    plan->total_leaves = total_leaves;
    plan->with_measures = version == kVersionV2;
    if (plan->with_measures) {
        plan->measure_names = inputs[plan->order[0]]->measure_names;
    }
    *eligible = true;
    return Status::OK();
}

Status hasi_splice(const HasiSplicePlan& plan, const std::vector<const HasiDirView*>& inputs,
                   const std::vector<HasiReadFn>& readers, uint32_t out_leaf_rows_header,
                   const HasiSinkFn& sink) {
    if (readers.size() != inputs.size()) {
        return Status::InvalidArgument("readers/inputs size mismatch");
    }
    uint64_t cells_total = 0;
    for (size_t idx : plan.order) {
        cells_total += inputs[idx]->cells_len;
    }
    // Header + rebased directory (36 B/leaf, bounded by the arming leaf cap).
    std::string head;
    head.reserve(kHeaderSize + plan.total_leaves * kDirEntrySize);
    put_u32(&head, kMagic);
    put_u32(&head, plan.with_measures ? kVersionV2 : kVersionV1);
    put_u32(&head, 0); // flags, reserved
    put_u32(&head, out_leaf_rows_header);
    put_u32(&head, static_cast<uint32_t>(plan.total_rows));
    put_u32(&head, static_cast<uint32_t>(plan.total_leaves));
    uint64_t rid_off = 0;
    uint64_t cells_off = 0;
    for (size_t idx : plan.order) {
        const HasiDirView& v = *inputs[idx];
        for (const auto& leaf : v.leaves) {
            put_u64(&head, leaf.min_cell); // sentinel [UINT64_MAX, 0] kept verbatim
            put_u64(&head, leaf.max_cell);
            put_u32(&head, static_cast<uint32_t>(leaf.rid_begin + rid_off));
            put_u32(&head, static_cast<uint32_t>(leaf.rid_end + rid_off));
            put_u32(&head, leaf.null_count);
            put_u64(&head, leaf.cells_offset + cells_off);
        }
        rid_off += v.num_rows;
        cells_off += v.cells_len;
    }
    RETURN_IF_ERROR(sink(reinterpret_cast<const uint8_t*>(head.data()), head.size()));
    for (size_t idx : plan.order) {
        const HasiDirView& v = *inputs[idx];
        RETURN_IF_ERROR(copy_range(readers[idx], v.cells_begin, v.cells_len, sink));
    }
    if (plan.with_measures) {
        std::string trailer;
        put_u32(&trailer, static_cast<uint32_t>(plan.measure_names.size()));
        for (const auto& name : plan.measure_names) {
            put_u32(&trailer, static_cast<uint32_t>(name.size()));
            trailer.append(name);
        }
        RETURN_IF_ERROR(sink(reinterpret_cast<const uint8_t*>(trailer.data()), trailer.size()));
        for (size_t idx : plan.order) {
            const HasiDirView& v = *inputs[idx];
            const uint64_t sketch_bytes = static_cast<uint64_t>(v.leaves.size()) *
                                          plan.measure_names.size() * kLeafMeasureSize;
            RETURN_IF_ERROR(copy_range(readers[idx], v.sketch_begin, sketch_bytes, sink));
        }
        std::string tail;
        put_u64(&tail, kHeaderSize + plan.total_leaves * kDirEntrySize + cells_total);
        RETURN_IF_ERROR(sink(reinterpret_cast<const uint8_t*>(tail.data()), tail.size()));
    }
    return Status::OK();
}

Status hasi_stream_rebuild(const HasiSplicePlan& plan,
                           const std::vector<const HasiDirView*>& inputs,
                           const std::vector<HasiReadFn>& readers, uint32_t leaf_rows,
                           const std::vector<uint32_t>& out_segment_rows,
                           const std::function<Status(size_t seg_idx, std::string&& blob)>& emit) {
    if (readers.size() != inputs.size()) {
        return Status::InvalidArgument("readers/inputs size mismatch");
    }
    uint64_t out_total = 0;
    for (uint32_t rows : out_segment_rows) {
        out_total += rows;
    }
    if (out_total != plan.total_rows) {
        return Status::InvalidArgument("output segment rows {} != planned rows {}", out_total,
                                       plan.total_rows);
    }
    size_t seg_idx = 0;
    while (seg_idx < out_segment_rows.size() && out_segment_rows[seg_idx] == 0) {
        RETURN_IF_ERROR(emit(seg_idx, std::string()));
        ++seg_idx;
    }
    auto builder = std::make_unique<HasiTreeBuilder>(leaf_rows);
    uint32_t seg_rows_left = seg_idx < out_segment_rows.size() ? out_segment_rows[seg_idx] : 0;
    auto feed = [&](uint64_t raw_cell) -> Status {
        if (seg_rows_left == 0) {
            return Status::InternalError("row feed overruns the output segments");
        }
        if (raw_cell == 0) {
            builder->add_nulls(1);
        } else {
            builder->add_value(s2_key_from_cell(raw_cell));
        }
        if (--seg_rows_left == 0) {
            std::string blob;
            RETURN_IF_ERROR(builder->finish(&blob));
            RETURN_IF_ERROR(emit(seg_idx, std::move(blob)));
            ++seg_idx;
            while (seg_idx < out_segment_rows.size() && out_segment_rows[seg_idx] == 0) {
                RETURN_IF_ERROR(emit(seg_idx, std::string()));
                ++seg_idx;
            }
            if (seg_idx < out_segment_rows.size()) {
                builder = std::make_unique<HasiTreeBuilder>(leaf_rows);
                seg_rows_left = out_segment_rows[seg_idx];
            }
        }
        return Status::OK();
    };
    std::string leaf_buf;
    for (size_t idx : plan.order) {
        const HasiDirView& v = *inputs[idx];
        for (size_t li = 0; li < v.leaves.size(); ++li) {
            const auto& leaf = v.leaves[li];
            const uint64_t stream_end =
                    li + 1 < v.leaves.size() ? v.leaves[li + 1].cells_offset : v.cells_len;
            if (stream_end < leaf.cells_offset) {
                return Status::Corruption("hasi leaf stream bounds inverted");
            }
            const size_t stream_len = static_cast<size_t>(stream_end - leaf.cells_offset);
            leaf_buf.resize(stream_len);
            if (stream_len > 0) {
                RETURN_IF_ERROR(readers[idx](v.cells_begin + leaf.cells_offset, stream_len,
                                             reinterpret_cast<uint8_t*>(leaf_buf.data())));
            }
            const auto* p = reinterpret_cast<const uint8_t*>(leaf_buf.data());
            const auto* end = p + stream_len;
            uint64_t prev = 0; // per-leaf delta base
            for (uint32_t r = leaf.rid_begin; r < leaf.rid_end; ++r) {
                uint64_t delta = 0;
                const size_t n = get_varint(p, end, &delta);
                if (n == 0) {
                    return Status::Corruption("hasi leaf stream truncated at rid {}", r);
                }
                p += n;
                const uint64_t raw = prev + static_cast<uint64_t>(zigzag_decode(delta));
                prev = raw;
                RETURN_IF_ERROR(feed(raw));
            }
        }
    }
    if (seg_idx != out_segment_rows.size() || seg_rows_left != 0) {
        return Status::InternalError("row feed did not cover all output segments");
    }
    return Status::OK();
}

} // namespace doris::segment_v2
