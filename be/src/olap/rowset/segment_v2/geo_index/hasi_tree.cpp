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

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>

namespace doris::segment_v2 {

namespace {

constexpr uint32_t kMagic = 0x48415349; // "HASI"
constexpr uint32_t kVersionV1 = 1;
constexpr uint32_t kVersionV2 = 2; // adds the trailing measures section
constexpr size_t kHeaderSize = 24;
constexpr size_t kDirEntrySize = 36;
constexpr size_t kLeafMeasureSize = 28; // f64 sum, f64 min, f64 max, u32 non_null

void put_u32(std::string* out, uint32_t v) {
    char buf[4];
    std::memcpy(buf, &v, 4);
    out->append(buf, 4);
}

void put_u64(std::string* out, uint64_t v) {
    char buf[8];
    std::memcpy(buf, &v, 8);
    out->append(buf, 8);
}

uint32_t get_u32(const uint8_t* p) {
    uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}

uint64_t get_u64(const uint8_t* p) {
    uint64_t v;
    std::memcpy(&v, p, 8);
    return v;
}

void put_varint(std::string* out, uint64_t v) {
    while (v >= 0x80) {
        out->push_back(static_cast<char>((v & 0x7F) | 0x80));
        v >>= 7;
    }
    out->push_back(static_cast<char>(v));
}

// Returns bytes consumed, 0 on malformed/overlong input.
size_t get_varint(const uint8_t* p, const uint8_t* end, uint64_t* v) {
    uint64_t result = 0;
    int shift = 0;
    const uint8_t* cur = p;
    while (cur < end && shift < 64) {
        uint8_t byte = *cur++;
        result |= static_cast<uint64_t>(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) {
            *v = result;
            return cur - p;
        }
        shift += 7;
    }
    return 0;
}

uint64_t zigzag_encode(int64_t v) {
    return (static_cast<uint64_t>(v) << 1) ^ static_cast<uint64_t>(v >> 63);
}

int64_t zigzag_decode(uint64_t v) {
    return static_cast<int64_t>(v >> 1) ^ -static_cast<int64_t>(v & 1);
}

// `ranges` sorted, disjoint, closed. First range whose hi >= v.
std::vector<CellRange>::const_iterator first_candidate(const std::vector<CellRange>& ranges,
                                                       uint64_t v) {
    return std::lower_bound(ranges.begin(), ranges.end(), v,
                            [](const CellRange& r, uint64_t val) { return r.hi < val; });
}

bool ranges_overlap_interval(const std::vector<CellRange>& ranges, uint64_t mn, uint64_t mx) {
    auto it = first_candidate(ranges, mn);
    return it != ranges.end() && it->lo <= mx;
}

bool ranges_contain_interval(const std::vector<CellRange>& ranges, uint64_t mn, uint64_t mx) {
    auto it = first_candidate(ranges, mn);
    return it != ranges.end() && it->lo <= mn && mx <= it->hi;
}

} // namespace

HasiTreeBuilder::HasiTreeBuilder(uint32_t leaf_rows)
        : _leaf_rows(std::clamp(leaf_rows, kMinLeafRows, kMaxLeafRows)) {}

void HasiTreeBuilder::_append_cell(uint64_t raw_cell) {
    put_varint(&_cells, zigzag_encode(static_cast<int64_t>(raw_cell - _cur.prev_cell)));
    _cur.prev_cell = raw_cell;
    if (raw_cell == 0) {
        _null_rids.add(_num_rows);
        ++_cur.null_count;
    } else if (!_cur.has_value) {
        _cur.min_cell = raw_cell;
        _cur.max_cell = raw_cell;
        _cur.has_value = true;
    } else {
        _cur.min_cell = std::min(_cur.min_cell, raw_cell);
        _cur.max_cell = std::max(_cur.max_cell, raw_cell);
    }
    ++_cur.rows;
    ++_num_rows;
    if (_cur.rows == _leaf_rows) {
        _seal_leaf();
    }
}

void HasiTreeBuilder::add_value(int64_t cell_key) {
    // Raw id 0 is not a valid S2 cell; st_s2_cellid never produces it (it yields NULL
    // for invalid coordinates), so it doubles as the NULL sentinel in the cell stream.
    _append_cell(s2_cell_from_key(cell_key));
}

void HasiTreeBuilder::add_nulls(uint32_t count) {
    for (uint32_t i = 0; i < count; ++i) {
        _append_cell(0);
    }
}

void HasiTreeBuilder::_seal_leaf() {
    if (_cur.rows == 0) {
        return;
    }
    if (!_cur.has_value) {
        // All-null leaf: an empty [min > max] range fails every intersection test.
        _cur.min_cell = std::numeric_limits<uint64_t>::max();
        _cur.max_cell = 0;
    }
    const uint32_t rid_end = _num_rows;
    const uint32_t rid_begin = rid_end - _cur.rows;
    put_u64(&_dir, _cur.min_cell);
    put_u64(&_dir, _cur.max_cell);
    put_u32(&_dir, rid_begin);
    put_u32(&_dir, rid_end);
    put_u32(&_dir, _cur.null_count);
    put_u64(&_dir, _cur_cells_offset);
    ++_num_leaves;
    _cur = LeafAccum();
    _cur_cells_offset = _cells.size();
}

void HasiTreeBuilder::finish_topology() {
    if (_topology_done) {
        return;
    }
    _seal_leaf();
    _topology_done = true;
}

Status HasiTreeBuilder::attach_measures(const std::vector<std::string>& measure_names) {
    if (_measure_seen || !_measure_names.empty()) {
        return Status::InternalError("measures already attached");
    }
    if (measure_names.empty() || measure_names.size() > kMaxMeasures) {
        return Status::InvalidArgument("invalid measure count {}", measure_names.size());
    }
    _measure_names = measure_names;
    return Status::OK();
}

Status HasiTreeBuilder::add_measure_row(uint32_t rid, const double* values,
                                        const uint8_t* nulls) {
    if (_measure_names.empty()) {
        return Status::InternalError("add_measure_row without attach_measures");
    }
    if (_measure_seen && rid <= _last_measure_rid) {
        return Status::InternalError("measure rid {} not increasing (last {})", rid,
                                     _last_measure_rid);
    }
    _measure_seen = true;
    _last_measure_rid = rid;
    ++_measure_rows_fed;
    // Leaves are fixed-size rid blocks, so the target leaf is known a priori --
    // measures may stream before, interleaved with, or after the cell feed.
    const size_t leaf_idx = rid / _leaf_rows;
    const size_t needed = (leaf_idx + 1) * _measure_names.size();
    if (_measures.size() < needed) {
        _measures.resize(needed);
    }
    // Rows whose geo cell is NULL belong to no region (§4.2 NULL semantics): their
    // measures never enter the sketch, whatever the caller feeds.
    if (_null_rids.contains(rid)) {
        return Status::OK();
    }
    HasiLeafMeasure* leaf_measures = &_measures[leaf_idx * _measure_names.size()];
    for (size_t m = 0; m < _measure_names.size(); ++m) {
        if (nulls != nullptr && nulls[m] != 0) {
            continue;
        }
        HasiLeafMeasure& agg = leaf_measures[m];
        agg.sum += values[m];
        agg.min = std::min(agg.min, values[m]);
        agg.max = std::max(agg.max, values[m]);
        ++agg.non_null;
    }
    return Status::OK();
}

Status HasiTreeBuilder::serialize(std::string* out) {
    finish_topology();
    out->clear();
    out->reserve(kHeaderSize + _dir.size() + _cells.size() +
                 _measures.size() * kLeafMeasureSize);
    put_u32(out, kMagic);
    put_u32(out, _measure_names.empty() ? kVersionV1 : kVersionV2);
    put_u32(out, 0); // flags, reserved
    put_u32(out, _leaf_rows);
    put_u32(out, _num_rows);
    put_u32(out, _num_leaves);
    out->append(_dir);
    out->append(_cells);
    if (!_measure_names.empty()) {
        _measures.resize(static_cast<size_t>(_num_leaves) * _measure_names.size());
        // trailer: measures section + its start offset. Written at the end so the
        // cells section keeps its v1 layout and offsets.
        const uint64_t measures_offset = out->size();
        put_u32(out, static_cast<uint32_t>(_measure_names.size()));
        for (const auto& name : _measure_names) {
            put_u32(out, static_cast<uint32_t>(name.size()));
            out->append(name);
        }
        for (const auto& m : _measures) {
            put_u64(out, std::bit_cast<uint64_t>(m.sum));
            put_u64(out, std::bit_cast<uint64_t>(m.min));
            put_u64(out, std::bit_cast<uint64_t>(m.max));
            put_u32(out, m.non_null);
        }
        put_u64(out, measures_offset);
    }
    return Status::OK();
}

Status HasiTreeBuilder::finish(std::string* out) {
    return serialize(out);
}

Status HasiTree::parse(std::string&& data) {
    _data = std::move(data);
    const auto* base = reinterpret_cast<const uint8_t*>(_data.data());
    if (_data.size() < kHeaderSize) {
        return Status::Corruption("hasi index too small: {} bytes", _data.size());
    }
    if (get_u32(base) != kMagic) {
        return Status::Corruption("hasi index bad magic");
    }
    const uint32_t version = get_u32(base + 4);
    if (version != kVersionV1 && version != kVersionV2) {
        return Status::Corruption("hasi index unsupported version {}", version);
    }
    _leaf_rows = get_u32(base + 12);
    _num_rows = get_u32(base + 16);
    const uint32_t num_leaves = get_u32(base + 20);
    const size_t dir_end = kHeaderSize + static_cast<size_t>(num_leaves) * kDirEntrySize;
    if (_data.size() < dir_end) {
        return Status::Corruption("hasi index truncated directory: {} leaves, {} bytes",
                                  num_leaves, _data.size());
    }
    _cells_base = base + dir_end;
    _cells_len = _data.size() - dir_end;
    _measure_names.clear();
    _leaf_measures = nullptr;
    if (version == kVersionV2) {
        // trailer: ... [measures section] [u64 measures_offset]
        if (_data.size() < dir_end + 8) {
            return Status::Corruption("hasi v2 index missing measures trailer");
        }
        const uint64_t measures_offset =
                get_u64(base + _data.size() - 8);
        if (measures_offset < dir_end || measures_offset + 4 > _data.size() - 8) {
            return Status::Corruption("hasi v2 bad measures offset {}", measures_offset);
        }
        _cells_len = measures_offset - dir_end;
        const uint8_t* p = base + measures_offset;
        const uint8_t* end = base + _data.size() - 8;
        const uint32_t num_measures = get_u32(p);
        p += 4;
        if (num_measures == 0 || num_measures > HasiTreeBuilder::kMaxMeasures) {
            return Status::Corruption("hasi v2 bad measure count {}", num_measures);
        }
        for (uint32_t m = 0; m < num_measures; ++m) {
            if (p + 4 > end) {
                return Status::Corruption("hasi v2 truncated measure names");
            }
            const uint32_t len = get_u32(p);
            p += 4;
            if (len > 256 || p + len > end) {
                return Status::Corruption("hasi v2 bad measure name length {}", len);
            }
            _measure_names.emplace_back(reinterpret_cast<const char*>(p), len);
            p += len;
        }
        const size_t sketch_bytes =
                static_cast<size_t>(num_leaves) * num_measures * kLeafMeasureSize;
        if (p + sketch_bytes != end) {
            return Status::Corruption("hasi v2 sketch section size mismatch");
        }
        _leaf_measures = p;
    }
    _leaves.clear();
    _leaves.reserve(num_leaves);
    uint32_t expect_rid = 0;
    for (uint32_t i = 0; i < num_leaves; ++i) {
        const uint8_t* p = base + kHeaderSize + static_cast<size_t>(i) * kDirEntrySize;
        Leaf leaf;
        leaf.min_cell = get_u64(p);
        leaf.max_cell = get_u64(p + 8);
        leaf.rid_begin = get_u32(p + 16);
        leaf.rid_end = get_u32(p + 20);
        leaf.null_count = get_u32(p + 24);
        leaf.cells_offset = get_u64(p + 28);
        if (leaf.rid_begin != expect_rid || leaf.rid_end <= leaf.rid_begin ||
            leaf.rid_end > _num_rows || leaf.null_count > leaf.rid_end - leaf.rid_begin ||
            leaf.cells_offset > _cells_len) {
            return Status::Corruption("hasi index bad leaf {}: rid [{}, {}), offset {}", i,
                                      leaf.rid_begin, leaf.rid_end, leaf.cells_offset);
        }
        expect_rid = leaf.rid_end;
        _leaves.push_back(leaf);
    }
    if (expect_rid != _num_rows) {
        return Status::Corruption("hasi index leaf coverage {} != num_rows {}", expect_rid,
                                  _num_rows);
    }
    return Status::OK();
}

int HasiTree::measure_index(const std::string& name) const {
    for (size_t i = 0; i < _measure_names.size(); ++i) {
        if (_measure_names[i] == name) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

HasiLeafMeasure HasiTree::_leaf_measure(uint32_t leaf_idx, uint32_t measure_idx) const {
    const uint8_t* p = _leaf_measures +
                       (static_cast<size_t>(leaf_idx) * _measure_names.size() + measure_idx) *
                               kLeafMeasureSize;
    HasiLeafMeasure m;
    m.sum = std::bit_cast<double>(get_u64(p));
    m.min = std::bit_cast<double>(get_u64(p + 8));
    m.max = std::bit_cast<double>(get_u64(p + 16));
    m.non_null = get_u32(p + 24);
    return m;
}

Status HasiTree::aggregate_inside(const std::vector<CellRange>& covering,
                                  const std::vector<CellRange>& interior, int measure_idx,
                                  HasiLeafMeasure* inside_agg, uint64_t* inside_rows,
                                  std::vector<uint32_t>* boundary_rids,
                                  HasiSearchStats* stats) const {
    if (measure_idx < 0 || static_cast<size_t>(measure_idx) >= _measure_names.size() ||
        _leaf_measures == nullptr) {
        return Status::InternalError("hasi aggregate: measure {} not present", measure_idx);
    }
    *inside_agg = HasiLeafMeasure();
    *inside_rows = 0;
    boundary_rids->clear();
    std::vector<uint64_t> cells;
    for (uint32_t li = 0; li < _leaves.size(); ++li) {
        const Leaf& leaf = _leaves[li];
        const uint32_t leaf_row_count = leaf.rid_end - leaf.rid_begin;
        const uint32_t value_rows = leaf_row_count - leaf.null_count;
        if (value_rows == 0 || !ranges_overlap_interval(covering, leaf.min_cell, leaf.max_cell)) {
            ++stats->leaves_skipped;
            stats->rows_rejected += value_rows;
            continue;
        }
        // Unlike whole-leaf retrieval accept, aggregation tolerates NULL-cell rows in
        // an interior leaf: they never entered the sketch, and the region predicate is
        // non-true for them anyway.
        if (ranges_contain_interval(interior, leaf.min_cell, leaf.max_cell)) {
            const HasiLeafMeasure m = _leaf_measure(li, static_cast<uint32_t>(measure_idx));
            inside_agg->sum += m.sum;
            inside_agg->min = std::min(inside_agg->min, m.min);
            inside_agg->max = std::max(inside_agg->max, m.max);
            inside_agg->non_null += m.non_null;
            *inside_rows += value_rows;
            ++stats->leaves_inside;
            stats->rows_inside += value_rows;
            continue;
        }
        RETURN_IF_ERROR(_decode_leaf_cells(leaf, &cells));
        for (uint32_t i = 0; i < leaf_row_count; ++i) {
            const uint64_t cell = cells[i];
            if (cell == 0) {
                continue;
            }
            if (cell_ranges_contain(covering, cell)) {
                boundary_rids->push_back(leaf.rid_begin + i);
                ++stats->rows_margin;
            } else {
                ++stats->rows_rejected;
            }
        }
        ++stats->leaves_boundary;
    }
    return Status::OK();
}

Status HasiTree::_decode_leaf_cells(const Leaf& leaf, std::vector<uint64_t>* cells) const {
    const uint32_t n = leaf.rid_end - leaf.rid_begin;
    cells->resize(n);
    const uint8_t* p = _cells_base + leaf.cells_offset;
    const uint8_t* end = _cells_base + _cells_len;
    uint64_t prev = 0;
    for (uint32_t i = 0; i < n; ++i) {
        uint64_t enc;
        size_t consumed = get_varint(p, end, &enc);
        if (consumed == 0) {
            return Status::Corruption("hasi index truncated cell stream at rid {}",
                                      leaf.rid_begin + i);
        }
        p += consumed;
        prev += static_cast<uint64_t>(zigzag_decode(enc));
        (*cells)[i] = prev;
    }
    return Status::OK();
}

Status HasiTree::search(const std::vector<CellRange>& covering,
                        const std::vector<CellRange>& interior, roaring::Roaring* hit,
                        HasiSearchStats* stats,
                        std::vector<std::pair<uint32_t, uint64_t>>* margin_out) const {
    *hit = roaring::Roaring();
    if (margin_out != nullptr) {
        margin_out->clear();
    }
    std::vector<uint64_t> cells;
    for (const auto& leaf : _leaves) {
        const uint32_t leaf_row_count = leaf.rid_end - leaf.rid_begin;
        const uint32_t value_rows = leaf_row_count - leaf.null_count;
        if (value_rows == 0 || !ranges_overlap_interval(covering, leaf.min_cell, leaf.max_cell)) {
            ++stats->leaves_skipped;
            stats->rows_rejected += value_rows;
            continue;
        }
        if (leaf.null_count == 0 &&
            ranges_contain_interval(interior, leaf.min_cell, leaf.max_cell)) {
            hit->addRange(leaf.rid_begin, leaf.rid_end);
            ++stats->leaves_inside;
            stats->rows_inside += leaf_row_count;
            continue;
        }
        RETURN_IF_ERROR(_decode_leaf_cells(leaf, &cells));
        for (uint32_t i = 0; i < leaf_row_count; ++i) {
            const uint64_t cell = cells[i];
            if (cell == 0) {
                continue;
            }
            if (cell_ranges_contain(interior, cell)) {
                hit->add(leaf.rid_begin + i);
                ++stats->rows_inside;
            } else if (cell_ranges_contain(covering, cell)) {
                if (margin_out != nullptr) {
                    margin_out->emplace_back(leaf.rid_begin + i, cell);
                } else {
                    hit->add(leaf.rid_begin + i);
                }
                ++stats->rows_margin;
            } else {
                ++stats->rows_rejected;
            }
        }
        ++stats->leaves_boundary;
    }
    return Status::OK();
}

} // namespace doris::segment_v2
