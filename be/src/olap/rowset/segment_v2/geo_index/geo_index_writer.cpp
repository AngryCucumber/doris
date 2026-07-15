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

#include "olap/rowset/segment_v2/geo_index/geo_index_writer.h"

#include <cstring>
#include <limits>

#include "common/cast_set.h"
#include "olap/rowset/segment_v2/column_writer.h"
#include "olap/rowset/segment_v2/geo_index/geo_index_properties.h"
#include "vec/columns/column_nullable.h"
#include "vec/columns/column_vector.h"
#include "vec/core/block.h"

namespace doris::segment_v2 {
#include "common/compile_check_begin.h"

GeoIndexColumnWriter::GeoIndexColumnWriter(IndexFileWriter* index_file_writer,
                                           const TabletIndex* index_meta)
        : _index_file_writer(index_file_writer), _index_meta(index_meta) {}

Status GeoIndexColumnWriter::init() {
    if (_index_file_writer == nullptr) {
        // Guards against a write path whose IndexFileWriter gating predicate was not
        // extended for GEO (has_inverted_index/has_ann_index/has_geo_index) -- fail
        // the load instead of dereferencing null in release builds.
        return Status::InternalError("geo index writer has no index file writer");
    }
    Result<std::shared_ptr<DorisFSDirectory>> dir = _index_file_writer->open(_index_meta);
    if (!dir.has_value()) {
        return Status::IOError("Failed to open geo index file: {}", dir.error().to_string());
    }
    _dir = dir.value();
    _builder = std::make_unique<HasiTreeBuilder>(geo_index_leaf_rows(_index_meta->properties()));
    _measure_names = geo_index_measures(_index_meta->properties());
    if (!_measure_names.empty()) {
        RETURN_IF_ERROR(_builder->attach_measures(_measure_names));
    }
    return Status::OK();
}

Status GeoIndexColumnWriter::add_values(const std::string name, const void* values,
                                        size_t count) {
    const auto* keys = reinterpret_cast<const int64_t*>(values);
    for (size_t i = 0; i < count; ++i) {
        _builder->add_value(keys[i]);
    }
    return Status::OK();
}

Status GeoIndexColumnWriter::add_nulls(uint32_t count) {
    _builder->add_nulls(count);
    return Status::OK();
}

Status GeoIndexColumnWriter::finish() {
    if (_builder->has_measures_attached() &&
        _builder->measure_rows_fed() != _builder->num_rows()) {
        // e.g. a write path without the block-level feeder (partial update) or a
        // measure column missing from this write: correctness first, no sketches.
        LOG(WARNING) << "geo index measures dropped: fed " << _builder->measure_rows_fed()
                     << " of " << _builder->num_rows() << " rows";
        _builder->drop_measures();
    }
    std::string data;
    RETURN_IF_ERROR(_builder->finish(&data));
    _written_bytes = static_cast<int64_t>(data.size());
    try {
        lucene::store::IndexOutput* out = _dir->createOutput(geo_index_file_name);
        // CLucene writeBytes takes an int32 length at a time.
        const size_t max_chunk = static_cast<size_t>(std::numeric_limits<int32_t>::max());
        size_t written = 0;
        while (written < data.size()) {
            size_t to_write = std::min(data.size() - written, max_chunk);
            out->writeBytes(reinterpret_cast<const uint8_t*>(data.data()) + written,
                            cast_set<int32_t>(to_write));
            written += to_write;
        }
        out->close();
        delete out;
    } catch (const std::exception& e) {
        return Status::IOError("Failed to write geo index: {}", e.what());
    }
    return Status::OK();
}

int64_t GeoIndexColumnWriter::size() const {
    return _written_bytes;
}

void GeoIndexColumnWriter::close_on_error() {}

Status GeoIndexColumnWriter::add_array_values(size_t, const CollectionValue*, size_t) {
    return Status::NotSupported("geo index does not accept array values");
}

Status GeoIndexColumnWriter::add_array_values(size_t, const void*, const uint8_t*, const uint8_t*,
                                              size_t) {
    return Status::NotSupported("geo index does not accept array values");
}

Status GeoIndexColumnWriter::add_array_nulls(const uint8_t*, size_t) {
    return Status::NotSupported("geo index does not accept array nulls");
}

Status GeoIndexColumnWriter::feed_block_measures(
        const TabletSchema& schema, const std::vector<std::unique_ptr<ColumnWriter>>& writers,
        IndexColumnWriter* retained_geo_writer, const std::vector<uint32_t>* group_col_ids,
        GeoMeasureFeedState* state, const vectorized::Block* block, size_t row_pos,
        size_t num_rows, uint32_t rid_base) {
    // Block positions map to tablet-schema cids either 1:1 (loads) or through the
    // column-group id list (vertical compaction re-inits the writer per group).
    const size_t width = group_col_ids != nullptr ? group_col_ids->size() : schema.num_columns();
    if (!state->resolved) {
        state->resolved = true;
        GeoIndexColumnWriter* geo_writer = nullptr;
        for (const auto& column_writer : writers) {
            auto* candidate =
                    dynamic_cast<GeoIndexColumnWriter*>(column_writer->geo_index_writer());
            if (candidate != nullptr) {
                geo_writer = candidate;
                break; // at most one geo index per table in the POC
            }
        }
        if (geo_writer == nullptr) {
            // v2b-w2: the indexed column's group already ran and released its writer
            // to the segment writer; measure groups keep feeding it.
            geo_writer = dynamic_cast<GeoIndexColumnWriter*>(retained_geo_writer);
        }
        if (geo_writer != nullptr && !geo_writer->measure_names().empty()) {
            std::vector<int> block_cols;
            for (const auto& name : geo_writer->measure_names()) {
                int idx = -1;
                for (size_t i = 0; i < width; ++i) {
                    const size_t cid = group_col_ids != nullptr ? (*group_col_ids)[i] : i;
                    const auto& col = schema.column(cid);
                    if (col.name() == name &&
                        (col.type() == FieldType::OLAP_FIELD_TYPE_DOUBLE ||
                         col.type() == FieldType::OLAP_FIELD_TYPE_FLOAT)) {
                        idx = static_cast<int>(i);
                        break;
                    }
                }
                if (idx < 0) {
                    // Full-width view: the column genuinely doesn't exist (or has a
                    // wrong type) -- worth a warning. A column-group subset simply
                    // doesn't carry the measure; another group will.
                    if (width == schema.num_columns()) {
                        LOG(WARNING) << "geo index measure column '" << name
                                     << "' not found or not FLOAT/DOUBLE; sketches disabled";
                    }
                    block_cols.clear();
                    break;
                }
                block_cols.push_back(idx);
            }
            if (!block_cols.empty()) {
                state->writer = geo_writer;
                state->block_cols = std::move(block_cols);
            }
        }
    }
    if (state->writer == nullptr || block->columns() < width) {
        return Status::OK();
    }
    // A row's cell must be indexed before its measures (the builder's NULL-cell
    // filter depends on it). In vertical compaction a value group can run BEFORE
    // the indexed column's group; skipping here degrades that segment to v1.
    if (state->writer->rows_indexed() < rid_base + num_rows) {
        return Status::OK();
    }
    for (int idx : state->block_cols) {
        if (static_cast<size_t>(idx) >= block->columns() ||
            block->get_by_position(idx).column.get() == nullptr) {
            return Status::OK();
        }
    }
    const size_t m = state->block_cols.size();
    std::vector<const double*> f64(m, nullptr);
    std::vector<const float*> f32(m, nullptr);
    std::vector<const uint8_t*> null_map(m, nullptr);
    for (size_t j = 0; j < m; ++j) {
        const auto* col = block->get_by_position(state->block_cols[j]).column.get();
        if (const auto* nullable =
                    vectorized::check_and_get_column<vectorized::ColumnNullable>(col)) {
            null_map[j] = nullable->get_null_map_data().data();
            col = &nullable->get_nested_column();
        }
        if (const auto* c64 = vectorized::check_and_get_column<vectorized::ColumnFloat64>(col)) {
            f64[j] = c64->get_data().data();
        } else if (const auto* c32 =
                           vectorized::check_and_get_column<vectorized::ColumnFloat32>(col)) {
            f32[j] = c32->get_data().data();
        } else {
            return Status::OK(); // unexpected runtime layout: skip, finish() degrades to v1
        }
    }
    std::vector<double> values(m, 0.0);
    std::vector<uint8_t> nulls(m, 0);
    for (size_t r = 0; r < num_rows; ++r) {
        const size_t src = row_pos + r;
        for (size_t j = 0; j < m; ++j) {
            nulls[j] = null_map[j] != nullptr ? null_map[j][src] : 0;
            values[j] = f64[j] != nullptr ? f64[j][src] : static_cast<double>(f32[j][src]);
        }
        RETURN_IF_ERROR(state->writer->add_measure_row(rid_base + static_cast<uint32_t>(r),
                                                       values.data(), nulls.data()));
    }
    return Status::OK();
}

#include "common/compile_check_end.h"
} // namespace doris::segment_v2
