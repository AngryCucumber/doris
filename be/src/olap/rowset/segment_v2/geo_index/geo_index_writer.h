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

#include <memory>
#include <string>

#include "olap/rowset/segment_v2/geo_index/hasi_tree.h"
#include "olap/rowset/segment_v2/index_file_writer.h"
#include "olap/rowset/segment_v2/index_writer.h"
#include "olap/rowset/segment_v2/inverted_index_fs_directory.h"
#include "olap/tablet_schema.h"

namespace doris::vectorized {
class Block;
} // namespace doris::vectorized

namespace doris::segment_v2 {

class ColumnWriter;

// The single file the HASI structure is stored under inside the per-index directory
// (compounded into the segment .idx file by IndexFileWriter, same as ann.faiss).
inline constexpr char geo_index_file_name[] = "geo.hasi";

// Shared v2b measure-feeding state for segment writers (horizontal SegmentWriter and
// VerticalSegmentWriter's flush path both call GeoIndexColumnWriter::feed_block_measures
// with their own instance; resolution happens lazily on the first block).
struct GeoMeasureFeedState {
    bool resolved = false;
    class GeoIndexColumnWriter* writer = nullptr;
    std::vector<int> block_cols;
};

// Streaming HASI index writer for the __s2 BIGINT column, mounted on
// ScalarColumnWriter (design doc HASI_POC.md §4.3). Values and null runs arrive
// strictly in rowid order; the builder keeps O(1) state, so this adds no buffering
// to the flush path. Built identically at load flush and compaction (the compaction
// output rowset goes through the same segment write path).
class GeoIndexColumnWriter : public IndexColumnWriter {
public:
    GeoIndexColumnWriter(IndexFileWriter* index_file_writer, const TabletIndex* index_meta);
    ~GeoIndexColumnWriter() override = default;

    Status init() override;
    Status add_values(const std::string name, const void* values, size_t count) override;
    Status add_nulls(uint32_t count) override;
    Status finish() override;
    int64_t size() const override;
    void close_on_error() override;

    // v2b: measure columns declared via the index property `measures` are streamed
    // by the segment writer (which sees whole blocks) through this row interface;
    // rid must match the segment rowid order the cell feed uses. finish() drops the
    // measures section unless every indexed row was fed (partial-update or missing
    // column paths then degrade to a v1 file; the aggregation existence gate treats
    // that as "sketch absent").
    const std::vector<std::string>& measure_names() const { return _measure_names; }
    Status add_measure_row(uint32_t rid, const double* values, const uint8_t* nulls) {
        return _builder->add_measure_row(rid, values, nulls);
    }

    // v2b-w2: cross-column-group support. Cells indexed so far (the NULL-cell filter
    // needs a row's cell before its measures), and whether measures were declared
    // but not completely fed yet (the segment writer then defers finish() past the
    // remaining column groups instead of degrading to v1 here).
    uint32_t rows_indexed() const { return _builder == nullptr ? 0 : _builder->num_rows(); }
    bool measures_pending() const {
        return _builder != nullptr && _builder->has_measures_attached() &&
               _builder->measure_rows_fed() != _builder->num_rows();
    }

    // Block-level feeder used by both segment writers: resolves the geo writer
    // (from the current writer set or `retained_geo_writer`, the deferred writer a
    // previous column group released) and the FLOAT/DOUBLE measure columns lazily,
    // then streams rows [rid_base, rid_base + num_rows) from block[row_pos...].
    // `group_col_ids` maps block positions to tablet-schema cids (vertical
    // compaction column groups); nullptr means block positions == schema positions.
    // A measure column missing from this group's view simply skips feeding here --
    // finish() degrades the file to v1 unless some group fed every row.
    static Status feed_block_measures(const TabletSchema& schema,
                                      const std::vector<std::unique_ptr<ColumnWriter>>& writers,
                                      IndexColumnWriter* retained_geo_writer,
                                      const std::vector<uint32_t>* group_col_ids,
                                      GeoMeasureFeedState* state, const vectorized::Block* block,
                                      size_t row_pos, size_t num_rows, uint32_t rid_base);

    // Array interfaces are meaningless for a BIGINT scalar column.
    Status add_array_values(size_t field_size, const CollectionValue* values,
                            size_t count) override;
    Status add_array_values(size_t field_size, const void* value_ptr, const uint8_t* null_map,
                            const uint8_t* offsets_ptr, size_t count) override;
    Status add_array_nulls(const uint8_t* null_map, size_t num_rows) override;

private:
    IndexFileWriter* _index_file_writer;
    const TabletIndex* _index_meta;
    std::shared_ptr<DorisFSDirectory> _dir;
    std::unique_ptr<HasiTreeBuilder> _builder;
    std::vector<std::string> _measure_names;
    int64_t _written_bytes = 0;
};

} // namespace doris::segment_v2
