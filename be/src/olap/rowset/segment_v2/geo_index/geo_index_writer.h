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

namespace doris::segment_v2 {

// The single file the HASI structure is stored under inside the per-index directory
// (compounded into the segment .idx file by IndexFileWriter, same as ann.faiss).
inline constexpr char geo_index_file_name[] = "geo.hasi";

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
    int64_t _written_bytes = 0;
};

} // namespace doris::segment_v2
