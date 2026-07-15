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
#include "olap/rowset/segment_v2/geo_index/geo_index_properties.h"

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

#include "common/compile_check_end.h"
} // namespace doris::segment_v2
