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

#include "olap/rowset/segment_v2/geo_index/geo_index_reader.h"

#include <CLucene.h> // IWYU pragma: keep
#include <CLucene/store/IndexInput.h>

#include <limits>

#include "common/cast_set.h"
#include "common/config.h"
#include "olap/rowset/segment_v2/geo_index/geo_index_iterator.h"
#include "olap/rowset/segment_v2/geo_index/geo_index_writer.h"
#include "olap/rowset/segment_v2/index_file_reader.h"
#include "olap/rowset/segment_v2/inverted_index_compound_reader.h"

namespace doris::segment_v2 {
#include "common/compile_check_begin.h"

GeoIndexReader::GeoIndexReader(const TabletIndex* index_meta,
                               std::shared_ptr<IndexFileReader> index_file_reader)
        : _index_meta(*index_meta), _index_file_reader(std::move(index_file_reader)) {}

Status GeoIndexReader::new_iterator(std::unique_ptr<IndexIterator>* iterator) {
    *iterator = GeoIndexIterator::create_unique(
            std::static_pointer_cast<GeoIndexReader>(shared_from_this()));
    return Status::OK();
}

Status GeoIndexReader::load_index(io::IOContext* io_ctx) {
    return _load_once.call([&]() -> Status {
        try {
            RETURN_IF_ERROR(
                    _index_file_reader->init(config::inverted_index_read_buffer_size, io_ctx));
            auto compound_dir = _index_file_reader->open(&_index_meta, io_ctx);
            if (!compound_dir.has_value()) {
                return Status::IOError("Failed to open geo index file: {}",
                                       compound_dir.error().to_string());
            }
            lucene::store::IndexInput* in = nullptr;
            CLuceneError open_err;
            if (!compound_dir.value()->openInput(geo_index_file_name, in, open_err)) {
                return Status::IOError("Failed to open {} in geo index: {}", geo_index_file_name,
                                       open_err.what());
            }
            std::string data;
            try {
                const int64_t len = in->length();
                data.resize(static_cast<size_t>(len));
                const size_t max_chunk =
                        static_cast<size_t>(std::numeric_limits<int32_t>::max());
                size_t done = 0;
                while (done < data.size()) {
                    size_t to_read = std::min(data.size() - done, max_chunk);
                    in->readBytes(reinterpret_cast<uint8_t*>(data.data()) + done,
                                  cast_set<int32_t>(to_read));
                    done += to_read;
                }
            } catch (...) {
                in->close();
                delete in;
                throw;
            }
            in->close();
            delete in;
            RETURN_IF_ERROR(_tree.parse(std::move(data)));
        } catch (const CLuceneError& err) {
            return Status::Error<ErrorCode::INVERTED_INDEX_CLUCENE_ERROR>(
                    "CLuceneError occurred when opening geo index, error msg: {}", err.what());
        }
        return Status::OK();
    });
}

Status GeoIndexReader::range_search(const std::vector<CellRange>& covering,
                                    const std::vector<CellRange>& interior, roaring::Roaring* hit,
                                    HasiSearchStats* stats,
                                    std::vector<std::pair<uint32_t, uint64_t>>* margin_out,
                                    io::IOContext* io_ctx) {
    RETURN_IF_ERROR(load_index(io_ctx));
    return _tree.search(covering, interior, hit, stats, margin_out);
}

#include "common/compile_check_end.h"
} // namespace doris::segment_v2
