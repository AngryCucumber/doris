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

#include "io/io_common.h"
#include "olap/rowset/segment_v2/geo_index/hasi_tree.h"
#include "olap/rowset/segment_v2/geo_index/s2_covering.h"
#include "olap/rowset/segment_v2/index_reader.h"
#include "olap/tablet_schema.h"
#include "util/once.h"

namespace doris::segment_v2 {

class IndexFileReader;
class IndexIterator;

// Reader for the HASI geo index (design doc HASI_POC.md §4.4). v1 exposes only the
// retrieval query; the whole serialized structure is loaded eagerly on first use
// (leaf directory + delta-encoded cell streams, ~1-3 B/row) behind a DorisCallOnce.
class GeoIndexReader : public IndexReader {
public:
    GeoIndexReader(const TabletIndex* index_meta,
                   std::shared_ptr<IndexFileReader> index_file_reader);
    ~GeoIndexReader() override = default;

    IndexType index_type() override { return IndexType::GEO; }
    uint64_t get_index_id() const override { return _index_meta.index_id(); }
    Status new_iterator(std::unique_ptr<IndexIterator>* iterator) override;

    Status load_index(io::IOContext* io_ctx);

    // Contract C1: the caller only ever intersects `hit` into its own row bitmap.
    // margin_out selects the result mode -- see HasiTree::search.
    Status range_search(const std::vector<CellRange>& covering,
                        const std::vector<CellRange>& interior, roaring::Roaring* hit,
                        HasiSearchStats* stats,
                        std::vector<std::pair<uint32_t, uint64_t>>* margin_out = nullptr,
                        io::IOContext* io_ctx = nullptr);

    const TabletIndex& index_meta() const { return _index_meta; }

private:
    TabletIndex _index_meta;
    std::shared_ptr<IndexFileReader> _index_file_reader;
    HasiTree _tree;
    DorisCallOnce<Status> _load_once;
};

using GeoIndexReaderPtr = std::shared_ptr<GeoIndexReader>;

} // namespace doris::segment_v2
