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

#include "common/factory_creator.h"
#include "olap/rowset/segment_v2/geo_index/geo_index_reader.h"
#include "olap/rowset/segment_v2/index_iterator.h"

namespace doris::segment_v2 {

class GeoIndexIterator : public IndexIterator {
public:
    explicit GeoIndexIterator(const GeoIndexReaderPtr& reader) : _geo_reader(reader) {}
    ~GeoIndexIterator() override = default;

    // Type-aware on purpose (unlike AnnIndexIterator, which ignores the requested
    // type): the indexed __s2 column carries ordinary range predicates injected by
    // the v0 rewrite, and IndexReaderHelper::has_bkd_index() decides "evaluate this
    // predicate through the inverted index" purely by get_reader(BKD) != nullptr.
    // Answering a BKD request with a geo reader would route those predicates into
    // inverted-index evaluation and fail the query.
    IndexReaderPtr get_reader(IndexReaderType reader_type) const override {
        if (std::holds_alternative<GeoIndexReaderType>(reader_type)) {
            return std::static_pointer_cast<IndexReader>(_geo_reader);
        }
        return nullptr;
    }

    // Geo retrieval goes through GeoIndexReader::range_search directly (the generic
    // IndexParam variant only models inverted/ann queries).
    Status read_from_index(const IndexParam& param) override {
        return Status::NotSupported("geo index does not implement read_from_index");
    }

    Status read_null_bitmap(InvertedIndexQueryCacheHandle* cache_handle) override {
        return Status::OK();
    }

    Result<bool> has_null() override { return true; }

    Status range_search(const std::vector<CellRange>& covering,
                        const std::vector<CellRange>& interior, roaring::Roaring* hit,
                        HasiSearchStats* stats,
                        std::vector<std::pair<uint32_t, uint64_t>>* margin_out = nullptr) {
        return _geo_reader->range_search(covering, interior, hit, stats, margin_out,
                                         _context ? _context->io_ctx : nullptr);
    }

    Status fold_inside(const std::vector<CellRange>& interior,
                       const std::vector<int>& measure_idxs, const roaring::Roaring& present,
                       HasiFoldResult* out) {
        return _geo_reader->fold_inside(interior, measure_idxs, present, out,
                                        _context ? _context->io_ctx : nullptr);
    }

    // v4 kNN candidate collection (loads the index on first use).
    Status knn_candidates(double lng0, double lat0, uint32_t k, const roaring::Roaring* present,
                          double slack_m, double initial_bound_l2,
                          std::vector<std::pair<uint32_t, uint64_t>>* out, HasiKnnStats* stats,
                          double* local_kth_l2, bool* bound_pruned) {
        return _geo_reader->knn_candidates(lng0, lat0, k, present, slack_m, initial_bound_l2,
                                           out, stats, local_kth_l2, bound_pruned,
                                           _context ? _context->io_ctx : nullptr);
    }

    GeoIndexReaderPtr geo_reader() const { return _geo_reader; }

private:
    GeoIndexReaderPtr _geo_reader;

    ENABLE_FACTORY_CREATOR(GeoIndexIterator);
};

} // namespace doris::segment_v2
