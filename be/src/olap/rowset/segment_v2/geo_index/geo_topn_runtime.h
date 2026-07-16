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

#include "olap/rowset/segment_v2/geo_index/geo_range_runtime.h"
#include "runtime/runtime_state.h"
#include "vec/exprs/vexpr_fwd.h"

namespace doris::segment_v2 {

// HASI v4: parsed form of the geo kNN pushdown (thrift geo_sort_info/geo_sort_limit,
// FE rule PushDownGeoTopNIntoOlapScan). Mirrors AnnTopNRuntime's role: one shared
// instance per scan node, prepared once, consumed read-only by every segment
// iterator. The actual best-first search + exact rescoring is orchestrated by
// SegmentIterator::_apply_geo_topn_predicate (it needs column reads for the lon/lat
// mode's exact distances), not here.
class GeoTopNRuntime {
    ENABLE_FACTORY_CREATOR(GeoTopNRuntime);

public:
    GeoTopNRuntime(bool asc, bool nulls_first, size_t limit,
                   vectorized::VExprContextSPtr order_by_expr_ctx)
            : _asc(asc),
              _nulls_first(nulls_first),
              _limit(limit),
              _order_by_expr_ctx(std::move(order_by_expr_ctx)) {}

    // Unwraps VirtualSlotRef(distance slot) -> st_distance_sphere(...) and extracts
    // the query center + source column block positions via extract_geo_distance_call.
    Status prepare(RuntimeState* state, const RowDescriptor& row_desc);

    bool is_asc() const { return _asc; }
    bool nulls_first() const { return _nulls_first; }
    size_t limit() const { return _limit; }
    size_t dest_column_idx() const { return _dest_column_idx; }
    // geo_idx_in_block (GEO_POINT mode) or lng/lat_idx_in_block (lon/lat mode) plus
    // lng0/lat0; radius/is_strict are meaningless for an order key.
    const GeoRangeSearchRuntime& distance() const { return _distance; }
    vectorized::VExprContextSPtr order_by_expr_ctx() const { return _order_by_expr_ctx; }

private:
    const bool _asc;
    const bool _nulls_first;
    const size_t _limit;
    vectorized::VExprContextSPtr _order_by_expr_ctx;
    size_t _dest_column_idx = size_t(-1);
    GeoRangeSearchRuntime _distance;
};

} // namespace doris::segment_v2
