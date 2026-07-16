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

#include "olap/rowset/segment_v2/geo_index/geo_topn_runtime.h"

#include "vec/exprs/vexpr_context.h"
#include "vec/exprs/virtual_slot_ref.h"

namespace doris::segment_v2 {

Status GeoTopNRuntime::prepare(RuntimeState* state, const RowDescriptor& row_desc) {
    RETURN_IF_ERROR(_order_by_expr_ctx->prepare(state, row_desc));
    RETURN_IF_ERROR(_order_by_expr_ctx->open(state));

    // Expected shape (same transport as ann topn):
    //   VirtualSlotRef(distance slot) -> st_distance_sphere(geo_slot, lng0, lat0)
    //                                  | st_distance_sphere(lng_slot, lat_slot, lng0, lat0)
    auto vir_slot_ref =
            std::dynamic_pointer_cast<vectorized::VirtualSlotRef>(_order_by_expr_ctx->root());
    if (vir_slot_ref == nullptr) {
        return Status::InvalidArgument(
                "geo topn order-by root must be a VirtualSlotRef, got\n{}",
                _order_by_expr_ctx->root()->debug_string());
    }
    DCHECK(vir_slot_ref->column_id() >= 0);
    _dest_column_idx = vir_slot_ref->column_id();

    auto vir_col_expr = vir_slot_ref->get_virtual_column_expr();
    if (vir_col_expr == nullptr ||
        !extract_geo_distance_call(vir_col_expr.get(), &_distance)) {
        return Status::InvalidArgument(
                "geo topn virtual column is not a recognizable st_distance_sphere call:\n{}",
                vir_col_expr == nullptr ? "<null>" : vir_col_expr->debug_string());
    }
    return Status::OK();
}

} // namespace doris::segment_v2
