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

#include "olap/rowset/segment_v2/geo_index/geo_range_runtime.h"

#include <s2/s1angle.h>
#include <s2/s2cap.h>
#include <s2/s2cell_id.h>
#include <s2/s2latlng.h>

#include <algorithm>

#include "vec/columns/column.h"
#include "vec/columns/column_vector.h"
#include "vec/common/assert_cast.h"
#include "vec/core/types.h"
#include "vec/exprs/vcast_expr.h"
#include "vec/exprs/vectorized_fn_call.h"
#include "vec/exprs/vliteral.h"
#include "vec/exprs/vslot_ref.h"

namespace doris::segment_v2 {

namespace {

const vectorized::VExpr* strip_casts(const vectorized::VExpr* expr) {
    while (expr != nullptr && dynamic_cast<const vectorized::VCastExpr*>(expr) != nullptr &&
           expr->get_num_children() == 1) {
        expr = expr->get_child(0).get();
    }
    return expr;
}

// Non-nullable numeric literal -> double.
bool literal_as_double(const vectorized::VExpr* expr, double* out) {
    expr = strip_casts(expr);
    const auto* literal = dynamic_cast<const vectorized::VLiteral*>(expr);
    if (literal == nullptr || literal->is_nullable()) {
        return false;
    }
    auto col = literal->get_column_ptr()->convert_to_full_column_if_const();
    if (col->size() != 1) {
        return false;
    }
    switch (literal->get_data_type()->get_primitive_type()) {
    case PrimitiveType::TYPE_DOUBLE:
        *out = assert_cast<const vectorized::ColumnFloat64*>(col.get())->get_data()[0];
        return true;
    case PrimitiveType::TYPE_FLOAT:
        *out = assert_cast<const vectorized::ColumnFloat32*>(col.get())->get_data()[0];
        return true;
    default:
        return false;
    }
}

const vectorized::VSlotRef* as_slot(const vectorized::VExpr* expr) {
    return dynamic_cast<const vectorized::VSlotRef*>(strip_casts(expr));
}

// st_distance_sphere(lng_slot, lat_slot, lng0_lit, lat0_lit) -- the same shape the
// v0 FE rewrite matches (slots first, constants last).
bool match_distance_call(const vectorized::VExpr* expr, GeoRangeSearchRuntime* out) {
    expr = strip_casts(expr);
    const auto* call = dynamic_cast<const vectorized::VectorizedFnCall*>(expr);
    if (call == nullptr || call->function_name() != "st_distance_sphere" ||
        call->get_num_children() != 4) {
        return false;
    }
    const auto* lng_slot = as_slot(call->get_child(0).get());
    const auto* lat_slot = as_slot(call->get_child(1).get());
    if (lng_slot == nullptr || lat_slot == nullptr) {
        return false;
    }
    double lng0 = 0;
    double lat0 = 0;
    if (!literal_as_double(call->get_child(2).get(), &lng0) ||
        !literal_as_double(call->get_child(3).get(), &lat0)) {
        return false;
    }
    out->lng_idx_in_block = lng_slot->column_id();
    out->lat_idx_in_block = lat_slot->column_id();
    out->lng0 = lng0;
    out->lat0 = lat0;
    out->distance_expr = call;
    return true;
}

} // namespace

bool extract_geo_range_search(const vectorized::VExpr* root, GeoRangeSearchRuntime* out) {
    if (root == nullptr || root->get_num_children() != 2) {
        return false;
    }
    const auto* cmp = dynamic_cast<const vectorized::VectorizedFnCall*>(root);
    if (cmp == nullptr) {
        return false;
    }
    bool strict = false;
    bool distance_on_left = false;
    switch (cmp->op()) {
    case TExprOpcode::LT: // dist < r
        strict = true;
        distance_on_left = true;
        break;
    case TExprOpcode::LE: // dist <= r
        strict = false;
        distance_on_left = true;
        break;
    case TExprOpcode::GT: // r > dist (mirrored)
        strict = true;
        distance_on_left = false;
        break;
    case TExprOpcode::GE: // r >= dist (mirrored)
        strict = false;
        distance_on_left = false;
        break;
    default:
        return false;
    }
    const vectorized::VExpr* dist_side =
            cmp->get_child(distance_on_left ? 0 : 1).get();
    const vectorized::VExpr* radius_side =
            cmp->get_child(distance_on_left ? 1 : 0).get();

    GeoRangeSearchRuntime runtime;
    if (!match_distance_call(dist_side, &runtime)) {
        // `dist > r` with the distance on the mirrored side would be an outside-circle
        // predicate; match_distance_call failing on the radius side rejects it here.
        return false;
    }
    if (!literal_as_double(radius_side, &runtime.radius_m)) {
        return false;
    }
    runtime.is_strict = strict;
    runtime.valid = true;
    *out = runtime;
    return true;
}

bool compute_circle_covering(const GeoRangeSearchRuntime& runtime,
                             std::vector<CellRange>* covering,
                             std::vector<CellRange>* interior) {
    S2LatLng center = S2LatLng::FromDegrees(runtime.lat0, runtime.lng0);
    if (!center.is_valid() || !(runtime.radius_m > 0)) {
        // The scalar predicate cannot match any row either (NULL / non-positive
        // radius), but keeping the bitmap untouched and letting the residual filter
        // decide is the conservative choice.
        return false;
    }
    const double outer = (runtime.radius_m + kGeoIndexMarginMeters) / kGeoEarthRadiusMeters;
    const double inner = (runtime.radius_m - kGeoIndexMarginMeters) / kGeoEarthRadiusMeters;

    S2Covering coverer(S2CellId::kMaxLevel, kGeoIndexCoveringMaxCells);
    std::vector<CellRange> outer_interior_unused;
    coverer.cover(S2Cap(center.ToPoint(), S1Angle::Radians(outer)), covering,
                  &outer_interior_unused);
    interior->clear();
    if (inner > 0) {
        std::vector<CellRange> inner_covering_unused;
        coverer.cover(S2Cap(center.ToPoint(), S1Angle::Radians(inner)), &inner_covering_unused,
                      interior);
    }
    return true;
}

double covering_keyspace_fraction(const std::vector<CellRange>& covering) {
    const uint64_t lo = S2CellId::FromFace(0).range_min().id();
    const uint64_t hi = S2CellId::FromFace(5).range_max().id();
    const double total = static_cast<double>(hi - lo);
    double sum = 0;
    for (const auto& r : covering) {
        sum += static_cast<double>(r.hi - r.lo);
    }
    return total > 0 ? sum / total : 1.0;
}

} // namespace doris::segment_v2
