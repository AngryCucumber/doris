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

#include "cast_base.h"
#include "geo/geo_types.h"
#include "runtime/primitive_type.h"
#include "vec/columns/column_nullable.h"
#include "vec/data_types/data_type_geo_point.h"
#include "vec/data_types/data_type_number.h"
#include "vec/runtime/geo_point_value.h"

namespace doris::vectorized {
#include "common/compile_check_begin.h"

struct CastToGeoPoint {
    static bool from_string(const StringRef& from, int64_t& to, CastParameters&);
};

inline bool CastToGeoPoint::from_string(const StringRef& from, int64_t& to, CastParameters&) {
    return GeoPointValue::from_string(&to, from.data, from.size);
}

// string -> geo_point rides the serde parse, same shape as the string -> ip cast.
template <CastModeType Mode>
class CastToImpl<Mode, DataTypeString, DataTypeGeoPoint> : public CastToBase {
public:
    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count,
                        const NullMap::value_type* null_map = nullptr) const override {
        const auto* col_from = check_and_get_column<DataTypeString::ColumnType>(
                block.get_by_position(arguments[0]).column.get());

        auto to_type = block.get_by_position(result).type;
        auto serde = remove_nullable(to_type)->get_serde();

        MutableColumnPtr column_to = to_type->create_column();
        ColumnNullable::MutablePtr nullable_col_to = ColumnNullable::create(
                std::move(column_to), ColumnUInt8::create(input_rows_count, 0));

        if constexpr (Mode == CastModeType::NonStrictMode) {
            RETURN_IF_ERROR(serde->from_string_batch(*col_from, *nullable_col_to, {}));
        } else if constexpr (Mode == CastModeType::StrictMode) {
            RETURN_IF_ERROR(serde->from_string_strict_mode_batch(
                    *col_from, nullable_col_to->get_nested_column(), {}, null_map));
        } else {
            return Status::InternalError("Unsupported cast mode");
        }

        block.get_by_position(result).column = std::move(nullable_col_to);
        return Status::OK();
    }
};

// bigint -> geo_point: the value must already be a flipped cell key in the
// st_s2_cellid domain (zero-cost migration path for existing __s2 columns).
// Keys that do not denote a valid S2 cell become NULL (non-strict) or an error
// (strict) instead of poisoning the index with undecodable values.
template <CastModeType Mode>
class CastToImpl<Mode, DataTypeInt64, DataTypeGeoPoint> : public CastToBase {
public:
    Status execute_impl(FunctionContext* context, Block& block, const ColumnNumbers& arguments,
                        uint32_t result, size_t input_rows_count,
                        const NullMap::value_type* null_map = nullptr) const override {
        const auto* col_from = check_and_get_column<DataTypeInt64::ColumnType>(
                block.get_by_position(arguments[0]).column.get());
        const auto& from_data = col_from->get_data();
        const auto size = col_from->size();

        auto col_to = DataTypeGeoPoint::ColumnType::create(size);
        auto& to_data = col_to->get_data();
        auto col_null_map = ColumnUInt8::create(size, 0);
        auto& null_data = col_null_map->get_data();

        double lng = 0;
        double lat = 0;
        for (size_t i = 0; i < size; ++i) {
            to_data[i] = from_data[i];
            if (!GeoPoint::DecodeS2CellKey(from_data[i], &lng, &lat)) {
                if constexpr (Mode == CastModeType::StrictMode) {
                    return Status::InvalidArgument(
                            "cast bigint to geo_point fail, not a valid cell key: {}",
                            from_data[i]);
                }
                null_data[i] = 1;
                to_data[i] = 0;
            }
        }

        block.get_by_position(result).column =
                ColumnNullable::create(std::move(col_to), std::move(col_null_map));
        return Status::OK();
    }
};

namespace CastWrapper {

inline WrapperType create_geo_point_wrapper(FunctionContext* context,
                                            const DataTypePtr& from_type) {
    std::shared_ptr<CastToBase> cast_to_geo_point;

    auto make_wrapper = [&](const auto& types) -> bool {
        using Types = std::decay_t<decltype(types)>;
        using FromDataType = typename Types::LeftType;
        if constexpr (IsStringType<FromDataType> || std::is_same_v<FromDataType, DataTypeInt64>) {
            if (context->enable_strict_mode()) {
                cast_to_geo_point = std::make_shared<
                        CastToImpl<CastModeType::StrictMode, FromDataType, DataTypeGeoPoint>>();
            } else {
                cast_to_geo_point = std::make_shared<
                        CastToImpl<CastModeType::NonStrictMode, FromDataType, DataTypeGeoPoint>>();
            }
            return true;
        } else {
            return false;
        }
    };

    if (!call_on_index_and_data_type<void>(from_type->get_primitive_type(), make_wrapper)) {
        return create_unsupport_wrapper(
                fmt::format("CAST AS geo_point not supported {}", from_type->get_name()));
    }

    return [cast_to_geo_point](FunctionContext* context, Block& block,
                               const ColumnNumbers& arguments, uint32_t result,
                               size_t input_rows_count,
                               const NullMap::value_type* null_map = nullptr) {
        return cast_to_geo_point->execute_impl(context, block, arguments, result, input_rows_count,
                                               null_map);
    };
}

} // namespace CastWrapper

#include "common/compile_check_end.h"
} // namespace doris::vectorized
