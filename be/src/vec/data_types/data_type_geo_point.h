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

#include <gen_cpp/Types_types.h>

#include <string>

#include "common/status.h"
#include "olap/olap_common.h"
#include "runtime/define_primitive_type.h"
#include "vec/core/types.h"
#include "vec/data_types/data_type.h"
#include "vec/data_types/data_type_number_base.h"
#include "vec/data_types/serde/data_type_geo_point_serde.h"

namespace doris::vectorized {

// GEO_POINT (HASI_POC.md §10): an int64-backed scalar holding the flipped s2 leaf
// cell key (raw id XOR 2^63, the __s2 encoding). Numeric machinery is BIGINT's;
// only the text form ("[lon, lat]", cell-center decode) differs, via the serde.
class DataTypeGeoPoint final : public DataTypeNumberBase<PrimitiveType::TYPE_GEO_POINT> {
public:
    PrimitiveType get_primitive_type() const override { return PrimitiveType::TYPE_GEO_POINT; }
    const std::string get_family_name() const override { return "GeoPoint"; }
    std::string do_get_name() const override { return "GeoPoint"; }

    doris::FieldType get_storage_field_type() const override {
        return doris::FieldType::OLAP_FIELD_TYPE_GEO_POINT;
    }

    bool equals(const IDataType& rhs) const override;

    Field get_field(const TExprNode& node) const override;

    MutableColumnPtr create_column() const override;

    using SerDeType = DataTypeGeoPointSerDe;
    DataTypeSerDeSPtr get_serde(int nesting_level = 1) const override {
        return std::make_shared<SerDeType>(nesting_level);
    }
};

template <typename DataType>
constexpr bool IsGeoPointType = false;
template <>
inline constexpr bool IsGeoPointType<DataTypeGeoPoint> = true;

} // namespace doris::vectorized
