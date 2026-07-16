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

#include "data_type_geo_point_serde.h"

#include <arrow/builder.h>

#include "vec/columns/column_const.h"
#include "vec/core/types.h"
#include "vec/runtime/geo_point_value.h"

namespace doris::vectorized {
#include "common/compile_check_begin.h"

Status DataTypeGeoPointSerDe::write_column_to_mysql_binary(const IColumn& column,
                                                           MysqlRowBinaryBuffer& result,
                                                           int64_t row_idx, bool col_const,
                                                           const FormatOptions& options) const {
    auto& data = assert_cast<const ColumnGeoPoint&>(column).get_data();
    auto col_index = index_check_const(row_idx, col_const);
    // the FE reports GEO_POINT as MYSQL_TYPE_STRING, so both protocols carry text
    std::string str = GeoPointValue::to_string(data[col_index]);
    if (UNLIKELY(0 != result.push_string(str.c_str(), str.length()))) {
        return Status::InternalError("pack mysql buffer failed.");
    }
    return Status::OK();
}

Status DataTypeGeoPointSerDe::deserialize_one_cell_from_json(IColumn& column, Slice& slice,
                                                             const FormatOptions& options) const {
    if (_nesting_level > 1) {
        slice.trim_quote();
    }
    auto& column_data = assert_cast<ColumnGeoPoint&>(column);
    int64_t val = 0;
    if (!GeoPointValue::from_string(&val, slice.data, slice.size)) {
        return Status::InvalidArgument("parse geo_point fail, string: '{}'",
                                       std::string(slice.data, slice.size));
    }
    column_data.insert_value(val);
    return Status::OK();
}

Status DataTypeGeoPointSerDe::write_column_to_pb(const IColumn& column, PValues& result,
                                                 int64_t start, int64_t end) const {
    const auto& column_data = assert_cast<const ColumnGeoPoint&>(column).get_data();
    auto* ptype = result.mutable_type();
    ptype->set_id(PGenericType::GEO_POINT);
    auto* values = result.mutable_int64_value();
    values->Reserve(cast_set<int>(end - start));
    values->Add(column_data.begin() + start, column_data.begin() + end);
    return Status::OK();
}

Status DataTypeGeoPointSerDe::read_column_from_pb(IColumn& column, const PValues& arg) const {
    auto& col_data = assert_cast<ColumnGeoPoint&>(column).get_data();
    auto old_column_size = column.size();
    column.resize(old_column_size + arg.int64_value_size());
    for (int i = 0; i < arg.int64_value_size(); ++i) {
        col_data[old_column_size + i] = arg.int64_value(i);
    }
    return Status::OK();
}

Status DataTypeGeoPointSerDe::write_column_to_arrow(const IColumn& column, const NullMap* null_map,
                                                    arrow::ArrayBuilder* array_builder,
                                                    int64_t start, int64_t end,
                                                    const cctz::time_zone& ctz) const {
    // exported as the raw flipped cell key (documented POC boundary)
    const auto& col_data = assert_cast<const ColumnGeoPoint&>(column).get_data();
    auto& int64_builder = assert_cast<arrow::Int64Builder&>(*array_builder);
    auto arrow_null_map = revert_null_map(null_map, start, end);
    auto* arrow_null_map_data = arrow_null_map.empty() ? nullptr : arrow_null_map.data();
    RETURN_IF_ERROR(checkArrowStatus(
            int64_builder.AppendValues(reinterpret_cast<const Int64*>(col_data.data()) + start,
                                       end - start,
                                       reinterpret_cast<const uint8_t*>(arrow_null_map_data)),
            column.get_name(), array_builder->type()->name()));
    return Status::OK();
}

Status DataTypeGeoPointSerDe::read_column_from_arrow(IColumn& column,
                                                     const arrow::Array* arrow_array, int64_t start,
                                                     int64_t end,
                                                     const cctz::time_zone& ctz) const {
    auto& col_data = assert_cast<ColumnGeoPoint&>(column).get_data();
    int64_t row_count = end - start;
    /// buffers[0] is a null bitmap and buffers[1] are actual values
    std::shared_ptr<arrow::Buffer> buffer = arrow_array->data()->buffers[1];
    const auto* raw_data = reinterpret_cast<const Int64*>(buffer->data()) + start;
    col_data.insert(raw_data, raw_data + row_count);
    return Status::OK();
}

Status DataTypeGeoPointSerDe::from_string_batch(const ColumnString& str, ColumnNullable& column,
                                                const FormatOptions& options) const {
    const auto size = str.size();
    column.resize(size);

    auto& column_to = assert_cast<ColumnType&>(column.get_nested_column());
    auto& vec_to = column_to.get_data();
    auto& null_map = column.get_null_map_data();

    for (size_t i = 0; i < size; ++i) {
        auto ref = str.get_data_at(i);
        null_map[i] = !GeoPointValue::from_string(&vec_to[i], ref.data, ref.size);
    }
    return Status::OK();
}

Status DataTypeGeoPointSerDe::from_string_strict_mode_batch(
        const ColumnString& str, IColumn& column, const FormatOptions& options,
        const NullMap::value_type* null_map) const {
    const auto size = str.size();
    column.resize(size);

    auto& vec_to = assert_cast<ColumnType&>(column).get_data();
    for (size_t i = 0; i < size; ++i) {
        if (null_map && null_map[i]) {
            continue;
        }
        auto ref = str.get_data_at(i);
        if (!GeoPointValue::from_string(&vec_to[i], ref.data, ref.size)) {
            return Status::InvalidArgument("parse geo_point fail, string: '{}'", ref.to_string());
        }
    }
    return Status::OK();
}

Status DataTypeGeoPointSerDe::from_string(StringRef& str, IColumn& column,
                                          const FormatOptions& options) const {
    int64_t val = 0;
    if (!GeoPointValue::from_string(&val, str.data, str.size)) {
        return Status::InvalidArgument("parse geo_point fail, string: '{}'", str.to_string());
    }
    assert_cast<ColumnType&>(column).insert_value(val);
    return Status::OK();
}

Status DataTypeGeoPointSerDe::from_olap_string(const std::string& str, Field& field,
                                               const FormatOptions& options) const {
    int64_t val = 0;
    if (!GeoPointValue::from_string(&val, str)) {
        return Status::InvalidArgument("parse geo_point fail, string: '{}'", str);
    }
    field = Field::create_field<TYPE_GEO_POINT>(val);
    return Status::OK();
}

Status DataTypeGeoPointSerDe::from_string_strict_mode(StringRef& str, IColumn& column,
                                                      const FormatOptions& options) const {
    return from_string(str, column, options);
}

void DataTypeGeoPointSerDe::write_one_cell_to_binary(const IColumn& src_column,
                                                     ColumnString::Chars& chars,
                                                     int64_t row_num) const {
    const uint8_t type = static_cast<uint8_t>(FieldType::OLAP_FIELD_TYPE_GEO_POINT);
    const auto& data_ref = assert_cast<const ColumnGeoPoint&>(src_column).get_data_at(row_num);

    const size_t old_size = chars.size();
    const size_t new_size = old_size + sizeof(uint8_t) + data_ref.size;
    chars.resize(new_size);

    memcpy(chars.data() + old_size, reinterpret_cast<const char*>(&type), sizeof(uint8_t));
    memcpy(chars.data() + old_size + sizeof(uint8_t), data_ref.data, data_ref.size);
}

} // namespace doris::vectorized
