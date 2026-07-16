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

#include "vec/data_types/data_type_geo_point.h"

#include "vec/columns/column_vector.h"

namespace doris::vectorized {

#include "common/compile_check_begin.h"

bool DataTypeGeoPoint::equals(const IDataType& rhs) const {
    return typeid(rhs) == typeid(*this);
}

MutableColumnPtr DataTypeGeoPoint::create_column() const {
    return ColumnGeoPoint::create();
}

Field DataTypeGeoPoint::get_field(const TExprNode& node) const {
    return Field::create_field<TYPE_GEO_POINT>(node.geo_point_literal.value);
}

#include "common/compile_check_end.h"

} // namespace doris::vectorized
