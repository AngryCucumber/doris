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

package org.apache.doris.nereids.types;

import org.apache.doris.catalog.Type;
import org.apache.doris.nereids.types.coercion.PrimitiveType;

/**
 * GEO_POINT type in Nereids: an 8-byte scalar storing the flipped s2 leaf cell key
 * (raw id XOR 2^63, same domain as st_s2_cellid). Text form is "[lon, lat]".
 * See be/src/olap/rowset/segment_v2/geo_index/HASI_POC.md §10.
 */
public class GeoPointType extends PrimitiveType {

    public static final GeoPointType INSTANCE = new GeoPointType();

    public static final int WIDTH = 8;

    private GeoPointType() {
    }

    @Override
    public Type toCatalogDataType() {
        return Type.GEO_POINT;
    }

    @Override
    public boolean acceptsType(DataType other) {
        return other instanceof GeoPointType;
    }

    @Override
    public String simpleString() {
        return "geo_point";
    }

    @Override
    public DataType defaultConcreteType() {
        return INSTANCE;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof GeoPointType;
    }

    @Override
    public int width() {
        return WIDTH;
    }

    @Override
    public String toSql() {
        return "GEO_POINT";
    }
}
