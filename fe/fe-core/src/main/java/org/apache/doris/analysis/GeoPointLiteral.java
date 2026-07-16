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

package org.apache.doris.analysis;

import org.apache.doris.catalog.TableIf;
import org.apache.doris.catalog.TableIf.TableType;
import org.apache.doris.catalog.Type;
import org.apache.doris.common.AnalysisException;
import org.apache.doris.common.FormatOptions;
import org.apache.doris.thrift.TExprNode;
import org.apache.doris.thrift.TExprNodeType;
import org.apache.doris.thrift.TGeoPointLiteral;

import com.google.gson.annotations.SerializedName;

/**
 * Legacy expr literal for GEO_POINT: holds the flipped s2 leaf cell key
 * (raw id XOR 2^63). Text form matches the BE GeoPointValue codec ("[lon, lat]").
 */
public class GeoPointLiteral extends LiteralExpr {

    @SerializedName("v")
    private long value;

    // for restore
    private GeoPointLiteral() {
    }

    public GeoPointLiteral(long value) {
        super();
        this.value = value;
        this.type = Type.GEO_POINT;
        analysisDone();
    }

    public GeoPointLiteral(String text) throws AnalysisException {
        super();
        try {
            this.value = org.apache.doris.nereids.trees.expressions.literal.GeoPointLiteral
                    .parseTextToKey(text);
        } catch (org.apache.doris.nereids.exceptions.AnalysisException e) {
            throw new AnalysisException(e.getMessage());
        }
        this.type = Type.GEO_POINT;
        analysisDone();
    }

    protected GeoPointLiteral(GeoPointLiteral other) {
        super(other);
        this.value = other.value;
    }

    public long getLongValue() {
        return value;
    }

    @Override
    public Expr clone() {
        return new GeoPointLiteral(this);
    }

    @Override
    protected String toSqlImpl() {
        return "\"" + getStringValue() + "\"";
    }

    @Override
    protected String toSqlImpl(boolean disableTableName, boolean needExternalSql, TableType tableType,
            TableIf table) {
        return "\"" + getStringValue() + "\"";
    }

    @Override
    protected void toThrift(TExprNode msg) {
        msg.node_type = TExprNodeType.GEO_POINT_LITERAL;
        msg.geo_point_literal = new TGeoPointLiteral(this.value);
    }

    @Override
    public boolean isMinValue() {
        return false;
    }

    @Override
    public int compareLiteral(LiteralExpr expr) {
        if (expr instanceof GeoPointLiteral) {
            return Long.compare(value, ((GeoPointLiteral) expr).value);
        }
        return 0;
    }

    @Override
    public String getStringValue() {
        return org.apache.doris.nereids.trees.expressions.literal.GeoPointLiteral.keyToText(value);
    }

    @Override
    protected String getStringValueInComplexTypeForQuery(FormatOptions options) {
        return options.getNestedStringWrapper() + getStringValueForQuery(options) + options.getNestedStringWrapper();
    }
}
