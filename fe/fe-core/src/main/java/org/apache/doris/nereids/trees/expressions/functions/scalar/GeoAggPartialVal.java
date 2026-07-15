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

package org.apache.doris.nereids.trees.expressions.functions.scalar;

import org.apache.doris.catalog.FunctionSignature;
import org.apache.doris.nereids.trees.expressions.Expression;
import org.apache.doris.nereids.trees.expressions.functions.AlwaysNullable;
import org.apache.doris.nereids.trees.expressions.functions.ExplicitlyCastableSignature;
import org.apache.doris.nereids.trees.expressions.visitor.ExpressionVisitor;
import org.apache.doris.nereids.types.DoubleType;
import org.apache.doris.nereids.types.VarcharType;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

import java.util.List;

/**
 * ScalarFunction 'geo_agg_partial_val' (HASI v2b geo aggregate pushdown marker).
 *
 * <p>Planted by PushDownGeoAgg as an olap-scan virtual-column expression:
 * {@code geo_agg_partial_val('sum'|'min'|'max', measure)}. Row-wise it is the
 * identity on the measure argument, which makes the rewritten plan exact without
 * any index cooperation; the BE segment iterator recognizes the marker and
 * replaces whole-leaf runs of the column with per-leaf sketch folds.
 */
public class GeoAggPartialVal extends ScalarFunction
        implements ExplicitlyCastableSignature, AlwaysNullable {

    public static final List<FunctionSignature> SIGNATURES = ImmutableList.of(
            FunctionSignature.ret(DoubleType.INSTANCE)
                    .args(VarcharType.SYSTEM_DEFAULT, DoubleType.INSTANCE)
    );

    public GeoAggPartialVal(Expression arg0, Expression arg1) {
        super("geo_agg_partial_val", arg0, arg1);
    }

    private GeoAggPartialVal(ScalarFunctionParams functionParams) {
        super(functionParams);
    }

    @Override
    public GeoAggPartialVal withChildren(List<Expression> children) {
        Preconditions.checkArgument(children.size() == 2);
        return new GeoAggPartialVal(getFunctionParams(children));
    }

    @Override
    public List<FunctionSignature> getSignatures() {
        return SIGNATURES;
    }

    @Override
    public <R, C> R accept(ExpressionVisitor<R, C> visitor, C context) {
        return visitor.visitGeoAggPartialVal(this, context);
    }
}
