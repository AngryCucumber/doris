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
import org.apache.doris.nereids.trees.expressions.functions.PropagateNullLiteral;
import org.apache.doris.nereids.trees.expressions.visitor.ExpressionVisitor;
import org.apache.doris.nereids.types.BigIntType;
import org.apache.doris.nereids.types.DoubleType;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

import java.util.List;

/**
 * ScalarFunction 'st_s2_cellid'. st_s2_cellid(lon, lat) returns the S2 leaf cell id of the
 * point mapped to an order-preserving signed BIGINT key (raw uint64 cell id XOR 2^63, so the
 * BIGINT order matches the uint64 Hilbert order across all 6 faces). Used as the expression
 * of the __s2 generated sort-key column for the HASI geo index; returns NULL for invalid
 * coordinates (consistent with st_distance_sphere).
 */
public class StS2CellId extends ScalarFunction
        implements ExplicitlyCastableSignature, AlwaysNullable, PropagateNullLiteral {

    public static final List<FunctionSignature> SIGNATURES = ImmutableList.of(
            FunctionSignature.ret(BigIntType.INSTANCE)
                    .args(DoubleType.INSTANCE, DoubleType.INSTANCE)
    );

    /**
     * constructor with 2 arguments.
     */
    public StS2CellId(Expression arg0, Expression arg1) {
        super("st_s2_cellid", arg0, arg1);
    }

    /** constructor for withChildren and reuse signature */
    private StS2CellId(ScalarFunctionParams functionParams) {
        super(functionParams);
    }

    /**
     * withChildren.
     */
    @Override
    public StS2CellId withChildren(List<Expression> children) {
        Preconditions.checkArgument(children.size() == 2);
        return new StS2CellId(getFunctionParams(children));
    }

    @Override
    public List<FunctionSignature> getSignatures() {
        return SIGNATURES;
    }

    @Override
    public <R, C> R accept(ExpressionVisitor<R, C> visitor, C context) {
        return visitor.visitStS2CellId(this, context);
    }
}
