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

import org.apache.doris.nereids.analyzer.UnboundFunction;
import org.apache.doris.nereids.analyzer.UnboundSlot;
import org.apache.doris.nereids.exceptions.AnalysisException;
import org.apache.doris.nereids.trees.expressions.Cast;
import org.apache.doris.nereids.trees.expressions.Expression;
import org.apache.doris.nereids.trees.expressions.Slot;
import org.apache.doris.nereids.trees.expressions.functions.scalar.ScalarFunction;

import com.google.common.collect.ImmutableList;

import java.util.List;
import java.util.Map;

/**
 * Validation helpers for the GEO (HASI) index, see be/src/olap/rowset/segment_v2/geo_index/.
 *
 * <p>A GEO index may only be created on a BIGINT column generated as
 * {@code st_s2_cellid(lng, lat)}: the BE answers {@code ST_Distance_Sphere(lng, lat, ...)}
 * predicates from the indexed cell ids, which is only sound when the cells provably derive
 * from the exact columns the predicate reads. The source column names are recorded into the
 * index properties ({@link #PROP_LNG_COLUMN} / {@link #PROP_LAT_COLUMN}) at CREATE TABLE
 * validation time so the BE can match a pushed-down predicate to this index without trusting
 * column naming conventions.
 */
public class GeoIndexUtil {
    public static final String PROP_LNG_COLUMN = "lng_column";
    public static final String PROP_LAT_COLUMN = "lat_column";
    public static final String PROP_LEAF_ROWS = "leaf_rows";

    public static final int MIN_LEAF_ROWS = 64;
    public static final int MAX_LEAF_ROWS = 1 << 22;

    private static final String S2_CELLID_FN = "st_s2_cellid";

    /**
     * Validates user-supplied GEO index properties. {@link #PROP_LNG_COLUMN} and
     * {@link #PROP_LAT_COLUMN} are derived from the generated column expression during
     * checkColumn and overwrite anything the user supplied, so they are accepted here.
     */
    public static void checkProperties(Map<String, String> properties) {
        for (String key : properties.keySet()) {
            switch (key) {
                case PROP_LEAF_ROWS:
                    String leafRows = properties.get(key);
                    try {
                        int v = Integer.parseInt(leafRows);
                        if (v < MIN_LEAF_ROWS || v > MAX_LEAF_ROWS) {
                            throw new AnalysisException(String.format(
                                    "leaf_rows of geo index must be in [%d, %d], got: %s",
                                    MIN_LEAF_ROWS, MAX_LEAF_ROWS, leafRows));
                        }
                    } catch (NumberFormatException e) {
                        throw new AnalysisException(
                                "leaf_rows of geo index must be an integer, got: " + leafRows);
                    }
                    break;
                case PROP_LNG_COLUMN:
                case PROP_LAT_COLUMN:
                    break;
                default:
                    throw new AnalysisException("unknown geo index property: " + key);
            }
        }
    }

    /**
     * If {@code expr} is {@code st_s2_cellid(lngSlot, latSlot)} (casts stripped, bound or
     * unbound), returns [lngColumnName, latColumnName]; otherwise null. Only plain column
     * references qualify: an index over cells computed from arbitrary expressions could not
     * be matched to a predicate at query time.
     */
    public static List<String> extractS2CellIdArgs(Expression expr) {
        if (expr == null) {
            return null;
        }
        String fnName = null;
        if (expr instanceof UnboundFunction) {
            fnName = ((UnboundFunction) expr).getName();
        } else if (expr instanceof ScalarFunction) {
            fnName = ((ScalarFunction) expr).getName();
        }
        if (fnName == null || !S2_CELLID_FN.equalsIgnoreCase(fnName) || expr.children().size() != 2) {
            return null;
        }
        String lng = slotName(expr.child(0));
        String lat = slotName(expr.child(1));
        if (lng == null || lat == null) {
            return null;
        }
        return ImmutableList.of(lng, lat);
    }

    private static String slotName(Expression expr) {
        while (expr instanceof Cast) {
            expr = expr.child(0);
        }
        if (expr instanceof UnboundSlot) {
            return ((UnboundSlot) expr).getName();
        }
        if (expr instanceof Slot) {
            return ((Slot) expr).getName();
        }
        return null;
    }
}
