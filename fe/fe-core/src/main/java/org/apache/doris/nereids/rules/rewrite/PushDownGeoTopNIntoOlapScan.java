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

package org.apache.doris.nereids.rules.rewrite;

import org.apache.doris.analysis.GeoIndexUtil;
import org.apache.doris.analysis.IndexDef;
import org.apache.doris.catalog.Index;
import org.apache.doris.nereids.properties.OrderKey;
import org.apache.doris.nereids.rules.Rule;
import org.apache.doris.nereids.rules.RuleType;
import org.apache.doris.nereids.trees.expressions.Alias;
import org.apache.doris.nereids.trees.expressions.Cast;
import org.apache.doris.nereids.trees.expressions.Expression;
import org.apache.doris.nereids.trees.expressions.NamedExpression;
import org.apache.doris.nereids.trees.expressions.SlotReference;
import org.apache.doris.nereids.trees.expressions.functions.scalar.StDistanceSphere;
import org.apache.doris.nereids.trees.expressions.literal.NumericLiteral;
import org.apache.doris.nereids.trees.plans.Plan;
import org.apache.doris.nereids.trees.plans.logical.LogicalFilter;
import org.apache.doris.nereids.trees.plans.logical.LogicalOlapScan;
import org.apache.doris.nereids.trees.plans.logical.LogicalProject;
import org.apache.doris.nereids.trees.plans.logical.LogicalTopN;
import org.apache.doris.nereids.util.ExpressionUtils;
import org.apache.doris.qe.ConnectContext;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * HASI v4: push `ORDER BY st_distance_sphere(...) [, tie-break keys] LIMIT k` into the olap
 * scan as a geo kNN hint (thrift geo_sort_info/geo_sort_limit), modeled on
 * {@link PushDownVectorTopNIntoOlapScan}. Differences from the vector rule:
 * <ul>
 * <li>extra ORDER BY keys after the distance key are allowed — only the distance key is pushed;
 *     the TopN above still performs the final (distance, tie-break) sort, and the BE returns all
 *     rows tied at the k-th distance so tie-breaking stays exact;</li>
 * <li>filter conjuncts are NOT rewritten to reference the virtual slot: the ST_* predicate shape
 *     must stay intact for RewriteGeoPredicate (which runs after this rule) and for the BE
 *     conjunct recognition in geo_range_runtime;</li>
 * <li>gated by session variables enable_geo_knn_pushdown and enable_geo_index_query.</li>
 * </ul>
 * Must run BEFORE RewriteGeoPredicate (same constraint as PushDownGeoAgg): this rule needs to
 * see the original plan shape, and the acceptance query has no filter at all.
 */
public class PushDownGeoTopNIntoOlapScan implements RewriteRuleFactory {
    @Override
    public List<Rule> buildRules() {
        return ImmutableList.of(
                logicalTopN(logicalProject(logicalOlapScan()))
                        .when(t -> t.getOrderKeys().size() >= 1).then(topN -> {
                            LogicalProject<LogicalOlapScan> project = topN.child();
                            LogicalOlapScan scan = project.child();
                            return pushDown(topN, project, scan, Optional.empty());
                        }).toRule(RuleType.PUSH_DOWN_GEO_TOPN_INTO_OLAP_SCAN),
                logicalTopN(logicalProject(logicalFilter(logicalOlapScan())))
                        .when(t -> t.getOrderKeys().size() >= 1).then(topN -> {
                            LogicalProject<LogicalFilter<LogicalOlapScan>> project = topN.child();
                            LogicalFilter<LogicalOlapScan> filter = project.child();
                            LogicalOlapScan scan = filter.child();
                            return pushDown(topN, project, scan, Optional.of(filter));
                        }).toRule(RuleType.PUSH_DOWN_GEO_TOPN_INTO_OLAP_SCAN)
        );
    }

    private Plan pushDown(
            LogicalTopN<?> topN,
            LogicalProject<?> project,
            LogicalOlapScan scan,
            Optional<LogicalFilter<LogicalOlapScan>> optionalFilter) {
        ConnectContext ctx = ConnectContext.get();
        if (ctx == null
                || !ctx.getSessionVariable().enableGeoKnnPushdown
                || !ctx.getSessionVariable().enableGeoIndexQuery) {
            return null;
        }
        // Idempotency: this scan already carries a geo topN.
        if (!scan.getGeoOrderKeys().isEmpty()) {
            return null;
        }

        // Only the FIRST order key is pushed; it must be ascending (nearest-first).
        OrderKey firstKey = topN.getOrderKeys().get(0);
        if (!firstKey.isAsc() || !(firstKey.getExpr() instanceof SlotReference)) {
            return null;
        }
        SlotReference keySlot = (SlotReference) firstKey.getExpr();
        Expression orderKeyExpr = null;
        Alias orderKeyAlias = null;
        for (NamedExpression projection : project.getProjects()) {
            if (projection.toSlot().equals(keySlot) && projection instanceof Alias) {
                orderKeyExpr = ((Alias) projection).child();
                orderKeyAlias = (Alias) projection;
                break;
            }
        }
        if (!(orderKeyExpr instanceof StDistanceSphere)) {
            return null;
        }
        StDistanceSphere distance = (StDistanceSphere) orderKeyExpr;

        // Validate the distance-call shape and locate the matching GEO index.
        if (!matchGeoIndex(scan, distance)) {
            return null;
        }

        // Push only the distance key; the TopN above keeps the full key list.
        List<OrderKey> geoOrderKeys = ImmutableList.of(firstKey);
        Plan plan = scan.appendVirtualColumnsAndTopN(
                ImmutableList.of(orderKeyAlias),
                ImmutableList.of(), Optional.empty(),
                ImmutableList.of(), Optional.empty(), Optional.empty(),
                geoOrderKeys, Optional.of(topN.getLimit() + topN.getOffset()));

        // Deliberately do NOT rewrite filter conjuncts (see class comment); re-parent only.
        if (optionalFilter.isPresent()) {
            plan = optionalFilter.get().withChildren(plan);
        }
        Map<Expression, Expression> replaceMap = Maps.newHashMap();
        replaceMap.put(orderKeyAlias, orderKeyAlias.toSlot());
        replaceMap.put(orderKeyExpr, orderKeyAlias.toSlot());
        List<NamedExpression> newProjections = ExpressionUtils
                .replaceNamedExpressions(project.getProjects(), replaceMap);
        LogicalProject<?> newProject = project.withProjectsAndChild(newProjections, plan);
        return topN.withChildren(newProject);
    }

    /**
     * Accepts the two supported shapes and requires a GEO index justified by the slot(s):
     * 3-arg geo_point form: st_distance_sphere(geo_point_slot, lon_lit, lat_lit) with an index
     * whose single column is the slot; 4-arg form: st_distance_sphere(lon_slot, lat_slot,
     * lon_lit, lat_lit) with an index whose lng_column/lat_column properties match the slots.
     */
    private boolean matchGeoIndex(LogicalOlapScan scan, StDistanceSphere distance) {
        if (distance.arity() == 3) {
            SlotReference geoSlot = asScanSlot(scan, distance.child(0));
            if (geoSlot == null || !geoSlot.getDataType().isGeoPointType()
                    || !isFiniteNumericLiteral(distance.child(1), 180.0)
                    || !isFiniteNumericLiteral(distance.child(2), 90.0)) {
                return false;
            }
            for (Index index : scan.getTable().getIndexes()) {
                if (index.getIndexType() != IndexDef.IndexType.GEO) {
                    continue;
                }
                List<String> cols = index.getColumns();
                if (cols != null && cols.size() == 1
                        && cols.get(0).equalsIgnoreCase(geoSlot.getName())) {
                    return true;
                }
            }
            return false;
        }
        if (distance.arity() == 4) {
            SlotReference lonSlot = asScanSlot(scan, distance.child(0));
            SlotReference latSlot = asScanSlot(scan, distance.child(1));
            if (lonSlot == null || latSlot == null
                    || !isFiniteNumericLiteral(distance.child(2), 180.0)
                    || !isFiniteNumericLiteral(distance.child(3), 90.0)) {
                return false;
            }
            for (Index index : scan.getTable().getIndexes()) {
                if (index.getIndexType() != IndexDef.IndexType.GEO) {
                    continue;
                }
                Map<String, String> props = index.getProperties();
                String lng = props == null ? null : props.get(GeoIndexUtil.PROP_LNG_COLUMN);
                String lat = props == null ? null : props.get(GeoIndexUtil.PROP_LAT_COLUMN);
                if (lng != null && lat != null
                        && lng.equalsIgnoreCase(lonSlot.getName())
                        && lat.equalsIgnoreCase(latSlot.getName())) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }

    private SlotReference asScanSlot(LogicalOlapScan scan, Expression expr) {
        while (expr instanceof Cast) {
            expr = ((Cast) expr).child();
        }
        if (!(expr instanceof SlotReference)) {
            return null;
        }
        SlotReference slot = (SlotReference) expr;
        if (!slot.getOriginalColumn().isPresent() || !slot.getOriginalTable().isPresent()
                || !scan.getOutputSet().contains(slot)) {
            return null;
        }
        return slot;
    }

    private boolean isFiniteNumericLiteral(Expression expr, double absBound) {
        if (!(expr instanceof NumericLiteral)) {
            return false;
        }
        double v = ((NumericLiteral) expr).getDouble();
        return Double.isFinite(v) && Math.abs(v) <= absBound;
    }
}
