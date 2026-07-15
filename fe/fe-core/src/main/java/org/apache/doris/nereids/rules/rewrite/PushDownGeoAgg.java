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
import org.apache.doris.catalog.KeysType;
import org.apache.doris.nereids.rules.Rule;
import org.apache.doris.nereids.rules.RuleType;
import org.apache.doris.nereids.trees.expressions.Alias;
import org.apache.doris.nereids.trees.expressions.Cast;
import org.apache.doris.nereids.trees.expressions.Expression;
import org.apache.doris.nereids.trees.expressions.NamedExpression;
import org.apache.doris.nereids.trees.expressions.Slot;
import org.apache.doris.nereids.trees.expressions.functions.agg.AggregateFunction;
import org.apache.doris.nereids.trees.expressions.functions.agg.Count;
import org.apache.doris.nereids.trees.expressions.functions.agg.Max;
import org.apache.doris.nereids.trees.expressions.functions.agg.Min;
import org.apache.doris.nereids.trees.expressions.functions.agg.Sum;
import org.apache.doris.nereids.trees.expressions.functions.scalar.Coalesce;
import org.apache.doris.nereids.trees.expressions.functions.scalar.GeoAggPartialCnt;
import org.apache.doris.nereids.trees.expressions.functions.scalar.GeoAggPartialVal;
import org.apache.doris.nereids.trees.expressions.literal.BigIntLiteral;
import org.apache.doris.nereids.trees.expressions.literal.VarcharLiteral;
import org.apache.doris.nereids.trees.plans.Plan;
import org.apache.doris.nereids.trees.plans.logical.LogicalAggregate;
import org.apache.doris.nereids.trees.plans.logical.LogicalFilter;
import org.apache.doris.nereids.trees.plans.logical.LogicalOlapScan;
import org.apache.doris.nereids.trees.plans.logical.LogicalProject;
import org.apache.doris.nereids.types.DoubleType;
import org.apache.doris.nereids.types.FloatType;
import org.apache.doris.qe.ConnectContext;

import com.google.common.collect.ImmutableList;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * HASI v2b geo aggregate pushdown (design doc geo_index/HASI_POC.md §7 v2b).
 *
 * <p>Rewrites
 * <pre>
 * Agg[sum(val), count(val), min(val), max(val), count(*)] (no group by)
 *   └── (Project)
 *         └── Filter[st_distance_sphere(lon, lat, x, y) &lt;[=] r]   -- single conjunct
 *               └── OlapScan[table with GEO index (lng=lon, lat=lat, measures ⊇ val)]
 * </pre>
 * into
 * <pre>
 * Project[restore original ExprIds: coalesce(count partials, 0), cast min/max back]
 *   └── Agg[sum(v_sum), sum(v_cnt), min(v_min), max(v_max), sum(v_rows)]
 *         └── (Project + v_* slots)
 *               └── Filter[unchanged]
 *                     └── OlapScan[+virtual columns v_* = geo_agg_partial_val/cnt(kind, val)]
 * </pre>
 *
 * <p>Correct by construction: the virtual-column marker functions row-wise ARE the
 * partial values (v_sum=val, v_cnt=val IS NOT NULL, v_rows=1), so the rewritten plan is
 * exact even if the BE never touches the index (no sketch, cost gate, deletes, superset
 * fallback). The BE segment iterator recognizes the markers and, where the contract-C3
 * gates hold, elides whole interior leaves from the row stream, emitting one
 * representative row per segment whose v_* values carry the merged leaf sketches.
 *
 * <p>Must run BEFORE {@link RewriteGeoPredicate}: this rule requires the filter to be
 * exactly the circle conjunct; the v0 envelope conjuncts that rule injects afterwards
 * are supersets of the circle covering, which the BE fold provably satisfies for every
 * folded leaf (null_count == 0 leaves only), so they stay compatible downstream.
 */
public class PushDownGeoAgg implements RewriteRuleFactory {

    @Override
    public List<Rule> buildRules() {
        return ImmutableList.of(
                logicalAggregate(logicalFilter(logicalOlapScan().when(PushDownGeoAgg::canPushDown)))
                        .when(agg -> agg.getGroupByExpressions().isEmpty())
                        .then(agg -> {
                            LogicalFilter<LogicalOlapScan> filter = agg.child();
                            return rewrite(agg, null, filter, filter.child());
                        }).toRule(RuleType.PUSH_DOWN_GEO_AGG),
                logicalAggregate(
                        logicalProject(logicalFilter(logicalOlapScan().when(PushDownGeoAgg::canPushDown))))
                        .when(agg -> agg.getGroupByExpressions().isEmpty())
                        .then(agg -> {
                            LogicalProject<LogicalFilter<LogicalOlapScan>> project = agg.child();
                            LogicalFilter<LogicalOlapScan> filter = project.child();
                            return rewrite(agg, project, filter, filter.child());
                        }).toRule(RuleType.PUSH_DOWN_GEO_AGG));
    }

    private static boolean canPushDown(LogicalOlapScan scan) {
        ConnectContext ctx = ConnectContext.get();
        if (ctx == null || !ctx.getSessionVariable().enableGeoAggPushdown
                || !ctx.getSessionVariable().enableGeoIndexQuery
                || !ctx.getSessionVariable().enableGeoIndexExactFilter) {
            return false;
        }
        boolean dupOrMow = scan.getTable().getKeysType() == KeysType.DUP_KEYS
                || (scan.getTable().getTableProperty() != null
                        && scan.getTable().getTableProperty().getEnableUniqueKeyMergeOnWrite());
        if (!dupOrMow) {
            return false;
        }
        // idempotency: bail once our markers are already planted on this scan
        for (NamedExpression vc : scan.getVirtualColumns()) {
            if (vc.anyMatch(e -> e instanceof GeoAggPartialVal || e instanceof GeoAggPartialCnt)) {
                return false;
            }
        }
        return true;
    }

    private Plan rewrite(LogicalAggregate<? extends Plan> agg,
            LogicalProject<? extends Plan> project, LogicalFilter<LogicalOlapScan> filter,
            LogicalOlapScan scan) {
        if (filter.getConjuncts().size() != 1) {
            return null;
        }
        RewriteGeoPredicate.GeoCircle circle =
                RewriteGeoPredicate.extractCircle(filter.getConjuncts().iterator().next());
        if (circle == null || !scan.getOutputSet().contains(circle.lonSlot)
                || !scan.getOutputSet().contains(circle.latSlot)) {
            return null;
        }
        Set<String> measures = findIndexMeasures(scan, circle);
        if (measures == null) {
            return null;
        }
        // The middle project (when present) must pass every measure slot through
        // untouched; slot-identity against the scan output guarantees that.
        Set<Slot> scanOutput = scan.getOutputSet();

        // classify each aggregate output; bail on the first unsupported shape
        List<AggPlanItem> items = new ArrayList<>();
        Slot anyMeasureSlot = null;
        for (NamedExpression out : agg.getOutputExpressions()) {
            if (!(out instanceof Alias) || !(((Alias) out).child() instanceof AggregateFunction)) {
                return null;
            }
            AggregateFunction f = (AggregateFunction) ((Alias) out).child();
            if (f.isDistinct()) {
                return null;
            }
            AggPlanItem item = new AggPlanItem((Alias) out);
            if (f instanceof Count && ((Count) f).isCountStar()) {
                item.kind = "rows";
            } else if (f instanceof Count || f instanceof Sum || f instanceof Min
                    || f instanceof Max) {
                if (f.arity() != 1) {
                    return null;
                }
                Expression child = stripCast(f.child(0));
                if (!(child instanceof Slot) || !scanOutput.contains(child)
                        || !measures.contains(((Slot) child).getName().toLowerCase(Locale.ROOT))
                        || !(child.getDataType() instanceof DoubleType
                                || child.getDataType() instanceof FloatType)) {
                    return null;
                }
                item.measureSlot = (Slot) child;
                anyMeasureSlot = item.measureSlot;
                item.kind = f instanceof Count ? "cnt" : f instanceof Sum ? "sum"
                        : f instanceof Min ? "min" : "max";
            } else {
                return null;
            }
            items.add(item);
        }
        if (items.isEmpty() || anyMeasureSlot == null) {
            // pure count(*) stays on the v2a COUNT_ON_INDEX path
            return null;
        }

        // one virtual column per distinct (kind, measure); count(*) shares a dummy measure
        Map<String, Alias> vcols = new LinkedHashMap<>();
        List<NamedExpression> newAggOutputs = new ArrayList<>();
        List<NamedExpression> restore = new ArrayList<>();
        for (AggPlanItem item : items) {
            Slot measure = item.measureSlot != null ? item.measureSlot : anyMeasureSlot;
            String key = item.kind + "#" + ("rows".equals(item.kind) ? "" : measure.getExprId());
            Alias vcol = vcols.computeIfAbsent(key, k -> {
                Expression arg = measure.getDataType() instanceof DoubleType ? measure
                        : new Cast(measure, DoubleType.INSTANCE);
                Expression fn = "sum".equals(item.kind) || "min".equals(item.kind)
                        || "max".equals(item.kind)
                                ? new GeoAggPartialVal(new VarcharLiteral(item.kind), arg)
                                : new GeoAggPartialCnt(new VarcharLiteral(item.kind), arg);
                return new Alias(fn);
            });
            Slot vslot = vcol.toSlot();
            AggregateFunction original = (AggregateFunction) item.original.child();
            Alias newOut;
            Expression restoreExpr;
            switch (item.kind) {
                case "sum":
                    newOut = new Alias(new Sum(vslot));
                    restoreExpr = newOut.toSlot();
                    break;
                case "min":
                    newOut = new Alias(new Min(vslot));
                    restoreExpr = newOut.toSlot();
                    break;
                case "max":
                    newOut = new Alias(new Max(vslot));
                    restoreExpr = newOut.toSlot();
                    break;
                default: // "cnt" / "rows": count semantics, 0 (not NULL) on empty input
                    newOut = new Alias(new Sum(vslot));
                    restoreExpr = new Coalesce(newOut.toSlot(), new BigIntLiteral(0L));
                    break;
            }
            if (!restoreExpr.getDataType().equals(original.getDataType())) {
                restoreExpr = new Cast(restoreExpr, original.getDataType());
            }
            newAggOutputs.add(newOut);
            restore.add(new Alias(item.original.getExprId(), restoreExpr, item.original.getName()));
        }

        LogicalOlapScan newScan = scan.appendVirtualColumns(new ArrayList<>(vcols.values()));
        Plan newChild = filter.withChildren(newScan);
        if (project != null) {
            List<NamedExpression> projections = new ArrayList<>(project.getProjects());
            for (Alias vcol : vcols.values()) {
                projections.add(vcol.toSlot());
            }
            newChild = project.withProjectsAndChild(projections, newChild);
        }
        Plan newAgg = agg.withAggOutput(newAggOutputs).withChildren(ImmutableList.of(newChild));
        return new LogicalProject<>(restore, newAgg);
    }

    /**
     * Finds a GEO index whose lng/lat property columns match the circle's slots and
     * returns its measure column names (lower-cased), or null when absent.
     */
    private static Set<String> findIndexMeasures(LogicalOlapScan scan,
            RewriteGeoPredicate.GeoCircle circle) {
        for (Index index : scan.getTable().getIndexes()) {
            if (index.getIndexType() != IndexDef.IndexType.GEO) {
                continue;
            }
            Map<String, String> props = index.getProperties();
            String lng = props == null ? null : props.get(GeoIndexUtil.PROP_LNG_COLUMN);
            String lat = props == null ? null : props.get(GeoIndexUtil.PROP_LAT_COLUMN);
            String measures = props == null ? null : props.get(GeoIndexUtil.PROP_MEASURES);
            if (lng == null || lat == null || measures == null
                    || !lng.equalsIgnoreCase(circle.lonSlot.getName())
                    || !lat.equalsIgnoreCase(circle.latSlot.getName())) {
                continue;
            }
            Set<String> names = new HashSet<>();
            for (String name : measures.split(",")) {
                if (!name.trim().isEmpty()) {
                    names.add(name.trim().toLowerCase(Locale.ROOT));
                }
            }
            return names.isEmpty() ? null : names;
        }
        return null;
    }

    private static Expression stripCast(Expression expression) {
        while (expression instanceof Cast) {
            expression = ((Cast) expression).child();
        }
        return expression;
    }

    private static final class AggPlanItem {
        final Alias original;
        String kind;
        Slot measureSlot;

        AggPlanItem(Alias original) {
            this.original = original;
        }
    }
}
