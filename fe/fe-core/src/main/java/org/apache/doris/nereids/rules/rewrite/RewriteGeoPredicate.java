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

import org.apache.doris.analysis.CastExpr;
import org.apache.doris.analysis.Expr;
import org.apache.doris.analysis.FunctionCallExpr;
import org.apache.doris.analysis.IndexDef;
import org.apache.doris.analysis.SlotRef;
import org.apache.doris.catalog.Column;
import org.apache.doris.catalog.GeneratedColumnInfo;
import org.apache.doris.catalog.Index;
import org.apache.doris.nereids.rules.Rule;
import org.apache.doris.nereids.rules.RuleType;
import org.apache.doris.nereids.trees.expressions.Cast;
import org.apache.doris.nereids.trees.expressions.ComparisonPredicate;
import org.apache.doris.nereids.trees.expressions.Expression;
import org.apache.doris.nereids.trees.expressions.GreaterThan;
import org.apache.doris.nereids.trees.expressions.GreaterThanEqual;
import org.apache.doris.nereids.trees.expressions.LessThan;
import org.apache.doris.nereids.trees.expressions.LessThanEqual;
import org.apache.doris.nereids.trees.expressions.Slot;
import org.apache.doris.nereids.trees.expressions.SlotReference;
import org.apache.doris.nereids.trees.expressions.functions.scalar.StDistanceSphere;
import org.apache.doris.nereids.trees.expressions.literal.BigIntLiteral;
import org.apache.doris.nereids.trees.expressions.literal.GeoPointLiteral;
import org.apache.doris.nereids.trees.expressions.literal.NumericLiteral;
import org.apache.doris.nereids.trees.plans.Plan;
import org.apache.doris.nereids.trees.plans.logical.LogicalFilter;
import org.apache.doris.nereids.trees.plans.logical.LogicalOlapScan;
import org.apache.doris.qe.ConnectContext;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.geometry.S1Angle;
import com.google.common.geometry.S2Cap;
import com.google.common.geometry.S2CellId;
import com.google.common.geometry.S2CellUnion;
import com.google.common.geometry.S2LatLng;
import com.google.common.geometry.S2Point;
import com.google.common.geometry.S2RegionCoverer;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * HASI geo index v0 predicate rewrite (design doc: be/src/olap/rowset/segment_v2/geo_index/HASI_POC.md §3.3-3).
 *
 * <p>Recognizes circle-containment predicates over a (lon, lat) column pair, e.g.
 * {@code st_distance_sphere(lon, lat, 116.4, 39.9) <= 1000}, on an olap scan whose table has a generated
 * column {@code __s2 = st_s2_cellid(lon, lat)} (the S2 leaf cell id mapped to a signed BIGINT sort key).
 * It injects a sargable envelope range conjunct {@code __s2 >= lo AND __s2 <= hi} derived from the
 * S2 covering of the query circle, while KEEPING the original ST_* predicate as the exact residual
 * filter. The injected range is a strict superset of the circle, so results are bit-identical with the
 * rewrite on or off; the benefit is key-range / zonemap pruning on the __s2 sort key.
 *
 * <p>Key encoding contract (doc §3.3-1, guarded by S2CellKeyCompatibilityTest): the __s2 column stores
 * {@code rawCellId ^ 2^63} so that signed BIGINT order equals unsigned Hilbert order across all 6 faces.
 * The envelope must be computed and compared in that flipped domain, otherwise rows are silently lost.
 *
 * <p>v0 limitations (deliberately conservative — skip rather than risk a wrong rewrite):
 * <ul>
 * <li>only {@code st_distance_sphere(slotLon, slotLat, lonConst, latConst) &lt;[=] rConst} and its mirrored
 *     form {@code rConst &gt;[=] st_distance_sphere(...)}; everything else is left untouched</li>
 * <li>single envelope range only; TODO(v0-⑤/v1): emit up to max_scan_key_num refined ranges
 *     (OR of per-cell ranges) once the multi-range plumbing is in place</li>
 * <li>TODO(v1): ST_Contains(constant shape, ST_Point(lon, lat)) form</li>
 * </ul>
 */
public class RewriteGeoPredicate implements RewriteRuleFactory {

    /**
     * Earth radius in meters used by BE st_distance_sphere (geo_functions); the covering cap angle
     * must be derived with the same constant or boundary rows may be dropped.
     */
    private static final double EARTH_RADIUS_METERS = 6371010.0;

    /** v0 only needs the envelope [min(covering), max(covering)], so a small covering is enough. */
    private static final int COVERING_MAX_CELLS = 8;

    /**
     * Expand the cap by this margin before covering: BE evaluates the residual predicate with
     * haversine (only ~8 significant digits at earth scale) while the Java cap uses chord angles,
     * so a row exactly on the circle boundary can fall a float-epsilon outside the un-expanded cap
     * and be silently dropped by the envelope. Same rationale as CircleRecheck::kMarginMeters (BE).
     */
    private static final double MARGIN_METERS = 1.0;

    @Override
    public List<Rule> buildRules() {
        return ImmutableList.of(
                logicalFilter(logicalOlapScan()).then(filter -> {
                    LogicalOlapScan scan = filter.child();
                    return rewrite(filter, scan);
                }).toRule(RuleType.REWRITE_GEO_PREDICATE)
        );
    }

    private Plan rewrite(LogicalFilter<LogicalOlapScan> filter, LogicalOlapScan scan) {
        ConnectContext connectContext = ConnectContext.get();
        if (connectContext == null || !connectContext.getSessionVariable().enableGeoPredicateRewrite) {
            return null;
        }
        Set<Expression> conjuncts = filter.getConjuncts();
        Set<Slot> handledS2Slots = new HashSet<>();
        ImmutableSet.Builder<Expression> injected = ImmutableSet.builder();
        boolean changed = false;
        for (Expression conjunct : conjuncts) {
            GeoCircle circle = extractCircle(conjunct);
            if (circle == null) {
                continue;
            }
            Slot s2Slot = circle.isGeoPointMode()
                    ? findGeoPointIndexSlot(scan, circle.geoSlot)
                    : findS2Slot(scan, circle.lonSlot, circle.latSlot);
            if (s2Slot == null) {
                continue;
            }
            // Skip when this filter already constrains the envelope slot (a user-written
            // predicate or a conjunct injected by an earlier application of this rule), to
            // keep the rewrite idempotent. The circle conjunct itself is excluded: in
            // geo_point mode it necessarily references the envelope slot.
            if (!handledS2Slots.add(s2Slot)
                    || anyOtherConjunctReferences(conjuncts, conjunct, s2Slot)) {
                continue;
            }
            long[] envelope = computeEnvelope(circle);
            if (envelope == null) {
                continue;
            }
            if (circle.isGeoPointMode()) {
                // same-domain literals keep the comparison sargable (no cast wrapping)
                injected.add(new GreaterThanEqual(s2Slot, new GeoPointLiteral(envelope[0])));
                injected.add(new LessThanEqual(s2Slot, new GeoPointLiteral(envelope[1])));
            } else {
                injected.add(new GreaterThanEqual(s2Slot, new BigIntLiteral(envelope[0])));
                injected.add(new LessThanEqual(s2Slot, new BigIntLiteral(envelope[1])));
            }
            changed = true;
        }
        if (!changed) {
            return null;
        }
        Set<Expression> newConjuncts = ImmutableSet.<Expression>builder()
                .addAll(conjuncts)
                .addAll(injected.build())
                .build();
        // the original ST_* conjunct is kept untouched as the exact residual filter
        return filter.withConjunctsAndChild(newConjuncts, scan);
    }

    /**
     * Matches {@code st_distance_sphere(slotLon, slotLat, lonConst, latConst) <[=] rConst} or the mirrored
     * {@code rConst >[=] st_distance_sphere(...)}. Returns null on any deviation from that shape.
     * Package-private static: PushDownGeoAgg (v2b) reuses the exact same circle shape.
     */
    static GeoCircle extractCircle(Expression conjunct) {
        Expression distance;
        Expression bound;
        if (conjunct instanceof LessThan || conjunct instanceof LessThanEqual) {
            distance = ((ComparisonPredicate) conjunct).left();
            bound = ((ComparisonPredicate) conjunct).right();
        } else if (conjunct instanceof GreaterThan || conjunct instanceof GreaterThanEqual) {
            distance = ((ComparisonPredicate) conjunct).right();
            bound = ((ComparisonPredicate) conjunct).left();
        } else {
            return null;
        }
        if (!(distance instanceof StDistanceSphere)) {
            return null;
        }
        StDistanceSphere distanceSphere = (StDistanceSphere) distance;
        // GEO_POINT overload: st_distance_sphere(geoSlot, lonConst, latConst)
        if (distanceSphere.arity() == 3) {
            Expression geoArg = stripCast(distanceSphere.child(0));
            if (!(geoArg instanceof SlotReference) || !geoArg.getDataType().isGeoPointType()) {
                return null;
            }
            Expression lonLit3 = distanceSphere.child(1);
            Expression latLit3 = distanceSphere.child(2);
            if (!(lonLit3 instanceof NumericLiteral) || !(latLit3 instanceof NumericLiteral)
                    || !(bound instanceof NumericLiteral)) {
                return null;
            }
            double lon = ((NumericLiteral) lonLit3).getDouble();
            double lat = ((NumericLiteral) latLit3).getDouble();
            double radius = ((NumericLiteral) bound).getDouble();
            if (!Double.isFinite(lon) || !Double.isFinite(lat) || !Double.isFinite(radius)
                    || lon < -180.0 || lon > 180.0 || lat < -90.0 || lat > 90.0 || radius < 0.0) {
                return null;
            }
            return new GeoCircle((SlotReference) geoArg, lon, lat, radius);
        }
        // first two arguments must be the point columns; slots may be wrapped in casts by type coercion,
        // st_s2_cellid applies the same coercion at generation time so the underlying column still matches
        Expression lonArg = stripCast(distanceSphere.child(0));
        Expression latArg = stripCast(distanceSphere.child(1));
        if (!(lonArg instanceof SlotReference) || !(latArg instanceof SlotReference)) {
            return null;
        }
        // last two arguments and the radius bound must be plain numeric literals; casts of literals are
        // already folded to literals before this rule runs, anything else is skipped
        Expression lonLit = distanceSphere.child(2);
        Expression latLit = distanceSphere.child(3);
        if (!(lonLit instanceof NumericLiteral) || !(latLit instanceof NumericLiteral)
                || !(bound instanceof NumericLiteral)) {
            return null;
        }
        double centerLon = ((NumericLiteral) lonLit).getDouble();
        double centerLat = ((NumericLiteral) latLit).getDouble();
        double radiusMeters = ((NumericLiteral) bound).getDouble();
        if (!Double.isFinite(centerLon) || !Double.isFinite(centerLat) || !Double.isFinite(radiusMeters)
                || centerLon < -180.0 || centerLon > 180.0
                || centerLat < -90.0 || centerLat > 90.0
                || radiusMeters < 0.0) {
            return null;
        }
        return new GeoCircle((SlotReference) lonArg, (SlotReference) latArg, centerLon, centerLat, radiusMeters);
    }

    /**
     * Finds a generated column {@code st_s2_cellid(lonCol, latCol)} in the scan table whose argument column
     * names match the predicate slots, and returns the corresponding slot from the scan output.
     */
    private Slot findS2Slot(LogicalOlapScan scan, SlotReference lonSlot, SlotReference latSlot) {
        for (Column column : scan.getTable().getFullSchema()) {
            GeneratedColumnInfo info = column.getGeneratedColumnInfo();
            if (info == null || info.getExpr() == null) {
                continue;
            }
            if (!matchesStS2CellId(info.getExpr(), lonSlot.getName(), latSlot.getName())) {
                continue;
            }
            for (Slot slot : scan.getOutput()) {
                if (slot.getName().equalsIgnoreCase(column.getName())) {
                    return slot;
                }
            }
        }
        return null;
    }

    /**
     * GeneratedColumnInfo stores the analyzed expression as a legacy Expr (translated by
     * CreateTableInfo.ExpressionToExpr): st_s2_cellid(lon, lat) becomes a FunctionCallExpr whose
     * children are SlotRef (possibly wrapped in CastExpr when the source columns are not DOUBLE).
     */
    private boolean matchesStS2CellId(Expr expr, String lonColName, String latColName) {
        if (!(expr instanceof FunctionCallExpr)) {
            return false;
        }
        FunctionCallExpr fnCall = (FunctionCallExpr) expr;
        if (!"st_s2_cellid".equalsIgnoreCase(fnCall.getFnName().getFunction()) || fnCall.getChildren().size() != 2) {
            return false;
        }
        Expr lonChild = stripLegacyCast(fnCall.getChild(0));
        Expr latChild = stripLegacyCast(fnCall.getChild(1));
        if (!(lonChild instanceof SlotRef) || !(latChild instanceof SlotRef)) {
            return false;
        }
        return lonColName.equalsIgnoreCase(((SlotRef) lonChild).getColumnName())
                && latColName.equalsIgnoreCase(((SlotRef) latChild).getColumnName());
    }

    /**
     * Computes the __s2 envelope of the query circle in the sign-flipped BIGINT key domain.
     * Returns {lo, hi} such that every point within the circle has {@code lo <= __s2 <= hi}, or null.
     */
    private long[] computeEnvelope(GeoCircle circle) {
        // st_distance_sphere: distance = angle * EARTH_RADIUS_METERS, so the circle is exactly the cap
        // of axis angle radius / EARTH_RADIUS_METERS around the center point
        S2Point center = S2LatLng.fromDegrees(circle.centerLat, circle.centerLon).toPoint();
        S2Cap cap = S2Cap.fromAxisAngle(center,
                S1Angle.radians((circle.radiusMeters + MARGIN_METERS) / EARTH_RADIUS_METERS));
        S2RegionCoverer coverer = S2RegionCoverer.builder().setMaxCells(COVERING_MAX_CELLS).build();
        S2CellUnion covering = coverer.getCovering(cap);
        if (covering.size() == 0) {
            return null;
        }
        // TODO(v0-⑤): emit up to max_scan_key_num refined per-cell ranges (OR of ranges) instead of the
        // single [min, max] envelope; needs the Java<->C++ covering cross-check tests as a prerequisite.
        long lo = Long.MAX_VALUE;
        long hi = Long.MIN_VALUE;
        for (S2CellId cell : covering) {
            // __s2 stores rawCellId ^ 2^63 (see class comment); min/max must be taken in the flipped
            // signed domain, comparing raw ids as signed longs would break across faces 4/5
            long cellLo = cell.rangeMin().id() ^ Long.MIN_VALUE;
            long cellHi = cell.rangeMax().id() ^ Long.MIN_VALUE;
            lo = Math.min(lo, cellLo);
            hi = Math.max(hi, cellHi);
        }
        return new long[] {lo, hi};
    }

    private boolean anyOtherConjunctReferences(Set<Expression> conjuncts, Expression self,
            Slot slot) {
        for (Expression conjunct : conjuncts) {
            if (conjunct != self && conjunct.getInputSlots().contains(slot)) {
                return true;
            }
        }
        return false;
    }

    /**
     * GEO_POINT mode: the envelope slot is the predicate's own geo_point column,
     * qualified when the scan table has a GEO index directly on that column.
     */
    private Slot findGeoPointIndexSlot(LogicalOlapScan scan, SlotReference geoSlot) {
        if (!scan.getOutputSet().contains(geoSlot)) {
            return null;
        }
        for (Index index : scan.getTable().getIndexes()) {
            if (index.getIndexType() != IndexDef.IndexType.GEO) {
                continue;
            }
            List<String> cols = index.getColumns();
            if (cols != null && cols.size() == 1 && cols.get(0).equalsIgnoreCase(geoSlot.getName())) {
                return geoSlot;
            }
        }
        return null;
    }

    private static Expression stripCast(Expression expression) {
        while (expression instanceof Cast) {
            expression = ((Cast) expression).child();
        }
        return expression;
    }

    private Expr stripLegacyCast(Expr expr) {
        while (expr instanceof CastExpr) {
            expr = expr.getChild(0);
        }
        return expr;
    }

    /** A "point (lonSlot, latSlot) within radiusMeters of (centerLon, centerLat)" predicate. */
    static final class GeoCircle {
        final SlotReference lonSlot;
        final SlotReference latSlot;
        // GEO_POINT mode (HASI_POC.md §10): the point is a single geo_point slot;
        // lonSlot/latSlot are null and the envelope goes onto this very column.
        final SlotReference geoSlot;
        final double centerLon;
        final double centerLat;
        final double radiusMeters;

        GeoCircle(SlotReference lonSlot, SlotReference latSlot,
                double centerLon, double centerLat, double radiusMeters) {
            this.lonSlot = lonSlot;
            this.latSlot = latSlot;
            this.geoSlot = null;
            this.centerLon = centerLon;
            this.centerLat = centerLat;
            this.radiusMeters = radiusMeters;
        }

        GeoCircle(SlotReference geoSlot, double centerLon, double centerLat, double radiusMeters) {
            this.lonSlot = null;
            this.latSlot = null;
            this.geoSlot = geoSlot;
            this.centerLon = centerLon;
            this.centerLat = centerLat;
            this.radiusMeters = radiusMeters;
        }

        boolean isGeoPointMode() {
            return geoSlot != null;
        }
    }
}
