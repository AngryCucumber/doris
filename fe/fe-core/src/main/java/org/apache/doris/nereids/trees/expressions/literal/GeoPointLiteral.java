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

package org.apache.doris.nereids.trees.expressions.literal;

import org.apache.doris.analysis.LiteralExpr;
import org.apache.doris.nereids.exceptions.AnalysisException;
import org.apache.doris.nereids.trees.expressions.Expression;
import org.apache.doris.nereids.trees.expressions.visitor.ExpressionVisitor;
import org.apache.doris.nereids.types.DataType;
import org.apache.doris.nereids.types.GeoPointType;

import com.google.common.geometry.S2CellId;
import com.google.common.geometry.S2LatLng;

import java.util.Objects;

/**
 * GEO_POINT literal: an s2 leaf cell key in the flipped signed domain
 * (raw id XOR 2^63, identical to st_s2_cellid / the BE GeoPointValue codec).
 * Text form is "[lon, lat]" in GeoJSON axis order — brackets required, so the
 * lat,lon bare-string convention of ES cannot be confused with it.
 */
public class GeoPointLiteral extends Literal implements ComparableLiteral {

    /** Wrapper so getValue().toString() yields the text form (see IPv4Literal.Inet4Addr). */
    public static class GeoPointKey {
        private final long key;

        public GeoPointKey(long key) {
            this.key = key;
        }

        public long toLong() {
            return key;
        }

        @Override
        public String toString() {
            return keyToText(key);
        }

        @Override
        public int hashCode() {
            return Objects.hash(key);
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof GeoPointKey && key == ((GeoPointKey) other).key;
        }
    }

    private final GeoPointKey value;

    public GeoPointLiteral(String text) throws AnalysisException {
        super(GeoPointType.INSTANCE);
        this.value = new GeoPointKey(parseTextToKey(text));
    }

    public GeoPointLiteral(long key) throws AnalysisException {
        super(GeoPointType.INSTANCE);
        if (!isValidKey(key)) {
            throw new AnalysisException("not a valid geo_point cell key: " + key);
        }
        this.value = new GeoPointKey(key);
    }

    /** Encodes (lon, lat) degrees to the flipped leaf cell key. */
    public static long encode(double lon, double lat) throws AnalysisException {
        if (!Double.isFinite(lon) || !Double.isFinite(lat)
                || lon < -180.0 || lon > 180.0 || lat < -90.0 || lat > 90.0) {
            throw new AnalysisException(
                    String.format("geo_point coordinates out of range: [%s, %s]", lon, lat));
        }
        return S2CellId.fromLatLng(S2LatLng.fromDegrees(lat, lon)).id() ^ Long.MIN_VALUE;
    }

    /** Parses "[lon, lat]" (whitespace tolerated, brackets required). */
    public static long parseTextToKey(String text) throws AnalysisException {
        String trimmed = text.trim();
        if (trimmed.length() < 2 || trimmed.charAt(0) != '['
                || trimmed.charAt(trimmed.length() - 1) != ']') {
            throw new AnalysisException("geo_point text must be \"[lon, lat]\", got: " + text);
        }
        String[] parts = trimmed.substring(1, trimmed.length() - 1).split(",");
        if (parts.length != 2) {
            throw new AnalysisException("geo_point text must be \"[lon, lat]\", got: " + text);
        }
        double lon;
        double lat;
        try {
            lon = Double.parseDouble(parts[0].trim());
            lat = Double.parseDouble(parts[1].trim());
        } catch (NumberFormatException e) {
            throw new AnalysisException("geo_point text must be \"[lon, lat]\", got: " + text);
        }
        return encode(lon, lat);
    }

    /** Formats a flipped cell key as "[lon, lat]" (cell center decode). */
    public static String keyToText(long key) {
        S2CellId cell = new S2CellId(key ^ Long.MIN_VALUE);
        if (!cell.isValid()) {
            return "[invalid]";
        }
        S2LatLng center = cell.toLatLng();
        return "[" + center.lngDegrees() + ", " + center.latDegrees() + "]";
    }

    public static boolean isValidKey(long key) {
        return new S2CellId(key ^ Long.MIN_VALUE).isValid();
    }

    @Override
    public GeoPointKey getValue() {
        return value;
    }

    @Override
    public double getDouble() {
        return (double) value.toLong();
    }

    @Override
    protected Expression uncheckedCastTo(DataType targetType) throws AnalysisException {
        if (targetType.isBigIntType()) {
            // Identity passthrough of the stored flipped S2 cell key (HASI_POC.md
            // §13.3 F3a) -- the exact inverse of the BIGINT->GEO_POINT ingest cast.
            // Without this, constant folding would fall back to text parsing of
            // "[lon, lat]" and throw NumberFormatException instead of folding.
            return new BigIntLiteral(value.toLong());
        }
        return super.uncheckedCastTo(targetType);
    }

    @Override
    public <R, C> R accept(ExpressionVisitor<R, C> visitor, C context) {
        return visitor.visitGeoPointLiteral(this, context);
    }

    @Override
    public LiteralExpr toLegacyLiteral() {
        return new org.apache.doris.analysis.GeoPointLiteral(value.toLong());
    }

    @Override
    public int compareTo(ComparableLiteral other) {
        if (other instanceof GeoPointLiteral) {
            // signed compare in the flipped domain == unsigned Hilbert order (storage order)
            return Long.compare(value.toLong(), ((GeoPointLiteral) other).value.toLong());
        }
        if (other instanceof NullLiteral) {
            return 1;
        }
        if (other instanceof MaxLiteral) {
            return -1;
        }
        throw new RuntimeException("Cannot compare two values with different data types: "
                + this + " (" + dataType + ") vs " + other + " (" + ((Literal) other).dataType + ")");
    }
}
