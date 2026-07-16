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

import org.apache.doris.nereids.exceptions.AnalysisException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * GEO_POINT literal codec guardrails (HASI_POC.md §10): the flipped-key encoding
 * must round-trip through the "[lon, lat]" text form (re-encoding a decoded center
 * always lands on the same cell), and invalid inputs must be rejected.
 */
public class GeoPointLiteralTest {

    @Test
    public void testEncodeDecodeRoundTrip() throws Exception {
        double[][] points = {
                {116.40, 39.90}, {-73.99, 40.72}, {179.999, -85.0},
                {-180.0, 0.0}, {180.0, 0.0}, {0.0, 90.0}, {0.0, -90.0}, {0.0, 0.0},
        };
        for (double[] p : points) {
            long key = GeoPointLiteral.encode(p[0], p[1]);
            Assertions.assertTrue(GeoPointLiteral.isValidKey(key), "key invalid for " + p[0]);
            String text = GeoPointLiteral.keyToText(key);
            // re-encoding the printed center must land on the same cell
            Assertions.assertEquals(key, GeoPointLiteral.parseTextToKey(text),
                    "text round trip changed the cell: " + text);
            // decoded center within ~1cm (1e-7 deg) of the original point
            String[] parts = text.substring(1, text.length() - 1).split(",");
            double lonDrift = Math.abs(Double.parseDouble(parts[0].trim()) - p[0]);
            double latDrift = Math.abs(Double.parseDouble(parts[1].trim()) - p[1]);
            // longitude drift blows up near the poles (small circle), check lat only there
            if (Math.abs(p[1]) < 89.0) {
                Assertions.assertTrue(lonDrift < 2e-7 || lonDrift > 359.9,
                        "lon drift " + lonDrift + " at " + text);
            }
            Assertions.assertTrue(latDrift < 2e-7, "lat drift " + latDrift + " at " + text);
        }
    }

    @Test
    public void testParseRejects() {
        // bare "a,b" is intentionally rejected: the ES bare-string convention is
        // lat,lon and silently accepting either axis order would corrupt data
        String[] bad = {"116.4, 39.9", "[181.0, 0.0]", "[0.0, 91.0]", "[1.0]",
                        "[1.0, 2.0, 3.0]", "[a, b]", "", "[nan, 0]", "[inf, 0]"};
        for (String s : bad) {
            Assertions.assertThrows(AnalysisException.class,
                    () -> GeoPointLiteral.parseTextToKey(s), "should reject: " + s);
        }
    }

    @Test
    public void testWhitespaceTolerated() throws Exception {
        long a = GeoPointLiteral.parseTextToKey("[116.4,39.9]");
        long b = GeoPointLiteral.parseTextToKey("  [ 116.4 , 39.9 ]  ");
        Assertions.assertEquals(a, b);
    }

    @Test
    public void testInvalidKeyRejected() {
        // raw cell 0 (flipped: Long.MIN_VALUE) is the NULL sentinel, not a valid cell
        Assertions.assertFalse(GeoPointLiteral.isValidKey(Long.MIN_VALUE));
        Assertions.assertThrows(AnalysisException.class, () -> new GeoPointLiteral(Long.MIN_VALUE));
    }

    @Test
    public void testOrderMatchesSignedKeyOrder() throws Exception {
        GeoPointLiteral a = new GeoPointLiteral(GeoPointLiteral.encode(116.40, 39.90));
        GeoPointLiteral b = new GeoPointLiteral(GeoPointLiteral.encode(116.41, 39.90));
        long ka = a.getValue().toLong();
        long kb = b.getValue().toLong();
        Assertions.assertEquals(Long.compare(ka, kb), Integer.signum(a.compareTo(b)));
    }
}
