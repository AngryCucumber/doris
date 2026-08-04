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
// software distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied.  See the License
// for the specific language governing permissions and limitations
// under the License.

import groovy.json.JsonSlurper

def getProfileList = {
    def dst = 'http://' + context.config.feHttpAddress
    def conn = new URL(dst + "/rest/v1/query_profile").openConnection()
    conn.setRequestMethod("GET")
    def encoding = Base64.getEncoder().encodeToString((context.config.feHttpUser + ":" +
            (context.config.feHttpPassword == null ? "" : context.config.feHttpPassword)).getBytes("UTF-8"))
    conn.setRequestProperty("Authorization", "Basic ${encoding}")
    return conn.getInputStream().getText()
}

def getProfile = { id ->
    def dst = 'http://' + context.config.feHttpAddress
    def conn = new URL(dst + "/api/profile/text/?query_id=$id").openConnection()
    conn.setRequestMethod("GET")
    def encoding = Base64.getEncoder().encodeToString((context.config.feHttpUser + ":" +
            (context.config.feHttpPassword == null ? "" : context.config.feHttpPassword)).getBytes("UTF-8"))
    conn.setRequestProperty("Authorization", "Basic ${encoding}")
    return conn.getInputStream().getText()
}

// GEO_POINT native type backtest (HASI_POC.md §10): ES-geo_point-parity ingest/output
// ("[lon, lat]" text + array literal + geo_point(lon,lat) + bigint key migration),
// value semantics (stored point == cell center, ≤~1cm quantization), and the whole
// HASI query chain (v0 envelope / v1.5 exact / v2b agg fold) running directly on a
// GEO_POINT column with the GEO index on the column itself.
suite("geo_point_type") {
    sql "SET enable_nereids_planner=true;"
    sql "SET enable_fallback_to_original_planner=false;"

    // ---- 1. type + ingest matrix (lon/lat doubles kept alongside as ground truth) ----
    sql "drop table if exists geo_point_t"
    sql """
    create table geo_point_t (
        `loc` geo_point null,
        `id` bigint not null,
        `lon` double null,
        `lat` double null,
        `val` double null,
        INDEX idx_loc(`loc`) USING GEO PROPERTIES("leaf_rows" = "64", "measures" = "val")
    ) engine=olap
    duplicate key(`loc`)
    distributed by hash(`id`) buckets 2
    properties("replication_num" = "1");
    """

    // string literal, array literal, constructor function -- all three ES-style forms
    sql """insert into geo_point_t values
        ('[116.40, 39.90]', 0, 116.40, 39.90, 1.0),
        ([116.41, 39.91], 1, 116.41, 39.91, 2.0),
        (geo_point(116.42, 39.92), 2, 116.42, 39.92, null),
        (null, 3, null, null, 4.0)"""
    sql "sync"

    // output form: "[lon, lat]" text, center within ~1cm of the ingested point
    def out = sql "select loc, lon, lat from geo_point_t where id < 3 order by id"
    assertEquals(3, out.size())
    out.each { row ->
        def text = row[0].toString()
        assertTrue(text.startsWith("[") && text.endsWith("]"), "geo_point text form: ${text}")
        def parts = text.substring(1, text.length() - 1).split(",")
        assertEquals(2, parts.length)
        double dLon = Double.parseDouble(parts[0].trim()) - ((Number) row[1]).doubleValue()
        double dLat = Double.parseDouble(parts[1].trim()) - ((Number) row[2]).doubleValue()
        // 1e-7 deg ~ 1.1cm
        assertTrue(Math.abs(dLon) < 2e-7 && Math.abs(dLat) < 2e-7,
                "cell-center decode drift too large: ${text} vs (${row[1]}, ${row[2]})")
    }
    def nullRow = sql "select loc from geo_point_t where id = 3"
    assertEquals(null, nullRow[0][0])

    // geo_lon/geo_lat accessors agree with the text form
    def coordDrift = sql """select count(*) from geo_point_t
        where id < 3 and (abs(geo_lon(loc) - lon) > 2e-7 or abs(geo_lat(loc) - lat) > 2e-7)"""
    assertEquals(0L, coordDrift[0][0])

    // text round trip re-encodes to the same cell; distance-0 to itself
    def roundTrip = sql """select count(*) from geo_point_t
        where loc is not null and cast(cast(loc as string) as geo_point) != loc"""
    assertEquals(0L, roundTrip[0][0])

    // invalid input -> NULL (non-strict cast semantics), bare "a,b" rejected on purpose
    def invalids = sql """select cast('[181.0, 0.0]' as geo_point),
                                 cast('[0.0, 91.0]' as geo_point),
                                 cast('116.4, 39.9' as geo_point),
                                 cast('nonsense' as geo_point)"""
    invalids[0].each { assertEquals(null, it) }

    // bigint key migration: cast(st_s2_cellid(lon,lat) as geo_point) == geo_point(lon,lat)
    def migrate = sql """select count(*) from geo_point_t where loc is not null
        and cast(cast(st_s2_cellid(lon, lat) as bigint) as geo_point) != loc"""
    assertEquals(0L, migrate[0][0])

    // 3-arg distance == 4-arg distance evaluated at the quantized point
    def distDrift = sql """select count(*) from geo_point_t where loc is not null and
        abs(st_distance_sphere(loc, 116.40, 39.90)
            - st_distance_sphere(geo_lon(loc), geo_lat(loc), 116.40, 39.90)) > 1e-9"""
    assertEquals(0L, distDrift[0][0])

    // ---- 2. grid data: retrieval parity across switch configs ----
    sql "drop table if exists geo_point_grid_t"
    sql """
    create table geo_point_grid_t (
        `loc` geo_point null,
        `id` bigint not null,
        `lon` double null,
        `lat` double null,
        `val` double null,
        INDEX idx_loc(`loc`) USING GEO PROPERTIES("leaf_rows" = "64", "measures" = "val")
    ) engine=olap
    duplicate key(`loc`)
    distributed by hash(`id`) buckets 2
    properties("replication_num" = "1");
    """
    def gridValues = []
    long gid = 0
    for (double dLon = -0.5; dLon <= 0.5; dLon += 0.02) {
        for (double dLat = -0.5; dLat <= 0.5; dLat += 0.02) {
            double lon = 116.40 + dLon
            double lat = 39.90 + dLat
            def v = (gid % 9 == 0) ? "null" : String.valueOf(gid * 0.5)
            gridValues << "(geo_point(${lon}, ${lat}), ${gid++}, ${lon}, ${lat}, ${v})"
        }
    }
    gridValues << "(null, ${gid++}, null, 40.0, 1.5)"
    gridValues.collate(500).each { chunk ->
        sql "insert into geo_point_grid_t values ${chunk.join(',')}"
    }
    sql "sync"

    def circles = [
            [116.40d, 39.90d, 5000.0d],
            [116.40d, 39.90d, 30000.0d],
            [116.40d, 39.90d, 80000.0d],
            [116.40d, 39.90d, 1.0d],  // near-empty
    ]
    def checkConfigs = { String phase ->
        circles.each { q ->
            def query = """select id from geo_point_grid_t
                           where st_distance_sphere(loc, ${q[0]}, ${q[1]}) < ${q[2]}
                           order by id"""
            sql "set enable_geo_predicate_rewrite=true;"
            sql "set enable_geo_index_query=true;"
            sql "set enable_geo_index_exact_filter=true;"
            def exact = sql query
            sql "set enable_geo_index_exact_filter=false;"
            def superset = sql query
            sql "set enable_geo_index_query=false;"
            def rewriteOnly = sql query
            sql "set enable_geo_predicate_rewrite=false;"
            def fullScan = sql query
            sql "set enable_geo_predicate_rewrite=true;"
            sql "set enable_geo_index_query=true;"
            sql "set enable_geo_index_exact_filter=true;"
            assertEquals(fullScan, exact, "[geo_point ${phase}] exact vs full r=${q[2]}")
            assertEquals(fullScan, superset, "[geo_point ${phase}] superset vs full r=${q[2]}")
            assertEquals(fullScan, rewriteOnly, "[geo_point ${phase}] envelope vs full r=${q[2]}")
        }
        // cross-check vs the 4-arg predicate on true lon/lat: any count difference
        // must be explainable by the ≤5cm quantization (bracket the radius)
        circles.each { q ->
            def cGeo = sql """select count(*) from geo_point_grid_t
                              where st_distance_sphere(loc, ${q[0]}, ${q[1]}) < ${q[2]}"""
            def rLo = Math.max(0.0d, q[2] - 0.05d)
            def rHi = q[2] + 0.05d
            def cLo = sql """select count(*) from geo_point_grid_t
                             where st_distance_sphere(lon, lat, ${q[0]}, ${q[1]}) < ${rLo}"""
            def cHi = sql """select count(*) from geo_point_grid_t
                             where st_distance_sphere(lon, lat, ${q[0]}, ${q[1]}) < ${rHi}"""
            long g = cGeo[0][0] as long
            assertTrue((cLo[0][0] as long) <= g && g <= (cHi[0][0] as long),
                    "[geo_point ${phase}] quantized count ${g} outside [${cLo[0][0]}, ${cHi[0][0]}] r=${q[2]}")
        }
    }
    checkConfigs("flush")

    // ---- 3. v2b aggregate fold directly on the geo_point column ----
    def aggCompare = { Object a, Object b, String msg ->
        if (a == null || b == null) {
            assertEquals(a, b, msg)
        } else if (a instanceof Double || a instanceof BigDecimal) {
            double da = ((Number) a).doubleValue()
            double db = ((Number) b).doubleValue()
            assertTrue(Math.abs(da - db) <= 1e-9 * Math.max(1.0d, Math.abs(da)),
                    "${msg}: ${da} vs ${db}")
        } else {
            assertEquals(a, b, msg)
        }
    }
    def aggBattery = { String phase ->
        def aggQueries = [
            "select count(*), count(val), sum(val), min(val), max(val) from geo_point_grid_t where st_distance_sphere(loc, 116.40, 39.90) < 80000",
            "select count(*), count(val), sum(val), min(val), max(val) from geo_point_grid_t where st_distance_sphere(loc, 116.40, 39.90) < 30000",
            "select count(*), count(val), sum(val) from geo_point_grid_t where st_distance_sphere(loc, 10.0, 10.0) < 100",
            "select avg(val), sum(val) from geo_point_grid_t where st_distance_sphere(loc, 116.40, 39.90) < 80000",
        ]
        aggQueries.eachWithIndex { q, qi ->
            sql "set enable_geo_index_query=true;"
            sql "set enable_geo_index_exact_filter=true;"
            sql "set enable_geo_agg_pushdown=true;"
            def fold = sql q
            sql "set enable_geo_agg_pushdown=false;"
            def rowPath = sql q
            sql "set enable_geo_index_query=false;"
            def fullScan = sql q
            sql "set enable_geo_index_query=true;"
            sql "set enable_geo_agg_pushdown=true;"
            assertEquals(rowPath.size(), fold.size(), "[gp-agg ${phase} q${qi}] row count")
            for (int r = 0; r < fold.size(); r++) {
                for (int c = 0; c < fold[r].size(); c++) {
                    aggCompare(rowPath[r][c], fold[r][c], "[gp-agg ${phase} q${qi}] cell(${r},${c}) fold vs row-path")
                    aggCompare(fullScan[r][c], fold[r][c], "[gp-agg ${phase} q${qi}] cell(${r},${c}) fold vs full-scan")
                }
            }
        }
    }
    def assertFolded = { String tag ->
        sql "set profile_level=2;"
        sql "set enable_profile=true;"
        def foldToken = "geo_point_fold_${tag}_" + System.currentTimeMillis()
        sql """select /* ${foldToken} */ count(*), count(val), sum(val), min(val), max(val)
               from geo_point_grid_t where st_distance_sphere(loc, 116.40, 39.90) < 80000"""
        String foldProfileId = ""
        int foldAttempts = 0
        while (foldAttempts < 10 && (foldProfileId == null || foldProfileId == "")) {
            List profileData = new JsonSlurper().parseText(getProfileList()).data.rows
            for (def profileItem in profileData) {
                if (profileItem["Sql Statement"].toString().contains(foldToken)) {
                    foldProfileId = profileItem["Profile ID"].toString()
                    break
                }
            }
            if (foldProfileId == null || foldProfileId == "") {
                Thread.sleep(300)
            }
            foldAttempts++
        }
        assertTrue(foldProfileId != null && foldProfileId != "",
                "profile for tagged geo_point agg query not found (${tag})")
        Thread.sleep(800)
        def foldProfile = getProfile(foldProfileId).toString()
        def foldLines = foldProfile.split("\n").findAll { it.contains("GeoAggFoldedLeaves") }
        assertTrue(!foldLines.isEmpty(), "GeoAggFoldedLeaves missing from profile (${tag})")
        def anyFolded = foldLines.any { line ->
            def m = (line =~ /GeoAggFoldedLeaves:\s*([0-9.]+)/)
            m.find() && Double.parseDouble(m.group(1)) > 0
        }
        assertTrue(anyFolded,
                "no leaves folded on the geo_point column (${tag}): " + foldLines.join(" | "))
        sql "set enable_profile=false;"
    }
    aggBattery("flush")
    assertFolded("flush")

    // ---- 4. compaction keeps the index + sketches on the geo_point column ----
    trigger_and_wait_compaction("geo_point_grid_t", "full")
    checkConfigs("compacted")
    aggBattery("compacted")
    assertFolded("compacted")

    // ---- 5. v4.5 F3 cast hygiene (HASI_POC.md §13.3) ----
    // F3a geo_point -> bigint: identity passthrough of the flipped key, the exact
    // inverse of the ingest direction -- roundtrip against st_s2_cellid, both the
    // column path (BE cast) and the constant path (FE fold).
    def castMismatch = sql """select count(*) from geo_point_t
                              where loc is not null
                                and cast(loc as bigint) != st_s2_cellid(lon, lat)"""
    assertEquals(0, (castMismatch[0][0] as long), "cast(loc as bigint) != st_s2_cellid roundtrip")
    def foldedCast = sql "select cast(cast('[116.4, 39.9]' as geo_point) as bigint), st_s2_cellid(116.4, 39.9)"
    assertEquals(foldedCast[0][1], foldedCast[0][0], "FE-folded gp->bigint != st_s2_cellid")
    def doubleRoundtrip = sql """select count(*) from geo_point_t
                                 where loc is not null
                                   and cast(cast(loc as bigint) as geo_point) != loc"""
    assertEquals(0, (doubleRoundtrip[0][0] as long), "gp->bigint->gp roundtrip drift")

    // F3b non-literal array constructor: CAST(array(lon, lat) AS geo_point) rides
    // the geo_point scalar; must equal the direct constructor on every row.
    def arrayCast = sql """select count(*) from geo_point_t
                           where lon is not null and lat is not null
                             and cast(array(lon, lat) as geo_point) != geo_point(lon, lat)"""
    assertEquals(0, (arrayCast[0][0] as long), "cast(array(lon,lat) as geo_point) != geo_point()")
    // and it works as an INSERT...SELECT source (the ES-parity migration shape)
    sql "drop table if exists geo_point_arrcast_t"
    sql """
    create table geo_point_arrcast_t (
        `loc` geo_point null,
        `id` bigint not null
    ) engine=olap duplicate key(`loc`)
    distributed by hash(`id`) buckets 1 properties("replication_num" = "1");
    """
    sql """insert into geo_point_arrcast_t
           select cast(array(lon, lat) as geo_point), id from geo_point_t where lon is not null"""
    def arrIngest = sql """select count(*) from geo_point_arrcast_t a
                           join geo_point_t g on a.id = g.id
                           where a.loc != geo_point(g.lon, g.lat)"""
    assertEquals(0, (arrIngest[0][0] as long), "array-cast ingest drift vs geo_point()")

    // Nullability probe (review finding): a NOT NULL bigint source cast to
    // geo_point must run through the runtime path (non-nullable input, nullable
    // declared result) without block type/column mismatch; ordinary ids are not
    // valid cell keys, so every row yields NULL in non-strict mode.
    def nnProbe = sql """select count(*), count(cast(id as geo_point))
                         from geo_point_t where id is not null"""
    assertTrue((nnProbe[0][0] as long) > 0, "nullability probe scanned nothing")
    assertEquals(0, (nnProbe[0][1] as long), "invalid keys must cast to NULL, got non-NULL")
    // valid keys through the same non-nullable runtime path stay non-NULL
    def nnValid = sql """select count(*) from geo_point_t
                         where lon is not null
                           and cast(cast(st_s2_cellid(lon, lat) as bigint) as geo_point)
                               != geo_point(lon, lat)"""
    assertEquals(0, (nnValid[0][0] as long), "valid-key bigint->geo_point drift")
}
