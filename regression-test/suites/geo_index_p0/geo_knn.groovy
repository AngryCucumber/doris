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

// HASI v4 kNN backtest: `ORDER BY st_distance_sphere(...), id LIMIT k` must be
// bit-exact with the pushdown on vs off (enable_geo_knn_pushdown) for both index
// modes (lon/lat + __s2 generated column; native geo_point column), across multiple
// segments, after full compaction, with NULL coordinates present (per-segment
// fallback), with a WHERE circle on top (fallback), with OFFSET, and for DESC
// (never pushed). Effectiveness is asserted via the RowsGeoKnnFiltered profile
// counter and the GEO SORT INFO explain block.
suite("geo_knn") {
    sql "SET enable_nereids_planner=true;"
    sql "SET enable_fallback_to_original_planner=false;"

    def centers = [[116.40d, 39.90d], [179.95d, 10.0d], [0.0d, 89.8d], [45.0d, 0.0d]]

    // Grid data in several insert batches (several segments). NULL rows land in
    // their OWN batch/segment so the grid segments stay NULL-free and the pushdown
    // can fire there (a segment with any NULL bails out by design under the default
    // ASC nulls-first ordering).
    def insertGrid = { String table, boolean geoPointMode ->
        long id = 0
        centers.each { c ->
            def insertValues = []
            for (double dLon = -0.6; dLon <= 0.6; dLon += 0.05) {
                for (double dLat = -0.6; dLat <= 0.6; dLat += 0.05) {
                    double lon = c[0] + dLon
                    if (lon > 180.0) lon -= 360.0
                    if (lon < -180.0) lon += 360.0
                    double lat = Math.max(-90.0d, Math.min(90.0d, c[1] + dLat))
                    if (geoPointMode) {
                        insertValues << "(geo_point(${lon}, ${lat}), ${id++}, ${lon}, ${lat})"
                    } else {
                        insertValues << "(${id++}, ${lon}, ${lat})"
                    }
                }
            }
            insertValues.collate(500).each { chunk ->
                if (geoPointMode) {
                    sql "insert into ${table}(loc, id, lon, lat) values ${chunk.join(',')}"
                } else {
                    sql "insert into ${table}(id, lon, lat) values ${chunk.join(',')}"
                }
            }
        }
        // NULL rows isolated in their own segment
        if (geoPointMode) {
            sql "insert into ${table}(loc, id, lon, lat) values (null, ${id++}, null, null), (null, ${id++}, null, null)"
        } else {
            sql "insert into ${table}(id, lon, lat) values (${id++}, null, null), (${id++}, null, null)"
        }
        sql "sync"
    }

    // ---- tables ----
    sql "drop table if exists geo_knn_dup_t"
    sql """
    create table geo_knn_dup_t (
        `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
        `id` bigint not null,
        `lon` double null,
        `lat` double null,
        INDEX idx_s2(`__s2`) USING GEO PROPERTIES("leaf_rows" = "64"),
        INDEX idx_lon(`lon`) USING INVERTED
    ) engine=olap
    duplicate key(`__s2`)
    distributed by hash(`id`) buckets 2
    properties("replication_num" = "1");
    """
    insertGrid("geo_knn_dup_t", false)

    sql "drop table if exists geo_knn_gp_t"
    sql """
    create table geo_knn_gp_t (
        `loc` geo_point null,
        `id` bigint not null,
        `lon` double null,
        `lat` double null,
        INDEX idx_loc(`loc`) USING GEO PROPERTIES("leaf_rows" = "64")
    ) engine=olap
    duplicate key(`loc`)
    distributed by hash(`id`) buckets 2
    properties("replication_num" = "1");
    """
    insertGrid("geo_knn_gp_t", true)

    def distExpr = { String table ->
        table == "geo_knn_gp_t" ? "st_distance_sphere(loc, %s, %s)"
                                : "st_distance_sphere(lon, lat, %s, %s)"
    }

    // On/off bit-exact battery. The tie-break `id` key makes the comparison
    // deterministic; the distance column itself is part of the compared output, so
    // any value divergence (contract C2) fails too.
    def checkOnOff = { String table, String tag ->
        centers.each { c ->
            [1, 10, 100, 20000].each { k ->
                def d = String.format(distExpr(table), c[0].toString(), c[1].toString())
                def query = """select id, ${d} as dist from ${table}
                               order by dist asc, id asc limit ${k}"""
                sql "set enable_geo_knn_pushdown=true;"
                def withKnn = sql query
                sql "set enable_geo_knn_pushdown=false;"
                def withoutKnn = sql query
                assertEquals(withoutKnn, withKnn,
                        "[${tag}] knn pushdown changed results: ${table} center=(${c[0]},${c[1]}) k=${k}")
            }
        }
        sql "set enable_geo_knn_pushdown=true;"
    }

    // Variants that must stay correct through the fallback / non-push shapes.
    def checkVariants = { String table, String tag ->
        def d = String.format(distExpr(table), "116.40", "39.90")
        def variants = [
                // OFFSET (limit+offset is pushed as the scan limit)
                "select id, ${d} as dist from ${table} order by dist asc, id asc limit 10 offset 5",
                // DESC: never pushed, must fall through cleanly
                "select id, ${d} as dist from ${table} order by dist desc, id asc limit 10",
                // WHERE circle + kNN: v4 POC bails per segment, v1.5 handles the filter
                "select id, ${d} as dist from ${table} where ${d} < 50000 order by dist asc, id asc limit 10",
                // distance not selected (alias only exists in the normalized project)
                "select id from ${table} order by ${d} asc, id asc limit 10",
        ]
        if (table == "geo_knn_dup_t") {
            // an INVERTED index answers this range predicate entirely, exercising
            // the generic need-read suppression x kNN-fallback interaction
            variants << "select id, ${d} as dist from ${table} where lon > 116.0 order by dist asc, id asc limit 10"
        }
        variants.each { query ->
            sql "set enable_geo_knn_pushdown=true;"
            def on = sql query
            sql "set enable_geo_knn_pushdown=false;"
            def off = sql query
            assertEquals(off, on, "[${tag}] variant mismatch on ${table}: ${query}")
        }
        // scanner-resident conjuncts (common-expr pushdown disabled): the WHERE is
        // applied AFTER the scan block, so a committed top-k would drop rows
        sql "set enable_common_expr_pushdown=false;"
        def scannerQ = """select id, ${d} as dist from ${table}
                          where abs(${d}) < 60000 order by dist asc, id asc limit 10"""
        sql "set enable_geo_knn_pushdown=true;"
        def scannerOn = sql scannerQ
        sql "set enable_geo_knn_pushdown=false;"
        def scannerOff = sql scannerQ
        assertEquals(scannerOff, scannerOn, "[${tag}] scanner-conjunct variant mismatch on ${table}")
        sql "set enable_common_expr_pushdown=true;"
        sql "set enable_geo_knn_pushdown=true;"
    }

    // Explain must carry the scan-level kNN hint.
    def checkExplain = { String table ->
        def d = String.format(distExpr(table), "116.40", "39.90")
        def plan = sql "explain select id, ${d} as dist from ${table} order by dist asc, id asc limit 10"
        def text = plan.collect { it.toString() }.join("\n")
        assertTrue(text.contains("GEO SORT INFO"), "explain missing GEO SORT INFO for ${table}:\n${text}")
        assertTrue(text.contains("GEO SORT LIMIT: 10"), "explain missing GEO SORT LIMIT for ${table}:\n${text}")
    }

    // The pushdown must actually fire on the NULL-free grid segments.
    def assertKnnFired = { String table, String tag ->
        sql "set profile_level=2;"
        sql "set enable_profile=true;"
        sql "set enable_geo_knn_pushdown=true;"
        def token = "geo_knn_${tag}_" + System.currentTimeMillis()
        def d = String.format(distExpr(table), "116.40", "39.90")
        sql "select /* ${token} */ id, ${d} as dist from ${table} order by dist asc, id asc limit 100"
        String profileId = ""
        int attempts = 0
        while (attempts < 10 && (profileId == null || profileId == "")) {
            List profileData = new JsonSlurper().parseText(getProfileList()).data.rows
            for (def profileItem in profileData) {
                if (profileItem["Sql Statement"].toString().contains(token)) {
                    profileId = profileItem["Profile ID"].toString()
                    break
                }
            }
            if (profileId == null || profileId == "") {
                Thread.sleep(300)
            }
            attempts++
        }
        assertTrue(profileId != null && profileId != "", "profile for tagged knn query not found (${tag})")
        Thread.sleep(800)
        def profile = getProfile(profileId).toString()
        def lines = profile.split("\n").findAll { it.contains("RowsGeoKnnFiltered") }
        assertTrue(!lines.isEmpty(), "RowsGeoKnnFiltered missing from profile (${tag})")
        def anyFired = lines.any { line ->
            def m = (line =~ /RowsGeoKnnFiltered:\s*([0-9.]+)/)
            m.find() && Double.parseDouble(m.group(1)) > 0
        }
        assertTrue(anyFired, "knn pushdown never fired (${tag}): " + lines.join(" | "))
        sql "set enable_profile=false;"
    }

    // ---- 1. multi-segment (pre-compaction) ----
    ["geo_knn_dup_t", "geo_knn_gp_t"].each { t ->
        checkExplain(t)
        checkOnOff(t, "flush")
        checkVariants(t, "flush")
        assertKnnFired(t, "flush_" + t)
    }

    // ---- 2. after full compaction (NULL rows merge into the grid segments: the
    // merged segment bails by the NULL gate, correctness must hold either way) ----
    trigger_and_wait_compaction("geo_knn_dup_t", "full")
    trigger_and_wait_compaction("geo_knn_gp_t", "full")
    ["geo_knn_dup_t", "geo_knn_gp_t"].each { t ->
        checkOnOff(t, "compacted")
        checkVariants(t, "compacted")
    }

    // ---- 3. MOW deletes: delete-bitmap rows must never surface in the top-k ----
    sql "drop table if exists geo_knn_mow_t"
    sql """
    create table geo_knn_mow_t (
        `id` bigint not null,
        `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
        `lon` double null,
        `lat` double null,
        INDEX idx_s2(`__s2`) USING GEO PROPERTIES("leaf_rows" = "64")
    ) engine=olap
    unique key(`id`)
    cluster by(`__s2`)
    distributed by hash(`id`) buckets 2
    properties("replication_num" = "1", "enable_unique_key_merge_on_write" = "true");
    """
    def mowValues = []
    long mid = 0
    for (double dLon = -0.5; dLon <= 0.5; dLon += 0.02) {
        for (double dLat = -0.5; dLat <= 0.5; dLat += 0.02) {
            mowValues << "(${mid++}, ${116.40 + dLon}, ${39.90 + dLat})"
        }
    }
    mowValues.collate(500).each { chunk ->
        sql "insert into geo_knn_mow_t(id, lon, lat) values ${chunk.join(',')}"
    }
    sql "sync"
    // Delete the 3 nearest rows to the query center; they must vanish from the top-k.
    sql "set enable_geo_knn_pushdown=true;"
    def nearest = sql """select id from geo_knn_mow_t
                         order by st_distance_sphere(lon, lat, 116.40, 39.90) asc, id asc limit 3"""
    nearest.each { row -> sql "delete from geo_knn_mow_t where id = ${row[0]}" }
    sql "sync"
    def q = """select id, st_distance_sphere(lon, lat, 116.40, 39.90) as dist
               from geo_knn_mow_t order by dist asc, id asc limit 10"""
    def onAfterDelete = sql q
    nearest.each { deleted ->
        onAfterDelete.each { row ->
            assertTrue(row[0] != deleted[0], "deleted row ${deleted[0]} surfaced in knn top-k")
        }
    }
    sql "set enable_geo_knn_pushdown=false;"
    def offAfterDelete = sql q
    assertEquals(offAfterDelete, onAfterDelete, "mow delete: knn on/off mismatch")
    sql "set enable_geo_knn_pushdown=true;"
}
