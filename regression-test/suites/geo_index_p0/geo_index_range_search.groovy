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

// HASI geo index v1 backtest (design doc HASI_POC.md §7 v1 / §8.1): the GEO index must
// only ever narrow the row bitmap, so enabling/disabling `enable_geo_index_query` must be
// bit-exact for every query, across multiple segments, after compaction, after MOW
// deletes, and for the non-key predicate-filter form. Index effectiveness is asserted
// separately through the RowsGeoIndexFiltered profile counter.
suite("geo_index_range_search") {
    sql "SET enable_nereids_planner=true;"
    sql "SET enable_fallback_to_original_planner=false;"

    def insertGrid = { String table ->
        def centers = [[116.40d, 39.90d], [179.95d, 10.0d], [0.0d, 89.8d], [45.0d, 0.0d]]
        long id = 0
        // several INSERT batches -> several rowsets/segments before compaction
        centers.each { c ->
            def insertValues = []
            for (double dLon = -1.0; dLon <= 1.0; dLon += 0.05) {
                for (double dLat = -1.0; dLat <= 1.0; dLat += 0.05) {
                    double lon = c[0] + dLon
                    if (lon > 180.0) lon -= 360.0
                    if (lon < -180.0) lon += 360.0
                    double lat = Math.max(-90.0d, Math.min(90.0d, c[1] + dLat))
                    insertValues << "(${id++}, ${lon}, ${lat})"
                }
            }
            insertValues << "(${id++}, null, 40.0)"
            insertValues.collate(500).each { chunk ->
                sql "insert into ${table}(id, lon, lat) values ${chunk.join(',')}"
            }
        }
        sql "sync"
    }

    def queries = [
            [116.40d, 39.90d, 5000.0d],
            [116.40d, 39.90d, 50000.0d],
            [179.95d, 10.0d, 30000.0d],     // antimeridian wrap
            [0.0d, 89.8d, 20000.0d],        // near pole
            [45.0d, 0.0d, 15000.0d],        // s2 face edge
            [116.40d, 39.90d, 1.0d],        // near-empty result
    ]

    def checkOnOff = { String table, String tag ->
        queries.each { q ->
            ["<", "<="].each { op ->
                def query = """select id from ${table}
                               where st_distance_sphere(lon, lat, ${q[0]}, ${q[1]}) ${op} ${q[2]}
                               order by id"""
                sql "set enable_geo_index_query=true;"
                def withIndex = sql query
                sql "set enable_geo_index_query=false;"
                def withoutIndex = sql query
                assertEquals(withoutIndex, withIndex,
                        "[${tag}] geo index changed results for center=(${q[0]},${q[1]}) r=${q[2]} op=${op}")
            }
        }
        // mirrored operand order
        sql "set enable_geo_index_query=true;"
        def mirroredOn = sql "select count(*) from ${table} where 50000 > st_distance_sphere(lon, lat, 116.40, 39.90)"
        sql "set enable_geo_index_query=false;"
        def mirroredOff = sql "select count(*) from ${table} where 50000 > st_distance_sphere(lon, lat, 116.40, 39.90)"
        assertEquals(mirroredOff, mirroredOn, "[${tag}] mirrored form mismatch")
        sql "set enable_geo_index_query=true;"
    }

    // ---- 1. DUP table, __s2 generated column as sort key + GEO index ----
    sql "drop table if exists geo_index_dup_t"
    sql """
    create table geo_index_dup_t (
        `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
        `id` bigint not null,
        `lon` double null,
        `lat` double null,
        INDEX idx_geo(`__s2`) USING GEO PROPERTIES("leaf_rows" = "1024")
    ) engine=olap
    duplicate key(`__s2`)
    distributed by hash(`id`) buckets 4
    properties("replication_num" = "1", "disable_auto_compaction" = "true");
    """
    insertGrid("geo_index_dup_t")
    checkOnOff("geo_index_dup_t", "dup-multi-segment")

    // ---- 2. compaction rebuilds the index through the normal write path ----
    trigger_and_wait_compaction("geo_index_dup_t", "full")
    checkOnOff("geo_index_dup_t", "dup-after-compaction")

    // ---- 3. index effectiveness: RowsGeoIndexFiltered > 0 in the profile ----
    sql "set profile_level=2;"
    sql "set enable_profile=true;"
    sql "set enable_geo_index_query=true;"
    def token = "geo_v1_profile_" + System.currentTimeMillis()
    sql """select /* ${token} */ count(id) from geo_index_dup_t
           where st_distance_sphere(lon, lat, 116.40, 39.90) < 5000"""
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
    assertTrue(profileId != null && profileId != "", "profile for tagged geo query not found")
    Thread.sleep(800)
    def profileText = getProfile(profileId).toString()
    def filteredLines = profileText.split("\n").findAll { it.contains("RowsGeoIndexFiltered") }
    assertTrue(!filteredLines.isEmpty(), "RowsGeoIndexFiltered counter missing from profile")
    // every pipeline instance prints its own counter line; the index is effective if any
    // instance filtered rows
    def anyFiltered = filteredLines.any { line ->
        def m = (line =~ /RowsGeoIndexFiltered:\s*([0-9.]+)/)
        m.find() && Double.parseDouble(m.group(1)) > 0
    }
    assertTrue(anyFiltered,
            "geo index filtered no rows for a city circle: " + filteredLines.join(" | "))
    sql "set enable_profile=false;"

    // ---- 4. UNIQUE MOW + CLUSTER BY, upsert + delete, on/off stays bit-exact ----
    sql "drop table if exists geo_index_mow_t"
    sql """
    create table geo_index_mow_t (
        `id` bigint not null,
        `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
        `lon` double null,
        `lat` double null,
        INDEX idx_geo(`__s2`) USING GEO PROPERTIES("leaf_rows" = "1024")
    ) engine=olap
    unique key(`id`)
    cluster by(`__s2`)
    distributed by hash(`id`) buckets 4
    properties("replication_num" = "1", "enable_unique_key_merge_on_write" = "true");
    """
    insertGrid("geo_index_mow_t")
    // move a batch of points (MOW upsert) and hard-delete another batch
    sql "insert into geo_index_mow_t(id, lon, lat) select id, lon + 0.5, lat from geo_index_mow_t where id between 100 and 200"
    sql "delete from geo_index_mow_t where id between 300 and 400"
    sql "sync"
    checkOnOff("geo_index_mow_t", "mow-after-upsert-delete")

    // ---- 4b. v1.5 exact filter: dropping the residual predicate must stay bit-exact
    // in every mode combination (off / superset / exact), incl. after upsert+delete ----
    queries.each { q ->
        ["<", "<="].each { op ->
            def query = """select id from geo_index_dup_t
                           where st_distance_sphere(lon, lat, ${q[0]}, ${q[1]}) ${op} ${q[2]}
                           order by id"""
            sql "set enable_geo_index_query=false;"
            def off = sql query
            sql "set enable_geo_index_query=true;"
            sql "set enable_geo_index_exact_filter=false;"
            def superset = sql query
            sql "set enable_geo_index_exact_filter=true;"
            def exact = sql query
            assertEquals(off, superset,
                    "[v1 superset] mismatch center=(${q[0]},${q[1]}) r=${q[2]} op=${op}")
            assertEquals(off, exact,
                    "[v1.5 exact] mismatch center=(${q[0]},${q[1]}) r=${q[2]} op=${op}")
        }
    }
    // same three-way check on the MOW table after upsert+delete
    [[116.40d, 39.90d, 50000.0d], [179.95d, 10.0d, 30000.0d]].each { q ->
        def query = """select id from geo_index_mow_t
                       where st_distance_sphere(lon, lat, ${q[0]}, ${q[1]}) < ${q[2]}
                       order by id"""
        sql "set enable_geo_index_query=false;"
        def off = sql query
        sql "set enable_geo_index_query=true;"
        sql "set enable_geo_index_exact_filter=true;"
        def exact = sql query
        assertEquals(off, exact, "[v1.5 exact mow] mismatch center=(${q[0]},${q[1]}) r=${q[2]}")
    }

    // ---- 4c. v2a count pushdown: plan shape + bit-exact counts ----
    sql "set enable_geo_index_query=true;"
    sql "set enable_geo_index_exact_filter=true;"
    sql "set enable_geo_agg_pushdown=true;"
    def countPlan = sql """explain select count(*) from geo_index_dup_t
                           where st_distance_sphere(lon, lat, 116.40, 39.90) < 50000"""
    def countPlanText = countPlan.collect { it[0] }.join("\n")
    assertTrue(countPlanText.contains("COUNT_ON_INDEX"),
            "geo count pushdown plan missing COUNT_ON_INDEX:\n" + countPlanText)

    [["geo_index_dup_t", 5000.0d], ["geo_index_dup_t", 50000.0d],
     ["geo_index_mow_t", 50000.0d]].each { t ->
        def query = """select count(*) from ${t[0]}
                       where st_distance_sphere(lon, lat, 116.40, 39.90) < ${t[1]}"""
        sql "set enable_geo_agg_pushdown=false;"
        sql "set enable_geo_index_query=false;"
        def plain = sql query
        sql "set enable_geo_agg_pushdown=true;"
        sql "set enable_geo_index_query=true;"
        def pushed = sql query
        assertEquals(plain, pushed, "[v2a count] mismatch on ${t[0]} r=${t[1]}")
    }

    // ---- 5. non-key __s2 (pure predicate-filter form): index still only narrows ----
    sql "drop table if exists geo_index_nokey_t"
    sql """
    create table geo_index_nokey_t (
        `id` bigint not null,
        `lon` double null,
        `lat` double null,
        `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
        INDEX idx_geo(`__s2`) USING GEO PROPERTIES("leaf_rows" = "1024")
    ) engine=olap
    duplicate key(`id`)
    distributed by hash(`id`) buckets 4
    properties("replication_num" = "1");
    """
    insertGrid("geo_index_nokey_t")
    checkOnOff("geo_index_nokey_t", "nokey-predicate-filter")

    sql "set enable_geo_index_query=true;"

    // ---- 6. v2b measures property: sketches are built at write (format v2 index
    // files); retrieval must be unaffected and bit-exact on such tables ----
    sql "drop table if exists geo_index_meas_t"
    sql """
    create table geo_index_meas_t (
        `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
        `id` bigint not null,
        `lon` double null,
        `lat` double null,
        `val` double null,
        -- leaf_rows=64: with ~2.5k rows over a ±0.5° grid, wider leaves span the
        -- Hilbert gaps between interior covering ranges and nothing whole-leaf
        -- folds; 64-row leaves are narrow enough for the v2b fold to fire
        INDEX idx_geo(`__s2`) USING GEO PROPERTIES("leaf_rows" = "64", "measures" = "val")
    ) engine=olap
    duplicate key(`__s2`)
    distributed by hash(`id`) buckets 2
    properties("replication_num" = "1");
    """
    def measValues = []
    long mid = 0
    for (double dLon = -0.5; dLon <= 0.5; dLon += 0.02) {
        for (double dLat = -0.5; dLat <= 0.5; dLat += 0.02) {
            def v = (mid % 9 == 0) ? "null" : String.valueOf(mid * 0.5)
            measValues << "(${mid++}, ${116.40 + dLon}, ${39.90 + dLat}, ${v})"
        }
    }
    measValues << "(${mid++}, null, 40.0, 1.5)"
    measValues.collate(500).each { chunk ->
        sql "insert into geo_index_meas_t(id, lon, lat, val) values ${chunk.join(',')}"
    }
    sql "sync"
    [[116.40d, 39.90d, 5000.0d], [116.40d, 39.90d, 30000.0d]].each { q ->
        def query = """select id from geo_index_meas_t
                       where st_distance_sphere(lon, lat, ${q[0]}, ${q[1]}) < ${q[2]}
                       order by id"""
        sql "set enable_geo_index_query=true;"
        def on = sql query
        sql "set enable_geo_index_query=false;"
        def off = sql query
        assertEquals(off, on, "[v2b measures table] retrieval mismatch r=${q[2]}")
    }
    // sum over the region must agree regardless of geo switches (aggregation still
    // runs row-wise pre-v2b-query-integration; this pins the baseline it must match)
    sql "set enable_geo_index_query=true;"
    sql "set enable_geo_agg_pushdown=false;"
    def sumOn = sql "select count(val), sum(val), min(val), max(val) from geo_index_meas_t where st_distance_sphere(lon, lat, 116.40, 39.90) < 30000"
    sql "set enable_geo_index_query=false;"
    def sumOff = sql "select count(val), sum(val), min(val), max(val) from geo_index_meas_t where st_distance_sphere(lon, lat, 116.40, 39.90) < 30000"
    assertEquals(sumOff, sumOn, "[v2b measures table] aggregate mismatch")
    sql "set enable_geo_index_query=true;"
    sql "set enable_geo_agg_pushdown=true;"

    // ---- 7. v2b aggregate pushdown: sum/min/max/count answered from leaf sketches.
    // Three configs must agree on every aggregate shape (fold / row path / full
    // scan); sums compare with a tiny relative tolerance since a folded double sum
    // is a differently-ordered reduction. The profile must show GeoAggFoldedLeaves
    // > 0 both before and after compaction -- the latter proves the cross-column-
    // group measure feeding kept sketches through the compaction rewrite. ----
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
            // fold-hot: the circle swallows the whole grid, interior leaves exist
            "select count(*), count(val), sum(val), min(val), max(val) from geo_index_meas_t where st_distance_sphere(lon, lat, 116.40, 39.90) < 80000",
            // boundary-dominated shapes
            "select count(*), count(val), sum(val), min(val), max(val) from geo_index_meas_t where st_distance_sphere(lon, lat, 116.40, 39.90) < 30000",
            "select sum(val), max(val) from geo_index_meas_t where st_distance_sphere(lon, lat, 116.40, 39.90) <= 5000",
            // empty result: count must be 0 (not NULL), sum NULL -- the coalesce path
            "select count(*), count(val), sum(val) from geo_index_meas_t where st_distance_sphere(lon, lat, 10.0, 10.0) < 100",
            // shapes the rewrite must SKIP but stay correct: unsupported func,
            // extra conjunct, group by
            "select avg(val), sum(val) from geo_index_meas_t where st_distance_sphere(lon, lat, 116.40, 39.90) < 80000",
            "select sum(val) from geo_index_meas_t where st_distance_sphere(lon, lat, 116.40, 39.90) < 80000 and id > 100",
            "select id % 3, sum(val) from geo_index_meas_t where st_distance_sphere(lon, lat, 116.40, 39.90) < 80000 group by id % 3 order by 1",
        ]
        aggQueries.eachWithIndex { q, qi ->
            sql "set enable_geo_index_query=true; "
            sql "set enable_geo_index_exact_filter=true;"
            sql "set enable_geo_agg_pushdown=true;"
            def fold = sql q
            sql "set enable_geo_agg_pushdown=false;"
            def rowPath = sql q
            sql "set enable_geo_index_query=false;"
            def fullScan = sql q
            sql "set enable_geo_index_query=true;"
            sql "set enable_geo_agg_pushdown=true;"
            assertEquals(rowPath.size(), fold.size(), "[v2b-agg ${phase} q${qi}] row count")
            assertEquals(fullScan.size(), fold.size(), "[v2b-agg ${phase} q${qi}] row count vs full scan")
            for (int r = 0; r < fold.size(); r++) {
                for (int c = 0; c < fold[r].size(); c++) {
                    aggCompare(rowPath[r][c], fold[r][c], "[v2b-agg ${phase} q${qi}] cell(${r},${c}) fold vs row-path")
                    aggCompare(fullScan[r][c], fold[r][c], "[v2b-agg ${phase} q${qi}] cell(${r},${c}) fold vs full-scan")
                }
            }
        }
    }
    def assertFolded = { String tag ->
        sql "set profile_level=2;"
        sql "set enable_profile=true;"
        def foldToken = "geo_v2b_fold_${tag}_" + System.currentTimeMillis()
        sql """select /* ${foldToken} */ count(*), count(val), sum(val), min(val), max(val)
               from geo_index_meas_t where st_distance_sphere(lon, lat, 116.40, 39.90) < 80000"""
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
                "profile for tagged geo agg query not found (${tag})")
        Thread.sleep(800)
        def foldProfile = getProfile(foldProfileId).toString()
        def foldLines = foldProfile.split("\n").findAll { it.contains("GeoAggFoldedLeaves") }
        assertTrue(!foldLines.isEmpty(), "GeoAggFoldedLeaves missing from profile (${tag})")
        def anyFolded = foldLines.any { line ->
            def m = (line =~ /GeoAggFoldedLeaves:\s*([0-9.]+)/)
            m.find() && Double.parseDouble(m.group(1)) > 0
        }
        assertTrue(anyFolded,
                "no leaves folded for a grid-swallowing circle (${tag}): " + foldLines.join(" | "))
        sql "set enable_profile=false;"
    }
    aggBattery("flush")
    assertFolded("flush")
    trigger_and_wait_compaction("geo_index_meas_t", "full")
    aggBattery("compacted")
    assertFolded("compacted")
}
