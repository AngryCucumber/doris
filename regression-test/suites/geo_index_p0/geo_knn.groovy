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

    // ---- v4.5 F2: fence + kNN joint acceleration (HASI_POC.md §13.1) ----
    // A fully-consumed circle fence must no longer veto the kNN pushdown: one
    // tagged profile shows BOTH the fence (RowsGeoIndexFiltered) and the kNN
    // (RowsGeoKnnFiltered) firing. Both rewrite states (ON: envelope predicates
    // pass the implication test; OFF: no envelope -- the path v4 already allowed
    // but never tested), both index modes.
    def profileCounter = { String profileText, String counter ->
        // exact value is the parenthesized form once K/M suffixes kick in
        def total = 0L
        profileText.split("\n").findAll { it.contains(counter) }.each { line ->
            def exact = (line =~ /${counter}:\s*[0-9.]+[KMB]?\s*\((\d+)\)/)
            def bare = (line =~ /${counter}:\s*(\d+)\s*$/)
            if (exact.find()) {
                total += Long.parseLong(exact.group(1))
            } else if (bare.find()) {
                total += Long.parseLong(bare.group(1))
            }
        }
        return total
    }
    def taggedProfile = { String token ->
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
        assertTrue(profileId != null && profileId != "", "profile not found for ${token}")
        Thread.sleep(800)
        return getProfile(profileId).toString()
    }
    def assertFenceKnnFired = { String table, boolean rewriteOn, boolean expectFence ->
        sql "set profile_level=2;"
        sql "set enable_profile=true;"
        sql "set enable_geo_knn_pushdown=true;"
        sql "set enable_geo_index_query=true;"
        sql "set enable_geo_index_exact_filter=true;"
        sql "set enable_geo_predicate_rewrite=${rewriteOn};"
        def tag = "fenceknn_${table}_${rewriteOn}"
        def d = String.format(distExpr(table), "116.40", "39.90")
        def q2 = """select id, ${d} as dist from ${table}
                    where ${d} < 50000 order by dist asc, id asc limit 10"""
        if (expectFence) {
            def token = "geo_${tag}_" + System.currentTimeMillis()
            sql "select /* ${token} */ ${q2.substring(q2.indexOf('id'))}"
            def profile = taggedProfile(token)
            assertTrue(profileCounter(profile, "RowsGeoIndexFiltered") > 0,
                    "[${tag}] fence never fired")
            assertTrue(profileCounter(profile, "RowsGeoKnnFiltered") > 0,
                    "[${tag}] knn never fired under a consumed fence")
        }
        // the answer stays bit-equal to the fallback in every configuration
        def on = sql q2
        sql "set enable_geo_knn_pushdown=false;"
        def off = sql q2
        sql "set enable_geo_knn_pushdown=true;"
        assertEquals(off, on, "[${tag}] fence+knn changed results")
        sql "set enable_profile=false;"
        sql "set enable_geo_predicate_rewrite=true;"
    }
    // trio mode with rewrite=OFF: nothing pulls the __s2 column into the read
    // schema, so _apply_geo_predicate finds no index iterator and the fence falls
    // back to expression evaluation entirely (pre-existing v1.5 boundary, §13.1)
    // -- correctness leg only. geo_point mode fires in both rewrite states.
    assertFenceKnnFired("geo_knn_dup_t", true, true)
    assertFenceKnnFired("geo_knn_dup_t", false, false)
    assertFenceKnnFired("geo_knn_gp_t", true, true)
    assertFenceKnnFired("geo_knn_gp_t", false, true)

    // Adversarial: a user-written __s2 predicate has the ENVELOPE'S SHAPE but is
    // not implied by the fence -- the gate must stay closed (correct results via
    // fallback) under both rewrite states.
    // The predicate value sits strictly INSIDE the fence circle's key range
    // (min+1 over circle rows): the result set is non-empty, the predicate
    // genuinely cuts into the fence (never implied), and a broken implication
    // check would commit a top-k that wrongly contains the excluded minimum row.
    def dupD = String.format(distExpr("geo_knn_dup_t"), "116.40", "39.90")
    def s2cut = sql """select cast(min(__s2) + 1 as bigint) from geo_knn_dup_t
                       where ${dupD} < 50000"""
    [true, false].each { rw ->
        sql "set enable_geo_predicate_rewrite=${rw};"
        def q3 = """select id, ${dupD} as dist from geo_knn_dup_t
                    where ${dupD} < 50000 and __s2 >= ${s2cut[0][0]}
                    order by dist asc, id asc limit 10"""
        sql "set enable_geo_knn_pushdown=true;"
        def on = sql q3
        sql "set enable_geo_knn_pushdown=false;"
        def off = sql q3
        sql "set enable_geo_knn_pushdown=true;"
        assertTrue(on.size() > 0, "user __s2 predicate variant returned nothing (rewrite=${rw})")
        assertEquals(off, on, "user __s2 predicate variant mismatch (rewrite=${rw})")
    }
    sql "set enable_geo_predicate_rewrite=true;"

    // Adversarial: an active version DELETE predicate must keep the gate closed
    // (deleted near neighbors must never surface, and RowsGeoKnnFiltered == 0).
    sql "drop table if exists geo_knn_del_t"
    sql """
    create table geo_knn_del_t (
        `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
        `id` bigint not null,
        `lon` double null,
        `lat` double null,
        INDEX idx_geo(`__s2`) USING GEO PROPERTIES("leaf_rows" = "64")
    ) engine=olap duplicate key(`__s2`)
    distributed by hash(`id`) buckets 1
    properties("replication_num" = "1", "disable_auto_compaction" = "true");
    """
    def delValues = []
    long did = 0
    for (double dLon = -0.2; dLon <= 0.2; dLon += 0.02) {
        for (double dLat = -0.2; dLat <= 0.2; dLat += 0.02) {
            delValues << "(${did++}, ${116.40 + dLon}, ${39.90 + dLat})"
        }
    }
    sql "insert into geo_knn_del_t(id, lon, lat) values ${delValues.join(',')}"
    def delNearest = sql """select id from geo_knn_del_t
                            order by st_distance_sphere(lon, lat, 116.40, 39.90) asc, id asc limit 2"""
    delNearest.each { row -> sql "delete from geo_knn_del_t where id = ${row[0]}" }
    sql "sync"
    sql "set profile_level=2;"
    sql "set enable_profile=true;"
    def delToken = "geo_delfence_" + System.currentTimeMillis()
    def delQ = """select /* ${delToken} */ id, st_distance_sphere(lon, lat, 116.40, 39.90) as dist
                  from geo_knn_del_t where st_distance_sphere(lon, lat, 116.40, 39.90) < 50000
                  order by dist asc, id asc limit 10"""
    def delOn = sql delQ
    def delProfile = taggedProfile(delToken)
    assertEquals(0L, profileCounter(delProfile, "RowsGeoKnnFiltered"),
            "knn fired despite an active delete predicate")
    delNearest.each { deleted ->
        delOn.each { row ->
            assertTrue(row[0] != deleted[0], "deleted row ${deleted[0]} surfaced under fence+knn")
        }
    }
    sql "set enable_geo_knn_pushdown=false;"
    def delOff = sql delQ.replace(delToken, delToken + "_off")
    sql "set enable_geo_knn_pushdown=true;"
    assertEquals(delOff, delOn, "delete-predicate fence variant mismatch")
    sql "set enable_profile=false;"

    // Adversarial: TWO geo indexes on different column pairs -- fence consumed on
    // index A, kNN ordered by index B's columns. The identity check must keep the
    // gate closed (results correct via fallback; B is nullable-free here but the
    // stash cid != knn cid regardless).
    sql "drop table if exists geo_knn_2idx_t"
    sql """
    create table geo_knn_2idx_t (
        `__s2a` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
        `__s2b` bigint generated always as (st_s2_cellid(`lon2`, `lat2`)) null,
        `id` bigint not null,
        `lon` double null,
        `lat` double null,
        `lon2` double null,
        `lat2` double null,
        INDEX idx_a(`__s2a`) USING GEO PROPERTIES("leaf_rows" = "64"),
        INDEX idx_b(`__s2b`) USING GEO PROPERTIES("leaf_rows" = "64")
    ) engine=olap duplicate key(`__s2a`)
    distributed by hash(`id`) buckets 1
    properties("replication_num" = "1", "disable_auto_compaction" = "true");
    """
    def twoIdxValues = []
    long tid = 0
    for (double dLon = -0.2; dLon <= 0.2; dLon += 0.02) {
        for (double dLat = -0.2; dLat <= 0.2; dLat += 0.02) {
            // every 7th row: NULL (lon2, lat2) INSIDE the fence circle -- the
            // detection teeth (review finding): if the identity guards were lost,
            // the NULL-gate lift would let the kNN commit a top-k that drops these
            // NULLS-FIRST rows, diverging from the fallback bit-exactly.
            if (tid % 7 == 3) {
                twoIdxValues << "(${tid++}, ${116.40 + dLon}, ${39.90 + dLat}, null, null)"
            } else {
                twoIdxValues << "(${tid++}, ${116.40 + dLon}, ${39.90 + dLat}, ${121.47 + dLon}, ${31.23 + dLat})"
            }
        }
    }
    sql "insert into geo_knn_2idx_t(id, lon, lat, lon2, lat2) values ${twoIdxValues.join(',')}"
    sql "sync"
    def q2idx = """select id, st_distance_sphere(lon2, lat2, 121.47, 31.23) as dist
                   from geo_knn_2idx_t
                   where st_distance_sphere(lon, lat, 116.40, 39.90) < 20000
                   order by dist asc nulls first, id asc limit 10"""
    sql "set enable_geo_knn_pushdown=true;"
    def on2idx = sql q2idx
    sql "set enable_geo_knn_pushdown=false;"
    def off2idx = sql q2idx
    sql "set enable_geo_knn_pushdown=true;"
    assertEquals(off2idx, on2idx, "two-geo-index fence/knn identity variant mismatch")

    // ---- v4.5 F1: cross-segment shared kNN bound (HASI_POC.md §13.2) ----
    // Three disjoint far-apart tiles as three un-compacted single-segment rowsets;
    // with serial scanning the tile-0 segment publishes a tight bound and the far
    // segments' walks collapse: GeoKnnBoundSkippedLeaves > 0 is the causal proof.
    sql "drop table if exists geo_knn_ms_t"
    sql """
    create table geo_knn_ms_t (
        `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
        `id` bigint not null,
        `lon` double null,
        `lat` double null,
        INDEX idx_geo(`__s2`) USING GEO PROPERTIES("leaf_rows" = "64")
    ) engine=olap duplicate key(`__s2`)
    distributed by hash(`id`) buckets 1
    properties("replication_num" = "1", "disable_auto_compaction" = "true");
    """
    def msTiles = [[116.30, 39.85], [151.10, -33.90], [-46.70, -23.60]]
    msTiles.eachWithIndex { tile, batch ->
        def values = []
        for (int i = 0; i < 900; i++) {
            values << "(${batch * 1000000 + i}, ${tile[0] + (i % 50) * 0.0005}, ${tile[1] + ((int) (i / 50)) * 0.0005})"
        }
        sql "insert into geo_knn_ms_t(id, lon, lat) values ${values.join(',')}"
    }
    sql "sync"
    sql "set enable_parallel_scan=false;"
    sql "set parallel_pipeline_task_num=1;"
    sql "set profile_level=2;"
    sql "set enable_profile=true;"
    def msQ = { String token ->
        """select /* ${token} */ id, st_distance_sphere(lon, lat, 116.31, 39.86) as dist
           from geo_knn_ms_t order by dist asc, id asc limit 20"""
    }
    def msFired = false
    def msOn = null
    for (int attempt = 0; attempt < 3 && !msFired; attempt++) {
        def token = "geo_msbound_${attempt}_" + System.currentTimeMillis()
        msOn = sql msQ(token)
        def profile = taggedProfile(token)
        msFired = profileCounter(profile, "GeoKnnBoundSkippedLeaves") > 0
    }
    assertTrue(msFired, "shared bound never pruned a far segment's walk")
    sql "set enable_geo_knn_pushdown=false;"
    def msOff = sql msQ("geo_msbound_off_" + System.currentTimeMillis())
    sql "set enable_geo_knn_pushdown=true;"
    assertEquals(msOff, msOn, "shared-bound multi-segment knn on/off mismatch")
    sql "set enable_profile=false;"
    sql "set enable_parallel_scan=true;"
}
