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

// HASI v3 compaction splice fast path (HASI_POC.md §12).
//
// Armed-path proof is CAUSAL via a debug point (a global metric delta would
// flake under concurrent suites): with Compaction::do_geo_index_rollup_force_error
// enabled, a compaction that ARMS the splice must FAIL; the very same compaction
// must succeed once the point is disabled (the point injects before any skip
// marks). Conversely, tables that must NOT arm (overlapping loads, delete
// predicates, config off) must compact fine even with the point enabled.
//
// Data recipe: geographic lon/lat tiles do NOT give disjoint S2 cell hulls
// (§12.5 review, verified empirically) -- the disjoint batches below use
// far-apart cities and the suite ASSERTS hull disjointness up front, failing
// loudly if the recipe ever degrades.

import groovy.json.JsonSlurper
import java.util.concurrent.TimeUnit
import org.awaitility.Awaitility

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

suite("geo_index_compaction", "nonConcurrent") {
    sql "set enable_geo_index_query=true;"

    // Far-apart tiles; disjointness is asserted below, not assumed.
    // [lon0, lat0, batch]
    def tiles = [
            [116.30, 39.85, 0], // Beijing
            [151.10, -33.90, 1], // Sydney
            [-46.70, -23.60, 2], // Sao Paulo
    ]
    def insertTile = { String table, double lon0, double lat0, long batch, int rows ->
        def values = []
        for (int i = 0; i < rows; i++) {
            double lon = lon0 + (i % 50) * 0.0005
            double lat = lat0 + ((int) (i / 50)) * 0.0005
            long id = batch * 1000000 + i
            // integer-valued measure keeps splice-vs-rebuild sums bit-exact
            values << "(${id}, ${lon}, ${lat}, ${(id % 97)})"
        }
        sql "insert into ${table}(id, lon, lat, val) values ${values.join(',')}"
    }
    def assertTilesDisjoint = { String table ->
        def hulls = sql """
            select cast(id / 1000000 as bigint) as batch, min(__s2), max(__s2)
            from ${table} group by batch order by min(__s2)
        """
        for (int i = 0; i + 1 < hulls.size(); i++) {
            assertTrue((hulls[i][2] as long) < (hulls[i + 1][1] as long),
                    "tile hulls not strictly disjoint -- pick farther tiles: ${hulls}")
        }
    }
    def createTable = { String name ->
        sql "drop table if exists ${name}"
        sql """
        create table ${name} (
            `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
            `id` bigint not null,
            `lon` double null,
            `lat` double null,
            `val` double null,
            INDEX idx_geo(`__s2`) USING GEO PROPERTIES("leaf_rows" = "64", "measures" = "val")
        ) engine=olap
        duplicate key(`__s2`)
        distributed by hash(`id`) buckets 1
        properties("replication_num" = "1", "disable_auto_compaction" = "true");
        """
    }

    // Query battery: range filter, aggregate fold, kNN -- captured as data so
    // before/after and on/off comparisons are bit-exact list equality.
    def battery = { String table ->
        def out = []
        for (t in tiles) {
            out << sql("""select count(id), sum(val) from ${table}
                          where st_distance_sphere(lon, lat, ${t[0] + 0.005}, ${t[1] + 0.005}) < 2000""")
            out << sql("""select id, st_distance_sphere(lon, lat, ${t[0] + 0.003}, ${t[1] + 0.003}) as d
                          from ${table} order by d asc, id asc limit 20""")
        }
        out << sql("select count(*), count(val), sum(val), min(__s2), max(__s2) from ${table}")
        return out
    }
    def batteryOnOff = { String table, String tag ->
        sql "set enable_geo_index_query=true;"
        def on = battery(table)
        sql "set enable_geo_index_query=false;"
        def off = battery(table)
        sql "set enable_geo_index_query=true;"
        assertEquals(off, on, "geo index on/off mismatch (${tag})")
        return on
    }

    def triggerFullExpectFailure = { String table ->
        // Hand-rolled trigger: trigger_and_wait_compaction asserts success, but
        // here the armed rollup must FAIL under the debug point.
        def backendId_to_backendIP = [:]
        def backendId_to_backendHttpPort = [:]
        getBackendIpHttpPort(backendId_to_backendIP, backendId_to_backendHttpPort)
        def tablets = sql_return_maparray """show tablets from ${table}"""
        for (tablet in tablets) {
            def be_host = backendId_to_backendIP["${tablet.BackendId}"]
            def be_port = backendId_to_backendHttpPort["${tablet.BackendId}"]
            def (exit_code, stdout, stderr) = be_show_tablet_status(be_host, be_port, tablet.TabletId)
            assert exit_code == 0
            def before = parseJson(stdout.trim())["last full success time"]
            (exit_code, stdout, stderr) = be_run_full_compaction(be_host, be_port, tablet.TabletId)
            assert exit_code == 0
            // Wait until the compaction is no longer running, then verify it did
            // NOT succeed (success time unchanged).
            Awaitility.await().atMost(120, TimeUnit.SECONDS).pollInterval(1, TimeUnit.SECONDS).until(() -> {
                def (ec, out, err) = be_get_compaction_status(be_host, be_port, tablet.TabletId)
                assert ec == 0
                return parseJson(out.trim()).run_status == false
            })
            (exit_code, stdout, stderr) = be_show_tablet_status(be_host, be_port, tablet.TabletId)
            assert exit_code == 0
            def after = parseJson(stdout.trim())["last full success time"]
            assertEquals(before, after,
                    "compaction succeeded despite the forced-error debug point -- rollup did not arm/enter")
        }
    }

    def injectName = "Compaction::do_geo_index_rollup_force_error"

    // ---- 1. Disjoint tiled loads: the splice must arm, enter, and preserve
    //         every query answer and the measure sketches. ----
    createTable("geo_cmp_disjoint_t")
    for (t in tiles) {
        insertTile("geo_cmp_disjoint_t", t[0] as double, t[1] as double, t[2] as long, 900)
    }
    assertTilesDisjoint("geo_cmp_disjoint_t")
    def before = batteryOnOff("geo_cmp_disjoint_t", "disjoint-precompaction")
    try {
        GetDebugPoint().enableDebugPointForAllBEs(injectName)
        triggerFullExpectFailure("geo_cmp_disjoint_t") // causal proof: armed & entered
    } finally {
        GetDebugPoint().disableDebugPointForAllBEs(injectName)
    }
    trigger_and_wait_compaction("geo_cmp_disjoint_t", "full")
    def after = batteryOnOff("geo_cmp_disjoint_t", "disjoint-postcompaction")
    assertEquals(before, after, "splice changed query results")

    // Sketches survived the splice: the v2b fold still fires on the compacted
    // segment (a circle swallowing a whole tile folds leaves wholesale).
    sql "set profile_level=2;"
    sql "set enable_profile=true;"
    def token = "geo_v3_fold_" + System.currentTimeMillis()
    def foldQueryBody = """count(val), sum(val) from geo_cmp_disjoint_t
           where st_distance_sphere(lon, lat, ${tiles[0][0] + 0.006}, ${tiles[0][1] + 0.005}) < 20000"""
    def foldResult = sql "select /* ${token} */ ${foldQueryBody}"
    // Value oracle for the folded aggregates: the same query with every geo
    // pushdown off must agree bit-exactly (integer-valued measures) -- a splice
    // that misplaces sketch rows would fold wrong sums while still reporting
    // GeoAggFoldedLeaves > 0.
    def foldOracle = sql """select /*+ SET_VAR(enable_geo_index_query=false,enable_geo_agg_pushdown=false) */
                            ${foldQueryBody}"""
    assertEquals(foldOracle, foldResult, "folded aggregates differ from the row-path oracle")
    String foldProfileId = ""
    for (int attempt = 0; attempt < 30 && (foldProfileId == null || foldProfileId == ""); attempt++) {
        List profileData = new JsonSlurper().parseText(getProfileList()).data.rows
        for (def profileItem in profileData) {
            if (profileItem["Sql Statement"].toString().contains(token)) {
                foldProfileId = profileItem["Profile ID"].toString()
                break
            }
        }
        if (foldProfileId == null || foldProfileId == "") {
            Thread.sleep(300)
        }
    }
    assertTrue(foldProfileId != null && foldProfileId != "", "fold profile not found")
    Thread.sleep(800)
    def foldProfile = getProfile(foldProfileId).toString()
    def foldLines = foldProfile.split("\n").findAll { it.contains("GeoAggFoldedLeaves") }
    assertTrue(!foldLines.isEmpty(), "GeoAggFoldedLeaves missing from profile")
    assertTrue(foldLines.any { line ->
        def m = (line =~ /GeoAggFoldedLeaves:\s*([0-9.]+)/)
        m.find() && Double.parseDouble(m.group(1)) > 0
    }, "no leaves folded after splice -- sketches lost: " + foldLines.join(" | "))
    sql "set enable_profile=false;"

    // ---- 2. Overlapping loads (same tile twice): must NOT arm -- compaction
    //         succeeds even with the forced-error point enabled. ----
    createTable("geo_cmp_overlap_t")
    insertTile("geo_cmp_overlap_t", 116.30d, 39.85d, 0L, 900)
    insertTile("geo_cmp_overlap_t", 116.30d, 39.85d, 1L, 900) // same cells: hulls overlap
    def beforeOverlap = batteryOnOff("geo_cmp_overlap_t", "overlap-precompaction")
    try {
        GetDebugPoint().enableDebugPointForAllBEs(injectName)
        trigger_and_wait_compaction("geo_cmp_overlap_t", "full") // must succeed: not armed
    } finally {
        GetDebugPoint().disableDebugPointForAllBEs(injectName)
    }
    def afterOverlap = batteryOnOff("geo_cmp_overlap_t", "overlap-postcompaction")
    assertEquals(beforeOverlap, afterOverlap, "inline rebuild changed query results")

    // ---- 3. Delete predicate on an input rowset: must NOT arm, and the delete
    //         must survive the compaction. ----
    createTable("geo_cmp_delete_t")
    for (t in tiles) {
        insertTile("geo_cmp_delete_t", t[0] as double, t[1] as double, t[2] as long, 300)
    }
    sql "delete from geo_cmp_delete_t where id >= 1000000 and id < 1000150"
    def beforeDelete = batteryOnOff("geo_cmp_delete_t", "delete-precompaction")
    assertEquals(750, (sql("select count(*) from geo_cmp_delete_t")[0][0] as long))
    try {
        GetDebugPoint().enableDebugPointForAllBEs(injectName)
        trigger_and_wait_compaction("geo_cmp_delete_t", "full") // must succeed: not armed
    } finally {
        GetDebugPoint().disableDebugPointForAllBEs(injectName)
    }
    def afterDelete = batteryOnOff("geo_cmp_delete_t", "delete-postcompaction")
    assertEquals(beforeDelete, afterDelete, "delete-predicate compaction changed query results")
    assertEquals(750, (sql("select count(*) from geo_cmp_delete_t")[0][0] as long))

    // ---- 4. Config kill switch: enable_geo_index_incremental_compaction=false
    //         must keep even disjoint loads on the inline path. ----
    createTable("geo_cmp_off_t")
    for (t in tiles) {
        insertTile("geo_cmp_off_t", t[0] as double, t[1] as double, t[2] as long, 300)
    }
    assertTilesDisjoint("geo_cmp_off_t")
    def beforeOff = batteryOnOff("geo_cmp_off_t", "off-precompaction")
    def backendId_to_backendIP = [:]
    def backendId_to_backendHttpPort = [:]
    getBackendIpHttpPort(backendId_to_backendIP, backendId_to_backendHttpPort)
    def setBeConfig = { String value ->
        for (String backend_id : backendId_to_backendIP.keySet()) {
            def (ec, out, err) = update_be_config(backendId_to_backendIP.get(backend_id),
                    backendId_to_backendHttpPort.get(backend_id),
                    "enable_geo_index_incremental_compaction", value)
            logger.info("update_be_config: ${out} ${err}")
        }
    }
    try {
        setBeConfig("false")
        GetDebugPoint().enableDebugPointForAllBEs(injectName)
        trigger_and_wait_compaction("geo_cmp_off_t", "full") // must succeed: switch off
    } finally {
        GetDebugPoint().disableDebugPointForAllBEs(injectName)
        setBeConfig("true")
    }
    def afterOff = batteryOnOff("geo_cmp_off_t", "off-postcompaction")
    assertEquals(beforeOff, afterOff, "switch-off compaction changed query results")
}
