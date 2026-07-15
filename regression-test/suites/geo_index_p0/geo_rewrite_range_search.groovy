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

// HASI geo index v0 backtest (design doc HASI_POC.md §7 v0 / §8.1):
// the RewriteGeoPredicate rule must (a) fire — visible as injected __s2 range conjuncts in
// the plan — and (b) never change results: rewrite on/off must be bit-exact for circles at
// city / antimeridian / pole / face-boundary locations, because the envelope is a superset
// and the original ST_* predicate is kept as the exact residual filter.
suite("geo_rewrite_range_search") {
    sql "SET enable_nereids_planner=true;"
    sql "SET enable_fallback_to_original_planner=false;"

    sql "drop table if exists geo_rewrite_t"
    sql """
    create table geo_rewrite_t (
        `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
        `id` bigint not null,
        `lon` double null,
        `lat` double null
    ) engine=olap
    duplicate key(`__s2`)
    distributed by hash(`id`) buckets 4
    properties("replication_num" = "1");
    """

    // Deterministic grid around several centers (incl. antimeridian, pole, face edge) plus
    // rings very close to each query radius so the boundary is actually exercised.
    def centers = [[116.40d, 39.90d], [179.95d, 10.0d], [0.0d, 89.8d], [45.0d, 0.0d]]
    def insertValues = []
    long id = 0
    centers.each { c ->
        for (double dLon = -1.0; dLon <= 1.0; dLon += 0.05) {
            for (double dLat = -1.0; dLat <= 1.0; dLat += 0.05) {
                double lon = c[0] + dLon
                if (lon > 180.0) lon -= 360.0
                if (lon < -180.0) lon += 360.0
                double lat = Math.max(-90.0d, Math.min(90.0d, c[1] + dLat))
                insertValues << "(${id++}, ${lon}, ${lat})"
            }
        }
    }
    insertValues << "(${id++}, null, 40.0)"    // NULL point never matches
    insertValues.collate(500).each { chunk ->
        sql "insert into geo_rewrite_t(id, lon, lat) values ${chunk.join(',')}"
    }
    sql "sync"

    def queries = [
            // [centerLon, centerLat, radiusMeters]
            [116.40d, 39.90d, 5000.0d],
            [116.40d, 39.90d, 50000.0d],
            [179.95d, 10.0d, 30000.0d],     // antimeridian wrap
            [0.0d, 89.8d, 20000.0d],        // near pole
            [45.0d, 0.0d, 15000.0d],        // s2 face edge
            [116.40d, 39.90d, 1.0d],        // near-empty result
    ]
    def operators = ["<", "<="]

    // (a) the rewrite fires: the plan contains injected __s2 range conjuncts
    sql "set enable_geo_predicate_rewrite=true;"
    def plan = sql """explain select count(*) from geo_rewrite_t
                      where st_distance_sphere(lon, lat, 116.40, 39.90) < 5000"""
    def planText = plan.collect { it[0] }.join("\n")
    assertTrue(planText.contains("__s2"),
            "RewriteGeoPredicate did not inject __s2 conjuncts:\n" + planText)

    // (b) on/off bit-exactness for every query x operator
    queries.each { q ->
        operators.each { op ->
            def query = """select id from geo_rewrite_t
                           where st_distance_sphere(lon, lat, ${q[0]}, ${q[1]}) ${op} ${q[2]}
                           order by id"""
            sql "set enable_geo_predicate_rewrite=true;"
            def withRewrite = sql query
            sql "set enable_geo_predicate_rewrite=false;"
            def withoutRewrite = sql query
            assertEquals(withoutRewrite, withRewrite,
                    "rewrite changed results for center=(${q[0]},${q[1]}) r=${q[2]} op=${op}")
        }
    }
    sql "set enable_geo_predicate_rewrite=true;"

    // mirrored operand order must also rewrite and stay exact
    def mirrored = sql """select count(*) from geo_rewrite_t
                          where 50000 > st_distance_sphere(lon, lat, 116.40, 39.90)"""
    sql "set enable_geo_predicate_rewrite=false;"
    def mirroredOff = sql """select count(*) from geo_rewrite_t
                             where 50000 > st_distance_sphere(lon, lat, 116.40, 39.90)"""
    sql "set enable_geo_predicate_rewrite=true;"
    assertEquals(mirroredOff, mirrored)

    // outside-circle predicates must NOT be rewritten (complement is not an envelope)
    def outsidePlan = sql """explain select count(*) from geo_rewrite_t
                             where st_distance_sphere(lon, lat, 116.40, 39.90) > 5000"""
    def outsideText = outsidePlan.collect { it[0] }.join("\n")
    assertFalse(outsideText.contains("`__s2` >="),
            "outside-circle predicate must not get an __s2 envelope:\n" + outsideText)

    // ---- non-key __s2: pure predicate-filter form (design doc §3.3-3) ----
    // __s2 as a plain generated VALUE column (not in the sort key): the rewrite must
    // still fire (it matches the generated-column expression, not key-ness) and stay
    // bit-exact. Benefit here is the cheap BIGINT range pre-filter evaluated at the
    // storage layer before the expensive spherical distance; no key-range pruning.
    sql "drop table if exists geo_rewrite_nokey_t"
    sql """
    create table geo_rewrite_nokey_t (
        `id`    bigint not null,
        `lon`   double null,
        `lat`   double null,
        `__s2`  bigint generated always as (st_s2_cellid(`lon`, `lat`)) null
    ) engine=olap
    duplicate key(`id`)
    distributed by hash(`id`) buckets 4
    properties("replication_num" = "1");
    """
    sql "insert into geo_rewrite_nokey_t(id, lon, lat) select id, lon, lat from geo_rewrite_t"
    sql "sync"

    sql "set enable_geo_predicate_rewrite=true;"
    def nokeyPlan = sql """explain select count(*) from geo_rewrite_nokey_t
                           where st_distance_sphere(lon, lat, 116.40, 39.90) < 5000"""
    def nokeyPlanText = nokeyPlan.collect { it[0] }.join("\n")
    assertTrue(nokeyPlanText.contains("__s2"),
            "rewrite must fire for a non-key __s2 generated column:\n" + nokeyPlanText)

    [[116.40d, 39.90d, 5000.0d], [179.95d, 10.0d, 30000.0d], [0.0d, 89.8d, 20000.0d]].each { q ->
        def query = """select id from geo_rewrite_nokey_t
                       where st_distance_sphere(lon, lat, ${q[0]}, ${q[1]}) < ${q[2]}
                       order by id"""
        sql "set enable_geo_predicate_rewrite=true;"
        def on = sql query
        sql "set enable_geo_predicate_rewrite=false;"
        def off = sql query
        assertEquals(off, on, "non-key rewrite changed results for center=(${q[0]},${q[1]}) r=${q[2]}")
    }
    sql "set enable_geo_predicate_rewrite=true;"
}
