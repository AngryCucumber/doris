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

// GEO index DDL validation (design doc HASI_POC.md §3.1/§3.2): only BIGINT
// st_s2_cellid generated columns on DUP / UNIQUE-MOW tables qualify; ALTER-adding to
// existing data is rejected because it is not clustered by __s2.
suite("create_geo_index_test") {
    sql "SET enable_nereids_planner=true;"
    sql "SET enable_fallback_to_original_planner=false;"

    def assertDdlFails = { String stmt, String fragment ->
        try {
            sql stmt
            assertTrue(false, "expected DDL to fail with '${fragment}': " + stmt)
        } catch (Exception e) {
            assertTrue(e.getMessage().contains(fragment),
                    "expected '${fragment}' in error, got: " + e.getMessage())
        }
    }

    // valid: DUP table, generated __s2 as key prefix
    sql "drop table if exists geo_ddl_ok_dup"
    sql """
    create table geo_ddl_ok_dup (
        `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
        `id` bigint not null,
        `lon` double null,
        `lat` double null,
        INDEX idx_geo(`__s2`) USING GEO PROPERTIES("leaf_rows" = "8192")
    ) engine=olap duplicate key(`__s2`)
    distributed by hash(`id`) buckets 1
    properties("replication_num" = "1");
    """
    def createStmt = sql "show create table geo_ddl_ok_dup"
    assertTrue(createStmt[0][1].contains("USING GEO"))

    // valid: UNIQUE MOW, non-key value column (predicate-filter form)
    sql "drop table if exists geo_ddl_ok_mow"
    sql """
    create table geo_ddl_ok_mow (
        `id` bigint not null,
        `lon` double null,
        `lat` double null,
        `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
        INDEX idx_geo(`__s2`) USING GEO
    ) engine=olap unique key(`id`)
    distributed by hash(`id`) buckets 1
    properties("replication_num" = "1", "enable_unique_key_merge_on_write" = "true");
    """

    // invalid: plain BIGINT column (not generated)
    sql "drop table if exists geo_ddl_bad1"
    assertDdlFails("""
    create table geo_ddl_bad1 (
        `id` bigint not null, `cell` bigint null,
        INDEX idx_geo(`cell`) USING GEO
    ) engine=olap duplicate key(`id`)
    distributed by hash(`id`) buckets 1 properties("replication_num" = "1");
    """, "generated column")

    // invalid: generated from a different function
    sql "drop table if exists geo_ddl_bad2"
    assertDdlFails("""
    create table geo_ddl_bad2 (
        `id` bigint not null, `lon` double null, `lat` double null,
        `cell` bigint generated always as (abs(`id`)) null,
        INDEX idx_geo(`cell`) USING GEO
    ) engine=olap duplicate key(`id`)
    distributed by hash(`id`) buckets 1 properties("replication_num" = "1");
    """, "st_s2_cellid")

    // invalid: not BIGINT
    sql "drop table if exists geo_ddl_bad3"
    assertDdlFails("""
    create table geo_ddl_bad3 (
        `id` bigint not null, `lon` double null, `lat` double null,
        `cell` int generated always as (cast(st_s2_cellid(`lon`, `lat`) as int)) null,
        INDEX idx_geo(`cell`) USING GEO
    ) engine=olap duplicate key(`id`)
    distributed by hash(`id`) buckets 1 properties("replication_num" = "1");
    """, "BIGINT")

    // invalid: AGG table (may be rejected by the GEO table-model gate or earlier by
    // generated-column validation depending on version -- any failure is correct)
    sql "drop table if exists geo_ddl_bad4"
    assertDdlFails("""
    create table geo_ddl_bad4 (
        `id` bigint not null, `lon` double max null, `lat` double max null,
        `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) max null,
        INDEX idx_geo(`__s2`) USING GEO
    ) engine=olap aggregate key(`id`)
    distributed by hash(`id`) buckets 1 properties("replication_num" = "1");
    """, "")

    // invalid: unknown property
    sql "drop table if exists geo_ddl_bad5"
    assertDdlFails("""
    create table geo_ddl_bad5 (
        `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
        `id` bigint not null, `lon` double null, `lat` double null,
        INDEX idx_geo(`__s2`) USING GEO PROPERTIES("no_such_prop" = "1")
    ) engine=olap duplicate key(`__s2`)
    distributed by hash(`id`) buckets 1 properties("replication_num" = "1");
    """, "unknown geo index property")

    // invalid: ALTER ADD on existing data (table deliberately has no geo index yet, so
    // the GEO-specific rejection fires rather than any duplicate-index check)
    sql "drop table if exists geo_ddl_alter_t"
    sql """
    create table geo_ddl_alter_t (
        `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
        `id` bigint not null, `lon` double null, `lat` double null
    ) engine=olap duplicate key(`__s2`)
    distributed by hash(`id`) buckets 1 properties("replication_num" = "1");
    """
    assertDdlFails("alter table geo_ddl_alter_t add index idx_geo2(`__s2`) USING GEO",
            "GEO index can only be created with CREATE TABLE")
    assertDdlFails("create index idx_geo3 on geo_ddl_alter_t(`__s2`) USING GEO",
            "GEO index can only be created with CREATE TABLE")

    sql "drop table if exists geo_ddl_ok_dup"
    sql "drop table if exists geo_ddl_ok_mow"
    sql "drop table if exists geo_ddl_alter_t"
}
