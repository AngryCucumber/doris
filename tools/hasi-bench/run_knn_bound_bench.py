#!/usr/bin/env python3
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""HASI v4.5 F1 cross-segment shared kNN bound benchmark (HASI_POC.md §13.4).

One tablet, N disjoint far-apart tile loads kept UN-compacted (the multi-segment
state the shared bound targets). kNN queries at tile centers, A/B over the BE
config enable_geo_knn_shared_bound with interleaved sub-ms client timing:
  - results must be bit-equal;
  - attribution is counters-first (GeoKnnBoundSkippedLeaves via regression);
    this script reports the latency side.

  python3 run_knn_bound_bench.py [--fe 127.0.0.1:8030] [--db hasi_kbench]
                                 [--tiles 8] [--rows-per-tile 3000000] [--runs 40]
"""

import argparse
import base64
import json
import math
import statistics
import sys
import time
import urllib.request

TILES = [
    (116.30, 39.85),   # Beijing
    (151.10, -33.90),  # Sydney
    (-46.70, -23.60),  # Sao Paulo
    (-0.20, 51.48),    # London
    (37.55, 55.70),    # Moscow
    (-122.45, 37.75),  # San Francisco
    (28.00, -26.20),   # Johannesburg
    (77.20, 28.60),    # Delhi
]

KNN_K = 100


def run_stmt(fe, db, user, password, stmt, timeout=1800):
    url = f"http://{fe}/api/query/internal/{db}"
    body = json.dumps({"stmt": stmt}).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        d = json.loads(resp.read())
    if d.get("code") != 0:
        raise RuntimeError(f"query failed: {d}")
    return d["data"]


def http_post(url, timeout=60):
    req = urllib.request.Request(url, data=b"", method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fe", default="127.0.0.1:8030")
    ap.add_argument("--db", default="hasi_kbench")
    ap.add_argument("--tiles", type=int, default=8)
    ap.add_argument("--rows-per-tile", type=int, default=3000000)
    ap.add_argument("--runs", type=int, default=40)
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="")
    args = ap.parse_args()

    def sql(stmt, db=None):
        return run_stmt(args.fe, db or args.db, args.user, args.password, stmt)

    run_stmt(args.fe, "information_schema", args.user, args.password,
             f"create database if not exists {args.db}")

    # Resolve one alive BE for config toggling.
    d = sql("show backends")
    meta = [c["name"] for c in d["meta"]]
    be = next(b for b in d["data"] if str(b[meta.index("Alive")]).lower() == "true")
    be_host, be_port = be[meta.index("Host")], be[meta.index("HttpPort")]

    def be_config(key, value):
        print(f"  BE config {key}={value}")
        http_post(f"http://{be_host}:{be_port}/api/update_config?{key}={value}")

    table = "geo_kb_t"
    sql(f"drop table if exists {table}")
    sql(f"""
        create table {table} (
            `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
            `id` bigint not null,
            `lon` double null,
            `lat` double null,
            INDEX idx_geo(`__s2`) USING GEO
        ) engine=olap duplicate key(`__s2`)
        distributed by hash(`id`) buckets 1
        properties("replication_num" = "1", "disable_auto_compaction" = "true")
    """)
    n = args.rows_per_tile
    be_config("write_buffer_size", "2147483648")
    try:
        for batch, (lon0, lat0) in enumerate(TILES[: args.tiles]):
            t0 = time.monotonic()
            sql(f"insert /*+ SET_VAR(parallel_pipeline_task_num=1) */ into {table}"
                f"(id, lon, lat) "
                f"select {batch} * {n} + number, "
                f"{lon0} + (number % 2000) * 0.00005, "
                f"{lat0} + floor(number / 2000) * 0.00005 "
                f"from numbers('number'='{n}')")
            print(f"  loaded tile {batch} ({n} rows) in {time.monotonic() - t0:.1f}s")
    finally:
        be_config("write_buffer_size", "209715200")

    # Queries: near-tile-0 center (its segment publishes a tight bound; the other
    # 7 far segments' walks should collapse) plus a mid-tile probe.
    specs = []
    for i in (0, 3, 6):
        lon0, lat0 = TILES[i]
        specs.append((f"center_tile{i}",
                      f"select /*+ SET_VAR(enable_sql_cache=false) */ id, "
                      f"st_distance_sphere(lon, lat, {lon0 + 0.01}, {lat0 + 0.01}) as d "
                      f"from {table} order by d asc, id asc limit {KNN_K}"))

    def battery():
        # interleaved A/B per iteration; sub-ms client wall clock
        timings = {name: {"on": [], "off": []} for name, _ in specs}
        payload = {}
        equal = True
        for name, q in specs:
            for state in ("on", "off"):
                be_config("enable_geo_knn_shared_bound", "true" if state == "on" else "false")
                sql(q)  # warmup per state
            for _ in range(args.runs):
                for state in ("on", "off"):
                    be_config("enable_geo_knn_shared_bound",
                              "true" if state == "on" else "false")
                    t0 = time.monotonic()
                    d2 = sql(q)
                    timings[name][state].append((time.monotonic() - t0) * 1000)
                    payload[(name, state)] = d2.get("data")
            if payload[(name, "on")] != payload[(name, "off")]:
                print(f"!! RESULT MISMATCH {name}", file=sys.stderr)
                equal = False
        return timings, equal

    print("== interleaved battery (multi-segment, un-compacted) ==")
    timings, equal = battery()
    be_config("enable_geo_knn_shared_bound", "true")

    ok = equal
    print(f"\n{'query':<16} {'bound_on':>9} {'bound_off':>10} {'on/off':>7}")
    log_sum = 0.0
    for name, _ in specs:
        on = statistics.median(timings[name]["on"])
        off = statistics.median(timings[name]["off"])
        r = on / off if off > 0 else float("inf")
        log_sum += math.log(r)
        print(f"{name:<16} {on:>8.2f}m {off:>9.2f}m {r:>7.3f}")
    gmean = math.exp(log_sum / len(specs))
    print(f"geometric mean on/off: {gmean:.3f} "
          f"{'PASS (bound helps or is neutral)' if gmean <= 1.0 else 'CHECK (bound overhead?)'}")
    sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()
