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

"""HASI micro-benchmark runner (design doc HASI_POC.md §8.2/§8.3, p0 scale).

Runs the circle-retrieval query suite against hasi_bench.geo_t (and plain_t as the
no-__s2 sanity baseline) under per-query SET_VAR configs, via the FE HTTP SQL API.
Timing = the API's server-side `time` field; 1 warmup + N hot runs, median reported.
Results must agree across configs (the count is printed and checked) -- a speedup
that changes the answer is a bug, not a win.

  python3 run_bench.py [--runs 5] [--fe 127.0.0.1:8030] [--db hasi_bench]
"""

import argparse
import base64
import json
import statistics
import sys
import urllib.request

QUERIES = [
    # name, table, lon0, lat0, radius_m
    ("small_1km_city", "geo_t", 116.40, 39.90, 1000.0),
    ("mid_10km_city", "geo_t", 116.40, 39.90, 10000.0),
    ("large_100km_city", "geo_t", 116.40, 39.90, 100000.0),
    ("xlarge_1000km", "geo_t", 116.40, 39.90, 1000000.0),
    ("near_empty_ocean", "geo_t", -150.0, -40.0, 10000.0),
    ("antimeridian_10km", "geo_t", 179.95, 10.0, 10000.0),
]

CONFIGS = [
    ("all_off", "enable_sql_cache=false,enable_geo_predicate_rewrite=false,enable_geo_index_query=false"),
    ("v0_rewrite", "enable_sql_cache=false,enable_geo_predicate_rewrite=true,enable_geo_index_query=false"),
    ("v1_index",
     "enable_sql_cache=false,enable_geo_predicate_rewrite=true,enable_geo_index_query=true,"
     "enable_geo_index_exact_filter=false"),
    ("v15_exact",
     "enable_sql_cache=false,enable_geo_predicate_rewrite=true,enable_geo_index_query=true,"
     "enable_geo_index_exact_filter=true"),
]

# sum/min/max/count(col) exercises the v2b sketch-fold path (needs a table with a
# `val` DOUBLE column and a geo index built with measures="val"; load val as
# (id % 1000) * 0.5 so every value is an exact half -- sums are then order-free
# exact doubles and the cross-config comparison can be bit-strict).
AGG_CONFIGS = [
    ("agg_off",
     "enable_sql_cache=false,enable_geo_predicate_rewrite=false,enable_geo_index_query=false,"
     "enable_geo_agg_pushdown=false"),
    ("agg_v15",
     "enable_sql_cache=false,enable_geo_predicate_rewrite=true,enable_geo_index_query=true,"
     "enable_geo_index_exact_filter=true,enable_geo_agg_pushdown=false"),
    ("agg_v2b",
     "enable_sql_cache=false,enable_geo_predicate_rewrite=true,enable_geo_index_query=true,"
     "enable_geo_index_exact_filter=true,enable_geo_agg_pushdown=true"),
]

# v4 kNN: ORDER BY st_distance_sphere(...), id LIMIT k. Result lists must be
# identical on/off (bit-strict, the distance is part of the payload).
KNN_CONFIGS = [
    ("knn_off", "enable_sql_cache=false,enable_geo_knn_pushdown=false"),
    ("knn_v4", "enable_sql_cache=false,enable_geo_knn_pushdown=true"),
]
KNN_K = 100

# count(*) exercises the v2a COUNT_ON_INDEX path on top of v1.5 exactness.
COUNT_CONFIGS = [
    ("count_off",
     "enable_sql_cache=false,enable_geo_predicate_rewrite=false,enable_geo_index_query=false,"
     "enable_geo_agg_pushdown=false"),
    ("count_v15",
     "enable_sql_cache=false,enable_geo_predicate_rewrite=true,enable_geo_index_query=true,"
     "enable_geo_index_exact_filter=true,enable_geo_agg_pushdown=false"),
    ("count_v2a",
     "enable_sql_cache=false,enable_geo_predicate_rewrite=true,enable_geo_index_query=true,"
     "enable_geo_index_exact_filter=true,enable_geo_agg_pushdown=true"),
]


def run_stmt(fe, db, user, password, stmt):
    url = f"http://{fe}/api/query/internal/{db}"
    body = json.dumps({"stmt": stmt}).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=300) as resp:
        d = json.loads(resp.read())
    if d.get("code") != 0:
        raise RuntimeError(f"query failed: {d}")
    return d["data"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--fe", default="127.0.0.1:8030")
    ap.add_argument("--db", default="hasi_bench")
    ap.add_argument("--table", default="geo_t")
    ap.add_argument("--meas-table", default="",
                    help="table with a val measure + measures geo index; enables the v2b agg section")
    ap.add_argument("--gp-table", default="",
                    help="GEO_POINT-column table (loc geo_point + val measure, GEO index on loc); "
                         "enables the native-type section (3-arg st_distance_sphere)")
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="")
    args = ap.parse_args()

    rows = []
    for qname, _table, lon0, lat0, radius in QUERIES:
        table = args.table
        counts = {}
        medians = {}
        for cname, setvars in CONFIGS:
            stmt = (f"select /*+ SET_VAR({setvars}) */ count(id) from {table} "
                    f"where st_distance_sphere(lon, lat, {lon0}, {lat0}) < {radius}")
            times = []
            count = None
            for i in range(args.runs + 1):
                data = run_stmt(args.fe, args.db, args.user, args.password, stmt)
                count = data["data"][0][0] if data.get("data") else None
                if i > 0:  # skip warmup
                    times.append(data["time"])
            counts[cname] = count
            medians[cname] = statistics.median(times)
        if len(set(counts.values())) != 1:
            print(f"!! RESULT MISMATCH for {qname}: {counts}", file=sys.stderr)
            sys.exit(2)
        base = medians["all_off"]
        rows.append((qname, counts["all_off"], medians, base))

    print(f"{'query':<20} {'rows':>8} {'all_off':>9} {'v0':>9} {'v1':>9} {'v1.5':>9} "
          f"{'v0_x':>6} {'v1_x':>6} {'v15_x':>6}")
    for qname, count, medians, base in rows:
        v0 = medians["v0_rewrite"]
        v1 = medians["v1_index"]
        v15 = medians["v15_exact"]
        print(f"{qname:<20} {count:>8} {base:>8.0f}ms {v0:>8.0f}ms {v1:>8.0f}ms {v15:>8.0f}ms "
              f"{base / max(v0, 0.001):>5.1f}x {base / max(v1, 0.001):>5.1f}x "
              f"{base / max(v15, 0.001):>5.1f}x")

    print()
    print(f"{'count(*) query':<20} {'rows':>9} {'off':>9} {'v1.5':>9} {'v2a':>9} "
          f"{'v15_x':>6} {'v2a_x':>6}")
    for qname, _table, lon0, lat0, radius in QUERIES:
        table = args.table
        counts = {}
        medians = {}
        for cname, setvars in COUNT_CONFIGS:
            stmt = (f"select /*+ SET_VAR({setvars}) */ count(*) from {table} "
                    f"where st_distance_sphere(lon, lat, {lon0}, {lat0}) < {radius}")
            times = []
            count = None
            for i in range(args.runs + 1):
                data = run_stmt(args.fe, args.db, args.user, args.password, stmt)
                count = data["data"][0][0] if data.get("data") else None
                if i > 0:
                    times.append(data["time"])
            counts[cname] = count
            medians[cname] = statistics.median(times)
        if len(set(counts.values())) != 1:
            print(f"!! COUNT MISMATCH for {qname}: {counts}", file=sys.stderr)
            sys.exit(2)
        base = medians["count_off"]
        v15 = medians["count_v15"]
        v2a = medians["count_v2a"]
        print(f"{qname:<20} {counts['count_off']:>9} {base:>8.0f}ms {v15:>8.0f}ms {v2a:>8.0f}ms "
              f"{base / max(v15, 0.001):>5.1f}x {base / max(v2a, 0.001):>5.1f}x")

    if not args.meas_table:
        return
    print()
    print(f"{'agg query (v2b)':<20} {'rows':>9} {'off':>9} {'v1.5':>9} {'v2b':>9} "
          f"{'v15_x':>6} {'v2b_x':>6}")
    for qname, _table, lon0, lat0, radius in QUERIES:
        table = args.meas_table
        results = {}
        medians = {}
        for cname, setvars in AGG_CONFIGS:
            stmt = (f"select /*+ SET_VAR({setvars}) */ "
                    f"count(*), count(val), sum(val), min(val), max(val) from {table} "
                    f"where st_distance_sphere(lon, lat, {lon0}, {lat0}) < {radius}")
            times = []
            result = None
            for i in range(args.runs + 1):
                data = run_stmt(args.fe, args.db, args.user, args.password, stmt)
                result = tuple(data["data"][0]) if data.get("data") else None
                if i > 0:
                    times.append(data["time"])
            results[cname] = result
            medians[cname] = statistics.median(times)
        if len(set(results.values())) != 1:
            # val is loaded as exact halves, so even sum must be bit-identical
            print(f"!! AGG MISMATCH for {qname}: {results}", file=sys.stderr)
            sys.exit(2)
        base = medians["agg_off"]
        v15 = medians["agg_v15"]
        v2b = medians["agg_v2b"]
        nrows = results["agg_off"][0] if results["agg_off"] else "?"
        print(f"{qname:<20} {nrows:>9} {base:>8.0f}ms {v15:>8.0f}ms {v2b:>8.0f}ms "
              f"{base / max(v15, 0.001):>5.1f}x {base / max(v2b, 0.001):>5.1f}x")

    if not args.gp_table:
        return
    # GEO_POINT native type (HASI_POC.md §10): the same circles through the 3-arg
    # predicate on a single geo_point column. Per-config results on the SAME table
    # must stay bit-identical (the quantized point is the value, every config
    # evaluates the same function); cross-table counts vs geo_t may differ by the
    # ≤1cm quantization at the circle boundary and are not asserted here.
    print()
    print(f"{'geo_point retrieval':<20} {'rows':>9} {'all_off':>9} {'v0':>9} {'v1':>9} {'v1.5':>9} "
          f"{'v15_x':>6}")
    for qname, _table, lon0, lat0, radius in QUERIES:
        table = args.gp_table
        counts = {}
        medians = {}
        for cname, setvars in CONFIGS:
            stmt = (f"select /*+ SET_VAR({setvars}) */ count(id) from {table} "
                    f"where st_distance_sphere(loc, {lon0}, {lat0}) < {radius}")
            times = []
            count = None
            for i in range(args.runs + 1):
                data = run_stmt(args.fe, args.db, args.user, args.password, stmt)
                count = data["data"][0][0] if data.get("data") else None
                if i > 0:
                    times.append(data["time"])
            counts[cname] = count
            medians[cname] = statistics.median(times)
        if len(set(counts.values())) != 1:
            print(f"!! GEO_POINT RESULT MISMATCH for {qname}: {counts}", file=sys.stderr)
            sys.exit(2)
        base = medians["all_off"]
        v0 = medians["v0_rewrite"]
        v1 = medians["v1_index"]
        v15 = medians["v15_exact"]
        print(f"{qname:<20} {counts['all_off']:>9} {base:>8.0f}ms {v0:>8.0f}ms {v1:>8.0f}ms "
              f"{v15:>8.0f}ms {base / max(v15, 0.001):>5.1f}x")

    print()
    print(f"{'geo_point agg (v2b)':<20} {'rows':>9} {'off':>9} {'v1.5':>9} {'v2b':>9} "
          f"{'v15_x':>6} {'v2b_x':>6}")
    for qname, _table, lon0, lat0, radius in QUERIES:
        table = args.gp_table
        results = {}
        medians = {}
        for cname, setvars in AGG_CONFIGS:
            stmt = (f"select /*+ SET_VAR({setvars}) */ "
                    f"count(*), count(val), sum(val), min(val), max(val) from {table} "
                    f"where st_distance_sphere(loc, {lon0}, {lat0}) < {radius}")
            times = []
            result = None
            for i in range(args.runs + 1):
                data = run_stmt(args.fe, args.db, args.user, args.password, stmt)
                result = tuple(data["data"][0]) if data.get("data") else None
                if i > 0:
                    times.append(data["time"])
            results[cname] = result
            medians[cname] = statistics.median(times)
        if len(set(results.values())) != 1:
            print(f"!! GEO_POINT AGG MISMATCH for {qname}: {results}", file=sys.stderr)
            sys.exit(2)
        base = medians["agg_off"]
        v15 = medians["agg_v15"]
        v2b = medians["agg_v2b"]
        nrows = results["agg_off"][0] if results["agg_off"] else "?"
        print(f"{qname:<20} {nrows:>9} {base:>8.0f}ms {v15:>8.0f}ms {v2b:>8.0f}ms "
              f"{base / max(v15, 0.001):>5.1f}x {base / max(v2b, 0.001):>5.1f}x")

    # ---- v4 kNN (both table forms; gate: city-center k=100 median >= 5x) ----
    for label, table, dist in [
        ("knn lon/lat", args.table, "st_distance_sphere(lon, lat, {lon0}, {lat0})"),
        ("knn geo_point", args.gp_table, "st_distance_sphere(loc, {lon0}, {lat0})"),
    ]:
        if not table:
            continue
        print()
        print(f"{label:<20} {'k':>5} {'off':>9} {'v4':>9} {'v4_x':>6}")
        for qname, _table, lon0, lat0, _radius in QUERIES:
            d = dist.format(lon0=lon0, lat0=lat0)
            results = {}
            medians = {}
            for cname, setvars in KNN_CONFIGS:
                stmt = (f"select /*+ SET_VAR({setvars}) */ id, {d} as dist "
                        f"from {table} order by dist asc, id asc limit {KNN_K}")
                times = []
                result = None
                for i in range(args.runs + 1):
                    data = run_stmt(args.fe, args.db, args.user, args.password, stmt)
                    result = tuple(tuple(r) for r in data.get("data", []))
                    if i > 0:
                        times.append(data["time"])
                results[cname] = result
                medians[cname] = statistics.median(times)
            if len(set(results.values())) != 1:
                print(f"!! KNN MISMATCH for {label}/{qname}", file=sys.stderr)
                sys.exit(2)
            base = medians["knn_off"]
            v4 = medians["knn_v4"]
            print(f"{qname:<20} {KNN_K:>5} {base:>8.0f}ms {v4:>8.0f}ms "
                  f"{base / max(v4, 0.001):>5.1f}x")


if __name__ == "__main__":
    main()
