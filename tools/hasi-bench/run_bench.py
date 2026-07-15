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


if __name__ == "__main__":
    main()
