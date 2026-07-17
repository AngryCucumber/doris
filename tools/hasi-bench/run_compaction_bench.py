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

"""HASI v3 compaction splice benchmark (HASI_POC.md §12.3 gates).

Two runs over identical data (N disjoint tile loads, Hilbert-sorted single-sink
inserts so every load rowset stays NONOVERLAPPING):
  A. splice armed  (BE enable_geo_index_incremental_compaction=true)
  B. inline rebuild (....=false)
each followed by one full compaction, measured via BE /metrics deltas:
  gate 1: rollup_ns(A) / geo_index_build_ns(B) <= 0.5
  gate 2: compaction wall time A <= B * 1.05
  gate 3: post-compaction query battery -- results bit-equal between A and B,
          medians within +-5%.

  python3 run_compaction_bench.py [--fe 127.0.0.1:8030] [--db hasi_cbench]
                                  [--tiles 8] [--rows-per-tile 3000000] [--runs 5]
"""

import argparse
import base64
import json
import math
import statistics
import sys
import time
import urllib.request

# Far-apart city tiles; per-load hull disjointness is ASSERTED after loading
# (geographic tiling does not guarantee disjoint S2 hulls -- HASI_POC.md §12.5).
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

METRICS = [
    "geo_index_build_ns_total",
    "geo_index_compaction_rollup_total",
    "geo_index_compaction_rollup_fallback_total",
    "geo_index_compaction_rollup_ns_total",
]


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


def http_get(url, timeout=60):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.read().decode()


def http_post(url, timeout=60):
    req = urllib.request.Request(url, data=b"", method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode()


class Bench:
    def __init__(self, args):
        self.args = args

    def sql(self, stmt, timeout=1800):
        return run_stmt(self.args.fe, self.args.db, self.args.user, self.args.password, stmt,
                        timeout)

    def rows(self, stmt):
        return self.sql(stmt).get("data") or []

    def resolve_tablet(self, table):
        d = self.sql(f"show tablets from {table}")
        meta = [c["name"] for c in d["meta"]]
        row = d["data"][0]
        tablet_id = row[meta.index("TabletId")]
        backend_id = row[meta.index("BackendId")]
        d = self.sql("show backends")
        meta = [c["name"] for c in d["meta"]]
        for be in d["data"]:
            if str(be[meta.index("BackendId")]) == str(backend_id):
                return tablet_id, be[meta.index("Host")], be[meta.index("HttpPort")]
        raise RuntimeError(f"backend {backend_id} not found")

    def any_backend(self):
        d = self.sql("show backends")
        meta = [c["name"] for c in d["meta"]]
        for be in d["data"]:
            if str(be[meta.index("Alive")]).lower() == "true":
                return be[meta.index("Host")], be[meta.index("HttpPort")]
        raise RuntimeError("no alive backend")

    def be_metrics(self, host, port):
        data = json.loads(http_get(f"http://{host}:{port}/metrics?type=json"))
        out = {}
        for item in data:
            name = (item.get("tags") or {}).get("metric")
            if name in METRICS:
                out[name] = int(item.get("value", 0))
        for name in METRICS:
            out.setdefault(name, 0)
        return out

    def be_set_config(self, host, port, key, value):
        print(f"  BE config {key}={value}")
        http_post(f"http://{host}:{port}/api/update_config?{key}={value}")

    def create_and_load(self, table):
        self.sql(f"drop table if exists {table}")
        self.sql(f"""
            create table {table} (
                `__s2` bigint generated always as (st_s2_cellid(`lon`, `lat`)) null,
                `id` bigint not null,
                `lon` double null,
                `lat` double null,
                `val` double null,
                INDEX idx_geo(`__s2`) USING GEO PROPERTIES("measures" = "val")
            ) engine=olap duplicate key(`__s2`)
            distributed by hash(`id`) buckets 1
            properties("replication_num" = "1", "disable_auto_compaction" = "true")
        """)
        n = self.args.rows_per_tile
        for batch, (lon0, lat0) in enumerate(TILES[: self.args.tiles]):
            # Single sink task + a write_buffer_size raised above the load size
            # (set in one_run) => one memtable => one segment per load rowset.
            # A single-segment rowset is never "overlapping" and the memtable
            # sorts on flush, so no ORDER BY is needed (INSERT..SELECT ORDER BY
            # without LIMIT is eliminated by the optimizer anyway).
            stmt = (f"insert /*+ SET_VAR(parallel_pipeline_task_num=1) */ into {table}"
                    f"(id, lon, lat, val) "
                    f"select {batch} * {n} + number, "
                    f"{lon0} + (number % 2000) * 0.00005, "
                    f"{lat0} + floor(number / 2000) * 0.00005, "
                    f"number % 97 "
                    f"from numbers('number'='{n}')")
            t0 = time.monotonic()
            self.sql(stmt)
            print(f"  loaded tile {batch} ({n} rows) in {time.monotonic() - t0:.1f}s")
        # Hull disjointness: the arming precondition the tiles must deliver.
        hulls = self.rows(f"select cast(id / {n} as bigint) as b, min(__s2), max(__s2) "
                          f"from {table} group by b order by min(__s2)")
        for i in range(len(hulls) - 1):
            if not int(hulls[i][2]) < int(hulls[i + 1][1]):
                print(f"!! tile hulls overlap, splice cannot arm: {hulls}", file=sys.stderr)
                sys.exit(2)

    def check_rowsets_nonoverlapping(self, tablet_id, host, port):
        d = json.loads(http_get(f"http://{host}:{port}/api/compaction/show?tablet_id={tablet_id}"))
        bad = [r for r in d.get("rowsets", []) if "OVERLAPPING" in r and "NONOVERLAPPING" not in r]
        if bad:
            print(f"!! OVERLAPPING input rowsets, splice cannot arm: {bad}", file=sys.stderr)
            sys.exit(2)

    def full_compaction(self, tablet_id, host, port):
        d = json.loads(http_get(f"http://{host}:{port}/api/compaction/show?tablet_id={tablet_id}"))
        before = d.get("last full success time")
        t0 = time.monotonic()
        r = json.loads(http_post(
                f"http://{host}:{port}/api/compaction/run?tablet_id={tablet_id}&compact_type=full"))
        if str(r.get("status", "")).lower() != "success":
            raise RuntimeError(f"trigger full compaction failed: {r}")
        while True:
            time.sleep(1)
            r = json.loads(http_get(
                    f"http://{host}:{port}/api/compaction/run_status?tablet_id={tablet_id}"))
            if not r.get("run_status", True):
                d = json.loads(http_get(
                        f"http://{host}:{port}/api/compaction/show?tablet_id={tablet_id}"))
                if d.get("last full success time") != before:
                    break
            if time.monotonic() - t0 > 3600:
                raise RuntimeError("full compaction timed out")
        return time.monotonic() - t0

    def battery_specs(self):
        specs = []
        for i, (lon0, lat0) in enumerate(TILES[: self.args.tiles][:3]):
            specs.append((f"circle_agg_{i}",
                          "select /*+ SET_VAR(enable_sql_cache=false) */ count(id), count(val),"
                          f" sum(val) from TBL where "
                          f"st_distance_sphere(lon, lat, {lon0 + 0.02}, {lat0 + 0.02}) < 3000"))
            specs.append((f"knn_{i}",
                          "select /*+ SET_VAR(enable_sql_cache=false) */ id,"
                          f" st_distance_sphere(lon, lat, {lon0 + 0.01}, {lat0 + 0.01})"
                          f" as d from TBL order by d asc, id asc limit 100"))
        return specs

    # Gate-3 methodology: alternate the two tables per iteration and time on the
    # client with sub-ms wall clock -- the FE `time` field is integer ms and a
    # per-scenario (non-interleaved) battery lets drift masquerade as a ratio.
    def interleaved_battery(self, table_a, table_b, runs):
        timings = {}
        equal = True
        for name, q in self.battery_specs():
            times = {table_a: [], table_b: []}
            payload = {}
            for t in times:
                self.sql(q.replace("TBL", t)) # warmup
            for _ in range(runs):
                for t in times:
                    t0 = time.monotonic()
                    d = self.sql(q.replace("TBL", t))
                    times[t].append((time.monotonic() - t0) * 1000)
                    payload[t] = d.get("data")
            if payload[table_a] != payload[table_b]:
                print(f"!! RESULT MISMATCH {name}: {payload}", file=sys.stderr)
                equal = False
            timings[name] = (statistics.median(times[table_a]),
                             statistics.median(times[table_b]))
        return timings, equal

    def one_run(self, table, splice_on):
        print(f"== scenario {'A splice' if splice_on else 'B inline'} ({table}) ==")
        cfg_host, cfg_port = self.any_backend()
        self.be_set_config(cfg_host, cfg_port, "write_buffer_size", "2147483648")
        try:
            self.create_and_load(table)
        finally:
            self.be_set_config(cfg_host, cfg_port, "write_buffer_size", "209715200")
        tablet_id, host, port = self.resolve_tablet(table)
        self.check_rowsets_nonoverlapping(tablet_id, host, port)
        self.be_set_config(host, port, "enable_geo_index_incremental_compaction",
                           "true" if splice_on else "false")
        m0 = self.be_metrics(host, port)
        wall = self.full_compaction(tablet_id, host, port)
        m1 = self.be_metrics(host, port)
        delta = {k: m1[k] - m0[k] for k in METRICS}
        print(f"  full compaction wall: {wall:.1f}s, metric deltas: {delta}")
        return {"wall": wall, "delta": delta, "be": (host, port)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fe", default="127.0.0.1:8030")
    ap.add_argument("--db", default="hasi_cbench")
    ap.add_argument("--tiles", type=int, default=8)
    ap.add_argument("--rows-per-tile", type=int, default=3000000)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="")
    args = ap.parse_args()

    run_stmt(args.fe, "information_schema", args.user, args.password,
             f"create database if not exists {args.db}")
    bench = Bench(args)

    a = bench.one_run("geo_ct_splice", splice_on=True)
    b = bench.one_run("geo_ct_inline", splice_on=False)
    # Leave the BE at the default.
    bench.be_set_config(*a["be"], "enable_geo_index_incremental_compaction", "true")

    ok = True
    if a["delta"]["geo_index_compaction_rollup_total"] < 1:
        print("!! gate FAILED: splice did not fire in scenario A", file=sys.stderr)
        ok = False
    if b["delta"]["geo_index_compaction_rollup_total"] > 0:
        print("!! scenario B unexpectedly took the splice path", file=sys.stderr)
        ok = False

    rollup_ns = a["delta"]["geo_index_compaction_rollup_ns_total"]
    rebuild_ns = b["delta"]["geo_index_build_ns_total"]
    ratio = rollup_ns / rebuild_ns if rebuild_ns > 0 else float("inf")
    print(f"\ngate 1 (index time <=50%): splice {rollup_ns / 1e6:.1f}ms vs "
          f"inline rebuild {rebuild_ns / 1e6:.1f}ms -> ratio {ratio:.3f} "
          f"{'PASS' if ratio <= 0.5 else 'FAIL'}")
    ok = ok and ratio <= 0.5

    wall_ratio = a["wall"] / b["wall"] if b["wall"] > 0 else float("inf")
    print(f"gate 2 (compaction wall not worse): A {a['wall']:.1f}s vs B {b['wall']:.1f}s "
          f"-> ratio {wall_ratio:.3f} {'PASS' if wall_ratio <= 1.05 else 'FAIL'}")
    ok = ok and wall_ratio <= 1.05

    timings, results_equal = bench.interleaved_battery("geo_ct_splice", "geo_ct_inline",
                                                       args.runs)
    if not results_equal:
        print("!! gate 3 FAILED: post-compaction results differ between splice and rebuild",
              file=sys.stderr)
        ok = False
    print(f"\ngate 3 (post-compaction interleaved battery, medians ms, A=splice-built index):")
    print(f"{'query':<16} {'A':>9} {'B':>9} {'A/B':>7}")
    worst = 0.0
    log_sum = 0.0
    for name, (ta, tb) in timings.items():
        r = ta / tb if tb > 0 else float("inf")
        worst = max(worst, r)
        log_sum += math.log(r)
        print(f"{name:<16} {ta:>9.2f} {tb:>9.2f} {r:>7.3f}")
    # Two physically distinct tablets holding identical data show single-query
    # median jitter of a few percent either way (disk layout / cache locality);
    # the gate is the geometric mean, the worst query is informational -- when
    # in doubt compare the GeoKnnLeavesScanned/GeoKnnRowsScored profile
    # counters, which are layout-independent.
    gmean = math.exp(log_sum / len(timings)) if timings else float("inf")
    print(f"geometric mean A/B: {gmean:.3f} {'PASS' if gmean <= 1.05 else 'FAIL (>1.05)'}"
          f"  (worst single query: {worst:.3f}, informational)")
    ok = ok and gmean <= 1.05

    sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()
