<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# G2 external catalog and S3 full streamed reads

`external_read_performance.py` and `LicenseExternalReadPerformance.java` run
one explicitly scheduled window. `source_kind=catalog` is LP-005;
`source_kind=s3_tvf` is LP-008. Both use persistent JDBC connections, concurrency
1/8, seed 20260922 and finite fractional open-loop operation rates. A complete
million-row SELECT, full client oracle and confirmed result/statement close is
one operation. Counts, rows and fetch batches never replace operation samples.

The tools do not start services, create catalogs, change global settings, import
licenses, choose capacity or qualify A/A/A/B performance. The existing JDBC,
Scanner, Flight, observer and functional tools remain unchanged.

## Actual operation, memory and connection contract

- Every operation selects exactly `id, grp, v, payload` from the declared catalog
  `public.source_rows` or the fixed S3 `lp008/*.parquet` prefix. S3 source evidence
  requires 100 objects of 10,000 rows and their complete independently verified
  bytes. Catalog evidence binds the native complete source CSV to its model SHA.
- Every row must be non-null: id 0..999999, grp=id%1024, v=id%100000 and complete
  lowercase MD5(decimal id). An ID bitmap detects duplicates/missing rows. Actual
  group/value/payload arrays, indexed by ID, feed a final canonical CSV digest.
  Java and Python independently compute the four-column expected model:
  `b2b90b17ef5b149fa1deca05a37b48198d0e709790be44ea2ecb80979d9cef7c`.
  Per worker arrays use about 44.125 MB plus JDBC/Java overhead. Their work stays
  inside service time; no estimated overhead is subtracted.
- The actual MariaDB 3.0.9 driver must return `StreamingResult`, forward-only,
  fetch size 1024. A buffered `CompleteResult` fails. Driver, connection, client
  and result classes are recorded. The same Connection, underlying StandardClient,
  physical socket and handshake connection ID must remain across warmup and
  measurement; reconnect/retry is disabled. Socket local/remote ports provide
  additional transport evidence. Failed sessions are poisoned and never replayed.
- JDBC metadata is exactly BIGINT(-5), INTEGER(4), BIGINT(-5), VARCHAR(12), labels
  id/grp/v/payload. The original A's real metadata-only preflight for both sources
  is bound separately; `LIMIT 0` is never counted as a successful full read.
- Each worker SETs and reads back SQL/query/file cache=false, query_timeout=60,
  batch_size=8192 and exec_mem_limit=536870912. This does not claim to flush the
  source database's buffers or operating system page cache.
- FE query timeout is 60 seconds, socket idle timeout 60 seconds, connection
  timeout 10 seconds. The harness adds an absolute 120-second dispatch budget
  through full oracle/close. Queue is outside this deadline and fully included in
  end-to-end latency. JDBC Statement query timeout is explicitly zero: the harness
  does not use the driver's separate cancellation connection. A watchdog closes
  the exact owned driver socket; its private-field ABI and JAR are bound. Normal
  connection close has a 5-second watchdog. An abort, late completion or missing
  close invalidates the window.
- JVM heap is 768 MiB, direct-memory limit 512 MiB. These are not RSS guarantees.
  Actual client/FE/BE/source resource samples remain an outer-controller task.

## Narrow interface

The module exports `plan(profile)`, `prepare_private_query(source_ref, output,
s3_client_path=None)`, `compile_helper(spec, output)`,
`run_window(profile_ref, context, runtime_ref, output, stop_file=None)` and
`normalize(manifest)`. CLI modes are `plan`, `prepare-private`, `compile`, `run`,
`normalize`, with `--input JSON --output NEW_PATH`.

Example diagnostic profile:

```json
{
  "schema_version": 1, "profile": "g2_external_read_v1",
  "qualification": "diagnostic", "source_kind": "catalog",
  "source_data_sha256": "b2b90b17ef5b149fa1deca05a37b48198d0e709790be44ea2ecb80979d9cef7c",
  "column_types": [-5, 4, -5, 12], "seed": 20260922, "concurrency": 1,
  "rate": 0.5, "warmup_seconds": 16, "duration_seconds": 24,
  "drain_seconds": 45, "max_requests": 1000, "max_raw_ledger_bytes": 67108864
}
```

Formal profiles require at least 180 seconds warmup, 600 seconds measurement and
10,000 successful complete operations. Duration can extend to 604800 seconds,
with at most 25000 planned requests per phase; budgets are predeclared. Insufficient
samples/resources remain unqualified. Rate/window length are excluded from the
business hash; kind, data model/hash, schema, connection/session/timeout settings,
concurrency, seed and drain/archive bounds are included. The outer capacity and
statistics controller still freezes the actual rate, schedule, length and SLO.

The compile spec contains `java_home` and exactly four installed JAR paths:
MariaDB 3.0.9 and Jackson annotations/core/databind 2.16.0. No downloads or broad
application classpath are used. Runtime evidence binds the actual JDK17.0.4,
JARs, compiled classes and Python/Java/clock/statistics sources. Nonempty
JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS and _JAVA_OPTIONS are rejected before compile
or launch. The explicit classpath takes precedence over an inherited CLASSPATH.
Driver JUL logging is disabled, and exceptions expose only class/SQLState/vendor
code, never SQL text, credentials or server exception messages.

## Source and private input bindings

`context.external_source` references a public JSON with exact fields:
`schema_version=1`, `source_kind`, `source_data_sha256`, actual `service` process
pin, `resources={cpu_affinity:[5],memory_limit_bytes:536870912}`, references to
`state`, `native_evidence`, `reachability`, `metadata_evidence`, `plan`, and either
the actual `catalog` name or fixed S3 `uri`. The state must be the live attached
private service, with native million-row/100-object proof and root's real original
A SQL and JDBC metadata preflights. No credential values are public fields.

For catalog, source_data_sha256 is the complete canonical native CSV SHA. For S3,
it is SHA256 of UTF-8 canonical JSON (`sort_keys=True`, separators `(',', ':')`)
of the ordered native 100 objects, each containing exactly key/bytes/sha256.
These must match the prepared 100×10000 object manifest.

`prepare-private` accepts only `{external_source:REF, s3_client_path:PATH}`
(omit the path for catalog). At root's invocation, it reads the mode0600 S3
configuration path and creates an exclusive mode0600 `{source_kind,sql}` file.
It returns only its path and SHA. It does not connect or print credential values.
`run` receives this file through `context.private_query`; it validates the exact
full-read grammar, copies it to mode0600 `query.private.json` in a mode0700 window
directory, and records only SQL/input hashes publicly. Do not publish private
query files with public evidence. Development and offline tests do not read the
actual S3 credentials; tests use explicit synthetic secrets.

The complete seven-field identity and artifact/snapshot bindings follow the
other P4 single-window tools. In addition, identity snapshots must contain:

- environment: `external_source` equal to the actual source reference;
- fixture: that `external_source`, `model_sha256` and `source_data_sha256`;
- client: actual `user`, `password_env`, `private_query`, `sql_sha256` and
  `connection_mode="reuse_jdbc_streaming"`.

These prevent keeping the same frozen identity while changing reader, source,
private SQL or credential binding. Runtime consumes the FE password only from the
declared environment variable. Context endpoints are query_port/user/password_env;
FE/BE configurations, installed slots, process identities and private namespace
are checked before/after, with process lifetimes checked during execution.

## Lifecycle, raw audit and formal boundaries

Phases are DIAGNOSTIC/CAPACITY/AA/AB, variants A/B. CAPACITY/AA reject B. A fresh
nonce/PID/start-ticks handshake maps actual JVM time to a bounded Python interval.
Warmup, every planned arrival and terminal result, client queue, service and total
latency, CPU boundaries including drain, errors/timeouts, session open/close and
actual parent wait are retained. A stop/source/identity failure still reaps only
the owned JVM; forced exit or incomplete evidence fails. SQL/private output and
all raw/dependency SHA bindings are rechecked by normalization.

AB also requires the eligible freeze and its same-boot publication before warmup,
matching G2/LP-005 or LP-008, `reuse_jdbc_streaming`, actual business identity,
rate/concurrency/seed, arrival vector and window lengths. No field accepts an
unbound success assertion as a formal performance decision.

Formal normalization requires an external observer audit covering **the entire
actual warmup/measurement CPU sampling interval**, using conservative JVM mapping
bounds, and actual license state ORIGINAL_A_NO_LICENSE or canonical usable B VALID.
The usual FE/BE artifact/config/pin and raw-sample bindings apply. It also requires
`observer.external_source` with exact pin/state/resources, sample_count>=2,
peak_rss_bytes, actual cgroup_memory_limit_bytes, peak_cgroup_memory_bytes,
cgroup_oom_kill_delta=0 and all_sample_cpu_affinities=[[5]]. Cgroup peak includes
PostgreSQL children; postmaster RSS alone does not prove source memory bounds.
The controller supplies and binds actual samples. No new general RPC/GC collector
is introduced. Missing source/resource observations leave formal work incomplete.

Normalized output follows the common P4 window schema. Diagnostic success is
`DIAGNOSTIC_VERIFIED_NOT_QUALIFIED`; even formally shaped raw `VERIFIED` evidence
always has `formal_performance_pass=false`. Independent capacity, repeated A/A,
candidate valid/expired behavior and A/B precision gates remain external.

Offline checks:

```bash
taskset -c 4 python3 -m unittest discover -s tools/license-checks -p 'test_external_read_performance.py' -v
```

Java `--self-test OUTPUT` checks a full reverse million-row model, negative
oracles, driver socket ABI and an unopened local socket watchdog; it makes no
connection. `--plan PROFILE NEW_DIRECTORY` writes only the independent Java
arrival vectors. Neither is actual external data or performance evidence.
