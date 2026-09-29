# Current G2 complex performance windows

This explicitly selected entry runs the fixed 33-column complex query from
`complex_planning_oracle.py`. It reuses the existing JDBC worker/connection and
view-DDL implementation. The original `complex_planning_fixture.py` entry retains
its functional Profile/EXPLAIN behavior and limits. Its historical evidence must
remain bound to the original source bytes; the original Java source is saved at
`.build-records/license-p4-20260929/complex/legacy-before-performance/`.

| Shape | Connections | Session and event |
| --- | --- | --- |
| cold, c1/c8 | one connection per request | SQL cache off, query cache off, no DDL |
| hot, c1/c8 | one reused connection per worker | SQL cache on, query cache off, ALTER VIEW at measurement epoch +180 seconds |

Short diagnostics are explicitly ineligible. Hot diagnostics still need a
duration greater than 180 seconds, scheduled arrivals on both sides of t180, and
actual successful requests before DDL and after its ACK. Formal windows retain
warmup >=180 seconds and measurement >=600 seconds. The statistical layer still
requires >=10,000 successful complete queries per window, sufficient A/A precision,
the original A/B limits and pair count. A 33-column row is one operation, not 33
samples. Low-rate cases must extend duration to obtain enough complete operations.

## Input and ownership

`complex_performance.py plan --input profile.json --output arrivals-plan.json`
validates and writes an arrival plan; it never launches a service or sends SQL.
The exact profile is:

```json
{
  "schema_version": 1,
  "profile": "g2_complex_performance_v1",
  "kind": "cold",
  "concurrency": 1,
  "qualification": "diagnostic",
  "seed": 20260922,
  "rate_per_second": 2.0,
  "warmup_seconds": 5,
  "duration_seconds": 10,
  "timeout_seconds": 10,
  "drain_seconds": 30,
  "prepare_timeout_seconds": 120,
  "cleanup_timeout_seconds": 30,
  "coordination_timeout_seconds": 60,
  "max_requests": 10000,
  "read_account": {
    "username": "massdb_p4_read",
    "host": "%",
    "password_env": "MASSDB_UI_P4_READ_PASSWORD"
  }
}
```

Use `qualification=formal` only with formal durations. The maximum duration is
86,400 seconds, warmup 1,800 seconds, total arrivals 100,000 and each JSONL file
512 MiB (16 KiB per complete line). These are client resource limits; exceeding
them never establishes a database capacity. Heap is 512 MiB, compilation heap
256 MiB, and the caller supplies a fixed combined controller/helper RSS budget
of at least 1,024 MiB plus outer service/resource observation. Frozen inputs also
bind the exact JDK 17.0.4+8 runtime, packaged MariaDB 3.0.9/Jackson dependencies,
client source, account reference, timeout/drain and connection settings.

The arrival generator deliberately reuses Python `Random(20260922).expovariate`,
continuing the RNG from warmup into measurement. It is not the Java Random
sequence used by other workloads. The algorithm is part of the business hash;
both full arrays and the measurement-array SHA are retained. Workers consume
indices modulo concurrency, waiting for each arrival without overlapping their
own requests. Delays add to the queue and end-to-end latency; no arrivals are
silently omitted or retried.

The only created object is `license_perf.license_complex_view`. Preparation uses
the existing bounded SQL executor and original complete million-row source
integrity query and schema check. It refuses an existing fixed-name view or
ownership lock. CREATE has no adoption clause. An uncertain CREATE retains its
lock and evidence for explicit recovery. Only an acknowledged owned view can be
restored and dropped, after real helper wait and thread/connection cleanup. A
compile failure before any helper launch can remove its verified owned view; it
cannot produce a valid window. Source schema and all source formulas are checked
again before DROP. Use a valid certificate for preparation and final SELECT
verification. This G2 read workload is measured in VALID state on B.

## Thin controller integration

The module intentionally has no implicit real-run CLI. A controller uses the
established `ui_baseline_fixture` API/owned guard and existing bounded `SqlOracle`
executor, retains its full SQL receipts, and supplies:

1. `freeze(api, profile_path, cluster, resources)`, stored as `plan["complex"]`;
   the plan also contains a new owned output directory and `resources`.
2. A launch record with `schema_version`, phase `CAPACITY/AA/AB/DIAGNOSTIC`, A/B
   variant, unique 32-hex token, window/pair IDs, boot ID, actual monotonic
   creation time, bounded UTC anchor, declared maximum clock uncertainty,
   `identity`, workload reference and actual FE/BE start ticks. Bindings are
   exactly `runner`, `java_helper`, `legacy_helper`, `oracle`, `lifecycle`,
   `clock_adapter`, `statistics`, `jdbc_driver`, `fe_artifact`, `be_artifact`,
   `environment`, `configuration`, `fixture`, `client`. All references are
   `{path, sha256}`. CAPACITY and AA are A-only. AB additionally requires the
   published eligible freeze and its publication reference before launch.
3. `ComplexPerformance(api, plan, guard, target, admin, deadline, cpu_services,
   launch, sql, cluster_path, lock_path)`. `target` has `name`, local `host` and
   `query_port`; `admin` uses explicit account/password-environment references.
   Distinct FE/BE CPU pins must match owned cluster members, executable roles,
   namespace, launch generation and service observations. No accounts are
   implicitly created. The output is `<plan.output>/complex-background`.
4. `start()` performs preparation, compilation, pins the actual child and waits
   for ready. Before releasing warmup, perform the real separate path preflight
   below and start the real external observer. `release_warmup()` performs the
   nonce request/reply/ACK clock bridge. The JVM samples FE/BE CPU before a
   500 ms lead-in, then runs all warmup arrivals. Poll with `check()` until
   `measurement-ready.json`, then call `release_measurement()`. The JVM again
   retains its actual CPU lead-in and uses an independent measurement epoch.
5. Poll boundedly through `measurement-end.json` and call `finish()`. It can
   also wait for the full remaining window using the supplied whole deadline.
   On controller failure, write the owned `stop` marker before `finish()`.
   Always finish in `finally`; do not abandon a live helper or stop the observer
   until its last CPU samples are covered. Final source verification and owned
   DROP follow the actual parent wait. Preserve nonzero exit/unknown DDL and
   partial raw receipts; no successful subset is eligible.

The whole deadline must cover preparation, preflight, both coordination gates,
warmup, measurement, bounded drain, Java cleanup and final SQL verification.
The existing supplied SQL executor must enforce its own remaining deadline.
Repeated windows use new owned directories/tokens and do not overlap.

## Path evidence outside measured requests

Before warmup, use the actual fixed query and full result oracle, then obtain
`SELECT last_query_id()` on that same connection with no intervening SQL. Fetch
the real FE Profile and run `EXPLAIN PHYSICAL PLAN` for that query. Cold must show
`Is Cached: No` without PhysicalSqlCache; hot must show `Is Cached: Yes` and
PhysicalSqlCache. This requires an actual warm cache in the preflight session.
Its temporary `enable_profile=true` does not change the performance sessions,
which explicitly set `enable_profile=false`.

The preflight proof contains status VERIFIED, kind cold/hot, auditor reference,
FE artifact reference, FE/BE `service_start_ticks`, actual controller
`completed_monotonic_ns`, and references `query_receipt`, `profile_text`,
`explain_receipt`, `session_receipt`. Query format is the existing `executeAndIdentify` receipt
(including SQL SHA and all 33 columns/values); explain format is
`{sql: "EXPLAIN PHYSICAL PLAN <fixed query>", rows: [<actual plan lines>]}`.
Completion must be between launch and the conservatively mapped warmup start.
The session receipt must contain the actual `reader_user`, `current_user`
(`'user'@'host'` or `user@host`), `current_catalog=internal`,
`current_database=license_perf`, positive integer `connection_id` and `settings`
with boolean `enable_sql_cache`, `enable_query_cache`,
`enable_short_circuit_query`, `enable_profile`. Query receipt carries that same
actual server connection ID. Capture identity/settings on the same connection
before the target query, and retain the actual session SELECT receipt through
the trusted preflight auditor. Only enable_profile differs from the timed
session. User/host must equal the frozen reader; an administrator's hot cache
does not prove another reader's cache path because user/catalog/database are
part of the cache key.
Use one trustworthy actual preflight executor and bind its source as auditor;
a caller-supplied VERIFIED label is not a substitute for raw Profile/query data.

No measured request executes query-ID SQL, EXPLAIN or a Profile fetch. Full JDBC
fetch and all 33 online comparisons remain within request timing. Cold connect,
SET and close costs remain included. Hot worker setup remains outside warmup
and has individual raw receipts. The t180 administrator ALTER and following
SHOW CREATE inspection remain in total FE CPU. All original/new integer values
are independently checked again: finished before DDL requires old values;
started after ACK requires new values; overlapping execution permits one whole
old or new result, never a mixture. No snapshot time is inferred. This window
proves correct invalidation results; it does not claim a new post-DDL Profile
proves cache reconstruction in every performance window.

## Independent normalization

`complex_performance.py normalize --input manifest.json --output audit.json`
requires `window_directory`, `launch`, `completion`, `path_preflight`,
`resources`, `license_state`. Output must be outside the raw directory.
External resource/state proof schemas match the other P4 adapters: status,
kind, actual launch SHA/boot, conservative start/end coverage, auditor and raw
artifact references. Resources additionally require actual role/artifact/PID/
generation pins, declared-budget verification and no failures. State must be
ORIGINAL_A_NO_LICENSE for A or VALID for B. Coverage includes CPU samples before
the 500 ms lead-in and the actual final CPU samples, not merely scheduled
arrivals. These are outputs from the actual existing observation/audit tools,
not manually asserted booleans.

The auditor rereads every raw intent/terminal, exact arrival array, complete
result and event, actual CPU boundary, worker setup, source/view ownership,
helper command/lifetime, runtime/dependencies/classes and cleanup. One actual
OWNED_PARENT_WAIT for the complex helper is required. Original bridge bounds
must meet the predeclared limit. The causal helper-finished -> parent-wait
constraint may narrow the offset interval by intersection; original mapping,
wait and effective mapping remain visible. Empty intersections fail. JVM CPU
and latency differences never use this interprocess mapping.

The normalized window uses the shared `p4_statistics` schema and retains all
unique raw and shared dependency references. All files are rehashed after
auditing. Success throughput divides complete queries by the actual interval
including drain; P95/P99 include queue latency, with service and queue
percentiles also reported. CPU is actual FE/BE total seconds per successful
query, including measurement overhead and DDL. No cost is subtracted.
Diagnostic status is DIAGNOSTIC_VERIFIED_NOT_QUALIFIED and
`formal_performance_pass` is always false here. Only the shared capacity/A/A/
published A/B workflow can award formal performance qualification.

## Offline checks

Run on the controller-approved offline CPU:

```sh
taskset -c 4 python3 -m unittest discover -s tools/license-checks -p 'test_complex*.py' -v
```

Set `MASSDB_COMPLEX_TEST_JAVA_HOME` to the exact JDK 17.0.4 installation and
`MASSDB_COMPLEX_TEST_CLASSPATH` to the packaged MariaDB/Jackson jars to enable
the Java proxy test. It compiles the actual two Java files and exercises their
target fetch, preserved legacy query-ID behavior and exact performance session
settings through local JDBC proxies. It never connects to a database. Synthetic
normalization fixtures are explicitly invented offline data for rejection
tests, not real performance evidence. Real single-window integration, capacity,
A/A and A/B remain separate controller-owned work.
