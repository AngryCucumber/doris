<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# G4 continuous DML window

`dml_performance.py` and `LicenseDmlPerformance.java` add one actual G4 window
for `insert_select`, `update`, or `delete`. A window selects exactly one operation
and either 1 or 8 reused JDBC worker connections. Each operation changes exactly
100 independently reserved rows. This does not replace the existing LP015
BEGIN/COMMIT/ROLLBACK functional fixture or claim that explicit transactions ran
inside these standalone DML windows.

The Python adapter inherits the existing `Background` owned launch, process
identity, bounded wait, RSS/affinity checks and parent-reap logic. The Java helper
uses the existing ownership pattern: an acknowledged CREATE, its configuration
hash, complete schema hash and actual tablet IDs are required before DROP. A
CREATE with uncertain ownership remains a manual-cleanup failure. It never adopts
an existing table merely because its name matches. Cleanup-only recovery uses the
same ownership checks; recovering cleanup cannot convert a failed window into PASS.

## Input, data and resource bounds

Use the exact profile schema accepted by `validate_config` and illustrated by
`profile()` in `test_dml_performance.py`. That example is diagnostic and uses a
synthetic storage path; the controller must supply the real owned storage paths,
accounts, timeouts and budgets before calling `freeze`.

- `profile=g4_dml_v1`, `schema_version=1`, `seed=20260922`,
  `rows_per_operation=100`, `concurrency=1|8`.
- `operation=insert_select|update|delete`, `license_state=VALID|EXPIRED`.
  The state describes the requested B treatment. Original A has no license state;
  its actual observation must be `ORIGINAL_A_NO_LICENSE`.
- Formal windows require at least 180 seconds of warmup and 600 seconds of
  measurement. Explicit `qualification=diagnostic` allows shorter windows and
  remains ineligible. Neither the helper nor adapter grants performance approval.
- Finite total `rate_per_second` in `(0,1000]`; Poisson arrivals use Java
  `Random(20260922)`/`StrictMath.log`, independently regenerated in Python with
  a fixed 1 ns rounding tolerance. Each phase resets the same fixed seed.
  Complete warmup and measurement arrival files are saved before any SQL.
- Explicit `max_requests` caps **warmup plus measurement**, at most 500000;
  `max_rows >= max_requests*100`, at most 50000000. Expected total arrivals must
  stay below 95% of the request cap, and generated arrivals still face the hard
  cap. Exceeding it fails before preparing data; no arrivals are dropped.
- `min_disk_free_bytes` must reserve at least `max_rows*1024 + 1 GiB`, with
  a hard upper bound of 1 TiB. Every configured owned storage directory is
  checked before preparation and approximately once per second while timing.
  The 1024-byte-per-row amount is a conservative admission budget, not a claim
  about physical compression or compaction size. Actual free space must continue
  to exceed the frozen floor. Client heap is fixed at 512 MiB; inherited live RSS
  and CPU-affinity enforcement use the controller's predeclared budget.
- `SHOW DATA` in the JDBC-selected `license_perf` database is read outside timing. Its rounded remaining
  quota is converted to a conservative lower bound (subtract one displayed
  0.001 unit); it must cover the generated row budget, and at least 16 replicas
  must remain available. The tool does not increase database quotas or disks.
  Root must also provide actual resource-observer evidence for server/client
  limits, disk, memory pressure and relevant failures. Resource failures cannot
  establish a product throughput or latency result.

Every generated request, including warmup, receives its own 100-row interval.
Measurement domains start after the entire warmup domain range. There are no
empty UPDATE/DELETE loops, row reuse, write retries or replays.

The target uses the proven LP015 UNIQUE KEY/MOW schema with 16 buckets and one
replica. UPDATE/DELETE preparation fills **all** request domains in bounded
10000-row chunks, using the original deterministic value model:
`grp=id%1024`, `v=id%100000`, `payload=MD5(decimal id)`.
INSERT SELECT reads the fixed 100 source rows from `license_perf.point_rows`,
projects their IDs into that request's unique range, and computes the same values.
UPDATE adds 1000000 to `v` and prefixes payload with `u_`; DELETE removes the full
range. SQL construction, dispatch, ACK inspection and transaction validation are
inside each request's measured service interval.

Original successful MySQL OK information is retained as bounded Base64 bytes,
not reconstructed from later state. The independent auditor parses its unique
`txnId`, label and `VISIBLE|COMMITTED` status, checks affected rows equal 100 and
rejects duplicate transaction IDs or labels across warmup and measurement.
A returned but invalid ACK remains `ACK_INVALID`. An exception after submission
without a returned ACK remains `UNKNOWN`, even if final rows show it committed.
Error output never copies JDBC exception messages or credentials.

## Controller lifecycle

The driver does not import certificates or change FE/BE protocols. Preparation
and final oracle SELECTs require a valid certificate. Root controls transitions:

1. Freeze the workload, exact JDK 17.0.4, MySQL Connector/J 8.0.33, packaged
   Jackson dependencies and helper sources with `freeze(api, input_path,
   cluster, resources, driver)`. The read-only driver may be the existing Maven
   artifact; it is hashed and remains fixed for A and B. Supply this frozen
   record as `plan["dml"]`, plus the existing controller resource/output fields.
2. Create a launch record **before** helper launch, then construct
   `DmlPerformance(api, plan, guard, target, cell, admin, whole_deadline,
   cpu_services={"fe":pin,"be":pin}, launch=record)`.
   CPU services must be actual distinct members of the pinned cluster.
3. `start()` compiles the fixed helper, binds its actual command/PID/lifetime,
   fully verifies the million-row source, creates and verifies the entire target
   input, and opens all worker connections. `ready.json` proves preparation;
   it does not start warmup. For EXPIRED, prepare while VALID and allow expiration
   before releasing warmup. The whole deadline must cover full data preparation,
   all phases, the external certificate transition, final oracle and cleanup.
4. `release_warmup()` performs the controller-request/JVM-sample/reply/ack clock
   handshake. The observed controller interval bounds the JVM sample; no global
   equality between Python monotonic and `System.nanoTime()` is assumed.
   The helper starts warmup only after acknowledgement.
5. Root waits for actual `measurement-ready.json`, whose warmup start/end cover
   all warmup requests and drain. `release_measurement()` then releases the
   measurement phase. Separate raw files retain every scheduled completion,
   its original outcome, queue/service/end-to-end timing and transaction receipt.
   Main-thread monitoring samples storage; no extra oracle SELECTs run in either
   timed phase. CPU samples from the same JVM enclose each actual interval,
   including a reported 500 ms leading preparation region and all request drain.
6. After `measurement-end.json`, workers close. `verification-ready.json` proves
   quiescence. Root restores VALID outside timing if needed, then calls
   `allow_verification()`. The helper rereads all source and target values with
   strict keyset pagination and checks every request's entire domain.
7. `finish()` requires actual parent wait and records `p4-completion.json`, then
   handles bounded ownership-checked recovery if necessary. `RAW_WINDOW_COMPLETE`
   means the lifecycle completed; it does not mean performance passed.

The controller must finish one window, including verification and actual child
exit, before preparing the next window. Preparation and final oracle SQL can
affect FE/BE load even though they are outside this window's measurement. This
single-window adapter does not schedule overlapping windows or approve overlap.

The final per-domain resolution can describe UNKNOWN as observed committed or
not committed; it never changes the original request receipt or treats absence
as rollback proof. Full-value verification checks all IDs, counts, NULL/type
constraints, deterministic columns and SHA-256. This is a post-window visibility
check, not an online write-to-visible latency measurement.

## Evidence and statistics interface

A launch contains `schema_version=1`, a unique 32-hex `launch_token`, `window_id`,
`pair_id`, `phase=CAPACITY|AA|AB|DIAGNOSTIC`, `variant=A|B`, actual `boot_id`,
`created_monotonic_ns`, bounded `utc_anchor`, `max_clock_uncertainty_ns`, the exact
P4 `identity`, `workload={path,sha256}`, `service_start_ticks={fe,be}`, and bindings
for `runner`, `java_helper`, `process_lifecycle`, `clock_adapter`, `statistics`,
`jdbc_driver`, `fe_artifact`, `be_artifact`, `environment`, `configuration`,
`fixture`, and `client`. Bindings are actual absolute-path/hash references.
A CAPACITY or AA launch must use A. AB additionally requires the eligible
`freeze` and its independent `publication` references, already published before
launch and before the conservative lower bound of warmup.

The business workload digest includes operation, concurrency, SQL/model semantics,
worker accounts, fixed client behavior and resource/data caps. Offered rate,
durations and license treatment are separately bound; they do not silently change
that business identity. Warmup/measurement schedule digests, requested rate and
actual duration remain exact per-window bindings. The normalizer returns the same
`p4_statistics` window schema as JDBC G1/G2, including actual warmup/measurement
boundaries, bounded clock mapping, five primary metrics, cleanup and oracle proofs.
It supports capacity, A/A and A/B evidence. A/B freeze/publication hashes remain in
each normalized window, not just an aggregate report.

Call `normalize` with a manifest containing `window_directory`, `launch`,
`completion`, `resources`, and `license_state` references. The latter two are
**required independent observer audits**, provided by root's actual run controller.
They are not produced by filling out this driver with assumed values. Each needs:

- `status=VERIFIED`, `kind=resources|license_state`, this `launch_sha256`, same boot,
  actual enclosing `coverage_start_monotonic_ns` and `coverage_end_monotonic_ns`;
- an `auditor={path,sha256}` identifying the observer implementation and nonempty
  `raw_artifacts` references containing that window's actual observations;
- resource audit: `budget_verified=true`, `resource_failures=[]` after independently
  applying all frozen resource limits; `services={fe:{pid,start_ticks,artifact},
  be:{pid,start_ticks,artifact}}` binds the actually deployed process lifetimes and
  artifact references to the launch. Root's guard and observer must prove these
  from the owned installation; supplying a candidate file alone cannot relabel A
  as B. The old UI `Guard` rejects B by design, so the caller must use a guard
  that checks the selected deployment and its original or candidate artifacts;
- license-state audit: `observed_state=VALID|EXPIRED` for B or
  `ORIGINAL_A_NO_LICENSE` for original A, established from actual observations.

Missing observations, external resource failures, wrong state, failed warmup,
UNKNOWN/invalid/missing operations, non-100-row ACKs, changed artifacts, missing
actual child wait or cleanup, and incomplete clock bounds reject normalization.
No completion time is fabricated from file modification times. Raw artifacts,
compiled/runtime bindings, observer data and source references are all retained;
shared inputs are dependencies, and each window's raw evidence is unique.

The normalizer independently rederives throughput including drain, E2E P95/P99,
service/queue quantiles, and FE/BE CPU per successful request. A window with fewer
than 10000 measured successes cannot qualify formal P99. Root still must execute
and validate A-only capacity, required rates and pairs, A/A precision, frozen
balanced A/B order, SLOs, resource observations and confidence intervals. The
one-window audit always leaves `formal_performance_pass=false`.
An explicit diagnostic profile or diagnostic launch additionally returns
`DIAGNOSTIC_VERIFIED_NOT_QUALIFIED`; the statistics layer requires `VERIFIED` and
cannot silently promote that evidence even if the diagnostic was long enough.

## Offline checks

```bash
taskset -c 4 python3 -B -m unittest discover -s tools/license-checks -p test_dml_performance.py -v
```

The tests contain explicitly synthetic protocol/observer/bytecode fixtures and do
not qualify actual performance. Actual Java `CONFIG --plan-only` computes both
schedules and request-domain bounds without JDBC, workers, CREATE or a browser.
Use an explicit private output and launch token; do not execute normal Java mode
just to inspect a plan. The root controller schedules live smoke and real windows.

Preparation, verification and cleanup failures preserve a fixed stage identifier and exception class. SQL failures additionally retain a bounded SQLState and numeric vendor code. Exception messages, causes, SQL text and credentials are excluded. The first real diagnostic preparation rejected the prior `SHOW DATA FROM license_perf` statement because `FROM` selects a table; its failed receipt and executed source remain archived.

The clock auditor first enforces the original bounded bridge and its declared
uncertainty limit. It then intersects that interval with the causal upper bound
from the same helper publishing its ordered measurement/verification/cleanup
receipts before its unique successful parent wait. Missing wait time, foreign
helper/lifetime, reordered JVM events or an empty intersection reject the window.
Both the original interval and wait constraint remain in the audit; raw completion
times, request elapsed times and CPU deltas are never rewritten or padded.

The frozen business hash includes the drain budget. A/B launch checks additionally
require the published cell's `license_state` to equal the requested VALID or
EXPIRED profile; actual state observation is still required independently.
