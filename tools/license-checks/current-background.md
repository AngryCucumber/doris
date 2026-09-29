<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# Current G5/G6/G7 allowed-business background

The explicit `current_allowed_business_v1` profile in `ui_background_fixture.py`
and `LicenseUiBackground.java` provides the current P0 background. The old
profile without this field keeps its point-read/write, 300-second behavior,
visibility checks and browser coordination. It is not silently relabelled G5.

The new profile has exactly sixteen reused JDBC worker connections: eight
metadata and eight write workers. A single seed-20260922 Java Random / StrictMath
Poisson stream describes the total offered rate. Even arrivals are writes and
odd arrivals are metadata. If the generated count is odd, the final arrival is
not scheduled: the complete generated stream is retained in `total-arrivals.tsv`
and generated/scheduled/tail counts are reported separately. The resulting
scheduled counts are exactly 50%/50%. This predetermined tail rule is not an
error omission or measured-result filtering. Python independently regenerates
the stream and checks Java offsets with a fixed 1 ns rounding tolerance.

Each INSERT has exactly 100 rows in a disjoint interval beginning at
`1000000000 + request_index * 100`. Every column uses the independent original
million-row model: `grp=id%1024`, `v=id%100000`, `payload=MD5(decimal id)`.
SQL construction and result checking are inside request timing. There are no
write retries. Original ACK, UNKNOWN, ERROR and NOT_SENT receipts remain intact
when later visibility inspection discovers committed rows.

Metadata rotates through `SELECT 1`, `SHOW TABLES FROM license_perf`, and
`DESC license_perf.point_rows`. The controller supplies complete, independently
reviewed column labels and row values in `metadata_oracles`; the helper never
learns expected values from its first response. SHOW TABLES uses the exact full
set after creation, including `point_rows` and `${OWNED_TABLE}`. This token is
replaced only in expected row values by the unique table's unqualified name;
the resulting expected matrix is saved before SQL. SHOW TABLES rows are sorted
by table name without removing duplicates. All DESC columns/rows, SQL NULLs,
SELECT's single value, result lengths and column labels are checked. Successful
metadata receipts include a canonical full-result SHA-256 checked independently
by the Python auditor. All three metadata queries are also executed outside
timing after target creation, before the helper declares readiness.

## Explicit profile and standalone adapter

Use `validate_current_config` (also dispatched by `validate_config`) and `freeze`
with a controller-owned plan. Do not use the old 54-window browser planner.
The root controller is responsible for exact package/environment/data bindings,
accounts and grants, source fixture preparation, A-only capacity, A/A and A/B
ordering, required resource observations and actual process exit/cleanup.
`CurrentBackground` is a thin subclass of the existing owned lifecycle; its
constructor additionally takes `cpu_services={"fe":pin,"be":pin}`. Both service
pins must be distinct, alive and members of the already frozen cluster pins.

Its independently frozen client dependency set is reused on A and B; it does
not automatically adopt a candidate FE's classpath. The package supplied to
`freeze` selects this client dependency set. No browser object or browser receipt
is required by `CurrentBackground`.

New profile fields replace the old independent read/write rates and online
visibility settings:

- `schema_version=1`, `profile=current_allowed_business_v1`, `group=G5|G6|G7`.
- `qualification=formal|diagnostic`. Formal G5/G6 duration is at least 600 seconds;
  G7 at least 300. Explicit diagnostics may be shorter, remain ineligible, and
  cannot replace formal windows.
- `duration_seconds` up to 7200, `rate_per_second` is a finite total offered rate
  in `(0,1000]`, including decimal capacity fractions.
- `seed=20260922`, `read_workers=8`, `write_workers=8`, `write_batch_rows=100`.
- `rate_basis=controller_frozen_input_not_capacity_qualification`.
- `metadata_oracles`: three `{sql,columns,rows}` objects, in the fixed SQL order;
  expected fields are strings or null. DESC contains the four source columns
  `id/grp/v/payload` with every displayed field. Root must freeze the actual
  schema before timing; the example in the offline tests is synthetic.
- Existing `read_account`/`write_account` use distinct username/password-env
  references. Oracle ADMIN credentials are passed separately through the existing
  environment mechanism. No literal passwords are accepted in this profile.
- Existing time bounds remain explicit: `timeout_seconds`, `drain_seconds`,
  `prepare_timeout_seconds`, `verify_timeout_seconds`, `cleanup_timeout_seconds`,
  `read_slo_millis`, `write_ack_slo_millis`. In the current profile these latency
  values are reported per-request checks; a single outlier does not replace the
  formal P95/P99/window SLO decision with the legacy all-requests limit.

The generated schedule has a one-million-operation bound. Expected count must
be below 950000 before launch. Exceeding the actual bound fails preparation;
there is no silent truncation other than the explicit final odd arrival.
The outside deadline must cover compilation, full source checks, preparation,
measurement/drain, verification release, full target checks and cleanup.

## Run protocol and certificate transitions

1. `CurrentBackground.start()` compiles the exact helper, validates actual process
   identity, verifies all million source rows, creates one owned empty target,
   checks metadata oracles, opens all sixteen worker connections, and waits for
   actual `ready.json`. It does not start traffic automatically. Preparation includes
   full business-data reads outside timing and must run with a valid certificate.
   For an EXPIRED/G6 window, prepare first, then let the certificate expire before
   releasing the timed window; do not try to prepare through a denied data state.
2. `release()` writes this token's `release.json`. Java samples FE/BE CPU from
   `/proc` in the same JVM time domain used by every raw request, selects a
   500 ms future epoch, writes `window-start.json`, and releases the workers.
   The actual CPU sample start/end and its leading/trailing enclosure are retained;
   the 500 ms leading region is not claimed to be a zero-width boundary.
3. `window-end.json` marks the scheduled end only. It does not prove outstanding
   operations have drained. `measurement-end.json` binds the actual last request
   and enclosing FE/BE CPU samples; `verification-ready.json` additionally proves
   workers have quiesced. The controller must use these actual receipts when
   relating Java to Node clocks or determining background/UI overlap.
4. Current-profile timed traffic contains only allowed writes and metadata.
   There are no point queries or online visibility SELECTs. This remains true
   during EXPIRED and other denied data-query states.
5. After the window, root may restore a valid certificate outside timing, then
   call `allow_verification()`. Only this creates `verify-release.json`; the helper
   does not renew a certificate itself or exempt an oracle user. It then verifies
   all source and target rows, every 100-row domain, and ACK/UNKNOWN resolution,
   and performs the original ownership-checked DROP cleanup.
6. `finish()` waits for actual child exit, rechecks source/dependencies/service
   identity, performs independent Python request/CPU/full-model audits, and uses
   the original bounded owned recovery if necessary. No browser overlap is claimed
   for this standalone adapter. On failure, keep raw receipts and cleanup status;
   do not turn an observed UNKNOWN into an ACK or infer rollback from absent rows.

Post-window visibility establishes the final full-value model. It does **not**
measure online write-to-visible latency, and no such latency is fabricated from
verification time. If root does not release verification, the bounded phase fails;
cleanup still follows the existing exact ownership policy. Complete business
correctness requires both request and full-model audits, not just affected rows.

The current raw auditor returns separate metadata/write counts, successful
latencies, successful QPS including drain, and end-to-end/service/queue P95/P99
for each stream. Both streams use the same actual complete request interval;
service is `finished-started`, queue is `started-scheduled`, and end-to-end is
`finished-scheduled`. Original per-request timing remains in the raw TSV files.
Combined QPS and latency are additional summaries and cannot replace separate
metadata/write assessment. The P99 sample floor is reported for each stream as
well as the combined count; a diagnostics window or fewer than 10000 successful
samples of the assessed stream cannot qualify its formal P99. FE/BE CPU deltas
and enclosure sizes describe the complete mixed workload and are never allocated
to individual request types. The auditor explicitly leaves
`formal_performance_pass=false`.
The statistics/controller layers must additionally prove capacity, frozen rates,
independent pair ordering, process/clock identity, full required resources,
confidence and detection precision.

## Offline validation

The Python suite covers both the original profile and current-profile corruption
cases. Use the controller-assigned offline CPU (currently CPU 4 during the
root-owned performance run):

```bash
taskset -c 4 python3 -B -m unittest discover -s tools/license-checks -p test_ui_background_fixture.py -v
```

The exact JDK 17.0.4 helper can execute `LicenseUiBackground CONFIG --plan-only`
for the current profile. This computes/saves arrival streams and metadata expected
matrices without opening any JDBC connection, creating a table, or starting workers.
Its result is `PLANNED_NOT_RUN`. Use a fresh private directory and explicit config;
never call normal execution merely to inspect a plan. Cross-language schedule
checks are recorded separately from actual database acceptance.
