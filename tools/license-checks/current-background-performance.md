<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# Current allowed-business P4 participant

`current_background_performance.py` supplies one G5/G6/G7 business window around the existing `CurrentBackground`. It retains 8 persistent metadata workers and 8 persistent write workers, the seeded alternating 50/50 arrival schedule, 100-row unique write batches, complete metadata values/columns, and independent complete source/target value models. It does not start services, provision accounts, import licenses, alter time, create an observer, or qualify an entire event/UI group.

The opt-in Java handshake is required for this adapter. Legacy `ui_background_fixture.py` callers and historical receipts retain their existing behavior. Root reviewed and applied the optional `LicenseUiBackground.java` patch after preserving the earlier execution source. The original/staged copies, application receipt and offline evidence remain under `.build-records/license-p4-20260929/current-background/p4-adapter-v1/`. The adapter explicitly refuses an unpatched helper. Shared Python remains unchanged.

## Workload and frozen context

The workload is the existing `current_allowed_business_v1` JSON, validated by `validate_current_config`. Groups G5/G6 require at least 600 measured seconds; G7 requires 300. There is no added warmup phase. Formal windows require **at least 10,000 planned and successful operations in each stream**, not 10,000 combined and not written row counts. Low-rate windows must be extended within the existing bounded duration. A diagnostic profile never becomes qualified through normalization.

`plan(profile)` returns the independent seed-20260922 Poisson reference, its reference SHA, the equal split and explicitly discarded odd tail. Decimal rates are preserved. Python `math.log` and Java `StrictMath.log` can differ by 1 ns: the Python reference SHA is **not** an execution freeze. Formal contexts bind `arrival_schedule={path,sha256}` to the actual helper’s offline `--plan-only` `total-arrivals.tsv`; the adapter checks every offset against the independent reference within 1 ns, then requires the live Java table to match the frozen actual SHA exactly. Diagnostics may omit this reference and record the actual measured schedule SHA. No arrival algorithm is changed. `business_binding(profile)` includes SQL/oracles, both business accounts, seed, fixed workers/batch size, connection and timeout behavior. It excludes rate, duration, group and diagnostic/formal selection; these are compared separately against the frozen cell. A/B must use identical business accounts and workload. The administrator used only for setup/full verification/owned cleanup is separately bound into the client identity.

The context requires:

- `schema_version=1`, `window_id`, integer `pair_id`, `group`, `phase` (`DIAGNOSTIC`, `CAPACITY`, `AA`, `AB`), `variant` (`A`, `B`). CAPACITY/AA accept only A.
- The seven standard `identity` fields and exact `bindings` for `SOURCES` plus FE/BE artifacts, environment, configuration, fixture and client. `workload` is a path/SHA reference.
- Exact FE/BE `services` pins (`pid`, `start_ticks`, `namespace`, `exe`, `command_sha256`), bound `service_configs`, host namespace, and private local `target={name,host:"127.0.0.1",query_port}`. The guard verifies actual FE entrypoint/classpath/JAR and BE executable; it accepts the explicitly bound candidate B artifact without invoking the original-A-only Guard.
- `runtime={java_home,jars}`: actual JDK 17.0.4 and exactly MariaDB 3.0.9 plus Jackson annotations/core/databind 2.16.0. There is no inherited broad FE classpath. Hidden JVM options/CLASSPATH are rejected. Credentials are environment references only.
- `admin_account={username,host,password_env}`, `resources={cpus,rss_limit_mib,cell_timeout_seconds,whole_timeout_seconds}`, `license_scenario` (`VALID`, `EXPIRED`, `EVENTS`), `coordination_seconds` (1–300), `max_clock_uncertainty_ns` (1–1e9), fresh `context_deadline_monotonic_ns` (at most 300 seconds ahead).
- For AB, pre-existing `freeze` and `publication` references: identity, group, workload, schedule, rate, duration, request count, 16 workers and connection mode `reuse_per_worker_no_replay` must match the frozen cell. Publication precedes launch and is revalidated during normalization.

The frozen client snapshot must contain `runtime(context.runtime)`'s returned actual JDK/JAR digests, exact resources, connection mode, administrator and read/write accounts. The fixture snapshot carries `business_workload_sha256`. Environment contains `runtime_policy={client_cpus,jvm_heap_mib:512}`. Configuration contains the exact service-config references. Endpoint, deployment and source checks do not reread large binaries during every request: immutable stat identities are checked while running; SHA bindings are verified at lifecycle boundaries and again by the independent audit.

## Outer-controller API and state barriers

```python
window = Window(context, output, stop_file=stop_path)
try:
    window.start()                          # compile, full pre-oracle, worker ready, fresh clock handshake
    measurement_proof = on_ready(window)    # caller obtains actual target state/event readiness
    window.release(measurement_proof)
    window.await_quiescence(checkpoint)     # caller may drive scheduled events/UI concurrently
    restored_proof = on_quiescent(window)   # caller obtains actual usable post-window state
    raw = window.finish(restored_proof)     # full source/target verification, owned cleanup, actual parent wait
except BaseException as error:
    if not window.closed:
        window.finish(failure=error)        # own child cleanup does not depend on valid clock/source proof
    raise
```

`run_window(context, output, on_ready, on_quiescent, checkpoint=None, stop_file=None)` performs the same sequence. The adapter does not invent either barrier. Each callback returns a path/SHA reference to a real audited receipt containing `status=VERIFIED`, stage (`READY_FOR_MEASUREMENT` or `READY_FOR_VERIFICATION`), `launch_sha256`, `boot_id`, `observed_monotonic_ns`, `observed_license_state`, `auditor` and nonempty original `raw_artifacts` references. The first proof must follow observed readiness; the second must follow observed worker quiescence. These receipts and actual helper release files are archived and independently checked.

Original A records `ORIGINAL_A_NO_LICENSE`, never a nonexistent license API. Candidate VALID accepts VALID or EXPIRING. Candidate EXPIRED requires actual EXPIRED at release. EVENTS declares an externally audited timeline. A complete business-table oracle SELECT cannot run under an expired candidate license: prepare under a usable license, switch at the first barrier, then restore a usable license **after quiescence** before full post-verification. The post-verification proof requires VALID/EXPIRING for B. Restore/import/time control belongs entirely to the outer authorized controller. The measured metadata/write traffic continues unchanged; source/target oracle SQL remains outside the measured interval.

The Java addition performs a bounded ready-nonce → controller nonce → JVM sample → digest-bound acknowledgment before ordinary readiness. It also records actual MariaDB client/thread IDs before and after each worker's loop, without additional measured SQL or changes to existing per-request timestamp arithmetic. The parent records the original work JVM's actual `wait()` exit, even if failure recovery uses another cleanup-only JVM. Source drift, expiry or malformed clock evidence cannot authorize a successful completion.

## Independent normalization

Pass the returned raw manifest plus an actual `observer` reference to `normalize`. Formal input requires the observer; diagnostic input may omit it. The observer must bind launch/boot, all deployed service pins/artifacts/configurations, nonempty raw evidence, `status=VERIFIED`, `budget_verified=true`, no resource failures, exact license scenario and `actual_state_timeline_verified=true`. Its interval must enclose the conservative mapped **first CPU sample start through last CPU sample end**, including drain. State/event/UI correctness still needs its own outer audit; this boolean cannot replace those original receipts.

Normalization rereads every request ledger, schedule, metadata oracle/hash, complete source/target model, session setting, worker connection receipt, helper class/source binding, actual work-JVM launch/wait and cleanup receipt. Missing/unknown/error outcomes fail; failed raw stays intact. Delays use the original same-JVM scheduled-arrival → completion differences, with service and client queue reported separately. The clock offset is a bounded estimate used for cross-process ordering only; UTC anchors never calculate latency.

The standard `window` contains combined business QPS/P95/P99 and **total FE/BE CPU divided by all successful business operations**. `business_stream_metrics` separately carries metadata and write throughput/P95/P99/service/queue metrics and each stream's 10,000-sample flag. CPU is never apportioned to a stream. Existing SQL/socket timeouts do not include client queue; SQL success alone does not prove a frozen latency/drain SLO. Capacity and A/A/A/B controllers must inspect both streams as required by their declared acceptance conditions. This adapter does not change the shared statistical comparator or claim per-stream comparison from combined percentiles.

`VERIFIED` means one formal-shaped raw window was independently audited. `formal_performance_pass=false` and `group_event_or_ui_qualification=false` always remain: capacity, A/A noise, A/B precision, original state transitions, rejection/management workload and UI behavior remain external requirements. Audits must be written outside the raw directory; preserve failed attempts and never rename old diagnostic raw as formal.

CLI is offline `plan` or `normalize` with `--input/--output`. Live work requires the explicit Python controller API and real barrier callbacks. The helper's `--p4-clock-only` mode is solely an offline no-JDBC handshake check; its receipt cannot be a business window.
