<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# G3 fresh FE plan and original BE scanner window

`external_scanner_performance.py` adds one explicitly scheduled window. Every
operation issues a fresh FE `POST /api/license_perf/point_rows/_query_plan`, reads
all 16 returned tablets through the original BE Thrift scanner, validates the
complete million-row unordered result, and confirms every scanner close.
One complete operation is **one sample**. Batch sizes are 1024/8192 and worker
counts 1/8. No BE code, authentication or protocol is changed.

`LicenseExternalScannerFixture.java` supplies the existing RowSetOracle,
Int64/Utf8 Arrow decoder, offset/EOS checks and Thrift calls through `scanOnce`.
Each worker now supplies its own handle registry. The old Python functional
entry remains unchanged, including its one-plan/four-read matrix. Its original
Java source and SHA `9b355faeba0d8c6fc5fba7f80cdcca7b35ab73fcd9bc464989306b26dbd51473`
are preserved under ignored `g3-scanner/legacy-source-v1`; prior functional
records describe that source, not a retroactive run of the new helper.

## Frozen operation and resource contract

- FE uses an owned loopback HTTP/1.1 client per worker. Automatic retries,
  redirects, proxies and cookies are disabled. Fully consumed responses return
  the connection to that worker's manager. A socket factory records actual
  successful connection generations; a stable client object alone is not
  reported as transport reuse. A server-closed connection may be replaced for
  the next operation. No failed request is replayed.
- Freshness comes from one actual POST receipt per operation. Equal opaque-plan
  hashes do not by themselves prove reuse. Original FE response bodies are
  bounded at 2 MiB and saved only in exclusive **0600** private files. Public
  records contain hash, length, tablet IDs and file references; passwords,
  Authorization, opaque plans and context IDs are never printed. These private
  files must not be published with public reports.
- Thrift remains one read socket per tablet and a separate close socket. The
  unchanged request sets `keep_alive_min=1`, `execution_timeout=60`, memory limit
  256 MiB, and no row limit. Each returned row is checked against its ID/MD5
  formula; a fresh bitmap and 32 MB actual-payload array prove the full set and
  independently expected sorted digest. No counts-only replacement is used.
- The **new harness**, not the original protocol, imposes 120 seconds from
  dispatch through completion. FE has a 15-second total budget and 5-second
  socket bounds; BE open including connection and each getNext have 10-second
  bounds; independent close has a 5-second total budget. Socket/HTTP watchdogs
  stop fragmented reads at their deadlines. Failure cleanup may use a separate
  5 seconds. Queue time is outside the dispatch deadline and fully included in
  end-to-end latency. Late completion is an error, never a successful sample.
- A received context stays registered until close returns OK. A close failure
  or open with no returned context is not cleared as released. Shutdown attempts
  owned closes concurrently; forced exit, missing ACK or unknown open invalidates
  evidence. An elapsed keepalive/server timeout does not prove cleanup.
- The JVM uses 768 MiB heap and 512 MiB maximum direct memory. Oracle arrays and
  Arrow buffers are bounded per active worker; the existing 128 MiB per-operation
  allocator also remains. Original per-batch process guards and full oracle cost
  stay inside service time. No estimated overhead is subtracted. The external
  controller must enforce sampled aggregate RSS/storage budgets with the actual
  observer; JVM limits alone are not a resource qualification.

## Narrow interface

The module exposes `plan(profile)`, `compile_helper(spec, output)`,
`run_window(profile_ref, context, runtime_ref, output, stop_file=None)` and
`normalize(manifest)`. It does not start services, choose capacity, import a
certificate or run an A/A/A/B loop. CLI modes are `plan`, `compile`, `run`,
`normalize`; each accepts `--input JSON --output NEW_PATH`.

Example diagnostic profile (not a capacity or performance pass):

```json
{
  "schema_version": 1, "profile": "g3_scanner_v1", "qualification": "diagnostic",
  "seed": 20260922, "batch_size": 8192, "concurrency": 1, "rate": 0.5,
  "warmup_seconds": 5, "duration_seconds": 10, "drain_seconds": 30,
  "max_requests": 1000, "max_private_plan_bytes": 67108864,
  "max_raw_ledger_bytes": 268435456
}
```

The finite fractional rate is complete operations/second. Java Random seed
20260922 and StrictMath Poisson arrivals are frozen; warmup and measurement each
start that seed. All planned requests remain in the schedule and each terminal
receipt records planned/start/finish, queue/service/end-to-end timing and errors.
Successful QPS uses the complete interval including drain. CPU counters bracket
the same interval. Duration may extend to 86400 seconds and each phase to 25000
requests; storage bounds are explicit. Formal profiles retain >=180 seconds
warmup, >=600 seconds measurement and >=10000 complete successful operations.
Extend the predeclared window/input budget; never count rows/tablets/batches as
operation samples. Errors, missing evidence or exhausted resources invalidate it.

The compile spec is `{java_home, jars}` for the actual JDK17.0.4 and installed
JARs. No dependency is downloaded. Runtime records bind both Java sources,
Python runner/oracle/clock/statistics sources, all JDK components, JARs and classes.

Context requires schema version, phase (`DIAGNOSTIC/CAPACITY/AA/AB`), A/B variant,
window/pair IDs, complete seven-field identity and its actual artifact/snapshot
bindings, profile reference, FE/BE pins and configuration references, endpoints
(`fe_http_port`, `be_port`, `user`, `password_env`), host namespace, coordination
seconds, bounded launch-context deadline and clock uncertainty. A-only phases
reject B. Execute in the owned private namespace. Before warmup, a nonce-bound
handshake maps the actual JVM clock to an explicit conservative Python interval;
it never assumes equal clock epochs. AB also needs an eligible matching freeze
and its same-boot publication, verified before launch/warmup and after execution.
Live validation also checks the owned installation's configuration and artifact
slots, the actual BE executable and FE JDK, and the FE's explicit or environment
classpath. Symlinked installed `lib` directories are checked by file identity.

Normalization input contains `window_directory`, `launch`, `completion`, and
for formal windows `observer`. The latter is an external audit binding raw
observer samples, matching actual FE/BE artifacts/configuration/pins, coverage
through drain, no resource failure and actual `ORIGINAL_A_NO_LICENSE` or usable
B `VALID` state. Root supplies this audit; the tool never invents it. Normalized
output uses the common P4 window/clock/CPU schema and retains all private/raw
references. `VERIFIED` means raw evidence verified; `formal_performance_pass`
always stays false. Diagnostic windows are explicitly ineligible.

Offline checks never contact a service:

```bash
taskset -c 4 python3 -m unittest discover -s tools/license-checks -p 'test_external_scanner*.py' -v
```

The Java helper additionally offers `--self-test OUTPUT` (own JVM clock, registry
and deadline checks on unopened local socket objects; no connections) and
`--plan PROFILE NEW_DIRECTORY` (arrival vectors only).
Run the existing fixture's `--self-test OUTPUT` to retain its ten independent
row-oracle checks. Real A/VALID/EXPIRED checks and capacity/precision remain
separate root-scheduled work.
