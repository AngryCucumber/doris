# Current G4 Stream Load window

`stream_load_baseline.py --profile current-g4` is an opt-in single-window
adapter. The default `legacy-lp012` plan/probe interface and historical results
keep their original meaning. Current G4 supports 1/8 workers, 1000/10000 rows
per batch, a frozen positive fractional rate in **batches/second**, and the
existing FE307→BE200 protocol with a new connection for each hop. There are no
request retries. It does not choose capacity or run its own AA/AB comparison loop.

The existing transport bounds, 60-second scheduled-arrival deadline (including
queue), 60-second server timeout, 65-second drain bound, unknown-transaction
tracking, exact label/row-count/TxnId receipts, ownership checks, and cleanup
remain. This deadline differs from the HTTP Query/JDBC dispatch timeout; freeze
each protocol's actual semantics separately.

## Plan inputs

Supply `--context`, `--cluster-record`, `--input`, `--output`, `--cpu`,
`--jdk-runtime-version`, `--user`, and `--password-env`. Paths must belong to the
checkout's `.build-records`; use a new output directory each time. Passwords stay
in the named `MASSDB_STREAM_*_PASSWORD` environment variable. Never place a
certificate or credential in context JSON.

The context contains:

```json
{
  "group": "G4", "seed": 20260922,
  "phase": "DIAGNOSTIC", "variant": "A", "license_state": "VALID",
  "cell_id": "G4-stream-c1-b1000", "window_id": "G4-stream-smoke-a-0", "pair_id": 0,
  "concurrency": 1, "batch_rows": 1000,
  "connection_mode": "stream_load_two_hop_close", "rate": 3.5,
  "warmup_seconds": 2, "duration_seconds": 5, "barrier_timeout_seconds": 600,
  "identity": "replace with the seven-field P4 source/build/environment/configuration/fixture/client identity",
  "business_workload_sha256": "compute from g4_business_binding(context, g4_input_binding(input_path))"
}
```

Replace the explanatory `identity` value with the real P4 object.
`phase=AA` requires variant A; `phase=AB` accepts A/B and requires `freeze`, an
absolute path to an eligible same-boot P4 freeze plus its `.published.json`.
Formal phases require `identity_bindings` containing actual absolute path/SHA
references for `environment`, `configuration`, `fixture`, and `client`, matching
the identity digests. The frozen cell must also contain `license_state` and
`batch_rows`, besides the common P4 rate/duration/business/arrival fields.

The business hash includes input SHA, batch size, concurrency, payload/target
model, transport and timeout policies, and the seeded arrival algorithm. It
excludes variant, certificate state, rate, and duration: those are independently
bound by the cell, context, actual phase, and state observations. Identical A
write flow can support separate VALID/EXPIRED comparisons through the outer
controller's explicitly declared baseline cell, using new independent windows.

The existing Java `--schedule-only` generator supplies seeded Poisson arrivals.
Formal minimums are 180 seconds warmup, 600 seconds measurement, and **10000
successful batch operations** per measured window. Inspect actual generated
counts and extend duration before execution when necessary; no silent replay or
sample waiver is available. Each phase is bounded at 100000 planned requests and
14400 seconds. Diagnostic mode may use smaller windows/data; its evidence can
never qualify as formal.

## One input, bounded slices

Current mode uses one immutable, hashed input file plus its usual LP-012 JSON
manifest. `prepare_g4_batches` independently checks every row/column/byte of that
file outside timing, then stores only offset/size/hash descriptors. Every active
request uses bounded `pread`, at most 1.28 MB for a 10000-row batch. No complete
second set of batch files is created. Measurement request `i` consumes the
unique IDs `[i*batch_rows, (i+1)*batch_rows)` once. A separate warmup table may use
the same input prefix. Additional unused input rows are still model-checked;
one sufficiently large frozen input can serve multiple predeclared rates.

The input must cover the larger generated phase count. A 10000-row batch formal
window needs at least 100 million measured rows /12.8 GB input; Poisson count may
require more. Generate only after root has frozen the actual counts and checked
space for input, DB storage and evidence. The explicit generator reuses the
existing formula, refuses overwrites, and checks input bytes plus 512 MiB free
evidence reserve; this reserve is **not** a promise of sufficient DB storage:

```bash
python3 tools/license-checks/stream_load_baseline.py --profile current-g4 \
  --mode generate-input --input "$NEW_INPUT_FILE" --rows "$EXPLICIT_ROW_COUNT"
```

Plan first; probe only when no other benchmark is active and inside the owned
private network namespace:

```bash
python3 tools/license-checks/stream_load_baseline.py --profile current-g4 \
  --mode plan --context "$CONTEXT_FILE" --cluster-record "$CLUSTER_RECORD" \
  --input "$INPUT_FILE" --output "$NEW_OUTPUT_DIRECTORY" --cpu "$CLIENT_CPU" \
  --user root --password-env MASSDB_STREAM_ADMIN_PASSWORD

python3 tools/license-checks/stream_load_baseline.py --profile current-g4 \
  --mode probe --plan "$NEW_OUTPUT_DIRECTORY/plan.json"
```

## External state and observer barriers

B must begin probe with a usable certificate so setup/empty-target SELECTs can
finish. The tool does not import certificates or change clocks.

1. After setup, the tool writes `g4-state-ready.json`. The controller arranges
   the requested stable VALID or naturally EXPIRED state, starts the existing
   `resource_observer.py`, and copies its actual initial RUNNING summary to an
   immutable launch snapshot. It atomically writes `g4-state-ack.json` by copying
   every ready field unchanged, adding `acknowledged_monotonic_ns` and
   `observer_launch: {path, sha256}`. Fresh nonce, plan SHA, boot and bounded time
   must match. No state is inferred from this acknowledgement: the tool then
   executes and archives actual `SHOW LICENSE` outside the timed window.
2. Warmup and measurement run without an intervening business SELECT. After
   their final completions, another actual `SHOW LICENSE` must prove the same
   certificate, applied version, clock epoch and no pending slot. VALID accepts
   both actual VALID and EXPIRING while trusted time remains before expiry;
   EXPIRED requires trusted time at/after expiry. Original A explicitly records
   `ORIGINAL_A_NO_LICENSE`, not a fabricated certificate state.
3. The tool writes `g4-oracle-ready.json`. The controller waits for an observer
   sample covering final completion, stops/joins the observer, restores B to a
   usable certificate, and atomically writes the matching `g4-oracle-ack.json`,
   adding final `observer_summary` and `observer_samples` path/SHA references.
   The tool verifies restoration with actual SHOW LICENSE, then checks both
   tables' complete IDs/columns and total/distinct row count. Group results are
   paged to keep helper output bounded. These are post-window visibility upper
   bounds, not actual commit-latency measurements.

Formal windows fail without the real observer launch/summary/raw samples.
The audit checks source and service pins, raw sample coverage from warmup through
drain, no observation errors or skipped slots, and unchanged collector settings.
No duplicate background metrics scraper is started by this profile. Synchronous
CPU/RSS boundaries and the existing helper resource guard are retained. Minimal
observer coverage does not imply total allocation or per-process network data.
Diagnostic mode may explicitly omit the observer and is labelled accordingly.

## Evidence and qualification

CPU counters bracket each actual request interval before worker cleanup and raw
serialization. Throughput includes drain; P95/P99 include queue from planned
arrival. Errors, timeouts, unsent and unknown commits remain in raw requests and
phase statistics even when a phase fails. Local cleanup never converts an
unknown server transaction into a proved abort.

`g4_audit_window` independently rechecks input slices, every original BE receipt,
unique label/TxnId, arrivals, deadlines, source state SQL, full visibility SQL,
CPU lifetime/boundaries, observer coverage and cleanup. It emits `g4-audit.json`
and the common P4 `g4-window.json` with exact Python monotonic clock domain.
DIAGNOSTIC_VERIFIED or VERIFIED indicates raw verification only;
`formal_performance_pass` remains false. The outer controller still supplies
confirmed A capacity, independent AA/AB pairs, and fixed statistical gates.
Any resource/input/sample/oracle failure is invalid evidence, not a waiver.

Offline checks (no real HTTP/database requests or large input generation):

```bash
taskset -c 4 python3 -m unittest discover -s tools/license-checks \
  -p 'test_stream_load*.py' -v
```
