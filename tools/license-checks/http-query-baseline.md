# G1 HTTP Query single-window runner

`http_query_baseline.py` executes one G1 HTTP Query window for the external P4
controller. It supports one or sixteen workers, A-only diagnostics, formal A/A
windows, and published-freeze A/B windows. It does not select capacity, an SLO,
pair order, or a performance verdict. In particular, a successful short smoke is
not an A/A precision result.

The endpoint is the existing non-streaming
`POST /api/query/default_cluster/<database>` API. The request sets
`X-Doris-Stream: false`, `Connection: keep-alive`, `is_sync: true`, and a row limit
of 1000. Each request selects exactly one `payload` by an independently generated
key in `0..999999`, from the previously verified million-row point fixture. The
required value is the lowercase MD5 of the ASCII decimal key. The actual HTTP
status must be 200, business code 0, result type `result_set`, exactly one string
cell, and exactly the declared `payload` column/type. Wrong keys, extra rows,
nulls, changed column metadata, HTTP errors, and application errors all fail the
oracle. No fixture setup SQL or license import occurs in this tool.

The current FE `StatementSubmitter` opens and closes a JDBC connection for each
HTTP query. Reusing the HTTP TCP connection therefore does **not** prove reuse of
an FE SQL session or prepared handle. Those are different G1 cells.

## Input and ownership

Inputs and output directories belong to this checkout's ignored `.build-records`.
Run inside the private network namespace recorded in `cluster_record`; literal
FE HTTP/query ports, service roots, PID lifetimes, installed FE JAR, and live BE
executable are checked before requests. The tool never starts or stops services.
`--validate-only` performs these filesystem/identity checks without requests or
compilation. It cannot verify the live HTTP response shape.

Example workload structure (replace placeholders with actual pinned values):

```json
{
  "group": "G1",
  "phase": "DIAGNOSTIC",
  "variant": "A",
  "window_id": "G1-http-c1-smoke-a-0",
  "pair_id": 0,
  "seed": 20260922,
  "connection_mode": "http_keep_alive",
  "concurrency": 1,
  "rate": 5,
  "warmup_seconds": 2,
  "duration_seconds": 5,
  "request_timeout_seconds": 15,
  "query_timeout_seconds": 10,
  "drain_timeout_seconds": 30,
  "database": "license_perf",
  "table": "license_perf.point_rows",
  "expected_column_type": "VARCHAR",
  "http_port": 18030,
  "user": "root",
  "password_env": "MASSDB_HTTP_BASELINE_PASSWORD",
  "cluster_record": "/absolute/owned/.build-records/cluster.json",
  "services": {
    "fe": {"pid": 123, "root": "/absolute/owned/.build-records/installation/fe"},
    "be": {"pid": 456, "root": "/absolute/owned/.build-records/installation/be"}
  },
  "build_identity": {
    "baseline_source_commit": "<actual 40-character source commit of this variant>",
    "fe_artifact": "/absolute/owned/.build-records/installation/fe/lib/doris-fe.jar",
    "be_artifact": "/absolute/owned/.build-records/installation/be/lib/doris_be"
  },
  "identity": {
    "source_commit": "<same actual source commit>",
    "fe_sha256": "<actual installed JAR SHA-256>",
    "be_sha256": "<actual running BE SHA-256>",
    "environment_sha256": "<actual environment snapshot SHA-256>",
    "configuration_sha256": "<actual configuration snapshot SHA-256>",
    "fixture_sha256": "<actual verified fixture snapshot SHA-256>",
    "client_sha256": "<actual client snapshot SHA-256>"
  },
  "business_workload_sha256": "<compute using business_binding below>"
}
```

The historical field name `build_identity.baseline_source_commit` is required by
the reused ownership validator; in an A/B candidate window it must contain the
candidate's actual source commit, equal to `identity.source_commit`.

`phase=AA` and `phase=AB` additionally require `identity_bindings` with exactly
`environment`, `configuration`, `fixture`, and `client`, each an absolute
`{"path": "...", "sha256": "..."}` reference to the corresponding real
controller snapshot. Their digests must equal the identity fields. Diagnostic
mode permits omission of these references and cannot produce formal evidence.
Only environment-variable names are accepted for passwords. Inline credential
fields and unknown top-level fields are rejected. Credentials, response error
text, and certificate material must not be placed in a workload or snapshot.

The canonical `business_binding(workload)` payload includes database/table,
worker count, seed, connection mode, client and SQL timeout policies, expected
column type, exact SQL template/hints, endpoint kind, result limit, arrival/key
algorithms, and payload formula. Optional `fixture_sha256` is included when
declared. It deliberately excludes A/B role, service endpoint/PID, rate,
warmup/duration, output paths, and build identity; those are independently frozen
in the cell and actual launch. Compute the hash rather than inventing it:

```python
import json
import sys
from pathlib import Path
sys.path.insert(0, "tools/license-checks")
import http_query_baseline as http

path = Path(".build-records/my-http-workload.json")
workload = json.loads(path.read_text())
workload["business_workload_sha256"] = http.business_binding(workload)["sha256"]
path.write_text(json.dumps(workload, indent=2) + "\n")
```

## Dispatch, timing, and cleanup

The runner compiles and invokes the existing `LicenseJdbcBaseline` generator
before connecting. Measured arrivals use seed 20260922 and the same Java
Random/StrictMath Poisson sequence as JDBC, including positive fractional rates.
Warmup has its own deterministic seed. Point keys are generated independently
from arrivals. The binary vectors, SHA sidecars, source dependencies, actual
Java executables, client affinity, and launch inputs are recorded before warmup.

Each worker owns one initial HTTP connection and consumes its fixed strided
portion of the open-loop arrival vector. Every planned request retains its
original arrival timestamp when the worker falls behind. Successful-operation
P95/P99 use **scheduled arrival to full response/oracle completion**; service
time, client queue, failed-request latency, and drain are reported separately.
Throughput divides successful requests by the entire request interval,
including drain. There is no arrival-to-completion deadline: queue delay remains
visible and must satisfy the controller's frozen SLO.

`request_timeout_seconds` is an absolute dispatch-to-completion deadline,
including connect/request/headers/body/oracle work. One watchdog interrupts
expired sockets; slow bytes cannot indefinitely renew an idle timeout.
`query_timeout_seconds` is also sent as an explicit SQL `SET_VAR` hint. Client
timeouts and recognized server timeout signatures are counted separately from
generic business errors. Unknown server error messages remain counted as
business errors, not silently classified as successful or proven non-timeouts.
Any error, whether classified as timeout or not, disqualifies the window.

No request is retried or redirected. A normally announced server connection
close is recorded; the next *different scheduled request* may open a replacement
connection. A transport error fails that request and may also require a new
connection for the next request. Raw rows retain connection generation and
whether the actual transport was reused. Full response bodies are drained for
reuse, bounded at 64 KiB, and then closed. Workers and their sockets are closed
after the measured boundary, with bounded joins and a retained failure receipt.
On an error this proves local cleanup only; it does not assert the server has
finished an interrupted query. Failed windows never supply passing evidence.

FE/BE CPU counters and RSS are read immediately before measured requests are
released and after their interval ends, before connection cleanup. Process
start ticks and the monotonic brackets are archived. CPU is independently
recomputed per successful operation. RSS boundaries are not a peak-memory
measurement. The outer controller must still collect resource-observer data
for the declared collector/coverage and whole-window resource requirements.

All request and boundary timestamps use Python `time.monotonic_ns()` in the same
clock domain. UTC is recorded only with surrounding monotonic anchors and is
never used to calculate latency. The normalized window declares
`monotonic_clock_domain=controller_monotonic_exact` and
`monotonic_mapping_uncertainty_ns=0`.

## External controller integration

Invoke one new output directory per window, for example:

```bash
nsenter --target "$NAMESPACE_PID" --net -- taskset -c 0-3 \
  python3 tools/license-checks/http_query_baseline.py \
  --workload "$WORKLOAD_FILE" --output "$NEW_OUTPUT_DIRECTORY" \
  --java-home "$JDK17_DIRECTORY"
```

The CPU set and identifiers are controller inputs, not tool defaults. Supply
the password environment variable through the execution environment, not a
command-line literal. Freeze the actual source/identity snapshots before formal
execution and stop unrelated compilation or tests during formal windows.

`AA`/`AB` require at least 120 seconds warmup, 300 seconds measured arrivals,
and 10,000 planned requests. These are minimum eligibility checks only; root's
declared cell controls the actual rate, durations, SLO, repetitions, capacity,
and resource schedule. B is permitted only in `phase=AB`. Both A and B of an AB
comparison must include `freeze` pointing to an eligible same-boot P4 freeze;
the adjacent `<freeze>.published.json` must already exist. Before warmup, the
tool checks its role identity, business hash, load shape, and actual arrival
vector against that freeze. Both hashes are included in the launch and final
normalized window. No freeze is consumed for A-only phases.

Artifacts include `workload.json`, `launch.json`, binary arrival/key vectors,
`warmup-worker-N.csv`, `worker-N.csv`, `resources.json`, `lifecycle.json`, and
`summary.json`. Every request has real HTTP status/business code, safe actual
payload/column values on success, request/response SHA-256, response length,
queue/service timestamps, and categorized failure fields. Raw response errors
and Authorization headers are not archived.

`audit_window` rechecks every scheduled index, worker assignment, key, request
hash, full successful payload/column oracle, warmup failures, metrics, PID
lifetimes, CPU boundaries, cleanup, and raw artifact/dependency hashes. It emits
`audit.json` and `window.json` with the existing P4 window schema and evidence
reference. Diagnostic status is `DIAGNOSTIC_VERIFIED`; formal raw-audit status
is `VERIFIED`. Neither is a performance verdict. `formal_performance_pass` is
always false. Missing/failed/raw-inconsistent windows retain their records,
return exit 2, and emit no verified normalized window. Input/setup failures
return nonzero and may occur before an audit exists.

The external P4 controller must calibrate this HTTP workload's own A-only
capacity, arrange independent AA/AB pairs, and feed verified windows and
resources to `p4_statistics`. A JDBC capacity report cannot stand in for HTTP
capacity merely because concurrency is the same. This single-window tool has
no hidden A/A loop and can be called from any such controller.

## Offline checks and live smoke

```bash
taskset -c 4 python3 -m unittest discover -s tools/license-checks \
  -p test_http_query_baseline.py -v
```

The tests use in-memory HTTP doubles and local socket pairs; no HTTP service,
FE/BE query, or browser is launched. They cover exact oracle failures, real
status preservation, keep-alive and replacement, no replay, absolute header
deadline interruption, malformed/truncated/oversize responses, secret omission,
queue delay, warmup errors, sixteen-worker cleanup, raw mutations, CPU lifetime
changes, published-freeze checks, and the real JDK schedule generator.

Before real measurement, the controller should run isolated short A-only smokes
for c1 and c16 and verify actual column type, hint compatibility, response
shape, transport generations, and the raw audit. A proposed small diagnostic is
c1 at 5 requests/s and c16 at 20 requests/s, each 2-second warmup and 5-second
measurement; the controller decides when these may run. They cannot establish
capacity, tail-latency precision, or formal performance acceptance. At initial
tool delivery only offline verification has been performed.
