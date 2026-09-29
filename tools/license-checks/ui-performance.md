<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# G7 actual License page workload

`LicenseUiPerformance.cjs` is the browser participant of the current P0 §5 G7
contract. It does not create a cluster, issue certificates, start a business
background, qualify capacity, or declare A/A or A/B equivalence. Importing it
has no runtime side effects. The older `LicenseUiConcurrentFixture.cjs` and its
original-A failure records remain unchanged.

Current required B profiles are details with 1/10/50 independent BrowserContexts
and imports with 1/10 contexts. Every context remains alive for the complete
300-second window. Preparation is sequential, preserving each context rather
than recycling contexts to reduce memory. The controller must observe the
actual browser process tree and enforce its frozen client memory/headroom
budget; this driver neither samples RSS nor silently raises the old 6 GiB limit.

Details enter the real License page once during preparation, then click its
refresh button at offsets 0, 10, ..., 290 seconds: exactly 30 measured GETs per
context, plus the separately recorded initial GET. The UI has no automatic
status refresh. Imports have three explicit validate/confirm/import/receipt
operations per context, at offsets 0/100/200 seconds, alternating text/file/text.
All contexts use the same certificate within a wave, and each wave has a
separate input. The owner must freeze each input's sequence, validity interval,
deployment and SHA-256. This measures one new commitment and idempotent
concurrent submissions per wave; it is not 30 distinct certificate commitments.
Distinct ADMIN principals avoid accidental reuse of one principal's burst
budget. Rate-limit negative cases remain separate G6/P2U evidence.

All HTTP calls come from actual FE UI actions or real logout. No Playwright
request routing, API responses, timing, or document fallback is synthesized.
Navigation uses real routes, and authentication uses the real login form and
HttpOnly Cookie. A can run `other-tabs` against its real Home/Configuration/Session
pages, or the outside controller can run only the shared business background.
A details/imports configurations are rejected because those pages do not exist
on A. B-only browser/API costs cannot be interpreted as an equivalent A UI delta.
The `other-tabs` window navigates at 0/100/200 seconds and demands zero license
requests throughout preparation and measurement; it does not manufacture
30 refreshes of a page absent on A.

## Controller interface

The owner creates a new private `.build-records/` output directory and a 0600
JSON config. Start the driver with the exact Node 22 executable and one config
path. Do not print configs, certificates, account passwords or browser cookies.

```json
{
  "schema_version": 1,
  "token": "32 lowercase hex characters",
  "variant": "B",
  "scenario": "details",
  "context_count": 50,
  "duration_seconds": 300,
  "refresh_interval_seconds": 10,
  "preparation_concurrency": 1,
  "role": "admin",
  "language": "en",
  "origin": "http://127.0.0.1:38031",
  "prefix": "/massdb",
  "action_timeout_seconds": 30,
  "prepare_timeout_seconds": 300,
  "deadline_monotonic_ns": "absolute deadline in this Node process hrtime domain",
  "chromium": "/explicit/chromium",
  "playwright": "/data/project/massdb-sql/ui/node_modules/playwright",
  "allow_no_browser_sandbox": true,
  "output": "/data/project/massdb-sql/.build-records/owned-new-window",
  "accounts_file": "/data/project/massdb-sql/.build-records/owned/accounts.json"
}
```

`accounts_file` is a 0600 JSON array with exactly one `{username,password}` per
context. For imports also supply `certificate_files`, exactly three objects
`{path,sha256}` referencing 0600 files of at most 65536 bytes with the exact UTF-8
certificate bytes; trailing bytes are not trimmed. None of the certificate
text or credentials are copied into reports. Record the real FE package,
Chromium/Node, server/worker placement and original service identities outside
this config as part of the controller's immutable plan.

The files below are atomically written by each producer. Every control message
contains the same token; do not reuse an output directory after a failure.

1. Driver writes bounded `progress.json` after each context is genuinely ready,
   then `ready.json` with context count, source hash, Node PID, host boot ID,
   `clock_domain=node_process_hrtime`, and actual monotonic/UTC anchors.
2. Controller verifies all required participants, readiness, ownership and the
   clock bridge, then writes `release.json` with `token`, `node_pid`,
   `clock_domain=node_process_hrtime`, `clock_bridge_sha256`,
   `epoch_monotonic_ns`, `epoch_unix_ms`, `duration_seconds=300`. The epoch must
   be in the future by at most 30 seconds and fit inside the frozen deadline.
   The controller derives it in the Node time domain. Java `nanoTime`, Python
   clocks and Node `hrtime` are not assumed to have a portable shared origin.
   The bridge hash only binds evidence; the driver cannot audit other processes'
   actual clocks or whether that evidence proves overlap.
3. Driver executes all context schedules, preserves failed and not-sent actions,
   requires every context to remain alive through the end, and writes
   `done.json`. It continues holding contexts and waits for `finish.json`.
   Background starting late, finishing early or lacking an actual receipt must
   make the controller's combined window incomplete, regardless of equal epoch
   fields or a `BROWSER_WINDOW_PASS` receipt.
4. Controller writes `{token}` to `finish.json` only after its own completion
   checks. Driver leaves the License page, checks for new license requests for
   two seconds after each unmount, checks transient certificate cleanup, performs
   real logout, closes contexts/browser, and writes `terminal.json`. Wait for
   the actual process exit and inspect both cleanup and measurement status.
5. Controller may write `stop.json` or send SIGTERM at any point. A 100 ms guard
   closes the browser on stop/deadline to interrupt outstanding operations. The
   outer owner still owns process-tree identity, hard cleanup deadlines and
   independent resource accounting; it must never turn missing cleanup into PASS.

Normal reports contain endpoint labels, request timing/status/counts, safe
status/receipt fields, body hashes and byte counts, and action latency including
client queue time. Full request URLs/headers/bodies, response error messages,
console messages and secret text are excluded. Secrets in URL/storage/console
or responses fail the run. Server-log secret scans remain the outside owner's
responsibility. Record per-context peak inflight and global peak separately.
Browser observer overhead is part of the measurement setup and is not claimed
zero. A pending real 202 may yield receipt polling; natural 200 responses do
not prove the 2/4/8/16/30-second/120-second state machine. Reuse the product-bound
P2U timing/fault evidence or run a separate real fault case, never pretend this
performance driver observed an untriggered branch.

The shared G5 business participant must use 16 reused workers, allowed writes
and metadata in the frozen 50/50 mix at 60% of demonstrated A capacity. It is
not the old point-read/insert background. Full write/metadata oracles, independent
A/A and A/B pairs, resources, 1% CPU/throughput and 2% latency detection precision,
and at least 10,000 successful operations for business P99 are external gates.
Page sample counts never replace business operations. Browser reports always
leave P99 unqualified and expose descriptive raw latency samples.

## Offline validation

```bash
.build-records/toolchains/node-v22.23.2-linux-arm64/bin/node --check tools/license-checks/LicenseUiPerformance.cjs
.build-records/toolchains/node-v22.23.2-linux-arm64/bin/node --test tools/license-checks/ui-performance-oracles.test.cjs
```

These tests exercise configuration/count/cadence, A/B separation, secret file
permissions, endpoint labeling, exact receipt versions, safe projection,
clock-domain binding and failure accounting. They start no browser, FE, BE or
SQL/HTTP traffic and are not substitutes for an actual G7 window.
