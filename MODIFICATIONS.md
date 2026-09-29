# MassDB SQL Modifications

MassDB SQL is derived from Apache Doris. Upstream source baseline: `59de8c4c524008e8ab2e43b79312f716a3a423a8` (`4.0.5-rc01`), verified against the [Apache repository](https://github.com/apache/doris/commit/59de8c4c524008e8ab2e43b79312f716a3a423a8) on 2026-09-06.

This inventory describes distribution changes, not a claim that all changes are owned by the company. Original Apache and third-party notices remain applicable. It supplements modification notices within editable files; it does not replace those notices.

## License renewal after quota reduction (2026-09-30)

- Revise the execution plan, P0 contract, management instructions, current
  progress, and import-core contract for renewal after expired coverage: allow
  lower FE/BE limits after safe, committed node removal brings full registered/reserved usage within
  the new limits. An expired historical base quota is no longer a permanent
  renewal floor; unexpired active/pending/base commitments remain protected.
- Preserve offline-member accounting, existing DROP safety checks, sequence
  and deployment binding, failure atomicity, and the existing
  `LICENSE_NODE_LIMIT_TOO_SMALL` error mapping. Expiry alone does not remove
  the last committed ADD limit or create unlimited node capacity.
- Set future-pending ADD limits to the per-role minimum of committed base and
  accepted pending limits. Recheck usage before persistent activation; higher
  pending quotas do not grant capacity early. Apply immediate renewal quotas
  in the certificate commit. Preserve the existing wire/storage format and
  strict FE package-digest gate; all registered FEs must use the same updated
  package before quota reduction. Recovery permits only nonoverlapping
  active/base-to-pending reductions and retains base-to-active validation.
- Limit FE product changes to `LicenseImportPolicy`, `LicenseImportState`, and
  the member ADD path in `LicenseManager`; preserve query admission and BE
  behavior. Add regression coverage for expiry boundaries, lower immediate and
  future renewals, actual/reserved usage, failed commits, recovery, and renewal
  idempotence; update the independent Python issuer to match the renewed rules.
- Pass all 279 tests in 31 FE suites on Temurin 17.0.4+8, with zero failures,
  errors, or skips, plus FE Maven packaging, Checkstyle, and 28 Python issuer
  tests. Verify the updated JAR in one real FE over JDBC/HTTP: expiry, removal
  of offline registered test identities, lower-quota import, ADD denials,
  original-receipt idempotence, and restart recovery. Extra identities have no
  FE/BE process or tablet; this does not validate live BE migration, real
  multi-FE failover, or new performance. Keep controlled pending/recovery and
  package-gate results distinct from that runtime scope.
- Preserve all earlier fixture failures and the original P1/P2/P3/P4 and HTTP
  supplement evidence. Record this change's source/package bindings, actual
  results, and limits in `docs/license-expired-renewal-20260930.md`.

## License external HTTP read admission (2026-09-29)

- Add the existing protected-read license guard to
  `fe/fe-core/src/main/java/org/apache/doris/httpv2/restv2/ESCatalogAction.java`
  for `POST /rest/v2/api/es_catalog/search`, before catalog initialization and
  search. Preserve metadata access through `get_mapping` for ordinary indices,
  aliases, comma-separated selectors, and `*`. Reject empty selectors, path
  separators, query/fragment/percent characters, whitespace, and controls before
  catalog initialization, preventing inputs such as `_search#` from changing
  the mapping URL into a data-search request.
- Add the same guard to
  `fe/fe-core/src/main/java/org/apache/doris/httpv2/restv2/ImportAction.java`
  for `POST /rest/v2/api/import/file_review`, before file listing and preview
  readers. Preserve existing authentication and redirect ordering, and keep
  license enforcement independent of `enable_all_http_auth`.
- Return actual HTTP 403 responses with structured `reason`, `message`, and
  `retryable` fields for license denials. Preserve ingestion writes and the
  existing behavior of valid requests; do not change BE or internal protocols.
- Add
  `fe/fe-core/src/test/java/org/apache/doris/httpv2/restv2/LicenseExternalHttpAdmissionTest.java`
  for controller admission, authentication/redirect precedence, side-effect
  ordering, metadata compatibility, and mapping-selector validation. On
  Temurin 17.0.4+8, v3 passed all 42 tests (12 new controller tests and 30 existing
  guard/snapshot/query-plan tests), FE Maven packaging, and Checkstyle, with
  zero failures, errors, or skips and no source changes during verification.
  Preserve the v1 header-registration Checkstyle failure and the v2 40-test
  success separately. These tests use the real guard with mocked external
  dependencies; no live HTTP/ES/broker integration or new performance result is
  claimed. See `docs/license-http-read-admission-20260929.md` for evidence.
- Update the execution plan, P0 contract, and implementation progress for this
  two-endpoint supplement. Preserve the original P4 package identity and its
  acceptance evidence, historical failures, and the remaining excluded
  SET/dictionary, procedure file/process, and UDF outbound paths. The historical
  Parquet reader cleanup failure is not fixed by these admission checks.

## License P4 measurement tooling (2026-09-29, historical tooling stage)

The following notes preserve the tooling-stage state. The original five-outlet
P4 quick acceptance and package verification were subsequently completed as
recorded in `docs/license-p4-acceptance-20260929.md`; that accepted package does
not include the later two-endpoint HTTP admission supplement above.

- Update the execution documents for the user's quick-acceptance scope and add
  `docs/license-p4-acceptance-20260929.md` with actual six-case JDBC A/B and
  valid-state functional results. Retain measured CPU and latency increases,
  the long-lived-A/newly-started-B limitation, and pending expiry, page and
  independent-package runtime checks. The historical capacity, long-window
  and fine-precision gates below no longer block this quick acceptance;
  previous failures and qualification records remain unchanged. Preserve the
  commercial HTML-comment header used by the existing Markdown documents;
  these documentation changes do not change FE/BE product behavior.
- Bind current G1-G7 measurements to the reduced execution contract while
  preserving historical LP records. Add complete static result oracles and
  actual JDBC statement lifecycle receipts to the existing query runner.
- Add an A-only freeze and paired A/B statistics layer with fixed CPU/throughput
  and latency precision ceilings. Require independent windows, raw evidence and
  capacity bindings; missing evidence or precision cannot establish a pass.
- Add an independent certificate-page performance driver for the retained
  detail and import concurrency levels, bounded requests, explicit controller
  barriers and cleanup. Keep browser samples separate from business metrics.
- Add an explicit current write/metadata background profile while preserving
  the original point-read profile. Retain sixteen reused workers, independent
  full-result checks, disjoint writes and post-window verification for expired
  certificates. Bind real JDBC execution records through a separate evidence
  adapter; missing lifecycle or clock-mapping records remain unqualified.
- Add an opt-in clock handshake to that background helper and a G5/G6/G7
  participant with actual reused-connection evidence, explicit state barriers
  and independently checked per-stream metrics. Keep legacy defaults and
  measured request timing unchanged; state, management and UI qualification
  remain the responsibility of the outer controller.
- Recheck the original million-row point fixture and short-circuit path, and
  retain new short-window diagnostics separately from formal acceptance.
- Add an opt-in bounded JDBC clock handshake and waited lifecycle evidence;
  historical windows remain unqualified when these records are missing. Add
  an HTTP Query driver with a complete payload oracle and absolute request
  deadlines, explicitly separating HTTP connection reuse from FE SQL sessions.
- Add current G4 single-window DML and Stream Load adapters. Use distinct
  operation domains, original transaction acknowledgements, complete final
  data checks and owned cleanup. Reuse one bounded Stream Load input file
  instead of copying every batch; require external certificate-state and
  resource-observer evidence before formal normalization. Preserve diagnostic
  failures and distinguish tool verification from performance qualification.
- Add a Flight single-window wrapper around the unchanged full-result fixture,
  with fresh FE tickets, reused channels, bounded scheduling and raw lifecycle
  evidence. Preserve the original 65535-batch failure and require separate real
  integration and paired performance acceptance.
- Add a fresh-plan scanner window with per-worker handle ownership, actual HTTP
  connection evidence, full million-row validation and acknowledged cleanup.
  Preserve unknown opens and failed closes; keep the original BE unchanged.
- Add a complex-planning window that reuses the independent 33-column oracle,
  retains cold per-request connections and hot reused connections with the
  fixed 180-second view change, and binds actual reader preflight evidence,
  process clocks, raw requests and waited cleanup to the measured launch.
  Original fixture defaults and historical evidence remain distinct.
- Add a catalog/S3 read window with streaming JDBC results and complete
  million-row, four-column validation. Bind the actual reader, private query
  digest, source identity and CPU observation interval; timeout cleanup closes
  only the owned socket and does not open a cancellation connection.
- Add an external JDBC INSERT SELECT window with disjoint 100-row operations,
  complete native PostgreSQL verification and transaction-locked owned-table
  cleanup. Retain unknown write outcomes, actual FE acknowledgements and
  separately frozen Java arrival schedules; offline tool checks do not qualify
  real capacity or paired performance.
- Add an explicit bounded long-window mode to the existing resource observer,
  preserving default limits and metrics. Enforce sample, log and disk bounds
  so low-rate workloads cannot silently lose observation coverage.
- Add an A-only Flight/scanner capacity controller with independently warmed
  windows, actual observer/client lifecycle and immutable predeclared SLOs.
  Separate short diagnostic pilots from full confirmation; retain the complete
  sample, pair, capacity-bracket and later A/A/A/B precision requirements.
  Extend the same loop to catalog/S3 reads with predeclared actual Java arrival
  files and complete source-container cgroup observations. Preserve native
  PostgreSQL address and FE session-autocommit semantics in external-write
  diagnostics without changing product protocol behavior.
  At this historical tooling stage, P4 acceptance remained incomplete; the tooling
  changes do not modify FE/BE product behavior or transport protocols.

## License P2U management page (2026-09-29)

- Add a lazy License tab after Configuration with server-authoritative status,
  active and pending certificate details, UTC/local expiry display and registered
  FE/BE usage. Preserve existing Web login eligibility and administrator checks.
- Support bounded file/text input, validation and explicit import confirmation.
  Keep certificate text in transient form memory and clear it on lifecycle or
  identity changes. Use a dedicated adapter that preserves management HTTP and
  receipt semantics without exposing submitted certificate text in errors.
- Query the original receipt after an uncertain submission instead of retrying
  imports. Bound serial polling with backoff and a monotonic deadline; stop on
  hidden pages, navigation, logout or network failure and allow manual recovery.
- Clear completion state when changing receipt targets or starting another
  operation, and preserve exact 64-bit versions without JavaScript rounding.
- Complete 40 browser feature groups plus independent model oracles on the final
  UI bundle. Record build, notices/legal and final-JAR two-FE integration by
  evidence layer, including natural renewal/expiry, response-loss recovery,
  permissions and cleanup. Retain initial failures, the existing TypeScript
  dependency parse failure and the original account-audit password issue.
  P4 performance acceptance remains separate; no BE or protocol changes are made.

## License P3 admission integration (2026-09-25)

- Add controlled tests of the actual statement RPC and replan retry loops with
  the real coordinator dispatch boundary. Verify expiry before and after first
  dispatch, new executions, cancellation, timeout, retry exhaustion and cleanup;
  parsing, planning and remote execution remain test doubles.
- Exercise queued EXPORT expiry through the real transient scheduler and export
  state machine, including cancellation, task removal and worker termination;
  the environment, storage deletion and license clock remain controlled fixtures.

- Add one FE read guard and retain small source/probe/empty-result facts through
  existing analysis and SQL cache dependencies. Cover ordinary results, reused
  prepared point queries, protected reads into external tables, EXPORT and new
  connector plans without changing BE code or transport protocols.
- Recheck admission after query queueing and before first execution dispatch.
  Scope an admitted execution to its existing retries; new statements and
  prepared executions must obtain fresh admission. Preserve internal writes,
  metadata and existing server maintenance entry points.
- Serialize FE/BE membership mutations with certificate commits, check an ADD
  batch against committed base quotas before mutation and release capacity only
  after successful DROP. Retain original membership and decommission checks.
- Preserve reserved license errors from membership DDL through SQL planner
  wrappers, including structured reasons and uncertain-commit retry limits.
- Keep procedure license denials as one typed error. Skip result finalization
  when that denial produced no query processor, avoiding an extra null-pointer
  error while retaining the original handling of other procedure failures.
- Add focused classification, execution, side-effect and membership tests.
  Give existing coordinator and cluster member tests explicit license fixtures
  while preserving their original fragment, membership and journal assertions.
  Complete the agreed P3 functional acceptance with layered unit, controlled
  execution and real protocol evidence. Preserve artifact identities, original
  failures and owned-fixture cleanup. The final JDK 17.0.4 FE package passes 22
  targeted tests and a real expiry regression for procedures and SQL permissions.
  Retain the original CREATE USER audit-password finding separately from clean
  certificate-material scans. The UI and full performance acceptance remain
  later work; this change does not claim zero performance regression.

## License P2 management integration (2026-09-25)

- Add FE-owned bounded certificate metadata, journal/image recovery, deployment
  initialization, import and repair receipts, dedicated management queues and
  public-key configuration. Preserve committed identity and activation after
  incomplete recovery; gate new formats on actual registered FE capabilities.
- Add SQL and HTTP license management with ADMIN checks, bounded request parsing,
  original-user forwarding, exact HTTP status and local application receipts.
  Redact license literals before parser failures, audit and profile output.
- Preserve a known durable commit when local publication fails: keep a
  confirmable 202 receipt, retry the exact record before further mutations and
  make concurrent retries idempotent. Prepare fallible restoration before
  publishing facts, keep receipt reason/message/retryable consistent and reject
  oversized certificate/repair fields with the precise input-limit reason.
- Complete P2 management acceptance with 183 passing license tests on JDK
  17.0.4, four text-SQL helper tests, Checkstyle and source-header checks.
  Exercise real multi-FE imports, natural expiry/renewal, image/journal restart,
  Master failover, original-user forwarding, response loss, delayed application,
  old-FE rejection and fresh Observer recovery. Record test-double fault cases
  separately from live FE evidence and retain historical failures.
- Add operator and acceptance documentation, scan real logs/decoded Profiles
  for certificate disclosure and verify owned fixture cleanup without changing
  the original FE/BE services. Keep test credentials and raw evidence untracked.
- Keep BE protocols and query/node admission enforcement outside this change;
  those guards remain P3, and the UI remains P2U.

## Commit message guidance (2026-09-22)

- `AGENTS.md`: require commit messages to follow recent Git history, with an
  English `[type](scope) summary` subject and a non-empty description explaining
  motivation, changes, and validation results or why tests were not run.

## Current license P0/P1 completion audit (2026-09-25)

- Freeze the reduced P0 contract in the existing document: 28 query, 14
  management/quota and four UI test groups with real source hooks, plus seven
  performance groups and explicit applicability of the historical LP001–026.
  Keep all future runtime cases unexecuted and retain the original numerical
  precision criteria and historical failures without adding an audit framework.
- Cover both Coordinator and NereidsCoordinator queue exits, preserve the original
  narrow probe shape through optimization, and align renewal gaps with the
  implemented protection of previously accepted coverage.
- Recompile the current 14 license sources offline and match all 39 classes to
  the actual FE JAR. Recompile the eight test classes and pass all 104 tests on
  that JAR with JDK 17.0.4+8; revalidate existing issuer/interoperability evidence.
  Record missing historical Maven XML honestly instead of treating it as current
  proof. Runtime integration and end-to-end performance remain later phases.

## License scope reduction (2026-09-24)

- Limit the current delivery to the user's own deployment. Defer the Kylin,
  openEuler and CPU-architecture release matrix instead of counting it as
  remaining work or a P1/development/delivery prerequisite. Retain JDK 17.0.4
  compatibility, explicit trust configuration and functional/performance checks
  in the actual deployment environment; preserve historical platform evidence.
- Replace the broad FE governance plan with five data-output boundaries, a shared
  guard and the necessary fast-path, queue and external-write hooks. Allow the
  user-approved narrow table-existence probe and proven empty results; retain
  certificate import, persistence, registered-node quotas and the FE license tab.
- Mark previous coverage, protocol and machine-contract definitions as historical
  expanded-scope inputs pending applicability mapping. Retain their exact JSON
  and failure evidence, numerical performance criteria and unchanged BE protocol.
  Disclose additional FE and expression channels outside the reduced proposal.
- Record the existing terminal receipt for the original UI matrix: client RSS
  exceeded its limit during preparation of 50 contexts; the full matrix remains
  unpassed. This documentation change does not implement runtime licensing or
  rerun database benchmarks.

## License P0 contract and P1 core implementation (2026-09-22)

- Bind background helper startup identities to the requested executable and argv
  before freezing a process pin. Require two complete matching observations within
  the original phase deadline; preserve strict later identity checks, real early
  exit waits and ownership before evidence writes. Validate 48 Python checks and
  four exact-JDK lifecycle cases without upgrading prior UI runtime failures.
- Add a pure GC log record-time parser and half-open window mapper with complete
  FE/log/clock bindings, confirmed-prefix checks and separate terminal-drain
  classification. Reject missing legacy timestamps and incomplete rotation
  evidence; do not infer STW boundaries or modify a running FE's logging.
- Account for architected counter quantization in primitive latency precision,
  binding actual clock capability and raw output to the current boot, time
  namespace and clocksource. Unknown clock resolution cannot qualify latency;
  increasing window counts cannot remove systematic timer uncertainty. Preserve
  historical reports and the original numerical precision targets.
- Add owned private namespaces for three original FE voters and four original
  BEs, with frozen resources, actual membership/replay oracles and pinned-process
  cleanup. Bootstrap with local FE metadata before registering any BE. Add full
  ten-million-row fanout fixtures for 64/256/1024 buckets, bounded full-coverage
  integrity checks and actual four-BE runtime profiles. Add pinned Kafka package
  and Routine Load fixtures; retain download and query failures separately from
  completed functional prerequisites and formal performance acceptance.
- Specify source-backed original-browser and background/HTTP fixture inputs,
  including real cookie authentication, deployment prefixes, automatic task
  provenance, ES exchanges and registered-broker preview requirements. Add
  bounded controllers, an existing-protocol read-only broker and real-browser
  helpers, with offline test sources. Keep unexecuted implementations and the
  remaining full matrices distinct from actual functional evidence.
- Add an independent full-column complex-query oracle bound to the frozen SQL,
  conservative same-clock DDL overlap classification and unique profile/SQL
  correlation. Preserve unavailable original planning timings and reject mixed
  snapshots or substituted fixtures. Add a same-JVM concurrent query/event
  adapter, frozen open-loop arrivals, raw per-request receipts and independent
  Profile/EXPLAIN audits. Bound overlap sampling and ownership-based cleanup;
  retain actual runtime matrices as separate requirements from offline checks.
- Extend background fixtures with lifecycle resource observations, bounded
  output capture and cancellation cleanup. Add explicitly selected continuous
  read/write browser background load, complete million-row content verification
  and independent write-visibility receipts. Keep each source version and its
  actual tests separate from frozen performance measurements.
- Add an explicit fixed browser refresh cadence with original API/DOM checks,
  serial timing and background-window correlation. Revalidate prepared Kafka
  files against the pinned official archive before executing its broker.
  Add a sustained original Stream Load window with complete immutable inputs,
  open-loop arrivals and independent visibility checks; sample and resource
  gaps remain explicit rather than becoming full performance passes.
- Add a read-only public trust review probe against actual delivered FE/Jackson
  classes and a declared JDK 17.0.4 build. Compare public purpose/fingerprints and
  explicit rotation dependencies, bind initial input bytes to both runtimes,
  and bound child processes. Do not install trust or imply that unprovided
  production keys, dependency completeness or target platforms are qualified.
- Execute focused tool tests and exact JDK 17.0.4 helper checks after confirming
  the interrupted primitive measurement has no surviving clients. Preserve its
  incomplete windows and unknown exit cause. Bound Stream Load batch reads and
  reject changed input content before upload. Select the installed Parquet
  format classes ahead of the older copy needed alongside generated broker
  types; retain failed helper runs and corrected input-validation evidence.
- Bind background helper registration to stable executable and command identities,
  validate the original timestamped dictionary success/version format, and set
  table auto-analysis policy through its supported ALTER workflow. Preserve real
  partial successes, cancellation and helper-exit sampling failures separately.
  Recover original packaged UI provenance without substituting a newer local
  UI build or promoting an unexecuted browser plan to runtime evidence.
- Separate sparse browser-action observations from the unchanged business-load
  sample and precision gates as explicitly approved by the user. Preserve UI
  concurrency, cadence and resource checks without claiming qualified browser
  P99 from insufficient samples. Persist primitive-run window checkpoints and
  confirmed counts without treating saved RUNNING state as proof of liveness.
- Add separate concurrent-browser and sustained Kafka fixture tools. Preserve
  actual browser contexts and per-window shared business background, and retain
  complete ten-million-row Kafka input, distinct producer/consumer concurrency,
  physical offset verification and bounded evidence. Keep development, offline
  checks and unexecuted runtime matrices explicit rather than claiming coverage
  from the earlier navigation or 100,000-row Kafka subsets.
- Validate original UI navigation with actual packaged assets, isolated accounts,
  real browser requests and explicit logout. Fix fixture selectors and asynchronous
  waits without changing the product, and preserve the original result-page
  history-state limitation. Bind shared background overlap receipts, bound larger
  concurrent-browser reports and stop subsequent windows after incomplete cleanup.
  Extend workload exclusion to owned Python, Java and Node entrypoints, including
  orphaned clients, and preserve every failed run under its original source hashes.
- Use the original parser's complete EXPLAIN ALL PLAN syntax in the complex-query
  fixture; retain the failed preparation and its confirmed view/process cleanup.
  Accept the original healthy OK/EOF profile states while preserving the actual
  state, query/SQL identity and cold-planning timing requirements. Validate with
  captured profiles and full-column receipts, keeping earlier failures intact.
- Accept the original FE's list-valued repeated Vary headers in the Stream Load
  fixture while continuing to reject ambiguous framing/routing fields. Request
  an explicit server timeout and distinguish acknowledged commits from unknown
  server transaction termination; local socket or database cleanup does not
  manufacture evidence that an uncertain transaction has ended.
  Derive bounded pending-reference queues from frozen arrivals and the unchanged
  request deadline, preserving the active upload limit and end-to-end latency.
  Record expired requests as failures without reading their bodies, and retain
  the original queue-overflow run and server write-stall evidence separately.
- Add opt-in collection of existing fragment/Thrift RPC counters and bounded
  tailing of the FE's existing GC log without changing its logging or protocols.
  Preserve lazy missing counters, process identities, separate read/confirmed
  archive cursors and the original default collector interface. Keep partial
  RPC coverage and unmapped GC events explicit; offline tests and a read-only
  smoke do not establish complete allocation/network attribution or overhead.
- Add opt-in stop-after-failure handling for concurrent-browser matrices,
  preserving the complete frozen plan, attempted-window failures and unfinished
  windows. Keep background cleanup failures and actual child exit evidence
  separate from browser completion or runtime performance qualification.
- Resolve incomplete process observations during UI background-helper exit with
  a bounded parent wait and the original phase deadline. Reject live identity
  changes and unresolved resource observations, preserve real exit statuses and
  first failures, and keep previous failed windows separate from repaired runs.
- Bound browser preparation to four simultaneous setup operations while retaining
  all declared contexts for the unchanged shared 300-second action window. Record
  actual created/ready counts, preserve preparation deadlines and first failures,
  and archive the exact process-RSS observation that crosses the original limit.
  Validate with 35 Python and 21 Node offline checks after preserving old sources;
  keep the original 50-context resource failure and full runtime matrix pending.
- Validate every timed point-query payload against a precomputed deterministic
  key model, including text/prepared and reused/per-request connections. Reject
  wrong-key, null, wrong-type and extra-column responses despite a correct row
  count. Bind oracle coverage to raw key sequences and retain earlier row-count
  diagnostics under their original tool hashes rather than upgrading them.
- Extend baseline fixtures with an owned-loopback read-only S3 endpoint serving
  verified Parquet bytes, per-phase request evidence and real schema/read/write
  oracles. Expose an explicit BE test memory profile and record fresh 4 GiB
  startup evidence after preserving 2 GiB memory-pressure failures. Retain the
  original BE executable, audit settings and transport; fixture reachability
  and rate-grid width do not establish integrated license or performance gates.
- Add an original-build Group Commit fixture for four batch sizes, both
  full-prepare modes and repeated server-prepared execution. Validate actual
  OK receipts, fast-path reuse, independent visibility and complete row models;
  preserve driver/protocol parsing failures and verified session/table cleanup.
- Add full-row Flight connection/batch fixtures and preserve the original
  65,535-batch payload mismatch as a failing case. Add bounded read-only resource
  sampling with process identity checks, metric allowlists and honest namespace
  traffic/GC attribution. Correct LP023 decoded-payload sizes using signed
  fixtures and a valid-signature invalid-claims negative case; retain every
  performance gate and keep incomplete cases from being reported as passed.
- Add an original-build DML/transaction fixture with independent visibility,
  commit/abort evidence, complete data models and cleanup. Record unsupported
  combinations and ACK-only START TRANSACTION separately from actual BEGIN.
  Add a plan-first P1 primitive matrix harness with bounded histograms and
  explicit missing classifier/integration scope; final tool checks and bounded
  smoke records remain separate from the unrun formal measurement matrix.
- Freeze the FE-only entry classification, operation/management contracts,
  compatibility boundaries and concrete acceptance mappings in
  `docs/license-p0-contract-20260922.md` and its JSON companion. Add a source
  inventory checker that detects unreviewed entry or hash changes; passing
  this design gate does not mean the corresponding runtime hooks are active.
- Extend the Java license core with an explicit bounded public-key manifest,
  separate license/clock-repair purposes, retained-key rotation checks and
  deterministic Unicode scalar rules shared with the offline issuer. Continue
  using JDK 17 JCA Ed25519 and the existing Jackson dependency, without adding
  a BE verifier or changing existing FE/BE communication protocols.
- Add an injectable monotonic license clock, bounded high-water progression,
  committed repair epochs and dedicated signed clock-repair challenges. Keep
  challenge consumption and prepared repair facts separate from publication;
  restarting or changing leadership invalidates unconsumed local challenges.
- Implement immutable active/pending/base import facts, original commit
  versions, a bounded 1,024-entry receipt history and strict restoration
  consistency. Add same-request acknowledgement, renewal coverage and capacity
  protection, explicit pending-base activation and a final time/member/trust
  recheck. `docs/license-import-core-20260922.md` and
  `docs/license-clock-core-20260922.md` specify the P2 persistence boundaries;
  the P1 core does not itself append or replay database journal records.
- Preserve allocation-free primary query-status evaluation and add a bounded
  live-clock epoch check. Provide a separate immutable management evaluation
  for simultaneous expiry, capability and independent FE/BE quota reasons;
  isolated-slot/base warnings do not independently reject a valid entitlement.
- Extend `tools/license-issuer/` with explicit-zone date conversion, claims
  preparation from an actual deployment request, authenticated renewal
  preflight, public trust-manifest export and dedicated repair signing and
  verification. Keep original keygen/sign/verify commands, strict bounded
  parsing and non-sensitive errors; private test keys are generated only in
  temporary directories and are not distributed as product trust material.
- Add `tools/license-checks/` for contract validation, Java/OpenSSL license
  and repair interoperability, full-code-point text compatibility, explicit
  source-versus-built-artifact dependency checks and controlled JDBC baseline
  measurement. The isolated baseline runner uses a private network namespace;
  statistics tests reject incomplete measurements and unsupported pass claims.
  Add a separate core-cost probe for snapshot/clock and management primitives,
  including actual thread allocation, GC and elapsed-time measurements; it
  does not claim to measure the future P3 classifier. Evidence records identify
  actual runtimes, loaded artifacts and hashes.
- Register all new commercial Java/Python source and tests in
  `dist/source-headers.json` and the matching License Eyes exception block,
  preserving upstream headers and existing third-party grants. Record targeted
  JUnit, offline issuer and repository-check results in the implementation
  evidence. Neither isolated core tests nor an unchanged-build A/A baseline
  proves integrated A/B business performance, SQL/API/UI enforcement, durable
  recovery or multi-FE propagation; those require later integration evidence.
- The first-batch entry below is historical. This batch supplies the trusted
  clock and import-policy primitives that were absent then; runtime SQL/API/UI
  admission and database persistence remain separate integration work. BE code,
  directly accessed BE endpoints and previously issued BE plans remain under
  the explicitly accepted FE-only scope boundary.

## License acceptance fixtures and validation corrections (2026-09-24)

- Add shared RFC 8032 known answers and fixed project license/repair JWS
  fixtures, with four Java and three Python/OpenSSL tests. Public test seeds
  remain test resources and are never installed as production trust roots.
- Add deterministic full-range point keys and bounded measurement barriers
  to the JDBC baseline tooling, preserving end-to-end queue latency and
  recording CPU boundaries separately from reused connection cleanup.
- Add predeclared rate calibration with explicit latency/drain limits;
  incomplete sweeps, insufficient confirmation windows and query errors
  cannot establish a capacity bracket or a release performance pass.
- Add a deterministic 128-byte CSV fixture and actual FE-to-BE Stream Load
  checks, including duplicate-label visibility on a DUPLICATE KEY table.
  Full input generation is recorded separately from actual loaded rows.
- Add isolated SQL/HTTP metadata and original-permission fixtures, with
  explicit error-envelope checks, temporary-account cleanup and restoration
  of the test FE HTTP-auth setting. Preserve failed probes separately.
- Generate the frozen 100-file Parquet input with existing distribution
  dependencies, independently read every row and compare complete row/payload
  digests to a separate model. Keep local fixture proof separate from actual
  external-store reachability and performance acceptance.
- Record the requested Kylin/openEuler, ARM64/x86 and JDK 17.0.4 target
  environment without extending local test results to untested combinations.
  Update implementation evidence to 104 Java and 25 offline issuer tests;
  full baseline precision and integrated runtime enforcement remain unproven.

## License primitives and offline issuer, first implementation batch (2026-09-22)

- Add strict compact-JWS verification under
  `fe/fe-core/src/main/java/org/apache/doris/massdb/license/`, using JDK 17
  Ed25519 and the existing Jackson dependency. Bound parsing, require the
  pinned algorithm/type/key, preserve original signing bytes, and distinguish
  verified immutable claims from deployment/time/member admission decisions.
- Add immutable query-status evaluation for active/pending entitlement and
  registered member counts. Keep committed base capacity separate: damaged
  capacity records do not invalidate otherwise usable query entitlement, and
  missing records do not imply a fresh-cluster bootstrap allowance. These
  classes do not implement a trusted clock, import admission or persistence.
- Add `tools/license-issuer/` with explicit offline key generation, signing,
  verification and real OpenSSL tests. No production/test trust root or private
  key is included; the tool is separate from FE/BE packaging.
- Record the user-approved FE-only license scope in the admission contract and
  26 performance case definitions. Preserve existing BE code, protocols, ports
  and connection settings. Previously issued plans may continue or reopen scans
  at BE after license expiry; new FE queries and plan requests remain subject to
  admission. Existing direct BE paths are accepted exclusions, not verified
  closures or measured low-probability events.
- Remove the previous internal-identity, execution-credential, lease and BE
  revocation work from current release prerequisites. FE still manages registered
  FE/BE capacity and releases slots only after committed member removal. All
  applicable performance cases remain unexecuted; excluded protocol tasks are
  marked out of scope, never passed.
- Record targeted FE tests, Java/OpenSSL interoperability, issuer tests and
  repository checks in `docs/license-implementation-progress-20260922.md`.
  Register new source headers. No SQL/API/UI/BE hook is active, no database
  service is changed, and no end-to-end performance or release claim is made.

## Runtime license certificate execution plan (2026-09-22)

- `docs/license-certificate-execution-plan-20260922.md`: define an offline signed
  license lifecycle, SQL/HTTP import, replicated FE state, FE admission and
  registered FE/BE node quotas while preserving ingestion, updates and safe
  metadata. Retain renewal, trusted time and repair, commit receipts, recovery,
  cache/prepared/queue handling, function capabilities, independent ingestion
  planning and FE output classification.
- Apply the user's explicit decision to leave BE unchanged. Classify the 48
  historical audit items as 25 retained FE items, 16 FE subsets and 7 accepted
  exclusions. Keep BE source references as boundary evidence; do not require
  BE credentials, identity redesign, protocol changes, leases or revoked old
  processes. Recalculate the scoped estimate as 31–45 person-days, provisional.
- Keep the FE certificate details/import tab in the first release, with existing
  ADMIN permissions, validation previews, receipts, proxy/i18n support, bounded
  requests and browser/real-FE acceptance tests. Upgrade and activation gates
  apply to FE license metadata and admission; BE requires no licensing upgrade.
- Require no measurable business performance regression under controlled A/A
  and A/B comparisons with the same unchanged BE build and connection settings.
  Include all new FE work, ingestion, metadata, UI and state transitions;
  regressions or insufficient evidence block release. No performance pass is
  inferred from the scope reduction or isolated certificate tests.
- `docs/license-code-coverage-20260922.md` and its JSON companion preserve 1,423
  historical records and 1,171 source hashes. Schema v2 separates historical
  advice from current requirements: 350 FE records, 891 FE subsets and 182
  accepted BE exclusions. Keep 19 original requirement mappings and add R20 for
  the scope decision. These counts are not runtime coverage or passing tests.
- Preserve historical isolated JDK signature/timezone/dependency probes and the
  later implementation results in their evidence records. This scope revision
  changes documentation only; SQL/API/UI admission, persistence and end-to-end
  integration remain to be implemented and validated.

## Master FE lock and journal incident runbook (2026-09-22)

- `docs/fe-lock-journal-runbook-20260922.md`: provide offline collection commands
  and a source-grounded procedure for following transaction/metadata waiters
  through journal completion, BDB replication or storage, asynchronous logging,
  and report task dependencies. Distinguish monitor waits, write-lock ownership,
  invisible read/StampedLock owners, and per-snapshot lock addresses.
- `tools/fe-stall-collect.sh`: allow an explicit matching `--jcmd` executable and
  stop subsequent thread sampling after a failed or timed-out JVM request.
- `tools/fe-thread-dump-summary.py`: summarize one offline thread dump with
  bounded stack groups and path indexes; optionally print all blocks referencing
  a lock address without inferring ownership. Register its commercial header.
- Validate collector control flow with isolated mocks and thread interpretation
  with an isolated JDK 17.0.2 lock probe; check parser errors, grouping and lock
  references locally. No production attach or FE/BE behavior change.

## Production Master FE GC evidence (2026-09-22)

- `docs/fe-gc-log-analysis-20260922.md`: analyze the supplied September 20
  Master GC excerpt, cross-check 142 collections, 426 pause events and 645
  statistics blocks, and separate concurrent cycles from pauses, historical
  allocation stalls from new events, live data from post-GC usage, and missing
  thread samples from zero threads. Record approximately 12500 Java threads
  and substantial heap-page allocation without attributing them to a specific
  application method. Keep parsed data, plots and source checksum under ignored
  `.build-records/fe-gc-20260922/`.
- Update prior configuration/source reports with the new evidence and its
  limited time coverage. No production commands or FE/BE runtime changes.

## Production FE configuration audit (2026-09-22)

- `docs/fe-config-audit-20260922.md`: compare the supplied FE configuration
  with registered fields, launcher behavior, and runtime consumers. Document
  ignored keys, Thrift fallback and the 100000-worker ceiling, database quota
  overrides, distinct transaction deadlines, report coalescing, clone limits,
  disk selection semantics, and conditional logging/checkpoint pressure.
- Update `docs/fe-stall-investigation-20260921.md` and its reproduction baseline
  to the user's confirmed Xms125g/Xmx300g attachment; distinguish source defaults
  from supplied settings, especially the earlier 4096-worker hypothesis.
  Incorporate the reported ingestion failures at lower Thrift ceilings: retain
  the current capacity while distinguishing idle connections, useful work and
  downstream blocking; do not classify the ceiling itself as a proven cause.
  Record SSD-backed FE metadata and separate local I/O evidence from replicated
  journal acknowledgements, in-memory catalog work and lock contention.
- This is configuration/source analysis; no production settings or FE/BE runtime
  code are changed, and no full-cluster reproduction is claimed.

## Large-cluster FE stall investigation (2026-09-21)

- `docs/fe-stall-investigation-20260921.md`: trace week-scale ingestion stalls
  through Thrift idle connections and rejection, journal/metadata locks,
  checkpoint/GC, transaction cleanup and publishing, metrics collection, BE HTTP
  waits, and reused RPC timeouts. Distinguish verified code mechanisms from
  unconfirmed production causes, and include an offline diagnosis/remediation
  guide. Record isolated libthrift and Spring Boot property-binding evidence.
  Incorporate the reported 512G/96-core, OpenJDK 17.0.2 ZGC, Xms180g/Xmx360g
  deployment: distinguish heap limits from commitment, checkpoint's integer
  used/max threshold, missing ZGC pool metrics, allocation stalls, and runtime
  version/heap-resizing experiments without claiming a production root cause.
  Add a phased single-host reproduction plan covering real FE/BE ingestion,
  simulated report scale, small-heap quorum tests, and isolated production-size
  JVM tests, with explicit limits on equivalence to the 600-host deployment.
- `tools/fe-stall-collect.sh`: add opt-in local evidence collection with bounded
  commands, private new output directories, optional JVM thread snapshots and a
  single loopback metrics request. Do not collect process arguments/environment,
  upload evidence, run GC/dumps, or alter services. Register its commercial header
  and teach the source-header checker shell comment syntax.
- This investigation does not change FE/BE runtime code or claim to reproduce
  the production incident; the collector is syntax- and smoke-tested locally.

## Performance deep audit (2026-09-21)

- `docs/performance-deep-audit-20260921.md`: document six additional opportunities
  in mixed window aggregation, sliding MIN/MAX, JSONB conversion, ARRAY reads,
  pipeline metrics and LRU recovery. Record isolated algorithm/library results,
  adverse random-input results and excluded paths after planner checks. Prioritize
  the existing query, ingestion and lifetime findings alongside ARM/NUMA follow-up
  experiments. No database implementation changes or end-to-end speedup claims.

## Database bug audit (2026-09-07)

- `docs/bug-audit-20260907.md`: record additional query correctness and JDBC
  array fidelity findings, reproduction inputs and observed results, plus the
  transaction visible-version notification overwrite found during broader review.
- `docs/performance-audit-20260907.md`: document ten optimization opportunities
  across planning, execution, ingestion, storage, cloud metadata and report
  processing, with current-method measurements and algorithm-model evidence.
- `docs/fe-memory-gc-audit-20260907.md`: record FE collector metric compatibility,
  Arrow native-buffer retention, long-lived object/cache lifecycle findings,
  isolated current-class checks and a read-only local FE memory observation.
  Cross-check the external 23-item review, correct overbroad Flight/profile,
  InsertOverwrite and capacity claims, and extend the report to 22 MEM entries
  plus nine capacity/GC topics. Add Ranger audit, connection reset, Flight
  multi-statement cleanup and DFS cleanup-failure findings, with seven new
  isolated method probes and an equal-heap-limit G1/ZGC flag comparison.
  These audit reports do not change database implementation or fix the findings.

## FE company license display (2026-09-07)

At the maintainer's request, the FE copyright page temporarily omits the
company proprietary license reader, download link and commercial summary in
both languages. Company copyright, upstream attribution and open-source
readers remain visible. The commercial license decision, source headers and
license files in the installation and static resources remain unchanged.

## A02 company license decision (2026-09-07)

The maintainer confirmed a proprietary commercial policy for company-owned
additions and modifications not already licensed under other terms. Earlier
Apache grants, upstream backports and third-party rights are retained. Historical
pending-license statements later in this file describe the earlier review state.

- `LICENSE-MASSDB.txt`, `dist/headers/massdb-commercial.txt`,
  `dist/product-provenance.json`, `dist/source-headers.json`: record the scope,
  agreement-based authorization and open-source exceptions. Move 11 independent
  files from pending to `LicenseRef-MassDB-Commercial`; retain the four existing
  independent Apache files and all original upstream headers.
- `build-support/check-source-headers.py`, `.licenserc.yaml`,
  `fe/check/checkstyle/checkstyle.xml`: validate commercial and Apache headers,
  license text hashes and npm references; keep rejection of future pending files.
- `ui/LICENSE.txt`, `ui/package{,-lock}.json`: point current package metadata to
  the complete scope notice, preserving any rights previously granted under the
  upstream package's historical ISC declaration.
- `build.sh`, `build-support/prepare-product-notices.py`, `dist/LICENSE-dist.txt`:
  carry the commercial notice in component builds and `fe/legal/` in the full
  package; the root license points to that location without extra root files.
- The public UI legal page adds a company-license reader and download, with
  Chinese/English scope text. Source-header, package and browser checks cover
  missing/mismatched notices and preserved third-party rights. Contributor guides
  and the implementation plan record the decision and remaining release work.

This licensing change does not alter SQL execution or storage code. It does not
complete third-party license review or determine customer-specific contract terms.

## Product version presentation (2026-09-07)

- `fe/be-java-extensions/jdbc-scanner/src/main/java/org/apache/doris/jdbc/MySQLJdbcExecutor.java`:
  retain JSON number text until conversion to the target array element type,
  preserving large-integer/decimal precision and floating-point signed zero without
  intermediate `Double` rounding or repeated `BigDecimal` parsing. Preserve NULL
  elements, including nested NULL arrays, and parse timestamp fractions with
  nanosecond fields to retain microseconds at precisions 0–6. The JDBC regression
  suite compares native reads, external reads and inserted copies at these boundaries.
- `fe/fe-core/src/main/java/org/apache/doris/datasource/jdbc/client/JdbcMySQLClient.java`:
  recognize both Doris and MassDB in the remote `version_comment`, independently
  of letter case and the default locale. Keep original column metadata and Doris
  type mapping for MassDB JDBC catalogs; ordinary MySQL retains its existing mapping.
  `regression-test/suites/external_table_p0/jdbc/test_doris_jdbc_catalog.groovy`
  compares native and JDBC column types for large integers, decimals, dates,
  timestamps and arrays.
  Read parameterized Doris decimal precision/scale and string/binary lengths from
  the full type declaration; array-column JDBC metadata does not describe element
  parameters. Regression coverage includes nested decimals, CHAR and VARCHAR arrays.
- `fe/fe-core/src/main/java/org/apache/doris/httpv2/controller/HardwareInfoController.java`,
  `fe/fe-core/src/main/java/org/apache/doris/httpv2/rest/{FeVersionInfoAction,BootstrapFinishAction}.java`
  and `fe/fe-core/src/main/java/org/apache/doris/metric/MetricRepo.java`: use the
  product version for the FE home page, version/bootstrap HTTP responses and
  the version metric label. Separate build metadata remains available for diagnostics.
- `be/src/http/{web_page_handler.cpp,action/version_action.cpp}`: use the same
  product version on the BE home page, page footer and version HTTP response;
  the page version no longer includes the build hash, platform or compiler details.
- `gensrc/script/gen_build_version.sh` generates a shared product version for
  Java and C++; BE uses the generated constant directly in its heartbeat response.
- `fe/fe-core/src/main/java/org/apache/doris/system/HeartbeatMgr.java`,
  `fe/fe-core/src/main/java/org/apache/doris/service/FrontendServiceImpl.java`
  and `be/src/agent/heartbeat_server.cpp`: report that product version in local
  and remote FE heartbeats and BE heartbeats. `SHOW FRONTENDS`, `SHOW BACKENDS`
  and the corresponding `SHOW PROC` tables display `massdb-2.0.5-sql-rc02`
  without a Git hash. Build diagnostics and export provenance retain build IDs.
- `fe/fe-core/src/main/java/org/apache/doris/qe/GlobalVariable.java`: display
  `massdb-2.0.5-sql-rc02` through `@@version_comment`, derived from the build's
  version components without a Git hash or mode suffix. Keep `@@version` and
  the MySQL handshake at the existing `5.7.99` compatibility value.
- `build-support/prepare-product-notices.py`, `ui/src/constants/branding.ts` and
  `ui/src/pages/legal-notices/index.tsx`: derive `MassDB V2.0.5` for the public
  version display while retaining the complete build version and source identity
  in distribution metadata. Hotfix and release-candidate fields remain separate.

## Product release candidate rc02 (2026-09-06)

- `ui/src/components/legal-footer/index.tsx` and `ui/public/locales/{en-us,zh-cn}.json`:
  simplify the footer to company attribution, product name and the notices link;
  retain the copyright scope in the notices page and NOTICE, and retain the
  MariaDB attribution and license link.
- `gensrc/script/gen_build_version.sh`: advance the independent product version
  to `massdb-sql-2.0.5-rc02`; the Apache Doris source baseline remains `4.0.5-rc01`.
- `dist/RELEASE-NOTES.txt`: record rc02 and the Playground layout improvements.
- `AGENTS.md` and the distribution guide: record the maintainer's standing
  authorization to discard this checkout's test metadata and obsolete
  installations on rebuild; retain only the latest verified output package.

## Historical changes through bdd44bf2835b

| Path | Change and attribution handling |
| --- | --- |
| `be/src/http/default_path_handlers.cpp` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `be/src/http/web_page_handler.cpp` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `be/src/olap/compaction.cpp` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `be/src/olap/rowset/segment_v2/inverted_index/query_v2/collect/multi_segment_util.h` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `be/src/tools/meta_tool.cpp` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `be/src/vec/functions/function_multi_match.cpp` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `be/src/vec/functions/function_search.cpp` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `be/test/vec/function/function_search_test.cpp` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `build-for-release.sh` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `build.sh` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `docker-compose/README.md` | Added in this fork. See the provenance evidence appendix for authorship and licensing status. |
| `docker-compose/conf/be/be.conf` | Copied from `conf/be.conf`; original ASF header retained, whitespace adjusted and modification notice added. |
| `docker-compose/conf/fe/fe.conf` | Copied from `conf/fe.conf`; original ASF header retained, whitespace adjusted and modification notice added. |
| `docker-compose/docker-compose.be-host.yml` | Added in this fork. See the provenance evidence appendix for authorship and licensing status. |
| `docker-compose/docker-compose.fe-host.yml` | Added in this fork. See the provenance evidence appendix for authorship and licensing status. |
| `docker-compose/docker-compose.same-host.yml` | Added in this fork. See the provenance evidence appendix for authorship and licensing status. |
| `docs/group-commit-be-restart-fix-plan.md` | Added in this fork. See the provenance evidence appendix for authorship and licensing status. |
| `fe/fe-common/src/main/java/org/apache/doris/common/Config.java` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `fe/fe-core/src/main/java/org/apache/doris/catalog/Env.java` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `fe/fe-core/src/main/java/org/apache/doris/catalog/TabletInvertedIndex.java` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `fe/fe-core/src/main/java/org/apache/doris/cloud/transaction/CloudGlobalTransactionMgr.java` | Apache Doris upstream backport(s) #61881; local commit(s) `5abf4fdd0d5`. Upstream authorship is retained; no company-original change is claimed. |
| `fe/fe-core/src/main/java/org/apache/doris/httpv2/controller/HardwareInfoController.java` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `fe/fe-core/src/main/java/org/apache/doris/load/GroupCommitManager.java` | Apache Doris upstream backport(s) #60652 and #61555; local commit(s) `3d3b870a175 and 508fb026de8`. Upstream authorship is retained; no company-original change is claimed. |
| `fe/fe-core/src/main/java/org/apache/doris/master/ReportHandler.java` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `fe/fe-core/src/main/java/org/apache/doris/planner/GroupCommitPlanner.java` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `fe/fe-core/src/main/java/org/apache/doris/qe/Coordinator.java` | Apache Doris upstream backport(s) #60652; local commit(s) `3d3b870a175`. Upstream authorship is retained; no company-original change is claimed. |
| `fe/fe-core/src/main/java/org/apache/doris/rpc/BackendServiceClient.java` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `fe/fe-core/src/main/java/org/apache/doris/rpc/BackendServiceProxy.java` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `fe/fe-core/src/main/java/org/apache/doris/system/SystemInfoService.java` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `fe/fe-core/src/main/java/org/apache/doris/task/AgentTaskCleanupDaemon.java` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `fe/fe-core/src/main/java/org/apache/doris/task/PublishVersionTask.java` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `fe/fe-core/src/main/java/org/apache/doris/transaction/DatabaseTransactionMgr.java` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `fe/fe-core/src/main/java/org/apache/doris/transaction/GlobalTransactionMgr.java` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `fe/fe-core/src/main/resources/doris-logo.png` | Replaced visual asset; modification recorded in this inventory, also copied into FE/UI legal resources. Company ownership evidence remains pending. |
| `fe/fe-core/src/test/java/org/apache/doris/master/ReportHandlerTest.java` | Added in this fork. See the provenance evidence appendix for authorship and licensing status. |
| `fe/fe-core/src/test/java/org/apache/doris/system/SystemInfoServiceTest.java` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `gensrc/script/gen_build_version.sh` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `regression-test/suites/load_p0/routine_load/test_routine_load_be_restart.groovy` | Apache Doris upstream backport(s) #61881; local commit(s) `5abf4fdd0d5`. Upstream authorship is retained; no company-original change is claimed. |
| `regression-test/suites/search/test_search_dsl_syntax.groovy` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `thirdparty/build-thirdparty.sh` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `ui/public/img/background.png` | Replaced visual asset; modification recorded in this inventory, also copied into FE/UI legal resources. Company ownership evidence remains pending. |
| `ui/public/img/logo.png` | Replaced visual asset; modification recorded in this inventory, also copied into FE/UI legal resources. Company ownership evidence remains pending. |
| `ui/src/components/codemirror-with-fullscreen/codemirror-with-fullscreen.tsx` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `ui/src/components/codemirror-with-fullscreen/massdb.css` | Renamed from `ui/src/components/codemirror-with-fullscreen/doris.css`; original notices retained. |
| `ui/src/favicon.ico` | Replaced visual asset; modification recorded in this inventory, also copied into FE/UI legal resources. Company ownership evidence remains pending. |
| `ui/src/index.html` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `ui/src/router/index.ts` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `webroot/be/favicon.ico` | Replaced visual asset; modification recorded in this inventory, also copied into FE/UI legal resources. Company ownership evidence remains pending. |
| `webroot/be/index.html` | Modified relative to upstream source baseline; original license header retained, modification notice added. |
| `webroot/be/logo.png` | Replaced visual asset; modification recorded in this inventory, also copied into FE/UI legal resources. Company ownership evidence remains pending. |
| `webroot/be/massdb.css` | Renamed from `webroot/be/doris.css`; original notices retained. |
| `webroot/be/massdb.js` | Renamed from `webroot/be/doris.js`; original notices retained. |
| `webroot/static/doris-logo.png` | Replaced visual asset; modification recorded in this inventory, also copied into FE/UI legal resources. Company ownership evidence remains pending. |
| `webroot/static/favicon.ico` | Replaced visual asset; modification recorded in this inventory, also copied into FE/UI legal resources. Company ownership evidence remains pending. |

The intervening commits include upstream fixes (`3d3b870a175`, `508fb026de8`, `5abf4fdd0d5`). These are not identified as company-original work. Full comparison methodology and contributor evidence status are in [the evidence appendix](docs/massdb-sql-copyright-review-evidence.md).

## Copyright implementation

The 2026-09-06 implementation adds a public legal-notices page, runtime library attribution, deterministic UI component notices and release checks. Router changes keep the legal page and sign-in public and evaluate login state on each navigation. FE assembly places the corresponding MariaDB source outside the web bundle. BE relinking delivery remains a separate, unfinished release task.

Localization JSON files cannot contain comments; their changes are recorded here: `ui/public/locales/zh-cn.json` and `ui/public/locales/en-us.json` add the legal-page text. The UI lockfile records the resolved build dependencies. `dist/product-provenance.json` records source/version mapping and separately records decisions that remain pending.

See [the implementation plan](docs/massdb-sql-copyright-productization-plan.md) for completed verification and remaining release requirements.

## Implementation file inventory (2026-09-06)

Existing Apache-derived files retain their original headers and carry the fixed
MassDB modification notice. For JSON metadata, the lockfile, and ignore rules,
this inventory provides the associated modification record. The generated UI
and FE `legal/MODIFICATIONS.txt` carry this file with the notices.

| Scope | Files | Change |
| --- | --- | --- |
| Product documentation | `README.md`, `CONTRIBUTING.md`, `AGENTS.md`, `ui/README.md`, `docker-compose/README.md` | Product identity, contribution rules, build and legal-material instructions. |
| FE web presentation | `ui/src/pages/{login,layout}/index.tsx`, `ui/src/pages/login/index.less`, `ui/src/router/{index.ts,renderRouter.tsx}`, `ui/src/index.{tsx,html}`, `ui/src/utils/utils.ts` | Shared footer, public notice route, live login-state evaluation and proxy-aware resources. |
| UI text and metadata | `ui/public/locales/{en-us,zh-cn}.json`, `ui/package.json`, `ui/package-lock.json`, `.gitignore`, `ui/.nvmrc`, `ui/.npmrc` | Legal-page translations, locked toolchain/dependencies and internal package identity. The pre-existing ISC metadata remains under review. |
| UI collection | `ui/config/webpack.common.js`, `ui/scripts/collect-bundled-licenses.cjs` | Build metadata, module/license inventory, SBOM, asset hashes and webpack evidence. |
| New UI components | `ui/src/constants/branding.ts`, `ui/src/components/legal-footer/`, `ui/src/pages/legal-notices/` | Typed product metadata, runtime attribution and local license readers. New-file license and company copyright decisions remain pending; explicit transition headers are checked by the source-header registry. |
| Distribution tooling | `build.sh`, `build-support/prepare-product-notices.py`, `dist/product-provenance.json` | Verify UI/JAR resources and assemble matching MariaDB source separately in FE packages. New tooling license decision remains pending. |
| License evidence | `dist/LICENSE-dist.txt`, `dist/ui-licenses/` | Correct MariaDB version and LGPL paths; preserve supplemental third-party text with source URLs and hashes. |
| Header correction | Three `docker-compose/docker-compose.*.yml` files and `fe/fe-core/src/test/java/org/apache/doris/master/ReportHandlerTest.java` | Maintainer confirmed independent authorship. Removed ASF contributor-agreement statement while retaining the existing Apache 2.0 grant; company ownership remains unverified. |
| Java header checks | `fe/check/checkstyle/checkstyle.xml`, `dist/headers/apache-2.0.txt` | Check the independent test's generic Apache header separately; keep upstream checks for other Java files. |
| BE presentation | `be/src/http/web_page_handler.cpp`, `be/src/http/default_path_handlers.cpp` | Match image alternative text to MassDB SQL and label Apache Doris documentation as an upstream reference. |
| Verification | `ui/scripts/legal-notices.test.cjs`, `build-support/test_product_notices.py` | Public routing/browser checks and artifact validation with failure cases. New test-file licensing remains pending. |
| Planning and evidence | `docs/massdb-sql-copyright-productization-plan.md`, `docs/massdb-sql-copyright-review-evidence.md`, `MODIFICATIONS.md` | Implementation status, historical source inventory and release requirements. |

Only modification-notice comments were added to the other historical text files
listed above; no database execution behavior is changed by those annotations.
A historical new path is not evidence of company ownership. Asset evidence,
upstream cherry-pick mapping, new-code licensing and complete FE/BE release
validation remain open as recorded in the plan.


## Pre-commit review corrections (2026-09-06)

- `build-support/prepare-product-notices.py`, `build.sh`, `env.sh`: assemble FE
  notices from the pinned local MariaDB source archive; validate Python and
  Node/npm before dependency compilation. Custom/headless UI paths need no Node.
  Source archives use Git export metadata or an explicit source reference;
  development builds may report `unknown` instead of inventing a commit.
- `dist/sources/`, `dist/source-version.json`, `.gitattributes`, `.gitignore`:
  retain corresponding LGPL source and support source-archive provenance.
- `build-support/check-source-headers.py`, `dist/source-headers.json`,
  `.licenserc.yaml`, `.github/workflows/license-eyes.yml`,
  `fe/check/checkstyle/checkstyle.xml`, `dist/headers/apache-2.0.txt`:
  validate registered transition headers, existing Apache grants and unchanged
  upstream headers. New independent Java uses a `massdb/` path segment and the
  complete generic Apache or company/SPDX template. `build-for-release.sh`
  rejects unresolved licensing and unknown source references.
- `docker/compilation/Dockerfile.ui` supplies a separate supported UI toolchain;
  legacy `Dockerfile`, `Dockerfile.gcc7`, `Dockerfile.gcc10` and `arm/Dockerfile`
  retain their native compiler environments and document the UI split.
- `ui/src/components/legal-footer/index.tsx`, `ui/src/constants/branding.ts`,
  `ui/src/index.html`, `ui/scripts/collect-bundled-licenses.cjs`:
  hide unconfirmed company-specific scope wording while keeping MariaDB notices,
  identify route segments case-sensitively from the end, and use the configured
  notice Python interpreter.
- `build-support/test_product_notices.py` and `ui/scripts/legal-notices.test.cjs`
  add offline/source archive, toolchain, attribution and ambiguous-prefix cases.
- `AGENTS.md`, `ui/README.md`, `docker/README.md`, the implementation plan and
  evidence appendix document the toolchain, transition state and review results.

The four historical independent files already contained Apache 2.0 license
language before this work. Its retention is an engineering preservation choice,
not verification of the original grant's authority or corporate ownership.
The source-header registry records pending new-file licensing separately.

## Full package build correction (2026-09-06)

- `build-for-release.sh`: copy the FoundationDB tools before compression so
  the archive includes the same tools as the unpacked release directory.

## Login footer presentation (2026-09-06)

- `ui/src/pages/login/index.tsx`, `ui/src/pages/login/index.less`,
  `ui/src/components/legal-footer/index.tsx` and `index.less`: extend the login
  background across the page and use a transparent, wrapping footer without a
  divider. Keep all runtime attributions and license links visible, with the
  existing footer appearance on business pages.

## Isolated package rebuild (2026-09-06)

- `build.sh`: honor `--output` when copying Cloud and FoundationDB tools so a
  rebuild into a fresh directory does not replace the default output files.

## Distribution artifact review (2026-09-06)

- `ui/src/pages/legal-notices/index.tsx` and `ui/scripts/legal-notices.test.cjs`:
  require plain-text notices and reject successful HTTP responses containing
  HTML/JSON error bodies; verify recovery after a missing notice is restored.
- `build.sh`: copy common declarations into Cloud output and include distribution
  notices, product/upstream version mapping and scoped native-link evidence.
- `build-support/prepare-product-notices.py`, `build-support/test_product_notices.py`:
  require clean known source provenance for release, and inventory actual Java
  archives, nested archives, embedded notices and Maven declarations offline.
  SBOM generation does not mark license review complete.
- `dist/LICENSE-dist.txt`, `dist/NOTICE-dist.txt`, `dist/licenses/`,
  `dist/binary-license-evidence.json`, `dist/native-link-evidence.json` and
  `dist/RELEASE-NOTES.txt`: record FoundationDB 7.1.57/7.3.69, Debezium 1.9.8.Final,
  Jindo binary license uncertainty and evidence scoped to the reviewed ARM64
  executables. Keep conditional native dependencies in the build catalog.
- `.gitignore`: exclude the local `.claude/` tool directory without inspecting it.
- The implementation plan, review appendix and dated package review record retain
  unresolved rights decisions and distinguish historical artifacts from current
  source validation.

## Authenticated footer presentation (2026-09-06)

- `ui/src/pages/layout/index.tsx`: use the transparent, compact footer throughout
  the authenticated layout, including Playground and QueryProfile. Let the page
  background continue behind the footer, remove its divider, and wrap runtime
  attributions without hiding copyright text or license links.

## Company attribution (2026-09-06)

- `NOTICE.txt`, `dist/product-provenance.json`: enable the maintainer-requested
  2026 attribution for company-owned modifications and original additions, using
  the Chinese and English company names. Retain all existing upstream notices;
  this attribution does not select a license for the pending independent files.
- `build-support/prepare-product-notices.py`, `build-for-release.sh`:
  derive the company addendum from product metadata and verify the source NOTICE
  during UI generation and release preflight. Include NOTICE at the release root;
  existing component and FE legal packaging also carry the company addendum.
- `build-support/test_product_notices.py`, `ui/scripts/legal-notices.test.cjs`:
  check metadata drift, missing company attribution despite updated hashes,
  public NOTICE access, and company display in both authenticated UI languages.
- `ui/README.md` and the implementation/review documents record attribution
  maintenance and distinguish customer materials from internal build evidence.

## Minimal installation package (2026-09-06)

- `build-support/prepare-product-notices.py`: assemble a new full installation
  from unchanged component inputs, retain runtime files and applicable legal
  materials, and store SBOMs, link evidence, source history, checksums and separate
  debug symbols in an external audit directory. Remove UI audit inventories from
  the delivered FE JAR and verify its remaining assets against the build inventory.
- `build.sh`, `dist/LICENSE-dist.txt`: stop copying historical native-link reports
  into components and remove the catalog's dependency on an on-disk evidence file.
- `build-for-release.sh`: use an isolated output directory, propagate the product
  version into the build, include Hive UDF, and use the common package assembler.
- `dist/RELEASE-NOTES.txt`, `ui/public/locales/en-us.json` and `zh-cn.json`:
  retain concise product modification and source-access explanations; keep
  internal implementation history out of the installed UI and package root.
- `build-support/test_product_notices.py`: exercise package input preservation,
  exclusion of audit files and separate symbols, required notices and sources,
  rejection of live data, and validation of FE assets after inventory removal.

The full package retains one shared set of plain-text license materials under
`fe/legal/`; normal component builds keep their own declarations for independent
distribution. No runtime library is stripped or removed by this packaging step.

## Build output retention (2026-09-06)

- `build-for-release.sh`: remove the current build's temporary component copies
  only after successful assembly and archive checks. Stage builds outside output,
  compress audit records and symbols under `.build-records/`, and publish only the
  final package/archive/checksum to `output/`. Refuse existing destination paths
  and stop immediately on build failure, preserving inputs for diagnosis.
- `ui/scripts/collect-bundled-licenses.cjs`, `ui/scripts/legal-notices.test.cjs`
  and `ui/README.md` use `.build-records/ui/` for build evidence and screenshots.
- `.gitignore`, `.licenserc.yaml`, `AGENTS.md` and the distribution guide separate
  internal records from deliverables and protect local installations and database
  state during cleanup. Path migrations and subsequent maintainer-requested
  deletion of the old installations and their data are recorded separately;
  historical installation copies are not retained by default.

## Playground layout (2026-09-06)

- `ui/src/pages/layout/` and `ui/src/pages/playground/`: size the SQL workspace
  between the navigation and runtime footer, align its panels and toolbars, and
  remove independent viewport heights and fixed search positioning. Keep the
  database tree and query results scrollable inside their panels.
- The database search and refresh controls occupy separate accessible controls;
  sidebar dragging updates the layout column and editor width, and narrow windows
  stack the tree above the editor. Existing upstream headers remain unchanged.
- `ui/scripts/legal-notices.test.cjs` checks panel/footer geometry, search/refresh,
  tree scrolling and sidebar resizing alongside the existing notice checks.
