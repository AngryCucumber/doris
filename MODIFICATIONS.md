# MassDB SQL Modifications

MassDB SQL is derived from Apache Doris. Upstream source baseline: `917b20be83878e98f94e3ebf7efccc80346e3e50` (`4.1.5-release`), verified against the [Apache repository](https://github.com/apache/doris/commit/917b20be83878e98f94e3ebf7efccc80346e3e50) on 2026-10-28.

This inventory describes distribution changes, not a claim that all changes are owned by the company. Original Apache and third-party notices remain applicable. It supplements modification notices within editable files; it does not replace those notices.

## Doris 4.1.5 baseline and MassDB 2.0.5-rc415 (2026-10-28)

- Base branch `4.1.5` on upstream tag `4.1.5-release`; migrate the product
  changes from `2.0.5` at `5d034e7c8b378d1a9e324f0cff5a57e42ddf625f`.
  Product numbering remains independent: `massdb-sql-2.0.5-rc415` for packages
  and `massdb-2.0.5-sql-rc415` for runtime product identification.
- Preserve Group Commit RPC deadlines, restart handling, report deduplication,
  per-backend report workers, storage-medium caching, compaction safeguards,
  metadata-tool startup initialization, JDBC array fidelity and product UI.
- Adapt the report-diff executor rejection policy to `LocalTabletInvertedIndex`;
  preserve the upstream abstract `TabletInvertedIndex` and its cloud implementation.
- Retain upstream Group Commit fixes #60652/#61555 (included by #61953) and
  the already-applied aborted-load locking fix #61881. These replace local
  backport commits `3d3b870a175`, `508fb026de8` and `5abf4fdd0d5`.
- Retain upstream bound-reader splitting #63138/#65687 and the CLucene
  multi-segment `readBlock` implementation #66736/#66738. These supersede
  local workarounds `597b5e8ebde`, `88078697871` and `c416a6f7bfb`; preserve
  upstream NestedGroup and scoring behavior.
- Preserve upstream JDBC timestamp/time-zone fixes and detection of Doris,
  SelectDB and VeloDB while adding MassDB detection and exact array decoding.
- Migrate BE modifications and source-header registrations from `http`, `olap`
  and `vec` to the upstream `service/http`, `storage` and `exprs` paths.
  Keep the upstream removal of the obsolete GCC 7 image and its newer build
  module, profiling and License Eyes workflows.
- Update active source provenance and release notes. Earlier sections and
  dated binary/package review evidence describe the original 4.0.5-based
  packages; their hashes and verification results do not describe rc415.
- Add JDBC unit coverage for exact large integers and decimals, signed zero,
  nested NULL arrays, NULL dates/booleans, timestamp fractions at precisions
  0–6 and MassDB recognition under a Turkish default locale.

Validation for this migration (2026-10-28/29; local evidence retained):

- Candidate and pristine upstream FE/BE product builds passed with the same
  JDK 17, Clang toolchain, Release configuration and SSE4.2 instruction mode.
  Rebuilt or upgraded the native dependencies required by 4.1.5, including
  Thrift 0.24.0, Arrow 24, simdutf, libunwind and the Rust readers.
- FE validation reconciled 10,902 distinct cases: 10,824 passed and 78 skipped.
  Exact numeric/JDBC values, nested arrays, timestamp precision, report queue
  interruption and storage-medium cache invalidation have targeted coverage.
  Controlled DNS cases passed for both candidate and upstream.
- The complete Release BE inventory executed 11,276 cases. After fixture
  corrections, 11,203 passed, 55 skipped and 18 failed. Seventeen failures
  require debug assertions and pass in the ASAN build; the remaining Release
  stack-trace failure reproduces with unchanged upstream tracing code and
  passes in ASAN. The ASAN inventory reconciles 11,278 distinct cases: 11,221
  passed and 57 skipped across the initial run, continuation and focused
  retries. Preserve the initial abort and failure records; complete Variant
  and CDC/ThreadPool suites pass after fixing their shared-state contamination.
- Java Checkstyle, 36 product/release Python tests, the UI production build,
  notice/browser checks and source-header checks passed. The regression
  framework's 39 tests pass, including shared local fixture preparation,
  export-directory cleanup and SSH argument handling.
- Live tests passed for storage cooldown and metadata changes, synchronous
  and asynchronous group-commit failover, publish failure cleanup, metadata
  CLI/restart round trips and all four candidate compaction/index combinations.
  The pristine horizontal/index-enabled compaction failure remains recorded.
- The complete local SQL regression executed 6,602 suites: 6,378 passed and
  224 failed in the initial run. After fixture corrections and isolated retries,
  6,577 pass and 25 remain failed. Seven require object-store fixtures returning
  HTTP 403; the other 18 have matching pristine-tag errors, results or capacity
  limits. This is a reconciliation across runs, not an all-green full run.
  Original failures and SQL goldens are retained.
- This local selection excludes P2/P3 groups and suites requiring unavailable
  external systems, Docker orchestration, Cloud/vaults, large benchmark datasets
  or restart orchestration. Selected workload-manager and failover cases were
  exercised separately. The original command and exact exclusion manifest are
  retained in `sql-regression/candidate-full-legacy-configured.json`; 6,602 is
  the selected local inventory, not every suite in the upstream repository.
- The remaining baseline cases comprise eight HBO fixtures referring to the
  absent `hbo_slow_query_threshold_ms` setting, one native AWS anonymous-read
  timeout, three query/PLSQL result or error differences, four TPC-DS Q24 golden
  mismatches, one DDL/counter verification suite, and the original 200-million-row
  window case. The window fails at the same 16 GiB query limit in both products;
  its original scale still needs a larger-memory host. Host-side S3 HEAD/GET
  succeeds, so the native-client timeout is not classified as endpoint downtime.
  HBO assertions after the missing setting remain unvalidated by those fixtures.
- Pristine controls reproduce all 14 CREATE and 12 RECREATE/ALTER observations
  and negative native writer counters after the original fault-injection suite.
  Both products also reuse a cached built-in result after changing UDF preference
  once SQL-cache eligibility is reached; fresh/cache-disabled UDF controls pass.
  These baseline findings are recorded without changing production cache logic.
- Two complete ABBA performance series ran on the same 32-CPU, 23-GiB host,
  each using fresh 1-FE/3-BE clusters, five measured rounds per block and the
  same checksum-verified TPC-H SF1 input. One series retained the optional
  Release symbols; the other matched slim-package deployment without them.
  Binaries, configuration templates and workloads were unchanged between series.
  Every query result hash matches across all eight blocks. All write row counts,
  distinct keys and amount totals match. Candidate compaction passes 80/80 cases;
  pristine horizontal/index-enabled compaction fails 20/80 with the same index
  error. Invalid baseline results are excluded from timing comparisons.

Slim-deployment medians (ten measured samples per product; query total is the
sum of 22 SQL elapsed times within each round):

| Measurement | Pristine 4.1.5 | MassDB rc415 | Candidate change |
| --- | ---: | ---: | ---: |
| TPC-H SF1 query round | 1.5314 s | 1.5102 s | -1.39% |
| 40,000 rows visible, Group Commit off | 6.7306 s | 6.7690 s | +0.57% |
| 40,000 rows visible, synchronous Group Commit | 8.0995 s | 8.0415 s | -0.72% |
| 40,000 rows visible, asynchronous Group Commit | 0.8976 s | 0.8834 s | -1.58% |
| FE CPU per completed tablet report | 0.1460 CPU-s | 0.1534 CPU-s | +5.04% |
| Completed tablet reports per second | 1.0295 | 0.9984 | -3.02% |

- Neither series triggered the investigation rule of more than 10% and 10 ms
  median latency growth in both order pairings. This is a triage threshold,
  not proof of zero regression. Per-round samples, p95, variation, individual
  query results and all observed changes remain available in the local records.
  Report CPU per completion rises 1.82%/10.73% in the two slim pairings; total
  FE CPU medians are equal at 5.055 CPU-seconds. Reports complete approximately
  once per second under this workload, despite more frequent HTTP triggers.
  Every BE completes reports in every round and end-of-round queues are zero.
  This workload does not establish a production report-throughput capacity.
- Slim-deployment simultaneous BE RSS peaks differ from upstream by -1.44% to
  +2.04% across phases/order pairings; no FE or BE peak exceeds upstream by 10%
  in both pairings. Loading the optional split symbols adds about 300-400 MiB
  RSS per BE and indexes about 1.03 million symbols instead of 56 thousand.
  Removing only those files from runtime lookup paths removes the fixed increase.
  RSS includes shareable file mappings and is not exclusive physical memory.
  Deploy matching symbols when detailed stack names justify this overhead.
- Host paging was observed: the slim series records 1.26/4.68 MiB swap-in and
  16.50/10.69 MiB swap-out during upstream/candidate phases. One-second process
  samples show zero VmSwap for every tested FE/BE. These are shared-host
  measurements with SF1 data, not a production sizing or tail-latency guarantee.
- Full Cloud/FDB runtime validation and a complete rc415 release package remain
  outstanding. The changed Cloud version metric has focused compile/link/runtime
  coverage only. The original `2.0.5` branch is unchanged; this work is local to
  `4.1.5` and has not been pushed.

Detailed machine-local evidence is under `.build-records/rc415-full-validation/`:
`fe-archive-reconciliation.json`, `be-release-aggregate.json`,
`be-asan-inventory-reconciliation.json`,
`sql-regression/candidate-suite-reconciliation.json`,
`sql-regression/remaining-suite-classification.json`,
`performance-comparison.json`, `performance-slim-comparison.json`, and
`final-performance-summary.json`. Original failures are preserved alongside
successful retries; the two performance series are never pooled together.

## rc415 code review fixes (2026-10-28)

Fixes for findings 1-9 of `docs/massdb-sql-rc415-code-review-20261028.md` that
belong to this branch. Findings P1-P8 are inherited from 4.1.5 and unchanged.

- `Env.java`, `Config.java`: the storage-medium map rebuild no longer waits for
  busy table locks while every report worker is queued on the build lock. The
  scan and the cooldown phase each share one 100 ms lock-wait budget across all
  tables, so many busy tables cannot add 100 ms each; once a phase's budget is
  spent, later busy tables are tried without waiting. A skipped table, or an
  expired SSD partition whose write lock is unavailable, marks the map
  incomplete; it is logged and reused only for `storage_medium_map_retry_second`
  (default 5, 0 rebuilds on the next report). Expired partitions no longer set
  the next cooldown deadline, so a failed cooldown no longer rebuilds on every
  report. The scan still records the metadata version before it starts; a
  completed cooldown changes metadata and causes one more scan.
- `LocalTabletInvertedIndex.java`: the cooldown replica check iterates a copy of
  the tablet's replicas taken under the index lock, because it runs after the
  report releases that lock while another report worker may delete a replica.
- `JdbcMySQLClient.java`: Doris type arguments are read up to the first closing
  parenthesis. `DECIMAL(p)` maps to scale 0. Empty, overflowing or extra
  arguments and a scale above the precision are malformed. A malformed top-level
  declaration uses the column's JDBC metadata as before this branch; a malformed
  array element maps to an unsupported element instead of the outer metadata.
- `ui/src/index.html`: the deployment prefix ends before the first route segment
  from which the remaining path is a complete route, so database or table names
  equal to route names (`/Playground/result/home`) no longer become the prefix.
  Prefixes containing route names keep working. Paths without a known route keep
  the upstream four-segment rule. A path that is both a valid route and a prefix
  plus a route, such as `/QueryProfile/home`, is read as the route.
- `GroupCommitPlanner.java`, `Config.java`: the prepared group-commit insert RPC
  waits at most the internal group-commit load timeout
  (`max(group_commit_interval_ms * group_commit_timeout_multipler, 600 s)`) plus
  `group_commit_insert_rpc_timeout_second` (default 300), capped by the insert
  timeout, instead of up to `insert_timeout`. The BE request is not cancelled
  (P3): rows of a timed-out insert can still be written after the error, so
  clients must not retry such an insert blindly.
- `Suite.groovy`: local fixture copies quote both paths, and a host name that
  only the SSH client can resolve is copied with scp instead of failing.
- `AgentTaskCleanupDaemon.java`: remove the unreachable null `succTablets`
  branch; 4.1.5 `PublishVersionTask` already defaults and normalizes the map.
- `HardwareInfoController.java`: remove the unused process listing method and
  its imports; the process row stays hidden.
- Restore the upstream text of `AgentTaskCleanupDaemon.java`,
  `PublishVersionTask.java`, `TabletInvertedIndex.java`, `GroupCommitManager.java`,
  `Coordinator.java`, `CloudGlobalTransactionMgr.java` and
  `multi_segment_util.h`, whose only difference from 4.1.5 was the modification
  or backport notice, and remove them from `dist/source-headers.json`.

Validation (2026-10-28, local evidence in `.build-records/rc415-review-fixes-20261028/`):
new FE tests fail on the previous code and pass now; 172 affected FE test classes
(1005 tests) pass with 4 skipped; Checkstyle, source headers, 35 notice tests, 41
regression-framework tests and the UI build, notice and browser tests pass. A
live FE built from this tree with the upstream 4.1.5 release BE cooled SSD
partitions to HDD, mapped JDBC catalog types and data exactly, rendered Playground
pages for databases named `home` and `Session` with and without a prefix (blank
with the previous script), and released a hung prepared group-commit insert after
605 s. BE, Cloud meta-service, `meta_tool` and the BE Java extensions of this tree
also build on this host against a locally built 4.1.5 third-party set; with that
BE the live checks pass again, the `meta_tool` round trip passes, and vertical and
horizontal compaction keep row and inverted-index counts. Concurrency follow-up:
two-thread stress tests for the storage-medium map and the cooldown replica check
(the latter fails with ConcurrentModificationException on the previous code),
three BEs reporting in parallel through three report workers during concurrent
DDL, and eight prepared group-commit inserts hung together, all released at 605 s
while the FE kept serving queries. Cloud mode runtime was not exercised.

## rc415 regression hardening (2026-10-28)

- Restore the process-wide SIGCHLD handler after each CDC client unit test.
  The upstream fixture otherwise leaves its child reaper installed, which can
  consume a later GoogleTest death-test child and abort the complete ASAN run.
  Preserve CDC production behavior and the existing death-test assertions.

- Match the existing local-FE behavior when preparing Java UDF fixtures for
  local BEs: verify the JAR exists and skip SSH/SCP to the same host and path.
  Deduplicate remote BE hosts before copying, preserving remote preparation.
  Generic fixture copies also use local paths for the current operating-system
  user, preserve same-file copies and retain SSH for remote or different users.
  Prepare and remove shared local export directories without requiring SSH;
  deduplicate backend addresses without modifying the map's collection view.

- Use the existing 4.1.5 base-table-unawareness session variable in the external
  DML materialized-view fixture, retaining its enabled/disabled rewrite checks.

- Exercise the BE workload queue with a table scan in its rejection fixture.
  Upstream 4.1.5 can answer a simple COUNT from FE metadata without entering
  that queue. Preserve the rejection assertion and production optimization.

- Enable partition analysis globally and run the fixture through a new connection
  so the planner inherits this global-only setting; restore the original default
  afterward. Reset global
  variables before resetting the session in UNSET tests so earlier suites do
  not determine the expected default values.

- Place each local cumulative-compaction delay fixture table on all participating
  BEs. The concurrency limit is per BE; distributing single-replica tables across
  different BEs cannot saturate the intended shared pool. Preserve cloud replica
  settings and the existing rowset-count assertions. Run this case with the
  upstream P0 large-task concurrency configuration enabled.

- Declare commit fault-injection fixture variables locally so the framework
  can execute its three-replica commit checks instead of rejecting global
  variable assignments before the first load.

- Scope catalog-recycle assertions to the fixture database ID, reset only
  that database on retries and compare the same partition before/after each
  deletion. Global partition names can otherwise select another suite's IDs
  and delete unrelated test metadata during parallel regression runs.

- Parse warehouse byte counts as 64-bit values in the SQL regression fixture,
  so a full test cluster with more than 2 GiB of data does not overflow the
  fixture's 32-bit parser. Retain the existing SQL and size assertions.

- Give the HNSW inner-product range test a search budget covering its 500
  vectors before comparing its result count with an exact index. Keep the
  count tolerance and distance assertions unchanged; production ANN defaults
  and algorithms are unchanged.

- Correct the Variant fixture to honor the documented "create if missing"
  root operation for an existing scalar root. Verify that its root, type and
  all 1,756 row values remain unchanged. Run resize operations on a clone so
  they do not replace the shared JSON fixture with ten default rows before
  later cases execute; the production Variant implementation is unchanged.

- Validate complex-column `get_data_at` pointers, extents and values, and compare
  canonical quantile-state payloads after local protobuf round trips. These tests must
  not compare object padding or owning pointers as serialized data.

- Correct two upstream BE test fixtures: allow the TDigest input distribution
  to produce zero while checking quantile bounds and monotonicity; declare the
  ORC date slot as DATEV2 to match its serialized DATEV2 expressions and assert
  the actual 1994 date offsets from the Unix epoch. Production algorithms are
  unchanged by these fixture corrections.

- `ReportHandler`: use non-interruptible insertion into the unbounded report
  queue. An interrupted RPC thread must not leave a pending deduplication key
  without a queue entry, which would prevent subsequent reports from being
  consumed. Add a regression test that reproduces the interrupted enqueue.
- `Env`, `PartitionInfo`, `DataProperty`, `Database` and `InternalCatalog`:
  invalidate the storage-medium cache on partition/storage changes and catalog
  membership changes. Bound reuse by the next SSD cooldown deadline as well as
  the configured TTL. A metadata change during a scan or an expired partition
  whose write lock times out prevents reuse of the incomplete snapshot.
  Preserve the existing cooldown mutation and edit-log behavior.
- `StorageMediumMapCacheTest`: cover metadata replacement, in-place storage
  changes, table registration/removal, disabled caching, cooldown expiry,
  write-lock timeout retry, changes during publication and concurrent report
  workers sharing a single catalog scan.
- `CompactionMixin`: replace input-profile counters when rebuilding basic
  information after ordered compaction falls back to a normal merge. Add a
  regression test for both the input totals and profile counters so a retry
  cannot report twice the rows, segments or bytes.
- `SymbolIndex`: recognize the split symbols installed by the Release build
  under `lib/debug_info/<binary>.dbg`, preserving the existing `.debug` search
  locations. Stripped service binaries otherwise return stack addresses without
  the pipeline/operator names required by the live stack-trace API test.
  This optional deployment increases BE RSS by about 300-400 MiB in the measured
  build; the slim package excludes the separate debug files.
- BE and Cloud version metrics: export the same MassDB product identifier as
  FE metrics, HTTP responses and heartbeat messages. Preserve command-line
  build identifiers and exact numeric/hash assertions in the metric tests.
- `MetricsTest`: adapt the upstream version-metric assertion to the MassDB
  product identifier already exported by `MetricRepo`, while retaining exact
  checks for numeric build labels, short commit hash and metric value.
- `meta_tool`: initialize the schema cache and column object pool before
  deserializing tablet metadata in a standalone process. Add a CLI regression
  test that loads a real schema into an isolated metadata directory and reads
  it back in a separate process; an empty directory alone missed the crash.
- `CollectionStatisticsTest`: initialize the mock literal's expression node
  type. Reusing memory from a slot-reference mock otherwise makes the collector
  cast a literal to `VSlotRef`, crashing the full unit suite even though the
  isolated missing-slot test passes.
- `LocalFileSystemTest`: create glob fixtures under the configured secure file
  directory so the same traversal and matching assertions work with an
  independent `CMAKE_BUILD_DIR`, including Release and ASAN test builds.
- `SegmentCacheTest` and `TabletCooldownTest`: disable and restore the separate
  disk file-cache option around fixtures that do not install a disk-cache
  factory. Preserve segment loading, memory accounting, sequence-column and
  remote-cooldown assertions while allowing reads and tablet cleanup to complete.

## Bundled Python runtime prototype (2026-10-29)

- Add `build-support/python-runtime/`. `build-python-runtime.py resolve` fetches a
  pinned python-build-standalone interpreter and the wheels of the configured
  layers (manylinux tags up to the target glibc) and writes a hash-pinned lock;
  `build` installs only that lock offline into a relocatable
  `python_env_mode = conda` root and packs a reproducible tarball for `be/lib/`.
- `check-python-runtime.py` verifies the env-root layout BE scans at startup,
  symlinks, ELF architecture, GLIBC/GLIBCXX symbol versions and 64 KiB page
  alignment, imports, an Arrow Flight UDF call through
  `be/src/udf/python/python_server.py` and the license inventory.
  `python-runtime.json` holds the pins and policies; `test_python_runtime.py`
  covers both scripts with synthetic ELF files and layouts.
- Target glibc 2.17 like the BE: only manylinux2014 wheels, with GLIBCXX 3.4.19
  and CXXABI 1.3.7 enforced for the operating-system libstdc++ the runtime
  uses (the BE links libstdc++ statically). pyarrow is pinned to 20.0.0, the
  newest release with manylinux2014 aarch64 wheels.
- Extend the default layers so common UDF needs work offline: pandas
  accelerators, networkx, sympy, xgboost and lightgbm (`analytics`); HTTP,
  HTML/XML, Chinese conversion and calendars, serialization, SM2/SM4 and other
  crypto, geo/IP/UA parsing and validation (`extended`); polars and duckdb
  (`engines`). GPL packages and those without glibc 2.17 wheels are left out.
  Upstream license texts are fetched by sha256 for wheels that ship none, and
  the check lists the symbol versions each operating-system library must provide.
- Prototype only: package assembly, `be.conf`, `start_be.sh` and the legal
  inventory are unchanged, so product behavior is unchanged.

## UI lockfile for the 4.1.5 axios update (2026-10-29)

- Regenerate the axios subtree of `ui/package-lock.json` for upstream's
  `axios ^1.16.0` (#63983): the lock carried over from the 4.0.5-based 2.0.5
  line still pinned axios 0.19.2, so `npm ci` and therefore `build.sh` /
  `build-for-release.sh` failed on a clean host. Only axios and its
  dependencies change (axios 1.21.0, follow-redirects 1.16.2, form-data,
  proxy-from-env, https-proxy-agent and their dependencies); resolved URLs
  stay on registry.npmjs.org. The UI source does not import axios, so the
  bundled component inventory and legal pages are unchanged.

## Complete rc02 release builds (2026-09-09)

- `build-for-release.sh`: explicitly select FE, BE, Cloud/MS, Broker and Hive UDF
  for the full build. Apply `--clean` to those selected components so Cloud is
  rebuilt as well; passing only `--output` previously selected no components.
  Preserve both AVX2 variants and add a validated `-j` option for the full build
  and the subsequent BE metadata-tool build on hosts with limited memory.
- `build-support/test_product_notices.py`: exercise the real component argument
  parser from the release fixtures. Verify complete component selection, clean
  rebuilds, CPU mode, job limits, invalid job counts and failure before publication.

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
