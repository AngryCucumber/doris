# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Apache Doris is a high-performance MPP (Massively Parallel Processing) analytical database for real-time analytics on large-scale data. It supports both storage-compute coupled and storage-compute separated (cloud) deployment modes.

### Main Components

- **FE (Frontend)** — Java 17. Query coordination, SQL parsing, query planning (Nereids CBO optimizer), metadata management, catalog services. Located in `fe/`.
- **BE (Backend)** — C++20. Columnar storage engine, vectorized query execution, pipeline execution engine. Located in `be/`.
- **Cloud** — C++. Cloud-mode meta-service for storage-compute separated architecture (backed by FoundationDB). Located in `cloud/`.
- **Broker** — Java. Reads data from external storage (HDFS). Located in `fs_brokers/`.

FE and BE communicate via Thrift and Protocol Buffers (IDL definitions in `gensrc/thrift/` and `gensrc/proto/`).

## Build Commands

Requires: JDK 17, Maven, CMake, Ninja, clang (default compiler), flex >= 2.6.0. Third-party libraries must be pre-built in `thirdparty/` (use `thirdparty/build-thirdparty.sh`).

```bash
# Build everything (FE + BE + Broker)
sh build.sh

# Build individual components
sh build.sh --fe
sh build.sh --be
sh build.sh --cloud
sh build.sh --broker
sh build.sh --be -j 16              # parallel BE build

# Additional build targets
sh build.sh --be-java-extensions     # BE Java extensions (JDBC, Hive, Iceberg scanners, etc.)
sh build.sh --hive-udf              # Hive UDF library
sh build.sh --meta-tool             # metadata tool
sh build.sh --index-tool            # index tool
sh build.sh --benchmark             # benchmark tool

# Clean build
sh build.sh --fe --clean
sh build.sh --be --clean

# Environment variables
USE_AVX2=0 sh build.sh --be                        # disable AVX2
STRIP_DEBUG_INFO=ON sh build.sh --be                # strip debug info
DISABLE_JAVA_CHECK_STYLE=ON sh build.sh --fe        # skip Java checkstyle
DISABLE_BE_JAVA_EXTENSIONS=ON sh build.sh --be      # skip BE Java extensions
DISABLE_BUILD_AZURE=ON sh build.sh --be             # disable Azure support
```

## Running Tests

### BE Unit Tests (Google Test)

```bash
# Build and run all BE tests
sh run-be-ut.sh --run

# Run specific test suite
sh run-be-ut.sh --run --filter=FooTest.*

# Run specific test, exclude others
sh run-be-ut.sh --run --filter=FooTest.*-FooTest.Bar

# Debug with gdb
sh run-be-ut.sh --run --gdb --filter=FooTest.*

# Coverage
sh run-be-ut.sh --clean --run --coverage
```

Test files must use `_test` suffix and be registered in `be/test/CMakeLists.txt`. Results go to `be/ut_build_ASAN/gtest_output/`.

### FE Unit Tests (JUnit / Maven)

```bash
# Build and run all FE tests
sh run-fe-ut.sh

# Run a specific test class
sh run-fe-ut.sh --run org.apache.doris.utframe.Demo

# Run a specific test method
sh run-fe-ut.sh --run org.apache.doris.utframe.Demo#testCreateDbAndTable

# Multiple tests
sh run-fe-ut.sh --run org.apache.doris.Demo,org.apache.doris.Demo2

# Coverage
sh run-fe-ut.sh --coverage
```

### Regression Tests (Groovy framework)

```bash
# Run all regression tests
sh run-regression-test.sh

# Run a specific suite
sh run-regression-test.sh --run test_select

# Run a specific directory
sh run-regression-test.sh --run -d demo,correctness/tmp

# Generate expected output
sh run-regression-test.sh --run test_select -genOut

# Parallel execution
sh run-regression-test.sh --run -parallel 4
```

Config: `regression-test/conf/regression-conf.groovy`. Logs: `output/regression-test/log/`. There are 200+ test suites under `regression-test/suites/` organized by feature and priority level (p0, p1, p2).

### Cloud Unit Tests

```bash
sh run-cloud-ut.sh
```

## Code Formatting & Linting

### C++ (clang-format 16 required)

```bash
# Format BE/Cloud code
build-support/clang-format.sh

# Check without modifying
build-support/check-format.sh
```

Config: `.clang-format` — Google-based, 100-char line limit, 4-space indent, 8-space continuation indent, pointers left-aligned.

Ignored paths (`.clang-format-ignore`): `be/src/apache-orc/*`, `be/src/clucene/*`, `be/src/gutil/*`, `be/src/glibc-compatibility/*`, select utility files, `cloud/src/common/defer.h`.

Static analysis: `.clang-tidy` is configured with `clang-diagnostic-*`, `clang-analyzer-*`, `bugprone-*`, `modernize-*`, `readability-*`, and `misc-*` checks (with select exclusions).

### Java (Maven Checkstyle)

Checkstyle runs automatically during FE build. Config: `fe/check/checkstyle/checkstyle.xml` (120-char line limit). Suppress with `// CHECKSTYLE OFF` / `// CHECKSTYLE ON` comments. Skip with `DISABLE_JAVA_CHECK_STYLE=ON`.

### Shell Scripts

```bash
build-support/shell-check.sh    # uses shellcheck + shfmt
```

### Editor Config

`.editorconfig` specifies: UTF-8 charset, LF line endings, 4-space indentation for Java/XML/Python/Shell files.

## Commit Message Convention

This project follows a structured commit message format:

```
[type](scope) brief description (#PR_number)
```

Common types: `fix`, `feature`, `improve`, `refactor`, `test`, `docs`, `chore`
Examples:
- `[fix](variant) fix variant column data_serdes not synced (#61096)`
- `[feature](bm25) support score range filter pushdown (#60997)`
- `[refactor](scan) extract scanner profile update logic (#61039)`

For cherry-picks to release branches, prefix with `branch-X.Y:`.

## Key Architecture Details

### FE Modules (`fe/pom.xml` multi-module project)

- **`fe-common`** — shared utility classes and common definitions
- **`fe-core`** — main FE process (SQL analysis, Nereids optimizer, catalog management, query planning, statistics)
- **`be-java-extensions`** — Java extensions loaded by BE via JNI:
  - `java-common` — shared utilities for extensions
  - `jdbc-scanner` — JDBC external table scanner
  - `hadoop-hudi-scanner` — Apache Hudi scanner
  - `iceberg-metadata-scanner` — Iceberg metadata reader
  - `paimon-scanner` — Apache Paimon scanner
  - `lakesoul-scanner` — LakeSoul scanner
  - `max-compute-scanner` — Alibaba MaxCompute scanner
  - `avro-scanner` — Avro format scanner
  - `java-udf` — user-defined functions in Java
  - `trino-connector-scanner` — Trino connector integration
  - `preload-extensions` — preloaded extensions
- **`hive-udf`** — Hive UDF library for ingestion

### FE Key Packages (`fe/fe-core/src/main/java/org/apache/doris/`)

- `nereids/` — Nereids CBO optimizer (see below)
- `datasource/` — multi-catalog/lakehouse framework (external catalog support)
- `catalog/` — internal catalog management (tables, databases, metadata)
- `analysis/` — SQL analysis and statement representation
- `planner/` — legacy query planner
- `qe/` — query execution coordinator
- `load/` — data loading (stream load, broker load, routine load)
- `transaction/` — transaction management
- `cloud/` — cloud-mode specific logic
- `mtmv/` — materialized views
- `statistics/` — table and column statistics for optimizer
- `job/` — job scheduling framework
- `backup/` — backup and restore
- `binlog/` — binlog for CDC
- `httpv2/` — HTTP REST API endpoints
- `plsql/` — PL/SQL stored procedure support
- `dictionary/` — dictionary feature support

### Multi-Catalog / Lakehouse (`datasource/`)

Doris supports querying external data sources through a multi-catalog architecture:
- `hive/` — Hive Metastore catalog (Hive, Spark tables)
- `iceberg/` — Apache Iceberg tables
- `hudi/` — Apache Hudi tables
- `paimon/` — Apache Paimon tables
- `jdbc/` — JDBC external databases (MySQL, PostgreSQL, Oracle, etc.)
- `es/` — Elasticsearch
- `maxcompute/` — Alibaba MaxCompute
- `lakesoul/` — LakeSoul tables
- `trinoconnector/` — Trino connector integration
- `kafka/` — Kafka data source
- `odbc/` — ODBC connections
- `infoschema/`, `systable/` — system catalogs

### Nereids Query Optimizer (`nereids/`)

The modern CBO (cost-based optimizer) is the primary optimizer:
- `parser/` — SQL parsing
- `analyzer/` — semantic analysis and binding
- `rules/` — transformation and implementation rules
- `cost/` — cost model
- `memo/` — memo structure (Cascades framework)
- `stats/` — statistics derivation
- `trees/` — plan tree representations
- `properties/` — logical and physical properties
- `pattern/` — plan pattern matching
- `jobs/` — optimization jobs
- `hint/` — query hints
- `processor/` — plan post-processing
- `types/` — type system

### BE Key Source Directories (`be/src/`)

- `olap/` — storage engine (tablets, rowsets, segments, compaction, schema change, memtable)
- `vec/` — vectorized execution engine:
  - `columns/` — column data structures
  - `core/` — block and core data types
  - `data_types/` — type system
  - `exec/` — vectorized execution operators (scan, join, aggregation, sort, etc.)
  - `functions/` — scalar and aggregate function implementations
  - `exprs/` — vectorized expression evaluation
  - `io/` — reader/writer for file formats (Parquet, ORC, etc.)
  - `json/`, `jsonb/` — JSON processing
  - `olap/` — vectorized storage engine operations
  - `runtime/` — runtime state and memory
  - `sink/` — data sink operators
  - `spill/` — spill-to-disk support
  - `aggregate_functions/` — aggregate function implementations
- `pipeline/` — pipeline execution engine:
  - `exec/` — pipeline execution operators
  - `local_exchange/` — local data exchange
  - `query_cache/` — query result cache
  - `shuffle/` — data shuffle
- `exec/` — legacy query execution operators
- `runtime/` — memory management, thread pools, runtime state
- `runtime_filter/` — runtime filters (Bloom, In, MinMax)
- `io/` — file I/O, external storage (HDFS, S3, Azure, GCS)
- `cloud/` — cloud-mode specific logic
- `exprs/` — expression evaluation
- `agent/` — tablet management agent
- `common/` — common utilities and status codes
- `http/` — HTTP server and handlers
- `service/` — Thrift/BRPC service implementations
- `util/` — utility functions
- `geo/` — geographic functions
- `glibc-compatibility/` — glibc compatibility layer

### Cloud Meta-Service (`cloud/src/`)

The cloud component provides metadata and resource management for storage-compute separated mode:
- `meta-service/` — core metadata service (transaction, tablet, rowset management)
- `meta-store/` — metadata storage abstraction (backed by FoundationDB)
- `recycler/` — data garbage collection
- `resource-manager/` — compute resource management
- `rate-limiter/` — request rate limiting
- `snapshot/` — metadata snapshots
- `common/` — shared utilities

### Generated Sources

`gensrc/` contains Thrift (27 files) and Protobuf (12 files) IDL definitions. Run `make` in `gensrc/` to regenerate (the main `build.sh` handles this automatically). Key definitions:
- `FrontendService.thrift`, `BackendService.thrift` — FE-BE RPC interfaces
- `PlanNodes.thrift` — query plan node definitions
- `cloud.proto` — cloud meta-service protocol
- `internal_service.proto` — internal BE-BE communication
- `olap_file.proto`, `segment_v2.proto` — storage format definitions

## Regression Test Authoring Guidelines

- Use `def` for all local variables (bare assignment creates globals that leak across parallel tests)
- Do not set global session variables (`set global ...`); use session-scoped `set` instead
- If global state changes are required, mark the test as `nonConcurrent`
- Use fixed time values, not `now()`, to prevent time-dependent flakiness
- After `streamLoad`, always add `sql """sync"""` before querying
- Do not create tables with the same name across different tests in the same directory
- Injection tests must be marked `nonConcurrent` and must clean up injections after running
- Test suites follow naming convention with priority suffix: `_p0` (core), `_p1` (extended), `_p2` (large-scale/performance)

## Additional Resources

### Extensions (`extension/`)

Integration adapters: DataX, dbt-doris, Logstash, Beats, Kettle, mysql_to_doris.

### FE Plugins (`fe_plugins/`)

Plugin examples: `auditdemo`, `auditloader`, `sparksql-converter`, `trino-converter`.

### Tools (`tools/`)

- **Benchmarking**: `tpch-tools/`, `tpcds-tools/`, `ssb-tools/`, `clickbench-tools/`
- **Profiling**: `FlameGraph/`, `jeprof`, `pipeline-tracing/`
- **Development**: `pick_pr.sh`, `auto-pick-script.py`

### Docker (`docker/`)

Compilation images (`docker/compilation/`) and runtime images (`docker/runtime/`) for FE, BE, Broker, Cloud, and all-in-one deployments. Third-party test infrastructure (Hive, Iceberg, Kerberos) in `docker/thirdparties/`.

### Contributed Libraries (`contrib/`)

External libraries: `apache-orc/` (ORC format), `clucene/` (full-text search), `faiss/` (vector search), `openblas/` (linear algebra).
