# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Apache Doris is an MPP analytical database. It has two main daemons:

- **FE (Frontend)** — Java. Query coordination, SQL parsing, query planning (Nereids optimizer), metadata management. Located in `fe/`.
- **BE (Backend)** — C++20. Columnar storage engine, vectorized query execution, pipeline execution engine. Located in `be/`.
- **Cloud** — C++. Cloud-mode meta-service. Located in `cloud/`.
- **Broker** — Java. Reads data from external storage (HDFS). Located in `fs_brokers/`.

FE and BE communicate via Thrift and Protocol Buffers (IDL definitions in `gensrc/thrift/` and `gensrc/proto/`).

## Build Commands

Requires: JDK 17, Maven, CMake, Ninja, clang (default compiler), flex >= 2.6.0. Third-party libraries must be pre-built in `thirdparty/`.

```bash
# Build everything (FE + BE + Broker)
sh build.sh

# Build individual components
sh build.sh --fe
sh build.sh --be
sh build.sh --cloud
sh build.sh --be -j 16          # parallel BE build

# Clean build
sh build.sh --fe --clean
sh build.sh --be --clean

# Environment variables
USE_AVX2=0 sh build.sh --be                    # disable AVX2
STRIP_DEBUG_INFO=ON sh build.sh --be            # strip debug info
DISABLE_JAVA_CHECK_STYLE=ON sh build.sh --fe    # skip Java checkstyle
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

Config: `regression-test/conf/regression-conf.groovy`. Logs: `output/regression-test/log/`.

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

Config: `.clang-format` (Google-based, 100-char line limit, 4-space indent). Ignored paths listed in `.clang-format-ignore` (third-party code like `be/src/clucene/`, `be/src/gutil/`).

Static analysis: `.clang-tidy` is configured with bugprone, modernize, readability, and performance checks.

### Java (Maven Checkstyle)

Checkstyle runs automatically during FE build. Config: `fe/check/checkstyle/checkstyle.xml` (120-char line limit). Suppress with `// CHECKSTYLE OFF` / `// CHECKSTYLE ON` comments. Skip with `DISABLE_JAVA_CHECK_STYLE=ON`.

### Shell Scripts

```bash
build-support/shell-check.sh    # uses shellcheck + shfmt
```

## Key Architecture Details

### FE Modules (`fe/pom.xml` multi-module project)
- `fe-common` — shared classes
- `fe-core` — main FE process (SQL analysis, Nereids optimizer, catalog, planner, statistics)
- `be-java-extensions` — Java extensions loaded by BE (JDBC scanner, Hive/Hudi/Iceberg/Paimon scanners, Java UDF, Avro scanner, etc.)
- `hive-udf` — Hive UDF library for ingestion

### BE Key Source Directories (`be/src/`)
- `olap/` — storage engine (tablets, rowsets, segments, compaction, schema change)
- `vec/` — vectorized execution (columns, blocks, functions, aggregation, joins)
- `pipeline/` — pipeline execution engine (async task scheduling)
- `exec/` — query execution operators
- `runtime/` — memory management, thread pools, runtime state
- `runtime_filter/` — runtime filters (Bloom, In, MinMax)
- `io/` — file I/O, external storage (HDFS, S3, Azure)
- `cloud/` — cloud-mode specific logic
- `exprs/` — expression evaluation

### Nereids Query Optimizer
The modern CBO (cost-based optimizer) lives in `fe/fe-core/src/main/java/org/apache/doris/nereids/`. It is the primary optimizer for query planning.

### Generated Sources
`gensrc/` contains Thrift and Protobuf IDL files. Run `make` in `gensrc/` to regenerate (the main `build.sh` handles this automatically).

## Regression Test Authoring Guidelines

- Use `def` for all local variables (bare assignment creates globals that leak across parallel tests)
- Do not set global session variables (`set global ...`); use session-scoped `set` instead
- If global state changes are required, mark the test as `nonConcurrent`
- Use fixed time values, not `now()`, to prevent time-dependent flakiness
- After `streamLoad`, always add `sql """sync"""` before querying
- Do not create tables with the same name across different tests in the same directory
- Injection tests must be marked `nonConcurrent` and must clean up injections after running
