# CLAUDE.md — Apache Doris Codebase Guide for AI Assistants

This file provides guidance for AI coding assistants (Claude, Copilot, etc.) working in the Apache Doris repository.

---

## Repository Overview

Apache Doris is a high-performance, real-time analytical database based on MPP architecture. It uses a 2-process design:

- **Frontend (FE)** — Java: query coordinator, metadata manager, MySQL protocol handler
- **Backend (BE)** — C++: columnar storage engine, vectorized query execution, pipeline executor
- **Cloud/Meta Service** — C++: cloud-native metadata service for elastic deployments
- **Broker** — Java: reads from external storage (HDFS, S3, etc.)

---

## Directory Structure

```
doris/
├── fe/                        # Frontend (Java, Maven multi-module)
│   ├── fe-core/               # Core query planning, catalog, optimizer
│   ├── fe-common/             # Shared FE utilities
│   ├── be-java-extensions/    # Java UDFs, JDBC/Hive/Hadoop scanners
│   └── hive-udf/              # Hive UDF compatibility layer
├── be/                        # Backend (C++, CMake)
│   └── src/
│       ├── exec/              # Query execution operators
│       ├── exprs/             # Expression evaluation
│       ├── olap/              # OLAP storage engine & tablet management
│       ├── pipeline/          # Pipeline execution engine
│       ├── runtime/           # Query runtime and memory management
│       ├── vec/               # Vectorized execution (column-based)
│       ├── io/                # I/O operations
│       ├── common/            # Shared utilities
│       └── service/           # Backend service interfaces
├── cloud/                     # Cloud/Meta Service (C++, CMake)
│   └── src/
│       ├── meta-service/      # Cloud metadata service
│       ├── recycler/          # Data recycling
│       └── resource-manager/  # Cloud resource management
├── common/                    # Shared C++ code for BE and Meta Service
├── gensrc/                    # Code generation (proto/, thrift/)
├── regression-test/           # End-to-end regression tests (Groovy)
│   └── suites/                # Test suites organized by feature/priority
├── pytest/                    # Python integration test framework
├── extension/                 # DataX, DBT, Kettle, Logstash connectors
├── fe_plugins/                # FE audit/SQL converter plugins
├── docker/                    # Docker images and compose files
├── conf/                      # Default FE/BE configuration templates
├── build-support/             # Build utilities, formatters, linters
├── .github/workflows/         # GitHub Actions CI/CD workflows
├── build.sh                   # Master build script
├── env.sh                     # Environment setup (Linux/macOS)
├── run-be-ut.sh               # Backend unit test runner
├── run-fe-ut.sh               # Frontend unit test runner
└── run-regression-test.sh     # Regression test runner
```

---

## Build System

### Prerequisites
- CMake 3.19.2+ (for BE and Cloud)
- Maven 3+ (for FE)
- JDK 11+ (for FE)
- GCC or Clang with C++17 support
- Thirdparty libraries (auto-compiled on first build)

### Build Commands

```bash
# Build all components
./build.sh

# Build individual components
./build.sh --fe                   # Frontend only
./build.sh --be                   # Backend only
./build.sh --cloud                # Cloud/Meta Service only
./build.sh --broker               # Broker only

# Common options
./build.sh --be --clean           # Clean rebuild
./build.sh --be -j 8              # Parallel build (8 jobs)
USE_AVX2=0 ./build.sh --be        # Disable AVX2 (for older CPUs)
STRIP_DEBUG_INFO=ON ./build.sh    # Strip debug symbols for release

# Release build
./build-for-release.sh

# Generate proto/thrift sources
./generated-source.sh
```

---

## Testing

### Backend Unit Tests (C++)
```bash
# Run all BE unit tests
./run-be-ut.sh --run

# Run specific test
./run-be-ut.sh --run --filter=MyTestName

# Run with GDB
./run-be-ut.sh --run --gdb --filter=MyTestName

# Run with coverage
./run-be-ut.sh --run --coverage

# Test files location: be/test/
```

### Frontend Unit Tests (Java)
```bash
# Run all FE unit tests
./run-fe-ut.sh --run

# Run specific test class
./run-fe-ut.sh --run org.apache.doris.utframe.Demo

# Test files location: fe/fe-core/src/test/
```

### Cloud Unit Tests (C++)
```bash
./run-cloud-ut.sh
```

### Regression Tests (End-to-End, Groovy)
```bash
# Run all regression tests
./run-regression-test.sh

# Test suites location: regression-test/suites/
# Priority groups: query_p0/, load_p0/, demo_p0/, etc.
```

### Python Integration Tests
```bash
cd pytest/
pytest
# Config: pytest.ini
# Dependencies: requirements.txt
```

---

## Code Style & Formatting

### C++ (Backend & Cloud)

- **Style:** Google C++ with customizations (see `.clang-format`)
- **Indentation:** 4 spaces
- **Line length:** 100 characters max
- **Pointer alignment:** Left (`int* ptr`, not `int *ptr`)
- **Continuation indent:** 8 spaces (double of base indent)

```bash
# Format a file
./build-support/clang-format.sh be/src/path/to/file.cpp

# Check formatting (run by CI)
./build-support/check-format.sh
```

**Static analysis** is configured in `.clang-tidy`:
- Function line limit: 80 lines
- Cognitive complexity limit: 50
- Checks: bugprone, modernize, readability, performance

### Java (Frontend)

- **Tool:** Maven Checkstyle plugin
- **Config:** `fe/check/checkstyle/checkstyle.xml`
- **Style:** Custom Google-based style, 4-space indentation

```bash
# Check Java code style
mvn checkstyle:check -f fe/pom.xml
```

### Shell Scripts
- **Tool:** ShellCheck
- **Config:** `.shellcheckrc`
- **Validation:** `./build-support/shell-check.sh`

### License Headers
All source files must have an Apache 2.0 license header. Validated by `license-eye` (config: `.licenserc.yaml`).

---

## Regression Test Writing Guidelines

When writing or modifying tests in `regression-test/suites/`:

1. **Always use `def` for local variables** to prevent cross-test pollution:
   ```groovy
   // Wrong
   ret = sql """select ..."""
   // Correct
   def ret = sql """select ..."""
   ```

2. **Do not set global session variables** unless the test is marked `nonConcurrent`:
   ```groovy
   // Wrong (affects parallel tests)
   sql """set global enable_pipeline_x_engine=true;"""
   // Correct (session-scoped)
   sql """set enable_pipeline_x_engine=true;"""
   ```

3. **Use fixed dates** instead of dynamic `now()` to prevent future test failures:
   ```groovy
   // Wrong
   sql """select count(*) from t where created < now();"""
   // Correct
   sql """select count(*) from t where created < '2023-11-13';"""
   ```

4. **Add `sql """sync"""` after `streamLoad`** in multi-FE environments:
   ```groovy
   streamLoad { ... }
   sql """sync"""
   sql """select count(*) from table"""
   ```

5. For tests requiring global changes, mark with `nonConcurrent`:
   ```groovy
   suite("my_test", "nonConcurrent") { ... }
   ```

---

## Key FE Packages

Located under `fe/fe-core/src/main/java/org/apache/doris/`:

| Package | Purpose |
|---------|---------|
| `nereids/` | New Cascades-style query optimizer (primary optimizer) |
| `planner/` | Legacy query planner |
| `analysis/` | Query analysis and semantic validation |
| `catalog/` | Metadata and schema management |
| `datasource/` | External data source integration |
| `load/` | Data loading and ingestion framework |
| `mysql/` | MySQL wire protocol implementation |
| `persist/` | Persistence, transaction handling, and edit logs |
| `job/` | Background job scheduling |
| `plsql/` | PL/SQL stored procedure support |

---

## Key BE Directories

Located under `be/src/`:

| Directory | Purpose |
|-----------|---------|
| `vec/` | Vectorized execution engine (column-based) |
| `pipeline/` | Pipeline execution scheduler |
| `olap/` | Storage engine: tablets, compaction, rowsets |
| `exec/` | Execution operators (scan, join, agg, etc.) |
| `exprs/` | Expression evaluation |
| `runtime/` | Query runtime state, memory management |
| `io/` | File I/O and cache layers |
| `common/` | Shared utilities, config, status codes |

---

## Code Generation

Protocol buffer (`.proto`) and Thrift (`.thrift`) files are in `gensrc/`. Generated sources are checked in.

```bash
# Regenerate all sources after modifying .proto or .thrift
./generated-source.sh
# OR
cd gensrc && make
```

---

## CI/CD Workflows

Key GitHub Actions workflows (`.github/workflows/`):

| Workflow | Trigger | What it checks |
|----------|---------|----------------|
| `checkstyle.yaml` | PR | Java code style (Checkstyle) |
| `clang-format.yml` | PR | C++ formatting (clang-format) |
| `code-checks.yml` | Push/PR | ShellCheck, license headers |
| `sonarcloud.yml` | PR/push | Code quality analysis |
| `title-checker.yml` | PR | PR title format validation |
| `auto-cherry-pick.yml` | PR merge | Auto cherry-pick to release branches |
| `stale.yml` | Scheduled | Mark stale issues/PRs |

PR titles must follow conventional commit format (validated by `title-checker.yml`). Examples:
```
[feat](nereids) add new join reorder rule
[fix](be) fix memory leak in vectorized scanner
[doc] update compilation guide
```

---

## Development Tips

### Adding a New SQL Function

1. Define the function in FE: `fe/fe-core/src/main/java/org/apache/doris/catalog/BuiltinScalarFunctions.java`
2. Implement the BE execution in `be/src/vec/functions/`
3. Add regression tests in `regression-test/suites/query_p0/sql_functions/`

### Adding a New Storage Format or Index

- BE storage code: `be/src/olap/`
- Schema/metadata: `fe/fe-core/src/main/java/org/apache/doris/catalog/`
- Thrift definitions: `gensrc/thrift/`

### Nereids (New Optimizer) vs Legacy Planner

The `nereids/` optimizer is the primary optimizer in current development. When modifying query planning:
- New features should go into `nereids/`
- Legacy planner is in `planner/` and `analysis/`

### Cloud-Native Mode

The `cloud/` directory contains the Meta Service for cloud deployments. It shares foundational code with BE via the `common/` directory.

---

## Git Conventions

- Branch naming: `feature/description`, `fix/issue-description`, `claude/task-name`
- Commits: descriptive messages referencing component (e.g., `[fix](be) fix tablet version check`)
- Apache project: all contributions require Apache CLA; significant contributions require discussion on dev mailing list

---

## License

Apache Doris is licensed under the Apache License 2.0. All source files must include the standard Apache license header.
