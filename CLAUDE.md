# CLAUDE.md - Apache Doris Development Guide

## Project Overview

Apache Doris is a high-performance, real-time analytical database based on MPP architecture. It consists of three main components:

- **FE (Frontend)** - Java-based query coordinator, metadata manager, and SQL parser
- **BE (Backend)** - C++-based storage engine and query execution engine
- **Cloud** - C++-based cloud-native meta-service (separate component)

Branch: `branch-3.0` (version 3.0.6.x)

## Repository Structure

```
fe/                    # Frontend (Java/Maven)
  fe-core/             #   Core FE logic (catalog, analysis, planner, nereids optimizer)
  fe-common/           #   Shared FE library
  spark-dpp/           #   Spark data preprocessing
  hive-udf/            #   Hive UDF support
  be-java-extensions/  #   Java extensions for BE
  check/               #   Checkstyle config
be/                    # Backend (C++/CMake)
  src/                 #   Source (vec/, olap/, pipeline/, runtime/, exec/, io/, cloud/, http/, util/)
  test/                #   GTest unit tests (mirrors src/ structure)
  cmake/               #   CMake modules
cloud/                 # Cloud meta-service (C++/CMake)
  src/                 #   meta-service/, recycler/, resource-manager/
  test/                #   Cloud unit tests
regression-test/       # Groovy-based regression test framework
  suites/              #   Test cases by feature (200+ dirs, named <feature>_p<priority>)
  data/                #   Expected outputs and test data
  framework/           #   Test framework code
gensrc/                # Proto/Thrift IDL definitions
  proto/               #   Protobuf (.proto files)
  thrift/              #   Thrift service definitions
extension/             # External integrations (DataX, dbt, beats, logstash)
fe_plugins/            # FE plugins (audit, converters)
thirdparty/            # Third-party C++ dependency management
ui/                    # React web dashboard
tools/                 # Benchmarking (TPC-H/DS, ClickBench, SSB), profiling, utilities
samples/               # Client examples (Java, Python, Go, Node.js, C++, Rust)
common/cpp/            # Shared C++ code (AWS, S3 utilities)
```

## Build System

### Prerequisites
- **JDK 17** (set via `JAVA_HOME` or `JDK_17`)
- **Maven** (auto-detected or set `MVN_CMD`)
- **CMake** + **Ninja** (preferred) or Make
- **Clang** (default toolchain) or GCC (set via `DORIS_TOOLCHAIN=gcc`)
- Third-party libs pre-built via `thirdparty/build-thirdparty.sh`

### Build Commands

```bash
# Full build (FE + BE + Broker + extensions)
./build.sh

# Component-specific builds
./build.sh --fe            # Frontend only
./build.sh --be            # Backend only
./build.sh --cloud         # Cloud meta-service only
./build.sh --fe --clean    # Clean rebuild of FE
./build.sh --be --clean    # Clean rebuild of BE
./build.sh -j 16           # Parallel BE compilation

# Special targets
./build.sh --meta-tool     # BE meta tool
./build.sh --index-tool    # BE index tool
```

### Key Environment Variables
- `DORIS_HOME` - Repository root (auto-set)
- `DORIS_THIRDPARTY` - Third-party library path
- `DORIS_TOOLCHAIN` - `clang` (default) or `gcc`
- `USE_AVX2` - Enable AVX2 instructions (0 or 1)
- `STRIP_DEBUG_INFO` - Separate debug symbols
- `DISABLE_JAVA_CHECK_STYLE=ON` - Skip Java checkstyle during FE build
- `DISABLE_BE_JAVA_EXTENSIONS` - Skip Java extensions in BE build

## Testing

### FE Unit Tests (JUnit 5)

```bash
./run-fe-ut.sh                                              # Run all FE tests
./run-fe-ut.sh --run org.apache.doris.catalog.SomeTest      # Run specific test
./run-fe-ut.sh --coverage                                   # With JaCoCo coverage
FE_UT_PARALLEL=4 ./run-fe-ut.sh                             # Parallel execution
```

- Framework: JUnit 5.8.2 (Jupiter) with JMockit 1.49
- Location: `fe/fe-core/src/test/java/org/apache/doris/` (mirrors main source)
- Checkstyle is skipped during test runs (`-Dcheckstyle.skip=true`)

### BE Unit Tests (Google Test)

```bash
./run-be-ut.sh                            # Build tests only
./run-be-ut.sh --run                      # Build and run all tests
./run-be-ut.sh --run --filter=VecTest*    # Run tests matching GTest filter
./run-be-ut.sh --clean --run --coverage   # Clean build + run + coverage
./run-be-ut.sh -j 16                      # Parallel compilation
```

- Framework: Google Test
- Location: `be/test/` (mirrors `be/src/` structure)
- Test files: `*_test.cpp` naming convention
- Build type: ASAN by default (output in `be/ut_build_ASAN/`)

### Cloud Unit Tests

```bash
./run-cloud-ut.sh --run                       # Build and run all
./run-cloud-ut.sh --run --filter=MetaTest*    # Specific tests
```

### Regression Tests (Groovy)

```bash
./run-regression-test.sh --run                       # Run all default group tests
./run-regression-test.sh --run -s suite_name         # Run specific suite
./run-regression-test.sh --run -d dir_name           # Run specific directory
./run-regression-test.sh --run -parallel 8           # Parallel execution
./run-regression-test.sh --run -runMode cloud        # Cloud mode tests
```

- Priority levels: `p0` (critical), `p1` (important), `p2` (supplementary)
- Suite naming: `<feature>_p<priority>` (e.g., `insert_p0`, `schema_change_p2`)
- Config: `regression-test/conf/regression-conf.groovy`

## Code Style & Formatting

### Java (FE)
- **Checkstyle** v9.3 enforced during builds
- Config: `fe/check/checkstyle/checkstyle.xml`
- Max line length: **120 characters**
- No tabs (spaces only), LF line endings
- Excludes: generated thrift/parquet code
- Skip with: `DISABLE_JAVA_CHECK_STYLE=ON`

### C++ (BE/Cloud)
- **clang-format** (Google-based with customizations)
  - Column limit: **100 characters**
  - Indent: 4 spaces
  - Pointer alignment: Left (`int* p`, not `int *p`)
- **clang-tidy** enabled with checks: bugprone, modernize, misc, readability, performance
  - Function size threshold: 80 lines
  - Cognitive complexity threshold: 50
- Config files: `.clang-format`, `.clang-tidy` at repo root
- Scope: `be/src/`, `be/test/`, `cloud/src/`, `cloud/test/`

## CI Workflows (GitHub Actions)

| Workflow | What it checks |
|----------|---------------|
| `clang-format.yml` | C++ formatting (BE & Cloud) |
| `checkstyle.yaml` | Java style (FE) |
| `code-checks.yml` | ShellCheck + Clang Tidy |
| `license-eyes.yml` | License headers |
| `title-checker.yml` | PR title format |
| `sonarcloud.yml` | Code quality analysis |

Heavy testing (p0, p1, BE UT, FE UT, cloud UT, performance) runs on TeamCity, triggered via PR comments.

## Commit Message Conventions

Follow the pattern: `[tag](scope) description (#PR_number)`

Common tags from history:
- `[fix]` - Bug fixes
- `[opt]` - Optimizations
- `[improve]` - Improvements
- `[regression-test]` - Test changes
- `[release]` - Release-related
- `[Chore]` - Maintenance tasks
- `[Fix]` - Alternative fix tag (capitalized also used)

Examples:
```
[fix](ui) fix ui builds failed error (#52711)
[opt](deps) add jindofs in classpath after hadoop libs (#51689)
[fix](cloud) compaction and schema change potential data race (#51048)
```

## Key Architecture Notes

### FE (Frontend)
- **Nereids** is the modern query optimizer (under `fe-core/.../nereids/` with 22+ subdirs) - preferred over the legacy planner
- Key packages: `catalog` (metadata), `analysis` (SQL analysis), `qe` (query execution), `load` (data loading), `cloud` (cloud mode)
- Java 8 source/target compatibility (despite JDK 17 build requirement)
- Maven modules: fe-common → fe-core (with spark-dpp, hive-udf, be-java-extensions)

### BE (Backend)
- **vec/** is the vectorized execution engine (largest module, ~800 files) - columnar processing
- **olap/** is the storage engine (~336 files)
- **pipeline/** is the pipeline execution framework
- Build produces `doris_be` binary
- Supports AMD64 and ARM64 architectures

### Regression Test Best Practices
- Use `def` for local variables (avoid polluting global scope)
- Avoid modifying global session variables or cluster config
- Use fixed timestamps instead of `now()` for deterministic tests
- Add `sql """sync"""` after StreamLoad in multi-FE environments
- Mark fault injection tests as `nonConcurrent`
- Mark FE restart/upgrade compatibility tests with `restart_fe` group

## Common Development Tasks

### Adding a new SQL function
1. BE: Implement in `be/src/vec/functions/` (C++)
2. FE: Register in the function catalog under `fe-core/.../catalog/`
3. Tests: Add BE unit test + regression test suite

### Modifying the optimizer
- Work in `fe/fe-core/src/main/java/org/apache/doris/nereids/`
- The Nereids optimizer uses a rule-based + cost-based approach

### Adding a Thrift/Protobuf service
1. Edit IDL files in `gensrc/thrift/` or `gensrc/proto/`
2. Run `./generated-source.sh` to regenerate code
3. Implement service handlers in both FE and BE as needed

### Working with third-party dependencies
- Version definitions: `thirdparty/vars.sh`
- Build script: `thirdparty/build-thirdparty.sh`
- Patches: `thirdparty/patches/`
