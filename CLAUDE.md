# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository overview

Apache Doris is an MPP-based real-time analytical database. The codebase is a large polyglot monorepo with three top-level processes plus shared infrastructure:

- `fe/` — **Frontend (Java 17)**. Multi-module Maven project (`fe-common`, `fe-core`, `be-java-extensions`, `hive-udf`, `fe/check`). `fe-core` is the main daemon: SQL parsing, query planning/optimization (the **Nereids** optimizer in `org.apache.doris.nereids`), metadata, the MySQL-protocol service, catalogs (Hive/Iceberg/Hudi/JDBC/etc. under `datasource/`), schedulers, transactions, and BDBJE-based metadata replication. The legacy planner still lives in `org.apache.doris.planner`; new work generally goes into `nereids`.
- `be/` — **Backend (C++20, CMake)**. Storage (`olap/`), vectorized execution engine (`vec/`), pipeline scheduler (`pipeline/`), runtime (`runtime/`), I/O (`io/`), services exposed over Thrift/BRPC (`service/`), HTTP handlers (`http/`). Each tablet is an LSM-tree column store; queries run as pipeline tasks over vectorized columns.
- `cloud/` — **MetaService / Recycler (C++)**. Separate daemon used by the storage-compute-separation (cloud) deployment. Talks to FDB and S3-compatible object storage. Sources under `cloud/src/{meta-service,meta-store,recycler,resource-manager,rate-limiter,snapshot}`.
- `gensrc/` — Thrift IDL (`thrift/`) and Protobuf (`proto/`) shared between FE/BE/cloud. `gensrc/Makefile` produces generated Java/C++ code consumed by both sides; running `bash generated-source.sh` regenerates them. **Always edit the IDL, never the generated code.**
- `regression-test/` — Groovy-based end-to-end SQL test framework (`framework/`, `suites/`, `data/`, `conf/`). Suites are sharded by group suffix: `_p0` is the fast/blocking tier, `_p1`/`_p2` are larger/slower tiers.
- `fs_brokers/`, `fe_plugins/`, `extension/`, `contrib/`, `samples/`, `docker/`, `tools/` — auxiliary components, connectors, plugins, and dev tooling. `thirdparty/` builds vendored native deps via `thirdparty/build-thirdparty.sh`.

The FE↔BE boundary is Thrift RPC for control-plane and BRPC for data-plane; understanding `gensrc/thrift/*.thrift` and `gensrc/proto/*.proto` is usually the fastest way to trace cross-process flows.

## Build

`build.sh` is the entry point — it sources `env.sh`, validates the toolchain, and dispatches to FE/BE/cloud/broker subbuilds. **JDK 17 is required** (`env.sh` enforces this; set `JDK_17` or `JAVA_HOME`). Native builds need a fully built `thirdparty/installed/` (see `thirdparty/build-thirdparty.sh`) or the prebuilt tarball from the official compilation docker image.

```bash
./build.sh                       # build everything (FE + BE + broker + java extensions)
./build.sh --fe                  # FE only (Maven)
./build.sh --be                  # BE only (CMake/Ninja)
./build.sh --cloud               # cloud MetaService (off by default)
./build.sh --fe --be --clean     # clean + rebuild FE and BE
./build.sh --be -j 16            # parallel native build
USE_AVX2=0 ./build.sh --be       # for CPUs without AVX2
DISABLE_JAVA_CHECK_STYLE=ON ./build.sh --fe   # skip checkstyle
```

Outputs land in `output/` (`output/fe`, `output/be`, `output/ms`, ...). BE CMake build dirs are `be/build_${BUILD_TYPE}` (default `Release`); UT builds use `be/ut_build_ASAN`.

## Tests

### BE C++ unit tests (gtest)
Test files **must** be suffixed `_test.cpp` and registered in `be/test/CMakeLists.txt`. Driver: `run-be-ut.sh`.
```bash
./run-be-ut.sh                                  # build only
./run-be-ut.sh --run                            # build + run all
./run-be-ut.sh --run --filter=FooTest.*         # gtest filter syntax
./run-be-ut.sh --clean --run --coverage         # with coverage
./run-be-ut.sh --run --gdb --filter=FooTest.Bar # debug under gdb
```
Results: `be/ut_build_ASAN/gtest_output/`.

### Cloud C++ unit tests
Same conventions as BE; tests live in `cloud/test/` and are registered in `cloud/test/CMakeLists.txt`. Driver: `./run-cloud-ut.sh [--clean] [--run] [--filter=...]`.

### FE Java unit tests
Driver: `run-fe-ut.sh` (wraps Maven).
```bash
./run-fe-ut.sh                                                     # build/test all
./run-fe-ut.sh --run org.apache.doris.utframe.Demo                 # one test class
./run-fe-ut.sh --run org.apache.doris.utframe.Demo#testCreateDb    # one method
./run-fe-ut.sh --run Class1,Class2                                 # multiple
./run-fe-ut.sh --coverage                                          # JaCoCo
```

### Regression / end-to-end (Groovy)
Driver: `run-regression-test.sh`. Config defaults at `regression-test/conf/regression-conf.groovy`; logs at `output/regression-test/log`.
```bash
./run-regression-test.sh --run                              # all default-group suites
./run-regression-test.sh --run -s test_select               # single suite by name
./run-regression-test.sh --run -g default                   # by group
./run-regression-test.sh --run -d query_p0                  # by directory
./run-regression-test.sh --run -s test_select -genOut       # generate missing .out
./run-regression-test.sh --run -s test_select -forceGenOut  # regenerate .out
./run-regression-test.sh --clean --run -s test_select       # clean framework + run
```

Suite-authoring rules enforced by reviewers (see `regression-test/README.md`):
- Always declare locals with `def` — bare assignments become globals and leak across parallel suites.
- Don't use `set global ...` or change cluster config inside a suite unless the suite is marked `nonConcurrent`.
- Use fixed timestamps, not `now()`, in expected results.
- After `streamLoad`, run `sql "sync"` before querying so multi-FE setups stabilize.

## Code style and conventions

- **C++**: `.clang-format` (Google-based, 4-space indent, 100 col, left pointer alignment) and `.clang-tidy` are authoritative. `.clangd` is preconfigured for editor integration.
- **Java (FE)**: Maven `checkstyle` runs as part of `validate`; bypass only with `DISABLE_JAVA_CHECK_STYLE=ON` for local iteration. The Apache Doris Backend C++ Coding Specification linked from `README.md` is expected to be followed strictly.
- **License headers**: every source file needs an ASF header — `.licenserc.yaml` and `.rat-excludes` drive the RAT check.
- **Generated code**: `gensrc/build/`, `fe/fe-core/target/`, `be/build_*/` are derived artifacts — do not commit.

## Working with Nereids (FE optimizer)

Nereids (`fe/fe-core/src/main/java/org/apache/doris/nereids`) is the modern Cascades-style optimizer and is where most planner work happens. Layout to know:
- `parser/` — ANTLR grammar → logical plan AST (`trees/plans/logical`).
- `analyzer/`, `rules/` — analysis and rewrite rules (RBO).
- `memo/`, `jobs/`, `cost/`, `stats/` — Cascades memo, search jobs, CBO cost/stats.
- `properties/`, `processor/`, `glue/` — physical-property derivation and translation to the executable plan that BE consumes.
- HBO support sits alongside CBO; the optimizer combines RBO + CBO + HBO.

The legacy `org.apache.doris.planner` is still wired in for fallback paths but new features should target Nereids unless a clear reason exists.

## Cross-process changes

Because FE, BE, and cloud share Thrift/Protobuf, any RPC or on-disk-format change is a multi-step edit:
1. Edit `gensrc/thrift/*.thrift` or `gensrc/proto/*.proto`.
2. Regenerate (`bash generated-source.sh` or let `build.sh` do it implicitly).
3. Update FE consumers (`fe/fe-core/.../rpc`, `.../persist`), BE consumers (`be/src/service`, `be/src/runtime`), and cloud consumers (`cloud/src/meta-service`) together — partial commits will break the build.
4. Persisted journal/edit-log changes need a journal version bump and corresponding `Journal*` / persistence handler edits in `fe-core/.../persist`.
