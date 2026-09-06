# Repository Guidelines

MassDB SQL is derived from Apache Doris; existing Java packages, C++ namespaces, and build variables still use Doris names.

## Project Structure & Module Organization

- `fe/`: Java frontend for SQL planning, metadata, and coordination; core sources are in `fe/fe-core/src/main/java`.
- `be/src/` and `cloud/src/`: C++ execution/storage backend and cloud services; corresponding tests are in `be/test/` and `cloud/test/`.
- `gensrc/`: Thrift/Protobuf definitions and generators; `common/`: shared utilities; `thirdparty/`: dependency builds.
- `regression-test/`: Groovy framework, SQL suites, fixtures, and expected results.
- `ui/`: React/TypeScript frontend; `webroot/`: service web assets; `conf/` and `bin/`: configuration templates and service scripts.

## Build, Test, and Development Commands

Run from the repository root. Configure JDK 17, Maven, CMake, and the C++ toolchain through `env.sh` and local `custom_env.sh` overrides.

- `bash build.sh --fe --be -j 8`: build FE/BE distributions into `output/`.
- `bash run-fe-ut.sh --run org.apache.doris.utframe.DemoTest`: run a selected frontend test.
- `bash run-be-ut.sh --run --filter='StatusTest.*'`: build and run selected backend tests.
- `bash run-regression-test.sh --run -s test_select`: run a SQL regression suite against a configured cluster.
- `cd ui && npm ci && npm run dev`: start UI development with Node 22.23.2/npm 10.9.9; `npm run build` bundles production assets and notices.

Configure `output/{fe,be}/conf/`; start services with `bash output/fe/bin/start_fe.sh --daemon` and `bash output/be/bin/start_be.sh --daemon`. Register BE before running SQL suites.

## Coding Style & Naming Conventions

Use UTF-8, LF endings, and four-space indentation for Java, C++, Python, and shell. Format C++ with clang-format 16 using `.clang-format` (100 columns). Java uses Checkstyle (120 columns): run `(cd fe && mvn checkstyle:check)`. Follow existing `PascalCase` classes, Java `camelCase` members, and C++ `snake_case` functions. Preserve upstream headers; add modification notices and update `MODIFICATIONS.md`. Follow `dist/source-headers.json` for independent headers; run `python3 build-support/check-source-headers.py`.

## Testing Guidelines

Place JUnit `*Test.java` files under `fe/*/src/test/java` and GoogleTest `*_test.cpp` files under matching C++ test directories. Add Groovy `test_*.groovy` suites under `regression-test/suites/`; maintain expected `.out` files in `regression-test/data/`. Cover changed behavior and error paths. FE/BE runners support `--coverage`. Keep cluster overrides in ignored `regression-test/conf/regression-conf-custom.groovy`. For UI notice changes, run `npm run check:notices` and `npm run test:legal` after building; prerequisites are in `ui/README.md`.

## Commit & Pull Request Guidelines

Follow recent history: `[fix](tools) fix meta_tool startup crashes`, using types such as `fix`, `test`, `opt`, or `chore`. PR titles use `[type](scope) summary`. Complete `.github/PULL_REQUEST_TEMPLATE.md`: explain the problem, link applicable issues/PRs, provide release notes, and record tests, behavior changes, and documentation needs. Explain when tests are unnecessary.
