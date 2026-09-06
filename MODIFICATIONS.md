# MassDB SQL Modifications

MassDB SQL is derived from Apache Doris. Upstream source baseline: `59de8c4c524008e8ab2e43b79312f716a3a423a8` (`4.0.5-rc01`), verified against the [Apache repository](https://github.com/apache/doris/commit/59de8c4c524008e8ab2e43b79312f716a3a423a8) on 2026-09-06.

This inventory describes distribution changes, not a claim that all changes are owned by the company. Original Apache and third-party notices remain applicable. It supplements modification notices within editable files; it does not replace those notices.

## Product release candidate rc02 (2026-09-06)

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
