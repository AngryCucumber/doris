<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->
<!-- Modified for MassDB SQL. See MODIFICATIONS.md for details. -->

# MassDB SQL UI

React/TypeScript administration pages derived from Apache Doris. The public
`/legal-notices` route provides Apache attribution, MariaDB runtime copyright,
local license texts and a list of bundled UI dependencies.

## Development and verification

Use Node **22.23.2**, npm **10.9.9** and Python **3.9+**. `.nvmrc`,
`packageManager`, `engines`, `.npmrc` and `package-lock.json` define the
supported installation; do not regenerate it with an arbitrary npm version.
From `ui/`:

```bash
npm ci
npm run dev                 # http://localhost:8030
npm run build               # production assets and legal/ in dist/
npm run check:notices       # versions, content and bundle hashes
npx playwright install chromium
npm run test:legal          # browser checks; screenshots in ../.build-records/ui/screenshots/
```

The browser tests use a local static server and mock the login API. They cover
public access, authenticated navigation, deployment prefixes, local reading
and downloads, HTTP 200 HTML/JSON fallbacks, recovery after missing notices, and
Chinese/English layouts at three widths. Notice endpoints must serve `text/plain`
(an optional charset is supported); JSON error responses are never license text.
Playground checks also cover aligned panels/toolbars, a visible footer, search and
refresh, independent tree scrolling, sidebar resizing and narrow-window stacking.
They do not replace tests against a running FE. No `npm run lint` script is
currently defined.

From the repository root, test artifact validation with:

```bash
python3 -m unittest discover -s build-support -p test_product_notices.py -v
```

## Notices and FE packaging

`config/webpack.common.js` invokes `scripts/collect-bundled-licenses.cjs` after
normal assets are generated. It inventories actual bundled modules, including
CodeMirror and dynamic chunks. Outputs include `legal/THIRD-PARTY-NOTICES.txt`,
`components.json`, `sbom.cdx.json` and `manifest.json`. Original license inputs
come from `dist/`, installed packages and reviewed `dist/ui-licenses/` supplements.
Generated UI assets belong in `dist/`; build inventories, webpack statistics and
screenshots belong in `../.build-records/ui/`, outside version control. Reserve
`../output/` for the latest program/package and archive/checksum.

The complete installation is assembled with `--assemble-package` in
`build-support/prepare-product-notices.py`. Its UI inventories, SBOMs and debug
symbols stay in a separate audit directory. Public notices and MariaDB source
remain under `fe/legal/`; build-only JSON inventories are also removed from the
delivered FE JAR. Verify that JAR with `--check-fe-jar PATH --ui-dist ui/dist` from
the root so the external build inventory checks every retained static resource.
The detailed repository `MODIFICATIONS.md` is not included in the installed UI;
the package README retains the product modification summary.

Browser tests can serve static files extracted from the delivered JAR with
`MASSDB_LEGAL_TEST_DIST=/path/to/extracted/static` and read its matching external
inventory through `MASSDB_LEGAL_TEST_MANIFEST=/path/to/audit/ui/manifest.json`.
Set `MASSDB_LEGAL_TEST_SCREENSHOTS` to keep those screenshots in the release record.

Product and source metadata come from `../dist/product-provenance.json` and the
existing version script. The maintainer has enabled the 2026 company attribution
for company-owned modifications and original additions. The source `NOTICE.txt`
addendum and the footer must agree with that metadata; UI validation and the
release preflight reject a mismatch. Component packaging copies the source NOTICE.
After changing the company names or years, use
`python3 build-support/prepare-product-notices.py --company-notice` from the root
to obtain the replacement company addendum, preserving all upstream notices, then
run the same script with `--check-company-notice`. New implementation file licensing and the
historical package `ISC` metadata remain separate decisions in the
[implementation plan](../docs/massdb-sql-copyright-productization-plan.md).

The root `build.sh` validates normal and `CUSTOM_UI_DIST` bundles before copying
them into FE resources and checks the resulting JAR. With `DISABLE_BUILD_UI=ON`,
existing UI resources are still validated; a build without any UI remains
supported. Rebuild stale custom assets against the same version and metadata.

FE package assembly uses the reviewed archive in
`../dist/sources/mariadb-connector-j-3.0.9.tar.gz` and verifies its SHA-256 and the
runtime JAR. It performs no download. Set `MASSDB_MARIADB_SOURCE_ARCHIVE` only to
use another local copy of that exact archive. Missing or mismatched inputs fail
before the FE build with recovery instructions. Source is copied to FE's
`legal/sources/`, separately from JAR static resources; BE materials remain a
separate release task.

`build.sh` checks Node/npm before dependency compilation. Set
`MASSDB_UI_NODE_DIR` to a Node installation prefix in `custom_env.sh`, or adjust
`PATH`. Set `MASSDB_NOTICE_PYTHON` to Python 3.9+ if `python3` is older. A prebuilt
`CUSTOM_UI_DIST` and a headless build do not require Node/npm.

Legacy CentOS 7 compiler images cannot run the supported official Node 22
binary. Use the separate [UI builder](../docker/compilation/Dockerfile.ui):

```bash
# Run from the repository root; build the toolchain image once.
docker build -f docker/compilation/Dockerfile.ui -t massdb-sql-ui-builder docker/compilation
docker run --rm --volume "$PWD:/workspace" massdb-sql-ui-builder
CUSTOM_UI_DIST="$PWD/ui/dist" bash build.sh --fe
```

Container installation still needs the npm registry or a populated npm cache.
For a fully offline workflow, prepare the toolchain image and npm dependencies
before disconnecting. FE notice assembly itself uses only local inputs.

`git archive` expands `dist/source-version.json` to identify the source commit.
Other source tarballs may supply `MASSDB_SOURCE_COMMIT`; without either source
reference a development build displays `unknown`. A release rejects unknown
or dirty source state. An explicit commit string alone does not prove a source
tree is clean; use a committed clean checkout or a verified Git export.
MassDB `2.0.5` remains its own product version, independently of the
Apache Doris `4.0.5-rc01` source baseline.

New implementation files have explicit pending-license headers registered in
`dist/source-headers.json`. Run `python3 build-support/check-source-headers.py`
from the repository root; `--release` intentionally fails until A02 is resolved.
The remaining files still undergo License Eyes checks. This transition does not
grant a license or permit release of the unresolved files.

To inventory a complete assembled package (outside `ui/`), run:

```bash
python3 build-support/prepare-product-notices.py \
    --inventory-java-package /path/to/massdb-package \
    --destination .build-records/java-inventory
```

The destination must be new and outside the package. The command uses local JARs
and cached Maven parent POMs only. It writes Java inventory, CycloneDX SBOM,
original embedded notices and `review-queue.csv`, including nested JARs. Shaded
code without metadata, native libraries and binary license applicability still
require review; reported declarations are evidence, not approval.

## Source layout

- `src/pages/`: login, business pages and public legal notices.
- `src/components/legal-footer/`: shared runtime attribution and navigation.
- `src/constants/branding.ts`: typed build metadata.
- `public/locales/`: English and Chinese text.
- `scripts/`: notice generation and browser verification.
