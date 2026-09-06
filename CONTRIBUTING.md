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

# Contributing to MassDB SQL

Use this repository's review process for MassDB changes. The project derives
from Apache Doris; contributions here do not constitute a contribution to ASF
or grant Apache project roles. Upstream contributions follow the
[Apache Doris contribution process](https://github.com/apache/doris/blob/master/CONTRIBUTING.md).

## Prepare a change

Read [AGENTS.md](AGENTS.md) for module layout, toolchains and test commands.
Keep changes focused and preserve existing Java packages, C++ namespaces,
protocols and configuration keys unless a migration is explicitly in scope.
Add tests for changed behavior and relevant failure paths; explain when a
change only needs documentation, formatting or browser verification.

## Preserve attribution

Retain upstream and third-party license and copyright notices. Add a short
`Modified for MassDB SQL. See MODIFICATIONS.md for details.` comment to modified
upstream text files and record source paths, copied files and asset provenance
in [MODIFICATIONS.md](MODIFICATIONS.md). Formats that cannot contain comments
need associated attribution that follows the distributed files.

Do not put ASF contributor-agreement statements on independently authored
files. Confirm the applicable license and rights holder before adding new
copyright or license claims. The current unresolved decisions and evidence
requirements are in the [copyright plan](docs/massdb-sql-copyright-productization-plan.md).
Keep contracts and identity records in the restricted evidence store; only
non-sensitive evidence references belong in this repository.

## Verify and request review

Run focused tests for the affected module. Run Java Checkstyle from `fe/`
with `mvn checkstyle:check`. For UI changes, follow [ui/README.md](ui/README.md)
and include screenshots when page behavior or layout changes. Dependency
updates also require regenerated notices and an inspection of their source
licenses; a successful build alone does not complete license review.

Use commit and PR titles such as `[fix](ui) preserve public notice access`.
Complete [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md):
explain the problem and resulting behavior, link applicable issues, provide
release notes, and record tests and remaining limitations. Include the required
new documentation and provenance inputs in the change; generated bundles,
local caches and private evidence do not belong in the commit.
