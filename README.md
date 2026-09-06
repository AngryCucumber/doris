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

# MassDB SQL

MassDB SQL is an analytical database derived from Apache Doris. This repository
contains the FE SQL planning and coordination services, BE execution and
storage engine, web administration UI, and build and deployment tools.

The product is maintained by 厦门市美亚柏科信息安全研究所有限公司
(Xiamen Meiya Pico Information Security Research Institute Co., Ltd.).
MassDB SQL is an independent product; it is not an Apache Software Foundation
release or endorsement.

## Build and contribute

See [Repository Guidelines](AGENTS.md) for repository layout, toolchain
requirements, build commands and focused FE/BE/regression tests. Contribution
requirements are in [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
bash build.sh --fe --be -j 8
```

Build output is placed in `output/`. Configure and start the services using
the instructions in `AGENTS.md`; register BE with FE before running SQL suites.
For the React/TypeScript interface and notice checks, see [ui/README.md](ui/README.md).
The existing ARM64 Compose deployment examples are documented in
[docker-compose/README.md](docker-compose/README.md).

## Upstream source and licenses

The recorded source baseline is Apache Doris `4.0.5-rc01`, commit
[`59de8c4c524008e8ab2e43b79312f716a3a423a8`](https://github.com/apache/doris/commit/59de8c4c524008e8ab2e43b79312f716a3a423a8).
MassDB product versions are independent of upstream version numbers.
[MODIFICATIONS.md](MODIFICATIONS.md) records fork changes and source attribution;
[dist/product-provenance.json](dist/product-provenance.json) supplies build metadata.

Preserve [LICENSE.txt](LICENSE.txt), [NOTICE.txt](NOTICE.txt) and applicable
[distribution licenses](dist/LICENSE-dist.txt). Third-party components retain
their respective licenses. Review [thirdparty/LICENSE.txt](thirdparty/LICENSE.txt)
for upstream component-specific license choices and optional build switches.
New-code licensing, company copyright scope and
remaining release-material work are recorded in the
[copyright implementation plan](docs/massdb-sql-copyright-productization-plan.md).
The current engineering work does not establish completion of that release review.

The FE's public `/legal-notices` page provides bundled license texts and component
attribution. FE source archives are delivered separately under its installation's
`legal/` directory; BE materials follow the corresponding BE release instructions.

[Apache Doris documentation](https://doris.apache.org/docs/) is an upstream
technical reference; check version and fork differences before applying it.
Apache, Apache Doris and Doris are trademarks of The Apache Software Foundation.
