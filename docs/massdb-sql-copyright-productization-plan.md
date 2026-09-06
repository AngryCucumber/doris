# MassDB SQL 产品化版权与 FE 页面修改计划

- 编制日期：2026-09-05
- 本版修订日期：2026-09-06
- 修订版本：v8，启用公司声明，精简完整安装包并将构建证据与调试符号独立归档；最新执行记录见第 14 节。
- 检查基线：`bdd44bf2835b`
- 文档状态：实施中。首批实现已提交至 `3bea4c4`，后续页脚、公司声明和组包修改在工作区；未完成项保持未勾选。第 9—13 节为历史执行记录，当前材料边界以第 14 节为准。
- 路径约定：文件路径以仓库根目录为基准；清单中的“新增”表示本计划新增文件，是否已实现以勾选状态和第 9 节为准。
- 输出整理：历史 `output/build-release-*`、`output/legal` 和截图已按原目录名压缩至 `.build-records/20260906-audit.tar.gz`；`output/` 只保留最新程序及 tar/校验文件。旧安装及其 FE 数据已按维护者后续要求删除，迁移与删除记录见 `.build-records/layout-20260906.json`。

## 0. 本次评审的采纳与纠正

评审指出的权属证据、许可证兼容性、UI 依赖和发布版本映射缺口成立。第二轮三项建议采纳，具体边界如下；四个新增文件的独立编写来源已于 2026-09-05 获维护者确认。证据及完整文件清单见[仓库事实复核附录](massdb-sql-copyright-review-evidence.md)。

| 评审意见 | 复核结论与本版处理 |
| --- | --- |
| 英文署名未经主体核验 | 采纳核验要求，增加中文名和中英文对应记录；不把“英文署名一概无效”作为结论 |
| A09 不应过度悬置四个新增文件 | 来源确认已关闭：维护者确认三个 Compose YAML 和测试文件均为独立编写，四个文件已移除 ASF 贡献专用陈述并保留原 Apache 2.0 许可，公司权属署名仍归 D01/A08；两个复制的 conf 保留原 ASF 头。头模板相似本身不能证明代码复制 |
| 12 个提交、7 个 massdb-dev 提交 | 当前比较范围实为 13/8；扩大至首次已识别自有提交之前为 17/9，且包含其他作者的提交 |
| 42 个变动、24 个文本缺修改头 | 指定比较范围内成立；该范围遗漏了更早的 MassDB 补丁，增加扩展清单 |
| LGPL/CDDL/EPL 等影响闭源方案 | 采纳；把逐组件义务和实际链接验证放在新增代码授权决定之前 |
| MariaDB 的 FE 依赖身份可立即确认 | 采纳：POM、驱动加载及依赖复制链路已确认；已实现该库署名与 LGPL 指引，已校验官方 3.0.9 构件和对应源码；实际 FE 替换运行验证仍须完成 |
| 源码及重链接材料不应由 FE 页面承载 | 采纳交付职责调整：页面展示声明与获取说明，材料由对应 FE/BE 发行包及配套交付承担；书面要约须满足所选条款条件 |
| 账号及素材权属缺证据 | 采纳；增加受限证据库、账号对应和设计素材来源清单 |
| Doris 元数据、上游文档和基础镜像与独立产品矛盾 | 部分采纳：应修正误指的产品身份；真实上游来源、技术引用和基础镜像依赖并不等于官方背书 |
| npm 依赖完全没有声明 | 实施前主分发清单缺少列举的 UI 包；本批已从实际 webpack 模块生成包级声明和 SBOM，嵌入代码、素材与镜像仍需专项审阅 |
| 产品版本与上游不对应 | 采纳映射要求；二者可以独立编号，不强求版本号相同 |
| 顶层 MODIFICATIONS 可替代多数文件头 | 不采用这一默认方案；保留逐修改文件的固定简短说明，清单承载细节 |
| 商标、软著及招投标范围缺失 | 采纳，区分发布要求、登记申请和具体投标项目材料 |
| AGENTS 与计划未跟踪 | 属实，增加首批提交的纳入检查；文件写入不代表已经提交 |
| 商标句、NOTICE 和完整页面草案不充分 | 扩充中英文页面及 NOTICE 追加草案；只声明实际涉及的商标，不为套用措辞添加 Logo |

## 1. 目标、已确认信息与待确定事项

目标：在 MassDB SQL FE 中展示清晰的产品身份和公司版权信息，提供可访问的开源声明，并让源码、构建产物与发布包中的声明保持一致。

| 项目 | 当前约定 |
| --- | --- |
| 产品名称 | `MassDB SQL` |
| 公司中文名（用户提供） | `厦门市美亚柏科信息安全研究所有限公司` |
| 公司英文全称 | `Xiamen Meiya Pico Information Security Research Institute Co., Ltd.` |
| 公司名展示 | 中文页脚使用中文全称，英文页脚使用英文全称；声明页和 NOTICE 同时列出两者 |
| 主体核验状态 | 名称来自用户，尚未核验营业执照、统一社会信用代码、名称变更或英文译名对应文件 |
| 上游来源 | Apache Doris |
| 首期界面 | FE 登录页、登录后的公共布局、独立开源声明页 |
| 版权范围 | 公司确实拥有权利的原创内容与修改；上游、外部贡献及第三方内容按各自权利归属处理 |
| 年份 | 本计划以 `2026` 为示例；实施前确认首次发布年份和实际修改年份 |
| 新增代码许可证 | 尚未确定；公司名称确认不等于确认 Apache 2.0 或商业授权方案 |

本期兼容性约束：保留既有 Java 包名、C++ 命名空间、数据库协议、配置键、数据目录及已有容器路径；品牌展示调整不触发这些接口的全局改名。BE 页面纳入发布声明覆盖检查，视觉改版作为后续任务。

企业名称登记和法律文书应核对营业执照名称；合法的外文译名可以使用。工程上通过中文主体与英文译名的明确对应减少歧义，不能仅凭英文署名推定版权无效。[企业名称登记管理规定实施办法第 7、28 条](https://www.samr.gov.cn/zw/zfxxgk/fdzdgknr/fgs/art/2023/art_1e269e76abdb405ab5253b7c78e45f6a.html)

本计划包括产品发布的版权、许可与品牌准备；软著登记、特定投标证明材料列为专项工作，不代替正式申请。未解决的权属和许可义务阻止相应发布方案定稿，但不影响先编写和评审界面方案。

## 2. 实施前仓库事实（`bdd44bf2835b` 快照）

| 位置 | 已核实情况 | 对计划的影响 |
| --- | --- | --- |
| `ui/src/index.html` | 页面标题已改为 `MassDB SQL` | 核查实际发布产物，避免重复修改 |
| `ui/src/pages/layout/index.tsx` | `Footer` 已导入，但页面底部的 Footer 被注释 | 接入共用版权组件 |
| `ui/src/pages/login/index.tsx` | 登录页没有版权区域 | 单独接入同一组件 |
| `ui/src/pages/{login,layout}/index.less` | 两处 Logo 引用 `ui/public/img/logo.png` | 验证现有替换成果、比例和窄屏效果 |
| `ui/src/router/renderRouter.tsx` | 路由渲染包含登录状态判断 | 仅新增路由不足以保证未登录访问 |
| `ui/src/utils/request.tsx` | 请求封装会拦截未登录且非 login 的请求，并按 JSON 解析响应 | 声明文本使用公开静态资源，不走业务请求封装 |
| `ui/src/i18n.tsx` | 已接入中文、英文 JSON 资源 | 复用现有国际化机制 |
| `ui/package.json` | 名称为 `Doris`，`license` 为 `ISC`，存在历史作者字段 | 授权元数据与 Apache 源码头的关系需要核查 |
| `build.sh` | `build_ui()` 将 `ui/dist/` 复制到 FE 的 `src/main/resources/static/` | 声明资源须进入 UI 构建产物及 FE JAR |
| `build.sh` | 支持 `CUSTOM_UI_DIST` 和 `DISABLE_BUILD_UI` | 预构建 UI、跳过 UI 构建也需要发布检查 |
| `build.sh` | `copy_common_files()` 复制根 `NOTICE.txt`、`dist/LICENSE-dist.txt`、`dist/licenses/` | 核查实际分发声明是否覆盖全部随包组件 |
| `NOTICE.txt`、`dist/NOTICE-dist.txt` | 前者 84 行，后者 11,455 行，后者有大量额外依赖声明 | 依据实际依赖审阅合并，不能按文件大小判断合规 |
| `.licenserc.yaml`、FE Checkstyle | 使用 ASF 配置和专用头模板 | 原创公司文件与上游文件需要分别验证 |
| `docker-compose/conf/{fe,be}/*.conf` | 与相应根配置只有行尾空格差异 | 保留 ASF 头，不按公司原创文件处理 |
| 三个 Compose YAML、`ReportHandlerTest.java` | Git 作者均为郑百钦；维护者已确认四个文件独立编写，现存 ASF 贡献专用头不适合作为其署名模板 | A09 来源确认完成；D01 按实际权利人修正头，保留现有 Apache 2.0 许可 |
| `fe/pom.xml`、`fe/fe-core/pom.xml`、`StatementSubmitter.java` | MariaDB JDBC 声明 3.0.9，为默认 compile 依赖；SQL 提交器直接加载驱动，构建复制运行时依赖到 FE 的 `lib/` | 已确认 FE 自身运行时使用；落实库署名及 LGPL 指引 |
| MariaDB 分发清单 | 清单写 3.0.4，与 POM 不一致；两处 LGPL 路径误拼为 `licenes/` | 按实际交付 JAR 校验版本、哈希和替换能力，修正清单与路径 |
| gsasl 构建 | 默认源码 1.8.0，配置为静态库；清单同时写 1.10.0/1.8.0 | 对平台、链接和库许可提供证据 |
| `ui/` 依赖 | 未跟踪锁文件；主分发清单缺少列举的 React、antd 等 UI 包 | 固定安装结果，结合 webpack 模块清单生成声明 |
| 版本脚本、Compose | 脚本默认含 `-rc01`，镜像默认标签不含 | 核对生效构建参数并生成统一版本映射 |

上述表格保留实施前检查结果。当前工程变化与浏览器、构建验证见第 9 节；实际 FE 服务和发布镜像尚未验收。

## 3. 实施依据与署名规则

Apache 2.0 第 4 条要求随分发提供许可证、为修改文件标明修改、保留适用的源码权利声明及 NOTICE 归属信息；NOTICE 可通过随包文件、随附文档或适当界面提供，没有逐页展示要求。公司修改可以另加署名，NOTICE 不承担修改许可证的作用。[官方许可证](https://www.apache.org/licenses/LICENSE-2.0)

公司原创文件可采用自有版权署名；只有选定 Apache 2.0 授权后才使用对应 SPDX 标识。ASF 专用贡献者协议头不能作为公司原创文件的默认模板。[官方文件头说明](https://www.apache.org/foundation/license-faq.html)

产品使用 MassDB SQL 自有名称与 Logo。Apache Doris 用于真实的来源说明，避免暗示 ASF 官方发行、关联或背书；如果将 Apache 名称或 Logo 用于 Powered by 品牌展示，需要另行核对其附加条件。[官方商标规则](https://www.apache.org/foundation/marks/faq/)

| 文件来源 | 署名处理 |
| --- | --- |
| 未修改的上游文件 | 保留原有许可头及适用声明 |
| 修改的上游文件 | 保留原头，追加明确修改说明；有可主张的原创修改且权属确认后再追加公司版权 |
| 公司原创文件 | 权属确认后使用公司署名；按最终选定许可证标注 |
| 复制、改名或拆分的上游文件 | 继续记录上游来源，不按“新增路径”自动归为原创 |
| 第三方代码与素材 | 保留对应许可与署名，记录来源、版本和授权依据 |
| 不适合写注释的图片、字体、二进制 | 记录在关联素材清单与发布声明中，核对所适用许可证的要求 |

### 文件头示例

修改 Apache 2.0 上游文本文件时，默认在原头之后追加一行稳定说明：

```cpp
// Modified for MassDB SQL. See MODIFICATIONS.md for details.
```

`MODIFICATIONS.md`（已新增）记录当前路径、原路径、来源提交、修改内容和证据编号。Apache 2.0 第 4(b) 要求修改文件本身携带显著说明，因此顶层清单仅作补充。二进制及不能嵌入注释的格式逐类设计伴随声明，并验证其随对应文件分发。[许可证第 4 条](https://www.apache.org/licenses/LICENSE-2.0)

这条简短说明不替代其他许可证的具体要求；例如 LGPL 2.1 修改文件还涉及修改日期，CDDL 涉及修改者标识，须按对应组件的实际许可补充。

不把持续更新日期或长修改日志放入每个文件头，降低与上游同步的冲突；也不承诺每次 rebase 都会冲突。首次添加和上游调整头部时人工核对来源，后续同步检查说明是否保留。

如确有可由公司署名的原创修改，可以另加以下版权行；仅空白修正不自动产生公司独占版权：

```cpp
// Modifications Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
```

仅用于确认以 Apache 2.0 授权的公司原创文件：

```cpp
// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
```

文件采用 JSX、CSS、HTML、Shell 等格式时使用对应注释语法。新增署名不替换已有上游作者或版权人。

### 3.1 第三方许可与交付方案

新增代码选择商业授权之前，先完成“组件—确切版本—许可证表达式—修改情况—链接/打包方式—随包范围—履行方式”的矩阵。不能将全部组件只归结为保留 NOTICE，也不能将出现弱著佐权许可证直接等同于整个产品必须开源。

| 组件或许可 | 当前证据 | 必须形成的决策与交付记录 |
| --- | --- | --- |
| MariaDB Connector/J | 已确认 FE 直接运行时依赖；默认版本 3.0.9，官方该版本驱动标注 LGPL-2.1-or-later；本方案按 2.1 条款设计 | FE 版权展示纳入库原始署名与 LGPL 正文入口；发布时核对 JAR 版本/哈希、用户替换能力、shading/修改及对应源码 |
| libgsasl | 默认源码 1.8.0，链接参数含静态归档；2026-09-06 ARM64 BE/Cloud 的哈希一致重链接与 LLD 抽取记录确认未纳入对象 | 当前两个哈希不因该库要求重链接材料；更换二进制/平台/配置后重验，不能由无符号直接推断所有发行均不含该库 |
| FoundationDB | 实包默认客户端 7.1.57、附加客户端 7.3.69；补入对应上游 Apache 2.0 许可与 ACKNOWLEDGEMENTS | 对应各自二进制哈希和上游子组件声明，不只登记目录中的 7.3.69 |
| JindoSDK/JindoCore | 6.8.2 随 FE/BE 分发；项目仓库采用 Apache 2.0，但二进制内未找到 Jindo 自身许可，适用范围仍待证据 | 核实二进制分发授权、内嵌原生库和第三方声明；不能拿 Jackson 许可替代，也不直接认定闭源/无授权 |
| CDC 与 Java 包 | CDC 含 185 个嵌套 JAR；整包去重含嵌套共 927 个 Java 构件，已生成实物清单、SBOM 与审阅队列 | 已补 Debezium 1.9.8.Final 原文；所有构件仍需审阅，自动提取不等于许可兼容性通过 |
| CDDL 1.0/1.1 | 分发清单列有相关组件及许可选择 | 逐件核对实际许可，处理受覆盖代码及修改的源码可得性、声明和获取方法 |
| EPL 1.0/2.0 | 清单列有不同版本及部分选择 | 按具体版本分析覆盖范围和源码义务，不把 EPL 1.0 与 2.0 混用 |
| GPLv2 + Classpath exception、双许可 | 清单有此类标签 | 读取每个构件的原始授权；区分 `OR`、`AND` 和附加例外，记录实际选择，不能凭汇总标题任选 |
| MIT/BSD/Apache 等 UI 包与素材 | UI 已有实际 bundle 清单和 SBOM；素材来源仍待证据 | 审阅准确版本、原始版权、许可证及必要 NOTICE，覆盖传递依赖与打包素材 |

选择 LGPL 2.1 第 6(a) 路径时，静态链接交付需提供对应库源码及修改，并提供足以重新链接应用的目标文件和/或源码及必要构建材料。只给库源码通常不够；也不必由此推定必须公开所有应用源码。第 6(b) 的共享库机制需实际支持替换，书面要约等其他方式也有条件；最终采用哪种方式必须有验证记录。商业条款应允许该条要求的用户自用修改与调试修改所需的逆向工程。[该版本 LGPL 第 4、6 条](https://raw.githubusercontent.com/mariadb-corporation/mariadb-connector-j/3.0.9/LICENSE)

MariaDB 的依赖身份已经确定：`fe-core` 的直接依赖未另设 scope，SQL 提交器在第 68 行指定驱动、第 106 行调用 `Class.forName`；Maven 复制运行时依赖到 `target/lib/`，`build.sh` 再复制到 `output/fe/lib/`。这里不再保留“是否属于 FE 运行时”的待定项；最终 JAR 核对属于发行一致性检查。[Maven scope 规则](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html)、[运行时依赖复制规则](https://maven.apache.org/plugins/maven-dependency-plugin/copy-dependencies-mojo.html)。该版本的许可标识及版权来源见[官方 Driver.java](https://raw.githubusercontent.com/mariadb-corporation/mariadb-connector-j/3.0.9/src/main/java/org/mariadb/jdbc/Driver.java)。

LGPL 2.1 第 6 条要求随作品显著说明使用该库及适用许可、提供许可副本；当作品运行时显示版权声明，还须包含库的版权和许可副本指引。本次 FE 增加公司版权展示，因此将 MariaDB 运行时署名列为明确实现要求：共用版权组件同时显示该库原始版权行和本地 LGPL 正文入口，声明页完整展开同一归属信息。具体视图安排见 4.1–4.2，不再仅列为“待评估”。[LGPL 第 6 条](https://raw.githubusercontent.com/mariadb-corporation/mariadb-connector-j/3.0.9/LICENSE)

共用页脚是本方案选定的展示位置；第 6 条本身没有指定必须使用页脚或某个路由。

CDDL 和 EPL 分别按受覆盖代码与实际版本履行义务；Classpath exception 也不应被当成取消组件所有许可要求。[CDDL 正文](https://oss.oracle.com/licenses/CDDL)、[EPL 2.0 正文](https://www.eclipse.org/legal/epl-2.0/)。GNU SASL 1.8.0 的取证来源为[官方源码包](https://ftp.gnu.org/gnu/gsasl/libgsasl-1.8.0.tar.gz)中的 README 与 COPYING.LIB。

### 3.2 贡献者与素材证据

建立受限证据索引：`账号/作者名 → 实际自然人 → 任职或委托关系 → 任务与权属约定 → 提交/素材 → 授权范围 → 证据编号与核验人`。覆盖 `massdb-dev`、其他作者、共享账号使用人及外部贡献者；实名 Git 作者同样不等于公司当然拥有版权。

素材单独保留设计源文件、委托/授权条款、来源、修改与交付日期、哈希及允许用途。重点核查 `39c744ec4d6` 和 `74a21b8eb4c` 的图片变更。身份证明和合同保存在受限系统，公开仓库只保存证据索引及结论。[计算机软件保护条例关于委托和职务开发的规定](https://www.cac.gov.cn/2013-02/08/c_126468744.htm)

### 3.3 产品版本与来源映射

产品版本可以独立于上游编号。已新增受版本管理的 `dist/product-provenance.json`，经构建展开后供 SBOM、声明页和发布说明共用。最终记录还需覆盖生效构建参数、上游版本标签（若能核实）、挑拣补丁映射及实际镜像 digest。

当前事实：产品脚本默认 `massdb-sql-2.0.5-rc01`；`59de8c4c524008e8ab2e43b79312f716a3a423a8` 已核对官方 Apache 仓库，对应源码版本 `4.0.5-rc01`；`5abf4fdd0d5` 为含自有补丁的比较点。当前 HEAD 为 `bdd44bf2835bde62f582bde9338cf030cdfb92bb`，本批存在未提交修改，页面会显示本地修改标记。上游发布标签及挑拣映射尚未完整核验。CI 最终还须核对镜像标签、SBOM、页面及 RC 差异，不能把比较点当作官方发布版本。

**版本编号结论：保留 MassDB SQL `2.0.5` 作为独立产品版本，不因上游存在同名数字而改号。** 产品、镜像名称及版本展示必须包含 MassDB 身份；来源另列为 Apache Doris `4.0.5-rc01` 和已核验提交。禁止由产品版本拼出“基于 Apache Doris 2.0.5”。`dist/product-provenance.json` 用 `versionPolicy: independent-product-version` 记录该口径。RC、实际镜像标签与补丁映射仍按 E10 核对，编号原则确定不等于这些发布参数均已验证。

### 3.4 页面说明与源码材料交付

本计划默认将完整许可材料随对应发行交付。源码和重链接材料可放在安装包内，或作为同次发行的配套材料包随同提供；使用下载交付时，按所选条款在同一分发位置提供相应获取途径。页面只承载声明、许可正文和简短获取说明，源码归档、BE 目标文件及构建工具不进入 FE 的静态资源。

| 对象 | 交付内容与位置 | 验收责任 |
| --- | --- | --- |
| FE 页面 / JAR 静态资源 | 原始版权、LICENSE、NOTICE、组件清单及 `SOURCE-ACCESS.txt` 获取说明 | 前端核对显示、离线阅读及说明与发行清单一致 |
| FE 安装包及配套材料 | MariaDB 对应源码、适用修改、原始声明及 JAR 替换说明；采用第 6(b) 路径时验证用户可换用接口兼容的修改库 | 发布维护者核对 FE 组件版本/哈希、包内路径与替换结果 |
| BE/Cloud 安装包及配套材料 | 先确定实际纳入的组件；若包含适用 LGPL 原生代码，再按选定条款交付对应源码、修改、必要目标文件及重链接说明 | 逐二进制核对；当前两个 ARM64 哈希未纳入 gsasl/idn/hdfs3，不扩大为其他代码或平台豁免 |
| 镜像与其他发行形式 | 声明、材料索引及对应镜像 digest；若材料另行提供，记录随附介质或发行下载位置 | 验收镜像及其配套交付，不能仅凭 FE 页面入口认定完成 |

若选择 LGPL 2.1 第 6(c) 的书面要约，须随相应作品提供正式要约，至少三年有效，向同一用户提供第 6(a) 所述完整材料，收费不超过实际分发成本；同时明确发行标识、申请渠道、履行责任及保存期限。页面可展示要约副本或指向随包文件，但一句“可联系获取源码”不是完整要约。独立随包的库二进制还须核对第 4 条的源码义务，不能将第 6(c) 自动当作所有交付的替代方案。[LGPL 第 4、6 条](https://raw.githubusercontent.com/mariadb-corporation/mariadb-connector-j/3.0.9/LICENSE)

获取说明必须区分 FE 与 BE，并给出实际安装包中的相对位置、配套材料包名称及校验信息，或已经落实的发行下载/要约方式。包内路径以可复制文本展示，不伪装成 FE HTTP 下载地址。libgsasl 的材料及运行时署名按 BE 自身交付和显示场景落实，FE 的汇总说明不能替代 BE 的义务。

## 4. 页面文案与交互约定

### 4.1 共用页脚

中文界面先展示公司版权及范围，再展示 FE 所用 MariaDB 库的版权与许可指引：

```text
© 2026 厦门市美亚柏科信息安全研究所有限公司
MassDB SQL 自有修改与新增部分 · 开源声明
MariaDB Connector/J · LGPL 2.1 或后续版本
{{mariadbCopyrightNotices}}
LGPL 许可全文
```

英文界面：

```text
© 2026 Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
MassDB SQL modifications and original additions · Open-source notices
MariaDB Connector/J · LGPL 2.1 or later
{{mariadbCopyrightNotices}}
Full LGPL license
```

“开源声明 / Open-source notices”指向计划新增的公开页面 `/legal-notices`。公司名允许自然换行，完整文本可选择和复制；不通过省略号隐藏名称。页脚置于正常文档流中，避免覆盖登录表单、查询编辑器或结果表格。

`{{mariadbCopyrightNotices}}` 由对应发行库的原始版权声明生成，保留必要署名及年份，不以公司名替换；在共用版权组件中直接显示。LGPL 入口指向本地完整正文。这里只增加简短署名，完整组件清单和大型许可文本留在声明页按需阅读。

### 4.2 开源声明页面完整正文模板

下列正文及 4.3 的 NOTICE 追加文本供审阅。`{{...}}` 是由已核验构建清单填充的字段；资源列表动态对应实际交付内容。页面检查拒绝未替换字段、缺失版权、空许可及错误指引。源码/重链接材料在对应安装包、配套材料包或选定履行渠道验收；不要求 FE 提供其 HTTP 下载接口。

中文正文：

```text
MassDB SQL — 版权与开源声明

产品版本：{{productVersion}}
源码提交：{{sourceCommit}}
上游来源：Apache Doris（{{verifiedUpstreamDescription}}）

产品主体
厦门市美亚柏科信息安全研究所有限公司
英文名称：Xiamen Meiya Pico Information Security Research Institute Co., Ltd.

版权与许可
MassDB SQL 基于 Apache Doris 开发，包含本公司开发的修改与新增内容。
© {{copyrightYears}} 厦门市美亚柏科信息安全研究所有限公司。
该公司版权声明仅适用于公司实际拥有权利的修改与原创内容。
Apache Doris 及其他上游、第三方组件保留各自版权与许可证。
各部分的适用授权以本次发行所附许可文件和组件清单为准。

FE 使用的 LGPL 组件
MariaDB Connector/J {{mariadbVersion}}
{{mariadbCopyrightNotices}}
本产品 FE 使用此库；该库及其使用受 GNU LGPL 2.1 或后续版本约束。
[阅读本地 LGPL 2.1 许可全文]

Apache 软件来源声明
本产品包含 Apache Software Foundation 开发的软件。
原始上游版权和归属信息保留在下方可阅读的 NOTICE 中。

商标声明
Apache、Apache Doris 和 Doris 是 The Apache Software Foundation 的商标。
MassDB SQL 是独立产品，与该基金会无隶属关系，亦未获得其背书。

许可与材料获取说明
[阅读或下载许可证全文]
[阅读或下载 NOTICE 及组件原始版权声明]
[查看第三方组件、版本与许可证清单]
[阅读源码与重链接材料获取说明]
{{sourceAccessInstructionsZh}}
获取说明按 FE、BE 列明安装包内位置、配套材料包或适用的正式要约。
请按本次发行随附说明获取对应材料；本页不改变各组件许可证。

[返回产品] [返回登录页]
```

英文正文：

```text
MassDB SQL — Copyright and Open-source Notices

Product version: {{productVersion}}
Source commit: {{sourceCommit}}
Upstream: Apache Doris ({{verifiedUpstreamDescription}})

Product entity
厦门市美亚柏科信息安全研究所有限公司
English name: Xiamen Meiya Pico Information Security Research Institute Co., Ltd.

Copyright and licensing
MassDB SQL is based on Apache Doris and includes modifications and additions
developed by the company named above.
© {{copyrightYears}} 厦门市美亚柏科信息安全研究所有限公司
(Xiamen Meiya Pico Information Security Research Institute Co., Ltd.).
This company copyright notice applies only to modifications and original
content in which the company owns the relevant rights.
Apache Doris and other upstream and third-party components retain their
respective copyrights and licenses. Applicable terms are identified in the
license files and component inventory supplied with this release.

LGPL component used by FE
MariaDB Connector/J {{mariadbVersion}}
{{mariadbCopyrightNotices}}
The FE uses this library. The library and its use are covered by GNU LGPL
version 2.1 or later.
[Read the local LGPL 2.1 license text]

Apache software attribution
This product includes software developed by The Apache Software Foundation.
Original upstream copyright and attribution notices are retained in NOTICE,
which can be read below.

Trademark notice
Apache, Apache Doris and Doris are trademarks of The Apache Software Foundation.
MassDB SQL is an independent product and is not affiliated with or endorsed
by the Foundation.

Licenses and material access instructions
[Read or download full license texts]
[Read or download NOTICE and original component copyright notices]
[View components, versions and licenses]
[Read source and relinking material access instructions]
{{sourceAccessInstructionsEn}}
Instructions identify package locations, companion archives or applicable
formal offers separately for FE and BE. Follow the instructions supplied
with this release to obtain the corresponding materials.
This page does not alter their licenses.

[Back to product] [Back to sign-in]
```

商标句采用 ASF 的归属表达方式；若实际使用 Apache feather logo 或 Apache Doris logo，再在相应声明中列入这些图形商标。不为了照搬模板而在产品上新增这些 Logo。[Apache Doris 官网商标说明](https://doris.apache.org/)

页面默认显示 MariaDB 版权区，同时提供完整 NOTICE 和第三方声明的阅读视图，不能仅以下载按钮或泛称“开源组件”替代运行时库署名。许可英文正文保持原文，中文只翻译介绍和操作标签。[许可译文说明](https://www.apache.org/foundation/license-faq.html)

页面采用普通链接、标题和文本区域，提供回到产品或登录页的入口。完整许可与依赖文本按需加载；网络失败时显示明确提示。获取说明从 3.4 的已核验发行清单生成，只描述已经落实的路径或履行方式；正式书面要约另随发行提供并审阅，本页面模板不自动构成要约。

### 4.3 NOTICE 的公司追加文本草案

在保留本次分发所需的上游及第三方 NOTICE 条目的前提下追加以下段落；不是将现有 NOTICE 整体替换为公司声明。2026-09-06 已按维护者指示启用，采用本草案年份和有限范围；独立权属证据核验仍见 A01/A05/A08。

```text
MassDB SQL modifications and original additions
Copyright (c) 2026 厦门市美亚柏科信息安全研究所有限公司
English name: Xiamen Meiya Pico Information Security Research Institute Co., Ltd.

The company copyright notice above applies only to modifications and original
content in which the company owns the relevant rights.
MassDB SQL is derived from Apache Doris. Upstream and third-party copyright
and attribution notices remain applicable to their respective components.

This additional attribution does not change the licenses applicable to any
part of this distribution.
```

原有 Apache Doris、Baidu、Impala、Kudu、AWS 等条目是否适用依据实际内容审阅；新增组件的具体归属从其对应版本原文生成，不能用公司追加段落替代。最终完整文件作为构建附件进入发布审阅。

## 5. 修改清单

优先级：P0 为授权和发布必备事项；P1 为首期 FE 实现；P2 为后续完善。角色为责任建议，不表示已分配到具体人员。

### A. P0：确定权属与发布口径

建议责任：产品负责人、研发负责人；权属和商业协议由法务核对。

- [ ] A01：取得营业执照或官方登记核验记录，确认中文法定名称、统一社会信用代码及名称变更；留存英文译名的公司确认、官网或合同依据，建立两种名称的对应记录。
- [ ] A02：在 A07 的兼容性矩阵及链接交付分析完成后，确定自有修改与新增模块采用 Apache 2.0、商业授权或明确的混合方案，记录适用文件范围与 EULA 中第三方权利的例外。
- [x] A03：2026-09-06 按维护者“新增公司声明”指示采用前文草案的 2026 年；通过统一元数据维护展示年份，不以浏览器时间自动改写。此项记录署名口径，不代替 A08 的权属证据。
- [ ] A04：核验 3.3 的官方上游映射，覆盖比较点之前的 `381a8d6c9cf`；以附录 42+12 个路径为初始范围，区分自有补丁与上游挑拣提交。
- [ ] A05：为每个替换的 Logo、favicon、背景图和字体保留设计源文件、来源、哈希、任务/委托关系及可商用、可修改、可再分发的授权依据。
- [ ] A06：审阅第 4 节中英文文案；若采用商业授权，明确第三方组件条款的适用范围。
- [ ] A07：对实际 FE/BE/UI/基础镜像组件建立 3.1 的矩阵，逐项确认版本、许可、例外、修改、源码提供与重链接方式；未通过的组件明确替换、移除、调整链接或另取授权方案。已有 Java 实物 SBOM、927 项审阅队列和当前 ARM64 原生链接证据；567 个 Java 构件存在元数据/原文缺口，Jindo 二进制许可适用范围未关闭，不能勾选完成。
- [ ] A08：建立 3.2 的受限证据索引，核验 `massdb-dev` 对应人员及是否共享账号、其他作者与公司的权属关系，不能以 Git 用户名作为唯一依据。
- [x] A09：2026-09-05 维护者确认三个 Compose YAML 与 `ReportHandlerTest.java` 均为独立编写，关闭这四个文件的专项来源核查；提交记录见附录第 4 节。文件头修正并入 D01，公司权属统一按 A08 落实；两个复制配置保留原头。
- [ ] A10：在拟销售地区对 MassDB SQL、MassDB 及图形标识开展相同/近似商标检索，按实际商品服务确定类别；留存查询日期、数据库、结果和专业判断，未注册不使用注册标记。
- [ ] A11：确定软著登记与具体招投标材料的负责人和范围，准备基于开源修改的来源、授权和改进证据，不将整个 Doris 代码申报为公司独立开发。
- [x] A12：确认逐文件简短修改说明与顶层 `MODIFICATIONS.md` 的组合规则；定义上游同步后的差异与声明复查步骤。

验收：形成可引用的权属与授权记录；未确定的许可证不能通过自动替换文件头或包元数据来“默认确认”。允许继续实现和验证工程草稿，但发布定稿须落实相应决策。

### B. P1：FE 共用版权组件与页面

建议责任：前端研发。

| 类型 | 文件 | 计划内容 |
| --- | --- | --- |
| 新增 | `ui/src/constants/branding.ts` | 集中保存产品名、公司中英文全称、版权年份与声明入口；与现有 `constants.ts` 区分导入 |
| 新增 | `ui/src/components/legal-footer/index.tsx` | 共用版权组件，支持登录页和公共布局 |
| 新增 | `ui/src/components/legal-footer/index.less` | 换行、间距、窄屏和键盘焦点样式 |
| 修改 | `ui/src/pages/layout/index.tsx` | 接入共用页脚，避免重复渲染 |
| 修改 | `ui/src/pages/login/index.tsx`、`index.less` | 接入同一页脚，保持表单完整可用 |
| 新增 | `ui/src/pages/legal-notices/index.tsx`、`index.less` | 来源介绍、商标说明、许可阅读与下载 |
| 修改 | `ui/src/router/index.ts` | 注册公开路由，置于通配的 `/` 布局路由之前 |
| 修改 | `ui/src/router/renderRouter.tsx` | 通过明确的公开路由标记支持声明页，保持业务页面登录要求 |
| 修改 | `ui/public/locales/zh-cn.json`、`en-us.json` | 增加版权范围、声明、下载、返回、错误提示等翻译 |
| 按需核查 | `ui/src/App.tsx`、`ui/src/utils/utils.ts` | 验证 BrowserRouter basename 与代理路径兼容性 |

- [ ] B01：用统一元数据实现第 4 节文案；中文页脚用中文名，英文页脚用英文名，声明页同时展示中英文主体对应。
- [x] B02：完成登录页、主布局和开源声明页的共用组件接入。
- [x] B03：对 `/legal-notices` 显式支持未登录访问；不能只依赖路由排序或当前模块级登录状态变量。
- [x] B04：通过普通静态链接或独立的文本读取逻辑获取许可，不调用会检查登录并解析 JSON 的业务请求封装。
- [x] B05：链接与返回导航适配现有部署前缀；验证直接访问、刷新、浏览器前进与后退。
- [x] B06：文本采用纯文本渲染；检查超长行、换行、阅读和下载行为。
- [ ] B07：检查 375px、768px、1440px 视口及中英文切换；页脚不遮挡原有操作。
- [x] B08：确认当前产品名称、Logo、favicon 在构建后实际显示正确；不进行无差别的 Doris 字符串替换。
- [ ] B09：展示经核验的产品版本、源码提交与上游说明；在共用版权组件和声明页显示 MariaDB 原始版权及 LGPL 正文入口；提供 3.4 的材料获取说明，完整源码和重链接材料由对应发行交付。

验收：未登录和已登录均能阅读声明；业务页面登录行为保持正常；公司名无截断、页面无重复页脚、无需外网即可阅读随包许可。

### C. P0/P1：声明内容与静态资源生成

建议责任：构建维护者、前端研发。

| 类型 | 文件 | 计划内容 |
| --- | --- | --- |
| 审阅 | `LICENSE.txt`、`NOTICE.txt` | 保留适用上游声明；在 NOTICE 中追加公司的适用修改署名 |
| 审阅 | `dist/LICENSE-dist.txt`、`dist/NOTICE-dist.txt`、`dist/licenses/` | 按实际分发组件核对许可证、归属声明和版本 |
| 新增 | `build-support/prepare-product-notices.py` | 从受审阅的仓库声明生成可复现的分发文件和索引 |
| 新增 | `ui/scripts/collect-bundled-licenses.cjs` | 结合实际安装树和 webpack 产物识别随包组件、原始许可及 NOTICE |
| 新增 | `dist/product-provenance.json` | 产品版本到可信上游及补丁的受审阅映射，构建时展开为发行记录 |
| 修改 | `ui/package.json` | 接入声明资源准备步骤；授权元数据核查后再修改相关字段 |
| 按需修改 | `ui/config/webpack.common.js`、`webpack.dev.js` | 支持开发和生产静态声明访问，协调清理及输出时序 |
| 修改 | `build.sh` | 把一致的声明产物接入 UI、FE/BE 分发与自定义 UI 路径 |

建议生成布局：

```text
ui/dist/legal/
  LICENSE.txt          # 适用于当前交付内容的许可正文
  NOTICE.txt           # 适用的上游、公司及随包组件归属声明
  THIRD-PARTY-NOTICES.txt # UI 与其他实际随包组件的完整必要声明
  licenses/            # 所需第三方许可正文
  SOURCE-ACCESS.txt    # 按 FE/BE 列出的源码与重链接材料获取说明
  manifest.json        # 来源、版本、版权、文件名、校验值与发行材料索引
```

以上是 UI 产物的核心结构；当前另生成 `MARIADB-NOTICE.txt`、`MODIFICATIONS.txt`、`components.json`、`sbom.cdx.json`。完整源码及重链接材料按 3.4 进入对应发行或配套材料包；例如安装包根目录下的 `legal/sources/`、BE 的 `legal/relink/`，当前 FE 已使用 `legal/FE-SOURCE-ACCESS.txt`；BE 说明的路径与内容待其实际材料组装确定。这些目录不复制到 UI 或 FE 静态资源。仓库声明继续作为受版本管理的输入，构建输出进入生成目录。

- [ ] C01：审阅根 NOTICE 与分发 NOTICE 的差异；保留适用于实际交付内容的条目，并记录合并或去重依据。
- [x] C02：新增声明生成步骤；输入缺失、许可文本为空或必需文件未生成时返回失败。
- [x] C03：将声明放入 UI 输出目录；处理 `CleanWebpackPlugin` 的清理顺序，不假定 `ui/public/` 会自动完整复制。
- [ ] C04：开发服务器和生产 FE 均提供同一套相对结构；页面链接适配实际静态资源地址和部署前缀。
- [ ] C05：确认 UI 的声明、许可正文和获取说明进入 `fe/fe-core/src/main/resources/static/` 及 FE JAR；复制范围不包含发行用源码归档、BE 目标文件或构建工具。
- [ ] C06：同一发布的 FE/BE 安装目录使用与页面相匹配的声明；如范围不同，在索引中明确各自包含的组件。
- [ ] C07：处理 `CUSTOM_UI_DIST`：验证其声明与本次分发相符，或统一注入本次声明；处理 `DISABLE_BUILD_UI`：发布检查仍然执行。
- [x] C08：声明生成后，比较输入来源、输出哈希和页面可下载文件；禁止缺失文本被 SPA 的 `index.html` 回退响应掩盖。
- [x] C09：固定受支持的 Node/npm 版本与 UI 锁文件；保留实际解析版本和 integrity，清单不能直接把 `^4.5.4` 等范围当作发行版本。
- [ ] C10：运行 5.C.1 的依赖与 bundle 取证，覆盖直接/传递依赖、动态 chunk、CSS、字体和图标；包括虽列在 devDependencies 但已入包的 CodeMirror。
- [ ] C11：生成 `THIRD-PARTY-NOTICES.txt`、组件清单与 SBOM；回查每个包的 LICENSE、NOTICE、版权头、例外及实际许可选择，缺失或无法判断则进入人工处理。
- [ ] C12：依据 A07 与 3.4，为 FE/BE 各平台分别组装对应源码、修改、必要对象文件及替换/重链接说明；记录与产物的版本和哈希对应并验证可用性。采用正式要约时核对期限、渠道和履行能力；页面只接收已核验获取说明。
- [ ] C13：修正 MariaDB 版本陈旧和 `licenes/` 路径错误，核定各平台 gsasl 版本；将类似清单与实物不一致加入失败条件。

验收：开发 UI、FE JAR、安装包均包含可阅读声明；页面获取说明准确，发行材料按选定方式完整可得，文件和版本可追溯。有效的随包交付不因缺少 FE 源码下载接口而失败。保留现有 `LICENSE-dist.txt` 等下游依赖的命名，或同步更新所有引用后再规范化。

### 5.C.1 UI 依赖清单生成步骤

1. 选择与当前 webpack 4 工程匹配的 Node/npm，生成并审阅 UI 锁文件；后续在干净环境按锁文件安装，保留 registry、完整性信息和安装日志。
2. 导出完整安装树，并用生产配置导出 webpack stats。示例在 `ui/` 中执行，输出放在 `ui/dist/` 外避免构建清理：

   ```bash
   mkdir -p ../output/legal
   npm ls --all --json > ../output/legal/ui-dependency-tree.json
   NODE_ENV=prod ./node_modules/.bin/webpack --profile --json > ../output/legal/ui-webpack-stats.json
   ```

3. 检查命令状态及 JSON 可解析性；处理缺失/无效依赖。若 SpeedMeasurePlugin 等输出污染标准输出，改为从构建 API 导出 `stats.toJson()`，不把日志当成合法清单。
4. 将 stats 中各 chunk/module 的实际路径映射到最近的包元数据，按包名、版本、来源和哈希去重；另核对复制资源、CSS 引用与外部资源。安装树不是最终随包树，构建工具和运行时依赖需要区分。
5. 从实际安装包收集原始许可、归属和 NOTICE，验证包含 React、antd、CodeMirror、sql-formatter 及其实际随包依赖；人工处理多许可、无 SPDX 或只有许可证链接的情况。
6. 生成机器可读清单、完整第三方声明和单独许可文件，接入 C03–C08 的静态资源/分发链。以 bundle、JAR 内资源和安装包再反查一次，避免只检查源项目。

上述命令依据 [npm ls 文档](https://docs.npmjs.com/cli/v11/commands/npm-ls/)和 [webpack 4 CLI 文档](https://v4.webpack.js.org/api/cli/)；实际 npm 版本由工程验证确定。合并声明时保留许可证要求的版权、许可与免责内容，不能只输出许可证名称列表。

### D. P0：源码头、包元数据和自动检查

建议责任：仓库维护者。

- [ ] D01：以附录逐文件清单整改本次发行包含的历史差异，24 个比较范围内修改文本及更早补丁补齐适用修改说明。四个 A09 已确认独立编写文件保留现有 Apache 2.0 许可，按 A08 确认的权利人改用准确署名，移除不适用的 ASF 贡献专用陈述；这项修正不撤销已有许可。两个复制配置保留原头，不向所有文件批量追加公司版权。
- [ ] D02：调整 `.licenserc.yaml` 及必要的辅助规则，验证上游头、公司原创头、修改声明和第三方例外。
- [x] D03：检查 `fe/check/checkstyle/checkstyle.xml`、`checkstyle-apache-header.txt`；让新规则接受正确的不同来源声明，同时保留其他代码风格检查。
- [ ] D04：如涉及 Groovy 框架头规则，同步检查 `regression-test/framework/checkstyle.xml` 和 `checkstyle-apache-header.txt`。
- [ ] D05：调整 `.github/workflows/license-eyes.yml` 的检查入口，覆盖实际开发分支、PR 和发布检查；不通过关闭全部头检查来解决冲突。
- [ ] D06：核查 `ui/package.json` 的 `ISC`、上游源码头及相关许可证文件的历史依据；A02 完成后再确定其 license 表达，不直接假定它是笔误。
- [x] D07：按内部包使用方式评估将包名规范为 `massdb-sql-ui`；保留历史作者的正确归属，维护者信息与原作者信息分别表达。
- [ ] D08：为自动化声明检查增加有意义的正反例：原始上游头、公司原创头、修改头可通过；删除上游头、遗漏修改声明、空分发声明会失败。
- [x] D09：新增并维护 `MODIFICATIONS.md`，记录差异、复制、改名和来源证据；与每个修改文本的固定简短说明配合。
- [ ] D10：将计划、事实附录及 `AGENTS.md` 显式纳入首批 Git 提交；用 `git ls-files` 和提交差异确认 PR 中存在所引用文档，个人工作目录及受限证据材料不随附。

验收：新旧合法文件均能通过检查；错误声明确实导致失败；任何自动修复都不会覆盖上游及第三方归属。

### E. P0/P2：发布包、镜像与文档

建议责任：发布维护者、文档维护者。

- [ ] E01：验证 `build-for-release.sh` 产生的归档包含完整声明与获取说明；检查 FE/BE 的随包或配套源码材料、重链接材料及适用正式要约，记录各包文件清单和关联哈希。
- [ ] E02：核查实际 MassDB 镜像构建入口；`docker-compose/README.md` 仅说明完整构建输出随镜像分发，不能据此认定声明已完整进入镜像。
- [ ] E03：核查 `docker/runtime/fe/Dockerfile`、`be/Dockerfile`、`ms/Dockerfile`、`all-in-one/Dockerfile` 等实际使用路径，以及镜像基础系统、JAR、原生库和前端资源的许可范围。MS 现调用共用声明复制，仍须对真实镜像逐个验证；不以“只发整包”免除组件或镜像检查。
- [ ] E04：为发布产物保存依赖清单/SBOM、版本、来源、许可证及声明位置；将缺项纳入发布检查。
- [x] E05：调整 `README.md` 的产品介绍和来源说明；更新 `CONTRIBUTING.md`、`AGENTS.md` 中与署名、头检查及验证方式相关的规则。
- [x] E06：更新 `ui/README.md`、`docker-compose/README.md`，说明开源声明入口和随包文件位置。
- [ ] E07：核对 BE 自身运行时版权显示及 libgsasl 等适用署名，本次发行所需义务按 P0 落实；BE 页面的其余视觉调整列 P2，继续保留 BE 分发包中的许可文件和材料获取说明。
- [ ] E08：按下表盘点产品身份和来源引用；对误导性身份修正、真实上游资料标注来源、技术兼容标识保留，不以字符串全局替换完成包装。
- [ ] E09：记录所用基础镜像的来源、digest、许可证和系统包清单；确认实际 MassDB ARM64 构建入口，再决定沿用或构建公司维护的基础镜像。
- [ ] E10：产品版本、RC、源码提交、上游补丁映射、镜像标签与 SBOM 均由 3.3 的元数据核对；未知官方上游版本不能伪填。

身份及来源盘点表：

| 位置 | 处理方式 |
| --- | --- |
| `README.md`、`ui/package.json` | 修正当前产品名、维护渠道；保留来源及原作者的正确归属 |
| `fe/pom.xml` 及实际发布子模块 POM | 核查 name、url、SCM、issue、mailingLists 及继承元数据；填入真实 MassDB 项目地址或移除不适用字段，不虚构公司地址 |
| `doap_Doris.rdf` | 当前是 ASF Doris 项目描述，不能作为 MassDB 项目身份发布；评估移出分发、作为上游参考保留或删除，不视为法律上一律必须删除 |
| `.asf.yaml`、`doap_Doris.rdf`、`CONTRIBUTING.md`、`CODE_OF_CONDUCT.md` | 核查 ASF 专属自动化、项目治理和联系渠道是否被误用于本产品 |
| `be/src/http/web_page_handler.cpp` | `alt="Doris"` 应与实际显示的 MassDB Logo 一致 |
| `be/src/http/default_path_handlers.cpp` | 上游技术文档链接可以保留，明确标注来源及版本适用性；若有对应产品文档再替换 |
| `docker/runtime/{fe,be,ms}/Dockerfile` | `FROM apache/doris:base-4.0` 是依赖来源，不构成 ASF 背书；锁定 digest 并核查镜像内容 |
| `docker/runtime/all-in-one/Dockerfile` | 当前从 Ubuntu 构建，不与上述基础镜像路径混为一谈；核查实际发布所选路径 |
| Java 包名、Maven groupId、配置键、容器路径 | 属于技术接口或兼容标识；改名需要另行评估迁移，不作为视觉包装必做项 |

真实的来源引用或依赖使用与“独立产品、无背书”并不冲突；需避免的是把自己的发行或维护渠道误写成 ASF 官方项目。[ASF 商标政策](https://www.apache.org/foundation/marks/)

验收：安装包、独立 FE/BE 包和实际发布镜像均可定位声明；页面与发布文档中的产品身份一致。

### F. P0/P2：中国侧登记、商标及交付证明

建议责任：产品负责人、公司法务/知识产权负责人。

- [ ] F01：保存中文主体与统一社会信用代码核验记录，将英文译名对应证明关联到 NOTICE、合同和登记材料。
- [ ] F02：完成 A10 的商标检索与专业判断，覆盖实际销售地区和相关商品服务；检索未发现冲突不等于权利保证，保留查询范围和日期。[官方商标查询提示](https://sbj.cnipa.gov.cn/sbj/sbcx//)
- [ ] F03：如申请软著，明确基于开源修改的开发方式、可主张部分、功能/性能改进、原软件来源及许可材料；按登记机构要求核对鉴别材料及名称一致性，不通过删除上游头伪造独立开发证据。[软件著作权登记办法第 7、9–11、17 条](https://www.ncac.gov.cn/xxfb/flfg/bmgz/202410/P020241015604759788122.pdf)
- [ ] F04：将营业执照、软件版本、开发完成时间、公司权属文件、开源许可与可能需要的补充证明形成申请材料索引；是否受理及证明是否充分由登记流程核定，本计划不承诺获证。
- [ ] F05：按每个招投标文件列明著作权证书、授权说明等实际要求和负责人；不将全部项目都假定为必须持有同一种证书。

软件著作权登记不是版权产生的普遍前提，登记证明也不是对所有开源许可履行情况的认证；登记和特定投标准备作为专项跟进。[计算机软件保护条例第 7、14 条](https://www.cac.gov.cn/2013-02/08/c_126468744.htm)

## 6. 验证矩阵与执行命令

以下为完整验证要求；已执行范围见第 9 节。UI 已固定 Node 22.23.2、npm 10.9.9，生成脚本需要 Python 3.9+。FE/BE 集成构建仍需仓库对应工具链。

| 验证对象 | 命令或方式 | 通过条件 |
| --- | --- | --- |
| UI 编译 | 首次按 C09 固定安装和锁文件；后续在 `ui/` 中按已验证工具版本运行 `npm ci --legacy-peer-deps`、`npm run build` | 编译成功，声明与实际安装/打包版本对应 |
| UI 开发 | 在 `ui/` 中运行 `npm run dev` | 登录页和声明资源均可访问；业务代理指向实际测试 FE |
| FE 集成构建 | 根目录运行 `bash build.sh --fe -j 8` | 默认启用 UI 构建时，FE JAR 包含页面与声明资源 |
| Java 规则 | 在 `fe/` 中运行 `mvn checkstyle:check`（规则文件使用相对路径） | 头规则和原有风格检查通过 |
| C++ 文件头 | 仅在本批修改 C++ 文件时运行仓库 clang-format 16 检查 | 格式一致，原有许可头保留 |
| 分发组装 | 完成必要构建后检查 `output/fe/`、`output/be/` 和归档 | 声明完整、非空、与依赖清单对应 |
| Docker | 在实际发布镜像中检查声明文件，并访问其 FE 页面 | 镜像内正文存在且页面能读取 |
| FE 运行时版权 | 检查共用版权组件及声明页的 MariaDB 原始版权、许可说明与本地正文入口 | 公司版权和库署名均实际显示，正文可离线阅读 |
| LGPL 链接与交付 | 对 FE/BE 安装包、配套材料及选定交付渠道核对版本/哈希、对应源码、目标文件与替换/重链接结果 | 所选履行方式实际可用，适用正式要约可履行；材料完整性不以 FE 是否提供下载接口判断 |
| 依赖完整性 | 对照 npm 安装树、webpack stats、FE JAR、原生库及基础镜像清单 | 无漏列组件，许可证正文路径有效，版本无过期混用 |
| Git 文档 | `git ls-files AGENTS.md docs/massdb-sql-copyright-productization-plan.md docs/massdb-sql-copyright-review-evidence.md` | 首批提交后所需文档均已纳入，不仅存在于本地未跟踪文件中 |

浏览器与访问验收：

- [ ] V01：无 Cookie、无 localStorage 的新浏览器上下文中，登录页公司版权、MariaDB 原始版权与许可指引均正确显示。
- [x] V02：未登录直接访问 `/legal-notices` 并刷新，内容正常，无登录弹窗或跳转循环。
- [x] V03：已登录访问声明页并返回业务页面，会话状态保持正确。
- [x] V04：未登录访问业务页面仍遵循原登录规则；公开声明资源不调用业务接口。
- [ ] V05：根路径和实际使用的反向代理前缀下，页面、语言切换和下载都正常。
- [ ] V06：在中文、英文及 375px/768px/1440px 视口下检查完整公司名、页脚布局、键盘可达性。
- [ ] V07：断开外网后，已部署 FE 仍能提供本地许可正文；外部 Apache 链接不影响本地阅读。
- [x] V08：打开 `/legal/LICENSE.txt` 等最终实际地址，核验状态码、文本类型和正文；不能只检查 HTTP 200。
- [ ] V09：正常构建、自定义 UI 产物和跳过 UI 构建三种发布流程都执行声明完整性检查。
- [ ] V10：保留登录页、业务页脚、声明页的中英文截图，以及构建、包内文件和声明校验记录。
- [x] V11：对 UI 第三方包声明进行缺项、无效路径、版本不一致的失败验证；确认 CodeMirror 等实际入包的 devDependency 也被覆盖。
- [ ] V12：分别从 FE/BE 实际发行和配套材料完成 LGPL 替换/重链接及获取验证；校验包内路径、材料哈希和适用要约的期限/履行渠道，页面说明与之相符。随包材料齐全时，不要求另有 FE HTTP 下载入口。
- [ ] V13：校验版本/来源字段均已核验且与产物一致，页面无模板变量或未处理的许可缺口。
- [ ] V14：上游同步后复查固定修改说明与 MODIFICATIONS 清单，保留复制来源和原有权利声明。

对登录判断和声明生成这两类行为变更增加针对性验证；纯文案与样式以构建和浏览器验收为主，优先复用现有验证方式。

## 7. 建议提交顺序

| 批次 | 建议标题 | 内容与前置条件 |
| --- | --- | --- |
| 1 | `[docs](legal) record provenance and licensing decisions` | 纳入本计划、事实附录及 AGENTS；完成发布方案所需 A 项与 F 项核验记录，未完成项明确状态 |
| 2 | `[chore](license) correct attribution and header checks` | 完成 D 项及本次发行历史差异整改，保留真正的上游复制头 |
| 3 | `[fix](build) deliver complete notices and license materials` | 完成 C 项、实际源码/重链接方案及 E 项发布验证；授权方案取决于此批的可行性 |
| 4 | `[feat](ui) add copyright footer and public legal notices` | 完成 B 项，依赖第 3 批资源契约，执行 V01–V14 中相关项 |
| 5 | `[docs](product) align branding and release provenance` | 同步身份元数据、版本映射、用户文档及发布证据；登记申请、具体投标和 BE 视觉扩展另按范围推进 |

每批 PR 描述包含具体行为变化、相关文件、验证结果；界面批次附截图。声明正文变更附来源与差异说明。

回退时保持已经交付的必要许可和署名文件；若前端功能需要回退，应保留可访问的声明入口或公开静态声明页。

## 8. 完成交付检查

- [ ] 中英文公司名称一致且对应关系有核验记录，中文登记材料使用已核实的法定名称。
- [ ] 年份、权属范围和新增代码授权方式有明确记录。
- [ ] FE 登录页与公共布局显示公司及 MariaDB 版权与 LGPL 指引，开源声明页支持未登录访问。
- [ ] Apache Doris 来源与商标说明清楚，完整许可和适用 NOTICE 可离线阅读。
- [ ] 上游和第三方声明得到保留，修改文件具有修改说明。
- [ ] A09 来源确认已归档，四个独立编写文件的头及全部待交付修改均已处理，复制文件的真实 ASF 头保留。
- [ ] LGPL 等组件的 FE/BE 发行材料及选定交付方式已验证，页面获取说明准确，商业条款与之相容。
- [ ] UI 及镜像传递依赖均有准确版本和必要声明，产品版本到上游的映射可追溯。
- [ ] 头检查、UI 构建、FE 集成和实际发布包检查通过。
- [ ] 自定义 UI、跳过 UI 构建及 Docker 镜像的声明交付路径均已验证。
- [ ] 中英文截图、测试记录、依赖清单与最终产物校验信息随发布归档。
- [ ] 商标检索、主体与贡献者证据已按发布范围核验；软著和投标专项的状态明确。
- [ ] 计划、附录与 AGENTS 已在对应提交中纳入，受限证据仅保留索引。


## 9. 首批实施记录（2026-09-06，本轮代码复核前）

本批根据“可以开始执行计划吗”的指示开展工程实施。勾选表示对应已验证范围完成，不表示本计划整体已完成；涉及完整 FE/BE 发行的条目仍保留未勾选。Git 工作区中的改动和新增文件尚未提交。

### 9.1 已落地的工程改动

| 范围 | 当前成果 | 对应清单及边界 |
| --- | --- | --- |
| 来源与历史文件 | 核对官方 Apache 仓库的 `59de8c4c524008e8ab2e43b79312f716a3a423a8`；扩展清单内 35 个历史修改文本和 2 个复制配置保留原头并添加固定修改说明；新增 `MODIFICATIONS.md` | A04 部分、A12、D01 部分、D09；上游挑拣补丁的官方映射和公司权属仍待核验 |
| 独立编写文件 | 三个 Compose YAML、`ReportHandlerTest.java` 改用通用 Apache 2.0 许可头，移除 ASF CLA 陈述；尚未添加未经确认的公司版权 | A09 来源已确认；D01 权属署名部分待 A08 |
| FE 页面 | 共用页脚、公开声明页、中英文正文、本地阅读和下载；显示 MariaDB 原始版权与 LGPL 指引；修正模块缓存登录判断、菜单索引和部署前缀资源定位 | B02–B06、B08；公司 Copyright 行由未开启的确认字段控制，B01/B07/B09 的完整验收待后续 |
| UI 依赖 | 锁定 Node 22.23.2/npm 10.9.9 和 npm lockfile；从 webpack 模块收集实际入包组件，包括动态 chunk、CSS 和 CodeMirror；生成第三方正文、组件清单、CycloneDX SBOM、文件哈希及 webpack 取证 | C09 已完成；C10/C11 已实现包级取证，复制素材、嵌入第三方代码及许可例外的人工审阅未完成 |
| 声明资源 | `prepare-product-notices.py` 与 webpack 插件共同生成 `legal/`；保留根及分发 NOTICE 正文，校验原始输入、元数据、文件哈希和产物清单；拒绝缺项、空文本及 HTML 回退 | C02/C03/C08；C01 的逐条适用性与去重审阅未完成 |
| FE 组装 | `build.sh` 接入默认、自定义及已有 UI 的校验，并检查 JAR 内资源；FE 对应 MariaDB 源码归档独立放在 `legal/sources/`，生成 `legal/FE-SOURCE-ACCESS.txt` | C05/C07/C12 部分；官方 JAR/源码的独立组装已验证，完整 FE 构建、用户替换驱动和 BE 重链接尚未验证 |
| 元数据与文档 | 修正 MariaDB 3.0.4 陈旧记录和 `licenes/` 拼写；新增受版本管理的产品来源输入；更新 README、贡献指南、UI/Compose 说明和 AGENTS | C13 部分、D07、E05/E06；gsasl 多平台实物、Maven 身份与镜像元数据仍待处理 |
| BE 文案 | Logo 的 alt 改为 MassDB SQL；内存文档标题明确 Apache Doris 上游来源 | E08 部分；不等于完成 BE 运行时许可展示或 BE 发布验收 |
| 头规则 | FE Checkstyle 单独验证独立测试文件的通用 Apache 头，其余 Java 文件继续原 ASF 头规则 | D03；License Eyes 及新原创文件授权头尚未定稿，D02/D05/D08 不能勾选 |

### 9.2 已执行的验证与可复现命令

- UI：在 `ui/` 中按固定工具版本执行 `npm ci --legacy-peer-deps`、`npm run build`、`npm run check:notices`、`npm run test:legal`。浏览器检查使用真实生产 bundle、本地静态服务与模拟业务响应，不是完整 FE 服务测试。
- 浏览器覆盖根路径、`/proxy/fe` 和 `/gateway/cluster/fe/default` 前缀；验证声明公开访问及刷新、登录/返回导航、本地 LGPL 阅读与下载、HTML 回退错误、中英文及 375/768/1440px 布局。关闭外部请求后，本地声明仍可阅读。公司 Copyright 开关尚未开启，对该行的显示不算验收通过。
- 产物检查：根目录执行 `python3 -m unittest discover -s build-support -p test_product_notices.py -v`；9 项测试覆盖声明缺失、HTML 回退、未列资产、空/不一致组件清单、陈旧元数据、与仓库原文不一致的声明、JAR 静态资源往返及 FE 源码与二进制匹配。
- 开发服务：已启动 webpack 开发服务并以浏览器读取公开声明和 LGPL 正文；开发构建保留生产输出，生产构建清理后重新生成声明。
- Java：在 `fe/` 中执行 `mvn checkstyle:check`，16 个 Maven 模块通过，0 个违规；根目录 `mvn -f fe/pom.xml checkstyle:check` 会受现有相对头模板路径影响，文档已改正工作目录。
- FE 材料：用官方 MariaDB 3.0.9 JAR 与对应源码归档完成独立组装验证；SHA-256 由 `dist/product-provenance.json` 固定。此项不是 FE 服务启动、驱动替换 SQL 测试或 BE 重链接验证。
- C++：使用 clang-format 16.0.6 对本批全部 8 个修改的 C++ 文件运行 `--dry-run --Werror`，检查通过；同时逐文件核对 48 个现有 ASF 头保持原文，4 个独立编写文件使用通用 Apache 2.0 头。
- 脚本与差异：执行 `bash -n build.sh build-for-release.sh`、`git diff --check`。本批其余历史 Java/C++/Groovy 文件仅追加修改说明，不改变数据库行为。

本地验证记录位于 `output/legal/`：`ui-dependency-tree.json`、`ui-bundled-packages.json`、`ui-webpack-stats.json`、UI 组件和声明产物、`screenshots/` 及 `fe-package-verification/`。它们是本次工程取证输出，未自动加入 Git，也不是正式发行归档。正式发行仍须归档对应最终提交与平台产物的证据。

本次生产构建识别 128 个依赖包实例和 33 个 UI 资源；保留登录页、业务页脚及声明页的 18 张中英文/视口截图。最终验证摘要及声明清单哈希见 `output/legal/verification.json`，构建、浏览器、产物测试和 Checkstyle 日志一并保存在该目录。开发模式取证使用其下 `ui-development/`，避免覆盖生产证据。

### 9.3 等待确认和后续实施

1. **A02/A03/A08：** 本次新增组件、生成脚本和测试的授权方式，以及公司可署名范围和起始年份，已在会话中请求确认，尚未收到答复。`dist/product-provenance.json` 保持 `newCodeLicense: null`、`companyCopyrightConfirmed: false`；`2026` 只是待确认的配置值。新增原创源码采用明确的待定授权状态头，由独立检查器验证，详见第 10 节；收到决策后补齐实际授权头，过渡状态不准进入正式发布。公司 NOTICE 追加段落尚未启用。
2. **A01/A05/A08/F：** 营业执照/英文译名对应、账号权属、素材授权、商标与登记材料仍需对应资料或负责人的核验记录；没有将用户确认“独立编写”扩大为全部内容的公司权属确认。
3. **A07/C01/C10–C13/E01–E04/E07/E09：** 完成 FE 全部运行依赖、BE 实际静态链接和基础镜像审计；组装实际平台的 BE 源码与重链接对象并验证。页面只索引材料说明，不提供虚构 BE 路径或用网页下载按钮代替交付。
4. **C04–C07/V09/V12：** 运行完整 FE 构建和服务验证，实际演练正常、自定义、跳过 UI 的打包路径；用 FE 包演练驱动替换 SQL，再校验 BE 包和镜像。当前 JAR 测试只把生产 UI 资源装入隔离测试归档后读取验证。
5. **A04/E08/E10：** 继续核对上游挑拣提交映射、实际镜像版本与 RC 参数；Maven `name/url/scm/issue/mailingLists`、ASF 项目描述和自动化元数据尚需按真实维护渠道处理。官方来源版本已核验为该提交的源码标识，不宣称已经核验同名发布标签。
6. **D02/D05/D08/D10：** 授权决策后完善覆盖不同文件来源的 CI 规则及正反例；评审工作区完整差异并把计划、附录、AGENTS 和新增源码一并纳入提交。当前没有执行提交、推送、镜像发布或生产部署。

正式发布以前，第 8 节仍需逐项通过。当前工作可以继续评审和集成，不应表述为产品版权方案已经全部闭环。


## 10. 提交前代码复核及修正（2026-09-06）

| 评审项 | 结论与本轮处理 |
| --- | --- |
| FE 组装隐含下载依赖 | 成立。将未经修改的 MariaDB 3.0.9 官方源码归档作为 `dist/sources/` 输入，保留 LGPL 正文和上游构建文件；`--install-fe` 不再联网，缺失/哈希错误提示恢复文件或指定本地变量，并在耗时编译之前预检 |
| 源码 tarball 缺 Git 即失败 | 成立。`git archive` 通过 `dist/source-version.json` 的 export-subst 写入提交；普通源码包可指定 `MASSDB_SOURCE_COMMIT`。无来源信息允许开发构建并显示 `unknown`，正式发布拒绝未知来源，不伪造提交或把未检查状态当作工作区干净 |
| 9 个新增源码无头、CI 未衔接 | 成立。原 9 个文件及本轮 2 个新增实现文件采用明确的待定授权状态头，登记于 `dist/source-headers.json`；License Eyes 只对登记路径交给独立检查，其他文件继续原检查。缺头、登记漂移、原头丢失和修改说明丢失会失败；过渡状态允许工程评审，`build-for-release.sh` 会拒绝待定授权文件 |
| Node 要求只存在于 npm 配置 | 成立。`build.sh` 在第三方编译前读取并验证 Node/npm 范围；`env.sh` 支持 `MASSDB_UI_NODE_DIR` 和独立的 `MASSDB_NOTICE_PYTHON`。CUSTOM_UI_DIST / headless 不要求 Node。CentOS 7 的 glibc 不满足官方 Node 22 二进制要求，保留原生编译镜像并提供独立 `Dockerfile.ui`，不只替换旧镜像中的版本字符串 |
| 公司版权未确认时文案悬空 | 成立。公司行与“自有修改与新增部分”同时隐藏，产品行保留产品名和声明链接；已确认来源的 MariaDB 署名及 LGPL 指引继续保留 |
| 四个纯上游回移文件被笼统标注 | 采纳可读性修正。“Modified for”原本不声明版权归属，但容易混淆。四个文件已明确写 Apache Doris backport 及 PR 号；MODIFICATIONS 记录 #60652、#61555、#61881 与本地提交的对应 |
| Checkstyle 不接受计划的 SPDX 短头 | 成立。使用完整多行匹配，接受原通用 Apache 头及“年份/中文名/英文名/SPDX”模板；模板原文放在 `dist/headers/`，独立检查器校验 XML 与模板一致。新独立 Java 文件约定路径包含 `massdb/` 段并登记来源；旧 ReportHandlerTest 保留单独兼容入口 |
| 四个历史独立文件被提前授权 | 需区分。三个 Compose YAML 和一个 Java 测试在本批以前已带 Apache 2.0 条款；本次保留条款并移除 ASF 贡献协议陈述，没有给其余新增文件套用 Apache 许可。此工程处理不证明原授权有效或公司拥有权利，已加入下述法务审阅记录 |
| base 路径忽略大小写且取首个匹配 | 成立。改为精确匹配已注册路由名并取最后一个路由片段；增加含 `/system/`、`/home/`、`/System/home/` 的前缀验收 |
| Python 低版本裸 traceback | 成立。脚本入口检查 Python 3.9+；FE 预检也在执行脚本之前检查解释器，错误明确给出 `MASSDB_NOTICE_PYTHON` |
| 2.0.5 与上游编号重名未作结论 | 已在 3.3 确定保留独立产品编号，来源使用独立字段。实际镜像 RC 和发布物映射仍需 E10 验证 |

### 10.1 过渡状态与法务审阅记录

- 待定状态头是工程状态记录，不是 Apache、商业或其他许可的授权文本。CI 的精确路径例外由 `check-source-headers.py` 接管验证；不能通过增加宽泛 ignore 或删除登记绕过。正式发布须清空待定项并采用经确认的真实授权。
- 既有 Apache 条款涉及 `docker-compose/docker-compose.{be-host,fe-host,same-host}.yml` 和 `ReportHandlerTest.java`。A09 已确认独立编写；保留原许可条款与移除 ASF CLA 陈述的差异供法务一并审阅，原授权权限和公司权属仍按 A08 核验。本次没有向外发送消息或假定法务已经批准。
- 公司 Copyright 开关保持关闭；新代码最终许可和公司权属/年份仍未替用户决定。上述过渡机制修复可评审性，不表示完整版权发布方案已完成。

### 10.2 操作和验证入口

```bash
# 仓库根目录：均不需要联网
python3 build-support/check-source-headers.py
python3 build-support/prepare-product-notices.py --check-fe-inputs
python3 build-support/prepare-product-notices.py --check-ui-toolchain

# 正式发布前：待定授权或未知来源必须失败
python3 build-support/check-source-headers.py --release
python3 build-support/prepare-product-notices.py --check-release-provenance

# UI 使用规定的工具链构建后
python3 -m unittest discover -s build-support -p test_product_notices.py -v
(cd ui && npm run build && npm run check:notices && npm run test:legal)
(cd fe && mvn checkstyle:check)
```

构建主机可在 `custom_env.sh` 设置 `MASSDB_UI_NODE_DIR`（含 bin/node、bin/npm 的安装前缀）和 `MASSDB_NOTICE_PYTHON`。独立 UI 镜像、离线准备和源码归档用法见 `ui/README.md`、`docker/README.md`、`dist/sources/README.md`。新工具链镜像不表示所有历史编译镜像已完成 FE/BE 工具链升级。

本轮验证结果保存到 `output/legal/review/verification.json`，相关日志放在同目录：

- 20 项 Python 测试通过，覆盖声明产物、本地源码组装、低版本预检、无 Git 来源、`git archive` 导出及排除目录、过渡头/Apache 头/原始头正反例。正式发布检查按预期拒绝 11 个待定授权文件。
- UI 生产构建与声明校验通过；浏览器覆盖 6 种部署前缀，保留 18 张截图，验证未确认公司版权时无悬空文案。使用本地静态服务和模拟业务响应，未启动实际 FE 服务。
- FE Checkstyle 的 16 个模块通过；Java 正则另行验证通用 Apache、公司完整头、公司 SPDX 短头和无授权文本反例。独立检查覆盖 11 个待定头、4 个独立 Apache 头和 55 个上游原头及修改说明。
- License Eyes v0.2.0 对本次 100 个变更文件检查：50 个有效、50 个按配置忽略、0 个无效；忽略的登记源码由独立检查器接管。此结果是变更范围检查，未声称 GitHub 全仓工作流已运行。
- `Dockerfile.ui` 已构建成本地镜像；`--network none` 容器中的 Node/npm/Python 版本和 FE 本地输入预检通过。官方 MariaDB JAR 与仓库内源码的隔离组装再次通过。镜像首次构建及 npm/Maven 依赖安装仍需网络或预备缓存。
- Shell 语法与 `git diff --check` 通过。验证未创建提交、推送或发布镜像。

完整 FE/BE 运行、驱动替换和重链接、实际产品镜像及全部依赖审计仍按第 8 节验收，不因本轮检查通过自动勾选。

## 11. 全组件编译与本地验收包（2026-09-06）

已按“完整编译发版包”的指示完成全组件编译，构建进程退出码为 0。目标为 Linux ARM64，产品版本为 `massdb-sql-2.0.5-rc01`；使用 Release 优化、3 路原生编译并行度和调试符号分离。基于提交 `bdd44bf2835bde62f582bde9338cf030cdfb92bb`，包含工作区未提交修改，不能将其视为该提交的干净构建。

- 组件：FE 与生产 UI、BE、Cloud Meta Service、HDFS Broker、9 个 BE Java 扩展、Hadoop 依赖、CDC 客户端、meta_tool 和 FoundationDB 辅助脚本。
- 编译检查：全组件构建成功；Java Checkstyle 无违规；FE JAR 内声明资源与实际 UI 清单一致，MariaDB JAR 与随包源码的匹配校验通过。
- 独立验证：20 项声明/产物测试、6 种前缀的浏览器检查、FE/BE/Cloud 版本检查和 meta_tool 帮助检查通过。直接运行 meta_tool 需要设置 JDK 17 的共享库路径，调用示例已放入包内 `BUILD-STATUS.md`。
- 打包修复：将 `build-for-release.sh` 的 tools 复制步骤移到压缩之前。实际包已验证包含 FoundationDB 脚本、关键组件和 BE/Cloud 调试符号；版本检查生成的日志及临时 Log4j 配置未带入包中。
- 包级检查：逐一验证压缩包内 1,691 个普通文件与 `SHA256SUMS` 一致，gzip 完整性和外部 SHA-256 校验通过。编译、浏览器和版本检查不等于完整 SQL 回归或实际集群部署验收。

本地输出：`output/massdb-sql-2.0.5-rc01-bin-arm64.tar.gz`，大小 3,422,724,610 字节（约 3.19 GiB），SHA-256 为 `ca46a906020f13b0cf065acf666a2afb9a17fc39b3aa9db849c86b6c69a75a94`。同目录保留解压目录和 `.tar.gz.sha256` 校验文件。完整记录、构建参数、编译时源码摘要及验证日志位于 `output/build-release-20260906/`；本节是编译后的执行记录，未改动已验证的二进制及声明资源。

**正式发布门禁仍未通过。** `build-for-release.sh` 按预期拒绝 A02 未决的 11 个源码文件。此次继续完成了编译和按发行目录布局的本地组包，包内明确记录 `approvedForExternalRelease: false`；这是内部验收材料，没有选定新增代码许可、确认公司权属/年份或代替 BE 源码与重链接验收，也没有执行 Git 提交、推送或对外发布。

## 12. 安装包复核与修正（2026-09-06）

详见 [安装包评审记录](massdb-sql-package-review-20260906.md)。本节更新当前结论，
此前第 9～11 节是当时执行记录，不将历史测试扩展为现已完成的许可审阅。

- A01/A02/A03/A05/A08 保持待确认。选择授权后应把文件迁入对应授权登记并同步
  License Eyes/Checkstyle 规则，不能只清空 `pending` 来绕过发布门禁。
- 发布来源检查现覆盖整个检出（忽略本地工具目录），拒绝 dirty/未知状态；尚未提交
  的工程改动仍只允许验收构建。Apache 许可本身并不要求 Git 提交，这是本项目发布
  可追溯性规则。编号独立性和准确上游基线已写入随组件复制的 `dist/RELEASE-NOTES.txt`。
- 已补 FoundationDB 两个实际客户端版本和 Debezium 的原始许可/致谢；Jindo
  二进制授权适用性仍须证据，不能仅以仓库或 Jackson 的 Apache 许可关闭 A07。
- 两个已核验哈希的 ARM64 BE/Cloud 重链接与 LLD 抽取证据确认没有纳入 gsasl/idn/hdfs3；
  `dist/native-link-evidence.json` 限定适用范围。保留条件依赖目录，删除所有 BE
  必然需要重链接材料的前提；Java 与内嵌原生库仍另行审阅。
- 增加离线 Java 实物清单/SBOM 命令，记录外层及嵌套 JAR、原始许可文本、声明来源与
  逐项审阅状态。生成成功不等于 927 项许可审阅已完成。
- 声明阅读器要求 `text/plain`，补 HTTP 200 JSON/HTML/空正文与恢复测试；MS 复制
  共用声明，独立组件与镜像检查仍保留；`.claude/` 加入忽略规则。
- 11:34 的旧压缩包及校验文件已移至 `output/archived-releases/20260906-1134/`。
  它的当前源码校验失败原因为 `MODIFICATIONS.txt` 已更新，不据此认定归档损坏；
  旧解压安装目录及数据保留。12:57 包是本轮代码修正前的验收包，本轮不原地改写。

## 13. 公司声明与安装包材料（2026-09-06）

维护者已指示新增公司声明。本轮采用第 4.3 节的 2026 年、中英文全称和有限范围，
将段落追加到根 `NOTICE.txt`，启用 `companyCopyrightConfirmed`。现有组件复制流程
携带该 NOTICE，正式发布入口补充安装包根 NOTICE；FE 生成的声明正文和登录前后
页脚同时包含公司署名。元数据与源 NOTICE 不一致、UI 缺失归属时检查失败。

该开关表示本次署名展示已获维护者指示，不表示营业执照、账号/雇佣、设计素材
或逐文件权属已核验。A01/A05/A08 继续留档；`newCodeLicense: null` 与 11 个待定
文件的许可状态不变，A02 仍须独立决定。

关于 `BUILD-INFO.json`、`BUILD-STATUS.md`、`MODIFICATIONS.md`、原生链接证据与其他
材料的交付边界，见[安装包声明与构建材料](massdb-sql-distribution-materials.md)。
当前 `LICENSE-dist.txt` 仍引用原生证据，不能直接删除；本轮不改写已有归档。

验证通过：UI 生产构建、声明/资源哈希校验、25 项 Python 测试，以及 6 种部署
前缀和中英文三种宽度的浏览器检查。真实组件复制函数和隔离 FE 材料组装验证
公司段落仅出现一次，根 NOTICE 原有内容逐字保留。日志位于
`output/legal/company-attribution-*.log`，组装记录为同目录
`company-attribution-packaging.json`。本轮未重新编译实际 FE JAR 或完整安装包。

## 14. 精简完整安装包（2026-09-06）

按维护者进一步指示，完整包根目录只保留 README/LICENSE/NOTICE 和运行组件。
构建过程、源码差异、详细修改历史、SBOM、逐文件哈希和原生链接证据存入与归档
对应的内部目录；BE/Cloud 的独立调试符号同时移出。公司署名、上游和第三方
归属、许可正文及 MariaDB 对应源码继续交付，材料集中于 `fe/legal/`。

同一组包入口已纳入 `prepare-product-notices.py`，创建新目录并保留输入原样，
禁止带入非空运行状态目录；正常组件构建保留独立声明。最终 FE JAR 和磁盘目录
去掉 UI 构建清单、SBOM 与详细修改历史，使用外部清单核验所有保留的静态资源。
正式脚本使用独立工作目录、传递产品版本并补充 Hive UDF；许可/权属未决事项
仍按原要求落实。详细材料边界见[安装包材料规则](massdb-sql-distribution-materials.md)。

新包位于 `output/massdb-sql-2.0.5-rc01-bin-arm64.tar.gz`，
大小 2,910,414,941 字节，SHA-256：
`30a774870685d77e4777b49d0b216bc91f301da2d66964aff43ddcd80ee86bcd`。
共 1,428 个普通文件；1,325 个运行文件与输入一致，FE JAR 除移出 3 个构建清单外
其余条目逐一一致。独立调试符号共 1,789,217,912 字节另存，不改变原生二进制。

28 项 Python 检查、源码头/脚本语法、UI 构建与浏览器检查、最终 JAR 页面浏览器
检查及 FE 版本启动通过；归档逐文件和原生证据哈希通过。未执行 Docker 构建或
集群 SQL 回归。记录及符号位于 `.build-records/20260906-audit.tar.gz` 内的
`build-release-20260906-minimal/`；本节
为编译后的文档补记，未改写已验证的运行文件。Java 审阅仍为 928 项中 568 项存在
取证缺口，新增代码许可等发布条件未因此完成。
