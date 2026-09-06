# MassDB SQL 版权计划：仓库事实复核与逐文件清单

- 核查日期：2026-09-05。
- 本轮补充复核日期：2026-09-06。
- 核查方式：本地 Git 历史、文件差异、构建配置及维护者在本次会话中的来源确认；没有独立验证员工身份、合同、营业执照、最终二进制或发布镜像。
- 对应计划：[产品化版权与 FE 页面修改计划](massdb-sql-copyright-productization-plan.md)。
- 第 1–3 节统计固定在实施前 HEAD；当前整改状态见第 4、7 节。工程修改不等于权属或完整发布义务已经核验。

## 1. 基线和统计口径

- 当前 HEAD：`bdd44bf2835bde62f582bde9338cf030cdfb92bb`。
- 评审比较点：`5abf4fdd0d58242522ecf47eb94ae5db69c67919`；这是本地历史节点，不能直接标成经过验证的 Apache 官方提交。
- 在该比较点到 HEAD 的范围内：13 个提交，8 个作者名为 `massdb-dev`、5 个作者名为 `郑百钦`。评审的“12/7”与当前 HEAD 不符。
- 使用 `git diff --name-status -M` 统计有 42 项净差异：24 个修改文本、8 个修改二进制、7 个新增路径、3 个内容相同的改名。改名按一项计算。
- 实施前 24 个修改文本中未检出明显标识 MassDB 修改的文件头；这是文本筛查结果，不能证明其他形式的声明或外部授权不存在。
- `5abf4fdd0d5` 的祖先已包含 `381a8d6c9cf`（2026-05-27，作者名 `massdb-dev`），因此 42 项并未覆盖全部较早的 MassDB 修改。
- 向前扩至该自有提交的父节点 `59de8c4c524`（本地标题 `4.0.5-rc01 (#61772)`）后，共 17 个提交、54 项净差异：43 M、8 A、3 R100。作者名统计为 `massdb-dev` 9 个、`郑百钦` 5 个、其他 3 个。
- 扩展范围包含后续上游挑拣修复，不能将其全部视为公司原创；还需对照可信 Apache 官方仓库确认提交和补丁来源。

复现命令：

```bash
git rev-parse HEAD
git log --format='%h %an %s' 5abf4fdd0d5..HEAD
git diff --name-status -M 5abf4fdd0d5 HEAD
git show --format=fuller --stat 381a8d6c9cf
git diff --name-status -M 59de8c4c524 HEAD
```

## 2. 42 项逐文件整改输入

类型：`M-text` 为修改文本，`M-binary` 为图片等二进制；`A` 只表示新增路径；`R100` 为内容一致的改名。

| 编号 | 类型 | 当前路径 | 处理结论或待办 |
| --- | --- | --- | --- |
| 01 | M-text | `be/src/http/default_path_handlers.cpp` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 02 | M-text | `be/src/http/web_page_handler.cpp` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 03 | M-text | `be/src/olap/compaction.cpp` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 04 | M-text | `be/src/olap/rowset/segment_v2/inverted_index/query_v2/collect/multi_segment_util.h` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 05 | M-text | `be/src/tools/meta_tool.cpp` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 06 | M-text | `be/src/vec/functions/function_multi_match.cpp` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 07 | M-text | `be/src/vec/functions/function_search.cpp` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 08 | M-text | `be/test/vec/function/function_search_test.cpp` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 09 | M-text | `build-for-release.sh` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 10 | M-text | `build.sh` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 11 | A | `docker-compose/README.md` | 无 ASF 头；核对文档作者、内容来源和适用授权 |
| 12 | A / 上游复制 | `docker-compose/conf/be/be.conf` | 与 `conf/be.conf` 仅行尾空格不同；保留 ASF 头，记录复制及空白调整 |
| 13 | A / 上游复制 | `docker-compose/conf/fe/fe.conf` | 与 `conf/fe.conf` 仅行尾空格不同；保留 ASF 头，记录复制及空白调整 |
| 14 | A / 已确认独立编写 | `docker-compose/docker-compose.be-host.yml` | 独立来源已确认；已改通用 Apache 2.0 头，移除 ASF CLA 陈述；公司署名待权属确认 |
| 15 | A / 已确认独立编写 | `docker-compose/docker-compose.fe-host.yml` | 独立来源已确认；已改通用 Apache 2.0 头，移除 ASF CLA 陈述；公司署名待权属确认 |
| 16 | A / 已确认独立编写 | `docker-compose/docker-compose.same-host.yml` | 独立来源已确认；已改通用 Apache 2.0 头，移除 ASF CLA 陈述；公司署名待权属确认 |
| 17 | M-text | `fe/fe-common/src/main/java/org/apache/doris/common/Config.java` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 18 | M-text | `fe/fe-core/src/main/java/org/apache/doris/catalog/Env.java` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 19 | M-text | `fe/fe-core/src/main/java/org/apache/doris/catalog/TabletInvertedIndex.java` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 20 | M-text | `fe/fe-core/src/main/java/org/apache/doris/httpv2/controller/HardwareInfoController.java` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 21 | M-text | `fe/fe-core/src/main/java/org/apache/doris/master/ReportHandler.java` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 22 | M-text | `fe/fe-core/src/main/java/org/apache/doris/system/SystemInfoService.java` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 23 | M-binary | `fe/fe-core/src/main/resources/doris-logo.png` | 归档设计、授权和提交人证据；按来源保留适用声明 |
| 24 | A / 已确认独立编写 | `fe/fe-core/src/test/java/org/apache/doris/master/ReportHandlerTest.java` | 独立来源已确认；已改通用 Apache 2.0 头，移除 ASF CLA 陈述；公司署名待权属确认 |
| 25 | M-text | `fe/fe-core/src/test/java/org/apache/doris/system/SystemInfoServiceTest.java` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 26 | M-text | `gensrc/script/gen_build_version.sh` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 27 | M-text | `regression-test/suites/search/test_search_dsl_syntax.groovy` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 28 | M-text | `thirdparty/build-thirdparty.sh` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 29 | M-binary | `ui/public/img/background.png` | 归档设计、授权和提交人证据；按来源保留适用声明 |
| 30 | M-binary | `ui/public/img/logo.png` | 归档设计、授权和提交人证据；按来源保留适用声明 |
| 31 | M-text | `ui/src/components/codemirror-with-fullscreen/codemirror-with-fullscreen.tsx` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 32 | R100 | `ui/src/components/codemirror-with-fullscreen/massdb.css` | 原路径 `ui/src/components/codemirror-with-fullscreen/doris.css`；保留许可头，在来源清单记录改名 |
| 33 | M-binary | `ui/src/favicon.ico` | 归档设计、授权和提交人证据；按来源保留适用声明 |
| 34 | M-text | `ui/src/index.html` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 35 | M-text | `ui/src/router/index.ts` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 36 | M-binary | `webroot/be/favicon.ico` | 归档设计、授权和提交人证据；按来源保留适用声明 |
| 37 | M-text | `webroot/be/index.html` | 原头已保留，2026-09-06 已补固定修改说明；公司权属另核验 |
| 38 | M-binary | `webroot/be/logo.png` | 归档设计、授权和提交人证据；按来源保留适用声明 |
| 39 | R100 | `webroot/be/massdb.css` | 原路径 `webroot/be/doris.css`；保留许可头，在来源清单记录改名 |
| 40 | R100 | `webroot/be/massdb.js` | 原路径 `webroot/be/doris.js`；保留许可头，在来源清单记录改名 |
| 41 | M-binary | `webroot/static/doris-logo.png` | 归档设计、授权和提交人证据；按来源保留适用声明 |
| 42 | M-binary | `webroot/static/favicon.ico` | 归档设计、授权和提交人证据；按来源保留适用声明 |

## 3. 需要扩展核查的 12 个路径

这些路径来自 `59de8c4c524..HEAD`，未包含在上面的 42 项中。`381a8d6c9cf` 直接涉及的文件单独标记；其余路径与上游挑拣提交的关系需要保留记录。

| 类型 | 路径 | 来源核查重点 |
| --- | --- | --- |
| A | `docs/group-commit-be-restart-fix-plan.md` | `381a8d6c9cf` 直接涉及；核对后续叠加修改 |
| M | `fe/fe-core/src/main/java/org/apache/doris/cloud/transaction/CloudGlobalTransactionMgr.java` | 核对上游挑拣提交及后续差异，不直接归入自有版权 |
| M | `fe/fe-core/src/main/java/org/apache/doris/load/GroupCommitManager.java` | 核对上游挑拣提交及后续差异，不直接归入自有版权 |
| M | `fe/fe-core/src/main/java/org/apache/doris/planner/GroupCommitPlanner.java` | `381a8d6c9cf` 直接涉及；核对后续叠加修改 |
| M | `fe/fe-core/src/main/java/org/apache/doris/qe/Coordinator.java` | 核对上游挑拣提交及后续差异，不直接归入自有版权 |
| M | `fe/fe-core/src/main/java/org/apache/doris/rpc/BackendServiceClient.java` | `381a8d6c9cf` 直接涉及；核对后续叠加修改 |
| M | `fe/fe-core/src/main/java/org/apache/doris/rpc/BackendServiceProxy.java` | `381a8d6c9cf` 直接涉及；核对后续叠加修改 |
| M | `fe/fe-core/src/main/java/org/apache/doris/task/AgentTaskCleanupDaemon.java` | `381a8d6c9cf` 直接涉及；核对后续叠加修改 |
| M | `fe/fe-core/src/main/java/org/apache/doris/task/PublishVersionTask.java` | `381a8d6c9cf` 直接涉及；核对后续叠加修改 |
| M | `fe/fe-core/src/main/java/org/apache/doris/transaction/DatabaseTransactionMgr.java` | `381a8d6c9cf` 直接涉及；核对后续叠加修改 |
| M | `fe/fe-core/src/main/java/org/apache/doris/transaction/GlobalTransactionMgr.java` | `381a8d6c9cf` 直接涉及；核对后续叠加修改 |
| M | `regression-test/suites/load_p0/routine_load/test_routine_load_be_restart.groovy` | 核对上游挑拣提交及后续差异，不直接归入自有版权 |

## 4. 新增文件的来源确认与文件头处理

实施前 7 个新增路径中有 6 个带 ASF 头，`docker-compose/README.md` 不带。以下内容对比以实施前版本为准，新增修改说明不改变复制来源判断。

- `docker-compose/conf/fe/fe.conf`：73 行，与 `conf/fe.conf` 对比 71 行完全一致，其余 2 行只有尾部空格不同。
- `docker-compose/conf/be/be.conf`：96 行，与 `conf/be.conf` 对比 93 行完全一致，其余 3 行只有尾部空格不同。
- 两个配置逐行去除行尾空白后分别与上游模板一致，故将它们定性为“公司原创且虚假 ASF 头”不成立。
- 三个 Compose YAML 由 `5fc594ecf48` 新增；`ReportHandlerTest.java` 由 `aee33c56087` 新增、`f7ad9470be9` 后续修改，并非被两个提交分别新增。这三个提交的 Git 作者均为郑百钦。
- **维护者确认（2026-09-05，本次会话）**：针对“三个 Compose YAML 和 ReportHandlerTest.java 分别是独立编写，还是参考／复制了上游文件”的明确提问，回答为“独立编写”。本附录据此关闭四个文件的来源待定项，A09 已完成。
- 2026-09-06 已将四个文件改为通用 Apache 2.0 许可头，移除 ASF 贡献专用陈述，保留现有许可且未添加公司版权行。来源确认不等于公司权属验证；D01 的公司署名部分仍待 A08。
- 与上游模板使用相同的许可头只能证明头部相似，不能据此认定正文为上游复制。两个 conf 的复制判断来自逐行内容对比，与四个文件的维护者确认区分记录。

## 5. 贡献与素材证据索引

- 账号 `massdb-dev` 的自然人对应、是否多人共用、任职或委托关系：未验证。
- 作者名 `郑百钦`：按维护者在本次会话提供的信息对应当前维护者；四个文件的独立编写已确认，公司权属关系仍按统一的 A08 记录，不另设这四个文件的来源调查。
- `39c744ec4d6`（2026-05-27）修改了 FE Logo、背景图和多处 favicon；`74a21b8eb4c`（2026-06-12）修改 `webroot/be/logo.png`，两次均署名 `massdb-dev`。
- 应归档：提交哈希、文件与素材哈希、账号到自然人的对应、任务或劳动/委托关系、权利归属文件、设计源文件及素材授权。
- 合同、身份证明等保存在受限证据库；仓库清单只记录证据编号、范围、保管责任与核验状态。

## 6. 实施前发现的声明与构建差异

| 项目 | 仓库证据 | 结论边界 |
| --- | --- | --- |
| MariaDB FE 运行时身份 | `fe/fe-core/pom.xml:607` 直接声明依赖，未另设 scope，默认 compile；`StatementSubmitter.java:68` 指定驱动，第 106 行加载，第 107 行用于建立连接 | 已确认 FE 自身运行时使用；新增 FE 版权展示须纳入库署名与 LGPL 正文指引 |
| MariaDB 交付链路 | `fe/fe-core/pom.xml:1038` 在 package 阶段将 runtime 范围依赖复制到 `target/lib/`；`build.sh:798` 将其复制到 `output/fe/lib/` | 标准构建按独立依赖 JAR 随 FE 交付；最终版本、哈希及用户替换能力仍需按实际发行验收 |
| MariaDB 版本与许可 | `fe/pom.xml` 声明 3.0.9；该官方版本的驱动头标注 LGPL-2.1-or-later；`dist/LICENSE-dist.txt` 记为 3.0.4 | 清单过期；按最终 JAR 核定版本与许可，不再将依赖是否属于 FE 列为未知 |
| libgsasl | `thirdparty/vars.sh` 默认 1.8.0；分发声明写 1.10.0/1.8.0 | 平台覆盖和最终版本仍需核实 |
| 静态链接 | `build_gsasl()` 使用 `--enable-shared=no`；`be/cmake/thirdparty.cmake` 将 gsasl 作为 STATIC IMPORTED | 存在静态链接构建配置；需对实际链接命令、map 和最终二进制取证 |
| LGPL 路径 | `dist/LICENSE-dist.txt` 中两处引用 `licenes/LICENSE-LGPL.txt` | 目录拼写错误；正文实际位于 `dist/licenses/LICENSE-LGPL.txt` |
| npm 清单 | `dist/LICENSE-dist.txt` 未检出 antd、react、react-dom、codemirror、sql-formatter 条目 | 已证实该分发清单缺项；不能据此断言未知构建产物的所有声明均缺失 |
| npm 版本固定 | `ui/` 没有受跟踪的 npm/yarn/pnpm 锁文件；包声明使用版本范围 | 先固定此次实际解析版本，再生成可追溯清单 |
| UI 运行时代码 | CodeMirror 在 devDependencies 中，但 TSX 导入其样式、模式和插件 | 不能仅扫描 production dependencies |
| 版本字符串 | 生成脚本默认 `massdb-sql-2.0.5-rc01`；Compose 默认镜像 `massdb-sql:2.0.5` | 是否覆盖 RC 环境变量需按构建核实，不能仅按镜像标签推断版本 |
| 未跟踪文档 | 核查前 `AGENTS.md` 和主计划为未跟踪文件 | 本次修订不会自动创建 Git 提交；提交计划时须显式纳入必要文档 |

本表保留实施前差异作为整改依据，当前完成状态见第 7 节。本附录不构成最终产物许可证审计结论；重新链接实验、软著申请和商标检索尚未执行。

MariaDB 许可和原始版权取自[官方 3.0.9 驱动源文件](https://raw.githubusercontent.com/mariadb-corporation/mariadb-connector-j/3.0.9/src/main/java/org/mariadb/jdbc/Driver.java)；运行时署名与交付条件见[该版本 LGPL 第 4、6 条](https://raw.githubusercontent.com/mariadb-corporation/mariadb-connector-j/3.0.9/LICENSE)。默认 compile scope 及 runtime 复制范围分别依照 [Maven 依赖规则](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html)和[依赖复制插件说明](https://maven.apache.org/plugins/maven-dependency-plugin/copy-dependencies-mojo.html)。页面与 FE/BE 发行材料的责任分工见主计划 3.4、C12 和 V12。


## 7. 2026-09-06 工程整改与验证记录

- 官方 Apache 仓库 API 返回 `59de8c4c524008e8ab2e43b79312f716a3a423a8`，标题为 `4.0.5-rc01 (#61772)`，与本地源码和该提交的版本脚本一致。[官方提交](https://github.com/apache/doris/commit/59de8c4c524008e8ab2e43b79312f716a3a423a8)。上游挑拣提交到官方原始提交的逐项映射仍待完成。
- 扩展清单内 35 个修改文本和 2 个复制配置均保留原有 ASF 头，追加固定 MassDB 修改说明；4 个独立编写文件保留通用 Apache 2.0 许可。逐文件结果见根 `MODIFICATIONS.md`，其正文也由构建复制到 UI/FE 声明目录。
- 新增共享页脚和公开声明页，支持中英文、本地许可正文及下载；MariaDB 署名来源绑定官方 3.0.9 源码。公司 Copyright 行仍关闭，名称、年份和新代码授权状态由 `dist/product-provenance.json` 分开记录。
- 已修正 `dist/LICENSE-dist.txt` 的 MariaDB 版本和两处 LGPL 路径拼写；保留根与分发 NOTICE 原文生成页面资源，逐条适用性审阅未完成，不能把合并原文视为审计完成。
- 安装 UI 依赖并固定锁文件和工具版本；构建插件从实际 webpack 模块生成组件清单、原始许可/归属文本、SBOM 和输出哈希。7 个 npm 包缺少独立许可文件，由 `dist/ui-licenses/overrides.json` 绑定版本、npm integrity、原始来源和补充文本哈希；不凭包名臆造版权人或年份。包级清单不替代嵌入第三方代码、手工复制素材与例外条款核查。
- UI 生产构建、浏览器验收、9 项产物校验和 FE 全量 Checkstyle 已执行；浏览器使用本地静态服务及模拟登录响应。真实 FE 服务和镜像未启动验收，JAR 往返检查使用由真实 UI 产物构造的隔离测试归档。
- 已用官方 MariaDB JAR/源码完成 `output/legal/fe-package-verification/` 材料组装；实际驱动替换执行 SQL、BE 对应源码与目标文件重链接仍未完成。FE 网页不承载这些源码归档或 BE 对象文件，也不承诺尚不存在的 BE 材料路径。
- 新增代码许可和公司署名范围仍待会话确认；根 NOTICE 公司追加、原创文件授权头与 License Eyes 规则尚未定稿。本批未提交 Git、推送或发布镜像。

可复现命令、验证边界、已完成和待完成清单见[主计划第 9 节](massdb-sql-copyright-productization-plan.md#9-首批实施记录2026-09-06本轮代码复核前)。


## 8. 提交前代码复核补充（2026-09-06）

- 四个纯回移文件的本地 Git 记录为：CloudGlobalTransactionMgr、routine-load regression 对应 `5abf4fdd0d5` / #61881；Coordinator 对应 `3d3b870a175` / #60652；GroupCommitManager 对应 `3d3b870a175`、`508fb026de8` / #60652、#61555。文件头现明确标注 Apache Doris backport，原 ASF 头保留。这里记录本地提交正文中的 PR 标识，不冒充已完成逐个官方补丁等价性验证。
- 原 9 个新增源码及本轮新检查器、UI Dockerfile 共 11 个文件采用明确的待定授权状态头；不写 ASF 贡献协议陈述，也不提前选 Apache 许可。`.licenserc.yaml` 的精确例外必须与登记一致，其他文件的检查继续执行，正式发布入口拒绝待定状态。
- 对四个既有独立文件的 Apache 许可保留问题已在主计划 10.1 列入法务审阅；不是原授权权限或公司权属已经核验的结论。
- FE 默认源码输入改为 `dist/sources/` 中 501,215 字节的官方归档，SHA-256 保持此前核验值；构建不再隐含下载。源码 tarball 的未知提交只允许开发构建，Git 导出来源文件和显式来源变量另行支持。
- Node 22 的 Linux 官方二进制需要比 CentOS 7 更新的 glibc；独立 UI 镜像使用固定 Node 22.23.2 Bookworm 镜像及 npm 10.9.9，保留历史原生编译镜像的环境边界。[Node 22 官方构建要求](https://github.com/nodejs/node/blob/v22.x/BUILDING.md)。
- License Eyes 的 `paths-ignore` 与 `comment: never` 按当前使用的 [v0.2.0 配置文档](https://github.com/apache/skywalking-eyes/blob/v0.2.0/README.md#configurations)设置。GitHub 工作流改用普通 PR 事件与只读权限，并调用独立头检查；不依赖 ASF 机器人指令或向 PR 自动发送评论。
- 本轮 20 项 Python 测试、6 种前缀的浏览器验收、FE 16 模块 Checkstyle 通过；变更范围 License Eyes 检查 100 个文件，0 个无效头，另行验证 11 个待定头、4 个独立 Apache 头和 55 个上游头。独立 UI 镜像已在本机构建，断网容器预检通过；完整 FE/BE 运行和正式产品镜像仍未验收。详细结果及日志索引见 `output/legal/review/verification.json`。

本轮实现、使用方式、授权边界和验证记录见[主计划第 10 节](massdb-sql-copyright-productization-plan.md#10-提交前代码复核及修正2026-09-06)。

## 9. 实际安装包证据补充（2026-09-06）

最新细节见 [安装包评审记录](massdb-sql-package-review-20260906.md)。此前“配置静态链接
即需要 gsasl 重链接材料”的表述收窄为实际纳入判断：当前 ARM64 BE/Cloud 经哈希一致
重链接和 LLD 抽取记录确认未纳入 gsasl/idn/hdfs3；对应二进制哈希及报告哈希已进入
`dist/native-link-evidence.json`。此结论不涵盖 Java、独立原生库或其他配置。

实际 FoundationDB 为 7.1.57 默认客户端和 7.3.69 附加客户端；Jindo 6.8.2 二进制
许可适用性未关闭。Java 实物清单含 1114 个外层 JAR、1303 个含嵌套出现位置、927 个
去重构件、613 份原文，567 个构件有许可证据缺口。完整审阅队列保留未审阅状态。

11:34 旧包对当前源码失败原因为 MODIFICATIONS 已更新，不是归档损坏的证明；旧归档
与校验文件已隔离，旧解压安装目录和数据保留。A01/A02/A03/A05/A08 决策与证据未变化。
