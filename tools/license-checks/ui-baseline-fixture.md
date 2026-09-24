<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP021 / LP022 原版 A 浏览器 fixture 规格

2026-09-24。状态：**offline_checks_passed / actual_browser_not_run**。已新增默认只计划的 Python controller、实际 FE 浏览器 driver、显式选择的独立 JDBC 读写背景/完整模型接口和固定10秒刷新子用例，当前只实现下文第9～11节的单context功能子集；其余段落仍是完整fixture验收规格。编写期间仅做静态检查；随后已完成39项Python、10项CJS检查及精确JDK17.0.4+8的背景helper编译。尚未启动真实浏览器或执行页面SQL/性能窗口。原版 A 的 Home、Playground、Configuration 与登录/路由可以先验证；License Tab、许可导入和回执轮询是后续 B/P2U 的真实页面，当前源码尚无这些入口。

权威负载定义仍为 [license-performance-cases-20260922.json](/data/project/massdb-sql/docs/license-performance-cases-20260922.json) 中 `LP-021`、`LP-022` 和 `measurement_policy`。本规格不修改它们，不缩减 License 覆盖，不把原版 A 做成假 License 页面。原版功能前提通过也不能把完整 LP021/LP022 或 P0/P1 总目标标为完成。

## 1. 源码依据与真实运行前提

| 依据 | 本 fixture 使用的事实 |
| --- | --- |
| [ui/README.md](/data/project/massdb-sql/ui/README.md)、[legal-notices.test.cjs](/data/project/massdb-sql/ui/scripts/legal-notices.test.cjs) | 现有测试用本地静态服务器，模拟 `/rest/`、`/api/` 和登录；其截图、前缀、布局检查可作实现参考，不能作为真实 FE 认证、API 或性能结果。构建环境固定 Node 22.23.2/npm 10.9.9；本规格编写时没有执行它们。 |
| [router/index.ts](/data/project/massdb-sql/ui/src/router/index.ts)、[renderRouter.tsx](/data/project/massdb-sql/ui/src/router/renderRouter.tsx)、[App.tsx](/data/project/massdb-sql/ui/src/App.tsx) | 真实路由是 `/login`、`/home`、`/Playground`、`/Configuration`；`/login` 和 `/legal-notices` 是 public。顶层保护依据 `checkLogin()`，即 localStorage 中非空 `username`，不是服务器认证证明。BrowserRouter 使用 basename。 |
| [utils.ts](/data/project/massdb-sql/ui/src/utils/utils.ts)、[index.html](/data/project/massdb-sql/ui/src/index.html)、[index.tsx](/data/project/massdb-sql/ui/src/index.tsx) | HTML 设置 base；`getBasePath()` 优先从同源 `main.<hex>.js` 的目录推导前缀，另有 pathname 回退；webpack public path 同步设为该前缀。必须检查实际 HTML、主 bundle、动态 chunk 和 API 请求，不能只看地址栏。 |
| [api.ts](/data/project/massdb-sql/ui/src/api/api.ts)、[request.tsx](/data/project/massdb-sql/ui/src/utils/request.tsx) | 请求加部署前缀并 `credentials: include`；登录独立发送 Basic，之后正常业务请求使用浏览器 cookie。HTTP 状态、JSON `code/msg`、有效数据与页面结果必须分别判定。 |
| [layout/index.tsx](/data/project/massdb-sql/ui/src/pages/layout/index.tsx) | Home 被排除在顶部菜单外，通过 logo 或深链接到达；Playground、Configuration 菜单文本来自路由 title，不能假定中文语言下会翻译。点击当前路径或从 Playground 离开可能触发整页 reload；不得把一次真实 reload 的请求重复记作多次用户操作。 |
| [i18n.tsx](/data/project/massdb-sql/ui/src/i18n.tsx)、[en-us.json](/data/project/massdb-sql/ui/public/locales/en-us.json)、[zh-cn.json](/data/project/massdb-sql/ui/public/locales/zh-cn.json) | 持久键是 `I18N_LANGUAGE`，测试值为 `en`/`zh-CN`，资源键为 en/zh；界面语言按钮切换该值并 reload。只对源码实际翻译的标签断言翻译，不要求所有英文标题都变中文。 |

执行器实施后，先冻结对应原版 A 的源码提交、脏补丁、FE JAR、BE 包、JDK、UI 主 bundle/动态 chunk/CSS、外部 UI manifest、浏览器及驱动版本和 SHA-256。真实页面必须由选定 A 的运行 FE 提供，允许下面的透明路径代理；不能用开发服务器、静态解包服务器、mock API 或当前 P1 JAR 偷换原版 A。仓库 UI 与选定包是否一致须以实际资源摘要/构建来源证明，本次没有验证该对应关系。

只在 checkout 内明确所有权的测试安装及私有网络 namespace 运行。先核对 cluster manifest、PID/start_ticks、namespace、安装路径、实际 FE HTTP/SQL 端点与 BE 身份；当前历史进程记录不证明服务仍存在。浏览器、代理、背景客户端必须能到达同一隔离测试拓扑，不能通过宿主默认代理误连其他安装。CPU/内存/网络/缓存/采样与客户端开销在运行清单冻结。当前 CPU0–4 的正式原语测量结束前，不启动本 fixture 或任何服务。

LP021 使用权威 `single_node_isolated`；LP022 的原版多节点前提使用 `multi_node_isolated`，即三投票 FE、四 BE。可参考 [multinode-baseline-cluster.md](/data/project/massdb-sql/tools/license-checks/multinode-baseline-cluster.md) 的实际成员/日志回放 oracle，但历史 `MEMBERSHIP_READY` 不代替本次健康检查。记录每个 FE 的实际 `IsMaster`、本地入口及应用进度；`Role=FOLLOWER` 可包含当前 Master，不能仅用 Role 字符串分类。对每个实际可服务 Follower 单独观察，不把一个 Follower 的结果外推到全部节点。

## 2. 冻结矩阵、代理和浏览器上下文

| 维度 | 原版 A 必须保留的输入 |
| --- | --- |
| 前缀 | 精确为 `""`、`/proxy/fe`、`/gateway/cluster/fe/default` |
| 语言 | `zh-CN`、`en`；在新 context 首次加载前只初始化语言键，认证必须真实登录 |
| 身份 | 独立 ADMIN 测试账号；不含 ADMIN/NODE 的非管理员账号，只授予冻结合成表所需 SELECT；另有无对象权限账号作权限负例。每个账号的实际 grants 留非秘密证明。不能给非管理员添加 ADMIN 使页面“通过”。 |
| FE 入口 | LP021 的单节点入口；LP022 的当前 Master 与每个可服务 Follower，代理固定到具体 FE，不能负载均衡后仍声称测到指定 Follower |
| 页面 | Home `/home`、Playground `/Playground`、Configuration `/Configuration`；表结构、结果路由另作下述检查 |
| 并发与时长 | LP021 contexts=1/10/50；LP022 contexts=1/10；每独立窗口 300 秒，至少五对 A/A，后续至少五对 A/B；数量或时长不足只能记 smoke/功能前提 |

先对每个前缀×语言×身份×实际 FE 入口做单 context 功能遍历，分别记录成功、原权限拒绝、原版缺陷、入口不可达。管理员和非管理员不能混成一个“成功页面平均值”。并发窗口按预先声明的相同身份/入口分布重放；若采用混合分布，明确每类 context 数及独立指标，不能隐藏被拒绝的页面。

两个非空前缀由仅供本次测试的透明代理剥离一次，再向 manifest 固定 FE 转发；空前缀也记录是否经过同一代理。归档代理版本/配置摘要、监听及 upstream 映射、Host/redirect/cookie 路径处理规则与无外部出口证据。不得统一返回 `index.html` 或伪造 JSON 成功来掩盖资源/API 404。除后续 B 的明确故障注入外，不改 API body/status，不额外注入 Basic，不强制补 `X-Doris-Stream`；这些会改变真实 UI 请求。

各身份、FE 和前缀使用独立 browser context；不同 FE 最好使用各自固定 origin，并记录实际映射。`PALO_SESSION_ID` 是 FE 本地会话管理器中的 cookie，源码设 Path `/`，同一 origin 的多个前缀不天然隔离它。即使同属一个集群，也不能把 Master 的 storageState/cookie复制到 Follower 后跳过登录。保存 browser version、viewport、locale/timezone、cache/service-worker 策略、是否 headless；最小布局回归使用现有测试的 375/768/1440 宽度，计时窗口使用事先固定同一尺寸，不能把不同尺寸的结果混合。

## 3. 登录、权限与秘密处理

真实登录顺序：新 context 访问 `<origin><prefix>/home`，验证前端跳到同前缀 `/login`；填入 `input#basic_username`、`input#basic_password`，按实际语言点击 Login/登录。等待真实 `POST <prefix>/rest/v1/login`、其业务结果以及成功后的 `/home`。登录页只在 `res.code===200` 时保存 username 并 `history.push('/home')`；不要把“URL 已变”当成登录后的受保护 API 可用。

[LoginController](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/controller/LoginController.java) 成功响应体为 `code:200,msg:"Login success!"`；普通成功 API 经 [ResponseEntityBuilder](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/entity/ResponseEntityBuilder.java) 包装成 `code:0,msg:"success"`。未授权异常也可能是 HTTP 200 携带 JSON 401，见 [RestApiExceptionHandler](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/exception/RestApiExceptionHandler.java)。代理/HTTP 错误可能另有实际状态；执行器须记录，不预设所有拒绝都是 HTTP 401。

必须保留以下原版差异，不能用测试配置绕开：

- [BaseController.checkWithCookie/checkCookie](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/controller/BaseController.java) 的 Basic 与 cookie 分支不同：非 Cloud 的 Basic 登录分支不会执行该处 ADMIN_OR_NODE 检查，`checkAuth=true` 的 cookie 分支会检查。因而非管理员可能登录返回成功，而随后 Home/Configuration 的 `/rest/v1/**` 被 [AuthInterceptor](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/interceptor/AuthInterceptor.java) 拒绝。这是待真实观察的原权限行为，不能预设非管理员一定能读三个页面或把拒绝归因许可证。
- [MetaInfoAction](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/rest/MetaInfoAction.java) 根据实际 `enable_all_http_auth` 决定 cookie 检查强度；table list/schema 另有对象权限。其 `getAllDatabases` 当前建立了过滤集合但返回 `dbNames`，不能使用数据库列表证明正确的 DB 权限过滤。实际列表保留诊断，表/列与业务读取的权限 oracle 单独验证。
- [StmtExecutionAction](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/rest/StmtExecutionAction.java) 对 UI query 使用 `checkWithCookie(...,false)`，实际 `enable_all_http_auth=true` 时另检查 ADMIN。冻结并记录配置原值、实际值及 Cloud 模式；不得把 [metadata-fixture.md](/data/project/massdb-sql/tools/license-checks/metadata-fixture.md) 的 Basic 请求和临时认证配置结果当成 UI cookie 结果。

单独记录错误口令、注销、cookie 清除而 username 保留、username 清除而 cookie 保留四种会话边界；每种用独立 context，最多一次用户触发，不无限登录重试。注销实际发送 `POST /rest/v1/logout`，UI 随后移除 username。只记录真实状态、可见提示及后续受保护 API 是否仍允许；提示框不能替代服务器 oracle。不得将页面守卫的 localStorage 值当作服务器身份。

账号密码只从受控进程内输入或 0600、受限目录的运行时配置读取；不进入命令行、URL、源码、报告、截图、shell history 或 stdout。可使用独立合成账号名作为非秘密身份标签。Basic 原文/base64、Cookie、Set-Cookie、认证挑战原值、browser storageState 全部禁止归档；只记录认证方式、cookie 名称与安全属性/是否设置，值不记录也不做可比指纹。不要启用记录认证输入的 Playwright trace/HAR/video；截图从登录完成且密码字段不可见后开始。页面 console 可能含表结构、SQL或表单失败对象，先分类/脱敏再写盘，不能直接复制所有参数和堆栈。

Home 硬件信息、Configuration 全量值也不默认公开：只保留合成环境必需且已审查的非秘密字段；配置中潜在密码/token/连接串、宿主名/IP等按运行清单规则排除。浏览器和代理不记录原始认证 header。FE 源码 DEBUG 日志可能打印 session cookie；测试保持该 logger 非 DEBUG，读取/归档服务日志前再次检查，不能因“测试环境”便复制秘密。临时账号由创建它们的管理连接删除，并以实际权限查询确认；不能把未登录/未创建的失败路径记作已清理账号。

## 4. 真实请求及初始页面 oracle

以下是当前客户端发起的无前缀路径；运行时须按矩阵加前缀。表中数据条件是通过要求，HTTP 状态要另存实际观察，不能从路径猜测。成功需 HTTP 语义允许、预期 JSON 结构/业务结果、独立内容 oracle 和页面渲染四者同时成立。

| 页面/动作 | 当前客户端请求 | 真实内容与页面检查 |
| --- | --- | --- |
| 登录 | `POST /rest/v1/login`，Basic header，无表单 body | 登录业务码与会话设置如上；随后独立 cookie 请求验证身份。失败不能伪造 username。 |
| Home 首次挂载 | `GET /rest/v1/hardware_info/fe/` | `data.VersionInfo` 和 `data.HardwareInfo`；Version/Git/BuildInfo/BuildTime/Features 对照选定 FE 构建元数据。CPU/内存等动态值只检查形状/合理范围，不与下一次采样硬比较。页面显示 Version、Hardware Info，成功分支 loading 结束，抽取展示内容与同次响应一致。空对象占位或无限 spinner 不能记成功。 |
| Configuration 首次挂载 | `GET /rest/v1/config/fe/` | 服务端映射 `/rest/v1/config/fe`，WebConfigurer 允许 trailing slash；必须由真实请求确认。`column_names` 为 Name/Value，rows 与当前 FE 配置一致。选预先允许公开的稳定项（如该节点端口）对照实际配置；表头、对应行、筛选、排序/分页及行数相符。不能只找 Configure Info 标题。 |
| Playground 首次挂载/树刷新 | `GET /api/meta/namespaces/default_cluster/databases` | `data` 为数组；树中出现本次允许观察的合成数据库，记录实际集合；无权账号按原权限分支观察。编辑器 `.CodeMirror`、Editor/编辑器、Execute/执行按钮及 footer 可见，空 SQL 不可执行。 |
| 展开合成数据库 | `GET /api/meta/namespaces/default_cluster/databases/<db>/tables` | 表集合对照本次 fixture DDL 与账号授权；不使用 mocked information_schema/mysql/60 个 database 节点。 |
| 点击合成表/表结构深链接 | `GET /api/meta/namespaces/default_cluster/databases/<db>/tables/<table>/schema` | 对照 SQL DESCRIBE 与冻结 DDL 的字段顺序、类型、可空性、键及默认值；当前 UI 不加 `with_mv=0`，不能直接套用另一 fixture 的响应格式假设。 |
| 显式 Execute | `POST /api/query/internal/<db>`，JSON `{"stmt":"<synthetic SQL>"}` | UI 未主动设置 `X-Doris-Stream:false`；服务端默认 `is_sync=true`，未传该 header 时走其原 stream 选择。保留真实 Content-Type/body/schema，确认 UI 能消费；不得由代理补 header 或重写 body来让测试成功。业务值与独立模型及页面完整结果逐项比对。 |
| Data Preview（功能检查专用） | 相同 query 端点，`SELECT * FROM <db>.<table> LIMIT 10` | 此按钮是实际业务读，不是纯元数据。由于 SQL 无 ORDER BY，不要求固定前十个 ID；逐条检查返回 ID 属于数据集且所有字段正确、数量上限和页面内容一致，不只数行。 |

Home/Configuration 的源码分别位于 [home/index.tsx](/data/project/massdb-sql/ui/src/pages/home/index.tsx)、[configuration/index.tsx](/data/project/massdb-sql/ui/src/pages/configuration/index.tsx)；树和 SQL 行为见 [tree/index.tsx](/data/project/massdb-sql/ui/src/pages/playground/tree/index.tsx)、[content/index.tsx](/data/project/massdb-sql/ui/src/pages/playground/content/index.tsx)、[content-structure.tsx](/data/project/massdb-sql/ui/src/pages/playground/content/content-structure.tsx)、[data-prev.tsx](/data/project/massdb-sql/ui/src/pages/playground/content/components/data-prev.tsx)。

浏览器 SQL 功能 oracle 使用 `license_perf.point_rows`，先确认该合成数据集百万行与完整模型。通过树选择数据库/表后在编辑器执行：

```sql
SELECT id, grp, v, payload
FROM license_perf.point_rows
WHERE id IN (0, 7, 999999)
ORDER BY id;
```

三行的 `grp=id%1024`、`v=id%100000`、`payload=MD5(十进制id的UTF-8字节)` 独立生成；ID、列名/顺序、类型、NULL、行数及每个值全部核对。只得到执行成功提示、执行时间或三行不够。源码 `getDbName()` 从路径末段用 `-` 分隔数据库和表，测试对象用冻结的无连字符名字；裸 `/Playground` 未建立数据库上下文，不直接在其上发 SQL，再把 `/internal/undefined` 失败称为 FE 不可达。

页面 API 的初始正确性先在计时外完成。每次导航/刷新仍做结果校验；将响应解析与模型成本保持 A/A、A/B 一致，明确哪些字段逐请求检查、哪些配置只在计时外核对。失败屏幕、空表、spinner、网络错误、非预期拒绝和 pageerror 独立留证，不按成功页面统计。

## 5. 路由、刷新、语言和布局操作序列

每个功能 context 固定执行并保存 action ID、起止单调时刻、前后 URL、实际请求链与判定：

1. 未登录 `/home` → 同前缀 `/login` → 真实登录 → `/home`。成功后核对主 bundle/chunk/CSS/API 均留在预期 origin/prefix；合法重定向逐跳记录，未声明外部地址视为失败。
2. 用顶部 Playground 菜单到 `/Playground`，检查真实树及编辑器；展开 `license_perf`，选择 `point_rows`。当前树选择路径为 `/Playground/structure/license_perf-point_rows`；在同 context 新标签页直接访问该路径并 reload，检查 schema/树/布局真实恢复。
3. 执行上节三行查询到 `/Playground/result/license_perf-point_rows`，核对完整响应和展示。用 back/forward 返回结构和结果，记录是否保持 history state。另开独立已登录页直接访问结果 URL并 reload；[content-result.tsx](/data/project/massdb-sql/ui/src/pages/playground/content/content-result.tsx) 直接读取 `location.state.msg`，没有从 URL 恢复结果的实现。本项是原版风险探针，实际失败原样保留，不能注入假的 history state、跳过直接访问或写成已经支持。
4. 点击 Configuration 并核对数据，再用 logo 回 Home；不要寻找不存在的 Home 菜单。继续 back/forward、当前菜单重复点击、从 Playground 离开以及直接访问三个页面。记录由源码触发的 reload、重挂载和重复请求及其因果关系，不预设每次点击只有一条请求。菜单高亮状态也单列观察，不能只看 URL。
5. 树搜索用真实数据库/表名，验证高亮与展开；清空搜索后恢复。点击树 Refresh/刷新并等待本次 `/databases` 返回与树重新一致。Configuration 筛选只过滤客户端现有数据，不把它称为服务器刷新。
6. 语言按钮 en↔zh-CN 切换后有 reload；核对用户名、前缀、当前页面、真实会话仍一致，以及 Editor/编辑器、Execute/执行、Refresh/刷新等实际翻译。Home 的 Version/Hardware Info、Configure Info 和菜单 title 目前是英文常量，单独记录不翻译的事实。
7. 三个宽度分别检查无横向页面溢出、唯一 footer、不遮挡登录表单或编辑器。Playground 在宽屏检查树与编辑器上下对齐、工具栏对齐、树独立滚动；窄屏检查上下堆叠。1440 宽度按现有测试拖动侧栏约 120px，验证实际列宽变化、CodeMirror 不溢出；源侧栏范围 220–480px。实际树不够长时先明确构造额外合成元数据或将滚动子项记缺少前提，不能凭 mock 的 60 个库认定通过。
8. 隐藏、恢复和关闭页面后继续观察有界时间。Home/Configuration/树的显式加载来自挂载和用户动作，当前源码没有为它们定义周期 polling；记录实际静默期和晚到/取消请求。Configuration/树初始 fetch 有 AbortController，Home 没有，不能要求所有正在进行的原版请求立即消失。以网络事件证明状态，不只用页面隐藏标记。

前缀深链接必须由真实 FE 或透明代理正确服务页面；[WebConfigurer](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/httpv2/config/WebConfigurer.java) 有 SPA fallback，因此 HTTP 200 HTML 不能算 API 成功。错误 MIME、JSON错误、HTML fallback、没有匹配 chunk 的页面均保留为失败。功能 fixture 的诊断禁止 page.route/fulfill 把失败改成成功；需要的后续故障注入用独立命名场景，不能污染 A 性能窗口。

## 6. 恒定查询/写入背景与计时计划

原版 A 的持续负载包括独立读流和独立写流，贯穿每个 300 秒窗口；即使某非管理员 UI 页面被原权限拒绝，背景仍按冻结计划运行。浏览器内一次三行 SQL 不替代持续背景。

- **读流：** 使用 `bench_small` 的百万键确定序列，通过真实 FE SQL/JDBC 入口执行既有 `SELECT payload ... WHERE id=?` 点查；每次核对单列、非空 String、唯一行和该键对应的精确 MD5。源表四字段的完整模型在计时前独立检查，不把它冒充每请求读取四列。冻结种子、完整到达时刻/键序列、连接复用、并发、路由 FE、timeout 与 SLO；模型在计时外预计算。沿用已有点查 oracle 的同版本工具，先核对其源码摘要，不在活跃窗口改工具。
- **写流：** 使用权威 `bench_small_plus_write_target` 的独立空目标表，结构与源表一致，源点查表不变。运行清单冻结真实原版支持的 INSERT方式、批量、行ID分配、字段模型、速率和连接；建议先做功能预检再选定唯一方式，不在不同窗口改成 Stream Load/Group Commit。每个计划批次 ID 区间互不重叠；记录实际 ACK/SQLState/影响行数、提交或可见状态，失败与未知结果不自动重放。窗口结束后独立连接全量读回，核对接受批次的精确 ID 集、去重、四字段与摘要；COUNT/SUM 单独不够。唯一键重写可能隐藏重复提交，必须同时核对请求序列/回执，不能用最终行数证明恰好一次。
- **同时性与清理：** 两条流使用分离连接与身份标签，归档实际发送/完成时间证明和 UI 窗口重叠；从后台客户端日志及数据库回读证明持续成功。无秘密的输入/回执/数据摘要保存于新报告目录。计时外重置目标表为同一快照并独立确认；结束后只清理本 fixture 明确创建的表/账号，源表前后摘要保持一致。清理未确认时不得开始下一窗口。

“恒定”指 A/A 和 A/B 使用完全相同且事前冻结的开环到达序列与目标速率；不是发现 UI 变慢后降低速率。数值速率必须在原版功能前提和容量诊断之后冻结，目前没有该浏览器场景的合格速率或 A/A 精度证据。客户端排队、超时、错误、重试/未知提交、成功吞吐都计入；测量浏览器/代理/校验器本身的 CPU/RSS/IO，不能把它们的瓶颈归为 FE。

LP021 用户刷新节奏固定每 10 秒一个计划时点，页面序列在窗口前冻结：Home 无专用刷新按钮时用整页 reload；Configuration 同理；Playground 使用树 Refresh。记录操作类型，不能把三种刷新当成相同 API成本。导航、back/forward、语言切换、隐藏/关闭的确定时点单独列在序列中。各 context 的启动/错峰方式固定，不能等上一操作完成再重排所有到达时间以隐藏排队。若上一动作未完成，原计划动作的等待/超时必须留样。

LP022 的 A 对照只执行相同的既有页面、身份/入口和读写背景；不存在“三次原版许可导入”。后续 B 每 context 三次导入的额外管理/UI成本加入配对对照，页面自身延迟另报描述性结果；不能据 A 缺少导入成本宣称 B 提升。300秒至少五对是原定下限，不代表已经满足95%置信/检测精度。逐窗口保留 P50/P95/P99、成功操作CPU、RSS/GC/IO/网络、背景排队和错误；按权威规则保证尾延迟样本量。浏览器操作样本不足时仅给描述性结果或延长/追加窗口，不借背景SQL样本数冒充页面P99样本数。

## 7. 网络证据、oracle 回执与结果分类

执行器应从请求开始到 response/body处理结束记录全部实际网络事件；不能仅截一份 DevTools 截图。每条记录至少有窗口/context/action/逻辑操作ID、FE角色及固定upstream标签、前缀、语言、身份类别、单调时刻、HTTP方法、脱敏后的origin/path、资源类型、redirect关联、HTTP status、Content-Type、JSON业务码及安全错误分类、传输/解码字节数、成功/取消/超时、完整性oracle结果。记录从到达到完成的端到端时间及客户端等待；浏览器cache命中和304、warm/cold导航分开，不伪造成新服务器执行。

响应 body 仅对受控合成数据和已准许字段保留；密钥、证书、账号凭据、cookie、全量硬件/config内容不进公开回执。若某API正文不宜保存，现场提取允许字段、完整性结果、非秘密结构/计数与经过审查的内容摘要；说明没有归档完整正文，不把删过敏感内容的文件摘要称为原始响应hash。请求 URL 不含认证内容；业务 SQL只使用公开合成数据。前后URL、DOM/截图/console、proxy日志应用同一脱敏规则；故障路径同样检查。

建议新报告目录包含 `manifest.json`、`actions.jsonl`、`network.jsonl`、`oracles.jsonl`、脱敏截图、背景请求/可见性/全量回读证据、CPU/RSS/GC/IO采样、清理回执及文件摘要清单。此处是输出规格，不表示这些产物已存在。报告顶层分别保存：

- `A_functional_prerequisite`: not_run / partial / pass / fail；每个矩阵格及子项有明确状态和证据。
- `A_A_precision`: not_run / inconclusive / qualified；无原始样本及独立复算不允许 qualified。
- `B_P2U_overlay`: not_implemented / not_run / partial / pass / fail，与 A 结果分开。
- `LP021_complete=false`、`LP022_complete=false`、`full_goal_complete=false`，直到各自完整适用矩阵、B功能及性能门槛真实达成。源码风险、既有缺陷或不足前提不是可悄悄删除的格子。

实际页面授权相关请求的“零新增请求”检查必须以完整网络清单为依据：A 没有许可页面，所以零许可请求只证明 A 基线；B 打开其他 Tab 时零主动许可详情请求才是后续惰性加载断言。A 不存在的许可快照/分类计数写 `not_applicable_on_A`，不能填0冒充已经安装了观测；B的对应观测仍待接入。

## 8. 保留的 B/P2U 叠加验收及未验证事项

后续使用真实 B FE 和其配套 UI，在同一三前缀、两语言、ADMIN/非ADMIN、Master/Follower矩阵上增加 License 页面。其最终浏览器路由/选择器/API以完成后的真实实现和既定P2U契约冻结；本规格不虚构当前存在的 `/License` 路由，不向 A 提交不存在的许可请求。

必须保留权威 LP021/LP022 输入：License首次加载、手动刷新、离开/返回/深链接、UTC及本地时间解释、基础额度与pending额度来源；有效UTF-8文件、粘贴JWS、malformed、future证书，每context三次导入；提交后仅中断测试响应、按指纹确认、旧回执被新证覆盖、未授权/超限/无效预览拒绝。未知提交不能自动重导；原始证书不得进localStorage、URL、日志或归档浏览器trace。

仅“结果待确认/已提交待同步”状态触发后续真实有限轮询：2/4/8/16秒增长、30秒封顶，总预算120秒，最多一个inflight；隐藏或卸载停止无用轮询，预算结束停止新请求并提供手动查回执，重新进入先刷新。实际发起/完成/取消时刻、预算边界、响应丢失后的真实提交事实与回执、Master/Follower应用版本须相互印证。A 没有提交日志或receipt，不能以模拟UI timers证明上述行为通过。

本次尚未验证：选定原版A的实际UI产物与本工作区源码对应、真实FE/代理三前缀可达、非管理员cookie行为、结果深链接实际表现、Playground默认stream响应可消费性、所有页面初始数据/布局、浏览器依赖可用性、读写背景速率与全量oracle、各节点身份/账号清理、A/A精度以及全部B/P2U叠加。下一步是在正式原语测量结束后的独立窗口审查并运行下述执行器；这份文档不将任何一项标为已通过。

## 9. 当前可执行工具与明确未实施项

[ui_baseline_fixture.py](/data/project/massdb-sql/tools/license-checks/ui_baseline_fixture.py) 默认 `--mode plan`，只创建全新的计划目录；必须另行显式 `--mode probe --plan ...` 才连接已有、归本checkout所有的原版FE。它不启动/停止FE或BE，不创建账号，不改认证配置；仅明确选择第10节背景时才创建本次专属写表。原版JAR若包含新 `org/apache/doris/massdb/license/` 类则拒绝，避免把当前P1产物当原版A。单节点复用现有cluster record校验，多节点复用 `ClusterGuard` 的七节点身份/namespace契约，在fe1 keeper namespace中访问各固定FE入口。

Probe在运行前和执行期间拒绝同checkout仍活跃的正式/诊断性能controller或已知Java客户端；解析 `/proc/<pid>/cwd` 加实际argv，同时识别绝对和相对脚本路径，不依赖命令行包含绝对ROOT。计划不执行该扫描，也不申请网络资源。每次probe只能使用一次冻结plan；变化过的工具、lockfile、Node/Chromium可执行文件、cluster输入或账号引用拒绝复用。

账号引用JSON只能包含下面字段，不接受密码正文。三个账号必须已经存在并分别符合ADMIN、仅合成表读取、无对象权限的角色；`host` 填实际账号绑定，`%` 仅为格式示例。工具对每个FE用独立管理员HTTP SQL执行实际SHOW GRANTS并检查ADMIN/NODE位，表列表/schema另验证非管理员对象权限；不会赋权让页面通过。

```json
{"schema_version":1,"accounts":[
  {"role":"admin","username":"ui_admin","host":"%","password_env":"MASSDB_UI_ADMIN_PASSWORD"},
  {"role":"reader","username":"ui_reader","host":"%","password_env":"MASSDB_UI_READER_PASSWORD"},
  {"role":"unprivileged","username":"ui_unprivileged","host":"%","password_env":"MASSDB_UI_UNPRIVILEGED_PASSWORD"}
]}
```

引用文件位于checkout `.build-records`；运行probe时三个环境变量必须显式存在（允许隔离测试空密码，但不默认回退为空），只支持有界ASCII测试凭据，以匹配当前UI的 `btoa`。密码仅经stdin管道送给Node，不进入参数、计划、报告或浏览器子进程环境。账号由外部准备者负责最终删除，本工具不声称已删除借用账号。每次独立Basic预检都显式注销其新FE会话；浏览器正常/异常结束也尝试真实logout。无法确认logout、graceful close或子进程退出均保留失败，三者不会互相替代。

以下只展示后续运行命令，编写本文件时未执行。资源和运行路径必须由实际环境提供，不内置历史PID或JDK路径：

```bash
python3 tools/license-checks/ui_baseline_fixture.py \
    --cluster-record .build-records/<owned-single-cluster>/cluster.json \
    --accounts .build-records/<inputs>/ui-accounts.json \
    --node /absolute/path/to/node --chromium /absolute/path/to/chromium \
    --cpus 0,1,2,3,4 --rss-limit-mib 2048 --reserve-mib 2048 \
    --output .build-records/<new-ui-probe>

# 在该cluster当前实际private namespace内，正式基准已停止后才执行：
python3 tools/license-checks/ui_baseline_fixture.py --mode probe \
    --plan .build-records/<new-ui-probe>/plan.json
```

多节点计划用 `--cluster-plan .build-records/<owned-multinode>/plan.json` 替代 `--cluster-record`，不能同时提供。Chromium sandbox默认开启；环境确实需要无sandbox时必须在plan阶段显式 `--allow-no-browser-sandbox`，该选择写入plan。不安装/下载Node、Chromium或Playwright；现存Playwright必须为仓库固定的1.63.0。实际运行Node版本和Chromium版本写入每格报告。

当前子集按FE×3前缀×2语言×3身份逐格执行，**同一时刻只有一个browser context**：单节点18格，三FE54格；不缩减矩阵来掩盖失败。先用独立Basic预检取得各FE角色、当前配置、构建信息、SHOW TABLES、DESCRIBE和三行SQL模型结果，然后真实UI进行登录与cookie分支、Home/Configuration初始数据、树刷新/展开、schema深链接、完整三行SQL及DOM、history back/forward、结果新页深链接风险、管理员菜单/logo/语言切换及logout。原权限拒绝必须命中原Cookie/Access denied语义；结果无history state无法恢复单列为baseline limitation，不能据此标完整功能通过。

[LicenseUiBaselineFixture.cjs](/data/project/massdb-sql/tools/license-checks/LicenseUiBaselineFixture.cjs) 使用真实生产UI，proxy只剥前缀并转发固定FE的原响应，已声明的原FE重定向映回该proxy前缀；不伪造API/静态资源。只允许登录、注销与冻结的三行只读UI query POST，不支持任意写入或文件上传；这是一项明确的当前子集边界，不是完整LP022导入实现。浏览器阻止外部网络，proxy与driver都不保存headers/body原文；network报告保存固定endpoint分类、时刻、状态、MIME类别、业务码、字节数和oracle，不保存可能含秘密的完整URL/query/console文字。

每格保存 `browser.json`、`controller.json`；顶层report实时记录完成格、未运行格、实际FE JAR hash/CPU与预检结果。私有browser profile权限0700，结束后删除，公开产物不含storageState/HAR/trace/截图。controller每200ms采样自身/代理加Node/Chromium树的RSS与CPU affinity，超预算或deadline终止本工具所拥有且PID/start_ticks/namespace/exe/command摘要仍匹配的子进程；Chromium脱离Node时由本次唯一profile路径补充识别。RSS是采样上界检查，不承诺无未采到的瞬时峰值，不创建cgroup或修改宿主资源设置。关闭浏览器的真实回执、FE logout、所有owned PID退出、profile删除分别记录。

当前明确尚未实现或未验证：第10节背景/百万行完整模型工具的真实执行、合格背景速率、1/10/50并发及300秒刷新/五对正式窗口、全部视口/resize/visibility/错误口令/session负例、UI产物与源码完整对应检查、B许可页面/文件导入/响应中断/回执轮询。现有point/background工具未被改动或在本工具中冒充已运行。顶层 `LP021_complete`、`LP022_complete`、`full_goal_complete` 始终false；有原版深链接缺陷时结果为PARTIAL，即使其余子项成功。

新增 [test_ui_baseline_fixture.py](/data/project/massdb-sql/tools/license-checks/test_ui_baseline_fixture.py) 和 [ui-baseline-oracles.test.cjs](/data/project/massdb-sql/tools/license-checks/ui-baseline-oracles.test.cjs) 的离线检查已实际通过，覆盖：默认plan、相对argv基准保护、路径/重定向、凭据引用、权限位、资源边界、PID复用、完整三行oracle及close成功/失败/超时。Python页面23项、背景16项，以及CJS10项均通过；结果见[Python/CJS日志](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/root-initial/receipt.json)。同一批日志中的复杂查询模块首次4项测试错误已独立修复并重测，不影响本节通过计数；离线检查不等于真实浏览器通过。

## 10. 显式读写背景、完整模型及清理接口

新 [ui_background_fixture.py](/data/project/massdb-sql/tools/license-checks/ui_background_fixture.py) 与 [LicenseUiBackground.java](/data/project/massdb-sql/tools/license-checks/LicenseUiBackground.java) 只由带背景输入的 UI probe 启动。plan 必须显式提供 `--background .build-records/<inputs>/ui-background.json`，probe 再次提供同一路径并核对冻结摘要。无此选项的计划仍是无背景功能子集；禁止 probe 给旧计划临时添加写入。改变源码或输入后必须生成新计划。

背景JSON严格包含下列字段；下面数值仅展示格式，**不是已校准或已批准的负载速率**。不接受缺省速率、隐式root空密码或配置中的密码正文。实际使用者须先在独立窗口验证原版功能和选择适当数值；工具始终不把该数值称为可持续容量。

```json
{
  "schema_version": 1,
  "seed": 20260922,
  "rate_basis": "explicit_functional_input_not_capacity_qualification",
  "duration_seconds": 300,
  "read_rate_per_second": 10,
  "write_batches_per_second": 1,
  "write_batch_rows": 10,
  "read_workers": 2,
  "write_workers": 1,
  "timeout_seconds": 10,
  "drain_seconds": 60,
  "prepare_timeout_seconds": 900,
  "verify_timeout_seconds": 900,
  "visibility_timeout_seconds": 30,
  "visibility_poll_millis": 500,
  "cleanup_timeout_seconds": 60,
  "read_slo_millis": 1000,
  "write_ack_slo_millis": 5000,
  "visibility_slo_millis": 10000,
  "read_account": {"username": "ui_bg_reader", "host": "%", "password_env": "MASSDB_UI_BG_READ_PASSWORD"},
  "write_account": {"username": "ui_bg_writer", "host": "%", "password_env": "MASSDB_UI_BG_WRITE_PASSWORD"}
}
```

两种背景账号必须已存在、名称与密码环境引用不同，由外部准备者负责授权和删除。读取账号只需要合成源表权限，写入账号须能向该测试数据库中新建的目标表执行冻结INSERT；工具不赋权。UI管理员账号经独立连接执行建表、完整值校验与清理。所有凭据仅进入受控JVM环境，不进入argv、配置正文或证据；JVM环境不继承 `JAVA_TOOL_OPTIONS`、`JDK_JAVA_OPTIONS`、`CLASSPATH`。Node仍不接收背景凭据。

选择背景时浏览器cell预算须至少360秒，整轮预算至少覆盖18或54格的这些窗口，并留足完整模型和清理时间；输入上限有界，超时保留FAIL而不删格。JDK取实际cluster record/plan中的checkout JDK17.0.4；Java、javac、modules、release及helper/冻结点查语义参考的摘要进入plan。probe才编译专用helper，javac堆256MiB、Java堆512MiB，不改已有 `LicenseJdbcBaseline.java`、`run_performance_baseline.py`、容量统计或原语工具。依赖来自已绑定的原版包，编译前后校验摘要并记录实际类和JDBC版本。

每格均生成 `cell-NNN-background` 新目录及不可预测 `license_perf.ui_bg_<32hex>` 新表；数据库和 `point_rows` 必须已存在。到达序列在任何SQL前由固定种子、`java.util.Random` 和 `StrictMath.log` 生成，读写用独立随机流。完整序号/相对纳秒/读键或写ID区间先保存为TSV并取摘要；MD5点查期望值和所有INSERT正文在窗口外预计算。所有格核对同一读/写schedule hash，不因浏览器快慢、队列或失败重新生成到达时间。

读连接复用服务端prepared模式 `SELECT payload FROM license_perf.point_rows WHERE id = ?`，保留冻结点查的单列、唯一行、非NULL String和精确小写MD5语义；不开每请求四字段扫描。写连接采用普通同步INSERT VALUES、autocommit和 `group_commit=off_mode`、严格插入、完整行更新；批次ID从1000000000开始按序号划分互不重叠区间，四字段公式与源表一致。每个worker有独立连接，读、写和oracle绝不共用连接；禁自动重连/写重放。实际会话变量在窗口前回读核对，禁止把设定请求当已生效。

每个worker按预定序号stride领取任务，等待固定绝对到达时间；队列堆积不移动计划，E2E为完成减原到达，包含客户端等待。保存计划/开始/结束、ACK或错误/未知/未发送、SQLState、错误码、影响行数，不保存异常正文。写ACK必须与批量影响行数一致；执行进入后任何不确定异常均按UNKNOWN保留。另一个oracle连接按冻结间隔读取该批完整ID域和每个值，记录首次观察到完整可见的上界时刻，不能把ACK当可见性。UNKNOWN即使后来可见也仍计错误，不自动重试；截止时未见不等于证明回滚。

窗口前与窗口后各通过独立oracle连接完整读取全部百万行：按 `ORDER BY id`、每页10000行的严格keyset推进，首批包含所有负值/额外ID的检查边界，逐行检查ID恰为0…999999及grp/v/MD5、列顺序、整型/String类型、NULL、重复/缺失/越界，并计算规范行SHA256。前后完整摘要和schema必须一致。结束后对写表作同样全量、有界keyset读回，核对每个计划批次精确ID域、四字段、完整或缺失、ACK对应的可见性，保存批次状态解析；不以COUNT/SUM或唯一键最终行数证明恰好一次。完整源模型和写表结果核对均在计时外。

表归属采用“创建前不存在、CREATE已明确ACK、DESCRIBE schema、实际tablet ID集合、config摘要、唯一token”的原始owner回执。cleanup先重新核对cluster PID/start_ticks/namespace/exe/command摘要及表的schema/tablet IDs，再DROP并独立确认不存在。CREATE结果未知或owner回执缺失且同名表存在时拒绝接管/删除，记录残留并停止后续格；不凭随机名字推断安全。正常、失败和外部中断都先停本工具worker和连接，再做完整值证据及清理。JVM被强制停止时controller可启动只清理模式，它也必须通过相同owner校核；清理不确认时不得运行下一格。

Java完成模型、连接及空表准备后发ready；浏览器建好真实context后发独立ready，controller才释放两者。Java记录300秒的monotonic/UTC边界，浏览器保存自己的时钟和观察边界，功能步骤之后仍保持context到真实window-end；失败/非管理员拒绝不会降低背景速率。分别归档driver请求日志、可见性、浏览器动作与起止回执。Python再独立检查schedule hash、序号完整性/唯一性、worker归属、写ID域、ACK影响行数、排队时间算式、SLO和实际发送/完成，并核对浏览器与真实背景窗口重叠。不同进程的monotonic原点不直接混用；各自的UTC锚点与controller观察时刻保留。

controller在运行中持续检查集群身份、已有正式基准冲突、子进程CPU affinity、整体RSS和绝对deadline。Java的CPU/RSS/IO单独采样，JDBC堆限额不冒充总RSS上限；浏览器监控合计自身、proxy、Node/Chromium和背景JVM。到达整轮deadline后停止负载，cleanup-only另获输入声明的有限清理预算；不延长原窗口或重发业务请求。每次编译前后及最终收据前复核冻结源码/JDK/完整依赖集合，启动前核对实际生成类。辅助JVM的独立network计数仍未实现，正式FE/BE资源/网络与配对统计也未实现，不把现有功能采样称为完整性能观测。

Python在Java停止后用独立实现流式重建百万行源模型与所有实际可见写ID的规范行摘要，逐一核对Java读回的完整SHA。源摘要按本次进程缓存一次，源表仍在每格窗口前后实际全部读取；两者不能互相替代。损坏summary或无法写停止标记也不能跳过独立的process reap和安全清理尝试；原pin消失不等于Popen已退出，恢复DROP只在原helper真正退出后进行。无法确认退出、表归属或删除均保留FAIL和明确残留分类。

当前已有精确17.0.4编译和离线检查证据，尚无实际背景负载运行证据。 [test_ui_background_fixture.py](/data/project/massdb-sql/tools/license-checks/test_ui_background_fixture.py) 的16项输入/秘密/旧plan拒绝、未知ACK、排队时延、缺失/重复回执及协调篡改ID域测试已通过。带背景的完整18/54单context矩阵、功能背景与完整模型均待真实运行；即使这些功能通过，LP021/022完整并发矩阵、License页面与B导入轮询、五对正式A/A和A/B、尾延迟样本量及精度仍不得标PASS。

## 11. 固定10秒刷新子用例（离线检查通过，真实页面待验）

本轮只补 LP021 的固定刷新执行能力；不修改权威LP021/LP022输入。plan 与 probe 均须显式添加 `--refresh-cadence`，且同一计划必须已经通过 `--background` 冻结第10节的恒定读写输入。浏览器cell预算至少420秒，整轮仍须保留全18或54格。没有这个选项时仍执行第9节原功能导航流程；不能在probe阶段把旧计划改成刷新负载。

该子用例先真实登录、独立检查Home初始页面，再发browser-ready以释放Java背景窗口。单个context在窗口内保持所选语言、前缀、身份和FE入口；起点Home，刷新固定在第10、20、…、290秒，共29次。第95秒另行导航到Playground、第195秒另行导航到Configuration，因此Home有9次整页reload，Playground有10次真实树Refresh按钮，Configuration有10次整页reload。两次导航是单独的额外计划事件，不能把它们算成刷新或假设三个页面的网络成本相同。完整31项事件在plan生成时冻结；结果里同时保存原计划序号、到达与deadline。

事件按事前固定时点运行，上一项较慢时下一项仍保留原到达时间；E2E包含排队。每项截止时间为原到达后20秒或窗口结束，两者取早。调度恢复时已经错过截止的项记 `QUEUE_DEADLINE_MISS` 并保留未发送事实。运行中的项超时或oracle失败会先关闭该page，避免未停止的Playwright操作与下一项重叠；剩余计划逐项记 `NOT_SENT_ABORTED`。背景不会因这些UI失败降速或重放，原300秒窗口/清理规则仍由独立Java/controller约束。

每个真实操作仍核对原FE API及Home构建值/DOM、Configuration初始30行/实际HTTP端口、Playground数据库树/编辑器、前缀路由与语言；原非管理员拒绝按实际Cookie/Access denied分支检查，只有实际出现“Cookie is invalid”的modal才关闭它。每个计划事件须对应唯一的目标API request ID、同一action分类、HTTP200、正确JSON业务或权限拒绝、完成状态和实际起止时刻；该action出现额外同类API请求也会失败。Python独立复核这些链接、重复/缺失请求、未移动的到达时点、含排队时延、每项deadline和实际背景窗口内的执行证据。它还要求下一项实际开始不早于前一项完成，失败中止后不得再发送，避免逐项自洽却彼此重叠的回执隐藏排队；不以定时器触发次数冒充成功刷新。

权限拒绝核对成功记录为 `original_permission_denials_verified`；只有实际业务成功刷新才计入 `successful_business_refreshes`。拒绝不能计作成功业务吞吐。调度和API观察使用浏览器单调时钟，跨进程只通过各自UTC锚点/真实背景回执核对重叠；Java纳秒仍以十进制字符串在JS证据中保留，不能混用进程时钟原点。

刷新子用例有单独 `subcase=fixed_refresh_cadence`，明确记录默认深链接、history、语言切换等导航子项为 `not_run_in_refresh_subcase`；这些既有要求仍由第9节独立功能子用例保留，不能把两种模式一次运行说成均已覆盖。对于带背景的默认导航，ADMIN表列表oracle只在原preflight列表基础上加入已由ready/owner确认创建的本次写表，避免把真实新增的owned表误判成未知数据；不改变非管理员权限期望。

新测试源码覆盖固定29+2计划、慢操作不重排到达、调度错过deadline、超时后关闭/保留全部未发送项、HTTP与JSON分层oracle、拒绝不算业务吞吐、重复/缺失请求、隐藏队列时间、跨事件计时重叠及越过实际背景窗口。本工具最新离线检查已通过24项Python、13项Node测试；本节300秒刷新与背景的实际浏览器/SQL仍未运行。原18格导航的独立实际记录见第12节。仍缺LP021的10/50 contexts与完整License覆盖、LP022的多context导入/可见性/有限轮询、完整会话负例/视口、正式配对统计与精度；本节不将任何完整用例标PASS。


## 12. 2026-09-24 原版单FE导航实际证据

`lp021-ui-navigation-actual-v2` 已执行全部18格：三种前缀×两种语言×三种真实账号权限。
账号仅本轮拥有：CREATE ACK及专有comment登记后使用，结束逐一DROP ACK；独立新JDBC查询确认
三个名称任意host均缺席。131个原FE JAR内static成员、原FE/BE进程身份均保持原发行值。

最终6 PASS、12 PARTIAL；原报告 `PARTIAL_OR_FAILED` 与exit2保留。18格规定的导航、原权限、
有权限账号的完整三行查询、前进后退和真实注销均已通过。12格额外的新页面结果深链观察到
history.state缺失限制；它不属于原版规定导航动作，也不能转化为P2U证书深链通过。
独立范围审计在 `.build-records/license-p0-p1-20260924/lp021-ui-navigation-actual-v2/required-navigation-audit.json`，
独立账号/进程/pins清理在同目录 `cleanup-audit/report.json`。原v1的18格失败完整保留，未覆盖或改状态。

真实尝试发现原测试器按钮定位未兼容AntD的双汉字空格与图标可访问名称；新版本以完整可见按钮
文本定位且保留role/button，所有登录响应等待及时挂拒绝handler。每项动作增量保存固定错误类别，
Node stdout/stderr只保存字节数、摘要和固定错误类别，不保存异常原文、Cookie、凭据或任意页面文本。
本轮没有300秒背景、1/10/50并发、正式A/A、授权页面或证书导入验收，完整LP021/022均仍未完成。
