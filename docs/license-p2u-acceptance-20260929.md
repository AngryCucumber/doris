<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# P2U 证书页面验收记录

日期：2026-09-29。**状态：P2U 已实现并完成约定范围的分层功能验收。** P4 性能验收仍未完成。

本阶段依据[执行计划](license-certificate-execution-plan-20260922.md)第 5.2 节和
[P0 契约](license-p0-contract-20260922.md)的 U01–U04，实现 FE 顶部证书页面。
P0/P1/P2/P3 已完成的记录保持不变。P4 的业务/页面并发性能矩阵及检测精度不以本次功能验证替代。
本次不修改 BE、通信协议或 Web 登录资格，不要求麒麟/openEuler 或多架构发行验证。

| 要求 | 所需证据 | 当前结果 |
| --- | --- | --- |
| U01 导航 | Configuration 后的 License Tab；独立懒加载；其他 Tab 零许可请求；根路径和反向代理前缀、直达/刷新/前进后退、中英切换 | 通过：受控浏览器和最终 JAR 实际页面 |
| U02 导入与权限 | 已有 Web 资格的 ADMIN/普通用户；文件/文本、64 KiB 输入限制、validate 后确认导入；坏证保旧、后端拒绝无权 POST；关闭/成功/注销清空正文，URL/storage/日志不含正文 | 通过：浏览器边界/清理及实际 FE 权限、导入和证书日志扫描 |
| U03 回执与取消 | 已提交未应用和丢响应只查询原指纹；2/4/8/16/30 秒串行退避，总预算 120 秒；隐藏/离开/注销/网络失败停止，手动查回执，不自动重提证书 | 通过：时序/延迟/202 由受控浏览器覆盖；真实 FE 截断响应后手动恢复 |
| U04 状态与角色 | active/pending、过期/未就绪/超额/时钟异常；UTC/本地展示；服务端决定状态；节点用量和上限；切换角色清除旧详情 | 通过：状态矩阵由受控响应覆盖；真实自然续期/过期、客户端时钟及角色切换 |
| 构建与原页面兼容 | Node 22.23.2/npm 10.9.9 构建；notices 校验；既有 legal/browser 测试；源码头校验 | 通过；完整 tsc 的既有依赖失败单列 |
| 实际 FE 联调 | 精确 JDK 17.0.4，真实 Cookie 登录、Master/Follower、实际 API、反向代理和 FE 内静态资源；测试对象/账号/服务清理 | 通过：最终 package3，全部自有测试服务已退出，原基准身份不变 |

浏览器模拟 API 测试用于验证可控错误、竞态和时序；实际 FE 记录用于证明登录、权限、持久导入、
回执及静态资源路由。两层分开列示，不能互相冒充。
首次失败及修正后结果保留在忽略目录 `.build-records/license-p2u-20260929/`；测试证书、私钥、
账号口令和临时安装不提交。原基准 FE/BE 生命周期固定，不能以本次夹具清理名义停止它们。

## 实现边界

- 新增页面、专用管理 API 适配器、指纹/回执模型和会话变化通知；沿用已有 FE 管理接口，
  没有修改 Java/BE 产品源码、验签依赖、通信协议或登录资格。
- `/License` 在 Configuration 后懒加载。其他 Tab 不请求许可状态；进入时读取一次，
  其后只响应手动刷新。ADMIN 查看详情并导入，已有 Web 资格的普通用户只看服务端脱敏状态。
- 文件和文本按 UTF-8 字节计数，最多 64 KiB；先预检，再显式确认导入。浏览器只计算提交字节的
  SHA-256 回执指纹，签名校验仍由 FE 完成。正文不写 URL、浏览器存储或诊断日志。
- 使用原请求指纹确认提交，并精确比较十进制版本，避免 JavaScript 大整数舍入。请求中断、
  错误指纹或不一致的 APPLIED 响应不能显示导入完成；网络失败停止自动查询，保留手动恢复入口。
- 轮询按 2/4/8/16/30 秒串行退避，`performance.now()` 控制 120 秒总预算，截止时中止在途请求。
  单次请求另有 30 秒上限，尊重 Retry-After；隐藏、离开、注销和网络失败均停止，恢复可见后不自启。
- 到期状态来自 FE，浏览器时钟只格式化时间。服务端的 active/pending 是存储槽名，pending 到生效时
  不一定立即搬到 active 槽；页面使用“主证书/续期证书”标题，当前有效期、用量和上限以状态区为准。

SQL 查询入口已在 P2 实现：`SHOW LICENSE` 查看状态，管理员还可使用
`SHOW LICENSE DEPLOYMENT` 和 `SHOW LICENSE IMPORT '<sha256-fingerprint>'`。
`SELECT @@massdb_license` 未实现。证书异常不阻止合法管理查询和续期。

## 浏览器、构建及产物证据

浏览器使用生产 bundle 和受控 API，不替代真实 FE。最终 browser-v5 在 ui-build-4 上完整执行
**40 个功能子组全部通过**，包括 3 个回执目标连续切换回归；另有模型组以 Node crypto 验证
11 个 SHA-256 边界向量和超过 JavaScript 安全整数范围的相邻版本。Node 报告的 42 项包含父组，
不与 40 个功能子组重复相加。根路径、两种代理前缀、375 px 中英页面均通过，标题距实际导航
下沿 26 px；此前相同 CSS 的截图已人工复核。早期 37 组分轮通过（v2 的 34 组、v3 的 3 组）和
v4 的 5 组布局复验保留为历史，不替代最终完整执行。逐组结果、原失败及绑定见
[浏览器完成清单](/data/project/massdb-sql/.build-records/license-p2u-20260929/tests/completion-audit.json)。

Node 22.23.2 / npm 10.9.9 的最终 ui-build-4 构建、`check:notices` 均通过。
`test:legal` 在 build3 上通过；build4 只改证书页状态清理，135 件资产中 131 件逐字相同，
其余变化为证书页 chunk、仅文件名哈希变化的 index.html/main runtime 和法律清单。
全部 CSS、其他行为 chunks 和版权正文保持相同，因此未重复未受影响的 legal 浏览器检查；
改变的许可行为以最终 40 组完整执行验收。详见
[最终构建审计](/data/project/massdb-sql/.build-records/license-p2u-20260929/final-build-audit-v2.json)
和[资产差异](/data/project/massdb-sql/.build-records/license-p2u-20260929/ui-build-4/assets-diff-vs-build3.json)。

最终 fe-package-3 在精确 JDK 17.0.4+8 上离线执行
`mvn -o -pl fe-core -am package -DskipTests -Dskip.doc=true`，退出 0，Checkstyle 未跳过，
FE JAR 版权清单检查通过；其中 135 件静态资源与最终 UI 构建完全一致。
Java 产品源码未改，未重复已有 Java 单测；与 P3 最终包比较，common 的 6,398 个 class 完全相同，
FE 的 10,396 个 class 无增删，10 个差异类仅构建版本/时间常量变化，保留 javap 差异归因。
详见[最终产物绑定](/data/project/massdb-sql/.build-records/license-p2u-20260929/fe-package-3/artifacts.json)。

| 实际 FE 联调最终产物 | SHA-256 |
| --- | --- |
| `doris-fe.jar` | `e5e05b1489d0e007a3d5aa097db15d99500c578e4241fdcb1c4c1ad197b8f4c2` |
| `doris-fe-common.jar` | `29a9fa69e68b0b88a44f3495c1827dbb61ffc7551beee17228c29ac7f43bd9fb` |

## 真实 FE 结果与清理

最终 cluster-v4/browser-v4 使用上表 package3、全新元数据及两个 FE，没有启动或修改 BE。
浏览器直接请求 FE JAR 中的页面，代理仅转发真实响应，不合成 SPA fallback 或 API 成功结果。
实际 Cookie 登录验证了根路径及 `/massdb` 前缀、HttpOnly 会话、导航/中英切换及刷新。
Cookie 证据来自登录上下文断言及代理入站的 19 次带 Cookie、无 Authorization 的 API 请求；
本轮 Playwright `request.headers()` 未暴露 Cookie，其采集字段为 false 不代表网络上没有 Cookie。
其他 Tab 没有许可请求，证书页 10.5 秒实际空闲没有后台状态轮询；更长时间边界由受控浏览器覆盖。

真实文件/文本预检后确认导入，序号 1 成为 active，序号 2 和 3 先进入 pending。
页面显示 2/2 FE、0/1 BE。对序号 3，代理在真实 FE 返回 200 后只发送 298 字节正文中的 32 字节，
客户端停止自动处理并保留原指纹，手动查询得到 APPLIED；应用 fetch、浏览器网络请求均各一次。
本轮自然导入和回执均为 200/APPLIED；202/COMMITTED、UNKNOWN 延迟、429 和有界轮询由浏览器
受控用例证明，不能称为本轮真实 FE 同步延迟故障。

不改变宿主机时间，实际等待续期生效及到期：从节点在 trusted_utc 1790658487 显示
active.sequence=3/pending=null；最终证书 expires_at=1790658616，Master/Follower 均在实际到期后
显示 EXPIRED。将浏览器 Date 改为 2041 年不会改变服务端 EXPIRING 状态。
普通 NODE 用户只收到状态、到期和角色三字段，直接管理 POST 返回 403；CSRF 缺失同样拒绝。
同一浏览器 ADMIN 注销再以 NODE 登录后，旧详情和导入入口清除。

初步 API 联调另覆盖匿名 401、Origin/CSRF、HTTP 大小限制和坏证保旧，使用的是已验收 P3 包；
最终包中的许可 Java 行为字节一致，构建版本常量差异单独归因。该旧包记录不写成最终浏览器执行。
所有自有测试账号已删除并核对，浏览器、代理和集群控制进程均实际等待退出 0，
自有网络命名空间无剩余进程，原基准 FE/BE 生命周期不变。最终 52 项诊断扫描没有证书/JWS
分段/签发私钥命中；原 CREATE USER 审计的 14 处测试口令命中仍保留为独立 FAIL。
完整请求、界面、包/源码绑定、早期失败和清理见
[真实 FE 最终审计](/data/project/massdb-sql/.build-records/license-p2u-20260929/runtime/final-runtime-audit.json)。

## 保留的失败与限制

1. 首轮浏览器测试终态为失败，原测试源码和日志保留；语言初始化及测试中禁用动画造成的夹具问题
   已修正。第二轮 37 个浏览器子组通过 34 个，3 个失败涉及暂停时钟下的弹窗关闭动画、断流夹具及
   对不一致回执字段的过度显示断言；第三轮仅复测这 3 组并通过，不回写前两轮为 PASS。
   另由实际截图发现 375 px 下固定导航换行遮挡标题，已只增加新证书页窄屏顶部留白，第四轮视觉复验通过。
2. 实际 API 前置联调的首个辅助脚本误将两小时证书要求为 VALID，实际正确状态为 EXPIRING；
   另一处使用了错误的全局 GRANT 语法。后续联调通过，两个原始失败均保留。
3. 既有 TypeScript 3.9.10 无法解析部分当前依赖声明，完整 `tsc --noEmit` 失败。
   没有升级依赖来扩大修改范围，也不宣称全项目类型检查通过；生产构建、浏览器行为及真实 FE 分别验收。
4. 原 CREATE USER 审计可能记录测试账号口令，相关命中与证书/JWS/签发私钥扫描分开记录。
   本次没有扩展为一般账号审计修复，测试账号须在最终清理中删除。
5. 功能测试不替代 P4 的业务负载、1/10/50 页面并发、A/A 噪声和 A/B 性能精度验收。
6. 无响应字节即断链的浏览器夹具观测到 Chromium 将一次应用 fetch 传输重试成多条 HTTP 请求。
   页面不做应用层自动重提；服务端仍按原指纹处理幂等提交。断响应恢复用例改为真实响应头后截断正文，
   分别记录应用调用与网络请求数，不将传输重试误判为页面重新提交，也不宣称浏览器底层绝不重传。
7. 最终独立复核发现回执 A 成功后，切换到 B 的指纹或开始新操作时会残留 A 的成功提示。
   已修复为换目标、新提交和新查询时清除旧成功状态，并补 3 个多目标连续操作回归。
   最终 40 组完整执行通过，原 37 组记录没有被改写成已覆盖此问题。
8. 实际浏览器联调先后遇到辅助脚本误用 Playwright `Response.url`、从节点 SQL Alive 已真但 HTTP
   尚未监听的问题。原失败保留；辅助脚本增加 HTTP 与恢复就绪等待，旧集群清理后使用新包重跑。
