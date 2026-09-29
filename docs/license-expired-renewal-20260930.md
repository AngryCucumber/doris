<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# 证书到期后缩容续期补充

日期：2026-09-30。支持旧证到期后，先完成 FE/BE 缩容，再导入额度较低的新证书续期。
原实现把历史基础额度保留为永久续期下限；本次取消已经过期承诺的这项下限，保留实际用量检查。
产品改动限于三个 FE 许可管理类和 Python 签发工具，不修改查询准入热路径、BE、页面或通信协议。

## 使用规则

例如旧证额度为 FE 3 / BE 10，新证额度为 FE 2 / BE 5：

1. 等待旧授权承诺到期。若还有未过期的 active、pending 或 base 高额度承诺，仍不能降低该额度。
2. 按正常流程缩容到 FE 不超过 2、BE 不超过 5；额度按已注册成员加预留量计算。
   停止进程或仅离线不释放额度。BE 应通过 `DECOMMISSION BACKEND` 完成数据迁移和真正除名；
   FE 删除仍需满足原有角色、主节点和法定人数约束。授权到期不会禁止这些管理操作。
3. 通过原 SQL、HTTP 或页面入口校验、导入新证。部署、签名、序号、时间等原校验仍适用。
4. 立即生效的新证成功提交后，当前证书及基础额度一起更新为 2/5；新增节点按 2/5 检查。
   导入失败保留原许可事实，不会自动删除节点，也不会消费新证序号。

未到期时，即使已经缩容，也不能用新证削减仍有效的额度承诺。
到期边界采用已有可信 UTC：`now == expires_at` 即旧承诺到期，不使用客户端本地时间或手工改时绕过。
到期本身不会把 ADD 上限清空；新证接受前仍保留最后已提交的基础额度。

如果新证未来才生效，可以在旧承诺到期、实际数量已满足新额后提前导入为 pending。
等待期间 FE/BE 的 ADD 上限分别取 `min(已提交基础额度, pending 额度)`，防止重新扩容超过已接受的低额度。
较大 pending 不会提前增加名额。到生效点重新核对用量，持久提交后才切换基础额度。
等待期 `SHOW LICENSE`、HTTP 和页面中的 `max_*` / `base_max_*` 仍可能显示旧证/旧基础额度，
应同时查看 pending 的额度；它们不另设“实际 ADD 上限”字段。

| 情况 | 返回/结果 |
| --- | --- |
| 旧承诺未到期，或注册加预留数量仍超过新证额度 | SQL `6201 / 45000`；HTTP `400`；`LICENSE_NODE_LIMIT_TOO_SMALL`、`retryable=false`、`NOT_SUBMITTED` |
| 缩容完成、旧承诺到期且其他校验通过 | 新证导入并持久生效；未来证书进入 pending |
| 按新额度新增 FE 超限 | SQL `6202 / 40001`，`LICENSE_FE_LIMIT_EXCEEDED` |
| 按新额度新增 BE 超限 | SQL `6202 / 40001`，`LICENSE_BE_LIMIT_EXCEEDED` |
| 重复提交仍保留回执的旧证 | 返回原提交确认，不恢复旧额度，不降低最高序号 |

本次保持证书和 journal/image 外壳格式不变。导入前，全部已注册 FE 必须通过原有的相同 FE 包摘要及信任集门禁。
旧 FE 构造器不支持“旧高 active/base + 新低 pending”的恢复组合，接受这种状态后不能回退到旧 FE 二进制。
新恢复规则只放宽签名区间不重叠的 active/base 到 pending 降额；base 到 active 的原校验保留。

## 验证记录

使用 Temurin 17.0.4+8，在 `fe/` 离线执行 Maven reactor 的 31 个 `License*Test` 类并生成 FE 包：

```sh
mvn -o -pl fe-core -am package -Dtest=<31 个 License 测试类> \
  -DfailIfNoTests=false -Dsurefire.failIfNoSpecifiedTests=false -Dskip.doc=true
```

完整可复用命令及类名见
[构建回执](../.build-records/license-expired-renewal-20260930/checks-v1/completion.json)。
实际 279 项测试通过，零失败、错误或跳过；Checkstyle、FE 构建通过，构建前后 6,986 项源码绑定未变。
其中 `LicenseImportPolicyTest` 28 项、`LicenseManagerTest` 33 项；这些数量包含原回归，不能当作全部新增测试。
覆盖到期前一秒/到期时刻、FE/BE 单独及同时降额、未释放/预留用量、未结束 pending 保护、提交前并发变化、
失败保旧、旧证幂等、即时降额持久化、低 pending 等待期 ADD、激活再次校验、journal 重放和 image 恢复。
许可兼容测试沿用真实门禁实现与受控主机证明；未重新部署真实多 FE 混包或切主场景。

离线签发工具执行：

```sh
MASSDB_TEST_OPENSSL=/usr/bin/openssl python3 tools/license-issuer/test_license_issuer.py -v
```

28 项通过，覆盖签发/验签及降额续期边界。该结果来自实际工具输出，未单独捕获原运行日志；
[签发工具回执](../.build-records/license-expired-renewal-20260930/issuer-tests-v1.json)明确记录了这一点及事后源码绑定。
工具只检查指定前证；最终是否允许接受仍由 FE 全状态、成员量和可信时间裁决。

真实运行使用上述最终 FE JAR、包内公钥和一个隔离 FE，经 JDBC/HTTP 验证以下流程：

- 导入 3/3 旧证，注册到 2 FE / 2 BE；低额候选在旧证有效及自然到期后未缩容时均被拒绝。
- 删除 Observer 后仍有 2 BE，HTTP 导入返回 400 和 `LICENSE_NODE_LIMIT_TOO_SMALL`，最高序号保留 1。
- 删除一个 BE 身份后，SQL 校验和导入 1/1 新证成功；`SHOW LICENSE` 与 HTTP 的当前/基础额度均为 1/1。
- FE 和 BE 超额 ADD 分别返回上述 6202 错误；旧证重复导入确认原回执，当前证书、最高序号和低额度不变。
- 同一元数据重启后保留新证、成员数量和低额度，超额 ADD 仍拒绝。

本轮额外 FE/BE 为自建离线注册身份，未启动额外 FE 或 BE 服务，没有业务表或 tablet；
`SHOW BACKENDS` 核对两个身份的 `TabletNum=0` 后，夹具用原生 `DROPP BACKEND` 删除它们。
这验证真实成员管理及额度释放，不等于验证线上 BE 数据迁移、真实多 FE 法定人数变化或业务查询结果。
证书自然到期，不修改服务器时间。最终续跑 `runtime-v4-followup3` 退出码为 0；
[运行汇总](../.build-records/license-expired-renewal-20260930/runtime-summary-v1.json)绑定前述分段证据和最终通过记录。
保留各原始失败状态，不把中断运行改写为全流程一次通过。

以下失败均保留，不改写为通过；后续只修正夹具，无产品代码变化：

| 记录 | 原失败及后续处理 |
| --- | --- |
| runtime-v1 | 拷贝包中已有空元数据目录，夹具重复 mkdir；改为检查目录为空后使用 |
| runtime-v2 | 原版拒绝直接 `DROP BACKEND`；保留安全规则，空数据夹具改用 `DROPP` |
| runtime-v3 | 紧邻 VALIDATE/IMPORT 触发原管理限流；按原 6 秒补充一个令牌的间隔调用 |
| runtime-v4 | 错把全局 `applied_version` 当作导入专用版本，后台时钟事实推进后断言失败；续跑比较原导入回执及许可事实 |
| runtime-v4-followup / followup2 | 已验证重启及幂等，紧邻停机的第二次启动前 bind 探测返回 EADDRINUSE；后续核对无遗留监听者。最终续跑检查实际监听并等待整个自建进程组结束，不把 bind 失败误判为产品恢复失败 |

原 P4 性能结果、Flight 大批次和 Parquet reader 等原版缺陷不因本次规则调整改变。
本次不增加逐查询验签、成员遍历或网络请求；未重跑性能基线，不宣称新测量已证明零开销。

## 交付绑定

| 产物 | SHA-256 |
| --- | --- |
| 本轮 FE JAR | `17fe1df5f64f011d45d2254668a8ac9e6a9e0975a0d1a928c62e0e4c4243d528` |
| 原字节保留的 common JAR | `29a9fa69e68b0b88a44f3495c1827dbb61ffc7551beee17228c29ac7f43bd9fb` |
| 原字节保留的 BE | `a9480210dbf70f6d00b3aea5ea8bb039e135d45ab5e1e4697fdef1ea03a36163` |
| 原包公共信任清单 | `b7b7e54f5197d753dd319619ecd5ff15d1387d9b7705f62756cf4e5ecbd45f7b` |

自用包目录为 `output/massdb-sql-2.0.5-license-renewal-bin-arm64`，归档及 SHA-256 文件同名。
打包脚本只允许上述三个 FE 类及生成的构建常量发生字节码变化，135 个 static 页面资源保持原字节。
原 UI 来源绑定仍是此前构建的提交；上一轮当前 checkout 的 notice `sourceCommit` 检查失败记录继续保留，
不能把复用静态资源描述为已经按本次新提交重新构建 UI。
包清单、归档内容和源码绑定分别见本轮 `package-build-v1.json`、`archive-verification-v1.json`；
私钥不进入代码库、发行包或验收归档。测试结束后删除本轮已停止安装目录、元数据、日志及临时证书，
仅保留脱敏检查记录，不备份运行安装。旧发行包在替换包校验成功后移除。
