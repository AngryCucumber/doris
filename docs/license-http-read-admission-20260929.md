<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# FE 独立 HTTP 读取许可补充

日期：2026-09-29。ES 搜索和文件预览已接入现有许可守卫；42 项定向测试和 JDK 17.0.4 FE 构建通过。
产品源码仅修改 `ESCatalogAction.java`、`ImportAction.java` 两个控制器。
本次新增的是原五出口之外的两个入口，旧 P4 包及其运行验收记录不包含本补充。

## 行为

| 入口 | 许可异常时的行为 |
| --- | --- |
| POST `/rest/v2/api/es_catalog/search` | 原认证和 HTTPS 重定向之后、ES catalog 初始化及搜索之前，返回 HTTP 403 |
| POST `/rest/v2/api/import/file_review` | 原 HTTPS 重定向和认证之后、文件枚举及 CSV/Parquet 读取之前，返回 HTTP 403 |
| GET `/rest/v2/api/es_catalog/get_mapping` | 正常索引选择器继续返回元数据，不检查业务读取许可 |

拒绝响应直接包含 `reason`、`message`、`retryable`，不套用 HTTP 200 的业务错误外壳。例如过期：

```json
{"reason":"LICENSE_EXPIRED","message":"LICENSE_EXPIRED","retryable":false}
```

有效和临近到期的许可继续允许读取；未就绪、缺失、到期、时钟异常等状态沿用共享守卫的拒绝规则。
关闭 `enable_all_http_auth` 不关闭许可检查；开启认证时原认证失败仍优先处理。
同一控制器实例的下一次请求重新读取已发布状态，能够观察到期和续期，不需要重启。
已获准并正在执行的请求不在到期时强制中断，符合现有 FE 准入规则。

为防止绕过限制，`get_mapping` 的 `table` 参数不能为空，也不能包含 `/`、`\`、`?`、`#`、`%`、
空白或控制字符。该参数原来直接参与 ES URL 拼接，例如 Servlet 解码后的 `_search#` 可使
追加的 `/_mapping` 落入 URL fragment，从而改变实际路径。现在在 catalog 初始化前拒绝这种参数。
参数错误保留原接口的 HTTP 200、业务 `BAD_REQUEST` 格式；它不是许可拒绝。
普通索引、别名、逗号分隔多个索引以及 `logs-*`/`*` 模式继续支持；包含上述字符的日期数学等表达式不支持。

正常请求仅调用 `LicenseQueryGuard.checkProtectedRead()` 读取现有许可状态，不在请求中解析证书、
重新验签或增加 RPC。此次没有新增性能测量，不能将其表述为已经证明零开销。
导入写入、其他元数据、BE、SSL/mTLS 和原协议均不改变。

## 验证

在 Temurin 17.0.4+8 上，从 `fe/` 执行以下离线构建，退出码 0：

```sh
mvn -o -pl fe-core -am package \
  -Dtest=LicenseExternalHttpAdmissionTest,LicenseQueryGuardTest,LicenseSnapshotTest,LicenseTableQueryPlanAdmissionTest \
  -DfailIfNoTests=false -Dsurefire.failIfNoSpecifiedTests=false -Dskip.doc=true
```

| 测试类 | 通过数 |
| --- | ---: |
| LicenseExternalHttpAdmissionTest | 12 |
| LicenseQueryGuardTest | 12 |
| LicenseSnapshotTest | 14 |
| LicenseTableQueryPlanAdmissionTest | 4 |
| 合计 | 42 |

零失败、零错误、零跳过，四份 Surefire XML 均为本轮新生成；构建前后产品及测试源码哈希一致。
FE reactor Checkstyle 同时通过。新增控制器测试覆盖全部拒绝状态及认证开关两态、CSV/Parquet、
有效/预警返回、到期后拒绝和续期后恢复、认证与重定向顺序、18 种非法及 7 种正常 mapping 参数。
拒绝路径核对外部调用次数为零；许可 guard 使用真实实现，许可状态和 ES/broker/Parquet 使用模拟对象。
这里验证的是控制器返回的 HTTP 状态和调用顺序，未启动实际 ES/broker 集成环境，也未重新跑长时间性能测试。

原始日志、源码绑定、XML 和产物绑定见
[checks-v3/completion.json](../.build-records/license-http-admission-20260929/checks-v3/completion.json)。
首次 `checks-v1` 因新商业测试未加入 Checkstyle 的精确路径规则而失败，失败记录保留；
补齐规则后的 `checks-v2` 40 项通过，随后补充 mapping 边界的最终 `checks-v3` 42 项通过。

| 最终构建产物 | SHA-256 |
| --- | --- |
| FE JAR | `6ee20458ea7142b75007860a37ec6691ccab72b57b18831e91ec988887d00636` |
| fe-common JAR | `29a9fa69e68b0b88a44f3495c1827dbb61ffc7551beee17228c29ac7f43bd9fb` |

## 交付与边界

本轮自用发行目录为 `output/massdb-sql-2.0.5-license-http-bin-arm64`；包构建与归档核对使用单独回执，
不将打包等同于真实服务验收。原 P4 启动、导入和重启记录仍绑定其原 FE 哈希。
新包使用上述 FE 构建及原包的 BE、公钥信任清单、页面和依赖；随包提供本记录和更新后的执行计划。
只保留核对后的最新发行目录、归档和 SHA-256 文件，历史验收与失败记录保存在 `.build-records/`。

此前用户允许保留的原版 Parquet reader 未关闭缺陷仍存在；本补充只保证许可拒绝时不打开 reader。
其他保留边界包括 BE 旧计划/下载、备份和 CCR，以及非查询 SET 字典、过程文件/进程和 UDF 外发；
本轮不把这些通道声明为已封堵。完整边界见[执行计划](license-certificate-execution-plan-20260922.md)。
