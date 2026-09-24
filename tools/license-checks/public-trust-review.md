<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# 实际公钥清单的只读验收

`review_public_trust.py` 使用指定交付 FE JAR 中真实的 `LicenseTrustStore`，核对管理员提供的公钥清单。
它补充已有 `verify_release.py` 临时测试密钥互通检查；这两项分别绑定实际公钥和密码实现/发行环境。
2026-09-24已完成19项Python离线检查及12个实际验收/拒绝命令；真实Java探针由Temurin17.0.4+8编译，
针对当前候选FE JAR/Jackson运行。输入仅为现有RFC8032测试公钥；尚未接收生产公钥，不能称生产交付门槛已通过。

需明确提供当前清单及通过受控交付渠道取得的 SHA-256、实际 JDK17.0.4 发行商构建、FE JAR 和同批
Jackson 目录。工具在本 checkout 新的 `.build-records` 目录编译独立探针，禁止注解处理器，
使用 `--release 8`；产品文件保持只读。运行前发现正在进行的基准测量则拒绝启动。

```bash
python3 -B tools/license-checks/review_public_trust.py \
    --manifest /secure/vendor/massdb-license-trust.json \
    --manifest-sha256 REPLACE_WITH_TRUSTED_SHA256 \
    --java-home /absolute/path/to/the-actual-jdk \
    --expected-java-runtime-version REPLACE_WITH_ACTUAL_JDK_RUNTIME \
    --artifact /absolute/path/to/delivered/fe/lib/doris-fe.jar \
    --fe-lib /absolute/path/to/delivered/fe/lib \
    --output .build-records/public-trust-review-001 --cpu 5
```

该命令会执行 Java 编译和验收，不是计划预览。JDK与CPU必须在实际目标机器上存在；客户版本尚未确定时，
不能用本机 Temurin17.0.4+8/Fedora/aarch64 的记录代替麒麟、openEuler 或 x86_64 的资格。
输出保留实际宿主/运行时、输入摘要、生成 class 摘要、实际加载类来源与摘要和 Ed25519 provider。
Java核心 class 必须是 major52，Jackson实际来源必须与指定目录一致。
JDK的`release`文件必须声明`JAVA_VERSION=17.0.4`；存在`JAVA_RUNTIME_VERSION`或`FULL_VERSION`时也须
与声明构建一致。厂商可以省略这些可选构建字段，最终仍必须核对真实进程的`java.runtime.version`完全相等。

Python先按发行工具的严格规则核对64KiB、重复/未知字段、1–32项、kid唯一性、规范Ed25519 SPKI和用途隔离；
Java再用实际交付类重新解析。完整公钥验收要求 `license` 与 `time_repair` 两种用途均有独立公钥。
归档只显示 kid、用途、44字节SPKI的SHA256；仅含一种用途的清单仍可能是产品合法配置，但不能通过这里的
完整公钥交付门槛。初次解析的字节摘要与Java实际读取摘要核对，禁止混用两份证据。

轮换时同时提供 `--previous-manifest` 和 `--retention`。后者的内容须由操作者从实际 active/pending、
过期基础额度及仍需复验的 image/journal/修复回执依赖汇总，格式精确如下：

```json
{
  "schema_version": 1,
  "previous_manifest_sha256": "<旧清单原始文件SHA256>",
  "license_kids": ["still-needed-license-key"],
  "time_repair_kids": ["still-needed-repair-key"]
}
```

两个列表必须显式存在、去重且属于旧清单的相应用途。空列表是操作者提供的声明；工具没有连接 Env、
journal 或归档存储，无法证明依赖已经全部回收。Java真实 `requireSafeReplacement` 和Python独立模型
都检查保留依赖、同kid替换和跨用途复用（包括换kid后复用）；旧清单及依赖文件各自绑定初始读取摘要。
报告明确保留 `retention_completeness_verified=false`，通过此检查不授权实际删除旧公钥。

每个编译/验收子进程最多120秒、采样RSS/高水位768MiB、每条输出流1MiB。取消在安全位置生效；
父进程用 `waitid(WNOWAIT)` 在清理自有进程组之前保留leader PID，覆盖leader已退出而子孙仍占用管道的情形，
最后独立回收leader并记录清理错误。超限、取消、输入变化、清理错误或Java/Python结论不一致均不能通过。
Linux在进程进入`Z`/`X`退出状态时可能先撤销RSS字段、后提供可回收的`waitid`结果；工具只对此已退出状态
允许缺少内存采样，仍等待原绝对deadline内的真实退出状态。活进程缺失RSS或超过限额仍拒绝。

`PUBLIC_TRUST_REVIEW_PASS` 只证明这份显式输入通过实际交付解析器和声明依赖检查。
清单本身不是认证根，此工具不证明签发方身份或私钥持有、不生成私钥、不安装公钥、不导入证书；
`production_release_qualified` 和 `full_goal_complete` 始终 false。
实际部署仍须核对受控交付来源、实际保留依赖的完整性、签发方提供的真实样本验签及运行环境记录。本次是用户自用版本，运行环境仅指实际部署环境，不要求历史麒麟/openEuler或多架构发行矩阵；本工具的历史字段不恢复已移出的平台验收目标。

## 实际工具验证记录

本次使用Eclipse Temurin`17.0.4+8`、SunEC、Fedora42/aarch64，实际候选
`fe/fe-core/target/doris-fe.jar`的SHA-256为`4281b01d3fea1c2b83145e5e64d9bfd401da6620381cc44fa3a666904881f2f5`，
Jackson为同目录的2.16.0三件套。Java辅助类采用`--release 8 -proc:none`编译。

- [19项Python检查日志](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/public-trust/python-tests-v3.stderr.log)全部通过，包含新增的Temurin字段兼容性和退出状态RSS负例。
- [实际验收摘要](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/public-trust/runtime-exit-fix-v3/validation-summary.json)记录2个完整controller正例（初始清单与保留依赖轮换）、5个controller负例、4个直接Java负例和1个直接Java合法配置边界；共12个命令符合预期。
- [初始清单报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/public-trust/runtime-exit-fix-v3/initial-public-test-smoke/report.json)与[轮换报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/public-trust/runtime-exit-fix-v3/safe-retention-public-test-smoke/report.json)保留实际加载类、JDK/输入/class摘要和子进程回收结果；[逐命令记录](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/public-trust/runtime-exit-fix-v3/smoke-commands.json)关联stdout/stderr摘要。
- [测试材料来源](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/public-trust/runtime-exit-fix-v3/test-material-provenance.json)明确仅复制仓库已有RFC8032 TEST2/3公钥，没有提取seed、生成密钥或安装信任集；私钥未知字段的测试canary未进入报告或诊断输出。

实际执行发现并修复两项误拒绝：Temurin使用`FULL_VERSION`而非`JAVA_RUNTIME_VERSION`；成功退出的javac在
`Z`状态下暂时无RSS、但尚未被`waitid`观察到。首轮[版本字段失败](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/public-trust/smoke-harness.stderr.log)、
第二轮[退出阶段失败](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/public-trust/runtime-field-fix-v2/initial-public-test-smoke/report.json)
及[实际Z状态诊断](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/tool-validation-20260924/public-trust/diagnostic-compile-exit-state.json)均保留，没有以重跑覆盖。

负例核对错误清单摘要、单用途完整验收拒绝、私钥未知字段、重复JSON字段、仍需保留的旧kid删除及跨用途轮换。
单用途清单在产品解析器中合法、但无法通过这里的完整交付要求，两种结果均显式验证。
这些结果只验证工具和公开测试清单，未证明生产签发方、实际历史依赖完整性、麒麟/openEuler/x86_64或其他JDK发行组合。
