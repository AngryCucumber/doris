<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# P1：JDK 17.0.4 精确版本验证

2026-09-24，北京时间。用户明确现用 JDK `17.0.4`；此前提到的麒麟/openEuler、ARM64/x86 组合已按用户后续说明移出本轮目标，当前版本先供用户自己使用，不要求多平台矩阵验收。
本记录将证书核心的实际产物放到 **Eclipse Temurin 17.0.4+8、Fedora 42 aarch64** 上验证：
发行密码学探针 **42/42**，独立加载同一产品 JAR 的核心 JUnit **104/104**，均零失败/跳过。
这证明记录的 JDK/OS/架构组合，不代表麒麟、openEuler、x86_64 或其他厂商 JDK 已通过。

## 官方来源和完整性

本机预装 JDK 为 `17.0.2`，另有 JDK 8、21，没有 `17.0.4`。
本次从 [Adoptium 官方 Temurin 17.0.4+8 发行页](https://github.com/adoptium/temurin17-binaries/releases/tag/jdk-17.0.4%2B8)
取得 Linux aarch64 JDK 及同发行的 SHA-256 文件。下载校验遵循
[Adoptium 官方归档说明](https://adoptium.net/installation/archives)。未采用第三方转载，也没有更新系统 JDK、PATH 或服务配置。

| 项目 | 实际值 |
| --- | --- |
| 供应商 | Eclipse Adoptium，Eclipse Temurin HotSpot |
| Java version / runtime version | `17.0.4` / `17.0.4+8` |
| javac | `javac 17.0.4` |
| 官方包 | `OpenJDK17U-jdk_aarch64_linux_hotspot_17.0.4_8.tar.gz` |
| 包大小 | 189,804,023 字节 |
| 官方及实际 SHA-256 | `8c23b0b9c65cfe223a07edb8752026afd1e8ec1682630c2d92db4dd5aa039204` |
| 实际操作系统 | Fedora Linux 42，kernel `6.15.4-200.fc42.aarch64`，glibc 2.41 |
| 签名 provider | `SunEC version 17` |
| 测试 CPU | 0–4 |

官方资产 URL、原始 API 响应、checksum 文件、完整 Java properties、下载时刻及实际 OS 信息保存在
[下载校验记录](/data/project/massdb-sql/.build-records/license-p1-jdk17.0.4-20260924/download-verification.json)。
解压目录为 `/data/project/massdb-sql/.build-records/license-p1-jdk17.0.4-20260924/jdk-17.0.4+8`，仅供这次隔离验证。

## 实际产物及执行证据

使用 2026-09-24 断网 Maven package 生成的 `fe/fe-core/target/doris-fe.jar`，不是旧发行包中未包含新核心的 JAR。
JAR SHA-256 为 `4281b01d3fea1c2b83145e5e64d9bfd401da6620381cc44fa3a666904881f2f5`。
Jackson core/databind/annotations 均来自同次 `target/lib`，版本 `2.16.0`；三份实际 JAR 摘要保存在探针报告。

```bash
unshare --net --fork --kill-child taskset -c 0-4 python3 tools/license-checks/verify_release.py \
    --java-home /data/project/massdb-sql/.build-records/license-p1-jdk17.0.4-20260924/jdk-17.0.4+8 \
    --fe-lib /data/project/massdb-sql/fe/fe-core/target/lib \
    --classes-from /data/project/massdb-sql/fe/fe-core/target/doris-fe.jar \
    --openssl /usr/bin/openssl \
    --report /data/project/massdb-sql/.build-records/license-p1-jdk17.0.4-20260924/jdk17.0.4-built-jar-report.json
```

实际执行由归档的 `run-offline-probe.py` 调用同一命令参数，并记录新 namespace 与宿主 namespace 不同；新 namespace
未启用网络接口或宿主路由。探针使用 Java 17.0.4 编译其辅助程序 `--release 8`，从指定产品 JAR 加载已有核心字节码，
不重新编译或替换目标核心类。全部实加载目标为 class major 52，具体来源与 class 摘要也记录在报告中。

- [42 项发行探针报告](/data/project/massdb-sql/.build-records/license-p1-jdk17.0.4-20260924/jdk17.0.4-built-jar-report.json)：
  实际 JCA provider、许可及修复用途、Java/OpenSSL 双向签验、错误 key/type/用途/篡改拒绝、完整 Unicode 文本互通。
- [断网执行记录](/data/project/massdb-sql/.build-records/license-p1-jdk17.0.4-20260924/offline-invocation.json)：
  实际命令、CPU 集合、namespace、起止时刻及退出码 0。
- [104 项核心测试报告](/data/project/massdb-sql/.build-records/license-p1-jdk17.0.4-20260924/jdk17.0.4-core-tests.json)：
  独立 JUnit launcher 在另一个断网 namespace 中使用精确 JDK 17.0.4，产品 JAR 优先于 test-classes；包括固定 RFC/JWS 向量。
  104 项成功、0 失败/异常中止/跳过。这是新增运行时组合的补充验证，不替代单列的 Maven 定向测试记录。
- [测试材料隔离扫描](/data/project/massdb-sql/.build-records/license-p1-jdk17.0.4-20260924/product-test-isolation.json)：
  遍历产品 JAR 的 10,577 个文件、109,151,214 字节解压内容，没有许可测试类、共享 fixture 资源或固定公开测试
  seed/public-key hex/JWS 文本。测试资源只用于测试，不被安装为生产信任根。

本次没有启动或请求 FE/BE、替换服务 JDK、安装生产公钥或变更服务器时间。所有私钥均为探针临时随机测试密钥，
或固定测试中的公开 RFC 测试 seed；不能用这些结果证明客户生产信任清单已审核。
后续按本次实际自用环境验证最终产物和 JDK 兼容；不以麒麟/openEuler 或多架构发行机矩阵作为当前完成门槛。历史记录不因范围调整外推为其他平台通过。
