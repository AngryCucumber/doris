<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP023 精确载荷夹具

LP023 的 VALID 维度为 **512、4096、16384 个 decoded canonical JSON UTF-8 字节**，不含 JWS header、base64url 和签名。256 字节保留为单独拒绝负例，不能计入有效管理操作成功吞吐。线程数 1/8/32、每窗操作数/时长、至少 5 对、原 1%/2% 精度及其他矩阵要求均保持不变。

`license_payload_fixture.py` 调用真实 `tools/license-issuer/license_issuer.py` 的 canonical 序列化、schema 校验、临时 Ed25519 签发与验证，再编译一个小型离线 probe，调用显式提供的 P1 `LicenseVerifier` 和 `LicenseSnapshot` 字节码。它不连接数据库，不修改 FE 信任配置，不导入证书，不做计时或性能通过判定。私钥只存在临时目录并在退出时删除；输出保留测试公钥、JSON/JWS、摘要和报告，拒绝覆盖已有输出目录。

可重复执行命令（从仓库根目录运行）：

```bash
python3 -B tools/license-checks/license_payload_fixture.py \
  --java-home .build-records/license-p1-jdk17.0.4-20260924/jdk-17.0.4+8 \
  --fe-lib output/massdb-sql-2.0.5-rc02-bin-arm64/fe/lib \
  --classes-from fe/fe-core/target/classes \
  --output .build-records/license-p0-p1-20260924/lp023-payload-fixture
python3 -B -m unittest discover -s tools/license-checks -p test_license_payload_fixture.py -v
python3 -B tools/license-checks/check_p0_contract.py --self-test \
  --output .build-records/license-p0-p1-20260924/p0-contract-lp023.json
```

`--classes-from` 也接受包含 P1 代码的 FE JAR。原版 A 包不含这些类，不能作为 P1 fixture oracle。报告记录所用生产类与 Jackson 依赖摘要；这与最终发行组合认证、完整 LP023 微基准及端到端性能证据不同。

## 最小尺寸的可执行证明

必需的 14 个 claim 名固定。`schema_minimum()` 给所有可变文本赋一个 ASCII 字符，deployment 使用 36 字节 canonical UUID，product 为 `MassDB SQL`；整数取合法一位数，features 为空，limits 保留两个正整数。JSON 字段顺序不影响总字节数，省去空白后每个值已达到 schema 所需最短编码。`minimum_proof()` 分别计算每项 key/冒号/value 长度以及外层括号/逗号，再与真实 canonical 序列化核对。

| 输入 | decoded JSON | compact JWS（kid=`a`） | 用途 |
|---|---:|---:|---|
| schema 最小 | 295 B | 554 B | 已过期且无 DATA_QUERY，仅证明下界 |
| 加 DATA_QUERY，未来 10 位 expires_at | 316 B | 582 B | 固定时刻查询状态 VALID 的最小示例 |
| 三个时间都使用 10 位 epoch | 334 B | 606 B | 常规时间表示的尺寸示例 |
| VALID 小档 | 512 B | 843 B | customer_id 为 197 个 ASCII 字符 |
| VALID 中档 | 4096 B | 5622 B | 30 个唯一 feature，其中包含 DATA_QUERY |
| VALID 大档 | 16384 B | 22006 B | 124 个唯一 feature，其中包含 DATA_QUERY |

`license_id` 是非空有界文本，不强制 UUID；`deployment_id` 才必须是 canonical UUID。上述 compact 长度依赖最短测试 kid，正式夹具须记录自己的实际值，不能混用 decoded 和 compact 长度。

正例固定测试时刻为 epoch `1800000000`，not_before/issued_at 为 0，expires_at 为 `2000000000`，1 FE/1 BE，测试 deployment 为全零 UUID。大档通过合法的唯一 feature 标识符补齐，每项最多 128 字符、总数不超过 128；不添加未知 claim，也不通过空白填充。正式测试应先绑定本次实际 deployment、时间、信任公钥及节点数，再按最终 canonical 字节数重建相同尺寸。若测试真正的管理提交，还须为每次提交处理 license_id/sequence、续期和幂等条件，不能用反复提交同一证书的幂等命中替代实际验签成本。

## 256 字节负例

从 schema 最小对象中只删除 `deployment_id`，用合法 customer_id 文本精确补到 256 字节。该输入是可解析、canonical JSON，其余字段满足 schema；补回 deployment 后校验通过。真实生产发行函数必须拒绝且不产出证书。随后仅测试夹具以临时私钥对这个非法 payload 签名，使用 OpenSSL 独立确认签名正确，再要求生产 Java 返回 **INVALID_CLAIMS**，不能把签名损坏、未知 key 或非法 JSON 当作这个负例通过。

负例按原线程/独立窗口要求单独报告拒绝数、延迟及 CPU，禁止计入 VALID 管理吞吐。离线 `FIXTURE_PASS` 仅表示输入及预期错误已核对，所有性能结果保持未运行。

## 2026-09-24 离线验证记录

上述命令已在 Temurin 17.0.4+8 执行：[夹具报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-payload-fixture/report.json)记录 295 B 对象为 EXPIRED，316/512/4096/16384 B 对象由生产 Java 判为 VALID，256 B 的独立 OpenSSL 验签正确且生产 Java 精确拒绝 INVALID_CLAIMS。生产发行工具拒绝签发该负例。临时私钥已删除。

[6/6 单元检查](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-payload-unit.log)覆盖精确 canonical 字节数、完整字段、合法 feature 上限、最小值边界及正负维度分离；[P0 契约及变异检查](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/p0-contract-lp023.json)全部通过。[校验摘要](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp023-payload-validation.json)绑定源码和契约 hash。以上均不将 LP023 的 `not_run` 改为性能通过。
