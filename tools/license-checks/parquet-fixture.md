<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP008 本地 Parquet 输入夹具

`parquet_fixture.py` 和 `LicenseParquetFixture.java` 准备性能清单要求的 **100 个 Parquet 文件，每个 10,000 行**。
只写入本 checkout 的 `.build-records` 新目录，使用已有发行包中的 JAR，不下载依赖、不启动 S3、也不请求 SQL/HTTP。
这完成数据准备这一前提；LP008 的状态保持 `not_run`。真实 S3/TVF 结构推断、SELECT、INSERT SELECT、请求计数和
许可副作用边界仍须另行证明，文件生成或本地读取不能替代发行可达或性能通过记录。

## 冻结数据模型

canonical LP008 未单列列定义，工具明确沿用 `datasets.bench_small` 的确定性模型，读取并归档原清单及其 SHA-256。
全局 id 从 0 至 999,999 连续分成 `part-00000.parquet` 至 `part-00099.parquet`；文件内按 id 升序：

| 列 | Parquet 类型 | 值 |
| --- | --- | --- |
| id | required INT64 | file_index × 10000 + row_index |
| grp | required INT32 | id % 1024 |
| v | required INT64 | id % 100000 |
| payload | required BINARY (STRING) | 十进制 id 的 ASCII 文本取 MD5，32 个小写十六进制字符 |

seed=20260922 标识同一 canonical 数据集；此模型没有随机数步骤。MD5 仅作为既有测试数据表达式，不用于证书签名。
格式固定为 UNCOMPRESSED、禁用字典、8 MiB row group、64 KiB page，避免本地压缩 native 库影响可重现性。
工具验证完整文件数、每列类型/必填/UTF-8 注解、footer 与实际读取行数、每列 min/max/sum、payload 长度及所有行的有序摘要。

写入使用发行包 `AvroParquetWriter<GenericRecord>`。**另一 JVM** 使用 `ParquetFileReader`、`ColumnIO`、
`GroupRecordConverter` 全量读取，未复用 Avro 的反序列化路径或写入器的预期数据。
Python 独立模型重算每个文件的所有 payload 和标准行文本，校验 SHA-256：

- 行摘要输入为每行 `id\tgrp\tv\tpayload\n` 的 UTF-8 字节，按实际文件行序连接。
- payload 摘要输入为每行 `payload\n` 的 UTF-8 字节，按实际文件行序连接。
- 独立的 min/max/sum/count 与两个完整摘要须同时匹配，不能只看 footer。

随后独立重写首个完整文件，检查字节级 SHA-256 一致；另验证截断文件被 reader 拒绝，以及更改 payload 摘要被模型拒绝。
负例和复现副本放在独立子目录，后续 S3 上传只能取 `parquet/` 中的 100 个原文件。

## 执行与证据

必须在基线计时窗口之外执行。Python、javac、写入器和 reader 都绑定同一个明确 CPU；Java 堆上限 512 MiB。
编译限时 60 秒、全量写入和全读各 240 秒、首文件复现 60 秒、截断负例 30 秒；超时/不匹配均失败，不覆盖已有证据。
下面命令使用已准备的真实 JDK 17.0.4 和原版发行依赖，网络 namespace 额外确保断网：

```bash
unshare --net --fork --kill-child python3 tools/license-checks/parquet_fixture.py \
  --java-home .build-records/license-p1-jdk17.0.4-20260924/jdk-17.0.4+8 \
  --fe-lib output/massdb-sql-2.0.5-rc02-bin-arm64/fe/lib \
  --output .build-records/license-p0-p1-20260924/lp008-parquet-new \
  --cpu 0
```

输出 `input-manifest.json` 记录原清单/生成器摘要、所有实际 classpath JAR 的路径/大小/SHA-256、模型及参数；
`commands.json` 记录每个本地步骤的命令、限时、耗时和退出码；各步日志分别保存。
`writer-report.json` / `reader-report.json` 记录实际 JDK、库加载来源及逐文件读取指标。
只有全部校验成功才产生 `fixture-report.json`，其中逐文件记录字节数、文件 SHA-256 和独立期望值。
运行报告同时保留 `external_read_reachability_proven=false` 和 `performance_pass_proven=false`。

## 2026-09-24 实际完成记录

在计时 pilot 完全结束后，使用上述断网调用、CPU0、Eclipse Temurin 17.0.4+8，在
`.build-records/license-p0-p1-20260924/lp008-parquet-v3` 完成整个流程，退出码 0。
实际显式 classpath 有 34 个已有发行 JAR；核心版本为 Parquet 1.17.0、Avro 1.12.1、Hadoop 3.4.2、
Jackson 2.16.0。初次最小 classpath 遗漏的 commons-collections4/JTS 已补齐；原失败日志保留在
`lp008-parquet` 和 `lp008-parquet-v2`，没有覆盖为成功记录，也没有下载额外库。

| 项目 | 实际结果 |
| --- | --- |
| 文件 / 每文件 / 合计行 | 100 / 10,000 / 1,000,000 |
| Parquet 数据总字节数 | 56,184,742 |
| ID 范围 | 0–999,999 |
| SUM(id) / SUM(grp) / SUM(v) | 499,999,500,000 / 511,370,976 / 49,999,500,000 |
| 独立全读 | 100/100 文件的全部模型指标及有序行/payload SHA-256 一致 |
| 首文件重复生成 | 文件字节 SHA-256 一致 |
| 负例 | 截断物理文件被 reader 拒绝；变更 payload 摘要被模型拒绝 |
| 本地总耗时 | 5.077 秒（包含编译、生成、全读、模型比较和负例；不属于压测指标） |

[总报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp008-parquet-v3/fixture-report.json)
SHA-256 为 `516956235e80be6461839ff9d2b9bd5153d2c0cc6f9f6eb3d27294fdd89cd927`。
逐文件输出摘要、全部输入及 JAR 摘要、实际库加载来源分别位于同目录的总报告、`input-manifest.json` 和
`reader-report.json`。生成器/reader 源码与编译后的 class 摘要也已记录。
Python 语法编译、仓库源文件头检查（54 个商业文件）及 `git diff --check` 通过。
此次没有启动 S3 或请求 FE/BE；LP008 的外部读取可达性与完整性能门槛仍未执行。
