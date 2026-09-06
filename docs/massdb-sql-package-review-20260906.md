# MassDB SQL 安装包评审与修正记录

复核日期：2026-09-06。对象为 12:57 的 Linux ARM64 验收包，归档 SHA-256：
`3914038c8a79f005dc76f0a2d31f17f2f54012c216fc95d3883b5c71c65724a5`。
这是工程与许可证据复核，未代替权利人确认或逐项许可兼容性审阅。

输出整理后，下文 `output/legal/` 等历史证据按原目录名保存在
`.build-records/20260906-audit.tar.gz`；旧发行归档已清理，先前迁至
`.local-installations/` 的两套旧安装及 FE 数据也已按维护者要求删除。
当前程序和归档位置见[安装包材料规则](massdb-sql-distribution-materials.md)。

## 评审结论

| 项目 | 判断与处理 |
| --- | --- |
| A02 新代码许可未定 | 正确。11 个文件仍待决定。选择实际许可后还须迁移授权登记、同步 License Eyes/Checkstyle 和 `ui/package.json` 元数据，不能仅清空 `pending`。 |
| A01/A03/A05/A08 主体、年份、账号、素材 | 正确。中英文公司名已记录，独立编写确认不等于公司权属证明；本轮不自行填写证明或启用公司署名。 |
| 未提交工作区不能作为正式来源 | 作为发布可追溯性要求采纳。包内已声明 `sourceModified: true`，不是完全没有披露；原生版本串单独不足以重建源码。新增整个检出范围的干净来源检查，提交字符串不能替代干净状态。 |
| 产品与上游版本数字相同 | 是识别风险，不是当然违反 Apache 许可。保留独立编号，新增随包发布说明及 Java SBOM 的独立上游字段；不以 MassDB 编号给 Apache Doris 匹配 CPE/CVE。 |
| Jindo/FoundationDB/CDC 未充分登记 | 正确。补版本、来源、许可和原文；FoundationDB 实际是默认 7.1.57 与附加 7.3.69 两个客户端。Jindo 二进制授权适用范围仍待核实。 |
| 无 gsasl/idn/hdfs3 符号即证明没有纳入 | 原推论证据不足；进一步重放链接并证明产物哈希一致后，确认当前两个二进制没有抽取这些库的对象。条件依赖清单保留，更换产物后重验。 |
| 旧归档校验失败 | 对当前源码的声明一致性检查确实失败，原因是 `MODIFICATIONS.txt` 已变更，不能等同归档损坏。旧归档及校验文件已隔离，旧解压目录和数据保留。 |
| Java 清单和逐项审阅未完成 | 正确。现已补实际 JAR/嵌套 JAR 清单、原文提取、SBOM 和审阅队列；逐项审阅仍未完成。 |
| HTTP 200 JSON 被当许可正文 | 正确。阅读器现在要求 `text/plain`，保留 HTML/空正文防护，加入 JSON/HTML 回退及恢复测试。 |
| MS 未复制声明 | 正确。MS 现调用共用复制函数；各组件另外带 `NOTICE-dist.txt`、版本说明及限定范围的原生证据。镜像仍须独立验收。 |
| `.claude/` 未忽略 | 正确。新增根目录忽略规则；仅用虚拟路径验证规则，未扫描或改动目录内容。 |

## 包内实物与来源

| 实物 | 实际版本与取证 |
| --- | --- |
| `ms/lib/libfdb_c.so` | 7.1.57；CMake 默认配置、二进制版本字符串及与本地版本化输入的 SHA-256 一致。 |
| `ms/lib/fdb/7.3.69/libfdb_c.so` | 7.3.69；目录、版本字符串和输入哈希对应。 |
| FE/BE 的两个 Jindo JAR | 6.8.2；由 `thirdparty/vars.sh` 中 Doris 第三方发行下载，内嵌 POM 没有 Jindo 自身许可声明。 |
| `be/lib/cdc_client/cdc-client.jar` | 185 个嵌套 JAR，其中 Flink CDC 3.5.0、Debezium 六个 1.9.8.Final 模块；不能用外层 Apache 头替代所有依赖的条款。 |

FoundationDB 两个版本的原始 LICENSE、ACKNOWLEDGEMENTS 与 Debezium 的 LICENSE、
COPYRIGHT 已保存到 `dist/licenses/`，来源与哈希见
[`dist/binary-license-evidence.json`](../dist/binary-license-evidence.json)。
上游依据：[FoundationDB 7.1.57](https://github.com/apple/foundationdb/tree/7.1.57)、
[FoundationDB 7.3.69](https://github.com/apple/foundationdb/tree/7.3.69)、
[Debezium 1.9.8.Final](https://github.com/debezium/debezium/tree/v1.9.8.Final)。

Jindo 官方仓库的 [LICENSE](https://github.com/aliyun/alibabacloud-jindodata/blob/200d9bc4356404ce304818411e247edf0f49d64a/LICENSE)
是 Apache 2.0；这条证据本身尚未建立其对所分发 6.8.2 二进制及内嵌原生库的覆盖关系。
不能因为 JAR 没有自带许可便断言没有授权，也不能用 Jackson 的许可推定 Jindo 授权。
二进制哈希见 [`dist/reviewed-binary-artifacts.json`](../dist/reviewed-binary-artifacts.json)。

## 原生链接证据与适用范围

`ninja -t commands -s` 取得最终链接指令；在隔离目录仅更换输出位置并添加
LLD `--why-extract`，随后执行原有 debug/strip/debuglink 步骤。结果：

| 产物 | SHA-256 | 结论 |
| --- | --- | --- |
| BE | `e5dc4a0f9f4374714bf14c719e85d90106861ecf80bba78a1aaf31aae1c22669` | 与随包二进制一致，三个归档的对象抽取数均为 0。 |
| Cloud | `7679b0e3aa38f9b42498250f82820844d5482b30bbf340d598763bf2ecfcbd80` | 与随包二进制一致，三个归档的对象抽取数均为 0。 |

链接输入仍包含 gsasl/idn，但链接器没有从中抽取对象；HDFS 使用 Hadoop JNI 库。
因此当前两个哈希不因 gsasl/idn/hdfs3 产生原先假定的源码/重链接交付要求。
这不覆盖 Java、独立共享库、内嵌原生库或其他平台。
[`dist/native-link-evidence.json`](../dist/native-link-evidence.json) 保存范围和报告哈希；
完整指令、抽取报告、对比结果在 `output/legal/package-review-20260906/relink-{be,cloud}/`。

## Java 清单与未完成审阅

统计口径：FE `lib/` 598 个 JAR，FE 全目录 603 个；BE 153 个，MS 140 个，
Broker/其他 extensions 218 个，合计 1114 个外层文件。含嵌套共 1303 个出现位置，
按内容哈希去重 927 个构件，提取 613 份不同许可/声明文本。

567 个构件存在“未解析到 POM 许可”或“缺内嵌许可文本”等证据缺口。
这不是 567 个组件违规，也不代表其余 360 个已合规；927 项全部保留 `unreviewed`。
包含关系不是完整运行时依赖图；无元数据的 shaded 代码、源码复制、原生库和例外条款
仍需人工/专项工具核查，POM 继承声明也不能替代许可证原文。

```bash
python3 build-support/prepare-product-notices.py \
  --inventory-java-package output/release-20260906-ui-refresh/massdb-sql-2.0.5-rc01-bin-arm64 \
  --destination output/legal/java-review-new
```

只读实际包和本地 Maven 父 POM 缓存，不联网；目标目录须不存在且在包外。
产出 `java-inventory.json`、`java-sbom.cdx.json`、`review-queue.csv` 及 `notices/`。
本次结果在 `output/legal/package-review-20260906/java-final/`。

## 归档与验证边界

11:34 旧包移至 `output/archived-releases/20260906-1134/`，未改写其内容或校验文件。
12:57 包的实物证据在代码修正前取得；本轮修改不会自动进入它的 FE JAR。
新的源码一致性校验会合理地拒绝沿用旧声明，更新安装包需要重新构建。
本轮不代替 A02 许可选择、主体/权属/素材凭证、全部 Java 审阅或实际镜像验收。
