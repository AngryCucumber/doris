# MassDB SQL 安装包声明与构建材料

## 公司声明

2026-09-06 按维护者“新增公司声明”的指示，采用前文草案的 2026 年及有限范围署名：

```text
Copyright (c) 2026 厦门市美亚柏科信息安全研究所有限公司
English name: Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
```

完整段落位于根 `NOTICE.txt`，仅覆盖公司拥有权利的修改和新增内容，保留原有
Apache Doris 及第三方归属。`dist/product-provenance.json` 控制年份、中英文名称
和 FE 展示；本次启用署名不代表选择新增文件的许可证或完成权属证据核验。

独立组件构建复制根 NOTICE；完整组包将共用归属集中到安装包根目录。FE 页面读取的
`legal/NOTICE.txt` 由根 NOTICE 与分发声明生成，登录前后页脚按界面语言署名。
修改元数据后，在仓库根目录执行：

```bash
python3 build-support/prepare-product-notices.py --company-notice
# 将输出用于更新 NOTICE.txt 中的公司段落，保留其他归属内容。
python3 build-support/prepare-product-notices.py --check-company-notice
```

## 哪些材料需要随包

Apache 2.0 要求交付许可证、保留适用归属，并在修改文件中作显著修改说明，
没有指定以下构建报告的文件名。NOTICE 可以追加公司归属，但不能借此改变
许可证。[Apache 2.0 第 4 条](https://www.apache.org/licenses/LICENSE-2.0)

| 文件或材料 | 客户安装包的处理 |
| --- | --- |
| `LICENSE.txt`、适用 `NOTICE`、许可正文 | 保留。完整包根目录为 LICENSE/NOTICE，详细组件许可集中于 `fe/legal/`；去除 BE/MS/Broker 根目录的重复副本 |
| `BUILD-INFO.json`、`BUILD-STATUS.md` | 不随包。版本、来源、安装方法和验收状态合并到 `README.txt`；构建参数与过程记录留内部 |
| `MODIFICATIONS.md` | 详细开发历史不随包；README 保留产品修改摘要，原文件中的修改声明继续保留。源码头中的该文件名指向源码仓库历史，不是安装依赖；UI 已不再复制此文档 |
| `NATIVE-LINK-EVIDENCE.json`、原始链接日志 | 不随包。已调整许可证目录的引用，避免悬空路径和套用历史二进制结论；当前二进制哈希与外部证据仍须核验 |
| `PRODUCT-PROVENANCE.json`、SBOM、逐文件 `SHA256SUMS` | 不随包，关联安装包哈希保存于内部审阅目录；压缩包旁另提供 `.sha256`。若合同另有 SBOM 交付要求，再单独提供 |
| `BUILD-SOURCE.patch`、`BUILD-SOURCE-HASHES.json`、审阅队列、历史证据 | 不随包，保留内部档案。属于组件许可证要求交付的源码补丁仍纳入对应源码材料，不能一概删除 |
| `be/lib/debug_info/`、`ms/lib/debug_info/` | 不随包，单独保存调试符号；运行二进制和动态库不重新 strip，不改变其哈希 |
| UI 的 `manifest.json`、`components.json`、`sbom.cdx.json` | 仅保留于构建产物和内部档案；最终 FE 目录及 FE JAR 均去除，使用外部构建清单验证保留的页面资源 |
| 对应源码、适用的重链接材料及获取说明 | 按实际组件许可证和选定履行方式交付。FE 的 MariaDB 源码与 `FE-SOURCE-ACCESS.txt` 属于此类，不能当作构建日志清理 |

## 落实边界

维护者进一步要求“能不打包进安装包就不打进安装包”。本轮据此实施以上规则，
完整包根目录只保留以下内容：

```text
README.txt   LICENSE.txt   NOTICE.txt
fe/          be/           ms/          extensions/          tools/
```

共享材料集中于 `fe/legal/`，便于 FE 页面阅读及离线查阅。正常 `build.sh` 的组件
输出仍保留独立分发声明；如果从完整包拆分 BE/MS/Broker 对外交付，须同时携带
适用的共享声明和材料，不能只复制运行目录后再分发。

`prepare-product-notices.py --assemble-package` 只创建新目录，不原地清理输入或现有
安装，拒绝打包非空运行日志、存储与 FE 元数据目录。内部档案通过压缩包哈希、
逐文件哈希及源差异关联交付物；不会因移出报告而把验收构建改标为正式发行。

## 构建输出保留策略

`output/` 只保留最新程序目录、tar 和 `.sha256`，不存放 `build-release-*`、
页面截图或独立审阅目录。临时组包在忽略目录 `.build-records/` 中完成；成功后
仅把程序和压缩包移入 `output/`，审阅记录/调试符号压缩为包外的 `audit.tar.gz`
并保留校验文件，删除临时组件和未压缩记录。失败时保留现场，后续核验后清理。
目标路径已存在时脚本拒绝覆盖，避免把已安装程序当作构建缓存删除。

历史 tar、未使用的解压副本和失败构建经核验后清理，不按每次 UI 调整保留一套
完整安装包。维护者已明确授权：本检出目录内的安装均用于测试，每次重新编译
都不保留旧元数据、存储和日志。先停止相关测试服务，再于新包核验通过后删除
旧安装及压缩包，不另建历史备份或 `.local-installations/`，新包使用空数据目录。
此约定不适用于本检出目录之外的安装。通用发布脚本仍拒绝覆盖已有目标路径，
由维护流程按上述授权先完成清理。

2026-09-06 的内部材料合并为 `.build-records/20260906-audit.tar.gz`，保留原记录
目录名；例如最新符号位于归档内 `build-release-20260906-minimal/audit/symbols/`。
原 `output/legal/` 是内部核验材料，现随此归档保存；安装程序内的 `fe/legal/`
仍须交付，不在清理范围内。路径迁移与校验结果见 `.build-records/layout-20260906.json`。

维护者随后明确要求不再保留 `.local-installations/`，两套旧安装及其 FE 数据已
删除，删除记录补充到上述 JSON；该目录不再作为需要恢复或继续保留的安装副本。
