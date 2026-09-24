<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP012 Stream Load 确定性输入与可达验证

`stream_load_fixture.py` 提供计时外输入生成及原版发行的导入正确性验证；`LicenseFixtureSql.java`
使用发行包中的 MariaDB/Jackson 和 JDK 17 执行 SQL oracle。工具不会修改 FE/BE 源码、启动服务、清空表或改宿主环境。
HTTP 必须实际经过 FE 重定向到同一私有 namespace 的 BE；目标只允许 `license_perf.ingest_fixture_rows[_suffix]`。
正式表不应使用该前缀。

固定数据为 10,000,000 行，seed 为 `20260922`，每条记录精确 128 字节，包含三个逗号及一个 LF，无表头、引号或 BOM。
`id=0..9999999`、`grp=id%1024`、`v=id%100000`。`payload` 的前 32 字节为十六进制 `MD5(decimal id)`；
之后重复十六进制 `SHA256(decimal seed)`，补足该行的 128 字节。全部字符是 UTF-8 的 ASCII 子集。
MD5 在这里仅生成确定性测试字符串，不用于认证。

生成默认完整输入；`--rows 10000` 可生成可达性小样，报告仍保留完整目标行数并明确区分：

```bash
python3 tools/license-checks/stream_load_fixture.py generate \
    --output .build-records/license-p0-p1-20260924/lp012-input-10000000.csv
```

输出 CSV 和相邻 `.csv.json`。JSON 保存实际字节数、输入 SHA-256、生成器源码 SHA-256、生成耗时及独立算术期望值。
已有文件拒绝覆盖；生成耗时不计入任何上传窗口。

以下命令中的 `<supervisor-pid>` 必须是 `isolated_baseline_cluster.py` 创建、当前仍存活的私有 namespace 监督进程。
工具核对 namespace、checkout 安装路径及两个实际进程；在宿主网络或已有外部安装执行时拒绝。

```bash
nsenter -t <supervisor-pid> -n -- python3 tools/license-checks/stream_load_fixture.py load \
    --input .build-records/license-p0-p1-20260924/lp012-input-10000.csv \
    --output .build-records/license-p0-p1-20260924/lp012-probe-new \
    --cluster-record .build-records/license-p0-p1-20260924/baseline-cluster/cluster.json \
    --table ingest_fixture_rows --batch-rows 10000
```

默认身份为该全新隔离安装的 `root`。密码仅通过 `MASSDB_BASELINE_PASSWORD` 环境传递；其他受控账号使用 `--user`
和 `--password-env`。凭据不写入命令参数、配置或报告。该版 FE 在重定向 Location 中包含 userinfo，工具仅在内存核对，
归档前移除其内容；重发到经过校验的 BE 地址时始终使用原认证头。

工具创建独立 `DUPLICATE KEY(id)` 目标，已有目标必须为空，不会自动 DROP/TRUNCATE。
选择重复键表是为了让 label 重放若错误再次写入能体现在行数上，避免唯一键覆盖掩盖重复导入。
批次允许 1,000 或 10,000 行；label 由唯一运行前缀及 `w00_c00_bNNNNNN` 组成，表示本次可达性窗口、单客户端和批次。
正式并发基线必须自行分配真实窗口/客户端标签，不把这里的顺序上传当成并发压测。

每批必须得到 FE HTTP 307、BE HTTP 200、业务 `Status=Success`、正确 label、正 TxnId、精确总行数和加载行数、
零过滤/零未选择行。`Publish Timeout`、HTTP 200 内业务失败、网络异常均不会记为成功。
所有成功批次后，SQL 同时验证 COUNT、COUNT DISTINCT、ID 范围、三个数字字段总和以及逐行表达式和完整 payload。
然后重发首批同一 label，要求 `Label Already Exists / FINISHED`，再运行完全相同的可见性验证，证明未增加数据。
报告保存实际建表结构、SQL 原始结果、输入摘要、HTTP 响应和包含重定向的耗时。

`FIXTURE_PASS` 只说明对应数据量的输入、端点、提交与重复 label 正确性已经实测。
小批通过不等于完整 1000 万行已装载，更不等于 LP012 的 1/8/32 并发、固定字节到达、180 秒预热、600 秒窗口、
五对 A/A/A/B、缺证/过期合法写入或无性能回退通过。

## 完整输入实际验证（2026-09-24）

[原始报告](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp012-full-be4g-v1/report.json)使用原版4GiB BE和Temurin17.0.4+8，实际顺序装载1,000个10,000行批次，共10,000,000行/1,280,000,000字节。每次FE307→BE200、零过滤/零未选择，label与TxnId均各1,000个不同值。

两次完整SQL核对均得到10,000,000个唯一ID、范围0–9,999,999、字段算术汇总正确、逐行完整payload错误数0；首批label重发返回FINISHED，重复前后全量结果一致。独立[完成审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp012-full-be4g-v1/completion-audit.json)逐块重新计算完整输入摘要并重读全部1,000份BE响应正文，确认没有用汇总标志替代原始回执。

所有本次客户端退出后，仅将该次独立 `ingest_fixture_rows_full_v1` 表删除并以SHOW确认不存在；[清理回执](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp012-full-be4g-v1-cleanup/report.json)单独保存，原始报告未覆盖。此记录补齐完整数据量的功能前提，仍不代替1/8/32并发、持续负载、许可状态或正式精度。
