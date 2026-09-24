<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# LP009 四 BE 实际执行前提

`fanout_fixture.py` 默认只生成计划，显式 `--mode probe` 才向本 checkout 已核验的
3 FE / 4 BE 私有测试集群发送请求。不启动或停止数据库服务，不改变 BE 代码或协议。
这是同机、共享 CPU 的功能前提；`case_status=not_run` 和 `performance_pass_proven=false`
保留完整 LP009 的性能矩阵、许可状态和精度要求。

每个 64/256/1024 分桶变体都实际写入 **10,000,000 行**，沿用冻结清单的 UNIQUE KEY、
replication_num=1、merge-on-write、row-column 和 light-schema-change 属性。
三个变体顺序创建、核验、删除；每个表使用独立随机所有权名称，已有同名表拒绝操作。
数据库可保留，但临时表必须通过 DROP 后 SHOW 确认删除。

## 数据和执行核对

- 全表检查行数、ID 范围、各数值列总和以及每行 `grp=id%1024`、`v=id%100000`、
  `payload=MD5(decimal id)`；空 payload 或域外 ID 均失败。
- 以互不重叠、首尾连续的 20 个 ID 区间逐一核对精确 `COUNT(DISTINCT id)`、行数、
  min/max、各字段总和与内容。每段 500,000 行，全部区间覆盖 0–9,999,999。
  全表核对负责额外/域外行，分段核对负责全部 ID 的唯一性和完整性。这不是采样。
- 通过独立 Python 整数模型计算所有 1024 组的 SUM(v) 和 COUNT(*)。
  对完整千万行执行 GROUP BY，比较全部无序结果；不把分段核对当作被测聚合查询。
- 通过原版 SHOW TABLETS 核对实际 tablet 数及 BE 放置位置，再从同一 SQL 会话取得
  聚合查询的 LAST_QUERY_ID，调用原版 `/api/profile/text`，归档原始 profile。
- profile 必须对应本次查询、完成且没有缓存命中。实际实例摘要须包含四个已拥有的 BE，
  详细 profile 必须具有 FINALIZED 的 OLAP scan task、精确 ScanRows、完整 TabletIds。
  四个 BE 均需扫描正行数，tablet 并集必须恰好覆盖该表，且符合实际元数据放置。
  注册节点、EXPLAIN、只调度未执行的实例、合并 profile 或近似扫描计数均不能替代这些证据。

运行时任务身份按原版 profile 的 fragment ordinal / BE / pipeline / task index 记录，
不伪造 UUID。保留原 SQL 结果、错误码/SQLState、DDL、JDBC 依赖摘要及完整分布证据。

## 限额和失败处理

测试 session 的 SQL/query cache 和 short-circuit 关闭，exec_mem_limit 显式固定 512 MiB。
原始 v1 在完整 COUNT(DISTINCT id) 时触发此限额，失败记录和成功 DROP 的回执保留在
`.build-records/license-p0-p1-20260924/lp009-fanout-v1/`。
之后的版本将独立内容 oracle 分段，没有减少数据、修改产品或扩大 BE 内存限制。

SQL 单次至多 600 秒，整个工作窗口至多 3600 秒；每次 SQL 先复核所有节点的
PID/start_ticks/netns/exe/cwd/命令身份。子进程超时或取消由 Python subprocess.run 回收，
SQL 失败保留原始结构化回执。SIGINT/SIGTERM/SIGHUP 触发 finally，重复信号不打断有界清理。
清理阶段 DROP 与 SHOW 各自最多 60 秒 SQL 加 15 秒进程等待。
进程退出并不证明服务端瞬时取消，DROP/后续检查仍须成功；失败不得标记完成。

## 使用

先通过 [多节点工具](/data/project/massdb-sql/tools/license-checks/multinode-baseline-cluster.md)
取得实际 `MEMBERSHIP_READY`。生成新计划会冻结当前工具、Java helper、集群计划、
性能清单、全部 SQL 和 Python 期望值；旧计划不可重复 probe：

```bash
python3 -B tools/license-checks/fanout_fixture.py \
  --cluster-plan .build-records/<multinode>/plan.json \
  --output .build-records/<new-fanout>
```

实际 probe 必须进入该集群 **fe1 keeper** 的私有 namespace：

```bash
nsenter -t <actual-fe1-keeper-pid> -n taskset -c 0-4 \
  python3 -B tools/license-checks/fanout_fixture.py --mode probe \
  --plan .build-records/<new-fanout>/plan.json
```

纯离线验证不启动服务、Java 或网络连接：

```bash
python3 -B -m unittest discover -s tools/license-checks -p test_fanout_fixture.py -v
```

当前 21 项检查包含 Python 整数模型与独立枚举比对、分段完整覆盖、全部分桶配置、
错误/缺失/重复分组及 tablet、缓存/不完整/错误节点/未完成 profile 拒绝、所有权与取消清理。
其中 profile 是明确的合成格式 fixture，不能充当真实四 BE 运行证据。

2026-09-24，精确 Temurin 17.0.4+8 和未修改原版包已完成三变体实际 probe：
每档 10,000,000 行、20 个完整 ID 区间、1024 组结果通过，四 BE 各扫描 2,500,000 行，
每 BE 分别拥有 16/64/256 个 tablet、2 个实际 scan task，每档共 16 个实例。
独立复核了 89 份原始 SQL 回执、全部 1000 万 ID 的 Python 枚举和三个真实 profile，
确认三张临时表均已删除。证据见
[实际完成审计](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/lp009-fanout-v2/completion-audit.json)。
测试客户端退出 0，随后七节点服务也全部停止并核验。此记录仍不代表完整 LP009 性能通过。
