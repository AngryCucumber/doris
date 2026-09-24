<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# 原版 3 FE / 4 BE 隔离成员前提

`multinode_baseline_cluster.py` 准备 LP009 所需的原版 3 个 FE 投票成员、4 个 BE。
默认只生成计划和独立配置；必须显式 `--mode launch --plan ...` 才启动。
`MEMBERSHIP_READY` 只表示本工具已核对加入、选主、心跳与日志回放，不代表查询实际使用了 4 个 BE，
更不代表 LP009、许可证拦截、故障切换或多机性能通过。
计划和报告中的 `LP009_complete`、`release_performance_pass` 始终为 false。

## 为什么不能同一地址只改 FE 端口

本分支原版有明确约束：

- `Env.java:1490` 的 `/role`、`:2116` 的 `/version`、`:2136` 的 `/info` 使用 helper 的 host 和
  **本机** `Config.http_port`，并不从 `--helper host:edit_log_port` 获得对方 HTTP 端口。
- `HeartbeatMgr.java:408` 只比较 host 判断是否给自己心跳；`:427` 访问远端 FE 时使用本机 `Config.rpc_port`。
  同一 host、不同端口的 FE 不能以 Alive 标记证明远端真实心跳。
- `ThriftServer.java:108/128/153` 固定监听 `0.0.0.0`；`HttpServer.start` 同样设置全地址监听。
  只给同一 netns 增加多个 IP，仍不能让原版多个 FE 共用这些端口。

因此工具使用一个新建的外层 private network namespace，在其中建立 `lpbr0` 和七组 veth，
每个 FE/BE 再拥有单独的子 netns。FE 地址为 `10.254.23.11`–`.13`，BE 为 `.14`–`.17`；
各 FE 使用相同原协议端口，各 BE 也使用相同端口。`priority_networks` 精确到本节点 `/32`。
这些地址仅在本次隔离网络中存在；外层 namespace 没有默认路由、没有宿主接口、没有外部 uplink，
节点也没有默认路由。SQL helper 从相应节点 netns 内连接 `127.0.0.1:29030`。
不存在代理、协议重写、FE/BE 产品代码更改或新增内部身份协议。

| 节点类型 | 端口 |
| --- | --- |
| FE | HTTP 28030、SQL 29030、RPC 29020、BDB edit log 29010、Flight 28070 |
| BE | heartbeat 29050、BE 29060、HTTP 28040、brpc 28060、Flight 28050 |

所有启动脚本直接从选定的原版发行目录复制，运行库链接到该原版目录。
原包文件、JDK java/javac/modules、工具/SQL helper、每节点生成的配置和脚本均保存 SHA-256；
启动前及成员 oracle 完成后复核。原包中的目录符号链接暂时拒绝，避免遗漏其实际依赖或产生循环。

## 资源必须明确冻结

工具不提供隐式的七节点资源默认值。先准备 JSON，为 `fe1/fe2/fe3` 分别设置
`cpus` 和 `heap_mib`，为 `be1`–`be4` 分别设置 `cpus`、`memory_mib` 和 `jvm_heap_mib`；
此外显式指定 `reserve_mib`（至少 2048）和 `allow_existing_host_limits`。
下面仅说明格式，数值为占位说明，必须替换后才能作为 JSON 输入：

```text
{
  "nodes": {
    "fe1": {"cpus": [已评估的CPU编号], "heap_mib": 已评估整数},
    "fe2": {"cpus": [已评估的CPU编号], "heap_mib": 已评估整数},
    "fe3": {"cpus": [已评估的CPU编号], "heap_mib": 已评估整数},
    "be1": {"cpus": [已评估的CPU编号], "memory_mib": 已评估整数, "jvm_heap_mib": 已评估整数},
    "be2": {"cpus": [已评估的CPU编号], "memory_mib": 已评估整数, "jvm_heap_mib": 已评估整数},
    "be3": {"cpus": [已评估的CPU编号], "memory_mib": 已评估整数, "jvm_heap_mib": 已评估整数},
    "be4": {"cpus": [已评估的CPU编号], "memory_mib": 已评估整数, "jvm_heap_mib": 已评估整数}
  },
  "reserve_mib": 已评估整数,
  "allow_existing_host_limits": true或false
}
```

每节点 keeper 和其服务继承指定 CPU affinity；服务启动后读取实际 affinity 和 JVM heap 选项。
BE 还从本节点原版 `/api/show_config?conf_item=mem_limit` 核对实际进程限制，保存真实 HTTP 响应。
记录 cgroup membership，但不创建或调整宿主 cgroup。线程池配置明确写入各节点 conf 并冻结。

启动前保守比较当前 `MemAvailable` 与三个 FE heap、四个 BE memory limit、四个 BE JVM heap
及 reserve 的总和。这个检查不能证明没有 native/mmap/page-cache/共享主机/cgroup 竞争，
也不是七节点的资源隔离保证。约 19.5 GiB 的当前主机是否能承载这套功能探测，仍须在实际窗口评估；
正式多机性能环境不能由这个同机模拟替代。

工具不执行 sysctl、swapoff、修改时钟、修改宿主接口或修改系统安装路径。
若明确允许现存 host limits，只有本次 BE 配置设置 `SKIP_CHECK_ULIMIT=true`，并保存现存 mmap/swap 信息；
这必须作为测试配置例外记录，不能冒称生产默认配置通过。

## 加入顺序与真实 oracle

1. 用全新、互不共享的 meta/storage/log 目录启动 fe1，在同一连接执行
   `SET forward_to_master=false; SHOW FRONTENDS`，核对本地连接 host、FOLLOWER、Join 和端口。
   注册 BE 前不能使用 `SELECT 1`，本分支原版会将该常量查询分配到 BE。
2. fe1 执行原版 `ALTER SYSTEM ADD FOLLOWER "<fe2-ip>:29010"`，再启动 fe2
   `--helper <fe1-ip>:29010`，等待其 SQL 可用；同样加入 fe3。
3. 分别启动四个 BE，并通过原版 `ALTER SYSTEM ADD BACKEND "<be-ip>:29050"` 注册。
4. 创建唯一临时数据库产生真实 journal，记录 master 的 journal 水位。
5. 从三个 FE 的本地 SQL 分别读取 `SHOW FRONTENDS`、`SHOW BACKENDS`。
   每次必须恰好是 manifest 中的三个不同 FE host、四个不同 BE host；所有 FE 的 Role 均为 FOLLOWER
   （这里包含可选举为 master 的投票成员），恰好一个 `IsMaster=true`，ClusterId 一致，
   `Join=true`、`Alive=true`、没有 ErrMsg，所有成员回放水位达到前述 marker，端口匹配。
   `CurrentConnected` 必须指向本次连接的 FE；BE 必须 Alive、没有 decommission、端口与 manifest 一致。
6. 删除临时数据库，再次检查冻结摘要，才标记 `MEMBERSHIP_READY`。

`SHOW FRONTENDS` 可能转发到 master，不能把在三个连接上执行它当作三份本地元数据查询。
这里依赖真实不同 host 避免 self 分支、BDB `Join`、远端心跳回报的 `ReplayedJournalId` 及实际响应；
本地连接标记只用于确认三个 SQL 入口，不能单独替代远端心跳证明。
所有 SQL 与结构化 errno/state、BE mem_limit 回执、网络接口/路由、namespace、keeper/service 身份保存到新工作目录。
只轮询只读就绪检查；变更语句失败不会自动重复注册。全新私有集群的 root 空密码只经 helper 环境默认读取，不写密码。

## 所有权、停止与失败清理

只有 `.build-records/` 下不存在的新目录可计划，已经尝试启动的计划不能再次 launch。
每个 keeper 的 PID 来自本工具直接 `Popen`；记录 start_ticks、namespace、exe、cwd、cmdline hash。
服务另外核对确切的 `DORIS_HOME`、新安装 cwd 和 FE/BE 进程类型。
每次发送 TERM/KILL 前都重新核对同一身份，拒绝 PID 复用、namespace 改变、命令或路径改变的目标。
不使用宽泛 pkill，不删除别的安装，不修改原包，不删除已有证据。

就绪等待、脚本、SQL、TERM/KILL 都有期限。失败路径先停止 node keepers，让它们清理自己的服务，
再独立核对服务是否退出；不能确认清理的状态为 `CLEANUP_FAILED`。
原启动脚本的 Popen 也纳入清理；已记录的 service 身份始终保留，后续发现不能替换同一 PID 的旧身份。
状态文件损坏时使用已保存的内存身份继续处理其他节点；归档失败不能跳过实际停止。
子 namespace 内仍有未分类的活进程时不发宽泛信号，也不声称清理完成。
有原始失败但已成功回收的最终状态为 `FAILED_CLEANED`，进程仍返回非零；正常停止为 `STOPPED`。
显式 stop 会再次验证顶层计划摘要和每个进程身份，处理 supervisor 已退出但已记录服务仍存活的情形。
网络只依赖本次进程持有的 netns；所有 keeper/service 退出后隔离接口随 namespace 释放。
KEEPER 状态文件、最终 cluster.json 和独立 stop 回执保留，便于复核实际是否清理完成。

## 使用

先只生成计划，不启动任何进程或编译 helper：

```bash
python3 -B tools/license-checks/multinode_baseline_cluster.py \
  --package output/massdb-sql-2.0.5-rc02-bin-arm64 \
  --java-home .build-records/license-p1-jdk17.0.4-20260924/jdk-17.0.4+8 \
  --resources .build-records/<reviewed-resource-profile>.json \
  --workdir .build-records/<new-multinode-directory>
```

在已协调的空闲窗口、内存预算明确后显式启动；命令保持前台监督，应保存终端日志：

```bash
python3 -B tools/license-checks/multinode_baseline_cluster.py --mode launch \
  --plan .build-records/<new-multinode-directory>/plan.json
```

另一个终端使用同一冻结计划停止：

```bash
python3 -B tools/license-checks/multinode_baseline_cluster.py --mode stop \
  --plan .build-records/<new-multinode-directory>/plan.json
```

纯离线用例（不创建 namespace、不编译 Java、不发送 SQL/HTTP）：

```bash
python3 -B -m unittest discover -s tools/license-checks -p test_multinode_baseline_cluster.py -v
```

2026-09-24，在原版容量 pilot 结束后已通过 **11/11 纯离线用例和 AST 语法检查**，
证据为 `.build-records/license-p0-p1-20260924/multinode-offline-v1/report.json`。
覆盖显式资源、原配置 heap 保留、真实成员/日志水位负例、PID/start_ticks/ns/cwd/命令变化拒绝、
计划路径和 pin 跨计划借用拒绝、rediscovery 不替换旧身份、损坏状态文件仍回收其他节点、归档失败处理。
这些是受控 mock/纯函数证据，不是实际服务 TERM/KILL 或启动故障演练。

同日已生成 `.build-records/license-p0-p1-20260924/multinode-plan-v1/plan.json`，冻结 1484 项摘要；
`plan-generation-check.json` 保存计划摘要、实际 shape 校验、没有 cluster/node 状态文件的证据。
候选资源为三个 FE 各 1024 MiB heap、四个 BE 各 2048 MiB process limit 和 256 MiB JVM heap、
2048 MiB reserve，总计 **14336 MiB**，各服务明确共享 CPU 6–9。
生成计划时 MemAvailable 为 9981 MiB，**不足以启动**；需要其它原版功能前提完成、现有单节点集群停止后
重新检查。计划生成没有启动服务或 Java helper，资源适用性仍未证明。
首次把计划控制器限制到 CPU 0–4 时，服务所需 CPU 6–9 被 guard 拒绝且尚未创建工作目录；
随后控制器使用 CPU 0–9 完成计划，服务配置仍固定为 6–9。
运行 launch 的控制器允许 CPU 集必须覆盖七节点声明的 CPU；实际服务 affinity 仍按每节点显式配置核验。

首次 v1 实际启动暴露了工具的 bootstrap 错误：BE 注册前执行 `SELECT 1`，原版返回
1105/HY000 `No backend available as scan node`。最终 `FAILED_CLEANED`，10 个记录 PID 全部退出，
原始 SQL 错误及清理回执保留在 `multinode-plan-v1/` 与 `multinode-launch-v1.json`。
工具改用本地 FE 元数据后，通过新增用例在内的 **13/13** 离线检查，重新冻结 v2 计划。

2026-09-24，`multinode-plan-v2/` 已实际达到 `MEMBERSHIP_READY`：原包和精确 JDK 17.0.4+8，
三个投票 FE、四个 BE、七个不同子 netns、15 个 supervisor/keeper/service 身份均已核对。
三入口成员 oracle、远端心跳和不低于 marker 32 的回放水位通过，临时 marker 数据库已删除。
1484 项冻结摘要再次检查通过。证据为
[实际启动核验](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/multinode-launch-v2.json)。
v2 完成三档千万行 [fanout fixture](/data/project/massdb-sql/tools/license-checks/fanout-fixture.md) 后，
已正常 `STOPPED`，15 个记录 PID 全部退出，子 namespace 无遗留进程。
停止前 `cluster-before-stop.json` 保留原始 manifest 字节与摘要；
[停止核验](/data/project/massdb-sql/.build-records/license-p0-p1-20260924/multinode-plan-v2/stop-audit.json)
及独立 stop 回执保存最终结果。完整 LP009 性能矩阵仍未执行。
