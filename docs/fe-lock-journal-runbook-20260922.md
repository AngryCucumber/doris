<!--
Copyright (c) 2026
厦门市美亚柏科信息安全研究所有限公司
Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
SPDX-License-Identifier: LicenseRef-MassDB-Commercial
Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
Upstream and third-party components retain their respective licenses.
-->

# Master FE 事务锁、元数据锁与 journal 等待排查操作单

适用现场：约 600 台服务器、200 万逻辑 tablet、存算一体；Master 运行约两周后
入库和监控出现卡顿。以已确认配置的 ZGC Xms125g/Xmx300g、OpenJDK 17.0.2 为准。
GC 附件窗口未显示可以直接解释长时间入库停滞的 GC 长暂停。
**当前要验证的是业务等待链，尚未确认发生了哪一种锁阻塞。**

目标是回答四件事：哪些入库线程在等待、等什么、谁能解除等待、解除等待的线程又卡在哪里。
线程上限 100000 和实际约 12500 个 Java 线程本身都不是根因证据。
先保持当前堆大小和线程上限，取得可比较的现场。

## 1. 在发生卡顿的 Master 采集一轮

提前把这两个文件放到离线环境：

- [fe-stall-collect.sh](/data/project/massdb-sql/tools/fe-stall-collect.sh)：在 Master 上运行，只收集本机证据。
- [fe-thread-dump-summary.py](/data/project/massdb-sql/tools/fe-thread-dump-summary.py)：离线处理文本；需要 Python 3.8 或更高版本，无第三方依赖，可以在另一台离线分析机运行。

确认实际 Master、FE 启动用户和 PID。优先使用部署记录与对应安装目录的 `fe.pid`，
并核对进程仍是该 FE。也可用对应 JDK 的 `jps -l` 辅助辨认
`org.apache.doris.DorisFE`，不要取机器上第一个 Java 进程。
SQL 尚可响应时可查看一次 `SHOW FRONTENDS` 的 `IsMaster` 和角色；
此命令在当前代码中也会读取 journal，不应作为卡顿时必须完成的前置步骤。

以下命令在脚本所在目录、以 FE 启动用户执行。
`12345` 必须替换成实际 FE PID；JDK 路径也应核对为现场启动 FE 所用的安装目录。

```bash
umask 077
FE_PID=12345
FE_DIAG_ROOT=$(mktemp -d /var/tmp/fe-lockcheck.XXXXXX)
bash ./fe-stall-collect.sh \
    --pid "$FE_PID" \
    --output "$FE_DIAG_ROOT/snapshot" \
    --jvm \
    --jcmd /usr/local/deploy/java17/bin/jcmd
```

这轮会保存 `/proc`、线程/FD 数、内存压力、9020 连接汇总，以及最多三份
`Thread.print -l`。前一份成功后间隔 5 秒再采下一份；每次 jcmd 客户端最多等待
15 秒，另有 1 秒结束宽限。输出目录必须是新目录，脚本不覆盖已有证据。

`Thread.print` 有 JVM 操作开销，约 12500 线程时尤其不要连续高频执行。
任一次失败或超时，脚本停止后续线程采样；客户端超时不等于目标 JVM 内的请求已取消。
先查看 `collection.txt` 和对应 `.stderr`，不要另开循环补抓，也不要直接升级为
`jstack -F`、heap dump 或 `GC.class_histogram`。
这些是故障采集的操作边界，不表示运行本脚本绝对没有暂停开销。
JDK 官方将线程转储列为随线程数量变化的中等影响操作，见
[jcmd 17 文档](https://docs.oracle.com/en/java/javase/17/docs/specs/man/jcmd.html)。

本轮不用 `--http-port`：`/metrics` 本身可能在等待相同的锁。
脚本不上传、不重启、不修改配置、不读取进程参数/环境变量。
另记下采集起止时间、当时受影响的库/表、导入是否完全无进展。
如果目前正常，可以先保存一份基线；正常快照不能代替卡顿时的快照。

## 2. 先分组，避免逐个翻阅上万条线程

对成功取得的每份文本分别运行；不要将三个快照拼接成一个输入。
以下变量沿用上一步，文件可留在现场。

```bash
python3 ./fe-thread-dump-summary.py \
    "$FE_DIAG_ROOT/snapshot/jvm-threads-1.txt" \
    > "$FE_DIAG_ROOT/summary-1.txt"
```

对 `jvm-threads-2.txt`、`jvm-threads-3.txt` 分别生成摘要。
工具给出线程状态计数、数量最多的十组完整调用栈，以及
`EditLog-Flusher`、`timePrinter`、事务、BDB、监控、异步日志等路径的原文件行号。
摘要只展示有限帧和线程例子；定位后要回到原文件读完整线程块，包括末尾的
`Locked ownable synchronizers`，直到下一个线程头。
例如摘要指向 L1234，可用 `less +1234 文件名` 打开。

首先区分以下几种情况，不能只数 `WAITING` 或 `RUNNABLE`：

| 常见完整调用链 | 初步含义与下一步 |
|---|---|
| Thrift → socket read，尚未进入 FE 业务处理 | 可能只是等待下一个请求的空闲连接；Java 显示 RUNNABLE 不等于消耗 CPU。与健康基线比较。 |
| 事务/表操作 → `ReentrantReadWriteLock` → park | 等待事务锁或表锁；按下一节查同一快照中的持有者。 |
| 事务/元数据操作 → `EditLog.logEditWithQueue` → `Object.wait` | journal 请求还未完成；同时检查此线程仍持有哪些业务锁，然后找 `EditLog-Flusher`。 |
| `MetricRepo.getMetric` → 事务读锁 | 监控可能被同一事务写锁拖住；其他线程若堵在 MetricRepo 类监视器，再追最先进入 getMetric 的线程。 |
| `TThreadPoolServer` 工作线程很多，但业务栈分散、持续完成 | 不能据此认定发生锁阻塞；需要继续区分连接容量、服务吞吐与瞬时峰值。 |

三个快照中的同一线程持续处于相同等待链，加上对应业务没有进展，是继续追查的强线索。
同一热点方法重复出现也可能是正常高频工作，不能单凭三个相同顶帧判定死锁。

## 3. 从等待者找到持锁者，再继续追下去

下面是判读示意，**不是已经取得的生产线程栈**：

```text
入库线程 A
  等事务锁 <R>：parking to wait for ... ReentrantReadWriteLock$FairSync

线程 B
  Object.wait → EditLog.logEditWithQueue → 事务操作
  waiting on <Q>
  Locked ownable synchronizers:
    <R> ReentrantReadWriteLock$FairSync

EditLog-Flusher
  flushEditLog → BDBJEJournal.write → 后续需要查明的阻塞点
```

这里能建立的关系是：**A 等待 B 持有的事务写锁 R；B 等待 journal 请求 Q 完成；
完成 Q 需要追 flusher。**
从实际快照复制完整十六进制地址，例如 `0x0000000123456789`，检索所有关联线程块：

```bash
python3 ./fe-thread-dump-summary.py \
    "$FE_DIAG_ROOT/snapshot/jvm-threads-1.txt" \
    --lock 0x0000000123456789 \
    > "$FE_DIAG_ROOT/lock-1.txt"
```

该工具只是检索地址引用，不会替你判定 owner。判读规则如下：

| 锁/等待种类 | 可以怎样关联 | 不能怎样推断 |
|---|---|---|
| `synchronized` 入口 `waiting to lock <X>` | 查另一个线程的 `locked <X>`，并确认它没有正在 wait 释放 X。 | 不能看到任意一条 `locked` 就判定当前持有。 |
| 当前事务/表的 `ReentrantReadWriteLock$FairSync` | 等待地址 R 若出现在另一线程的 `Locked ownable synchronizers`，可定位排他写锁持有者。 | 被共享读锁挡住时，读锁持有者通常不会列在 ownable 区域；找不到 owner 不等于锁泄漏。 |
| `Object.wait()` | 追踪通知者或负责完成请求的线程。当前 EditLog 请求对应 flusher 的完成通知逻辑。 | wait 已释放正在等待的 monitor Q；同一栈下方仍可能打印 `locked <Q>`，不能当成仍占有 Q。其他独立持有的业务锁 R 可能还在。 |
| `StampedLock` | 地址可归组等待者；结合持 stamp 的源码路径、report 子任务和 `CompletableFuture.join` 追任务依赖。 | StampedLock 不记录线程所有权，不能从 ownable 列表找到唯一 owner，即使是写锁也如此。 |

锁地址只在**同一份快照内**关联。ZGC 可能移动对象，地址也可能被复用；
跨快照比较同一进程的线程 ID、名称、调用路径和业务进展，不把 `<0x...>` 当稳定身份。
`Thread.print` 未报告 Java 死锁，也不能排除共享读锁、StampedLock、任务完成依赖导致的停滞。
这些锁展示差异已用本地 JDK 17.0.2 的独立小进程验证，未向生产 FE 注入故障。
关于 StampedLock 的所有权语义，见
[JDK 17 API](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/concurrent/locks/StampedLock.html)。

## 4. 按实际持锁者或 flusher 栈分流

| 现场证据 | 优先检查 | 对应处理方向 |
|---|---|---|
| flusher 在 BDB/JE 复制确认路径等待，同期出现 `InsufficientReplicasException` / `InsufficientAcksException` | Master 与有投票权的 Follower 的连接、存活、复制进度及对端压力。先确认实际 FE 投票拓扑；Observer 不参与投票。单个 Follower 故障不必然丢多数派。 | 恢复实际缺失的复制确认能力，处理网络或对端瓶颈。保留现有持久化/多数确认语义。 |
| flusher 堵在 `BDBJEJournal` 监视器；持有者 `timePrinter` 在 `BDBJEJournal.write` 内 sleep/retry | 找同一时段写 BDB 异常及重复 journal ID。当前时间戳写失败可长期重试，方法监视器在重试 sleep 时仍未释放。 | 先处理具体 BDB 异常原因；这一链可以解释 Master 尚存活、查询仍可用而写入受阻。它目前是源码支持的假设。 |
| BDB 写入链下出现 `FileDispatcherImpl.force0` / `FileChannel.force` / `FileDescriptor.sync` 等 | 元数据所在实际设备的延迟、队列、竞争 I/O，并对照正常时段。 | 处理已确认的存储延迟或共享设备竞争；SSD 介质本身不能排除此项。 |
| 持业务锁的线程进入 Log4j/Disruptor 队列等待 | 同时找异步日志消费线程是否卡在文件写入/滚动，以及日志目录所在设备。当前事务解锁前可能先记录慢锁日志。 | 处理日志写入瓶颈和异常日志洪峰；若验证临界区内日志放大阻塞，再设计移动日志位置/限量的代码修复。 |
| 持事务写锁者在 `removeUselessTxns`、事务遍历/删除或其他计算路径 | 三次完整栈是否推进、影响哪些库、线程 CPU 是否增长；后半程仍可能转入 journal 等待。 | 确认规模与持锁时长后，评估分批工作量和临界区缩短；仅看到清理方法名不直接改清理周期。 |
| report 相关线程等 `StampedLock`；其他 report 路径等 `CompletableFuture.join` | 父任务、共享子线程池、子任务正在等的资源及工作进展。 | 查明读 stamp 的释放依赖和子任务瓶颈；不能用“没有 owner”排除此链。 |
| flusher 在 `LinkedBlockingQueue.poll` 的 100ms 等待，生产者没有持续 journal 等待 | 这通常是暂时无任务的正常空闲。 | 转查入库线程当前所在阶段。若确有大量持久 producer 等待且 flusher 始终空闲，再核对是否同一 Master/时段及任务完成状态。 |

`timePrinter` 正常在守护线程循环中休眠并不异常：需要看到它**在 BDB 写方法内部**休眠，
持有相同监视器，并有写失败重试证据。
同理，文件写调用要看完整父栈：Log4j 日志文件写入与 BDB journal 落盘是两条不同路径。
BDB 内部事务锁等待也与 FE 的事务读写锁不同。

## 5. 仅对已经命中的分支补充证据

### 元数据或日志 I/O 分支

元数据目录来自已确认配置。以下命令为只读；`iostat`/`pidstat` 需要已安装 sysstat，
没有则记录缺项，不要求离线现场临时安装。

```bash
FE_META_DIR=/usr/local/deploy/massdb-sql-storage/massdb-sql-meta
timeout -k 1s 5s findmnt -T "$FE_META_DIR"
timeout -k 1s 5s df -h "$FE_META_DIR"
timeout -k 1s 15s iostat -x -y 1 10
timeout -k 1s 15s pidstat -d -p "$FE_PID" 1 10
```

对日志目录也执行 `findmnt -T`，确认是否与元数据共用设备。
`LOG_DIR=${DORIS_HOME}/log` 必须按实际安装解析，不能仅由元数据路径猜日志路径。
在采样时间内查看 `await`、队列及吞吐变化，结合正常基线和持锁者栈判断；
SSD/NVMe 的 `%util` 单个值不能证明或排除设备瓶颈，不设通用的固定毫秒阈值。
如果线程是计算状态，需要时再用 `pidstat -t -u -p "$FE_PID" 1 5` 获取短时线程 CPU；
线程很多时输出也很大，应落本机文件，按原始栈中的十六进制 nid 对应十进制 TID。

### BDB 复制分支

当前配置复制端口为 9010。在 Master 和相关 Follower 同一时段查看：

```bash
timeout -k 1s 10s ss -H -tin '( sport = :9010 or dport = :9010 )'
```

关注重传、发送队列、连接变化以及对端 FE 压力；TCP 连通不证明应用确认及时。
结合实际投票组和 JE 异常判断，而不是只做 ping。
若使用故障切主恢复，需要先核对复制与角色状态，不在未明确数据状态时随意删除 BDB 目录、
强制恢复元数据或改成 `NONE`/`NO_SYNC`。

### 同时段有限日志片段

只读与快照同时段的 FE 普通日志尾部或明确覆盖该时间的滚动文件。
以下 `FE_LOG_DIR` 是占位路径，替换成实际目录后运行：

```bash
FE_LOG_DIR=/replace/with/actual/fe/log
timeout -k 1s 10s tail -n 20000 "$FE_LOG_DIR/fe.log" \
    > "$FE_DIAG_ROOT/fe-log-tail.txt"
```

在该小文件中搜索 `sleep and retry`、`journal id`、`write bdb`、
`InsufficientAcks`、`InsufficientReplicas`、`LockTimeout`、`DatabaseException`，
并保留异常前后完整堆栈。日志量大时尾部可能不覆盖故障时刻，未搜到不能证明没发生。
不要递归扫描两周的所有日志，也不用全局打开 DEBUG。
本版本 `write bdb is too slow` 的实际条件是 **100000ms**，
所以没有这条警告不能排除数秒或数十秒的 journal 延迟。

## 6. 第一轮怎样反馈与形成结论

原始文件可以全部留在离线环境。先整理以下信息即可继续缩小范围：

1. `collection.txt` 是否三次成功、具体采集时间与当时导入是否持续无进展。
2. 三份摘要里最大的业务等待组、数量和是否持续出现；空闲 socket 线程单列。
3. 一个代表性等待者、对应持锁者、`EditLog-Flusher`、`timePrinter` 的完整线程块。
4. 命中分支时，再附同时段 BDB 异常片段或磁盘/复制摘要。

优先形成这样的可核对陈述：
“这三次快照中，库相关事务线程持续等待写锁；持锁线程在等 journal 完成；
flusher 又被 timePrinter 持有的 journal 监视器挡住；相同时间出现某项 BDB 重试异常。”
这类证据链足以明确下一步处理方向，比“线程很多/CPU 不高/SSD 正常/没有死锁提示”更有判断价值。
若没有观察到该链，就按实际业务栈切换方向，不将 GC、锁或线程数预设为根因。

## 7. 当前版本的关键源码位置

- [事务锁及解锁](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/transaction/DatabaseTransactionMgr.java:171)：写锁释放前先检查并记录持锁时长；清理路径也可能持锁写 journal。
- [journal 生产者等待](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/persist/EditLog.java:1518)：请求入队后等待完成，没有总体等待期限。
- [flusher 写入与完成通知](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/persist/EditLog.java:184)：写入后才通知生产者。
- [时间戳写入与重试](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/journal/bdbje/BDBJEJournal.java:230)：同步方法内 OP_TIMESTAMP 长期重试。
- [timePrinter 创建](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/catalog/Env.java:3141)：精确线程名为 `timePrinter`。
- [指标采集](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/metric/MetricRepo.java:1312)：同步入口及后续业务指标读取。
- [report 读 stamp 与子任务](/data/project/massdb-sql/fe/fe-core/src/main/java/org/apache/doris/catalog/TabletInvertedIndex.java:158)：需结合子任务完成依赖分析。

本操作单与工具没有修改 FE/BE 运行逻辑，也未在生产服务器执行采集。
