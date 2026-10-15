# MassDB SQL 每日表备份与恢复（HDFS）

适用于本仓库版本的**存算一体、原生 OLAP 表**。脚本使用 `BACKUP SNAPSHOT` 保存数据与表元数据，
每张表一个物理备份，每次全部成功后发布一个恢复点。默认每日全量；停写窗口内可复用未变化表。
恢复到新表后生成整表交换 SQL，保留交换前的表。不自动执行交换、不删除业务表。

这是外部调度工具，不是数据库原生增量备份。没有分区的 OLAP 表也可以使用。
新增工具的代码遵循仓库 `LICENSE-MASSDB.txt`；不改变 Apache Doris 原有代码的许可。

## 环境与配置

- 一台 Linux 调度机，Bash 4.4+、jq 1.6+、GNU coreutils、系统时区数据库、MySQL 命令行客户端和
  Hadoop 的 `hdfs dfs`。备份、恢复和测试脚本均为 `.sh`，不需要 Python。
- 调度机能连接当前 master FE 的查询端口及 HDFS；**配置直接连接 master FE，不能配置随机分发的负载均衡地址**。
  主从切换后更新配置再重试。脚本检查元数据读取时连接的 FE 是否为 master。
- 使用专用数据库运维账号。脚本查询 `SHOW CREATE REPOSITORY` 和 `SHOW PROC`，本版本需要 ADMIN 权限；
  账号凭据保存在调度机的 0600 文件中，不写入脚本或命令行。该脚本本身不需要 root 身份运行。
- FE、BE 和调度机均已配置可访问同一个 HDFS namespace 的身份与网络。
  Kerberos 环境由现有运维流程维护有效票据，脚本不登录或续期。
- 一个数据库使用一个专用 repository。备份和恢复同库串行，脚本也在 HDFS 上加互斥锁。
  不要让其他工具同时修改这个 repository 的备份文件。

先在 MassDB SQL 中创建仓库，替换 HDFS 地址和身份。以下是非 Kerberos 示例：

```sql
CREATE REPOSITORY daily_hdfs_repo
WITH HDFS
ON LOCATION "/backups/massdb_daily"
PROPERTIES (
    "fs.defaultFS" = "hdfs://nameservice1",
    "hadoop.username" = "massdb_backup"
);
```

使用 HDFS HA 时，还需要按部署配置提供 `dfs.nameservices`、NameNode RPC 地址、failover provider 等属性；
FE/BE 配置与调度机的 Hadoop 配置必须一致。Kerberos 仓库按实际集群的认证配置创建。
`hdfs_location` 必须是 `fs.defaultFS` 与仓库 `LOCATION` 拼接后的完整 URI，脚本会比对。

将 `config.example.json` 复制到 `/etc/massdb-backup/config.json`，修改 FE、数据库、表清单和 HDFS URI。
`tables` 必须明确列出需要备份的 50 张表。当前脚本接受字母、数字和下划线组成的数据库、表与仓库名。
一个配置对应一个数据库；多个数据库分别使用配置与仓库。

`/etc/massdb-backup/mysql.cnf` 示例，权限设置为 `chmod 600`：

```ini
[client]
user=backup_operator
password=REPLACE_WITH_YOUR_PASSWORD
```

不要把填入密码后的配置放进 Git。需要 TLS 时在该文件中按 MySQL 客户端配置 CA 和服务器校验。
JSON 配置和仓库清单不含客户端密码。脚本不回显可能包含凭据的客户端 stderr；连接失败时在调度机上
用相同客户端配置单独诊断，不把凭据输出到公共日志。

## 首次备份、每日运行

以下命令假设脚本部署于 `/opt/massdb-backup/massdb_backup.sh`。
从本仓库运行时可用 `bash tools/backup-restore/massdb_backup.sh` 替换相应路径。

```bash
bash /opt/massdb-backup/massdb_backup.sh --config /etc/massdb-backup/config.json backup
bash /opt/massdb-backup/massdb_backup.sh --config /etc/massdb-backup/config.json list
```

默认是每张表全量备份，包括没有变化的表。原生备份支持在线读取数据；脚本对表结构变化作保守检查，
在备份过程中修改 DDL、出现临时分区或表状态异常会阻止完整恢复点发布。
每表最长等待默认 12 小时，一轮最长 20 小时；任意表失败，退出码非零，日志不出现该轮 `COMPLETE`。
成功的前几张表备份仍保留，但不会将未完成的 50 张表伪装成完整恢复点。

在调度机的 `Asia/Shanghai` 时区，每天 02:00 运行的 cron 示例：

```cron
0 2 * * * /usr/bin/bash /opt/massdb-backup/massdb_backup.sh --config /etc/massdb-backup/config.json backup >> /var/log/massdb-backup.log 2>&1 && /usr/bin/bash /opt/massdb-backup/massdb_backup.sh --config /etc/massdb-backup/config.json prune --apply >> /var/log/massdb-backup.log 2>&1
```

确保 cron 的 `PATH`、`JAVA_HOME`、`HADOOP_CONF_DIR` 和 Kerberos 票据环境正确，日志目录可写。
JSON 的 `timezone` 决定保留期日界线，不改变 cron 的调度时区。
将非零退出码和超过 24 小时没有新 `COMPLETE` 的情况接入现有告警。

## 很少变化的表：复用完整备份

若上游可以停写，先停止目标表的所有导入、更新、删除、DDL、自动分区变更等任务，并等在途事务结束。
**从命令启动到完成都保持这个窗口**，再运行：

```bash
bash /opt/massdb-backup/massdb_backup.sh --config /etc/massdb-backup/config.json backup --reuse-unchanged --quiesced
```

首次仍会全备，之后比较表 ID、原始建表语句、索引 ID/SchemaVersion/SchemaHash、
分区 ID/VisibleVersion，以及数据库版本。未变化且之前在停写窗口中完成的表可以复用；变化表重新全备。
普通在线全备记录不会被直接当作可复用记录，启用此模式的第一轮会重新建立基线。
底层文件 compaction 不直接触发逻辑数据版本变化，脚本不按文件修改时间或行数判断变更。

脚本检查在途事务并在采集前后、恢复点发布前再次比对，但这些检查**不等于获得数据库写锁**。
`--quiesced` 是调用方对真实停写窗口的保证，不会自动暂停业务。无法建立窗口就用默认全量模式。
需要 50 张表统一的业务截止点时，也应在备份前统一停止写入并排空事务。
在线全量模式提供各表的备份时点，不承诺跨表事务一致性。

以每表 100 GB 单副本、50 张表计算，每天全备保留 30 天约 150 TB 逻辑备份空间；
复用模式下完全不变约 5 TB，每天变化 1 张表约 7.9 TB，变化 5 张约 19.5 TB。
**HDFS 的副本或纠删码开销另算**，3 副本 HDFS 的 150 TB 逻辑空间约需 450 TB 原始空间，
还需考虑 Trash、失败任务、演练及运行余量。数据库原本的多副本不会都备份到 repository。

## 保留近 30 天、保护仍被引用的旧备份

```bash
# 只输出清理计划
bash /opt/massdb-backup/massdb_backup.sh --config /etc/massdb-backup/config.json prune

# 执行计划对应的清理
bash /opt/massdb-backup/massdb_backup.sh --config /etc/massdb-backup/config.json prune --apply
```

按配置时区保留今天及前 29 个自然日的完整恢复点；同一天重跑产生独立恢复点。
恢复点日期以该轮开始时间计。最近一次完整恢复点永远保留，距离其完成已超过 36 小时则拒绝实际清理。
失败的日期不会补造一个成功恢复点。

清理只操作该工具记录且拥有的快照：没有保留恢复点或 pin 引用、且备份记录也已超过保留期才回收。
先删除过期清单，再删除失去引用的物理快照和记录，失败后可重试。
任何被保留清单引用的老快照都会继续保留，哪怕它是在几个月前生成的。
不要给仓库另外添加“对象/目录超过 30 天就删除”的策略。

删除使用 HDFS Trash，不使用 `-skipTrash`。实际空间释放取决于集群 Trash 策略；
如果管理员禁用了 Trash，`hdfs dfs -rm` 就会直接删除。脚本不改集群的 Trash 配置。
脚本完成前进程崩溃，可能留下未登记的原生快照，它们**不会自动删除**，需结合 `SHOW BACKUP`
与 HDFS 内容另行检查。断点续传与自动接管遗留数据库任务不在本工具范围内。

## 恢复数据和旧表结构，再整表替换

先用 `list` 找到恢复点 ID。以下以 `latest` 为例；历史恢复使用实际 ID 替换它：

```bash
bash /opt/massdb-backup/massdb_backup.sh --config /etc/massdb-backup/config.json restore --point latest --table orders --as orders_restore_20261012 --output-dir /var/lib/massdb-backup/restore-20261012
```

脚本校验快照及版本，然后将备份中的表结构和数据恢复为同一数据库下的新普通表。
目标表必须不存在。只有新的 `RESTORE` 作业真正 `FINISHED`、新表为 NORMAL 状态后，才输出：

- `orders_restore_20261012.backup-ddl.sql`：备份时记录的建表语句，供核对。
- `orders_restore_20261012.swap.sql`：`ALTER TABLE ... REPLACE WITH TABLE ... PROPERTIES ('swap'='true')`。

校验恢复表的字段、索引、分区、关键业务汇总和抽样数据；确认应用兼容旧结构。
切换前暂停原表写入及 DDL、排空在途导入，再通过 MySQL 客户端执行生成的 `swap.sql`。
交换不要求原表与恢复表结构相同；交换前的原表留在恢复表名称下，可以另行换回。
没有自动执行 `DROP TABLE`，原表已经被删除的情况应单独安排新表改名，不要直接运行交换 SQL。

恢复目标副本数跟随备份。新旧表共存所需的磁盘空间要按数据库目标副本数预留。
动态分区默认不自动启用，以免恢复后立刻清理历史分区；colocate 默认不恢复。
校验完成后按保存的 DDL、当前集群布局和业务意图恢复这些设置。异步物化视图、外表及外部导入任务
不属于这份 OLAP 表备份，需要另行管理。恢复为旧版本会回退之后的数据和结构变更，不会自动合并新写入。

使用本工具恢复时 HDFS 锁会阻止本工具清理。如果要在另一个数据库或集群手工恢复，先固定恢复点：

```bash
bash /opt/massdb-backup/massdb_backup.sh --config /etc/massdb-backup/config.json pin --point RECOVERY_POINT_ID
# 手工恢复完成且不再需要保护后，解除固定
bash /opt/massdb-backup/massdb_backup.sh --config /etc/massdb-backup/config.json unpin --point RECOVERY_POINT_ID
```

所有手工恢复必须遵守 pin 约定；本工具不能发现其他集群正在读取 HDFS 的行为。
固定后的清单独立保存在 `pins/`，即使原来的日常清单过期，物理备份仍被保护。

## 故障排查与验收

元数据与原生快照一起保存在 HDFS，调度机丢失后可用相同配置继续管理：

```text
<hdfs_location>/__palo_repository_<repository>/
  __repo_info                 原生仓库身份信息，清理时保留
  __ss_mb_.../                原生表快照
  _massdb_backup/
    owner.json               策略身份，与数据库/仓库/HDFS URI 绑定
    points/*.json            完整恢复点
    records/*.json           成功表备份、DDL、版本及复用信息
    pins/*.json              显式保留的恢复点
    lock/owner.json          正在运行的调度机、PID、开始时间
```

互斥锁没有自动过期。如果进程被杀或 HDFS 中断，可能遗留 `lock/`；
先读取锁所有者，确认对应进程已停止，并确认 `SHOW BACKUP`、`SHOW RESTORE` 无活动作业，
再由运维删除该锁目录后重试。**不能仅因为锁超过某个时长就删除**。
SQL/轮询超时不代表数据库任务已取消；不要立即启动另一轮或清理仍在运行的快照。

HDFS 客户端采用原生校验，工具另外校验备份信息文件的 MD5、表清单和完整备份类型。
这些检查不能替代真实恢复演练。建议先选一张代表性的 100 GB 表完成：备份、修改原表结构、
恢复新表、业务校验、整表交换、必要时换回；以实际结果验收半天的恢复目标。
本工具不运行每天扫描数百亿行的 `COUNT(*)`，也不声称已经完成生产集群恢复验证。

离线测试：

```bash
bash tools/backup-restore/test_massdb_backup.sh
python3 build-support/check-source-headers.py
```

实现根据本仓库 `BackupHandler`、`Repository`、`BackupJobInfo` 和 SHOW 命令的输出字段编写。
操作接口另见 [Doris 备份说明](https://doris.apache.org/docs/4.x/admin-manual/data-admin/backup-restore/backup/)、
[整表替换说明](https://doris.apache.org/docs/4.x/sql-manual/sql-statements/table-and-view/table/ALTER-TABLE-REPLACE/)
和 [Hadoop 文件系统命令](https://hadoop.apache.org/docs/stable/hadoop-project-dist/hadoop-common/FileSystemShell.html)。
