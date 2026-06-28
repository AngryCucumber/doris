# Tablet 冷热分层迁移 · 10 分钟演示脚本

面向专利评审演示。展示 **B 路线"tablet 级"冷热分层**的三个核心点:

1. **访问频率驱动**:被访问的数据自动升 SSD,长期不访问自动降 HDD;
2. **tablet 级粒度**:同一个分区内部,不同 tablet 可独立处于 SSD / HDD(区别于 partition 级整片搬);
3. **分区级粒度**:被访问的分区热、未访问的分区冷;
4. **迁移对业务透明**:tablet id / 查询入口 / 查询结果均不变,只换底层介质。

---

## 0. 前置条件

- 一个跑起来的 MassDB/Doris 集群,FE 默认 `9030`,BE 配了 **SSD + HDD 两类盘**
  (`storage_root_path = .../storage_ssd,medium:SSD;.../storage_hdd,medium:HDD`)。
- **建议单 BE**:本特性就是"同一 BE 节点内 SSD↔HDD",单 BE 演示物理分布最干净;
  多 BE 时单副本表会被通用负载均衡器搬动,干扰物理观测(可用第 4 步的 `disable_balance` 规避)。
- 用任意 MySQL 客户端连接:`mysql -h <FE_IP> -P 9030 -u root`。

> 观测有两个视角,演示时讲清楚:
> - **决策视角**(tiering 想怎么放)= `SHOW PROC '/tiering/tablet_states'` 的 `TargetMedium / Temperature / Score` —— **干净、权威**,直接对应每个 tablet 的冷热判定;
> - **物理视角**(数据实际在哪块盘)= `SHOW TABLETS FROM <db>.<tbl>` 的 `Path` 列(含 `storage_ssd`/`storage_hdd`)。

---

## 1. 演示参数(仅演示用,生产请用正常阈值/周期)

```sql
-- 关掉通用均衡器,避免单副本表被搬动干扰物理观测
ADMIN SET FRONTEND CONFIG ("disable_balance" = "true");
ADMIN SET FRONTEND CONFIG ("disable_disk_balance" = "true");
-- 演示只看"访问驱动",先把"写入新鲜度保护"调到最小(否则刚灌的数据会先被整体保护成热)
ADMIN SET FRONTEND CONFIG ("tablet_tiering_fresh_write_protect_sec" = "1");
ADMIN SET FRONTEND CONFIG ("tablet_tiering_min_score_gap" = "1");
```

> 全局开关默认值:`enable_tablet_tiering=true`、`tablet_tiering_dry_run=false`、
> BE `enable_tablet_heat_report=true`(若未开需在 fe.conf/be.conf 打开并重启)。

---

## 2. 建表:多分区 + 单分区多 tablet

```sql
CREATE DATABASE IF NOT EXISTS demo;
USE demo;

-- 3 个分区(p1/p2/p3);每个分区 8 个 bucket = 8 个 tablet。初始全部放 HDD。
CREATE TABLE sales (id INT, amt INT)
DUPLICATE KEY(id)
PARTITION BY RANGE(id) (
  PARTITION p1 VALUES LESS THAN (1000),
  PARTITION p2 VALUES LESS THAN (2000),
  PARTITION p3 VALUES LESS THAN (3000)
)
DISTRIBUTED BY HASH(id) BUCKETS 8
PROPERTIES ("replication_num" = "1", "storage_medium" = "HDD");

-- 在表上开启 tablet 冷热分层(演示阈值)
ALTER TABLE sales SET (
  "tablet_tiering.enable"            = "true",
  "tablet_tiering.hot_threshold"    = "3",     -- 分数 ≥ 3 判热 → SSD
  "tablet_tiering.cold_threshold"   = "2",     -- 分数 ≤ 2 且空闲够久 判冷 → HDD
  "tablet_tiering.cooldown_time"    = "15",    -- 停止访问 15s 后才允许降冷(演示用小值)
  "tablet_tiering.min_hot_residence"  = "0",
  "tablet_tiering.min_cold_residence" = "0"
);

INSERT INTO sales SELECT number, number*10 FROM numbers("number" = "3000");
```

可以验证策略已挂上(也演示了 `SHOW CREATE` 能看到分层属性):

```sql
SHOW CREATE TABLE sales\G        -- PROPERTIES 里能看到 tablet_tiering.*
SHOW PROC '/tiering/policies';   -- 有一条 TABLE scope 的策略
```

**初始分布(全 HDD)** —— 决策视角此刻还没有记录(没产生迁移),物理视角全 HDD:

```sql
SHOW TABLETS FROM sales PARTITIONS(p1);   -- Path 列全部是 .../storage_hdd
```

---

## 3. 访问驱动升温:只反复访问 p1 的 3 个 key

这 3 个等值查询会被**按分布键裁剪到各自的单个 tablet**(可用 `EXPLAIN` 看到 `tablets=1/8`),
所以只有这 3 个 tablet 升温,p1 其余 5 个、以及 p2/p3 全程不被访问。

```sql
EXPLAIN SELECT count(*) FROM sales WHERE id = 5;   -- 看 OlapScanNode: tablets=1/8

-- 演示时循环跑约 30~40 秒(用脚本或手动多跑几次):
-- for i in $(seq 1 16); do mysql ... -e "
SELECT count(*) FROM sales WHERE id = 5;
SELECT count(*) FROM sales WHERE id = 305;
SELECT count(*) FROM sales WHERE id = 705;
-- "; sleep 2; done
```

---

## 4. 看分布:tablet 级混放 + 分区级差异(本演示的核心)

**决策视角(权威)** —— p1 的 8 个 tablet,只有被访问的 3 个判热升 SSD:

```sql
SHOW PROC '/tiering/tablet_states';
```

实测输出(p1 的 8 个 tablet,节选关键列):

```
TabletId         TargetMedium  Temperature  Reason             Score
1782619717052    SSD           HOT          HIGH_QPS_PROMOTE   30.0   <- 被访问
1782619717062    SSD           HOT          HIGH_QPS_PROMOTE   30.0   <- 被访问
1782619717064    SSD           HOT          HIGH_QPS_PROMOTE   30.0   <- 被访问
1782619717050    HDD           COLD         LOW_ACCESS_DEMOTE  0.0
1782619717054    HDD           COLD         LOW_ACCESS_DEMOTE  0.0
1782619717056    HDD           COLD         LOW_ACCESS_DEMOTE  0.0
1782619717058    HDD           COLD         LOW_ACCESS_DEMOTE  0.0
1782619717060    HDD           COLD         LOW_ACCESS_DEMOTE  0.0
```

> **讲解点 1（tablet 级)**:同一个分区 p1 内部,3 个被访问的 tablet → SSD,其余 5 个 → HDD。
> 这正是 B 路线区别于"partition 级整片冷热"的地方——决策粒度是**单个 tablet**。
>
> **讲解点 2（分区级)**:p2、p3 完全没被访问,它们的 tablet 不会出现热记录(或保持 HDD/COLD)。
> 即"被访问的分区热、未访问的分区冷"也天然成立。

**物理视角确认**(单 BE 时最干净):

```sql
SHOW TABLETS FROM sales PARTITIONS(p1);
-- 被访问的 3 个 tablet 的 Path 变成 .../storage_ssd,其余 5 个仍 .../storage_hdd
```

> 多 BE 演示时,单副本 tablet 可能分散在不同 BE 上;以**决策视角**为准,
> 物理迁移随后由调度器逐个落实(`SHOW PROC '/tiering/tablet_states'` 的 TargetMedium 是权威意图)。

---

## 5. 停止访问 → 自动降冷回 HDD

停止上面的查询循环。规则:

```
降冷(SSD→HDD) ⟺ score ≤ cold_threshold  且  距上次访问 > cooldown_time  且  过了 min_hot_residence
```

- `score` 随访问窗口滚出而下降(read_5m 是 5 分钟窗,停访后约 5 分钟归零);
- `cooldown_time`(这里 15s)= 停止访问多久后才允许降冷,是主旋钮。

约 **3~6 分钟**后(取决于此前访问量,演示阈值下),3 个热 tablet 的决策会翻回 `HDD / COLD`:

```sql
SHOW PROC '/tiering/tablet_states';        -- 3 个热 tablet 的 TargetMedium 变回 HDD
SHOW TABLETS FROM sales PARTITIONS(p1);    -- Path 全部回到 .../storage_hdd
```

> **想现场快速演示降冷**(不等分数自然衰减):临时把阈值抬到当前分数之上,
> 下一个评估周期(约 10s)即判冷:
> ```sql
> ALTER TABLE sales SET ("tablet_tiering.hot_threshold"="200","tablet_tiering.cold_threshold"="100");
> -- 观察 SHOW PROC '/tiering/tablet_states' 里热 tablet 翻成 HDD/COLD,然后改回去
> ```

---

## 6. 迁移对业务透明:查询结果不变

迁移全程不改 tablet id、不改查询入口,数据无损:

```sql
SELECT count(*) FROM sales;              -- 仍是 3000
SELECT amt FROM sales WHERE id = 705;    -- 仍是 7050
```

---

## 7. 对应专利的讲解清单

| 演示现象 | 对应机制 / 代码 |
|---|---|
| 访问后 3 个 tablet 升 SSD,reason=`HIGH_QPS_PROMOTE` | BE `tablet_heat_collector` 采集访问频率/点查/扫描字节 → FE 评分 `score ≥ hot_threshold` 判热 |
| 同分区内 3 SSD / 5 HDD | 决策粒度是 **tablet**(`TabletTierState` 每 tablet 一份目标介质),非 partition `DataProperty` |
| 停止访问后降 HDD,reason=`LOW_ACCESS_DEMOTE` | `score ≤ cold_threshold` 且 `idle > cooldown_time`(最近访问时间因子) |
| tablet id / 查询结果不变 | 复用 `EngineStorageMigrationTask`:拷 rowset → 装载新目录成功才切换 → 失败旧目录继续服务 |
| 三级策略(表/分区/租户)、SHOW CREATE 回显 | `TieringPolicyManager` 字段级合并;`ALTER TABLE/DATABASE SET('tablet_tiering.*')` |

---

## 附:观测命令速查

```sql
SHOW PROC '/tiering/policies';        -- 各 scope(TABLE/PARTITION/TENANT)的策略
SHOW PROC '/tiering/tablet_states';   -- 每个 tablet 的 TargetMedium/Temperature/Reason/Score(决策视角,权威)
SHOW TABLETS FROM demo.sales PARTITIONS(p1);  -- Path 列 = 实际所在盘(物理视角)
EXPLAIN SELECT count(*) FROM demo.sales WHERE id=5;  -- 看等值查询裁剪到单 tablet(tablets=1/8)
```

## 附:演示后清理 / 恢复

```sql
DROP TABLE IF EXISTS demo.sales;
ADMIN SET FRONTEND CONFIG ("disable_balance" = "false");
ADMIN SET FRONTEND CONFIG ("disable_disk_balance" = "false");
ADMIN SET FRONTEND CONFIG ("tablet_tiering_fresh_write_protect_sec" = "1800");
ADMIN SET FRONTEND CONFIG ("tablet_tiering_min_score_gap" = "20");
```

> 时间预算(单 BE):建表+灌数 ~1 min,访问升温+看分布 ~3 min,停访降冷 ~4 min(可用快速降冷选项压缩),核对+讲解 ~2 min ≈ 10 min。
