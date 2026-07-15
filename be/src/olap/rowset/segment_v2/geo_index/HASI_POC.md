# HASI —— 万亿级 geo_point 层次聚合空间索引 POC

> Hierarchical Aggregating Spatial Index
> 自研空间索引，目标在区域聚合 / 范围 / 距离 / contains / kNN 查询上**整体快于 Elasticsearch(Lucene BKD)**。
> 本文结合当前仓库源码给出落地设计、改造点（精确到 file:line）与代码骨架。
>
> **rev2**：经多智能体对照源码评审后修订——修正锚点（写路径挂载从 ArrayColumnWriter 改到 ScalarColumnWriter 等）、
> 补齐正确性 gate（删除/时间桶/残余谓词）、重写精算核契约与 kNN 算法、树结构改为扁平叶目录+隐式 F 叉金字塔、
> §7/§8 重构为逐阶段可回测（v0–v4，每阶段独立交付/验证出口/回退开关/量化门槛）。

---

## 0. 需求（本 POC 必须满足的）

| # | 需求 | 说明 |
|---|---|---|
| R1 | **万亿行**可用 | 1e12 量级，查询不能正比于总点数 |
| R2 | 支持**区域聚合** | `count / sum / min / max / 去重(HLL) / 分位数(t-digest)`，按任意 region |
| R3 | 支持**范围/框、半径距离、多边形 contains、kNN** | 检索类查询 |
| R4 | 支持**地理计算**下推 | `ST_Distance_Sphere / ST_Contains` 等谓词在存储层求值。注意：仓库**没有 ST_Within**（BE/FE 均未实现，关系谓词只有 `st_contains/st_intersects/st_disjoint/st_touches`）；且 `ST_Distance_Sphere` 只有 4 个 DOUBLE 参数的签名（`StDistanceSphere.java:40-47`），谓词形态是 `ST_Distance_Sphere(lon, lat, lon0, lat0) < r` |
| R5 | **自研**索引，复用现有架构 | 不引第三方索引引擎；复用 Doris 分区/分桶/compaction/MPP |
| R6 | **可接受空间换时间** | 允许预聚合金字塔带来的额外存储 |
| R7 | **比 ES 更快** | 核心指标：区域查询代价 ∝ **边界(周长)** 而非面积；区域聚合期望 10–100×，检索期望 2–5× |

**核心原理（一句话）**：别人逐个 recheck 区域内的点（代价 ∝ 面积内点数）；HASI 让**完全落在 region 内的层次 cell 直接返回预聚合值（O(1)，不下钻）**，只有跨越 region 边界的 cell 才扫描精算 —— 于是代价 ∝ 边界。

**三条硬性契约（正确性红线，全文各节都必须服从）**：

- **C1 检索只收窄**：geo 索引对 `_row_bitmap` 的唯一合法操作是 `_row_bitmap &= hit`，禁止替换或并入。
  "整块 accept 免 recheck" 指**免几何精算**，不免位图求交——否则会复活已被 delete bitmap /
  其他谓词剔除的行（roaring 求交代价可忽略）。
- **C2 精确判定复用原实现**：索引路径**禁止重新实现任何距离/包含公式**。SIMD/几何 prefilter 只允许
  带保守余量的 clear-accept / clear-reject，余量带内一律回调与全表路径完全相同的标量函数
  （`GeoPoint::ComputeDistance` / `GeoPolygon::contains` / `GeoCircle::contains`），保证与全表对拍逐位一致（见 §4.6）。
- **C3 sketch 使用先过 gate**：预聚合值只有在通过全部正确性 gate（表模型 / delete predicate /
  delete bitmap / 时间桶三态 / 残余谓词 / per-rowset measure sketch 存在性，见 §5.2）后才允许返回，任何一条不满足则降级行扫。
  **正确性永远由查询期 gate 保证，compaction 重算 sketch 只是把降级比例收敛回去的性能优化。**

---

## 1. 现状盘点（已具备的地基）

调研结论：**两个关键地基已经就绪**，自研成本远低于从零开始。

### 1.1 S2 几何库已集成（无需引新依赖）
- thirdparty 已打包 `thirdparty/src/s2geometry-0.10.0.tar.gz`，编译产物在 `thirdparty/installed/include/s2/`，含
  `s2cell_id.h`、`s2region_coverer.h`、`s2cap.h`、`s2latlng.h`、`s2polygon.h`、`s2cell_union.h`、`s2closest_edge_query.h`。
- `be/src/geo/geo_types.h` 已用 S2 封装好查询几何：
  - `GeoPoint`（内含 `S2Point`，成员在 `:133`），`be/src/geo/geo_types.h:89`
  - `GeoPolygon`（内含 `S2Polygon` `:207`，`polygon()` 访问器 `:184`），`be/src/geo/geo_types.h:172`
  - `GeoCircle`（内含 `S2Cap` `:272`，`circle()` 访问器 `:254`），`be/src/geo/geo_types.h:243`
  - 基类虚函数 `GeoShape::contains()`，`be/src/geo/geo_types.h:65`（**默认返回 false**，实际逻辑在各子类 override）
- 标量函数已存在：`st_point`(`functions_geo.cpp:45`)、`st_distance_sphere`(`:197`)、`st_circle`(`:456`)、
  `st_contains`(`:540`)；FE 注册见 `BuiltinScalarFunctions.java:1042-1062`。
- **两个必须记住的实现细节**（精算核一致性依赖它们，见 §4.6）：
  - `ST_Distance_Sphere` = `GeoPoint::ComputeDistance`（`geo_types.cpp:624`）：haversine × 半径常数 **6371010.0 m**；
    `ST_Contains(ST_Circle(...), p)` = `S2Cap::Contains`：**S1ChordAngle 闭区间** —— 两条数值路径不同。
  - `ST_Contains(polygon, point)` 在 S2 判 true 后还有 **1e-6 度平面距离的贴边排除**
    （`TOLERANCE`，`geo_types.cpp:54`；"点在边上不算 contains"）。
- **缺口**：仓库今天没有任何 "经纬度 → S2 cell id" 的标量函数——它是 `__s2` 生成列表达式的硬前提，列为 v0 前置交付（§3.3-1）。

> 含义：HASI 的"几何 → S2 cell 覆盖(covering)"、"点是否在 region 内"全部可直接复用现有 S2，
> 只需补一个 `S2RegionCoverer` 包装层 + 一个 cell id 标量函数。

### 1.2 自定义索引框架已成熟，ANN 是模板（但不能盲抄）
索引抽象（与列解耦、独立索引文件、按 `IndexType` 工厂分发）：

| 角色 | 基类 | 文件 |
|---|---|---|
| 写入 | `IndexColumnWriter` | `be/src/olap/rowset/segment_v2/index_writer.h:49` |
| 读取 | `IndexReader` | `be/src/olap/rowset/segment_v2/index_reader.h:36` |
| 迭代 | `IndexIterator` | `be/src/olap/rowset/segment_v2/index_iterator.h:48` |
| 工厂 | `IndexColumnWriter::create()` | `be/src/olap/rowset/segment_v2/index_writer.cpp:49` |

**ANN（向量索引）是最近新增的同构索引**：
- 目录 `be/src/olap/rowset/segment_v2/ann_index/`（writer/reader/iterator + `ann_topn_runtime` + `ann_range_search_runtime`）
- 工厂分发：`index_writer.cpp:68`（inverted 分支）/ `:128`（ann 分支）。
  **注意 `:129` 有 `DCHECK(type == OLAP_FIELD_TYPE_ARRAY)`——ANN 只接受 ARRAY 列；GEO 分支必须去掉该假设、接受 BIGINT 标量。**
- **写路径挂载（rev2 修正）**：ANN 挂在 `ArrayColumnWriter`（`column_writer.cpp:1045/:1062/:1098`）是因为向量是
  `ARRAY<FLOAT>`。`__s2` 是 **BIGINT 标量**，正确模板是 **`ScalarColumnWriter`**：
  init 建 builders（`column_writer.cpp:548-550` 经工厂 `create`）、喂值（`:610` `builder->add_values(get_field()->name(), data, ...)`）、
  `add_nulls`（`:573-576`）、finish（`:773-776`）。
- 读路径挂载：`segment_iterator.cpp:392` 调用 `_init_index_iterators()`（定义在 `:1332`）；
  ANN 有**两条**下推通路：topn `_apply_ann_topn_predicate()`（`:695`，调用点 `:427`，在 delete bitmap 减除 `:411-419` **之后**）
  与 range search（`:614` → `:1020-1034` 写 `_row_bitmap`，在 delete bitmap **之前**、靠 `:414` 兜底）。
  **ANN 出口的准确语义**：把当前 `_row_bitmap` 作为搜索选择器传入（faiss IDSelector，`faiss_ann_index.cpp:134-155`），
  **在输入位图约束下搜索、结果 ⊆ 输入后写回**——不是无条件"把命中写进位图"。GEO 检索对齐该收窄语义（契约 C1）。
- 索引类型枚举是**一条链路而非一个点**（漏任何一处都是运行时异常，完整清单见 §3.1）。
- compaction：**ANN 无增量合并——compaction 输出 rowset 走与导入相同的 segment 写路径全量重建索引**；
  `inverted_index_compaction.h:35` 的 `compact_column` 是 lucene 目录级合并，条件苛刻（仅 vertical + DUP/MOW + 字符串列）。
- ANN 单测在 `be/test/olap/vector_search/`（9 个 `*_test.cpp`），不在 `be/test/olap/rowset/segment_v2/`。

> 结论：HASI 走 `TabletIndex` + 独立索引文件路线，新增 `IndexType::GEO = 5`，
> 新建 `geo_index/` 目录。写侧模板是 ScalarColumnWriter + inverted 的 `_rid` 计数模式，读侧模板是 ANN range search。

---

## 2. HASI 总体架构（四层）

```
                         查询几何 (GeoCircle/Polygon/box)
                                    │  S2RegionCoverer
                                    ▼
   ┌───────────────────────── HASI 树遍历（每节点三态）─────────────────────────┐
   │  完全在内 → 取节点预聚合 sketch（聚合O(1)）/ 整块行 accept（检索免几何精算） │
   │  完全在外 → 剪枝                                                            │
   │  边界相交 → 下钻；叶子做 ④ 三段式精算                                       │
   └───────────────────────────────────────────────────────────────────────────┘
        ① 基础数据按 S2 Hilbert 序聚簇      ② HASI 金字塔（本索引）
        ③ 学习型导航（可选加速）            ④ 双框 prefilter + SIMD + 余量带回调精确核
```

- **① 复合聚簇 `(time_bucket, __s2)`**：`__s2 BIGINT` 生成列（值 = `st_s2_cellid(lon, lat)` 叶子 cell id），
  与粗时间桶组成复合排序键——先按时间桶分段，**桶内**按空间 Hilbert 序聚簇。**载体按表模型分方案**（rev2，原"隐藏列进 key"机制不存在，见 §3.3-2）：
  - **DUP 表**：`__s2`/`time_bucket` 做**可见生成列**并排进 key 前缀——`CreateTableInfo.java:1088-1089`
    已允许生成列做 key，机制现成；代价是列对用户可见（SHOW CREATE 如实展示）。
    "隐藏生成 key 列"是全新机制（现有 `__DORIS_*` 隐藏列全是 schema 末尾的 value 列），波及面大，列为后续可选优化。
  - **UNIQUE MOW 表**：走 **cluster key**（`CreateTableInfo.java:623-629`，排序键与唯一键分离的现成机制），不动唯一键。
  - **AGG 表**：不支持。
  - 若表无时间列：退化为单键 `(__s2)`。`time_bucket` 粒度（小时/天）作为索引属性可配。
- **② HASI 金字塔（核心索引文件）**：**扁平叶目录 + 隐式 F 叉金字塔**（rev2，替代显式指针四叉树，见 §4.2）。
  叶目录 = 按 Hilbert 序的平坦数组（每叶 ≤ `leaf_rows` 行，**分裂点强制对齐 distinct cell 边界**，防止同 cell 高频打点横跨分裂点造成叶区间重叠）；
  其上按完全 F 叉树（下标计算，无指针）叠内部层，每个内部节点持有子树可合并 sketch → 树即多分辨率聚合金字塔。
  每个 `(time_bucket)` run 一棵子树（森林），writer 以 cell id 下降自动检测 run 边界，无需额外输入列。
- **③ 学习型导航（可选）**：`cell_id → 叶子下标` 的分段线性模型，替代金字塔下降的二分；**只加速，不决定正确性**。
- **④ 精算核**：三段式契约（C2）——保守 accept / 保守 reject / 余量带回调原实现；SIMD 批量。详见 §4.6。

---

## 3. 改造清单（精确到文件）

### 3.1 索引类型枚举——一条完整链路（漏一处即运行时异常）
| # | 位置 | 改动 |
|---|---|---|
| 1 | `gensrc/proto/olap_file.proto:400-406` | `enum IndexType` 加 `GEO = 5` |
| 2 | `gensrc/thrift/Descriptors.thrift:223` | `enum TIndexType` 加 `GEO = 5`（`Index.toThrift` 用 `TIndexType.valueOf(name)`，漏加直接抛 `IllegalArgumentException`，FE 无法下发 schema） |
| 3 | `fe/.../catalog/Index.java` | `toThrift`（`:304`）与 `toPb`（`:324-347`，漏加抛 `RuntimeException`，云模式持久化失败）各加 GEO case |
| 4 | `fe/.../analysis/IndexDef.java:208`（legacy）+ `fe/.../nereids/trees/plans/commands/info/IndexDefinition.java`（**Nereids 实际入口**） | 枚举 + `isGeoIndex()` + `checkColumn` 分支（两处同步改） |
| 5 | `be/src/olap/tablet_schema.h:335-337` | 仿 `is_ann_index()` 加 `is_geo_index()`（头文件内联） |
| 6 | `be/src/olap/tablet_schema.cpp:859 / :889` | 两个 `TabletIndex::init_from_thrift` 重载的 switch 各加 `TIndexType::GEO` case |
| 7 | `fe/.../alter/SchemaChangeHandler.java:2780`（`processAddIndex`） | POC 阶段对 `isGeoIndex()` 直接抛 `AnalysisException("GEO index can only be created with table")`——ALTER 加 GEO 索引到存量数据会破坏"叶子=连续行块"前提（§9-7）。`BUILD INDEX` 路径无需改：`BuildIndexClause.java:109-113` 白名单已自动拒绝 |
| 8 | 护栏单测 | FE 单测遍历 `IndexDef.IndexType` 全部枚举值调 `toThrift`+`toPb` 断言不抛异常，防今后加类型再漏 |

> 核对基准：`git log` 找 ANN 引入 commit 的完整文件清单，逐项标注 GEO 对应改动或"不适用"。

### 3.2 FE —— 索引定义与校验
```java
// IndexDef.java / IndexDefinition.java（两处同步）
public boolean isGeoIndex() { return this.indexType == IndexType.GEO; }

// checkColumn() 增加分支
if (indexType == IndexType.GEO) {
    // 仅允许建在 __s2 BIGINT 生成列（或经纬度对，由 FE 自动生成 __s2）上；仅 DUP / UNIQUE-MOW 表
    if (!GeoIndexUtil.isSupportedColumn(column)) {
        throw new AnalysisException("GEO index only supports geo_point / (lon,lat) columns");
    }
    // 属性：s2_max_level / leaf_rows / fanout / measures / sketch_min_rows / time_bucket 粒度 / tdigest_compression
    GeoIndexUtil.checkProperties(properties);
}
```
新增 `fe/.../analysis/GeoIndexUtil.java`（仿 `InvertedIndexUtil.java`）：解析
`leaf_rows`(默认 65536)、`fanout`(默认 16)、`measures="count,sum(amount),hll(uid),tdigest(latency)"`、
`sketch_min_rows`(默认 4×leaf_rows，见 §6)、`tdigest_compression`。

### 3.3 FE —— 聚簇列 + Nereids 下推
1. **v0 前置：S2 标量函数**。新增 `st_s2_cellid(lon, lat) → BIGINT`。
   **编码约定（rev2.1 实现期确定）**：返回值 = 叶子 cell id **XOR 2^63**（符号位翻转）——
   raw cell id 是 uint64 且 face 4/5 最高位为 1，直接 bit-cast 成 BIGINT 会让这两个 face 排到最前、
   破坏跨 face 的 Hilbert 序（排序键聚簇与 BETWEEN 区间都会错）；翻转符号位后 int64 序 == uint64 序。
   FE Java 侧（v0-⑤ covering 转区间）与 BE 索引内部（uint64 域）在 `__s2` 列边界做同一变换。
   **四文件清单（rev2.1 已核实，已实现）**：
   BE `functions_geo.cpp` 新增 struct（仿 `:197-230` StDistanceSphere）+ `register_function_geo`（`:920` 起）注册；
   FE ① `nereids/.../functions/scalar/StS2Cellid.java`（仿 `StDistanceSphere.java:36-74`，ret BigInt args Double,Double）、
   ② `BuiltinScalarFunctions.java` 注册（仿 `:1050`）、③ `nereids/.../visitor/ScalarFunctionVisitor.java` 新增 visit 方法
   （`accept()` 编译依赖）。**无需** gensrc / FunctionSet.java / thrift 改动——geo 函数已 Nereids-only 注册，
   `ExpressionTranslator.visitScalarFunction`（`:685-697`）走通用 FUNCTION_CALL，BE 按名字经 SimpleFunctionFactory 解析。
   生成列表达式**只能引用已注册的 ScalarFunction**（`CreateTableInfo.java:1226-1237`），
   没有它整条聚簇路线无表达式可用；同时它也是回填工具与对拍测试的共同依赖。
2. **建表时生成 `__s2` 列 + 复合排序键**：复用生成列机制（`GeneratedColumnDesc.java`，INSERT/LOAD 两路都会计算；
   回归先例 `regression-test/suites/ddl_p0/test_create_table_generated_column/`）。key 载体按表模型分方案（§2①）。
3. **`RewriteGeoPredicate`（v0 规则）**：识别 `ST_Distance_Sphere(lon,lat,c1,c2) < r`、`ST_Contains(常量shape, ST_Point(lon,lat))`
   → 注入 `__s2` **包络区间 conjunct**（`__s2 BETWEEN min(covering) AND max(covering)`，可选 ≤`max_scan_key_num`
   （默认 48，`SessionVariable.java:1403-1404`）个细化区间）**+ 保留原 ST_\* 谓词做残差精确过滤**。
   开关 `enable_geo_predicate_rewrite`。**落地细节（rev2.1 核实）**：
   - **FE 计划期 covering 的来源 = v0-⑤ 的 Java S2 库（已定路线）**：fe-core 引入
     `com.google.geometry:s2-geometry:2.0.0`（Maven Central，Apache-2.0，Google 官方 Java 移植；同步 LICENSE/NOTICE；
     Java↔C++ 的 S2CellId 编码是跨移植稳定契约，以对拍单测兜底）。
     备选 b'（不引 Java 库时的保底）：注入 `__s2 >= st_s2_range_min(...) AND __s2 <= st_s2_range_max(...)`
     未折叠常量表达式，由 BE 扫描归一化现场求值进 key range（`olap_scan_operator.cpp:98-119` 对非字面量常量
     `get_const_col` 求值）——只能表达单包络区间；**不得依赖 FoldConstantRuleOnBE**
     （其 `shouldSkipFold` 对 `st_*` 前缀函数显式跳过，且 `enable_fold_constant_by_be` 默认 false）。
   - 规则挂载：`Rewriter.java` 的 `CTE_CHILDREN_REWRITE_JOBS_AFTER_SUB_PATH_PUSH_DOWN`
     （`PushDownVirtualColumnsIntoOlapScan` 之后，`:783` 旁），匹配 `logicalFilter(logicalOlapScan())`；
     `RuleType.java` 加枚举。注意该点之后 `FoldConstantRule` 不再运行——路线 a 直接产 literal 不受影响。
   - session var 三件套（仿 `SHOW_HIDDEN_COLUMNS`）：常量 + `@VariableMgr.VarAttr(name=..., needForward=true)` + 字段。
   - **非 key `__s2`（纯谓词过滤形态，rev2.2 显式支持并回归锁定）**：规则按生成列表达式匹配、
     不要求 `__s2` 是 key/cluster key——`__s2` 做普通 value 生成列时改写照常注入、结果 bit-exact。
     收益结构：无 key-range 剪枝、乱序下 ZoneMap 基本失效，剩"存储层 BIGINT 区间预过滤先行、
     昂贵球面距离只算幸存行"的 CPU 减负（2–5×，IO 不省）；数据有天然空间局部性时 ZoneMap 可部分生效。
     适用：不能改排序键的存量/共享表。要数量级收益仍需聚簇（DUP key 前缀 / UNIQUE CLUSTER BY，§2①）。
4. **v1 检索下推的谓词传输（rev2.3 实现修订：不加 plan-node thrift 字段）**。
   实现期核对 ANN range search 发现其根本没有专用 thrift 字段——谓词作为**普通 conjunct**
   经 `_common_expr_ctxs_push_down` 下推（`scan_operator.cpp` 通用通道，
   `PushDownVirtualColumnsIntoOlapScan` 对 ComparisonPredicate 显式跳过 CSE 虚拟列），
   BE 在表达式树上模式识别。GEO 照搬该模式，v1 无 FE 规则、无 PlanNodes.thrift 改动：
   - **BE 识别**（`geo_range_runtime.cpp::extract_geo_range_search`）：
     `st_distance_sphere(lng_slot, lat_slot, lng0_lit, lat0_lit) </<= r_lit` 及镜像
     `r >/>= st_distance_sphere(...)`；剥 cast；外圆形态（`dist > r`）不可索引、自动拒绝。
   - **安全对应关系**：BE 无法从谓词推断 `__s2` 生成列的来源列——FE 在 CREATE TABLE 校验
     （`IndexDefinition.checkColumn`）时把 `st_s2_cellid(lng, lat)` 的实参列名写进索引
     properties（`lng_column`/`lat_column`，`GeoIndexUtil.java`），BE 按属性匹配谓词 slot
     对应的 tablet 列名（大小写不敏感），**绝不按列名约定猜**。
   - **回退开关**：session var `enable_geo_index_query`（needForward，默认 true）→
     `TQueryOptions.204` → `segment_iterator::_apply_geo_predicate` 入口检查。
   - 原 TGeoIndexFilter 设计中的时间区间/度量列表字段是聚合（v2）需求，届时再评估载体
     （届时若仍走 conjunct 识别路线，时间三态可由残余时间谓词在 BE 侧同样模式识别）。
5. **`PushDownGeoAgg`（v2 规则）+ 可下推判定矩阵**：识别 `SELECT agg(m) ... WHERE <geo region>`，
   计划形态仿 `COUNT_ON_INDEX`（`AggregateStrategies.java:384-394`）：**LogicalFilter（残余时间谓词 + ST_\* 残差）保留在 scan 之上**。
   FE 静态判定（缺一不可，否则不生成 sketch 计划）：
   - 聚合函数集合 ⊆ 索引 `measures`，参数为裸列，且 **null 语义匹配**（`count(col)` 需要 sketch 里该 measure 的
     非空计数，NodeAgg 须按 measure 存 `non_null_count`，仿 `AggregateStrategies.java:581-596` 的 checkNullSlots）；
   - GROUP BY 为空或仅由 time_bucket / 空间 cell 等 sketch 自身键构成；无 distinct（除非落到 HLL measure）；
   - WHERE 去掉 geo 谓词后，残余谓词能被时间桶三态吸收（§5.2 第 0 步），否则整体回退检索路径；
   - 表模型 gate：`keys_type == DUP_KEYS`，或 UNIQUE 且 MOW（先例 `AggregateStrategies.java:345-352`）；AGG/MOR 不生成 sketch 计划。

   BE 运行时复核（防 runtime filter 与版本不一致的兜底）：runtime filter 只在 BE 出现（落入 `_col_predicates`，
   `segment_iterator.cpp:303-309/:1130`），仿 `:705-716` 判 `_col_predicates` / `_common_expr_ctxs_push_down`
   非空则该 segment 放弃 sketch 改行扫。总开关 session var `enable_geo_agg_pushdown`（仿
   `enable_pushdown_count_on_index`，`AggregateStrategies.java:308-311`）。

   **部分聚合回流**：scan 内混合执行——`geo_agg_runtime` 在每个 segment 上把 interior sketch 与 boundary
   行精算折叠成同一份部分聚合，scan 统一输出部分聚合行。回流类型推荐**普通列 + FE 聚合改写**
   （`count(*)→sum(cnt)`、`sum→sum`、`min/max→min/max`、HLL 走 HLL 列 + `hll_union`、分位走 `QUANTILE_STATE`——
   语义等同现有 AGG rollup/MV 改写，无字节格式耦合）；`agg_state` + `xxx_merge`
   （`data_type_agg_state.h:38`、`AggCombinerFunctionBuilder.java:39-49`）作为统一但耦合字节布局的备选。
6. **分桶裁剪二选一**（rev2：现有 `HashDistributionPruner` **只支持等值/IN**，`HashDistributionPruner.java:39-51`，
   区域查询的 cell 范围不会触发裁剪；且原 §9"复合分桶键防热点"与"按 cell 裁桶"互斥）：
   - **方案 A**：分桶列 = 固定粗 level（6~7）单列 `__s2_coarse`；新增 FE 规则把 covering 归一到该 level 展开成 IN-list
     （粗 cell 展开 4^Δ 子 cell、细 cell 取祖先，构成正确超集）。两个上限都要处理：
     `max_distribution_pruner_recursion_depth`（默认 100，`Config.java:1324`）与
     `ExpressionColumnFilterConverter.java:103-106` 的转换期上限；展开数 ≥ 桶数即放弃。承认粗 cell 分桶的热点风险。
   - **方案 B**：放弃分桶裁剪级（漏斗改三级），分桶键按防热点设计（cell+时间/高基列复合），
     收敛依赖 `__s2` 排序键的 segment 内 key range/ZoneMap 剪枝。**POC 推荐 B**（简单、无热点），A 列为 v3 调优项。

### 3.4 BE —— 新建 `be/src/olap/rowset/segment_v2/geo_index/`
```
geo_index/
  CMakeLists.txt
  s2_covering.h / .cpp          # GeoShape -> 叶子键空间闭区间 + interior/covering 双列表（§4.1）
  hasi_tree.h / .cpp            # 扁平叶目录 + 隐式 F 叉金字塔 + 三态分类（§4.2）
  hasi_sketch.h                 # count/non_null/sum/min/max/HLL/t-digest 包装（可合并接口）
  geo_index_writer.h / .cpp     # : public IndexColumnWriter（ScalarColumnWriter 挂载，_rid 计数）
  geo_index_reader.h / .cpp     # : public IndexReader
  geo_index_iterator.h / .cpp   # : public IndexIterator
  geo_range_runtime.h / .cpp    # 检索下推：hit 求交进 _row_bitmap（契约 C1）
  geo_agg_runtime.h / .cpp      # 聚合下推：gate + interior sketch + 边界折叠（契约 C3）
  geo_recheck_simd.h            # 三段式精算核（契约 C2）
  geo_stats.h                   # inside_subtree_hits / boundary_leaves / rechecked_rows 等计数器
```

### 3.5 BE —— 工厂与读写挂载点（rev2 修正为 Scalar 路径）
- `index_writer.cpp:49 IndexColumnWriter::create()`：`:128` ann 分支后加 GEO 分支
  （**不带 `:129` 的 ARRAY DCHECK**，接受 BIGINT 标量）：
  ```cpp
  } else if (index_meta->is_geo_index()) {
      *res = std::make_unique<GeoIndexColumnWriter>(index_file_writer, index_meta);
      RETURN_IF_ERROR((*res)->init());
  }
  ```
- **写路径挂载 = `ScalarColumnWriter`**：建 writer 在 init（`column_writer.cpp:548-550` 同通道或新增
  `_opts.need_geo_index`/`_geo_index_writer`）、喂值 `:610` 旁、`add_nulls` `:573-576` 旁、finish `:773-776` 旁。
  配套：`ColumnWriterOptions` 加字段；`segment_writer.cpp` 与 `vertical_segment_writer.cpp` 各自
  `_create_column_writer` 绑定索引 meta。
- **measure 列的喂入（rev2 关键修正）**：`IndexColumnWriter` 是严格单列的——`add_values` 只会收到
  **本列**数据（`column_writer.cpp:610` 传 `get_field()->name()` + 本列 page 数据），
  `sum(amount)/hll(uid)` 等**跨列 measure 不可能经该接口流入**。分阶段处理：
  - **v2a：count-only**——count（及 non_null_count）仅需 `__s2` 列自身，挂 ScalarColumnWriter 零框架改动；
  - **v2b：带 measure 的 sketch**——**默认构建时机 = compaction**（rev2.1 已定）：
    compaction 输出 segment 落盘后，仿 `be/src/olap/task/index_builder.cpp:762/:798` 的已验证模式
    **读回** `__s2` + measure 列构建重 sketch。新写入 rowset 缺 measure sketch → 聚合 gate 加一条
    "per-rowset sketch 存在性标志"，缺失时该 rowset 的 INSIDE 块走整块流式行扫折叠
    （count/topology 仍随 flush 建，`count(*)` 永不降级）。持续导入下未 compact 数据占比
    通常 <1–5%（cumulative compaction 分钟级追平），对大历史窗口聚合影响 <5%。
    flush 期同步读回（同一实现挂在导入 segment 封口后）作为可选开关，供低写入压力场景换实时性。
    备选实现（不推荐先做）：SegmentWriter 级 "segment 索引 writer" 钩子——
    `SegmentWriter::append_block`（`segment_writer.cpp:673`）/`VerticalSegmentWriter::write_batch`
    处整块 Block 全列可见（注意 vertical 按列组分批，需处理列组间 rowid 对齐）。
- 读路径：`_init_index_iterators()`（定义 `segment_iterator.cpp:1332`）为 GEO 列建 `GeoIndexIterator`；
  新增 `_apply_geo_predicate()`（挂载位置与语义见 §4.5）。
- **compaction（rev2 修正）**：基线 = **随写路径全量重建**（与 ANN 同模式：compaction 输出 rowset 走正常
  segment 写路径重建索引，无条件覆盖 horizontal / 非 DUP-MOW / 有删除等所有路径）。数据流按
  `(time_bucket,__s2)` 保序归并，叶子划分 + roll-up 是 O(n) 单遍，代价可控。
  注意 vertical compaction 列组隔离（`merger.cpp:168-241`：key 组先行、value 组分批）——带 measure 的
  geo 索引构建须在 segment 封口后统一 build（与 §3.5 v2b 的 compaction 读回模式天然一致）。
  "子树 sketch 直接 merge"降级为 v3 快路径优化：仅当 [输入行无删除 && 输出叶子恰为输入整叶并集] 时启用，写明检测条件与回退。

---

## 4. 核心代码骨架（PoC 级，结构对齐仓库现状，标注 TODO）

### 4.1 S2 覆盖工具 `s2_covering.h`
```cpp
#pragma once
#include <s2/s2cell_id.h>
#include <s2/s2cell_union.h>
#include <s2/s2region_coverer.h>
#include <cstdint>
#include <vector>
#include "geo/geo_types.h"   // 复用已封装的 GeoCircle/GeoPolygon(S2Cap/S2Polygon)

namespace doris::segment_v2 {

// 一段闭区间 [lo, hi]，lo/hi 均为**叶子级** cell id（Hilbert 序连续）。
// 约定：所有区间统一经 S2CellId::range_min()/range_max() 归一到叶子键空间后再比较/归并——
// 与 __s2 列（叶子 id）同一键空间，混合层级 covering cell 由此正确表示为区间。
// 警告：不要用 range_max().next() 当上界（最后一个 face 的尾部 cell 会 uint64 回绕，
// S2 头文件明确警告）；闭区间 + `<= hi` 比较，或半开区间用裸 uint64 `hi+1` 并特判回绕为 0。
struct CellRange { uint64_t lo; uint64_t hi; };

// 编码：经纬度 -> 叶子 cell id（索引内部统一用 raw uint64 域）
inline uint64_t s2_leaf_id(double lat_deg, double lon_deg) {
    return S2CellId(S2LatLng::FromDegrees(lat_deg, lon_deg)).id();
}
// __s2 列（BIGINT）域 与 索引内部（uint64）域 的边界变换（§3.3-1 编码约定）：
// __s2 = int64(cell_id ^ 2^63)；cell_id = uint64(__s2) ^ 2^63。已实现于 GeoPoint::ComputeS2CellKey。

// 自适应多分辨率覆盖：内部用大 cell、边界用小 cell
class S2Covering {
public:
    S2Covering(int max_level, int max_cells) : _max_level(max_level), _max_cells(max_cells) {}

    // region 由 GeoShape 提供（GeoCircle::circle()->S2Cap / GeoPolygon::polygon()->S2Polygon）
    // 输出两组已归一化（叶子键空间、有序、相邻已归并）的区间列表：
    //   covering C（GetCovering，⊇ region）：∉C 即可 reject
    //   interior I（GetInteriorCovering，⊆ region）：∈I 即可 accept（polygon 还需贴边侵蚀，见 §4.6）
    // 注意：C/I 是两次独立近似（interior 可为空、cell 不保证父子对应），三态分类不依赖
    // "C∖I 恰为整 cell"——见 §4.2 分类算法；需要精确 cell 差集时用 S2CellUnion::Difference。
    // 参数注记：max_cells 默认 8 时 covering 面积中位数≈region 的 2 倍（S2 头文件实测表），
    // 边界假阳性面积随 max_cells 增大而收窄，v1 起建议 max_cells 64~256 并纳入基准扫参。
    void cover(const S2Region& region,
               std::vector<CellRange>* covering,
               std::vector<CellRange>* interior);

private:
    int _max_level, _max_cells;
};

} // namespace doris::segment_v2
```

### 4.2 HASI 金字塔 `hasi_tree.h`（rev2：扁平叶目录 + 隐式 F 叉，替代显式指针树）
```cpp
#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include "hasi_sketch.h"

namespace doris::segment_v2 {

// 可合并聚合。NULL 语义（与 ST_* 谓词对 NULL 返回非 true 的过滤语义一致）：
//  - geo 列为 NULL 的行不属于任何 cell/节点，count/sum 一律不含之；
//  - measure 值为 NULL：sum/HLL/t-digest 跳过该值，但 row_count 仍按行计；
//  - 每个 measure 单独维护 non_null_count —— count(col) 下推的正确性依赖它（§3.3-5）。
struct NodeAgg {
    int64_t row_count = 0;
    std::vector<int64_t> non_null_counts;   // 每 measure 一个
    std::vector<double>  sums, mins, maxs;
    // HLL / t-digest 不内联在节点里，经 sketch_ref 指向索引文件的 sketch blob 段（见下）
    void merge(const NodeAgg& o);           // roll-up：子 -> 父
};

// 叶目录：两个平坦数组（按 Hilbert 序）。
//   leaf_cell_hi[i]  = 该叶最后一个叶子级 cell id（cell_lo 隐含 = 前叶 hi 之后的下一 distinct id）
//   leaf_row_end[i]  = 行区间前缀和（row_begin 隐含 = leaf_row_end[i-1]）
// 分裂规则：每叶 ≤ leaf_rows 行，且分裂点强制对齐 distinct cell 边界（切分处向后跳到下一个
// 不同 cell id），保证叶区间两两不相交；叶大小上界 = leaf_rows + 同 cell 最大重复数。
// 内部层：完全 F 叉树按下标计算（Eytzinger 式，parent/child 用除法，无指针、无 children[] 哨兵），
// 每层节点只存定长 NodeAgg 小字段 + sketch blob 偏移。F 可配（默认 16：内部节点≈叶子/15，
// 深度 log16，重 sketch 开销近乎归零；纯二叉会使内部节点≈叶子数，重 sketch 成本×3，不取）。
//
// 森林：每个 time_bucket run 一棵子树。写入端以 "cell id 下降" 检测 run 边界（(time_bucket,__s2)
// 键序下桶内 __s2 单调不减，跨桶必下降）——无需把 time_bucket 列喂进索引。
// 每棵子树记录 (bucket_ordinal, rid_begin)，时间三态判定按子树粒度进行（§5.2 第 0 步）。
//
// 文件布局（独立索引文件，DorisFSDirectory，同 ANN）分两段：
//   topology 段：叶目录 + 各层 NodeAgg 定长字段（常驻内存，纯检索查询不碰 sketch）
//   sketch blob 段：每节点 {offset,len}，按需懒加载（HLL/t-digest 只挂行数 ≥ sketch_min_rows 的节点，§6）
class HasiTree {
public:
    // 写入期：流式单遍构建（rev2.1）。输入已按 (time_bucket,__s2) 有序且 rid 连续，
    // 因此**不缓冲 (rid, cell) 对**（16B/行，千万行 segment 峰值 ~160MB 内存），而是维护
    // O(F×depth) 的常量状态（几 MB）：当前叶累加器{row_count, first/last_cell, NodeAgg}
    // + 每层一个待满 F 槽的父节点栈（深度 log_F ≤5）+ 当前路径上的活跃 sketch 集。
    // 行到来：cell 下降 → 封当前子树、开新 time_bucket run；
    //         distinct cell 边界且当前叶超 leaf_rows → 封叶；某层攒满 F 个 → 向上 merge 封父。
    // 叶目录 / NodeAgg / sketch blob 全部顺序追加写，CPU 与缓冲式相同（~2-5ns/行）。
    void add(uint32_t rid, uint64_t cell_id);    // 逐值流式喂入（writer 的 add_values 直接转发）
    void add_nulls(uint32_t count);              // 只推进 rid，不产生表项
    Status finish();                             // 封尾部所有未满节点
    // v2b 补挂（默认走 compaction 路径）：finish() 后 topology 驻留内存，读回 measure 列
    // 按 rid 顺序流式喂入，全部喂完再一次性 save——**索引文件只写一次**，无文件重写/替换问题；
    // 叶分裂已由 topology 固定，measure 行按 rid 路由到所在叶及其祖先节点的 sketch。
    // 普通导入 flush（v2a）则 finish() 后直接 save（无 sketch 段，文件头存在性标志不置位）。
    Status attach_measures(const MeasureSpec& measures);           // 声明将补挂的度量集
    Status add_measure_row(uint32_t rid, const MeasureRow& row);   // 顺序 rid；NULL 按 NodeAgg 语义
    Status save(io::FileWriter* w) const;
    Status load(io::FileReader* r);      // topology 段 eager，sketch 段 lazy
};

} // namespace doris::segment_v2
```

**节点三态分类算法**（查询期，树遍历与 covering 区间的对齐方式——把 §2 图中的"每节点三态"写实）：

1. 预处理：`S2Covering::cover` 产出 C/I 两组叶子键空间闭区间（已排序、相邻已归并）。
2. `DFS(node, pi, pj)`：pi/pj 为 C/I 列表游标，子节点按 Hilbert 序访问故游标单调前进，
   双指针总移动 O(|C|+|I|)：
   - 先推进 pi/pj 越过 `hi < node.cell_lo` 的区间；
   - 节点区间与 C 不相交 → **OUTSIDE** 剪枝（C ⊇ region 保证正确拒绝）；
   - 节点区间 ⊆ 某个 I 区间 → **INSIDE**：聚合取 sketch / 检索整块 accept，不下钻（I ⊆ region 保证正确接受）；
   - 否则 **BOUNDARY**：内部节点下钻；叶子对每行用 `__s2` 值做整数三分——∈I 免几何精算 accept、
     ∉C reject、其余进 §4.6 精算核。
3. 代价：每个 I 区间对金字塔的分解是 O(depth) 个极大 INSIDE 子树（线段树分解论证），
   访问节点数 O((|I|+|B|)·log_F L)，几何精算只发生在边界 cell 的行——
   **"代价 ∝ 边界"乘一个 log 因子后成立**。`GeoStats` 记 `inside_subtree_hits / boundary_leaves / rechecked_rows`，
   §8 回归对固定数据集断言 `rechecked_rows` 随半径 r 呈 O(r)（周长标度）而非 O(r²)。

### 4.3 写入器 `geo_index_writer.h`（ScalarColumnWriter 挂载 + `_rid` 计数）
```cpp
#pragma once
#include "olap/rowset/segment_v2/index_file_writer.h"
#include "olap/rowset/segment_v2/index_writer.h"
#include "geo_index/hasi_tree.h"

namespace doris::segment_v2 {

class GeoIndexColumnWriter : public IndexColumnWriter {
public:
    static constexpr const char* S2_MAX_LEVEL    = "s2_max_level";     // 默认 30（叶子）
    static constexpr const char* LEAF_ROWS       = "leaf_rows";        // 默认 65536
    static constexpr const char* FANOUT          = "fanout";           // 默认 16
    static constexpr const char* MEASURES        = "measures";
    static constexpr const char* SKETCH_MIN_ROWS = "sketch_min_rows";  // 默认 4*leaf_rows

    GeoIndexColumnWriter(IndexFileWriter* w, const TabletIndex* meta)
        : _index_file_writer(w), _index_meta(meta) {}

    Status init() override;                       // open dir, 读 properties
    // 只接收 __s2 列自身数据（v2a 起 count/topology 由此可得）。
    // 行号核算仿 inverted_index_writer.cpp:270-272 的 _rid 模式，且**不缓冲**（rev2.1 流式）：
    //   add_values: 逐值 _tree.add(_rid++, cell_id)（树内部以 cell id 下降检测 time_bucket run 边界）
    //   add_nulls : _tree.add_nulls(count), _rid += count（NULL 行占 rowid 不产生表项；
    //               (time_bucket,__s2) 键序下 NULL 连续排在每桶段首——memtable null_direction_hint=-1，
    //               故各桶值行天然连续，叶区间仍是连续 [rid_begin, rid_end)）
    Status add_values(const std::string name, const void* values, size_t count) override;
    Status add_nulls(uint32_t count) override;
    Status finish() override;                     // _tree.finish()（v2a: count-only）+ save
    int64_t size() const override;
    void    close_on_error() override;
    // array 接口对 geo 不用，返回 NotSupported
    Status add_array_values(size_t, const void*, const uint8_t*, const uint8_t*, size_t) override;
    Status add_array_values(size_t, const CollectionValue*, size_t) override;
    Status add_array_nulls(const uint8_t*, size_t) override;
private:
    IndexFileWriter*     _index_file_writer;
    const TabletIndex*   _index_meta;
    std::shared_ptr<DorisFSDirectory> _dir;
    uint32_t              _rid = 0;
    HasiTree              _tree;                  // 流式构建，无按行缓冲
};

} // namespace doris::segment_v2
```
> 带 measure 的 sketch（v2b）**不经过**本 writer 的 add_values：默认在 compaction 后由 index_builder 式
> 读回构建（§3.5；flush 同步读回为可选开关，SegmentWriter 钩子为不推荐备选），经 §4.2 的
> `attach_measures`/`add_measure_row` 补挂后一次性 save。本 writer 的 `finish()` 对齐
> `ann_index_writer.cpp:46` 的 `_index_file_writer->open(_index_meta)` 取 dir 后 save。

### 4.4 读取器/迭代器/运行时
- `geo_index_reader.h` : `public IndexReader`，`index_type()→GEO`、`new_iterator()`、`load_index()`（topology eager / sketch lazy）；
  两类查询（签名体现契约 C1/C3）：
  ```cpp
  // 检索：在 input 约束下求命中，结果 ⊆ input（内部 INSIDE 块整区间 addRange 后统一 &= input）
  Status range_search(const GeoSearchParams& p, const roaring::Roaring& input,
                      roaring::Roaring* hit, GeoStats* s);
  // 聚合：调用方已过 FE gate；本函数执行 BE 级 gate 后遍历：
  //   sketch 存在性 = 索引文件头的 measure sketch 标志（v2b compaction 构建后才置位）；
  //                  缺失 → 本索引的 INSIDE 块降级整块流式行扫折叠（count/topology 不受影响）
  //   deleted    = 本 segment delete bitmap（_opts.delete_bitmap.at(segment_id())，可空）
  //   [t_lo,t_hi) = 时间窗（对每棵 time_bucket 子树先做时间三态，§5.2 第 0 步）
  //   INSIDE 节点若行区间与 deleted 相交（roaring intersect-with-range，近常数）→ 整棵降级 BOUNDARY 行扫
  //   BOUNDARY 行号回填 boundary_rows，交给上层带完整谓词/删除语义的行扫路径
  Status aggregate(const GeoSearchParams& p, const roaring::Roaring* deleted,
                   NodeAgg* partial, roaring::Roaring* boundary_rows, GeoStats* s);
  ```
- `geo_index_iterator.h` : `public IndexIterator`，持 `GeoIndexReader`（同 `ann_index_iterator.h`）。
- `geo_range_runtime.h` : 在 `segment_iterator.cpp` 内被 `_apply_geo_predicate()` 调用。
- `geo_agg_runtime.h` : 聚合下推，先执行 rowset 级 gate（`_opts.delete_condition_predicates->num_of_column_predicate() > 0`
  → 整 rowset 回退行扫，判法对齐 `segment_iterator.cpp:2939-2941`；delete 列不在 geo 索引认知内，sketch 上不可求值），
  再调 `aggregate()`，把 interior partial 与 boundary 行精算折叠成部分聚合行输出（§3.3-5 回流方案）。

### 4.5 segment_iterator 读路径接入
```cpp
// be/src/olap/rowset/segment_v2/segment_iterator.cpp
// 挂载点选 :427（_apply_ann_topn_predicate 同位置）：此时 _row_bitmap 已经过 key ranges(:406)、
// 各类索引/谓词(:408)、delete bitmap 减除(:411-419)、row ranges 求交(:421-423)——
// 输入已剔除删行，&= 收窄后自然安全（契约 C1）。
Status SegmentIterator::_apply_geo_predicate() {
    if (_geo_runtime == nullptr) return Status::OK();
    int32_t cid = _geo_runtime->src_column_idx();
    IndexIterator* it = _index_iterators[cid].get();
    if (it == nullptr || it->get_reader(IndexReaderType::GEO) == nullptr) {
        return Status::OK();                       // 无 GEO 索引 -> 回落普通谓词（v0 路径）
    }
    // 代价门槛（仿 ANN topn 的 30% 门槛 :750-761）：输入位图基数占比过大 / covering 区间数超限时
    // 放弃索引，改走 __s2 排序键 + ZoneMap 扫描
    if (!_geo_runtime->worth_indexing(_row_bitmap, segment_rows())) return Status::OK();
    roaring::Roaring hit;
    RETURN_IF_ERROR(_geo_runtime->evaluate(it, _row_bitmap, &hit, &_opts.stats->geo_stats));
    _row_bitmap &= hit;                            // 只收窄，绝不替换/并入
    return Status::OK();
}
```
统计计数器**四层命名映射表**（全文/回归脚本按此表取名，防漂移；对齐 ANN 写法 `:772-781`）：

| GeoStats 内部字段 | OlapReaderStatistics | profile 名 | §8.3 CSV 列 |
|---|---|---|---|
| `rows_filtered` | `rows_geo_index_filtered` | `RowsGeoIndexFiltered` | `rows_index_filtered` |
| `rechecked_rows` | `geo_boundary_recheck_rows` | `GeoBoundaryRecheckRows` | `boundary_recheck_rows` |
| `inside_subtree_hits` | `geo_sketch_hit_nodes` | `GeoSketchHitNodes` | —（仅聚合归因用） |
| `boundary_leaves` | `geo_boundary_leaves` | `GeoBoundaryLeaves` | —（O(r) 标度断言用） |

### 4.6 三段式精算核 `geo_recheck_simd.h`（契约 C2 的实现）
索引判定必须与全表标量路径**逐位一致**，而仓库两条圆形谓词的数值路径不同：
`ST_Distance_Sphere` = haversine × **6371010.0 m**、开区间 `<`（`geo_types.cpp:624`）；
`ST_Contains(circle)` = S1ChordAngle 闭区间（`GeoCircle::contains`，`geo_types.cpp:1556`）。
因此 `GeoSearchParams` 携带 **来源谓词类型 + 比较算子 + 原始阈值**（§3.3-4），判定三段：

1. **保守 accept**：interior 判定用按余量 δ **收缩**的 cap（角半径 `r/6371010 − δ`）。
   δ 覆盖 haversine-vs-chord 公式差与浮点误差——注意 haversine 在地球尺度只有 ~8 位有效数字
   （绝对误差可达 ~10cm 量级，`s2latlng.cc:53-56`），δ 取米级绝对余量而非相对 1e-12。
2. **保守 reject**：外扩 δ 的 cap / 外接框。
3. **余量带**：逐点回调与全表路径完全相同的函数——`ST_Distance_Sphere` 谓词调
   `GeoPoint::ComputeDistance` 用原始算子比较；`ST_Contains(circle)` 调 `GeoCircle::contains`；
   多边形调 `GeoPolygon::contains`。**禁止在索引路径重写公式。**

```cpp
// 圆形双框 prefilter（SIMD 批量，正确性要点如下）：
//  外框：直接取 S2Cap::GetRectBound()（原生处理极点与经度回绕，s2cap.cc:183-186 的保守分支一并覆盖）。
//        经度测试用归一化偏差：d = lon - lon0; d -= 360 * round(d / 360); |d| <= half_width
//        （一条 SIMD round 指令；rect.lng().is_full() 时跳过经度测试）；纬度直接用 rect 的 [lat_lo, lat_hi]。
//        —— naive 的 |lon-lon0| 在 ±180 处会把 Δlon=0.2° 算成 359.8° 而丢行；
//        naive 的 r/cos(lat0) 经度半宽恒小于真值 asin(sin r / cos lat0)，边缘点会被 false reject。
//  内框：必须是 cap 的子集。Δlat_in 取保守值（r_deg/√2 级）；Δlon_in 由最坏角点反解——
//        取 lat0∓Δlat_in 中 |lat| 较小（靠赤道一侧，haversine 经度项 cos(lat) 因子最大）的角点，
//        代入 haversine 解出令角点距离 <= r·(1−ε) 的 Δlon_in；|lat0|+r 近极点时放弃内框只留外框+精确核。
//  环带：三段契约第 3 段，逐点回调原实现。
inline void recheck_circle_simd(const double* lat, const double* lon, size_t n,
                                const GeoSearchParams& p, uint8_t* keep /*out*/);

// 多边形：covering INSIDE cell 免几何精算有一个额外前置——ST_Contains 有 1e-6 度平面贴边排除
// （TOLERANCE，geo_types.cpp:54）：interior cell 的角/边可以贴在多边形边界上，cell 内可存在
// 距边 < 1e-6 度的点（全表判 false）。因此 INSIDE 免精算前须做“安全侵蚀”判定：
// 用 S2ClosestEdgeQuery（S2CellTarget 对查询多边形的 S2ShapeIndex）求 cell 到多边形边界的球面
// 最小距离，仅当 > S1Angle::Degrees(2 * TOLERANCE) 才允许整块 accept / merge sketch
// （球面度距 <= 平面度距，故此界保守）；否则该 cell 降级为边界 cell 逐点调 GeoPolygon::contains。
// 注意：不要用“cell 四角调 compute_distance_to_line 粗判”替代——最近点可在 cell 边内部，四角判定不保守。
```

**可选加速（R6 空间换时间）**：为 geo 列附带存储单位向量 `(x,y,z)`（3×float 或量化），
粗判阶段圆内测试退化为一次 SIMD 点积 `dot(p,c) >= cos θ`，无逐点三角函数；
不加列时也可从 `__s2` 叶子 id 经 `S2CellId::ToPoint` 还原近似单位向量（误差 ~cm 级，计入 δ 余量）。

---

## 5. 查询执行流（端到端）

### 5.1 剪枝漏斗（参数化——各级收敛比取决于查询与数据，不再写死数量级）
```
分区裁剪(时间)  →  [分桶裁剪(可选,方案A)]  →  segment 内 key range/ZoneMap(__s2 排序键)
   →  HASI 金字塔 INSIDE 跳过  →  边界叶子三段式精算
```
给定：时间窗占比 α、区域 covering 占空间比 β、边界/面积比 γ、leaf_rows、fanout，
每级基数 = 上级 × 对应收敛比。§8.3 的基准报告按（城市小区域 / 省级大区域 / 全国聚合）三组代表参数给实测算例；
分桶级是否存在取决于 §3.3-6 的方案选择（POC 推荐 B：无此级，靠排序键 key range 补偿）。

### 5.2 区域聚合 `SELECT count(*), sum(amount) FROM t WHERE ST_Distance_Sphere(lon,lat,:lon0,:lat0) < :r`
0. **时间桶三态（若带时间谓词）**：对每棵 time_bucket 子树——桶区间 ⊆ [t_lo,t_hi) → 允许 sketch；
   相交不包含 → 该子树**全部行**（含空间 INSIDE 部分）降级行扫，由计划中保留的残余时间谓词过滤；不相交 → 剪枝。
1. **FE gate**（§3.3-5 判定矩阵全过才生成 sketch 计划）：函数 ⊆ measures 且 null 语义匹配、GROUP BY 形态、
   无残余谓词、表模型 DUP/UNIQUE-MOW。计划形态：LogicalFilter（残余谓词）保留在 scan 之上。
2. **BE gate**：runtime filter 复核（`_col_predicates` 非空 → 本 segment 弃 sketch）；
   rowset 级 delete predicate → 整 rowset 行扫；segment 级 delete bitmap → 相交节点降级（§4.4）；
   per-rowset measure sketch 存在性标志（索引文件头，v2b compaction 构建后置位）缺失 →
   该 rowset 的 INSIDE 块走整块流式行扫折叠（count 类不受影响）。
3. **遍历**：三态分类（§4.2）——INSIDE 节点 O(1) 取 sketch 合并（不下钻、不扫描）；
   BOUNDARY 行号回填，行走普通扫描（天然吃 delete bitmap 减除与残余谓词）+ 三段精算后并入。
4. **回流**：scan 输出部分聚合行（普通列 + FE 聚合改写，§3.3-5），上层 agg 合并。
5. 代价 ∝ 边界节点数 ≈ 周长（×log 因子），与区域内总点数无关（R7）。

### 5.3 半径/框/contains 检索（R3/R4）
`range_search()`：INSIDE 块整区间 accept（免几何精算），BOUNDARY 块三段式精算 →
`hit` 求交进 `_row_bitmap`（契约 C1）→ 后续列延迟物化。大范围低选择度时代价门槛放弃索引（§4.5）。

### 5.4 kNN（v4 交付）
**树上 best-first（Hjaltason–Samet）**，不做"扩张 cap covering 重跑 coverer"（后者需初始半径猜测、
每轮重复访问已覆盖 cell，稀疏区多轮、稠密区首轮爆量）：
- 优先队列按**节点 min chord-distance** 排序：节点 `[cell_lo, cell_hi]` 经 `S2CellUnion::FromMinMax`
  （`s2cell_union.h:109`，要求叶子级端点——叶目录端点本就是叶子 id）展开为 O(level) 个对齐 cell，
  对各 cell 取 `S2Cell::GetDistance(S2Point)`（`s2cell.h:141`）的最小值。S1ChordAngle 与大圆角单调等价，用于排序安全。
- 叶子扫点维护 k-堆；队首 min-dist ≥ 当前第 k 距离即终止。
- **种子播种**：查询点所在叶子经二分定位，沿 Hilbert 序两侧各取若干行（~4k）先算距离得初始第 k 阈值，显著加速剪枝。
- **最终排序值必须用 `GeoPoint::ComputeDistance` 重算**（与 `ST_Distance_Sphere` 逐位一致，契约 C2）。
- 多 segment/tablet：每段 limit=k，上层 TopN 归并；段间共享阈值可挂 RuntimePredicate
  （FE 规则仿 `PushDownVectorTopNIntoOlapScan.java`，thrift 仿 `ann_sort_info`，`PlanNodes.thrift:855-856`）。
- 多时间桶：各子树入同一个优先队列，共享 k-堆。

---

## 6. 空间换时间的账（R6，参数化公式替代拍脑袋数字）

- `__s2` 列：8B/行，排序后 delta+RLE，可压到 ~1–2B/行。
- **金字塔每行开销公式**：`bytes/row = Σ_measure S_sketch(measure) × F/(F−1) / leaf_rows_effective`
  （F 叉内部节点总数 ≈ 叶子数/(F−1)；sketch 分层挂载时 leaf_rows_effective = sketch_min_rows）。
- 单 sketch 体积（Doris 实现口径）：
  - count/non_null/sum/min/max：定长 ~8-16B/measure，可忽略；
  - HLL：**用 `be/src/olap/hll.h` 的 explicit/sparse/full 自适应编码**（低基数节点 ≤1.3KB/≤12KB，dense 上限 16KB），
    不要固定 dense；
  - t-digest：~12B/centroid × 容量 2×compression（`tdigest.h`）。与 `percentile_approx` 同口径的
    compression ∈ [2048,10000]（`aggregate_function_percentile.h:64-76`）→ 单 sketch ≈ **49KB~240KB 上界**——
    这才是空间大头，`tdigest_compression` 必须作为索引属性独立可配（并在文档写明与 percentile_approx 默认 10000 的误差口径差异）。
- **分层挂载 `sketch_min_rows`（默认 4×leaf_rows）**：仅子树行数达阈值的节点物化 HLL/t-digest，
  小节点查询时降级行级回算（复用边界精算路径）。示例：leaf_rows=65536、F=16、sketch_min_rows=256Ki、
  compression=2048 → t-digest ≈ 0.2B/行/度量，HLL ≤ 0.07B/行/度量——相对 `__s2` 列本身都可忽略。
- 真正花钱处仍是 **多 measure × 多分辨率**，每多一组 `(度量, sketch 类型)` 多一份，按上式核算后配置。

### 6.1 写入开销预算（rev2.1，按表模型，估算 ±2× 内可信、v0 落地时按 §8.2 实测校准）

背景事实：flush 虽在独立线程池，但有三个反压点（单 writer 在途 flush 数默认 2 `memtable_flush_running_count_limit`、
close 时同步等待、load 内存硬限），flush 吞吐低于摄入吞吐时直接压回导入线程——挂 flush 线程的索引构建并非免费；
这正是 ANN（同步 build faiss，10μs–1ms/行）与 inverted（分词+lucene，1–10μs/行）拖慢导入的机制。

| 阶段 | 每行增量 | DUP 窄表(≤10列) | DUP 中等表(20–50列) | 说明 |
|---|---|---|---|---|
| v0 聚簇 | +100–200ns | −10%~−25% | −3%~−8% | `st_s2_cellid` 求值(~100ns，向量化后 40–60ns)+两 BIGINT 列存储+排序净增。**原无 key 的 DUP 表跳变最大**（丧失零拷贝 swap 快速通道 `memtable.cpp:692`）；原有 key 表净增很小（tie-区间 pdqsort 下原 key 排序工作量等量减少） |
| v1 topology | +15–30ns | −1%~−3% | <−1% | 有序输入 O(n) 流式建树（§4.2），量级≈"多存一个 BIGINT 列+ZoneMap"，比 inverted 轻 ~2 个数量级、比 ANN 轻 3–4 个 |
| v2a count | +2–5ns | <−1% | 可忽略 | 每行 1–2 次自增 |
| v2b 重 sketch（默认 compaction） | ≈0（导入） | ≈0 | ≈0 | compaction CPU +10%~20%（计入 compaction 预算，防版本堆积）；若开 flush 同步读回：+100–250ns/行 → 导入 −5%~−15% |

- **UNIQUE MOW**：基线本有每行 PK 索引+BF 构建、跨 rowset 点查、delete bitmap 三段计算（μs 级/行），HASI 相对占比减半 → 合计 −3%~−8%。
  cluster key 载体的净新增 = memtable 第二遍全量重排（`_sort_by_cluster_keys`，`memtable.cpp:351`）+ PK 编码串内存物化排序 +
  双索引（PK 稠密 + cluster short key），共三次排序；flush 内存峰值升高。**硬约束：cluster key 表不支持 partial update**（`memtable.cpp:703-705`）。
- **AGG**：不支持（写入期聚合、行是部分聚合状态、无 delete bitmap 可扣除，sketch 语义冲突；先例 `AggregateStrategies.java:345-352` 同样只放行 DUP/MOW）。
- 配套优化已入设计：流式单遍建树（§4.2，内存 O(n)→O(F·depth)）、`sketch_min_rows` 天然免除小 segment 重 sketch、
  `tdigest_compression` 默认 2048、HLL 复用自适应编码、load profile 增加 `geo_index_build_ns` 计数器。

---

## 7. 分阶段计划（每阶段独立可交付、可回测、可回退）

> 原则：每阶段有 **(a)** 独立交付物 **(b)** 独立验证出口（不依赖后续阶段） **(c)** 会话级回退开关
> （关掉 = 上一阶段行为）**(d)** 量化通过门槛。kNN 从 R3 拆出为 v4 显式立项。

| 阶段 | 目标 | 交付物 | 验证出口 | 回退开关 |
|---|---|---|---|---|
| **v0** | S2 聚簇 + 谓词改写基线 | ① BE+FE 标量函数 `st_s2_cellid(lon,lat)`（四文件清单，§3.3-1）；② `__s2` 生成列 + 复合排序键（按表模型，§2①）；③ FE `RewriteGeoPredicate`：ST_* → `__s2` 包络区间 conjunct + 保留 ST_* 残差（§3.3-3）；④ `s2_covering.*` + `geo_recheck_simd.h`（BE 单测级，不接查询链路）；⑤ fe-core 引入 `com.google.geometry:s2-geometry:2.0.0`（Apache-2.0，同步 LICENSE/NOTICE）+ **Java↔C++ cell id/covering 跨语言对拍单测**（随机点 + §8.1 cell 边界/face 交界用例）——③ 的多细化区间依赖此项，单包络区间为保底 | 端到端 SQL：开/关改写两次执行结果 bit-exact；profile `RowsKeyRangeFiltered`/`RowsStatsFiltered` 证明剪枝发生；DDL smoke：DUP 生成列进 DUPLICATE KEY 建表+导入+SHOW CREATE 快照，UNIQUE MOW `CLUSTER BY` 含生成列建表对拍（FE 校验可过但无回归先例，落为被测事实；失败则 UNIQUE 路线降级为 `__s2` 进 unique key 前缀） | `set enable_geo_predicate_rewrite=false` |
| **v1** | 检索下推（索引全链路） | `IndexType::GEO` 全链路（§3.1 八项）；`geo_index/` writer/reader/iterator + `geo_range_runtime`；BE 侧 conjunct 识别（§3.3-4 rev2.3，无 thrift plan 字段）；`_apply_geo_predicate()` `&=` 收窄 + 代价门槛（covering 占键空间 >50% 放弃）；profile 计数器 `RowsGeoIndexFiltered`/`GeoBoundaryRecheckRows`/`GeoBoundaryLeaves`；compaction 期索引随写路径**全量重建**（零特判，实测通用） | 索引开/关对拍 bit-exact；compaction 前后、MOW upsert+delete 后对拍；非 key 形态对拍；profile 断言 `RowsGeoIndexFiltered>0` | `set enable_geo_index_query=false`（回落 v0） |
| **v1 已落地形态与偏差（rev2.3 纪要）** | — | ① **候选+残差复检模型**：索引只做 `_row_bitmap &= hit`（`hit ≡ {cell∈C}`，NULL 行不命中），原 ST_\* 谓词保留在计划里做精确过滤——C1/C2 由结构保证；"INSIDE 免几何精算"（识别后从 `_remaining_conjunct_roots` 摘除 + 余量带行读 lon/lat 精算）列为 **v1.5**，是 v1 性能门槛（大 region ≥3×）不达标时的已知抓手。② **v1 树 = 扁平叶目录**（定长行块 + 每叶 min/max cell + 每行 zigzag-varint delta cell 流，~1-3B/行）：不做 distinct-cell 对齐分裂（那是 v2 金字塔 sketch 的不相交前提），叶区间允许重叠——聚簇表得整叶 skip/accept 快路径，**非 key 表退化为逐行三分过滤**（同一格式天然覆盖 §9-7 的"非聚簇降级模式"）；隐式 F 叉金字塔随 v2a 挂 sketch 时落地。③ 索引文件整体 eager 加载（DorisCallOnce），叶 cell 流懒解码在查询内；大 segment 懒加载留 TODO。④ 挂载点在 `_get_row_ranges_by_column_conditions` 的 inverted/ann 块之后（delete bitmap 减除之前——纯 `&=` 下位置无关正确性）。⑤ 依赖 `enable_common_expr_pushdown`（默认开）把谓词送进 segment iterator；关闭时索引静默不生效、结果仍正确。 | 见 `geo_index_range_search.groovy` | 同上 |
| **v2a** | 聚合下推·count-only | 在 v1 已建 topology 之上增加 count/non_null sketch（仅 `__s2` 列自身可得，零跨列改动）+ `aggregate()` + 全部正确性 gate（时间三态/删除三级/残余谓词/表模型/sketch 存在性，§5.2）；FE `PushDownGeoAgg`（COUNT_ON_INDEX 式计划形态） | count 类聚合与关闭下推 bit-exact（含 delete、多 segment、时间不对齐桶边界场景） | `set enable_geo_agg_pushdown=false` |
| **v2b** | 聚合金字塔·全度量 | measure sketch（sum/min/max/HLL/t-digest），**构建时机默认 = compaction 读回**（§3.5，flush 同步为可选开关）；per-rowset sketch 存在性 gate（缺失→INSIDE 流式行扫折叠）；sketch 分层挂载 + blob 懒加载；scan 内边界折叠回流（§3.3-5） | sum/min/max bit-exact；HLL 相对误差 ≤2%、t-digest 分位误差 ≤1%（对拍同函数非下推执行）；**“面积倍增、延迟平坦”曲线**（代价∝边界的直接证据）；导入吞吐无回退（±2%，v2b 不在导入关键路径） | 同上（粒度到 rule） |
| **v3** | 增量与调优 | compaction 子树 roll-up 快路径（检测条件+回退全量重建，§3.5）；学习导航层；多 measure/多分辨率配置；（可选）分桶裁剪方案 A | 增量 roll-up 与全量重建对拍 bit-exact；学习导航开/关结果一致；compaction 索引耗时下降 | BE conf `enable_geo_index_incremental_compaction=false` |
| **v4** | kNN（R3 收口） | FE `PushDownGeoTopNIntoOlapScan`（仿 `PushDownVectorTopNIntoOlapScan.java`）+ thrift `geo_sort_info`；BE 树上 best-first（§5.4） | 与 `ORDER BY ST_Distance_Sphere(...), id LIMIT k` 全排序对拍 bit-exact（加 id 消除并列距离不确定性） | `set enable_geo_knn_pushdown=false` |

**阶段依赖**：v0→v1→{v2a→v2b, v4 并行}→v3。v2a 与 v4 都只依赖 v1。

**每阶段性能通过门槛（基线与测法见 §8）**：

| 阶段 | 基线 | 门槛 |
|---|---|---|
| v0 | 关改写全表 ST_* | 小圆（1km）p50 ≥5×；`RowsKeyRangeFiltered+RowsStatsFiltered ≥ 90%` 总行数（合成均匀集） |
| v1 | v0 | 大 region（100km+）p50 ≥3×（免精算收益）；`GeoBoundaryRecheckRows/命中行数` ≤ 理论边界占比×1.5 |
| v2a/v2b | v1 检索+普通聚合 | 区域 count/sum ≥10×；**面积 4× 时延迟增幅 ≤1.3×**（∝边界验证） |
| v3 | v1 全量重建 compaction | compaction 索引耗时 ≤50%；查询性能无回退（±5%） |
| v4 | 全排序 topn | k=100 城市中心 p50 ≥5× |

---

## 8. 测试与验证（回测方案 + 基准 harness）

### 8.1 正确性回测（每阶段全绿才能进入下一阶段）

**对拍方法**：同一张表、同一条查询，`set <阶段开关>=true/false` 各执行一次，逐行比较（严格 `ORDER BY id`）。
精确结果 bit-exact；近似 sketch（HLL/t-digest）用相对误差界。用例风格仿
`regression-test/suites/ann_index_p0/ann_range_search.groovy`（建表带 INDEX → 插入 → qt_ 快照），
索引生效断言仿 `ann_index_only_scan.groovy` 的 profile REST 方式
（`set profile_level=2; set enable_profile=true;` 后取 `/rest/v1/query_profile` 的 `RowsGeoIndexFiltered`）。

**SQL 用例集（按仓库真实函数签名）**：
```sql
-- 半径（4 参签名，StDistanceSphere.java:40）
SELECT count(*) FROM t WHERE ST_Distance_Sphere(lon, lat, :lon0, :lat0) < :r;
-- 多边形 contains
SELECT id FROM t WHERE ST_Contains(ST_Polygon(:wkt), ST_Point(lon, lat)) ORDER BY id;
-- bbox：矩形 polygon 表达
-- 聚合（v2）：count / sum(amount) / min / max / HLL 去重 / percentile，同 WHERE
-- kNN（v4）：SELECT id FROM t ORDER BY ST_Distance_Sphere(lon,lat,:lon0,:lat0), id LIMIT :k;
```

**边界 case 矩阵（每阶段回归全跑）**：

| 类别 | 用例 |
|---|---|
| 极点 | 圆心 lat=±90；半径覆盖极点的圆；含极点的多边形（内框退化路径） |
| 反子午线 | 跨 ±180° 的圆/多边形；lon=180 与 lon=-180 的点等价性；±180 附近的**贴边点**（平面 TOLERANCE 距离在此失真，行为必须锁定与全表一致） |
| 贴边/ULP | 距圆周 ±米级 1e-7~1e-9 的点环（haversine vs chord 语义差）；距多边形边 0~2e-6 度的贴边点（TOLERANCE 侵蚀验证，interior 免精算行集必须 ⊆ 全表 ST_* 结果） |
| 空 region | 半径 0；退化多边形；与数据不相交的 region |
| 全球 region | 半径 ≥ 20015km；覆盖全球的多边形（等价全表，验证 covering 上限不爆炸） |
| NULL/非法 | lon/lat 为 NULL 的行（谓词求值非 true → 不命中，开/关一致）；lat>90 非法坐标 |
| cell 边界 | 恰在 S2 cell 边界、cube face 交界的点；最后一个 face 尾部 cell（CellRange 上界回绕） |
| 存储形态 | 多 segment（多次导入不 compact）/ compaction 后 / MOW delete 后（sketch 降级验证）/ 时间谓词不对齐桶边界 |

**BE 单测**（放 `be/test/olap/rowset/segment_v2/geo_index/`，模板参考 `be/test/olap/vector_search/*_test.cpp` 九件套）：
covering interior/boundary 划分（随机 region × 随机点暴力对拍）、金字塔 build/save/load roundtrip、
三态分类 DFS 与逐 cell 暴力判定等价、sketch merge 结合律与幂等、`geo_recheck_simd` 与标量 S2 判定逐点一致（含环带边缘）、
`_rid`/NULL 行号核算、v3 增量 roll-up 与全量重建等价。

### 8.2 性能回测纪律
- **数据集规模**：功能级 1e6（p0，分钟级）；性能级 1e8 单 BE（p1/nightly）；1e9–1e10 三节点（发布前手动）。
- **测量**：每条查询 cold（清 page cache）+ hot 各 3 轮取中位；报 p50/p95；同时采集 profile 行数计数器做**归因**——
  速度提升必须能被剪枝计数解释，否则视为无效通过。
- **回退验证**：每阶段附带"开关关闭"运行，确认回退路径结果正确且性能等于上一阶段基线（防开关名存实亡）。
- **导入吞吐测法**（§6.1 预算校准 + §7 v2b "±2%" 门槛的判定口径）：固定数据集（合成-倾斜 1e8）stream load，
  被测开关（v0 聚簇 DDL / v1 索引 / v2b flush 同步读回）开与关各跑 ≥3 轮取中位吞吐对比；
  采集 load profile 的 `geo_index_build_ns` 做归因（吞吐差必须能被该计数解释）；
  v0 基线 = 同 schema 无 `__s2`/排序键的裸表，v1/v2b 基线 = 前一阶段开关关闭。

### 8.3 贯穿各阶段的基准 harness

**目录组织（对齐仓库现状）**：
```
regression-test/suites/geo_index_p0/          # 功能正确性（仿 ann_index_p0/ 扁平命名）
  create_geo_index_test.groovy                # DDL/属性校验/不支持类型与表模型报错/ALTER 拒绝
  s2_generated_column.groovy                  # v0: __s2 生成列 + 排序键
  geo_rewrite_range_search.groovy             # v0: 谓词改写开/关对拍
  geo_index_range_search.groovy               # v1: 圆/bbox/polygon 对拍
  geo_index_edge_cases.groovy                 # 极点/反子午线/贴边/空/全球/NULL 矩阵
  geo_index_mow_delete.groovy                 # MOW delete + sketch 降级回落
  geo_index_compaction.groovy                 # compaction 前后对拍（v1 全量重建、v3 增量；
                                              #  v2b: 未 compact 时存在性 gate 降级对拍 + compact 后 sketch 路径 profile 断言）
  geo_agg_pushdown.groovy                     # v2a/v2b: 精确聚合对拍 + profile 断言
  geo_agg_sketch_accuracy.groovy              # v2b: HLL/t-digest 误差界（含层层合并衰减曲线）
  geo_knn.groovy                              # v4: 与全排序对拍
  geo_index_fallback_switch.groovy            # 所有开关的回退等价性
regression-test/data/geo_index_p0/*.out       # qt_ 快照
regression-test/suites/geo_bench_p2/          # 真实数据性能（仿 opensky_p2/：ddl/ + load.groovy + sql/）
  ddl/osm_points.sql  load.groovy  sql/q_circle_small.sql ... sql/q_agg_city.sql
tools/hasi-bench/                             # 跨引擎对照 harness（仿 tools/clickbench-tools/）
  gen_synthetic.py   queries/*.sql|*.es.json|*.pg.sql   run.sh   report.py
```

**数据集**：
1. **合成-均匀**：全球均匀 1e6/1e8（datagen → stream load，仿 `opensky_p2/load.groovy`）。
2. **合成-倾斜（必测，均衡分裂的命根子）**：90% 点落 200 个城市高斯簇（σ=5km）+ 9% 道路线状 + 1% 海洋均匀；固定随机种子。
3. **真实**：仓库已有 `opensky_p2`（~3 千万行真实航班经纬度，`sql/avgDistance.sql` 已在用 `st_distance_sphere`）——零成本起步；
   再加 OSM planet nodes 抽样 1e8/1e9 作主力集（托管 regression S3 bucket，同 opensky 模式）。

**查询套件（每数据集固定 ~40 条，Q1–Q40）**：小/大圆（100m/1km/10km/100km/1000km × 圆心在城市簇/海洋/极点/反子午线）、
bbox 同尺度、多边形（凸 6 边/凹 50 边/带洞/跨反子午线）、kNN（k=1/10/100/1000）、
区域聚合（count / count+sum / HLL / t-digest × 小中大 region）、时空复合（命中 1 桶 / 全部桶 / 不对齐桶边界）。

**对照系**：① Doris 关全部 geo 开关；② Doris 仅 v0 聚簇；③ Doris 当前阶段全开；
④ ES 8.x `geo_point`（geo_distance/geo_bounding_box/geo_polygon/geo 聚合，R7 直接对手）；
⑤ PostGIS GiST（正确性金标准兼性能参照）。ES/PostGIS 在 `tools/hasi-bench/` 内跑，不进 regression-test。

**结果表格式（`report.py` 输出 CSV + Markdown，进版本库留痕）**：

| dataset | rows | engine_config | query_id | region_type | selectivity | cold_hot | p50_ms | p95_ms | rows_returned | rows_index_filtered | boundary_recheck_rows | speedup_vs_baseline | gate | pass |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| osm_1e8 | 1e8 | doris_v2b | Q17_agg_city_100km | circle | 0.8% | hot | 12 | 18 | 1 | 9.9e7 | 3.1e5 | 34× | ≥10× | ✅ |

**每阶段发布判定 = 正确性用例全绿 + 门槛列全 pass + 回退开关等价性通过。**

---

## 9. 风险与边界（诚实记录）
1. **删除/更新与 sketch**：HLL/t-digest 可并不可减。**正确性由查询期三级 gate 保证**（FE 表模型 gate /
   rowset 级 delete predicate 回退 / segment 级 delete bitmap 节点降级，§5.2）；compaction 重算只是
   把降级比例收敛回去的优化。检索路径的删除正确性由 `&=` 收窄契约（C1）独立保证。
2. **倾斜**：均衡分裂是命根子；分裂点强制对齐 distinct cell 边界（防同 cell 高频打点破坏区间不相交）；
   分桶方案见 §3.3-6（POC 选 B，热点风险留给方案 A 评估）。
3. **ad-hoc 度量**：金字塔只覆盖预定义 measure 集；未预聚合度量回落检索路径（INSIDE 块整体流式 + SIMD，仍快于 ES）。
4. **学习导航**：对分布漂移敏感 → 只当加速层，compaction 随子树重训；正确性永远以排序数据为准。
5. **收益分层**：区域聚合/大区域 = 数量级；小区域高选择度点查 = 2–5×（ES BKD 本就强，不夸大）。
6. **t-digest 层层合并精度衰减**：HASI 是"叶→根多层合并 + 跨桶/跨 segment 再合并"的最坏形态，
   p99/p999 误差会大于直接 `percentile_approx`。缓解：t-digest 只挂粗层节点（细层本就走行级精算）；
   §8 固化"分位误差 vs 直接执行"的衰减曲线；必要时换误差有界于合并的 KLL/REQ 类 sketch。
7. **存量表**：POC 不支持 ALTER 加 GEO 索引（FE 直接报错，§3.1-7）——存量数据未按 `__s2` 聚簇，
   "叶子=连续行块"不成立。未来若支持，需设计非聚簇降级模式（叶子存 roaring 行集，检索可用、
   聚合/整块 accept 降级），并写明性能声明按模式区分。
8. **排序键载体**：DUP 表用可见生成列进 key 前缀（机制现成）；"隐藏 key 列"是全新机制
   （波及 SHOW CREATE / SELECT * / short key / rollup / schema change 等所有"key=用户声明前缀"假设），
   不在 POC 范围。UNIQUE MOW 走 cluster key；AGG 不支持。
9. **枚举链路**：GEO 类型贯穿 proto/thrift/FE 两套枚举/toThrift/toPb/init_from_thrift 共八处（§3.1），
   靠护栏单测防漏，以 ANN 引入 commit 的文件清单为核对基准。
10. **IndexFileWriter/Reader 门控暗链（v1 实测踩坑）**：§3.1 的八处枚举之外还有一条更隐蔽的链——
    BE 里 16 处 `has_inverted_index() || has_ann_index()` 门控（segment_creator/beta_rowset_writer/
    vertical_beta_rowset_writer/beta_rowset 读侧/segcompaction/snapshot_manager/cloud 四处）决定
    是否创建/打开索引文件 writer/reader。漏掉任何一处，只含 GEO 索引的表在 flush 或查询时对空
    `IndexFileWriter*` 解引用直接 SIGSEGV（release 版 DCHECK 不生效；v1 首轮回归即触发）。
    已全部扩展为 `|| has_geo_index()`，并在 `GeoIndexColumnWriter::init` 加了空指针防线;
    未来新增索引类型时此清单与 §3.1 同级必查。

---

## 附：关键源码锚点速查（rev2 全部经源码核对）
| 用途 | 位置 |
|---|---|
| 索引类型枚举(proto / thrift) | `gensrc/proto/olap_file.proto:400-406`；`gensrc/thrift/Descriptors.thrift:223` |
| 索引类型/校验(FE) | `IndexDef.java:208/:220/:240`（legacy）；`nereids/.../info/IndexDefinition.java`（Nereids 入口）；`Index.java` toThrift`:304`/toPb`:324-347` |
| 写入基类/工厂 | `index_writer.h:49`；`index_writer.cpp:49`（工厂）`:68`(inverted)/`:128`(ann，`:129` DCHECK ARRAY 勿抄) |
| 读取/迭代基类 | `index_reader.h:36`、`index_iterator.h:48` |
| ANN 模板 | `be/.../segment_v2/ann_index/`；单测 `be/test/olap/vector_search/`（9 件） |
| 写路径挂载（**Scalar**） | `column_writer.cpp:548-550`(init 建 builder) / `:573-576`(add_nulls) / `:610`(喂值) / `:773-776`(finish)；`_rid` 模式 `inverted_index_writer.cpp:270-272` |
| segment 级读回构建 | `be/src/olap/task/index_builder.cpp:762/:798`；SegmentWriter 钩子候选 `segment_writer.cpp:673` |
| 读路径挂载 | `segment_iterator.cpp:392`(调用)/`:1332`(定义)；ANN topn `:695`(调用 `:427`)；range search `:614`→`:1020-1034`；delete bitmap 减除 `:411-419`；30% 门槛 `:750-761`；运行时复核 `:705-716`；delete predicate 判法 `:2939-2941` |
| compaction | 基线随写路径全量重建（ANN 模式）；lucene 合并参考 `inverted_index_compaction.h:35`（接口不复用）；vertical 列组 `merger.cpp:168-241` |
| 删除语义 | `beta_rowset_reader.cpp:130-134`(delete predicate)/`:171-186`(delete bitmap) |
| 聚合下推先例 | `AggregateStrategies.java:308-311`(开关)/`:345-352`(表模型 gate)/`:384-394`(计划形态)/`:581-596`(null slots)；`PlanNodes.thrift:823`(TPushAggOp) |
| kNN 先例 | `PushDownVectorTopNIntoOlapScan.java`；`PlanNodes.thrift:855-856`(ann_sort_info) |
| 分桶裁剪现实 | `HashDistributionPruner.java:39-51/:103-117`；`Config.java:1324`(上限 100)；`ExpressionColumnFilterConverter.java:103-106` |
| 生成列/排序键 | `GeneratedColumnDesc.java`；`CreateTableInfo.java:623-629`(cluster key)/`:1088-1089`(生成列可做 key)/`:1226-1237`(表达式须已注册函数)；`memtable.cpp:192`(key 前缀+NULL 排序方向) |
| ALTER 拒绝点 | `SchemaChangeHandler.java:2780`(processAddIndex)；`BuildIndexClause.java:109-113` |
| S2 几何封装 | `geo_types.h:65/:89/:172/:243`；`geo_types.cpp:54`(TOLERANCE)/`:624`(ComputeDistance, 半径 6371010.0)/`:1556`(GeoCircle::contains) |
| S2 头文件 | `thirdparty/installed/include/s2/`：`s2cell_id.h:90`(6 faces)/`:254-275`(range_min/max)；`s2cell_union.h:109`(FromMinMax)/`:224`(Difference)；`s2cell.h:141`(GetDistance)；`s2cap.cc:183-186`(GetRectBound) |
| 标量 geo 函数 | `functions_geo.cpp:45/:197/:456/:540`；`BuiltinScalarFunctions.java:1042-1062`；`StDistanceSphere.java:40-47`(4 参签名)；**无 ST_Within** |
| sketch 体积口径 | `be/src/olap/hll.h`(自适应编码)；`tdigest.h`(~12B/centroid×2×compression)；`aggregate_function_percentile.h:64-76`(compression∈[2048,10000]) |
| 回归测试先例 | `ann_index_p0/ann_range_search.groovy`、`ann_index_only_scan.groovy`(profile 断言)、`test_count_on_index.groovy`、`opensky_p2/`(数据+st_distance_sphere)、`ddl_p0/test_create_table_generated_column/`、`tools/clickbench-tools/` |
| **v1 已落地文件清单（rev2.3）** | BE `geo_index/`：`hasi_tree.{h,cpp}`（叶目录+流式构建+三态检索）、`geo_index_writer.{h,cpp}`、`geo_index_reader.{h,cpp}`、`geo_index_iterator.h`（get_reader 类型感知，防 __s2 范围谓词被误路由进倒排求值）、`geo_range_runtime.{h,cpp}`（BE 谓词识别+covering+代价门槛）、`geo_index_properties.h`；挂载改动：`index_writer.{h,cpp}`(工厂+check_support_geo_index)、`column_writer.{h,cpp}`(Scalar 挂载+write_geo_index)、`segment_writer.*`/`vertical_segment_writer.*`、`tablet_schema.*`(geo_index 访问器)、`tablet_meta.cpp`、`column_reader.cpp`、`index_iterator.h`(GeoIndexReaderType)、`segment_iterator.{h,cpp}`(`_apply_geo_predicate` + `_check_apply_by_inverted_index` 非倒排闸门)、`olap_common.h`+`olap_scan_operator.*`+`olap_scanner.cpp`(计数器)；FE：`GeoIndexUtil.java`(属性校验+生成列匹配+lng/lat 回填)、`IndexDef.java`、`IndexDefinition.java`、`Index.java`、`CreateTableInfo.java`、`SchemaChangeHandler.java`(ALTER 拒绝)、`LogicalPlanBuilder.java`、`DorisLexer/Parser.g4`、`SessionVariable.java`；gensrc：`olap_file.proto`(GEO=5)、`Descriptors.thrift`(GEO=5)、`PaloInternalService.thrift`(TQueryOptions.204)；单测：BE `hasi_tree_test.cpp`、FE `IndexTest`(枚举护栏)+`IndexDefinitionTest`(GEO checkColumn)；回归：`geo_index_p0/create_geo_index_test.groovy`、`geo_index_p0/geo_index_range_search.groovy` |
