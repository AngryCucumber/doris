# HASI —— 万亿级 geo_point 层次聚合空间索引 POC

> Hierarchical Aggregating Spatial Index
> 自研空间索引，目标在区域聚合 / 范围 / 距离 / contains / kNN 查询上**整体快于 Elasticsearch(Lucene BKD)**。
> 本文结合当前仓库源码给出落地设计、改造点（精确到 file:line）与代码骨架。

---

## 0. 需求（本 POC 必须满足的）

| # | 需求 | 说明 |
|---|---|---|
| R1 | **万亿行**可用 | 1e12 量级，查询不能正比于总点数 |
| R2 | 支持**区域聚合** | `count / sum / min / max / 去重(HLL) / 分位数(t-digest)`，按任意 region |
| R3 | 支持**范围/框、半径距离、多边形 contains、kNN** | 检索类查询 |
| R4 | 支持**地理计算**下推 | `ST_Distance_Sphere / ST_Contains / ST_Within` 等谓词在存储层求值 |
| R5 | **自研**索引，复用现有架构 | 不引第三方索引引擎；复用 Doris 分区/分桶/compaction/MPP |
| R6 | **可接受空间换时间** | 允许预聚合金字塔带来的额外存储 |
| R7 | **比 ES 更快** | 核心指标：区域查询代价 ∝ **边界(周长)** 而非面积；区域聚合期望 10–100×，检索期望 2–5× |

**核心原理（一句话）**：别人逐个 recheck 区域内的点（代价 ∝ 面积内点数）；HASI 让**完全落在 region 内的层次 cell 直接返回预聚合值（O(1)，不下钻）**，只有跨越 region 边界的 cell 才扫描精算 —— 于是代价 ∝ 边界。

---

## 1. 现状盘点（已具备的地基）

调研结论：**两个关键地基已经就绪**，自研成本远低于从零开始。

### 1.1 S2 几何库已集成（无需引新依赖）
- thirdparty 已打包 `thirdparty/src/s2geometry-0.10.0.tar.gz`，编译产物在 `installed/include/s2/`，含
  `s2/s2cell_id.h`、`s2/s2region_coverer.h`、`s2/s2cap.h`、`s2/s2latlng.h`、`s2/s2polygon.h`。
- `be/src/geo/geo_types.h` 已用 S2 封装好查询几何：
  - `GeoPoint`（内含 `S2Point`），`be/src/geo/geo_types.h:89`
  - `GeoPolygon`（内含 `S2Polygon`），`be/src/geo/geo_types.h:172`
  - `GeoCircle`（内含 `S2Cap`），`be/src/geo/geo_types.h:243`
  - 统一基类 `GeoShape::contains()`，`be/src/geo/geo_types.h:65`
- 标量函数已存在：`ST_Point / ST_Distance_Sphere / ST_Contains / ST_Circle / ...`
  实现见 `be/src/vec/functions/functions_geo.cpp`，FE 注册见
  `fe/fe-core/src/main/java/org/apache/doris/catalog/BuiltinScalarFunctions.java`。

> 含义：HASI 的"几何 → S2 cell 覆盖(covering)"、"点是否在 region 内"全部可直接复用现有 S2，
> 只需补一个 `S2RegionCoverer` 包装层。

### 1.2 自定义索引框架已成熟，ANN 是完美模板
索引抽象（与列解耦、独立索引文件、按 `IndexType` 工厂分发）：

| 角色 | 基类 | 文件 |
|---|---|---|
| 写入 | `IndexColumnWriter` | `be/src/olap/rowset/segment_v2/index_writer.h` |
| 读取 | `IndexReader` | `be/src/olap/rowset/segment_v2/index_reader.h` |
| 迭代 | `IndexIterator` | `be/src/olap/rowset/segment_v2/index_iterator.h` |
| 工厂 | `IndexColumnWriter::create()` | `be/src/olap/rowset/segment_v2/index_writer.cpp:49` |

**ANN（向量索引）是最近新增的同构索引，照抄它即可**：
- 目录 `be/src/olap/rowset/segment_v2/ann_index/`（writer/reader/iterator/runtime 全套）
- 工厂分发：`index_writer.cpp` 中 `is_inverted_index()` / `is_ann_index()` 分支（`index_writer.cpp:127` 起）
- 写路径挂载：`column_writer.cpp:1037`（建 inverted writer）、`column_writer.cpp:1045`（建 `_ann_index_writer`）、`:1098`（喂 `add_array_values`）、`:1062`（`finish`）
- 读路径挂载：`segment_iterator.cpp:392` `_init_index_iterators()`；`segment_iterator.cpp:695` `_apply_ann_topn_predicate()`；`segment_iterator.cpp:765` `evaluate_vector_ann_search(ann_index_iterator, &_row_bitmap, ...)` —— **索引算完把命中行写进 `_row_bitmap`**，这正是 HASI 检索下推要复用的出口
- 索引类型枚举：proto `gensrc/proto/olap_file.proto:400`（`BITMAP=0 … ANN=4`）；FE `IndexDef.java:208`（枚举）、`:220`（`isAnnIndex`）、`:240`（`checkColumn`）
- compaction 合并钩子：`be/src/olap/rowset/segment_v2/inverted_index_compaction.h:35` `compact_column(...)`

> 结论：HASI 走 `TabletIndex` + 独立索引文件路线（与 ANN/inverted 一致），新增 `IndexType::GEO = 5`，
> 新建 `geo_index/` 目录，照 `ann_index/` 复刻一套。

---

## 2. HASI 总体架构（四层）

```
                         查询几何 (GeoCircle/Polygon/box)
                                    │  S2RegionCoverer
                                    ▼
   ┌───────────────────────── HASI 树遍历（每节点三态）─────────────────────────┐
   │  完全在内 → 取节点预聚合 sketch（聚合O(1)）/ 整块行 accept（检索免recheck） │
   │  完全在外 → 剪枝                                                            │
   │  边界相交 → 下钻；叶子做 ④ 双框+SIMD 精算                                   │
   └───────────────────────────────────────────────────────────────────────────┘
        ① 基础数据按 S2 Hilbert 序聚簇      ② HASI 树+聚合金字塔（本索引）
        ③ 学习型导航（可选加速）            ④ 双框 prefilter + SIMD 精算核
```

- **① 复合聚簇 `(time_bucket, __s2)`**（**已定**）：隐藏生成列 `__s2 BIGINT`（S2 叶子 cell id），
  与粗时间桶组成**复合排序键** `ORDER BY (time_bucket, __s2)` —— 先按时间桶分段，**桶内**按空间 Hilbert 序聚簇。
  含义：① 时空查询天然先吃**时间分区/桶裁剪**，再吃**桶内空间 cell 范围扫**；② HASI 树**按 (time_bucket) 分段建/合并**
  （每个时间桶一棵子树，覆盖查询=对命中的若干时间桶各做一次空间 covering 扫）；③ 排序后 `__s2` 在桶内仍高度有序，
  delta+RLE 压缩不受影响。`time_bucket` 粒度（小时/天）按写入与查询的时间窗权衡，作为 GEO 索引属性可配。
- **② HASI 树（核心索引文件）**：按**数据量均衡分裂**的 S2/四叉树（每叶子 ≤ N 行，应对城市/海洋倾斜）。
  每个**内部节点**持久化子树的可合并 sketch（count/sum/min/max/HLL/t-digest）→ 树即多分辨率聚合金字塔。
- **③ 学习型导航（可选）**：`cell_id → 行块 offset` 的分段线性模型，替代树下降的二分；**只加速，不决定正确性**。
- **④ 精算核**：内接框 accept / 外接框 reject / 仅环带做精确 `S2`/haversine；SIMD 批量。

---

## 3. 改造清单（精确到文件）

### 3.1 Proto —— 新增 GEO 索引类型
`gensrc/proto/olap_file.proto:400`
```proto
enum IndexType {
    BITMAP = 0;
    INVERTED = 1;
    BLOOMFILTER = 2;
    NGRAM_BF = 3;
    ANN = 4;
    GEO = 5;          // <-- HASI
}
```
> HASI 数据走独立索引文件（同 ANN），不需要往 `segment_v2.proto` 的 `ColumnIndexMetaPB` 加内嵌结构；
> 索引内部的页/节点布局自定义序列化（见 §4.2）。

### 3.2 FE —— 索引定义与校验
`fe/fe-core/src/main/java/org/apache/doris/analysis/IndexDef.java`
```java
// :208 枚举加 GEO
public enum IndexType { BITMAP, INVERTED, BLOOMFILTER, NGRAM_BF, ANN, GEO }

// 仿 :220 isAnnIndex()
public boolean isGeoIndex() { return this.indexType == IndexType.GEO; }

// :240 checkColumn() 内增加分支
if (indexType == IndexType.GEO) {
    // 仅允许建在 geo_point/经纬度对 或 已生成的 __s2 BIGINT 上
    if (!GeoIndexUtil.isSupportedColumn(column)) {
        throw new AnalysisException("GEO index only supports geo_point / (lat,lon) columns");
    }
    // 属性：s2_min_level/s2_max_level/leaf_rows/measures(预聚合度量集)
    GeoIndexUtil.checkProperties(properties);
}
```
新增 `fe/.../analysis/GeoIndexUtil.java`（仿 `InvertedIndexUtil.java`）：解析 `s2_min_level`、`s2_max_level`、
`leaf_rows`、`measures="count,sum(amount),hll(uid),tdigest(latency)"`。

### 3.3 FE —— 隐藏 `__s2` 聚簇列 + Nereids 下推
1. **建表时生成隐藏列 + 复合排序键（已定）**：当列上声明 `GEO` 索引时，自动生成 `__s2_<col> BIGINT`
   （值 = `S2CellId(lat,lon).id()`），并构造**复合排序键 `(time_bucket, __s2)`**：
   `time_bucket` 取建表指定的时间列按 `s2_time_bucket`（默认 `HOUR`/`DAY`）截断生成的隐藏列，排在 key 前；`__s2` 紧随其后。
   落点：`CreateTableCommand` / `OlapTable` 列与 keysColumn 构造处；需保证两隐藏列在 DUP key（或 UNIQUE key 末段）中相邻有序。
   > 若表无显式时间列：退化为单键 `(__s2)`（纯空间聚簇），其余逻辑不变。
2. **谓词/聚合下推规则**（新增 Nereids rule，仿 ANN topn 的注入方式）：
   - `PushDownGeoFilter`：识别 `ST_Distance_Sphere(geo, p) < r`、`ST_Contains(poly, p)`、bbox →
     生成 `GeoIndexFilter(shape, covering)` 物理属性 + 残差精确谓词。
   - `PushDownGeoAgg`：识别 `SELECT agg(m) ... WHERE <geo region>`，命中预聚合度量集时路由到 HASI sketch；
     边界 cell 生成"回原始数据精算"子计划 union。
3. **Thrift 透传**：在 `gensrc/thrift/` 的 scan range / OlapScanNode 选项里增加 `TGeoIndexFilter`（shape WKB + 度量列表），
   下发到 BE（仿 ANN 的 `ann_topn` 透传）。

### 3.4 BE —— 新建 `be/src/olap/rowset/segment_v2/geo_index/`
照 `ann_index/` 结构：
```
geo_index/
  CMakeLists.txt
  s2_covering.h / .cpp          # GeoShape -> cell-id 区间 + RegionCoverer（自适应多分辨率）
  hasi_tree.h / .cpp            # 节点结构 + 可合并 sketch + 序列化/反序列化
  hasi_sketch.h                 # count/sum/min/max/HLL/t-digest 包装（可合并接口）
  geo_index_writer.h / .cpp     # : public IndexColumnWriter   （仿 ann_index_writer）
  geo_index_reader.h / .cpp     # : public IndexReader          （仿 ann_index_reader）
  geo_index_iterator.h / .cpp   # : public IndexIterator        （仿 ann_index_iterator）
  geo_range_runtime.h / .cpp    # 检索下推：算命中行 -> _row_bitmap （仿 ann_topn_runtime）
  geo_agg_runtime.h / .cpp      # 聚合下推：满覆盖取 sketch + 边界回算
  geo_recheck_simd.h            # 双框 prefilter + SIMD haversine / 点在多边形
```

### 3.5 BE —— 工厂与读写挂载点
- `index_writer.cpp:49 IndexColumnWriter::create()`：在 `is_ann_index()` 分支后加
  ```cpp
  } else if (index_meta->is_geo_index()) {
      *res = std::make_unique<GeoIndexColumnWriter>(index_file_writer, index_meta);
      RETURN_IF_ERROR((*res)->init());
  }
  ```
  （`TabletIndex::is_geo_index()` 仿 `is_ann_index()` 增加，落点 `be/src/olap/tablet_schema.{h,cpp}`）
- 写路径 `column_writer.cpp:1045` 旁：建 `_geo_index_writer`；`:1098` 旁喂值；`:1062` 旁 `finish()`。
- 读路径 `segment_iterator.cpp:392 _init_index_iterators()`：为 GEO 列建 `GeoIndexIterator`；
  新增 `_apply_geo_predicate()`（仿 `_apply_ann_topn_predicate()` 在 `:695`），把命中行写入 `_row_bitmap`（`:765` 同款出口）。
- compaction `inverted_index_compaction.h:35` 同级新增 `geo_index_compaction`：合并子树并 **roll-up sketch**（增量维护，无全局重建）。

---

## 4. 核心代码骨架（PoC 级，结构对齐 ANN，标注 TODO）

### 4.1 S2 覆盖工具 `s2_covering.h`
```cpp
#pragma once
#include <s2/s2cell_id.h>
#include <s2/s2region_coverer.h>
#include <cstdint>
#include <vector>
#include "be/src/geo/geo_types.h"   // 复用已封装的 GeoCircle/GeoPolygon(S2Cap/S2Polygon)

namespace doris::segment_v2 {

// 一段闭区间 [lo, hi] of S2 cell ids（Hilbert 序连续）
struct CellRange { uint64_t lo; uint64_t hi; };

// 编码：经纬度 -> 叶子 cell id（建表/写入时给 __s2 列用）
inline uint64_t s2_leaf_id(double lat_deg, double lon_deg) {
    return S2CellId(S2LatLng::FromDegrees(lat_deg, lon_deg)).id();
}

// 自适应多分辨率覆盖：内部用大 cell、边界用小 cell，压低区间数与假阳性面积
class S2Covering {
public:
    S2Covering(int min_level, int max_level, int max_cells)
        : _min_level(min_level), _max_level(max_level), _max_cells(max_cells) {}

    // region 由 GeoShape 提供（GeoCircle::circle()->S2Cap / GeoPolygon::polygon()->S2Polygon）
    // 输出：covering 区间（用于 cell 范围扫）+ 标记每个 cell 是否“完全在 region 内”
    void cover(const S2Region& region,
               std::vector<CellRange>* ranges,
               std::vector<CellRange>* interior_ranges /*满覆盖，可走 sketch / 免 recheck*/);

private:
    int _min_level, _max_level, _max_cells;
    // 用 S2RegionCoverer 得 covering；再用 GetInteriorCovering 得 interior。
    // interior_ranges 对应 §2 图中“绿色 cell”，ranges\interior 即“橙色边界 cell”。
};

} // namespace doris::segment_v2
```

### 4.2 HASI 树与 sketch `hasi_tree.h`
```cpp
#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include "hasi_sketch.h"

namespace doris::segment_v2 {

// 可合并聚合：满足 merge() 即可挂到内部节点（count/sum/min/max 可加；HLL/t-digest 可并不可减）
struct NodeAgg {
    int64_t count = 0;
    // 按建索引时的 measures 配置动态承载：sum[], min[], max[], HllSketch[], TDigest[]
    std::vector<double> sums, mins, maxs;
    std::vector<HllSketch> hlls;
    std::vector<TDigest> tdigests;
    void merge(const NodeAgg& o);     // roll-up：子 -> 父；compaction 合并
};

struct HasiNode {
    uint64_t cell_lo, cell_hi;        // 该节点覆盖的 S2 cell 区间（Hilbert 连续）
    NodeAgg  agg;                     // 子树预聚合（内部节点 = 多分辨率金字塔）
    uint32_t row_begin, row_count;    // 叶子：指向聚簇基础数据的连续行块
    int32_t  children[4];             // 内部节点的子节点下标；叶子为 -1
    bool     is_leaf() const { return children[0] < 0; }
};

// 整棵树序列化进独立索引文件（DorisFSDirectory，同 ANN 的 _index_file_writer->open(_index_meta)）
class HasiTree {
public:
    // 写入期：按数据量均衡分裂构建（叶子 <= leaf_rows）
    void build(const std::vector<uint64_t>& sorted_cell_ids, int leaf_rows,
               const MeasureSpec& measures, const AggInput& cols);
    Status save(io::FileWriter* w) const;
    Status load(io::FileReader* r);

    const HasiNode& root() const { return _nodes[0]; }
    const HasiNode& child(const HasiNode& n, int i) const { return _nodes[n.children[i]]; }
private:
    std::vector<HasiNode> _nodes;     // 0 号为根
};

} // namespace doris::segment_v2
```

### 4.3 写入器 `geo_index_writer.h`（仿 `ann_index_writer.h`）
```cpp
#pragma once
#include "olap/rowset/segment_v2/index_file_writer.h"
#include "olap/rowset/segment_v2/index_writer.h"
#include "geo_index/hasi_tree.h"
#include "geo_index/s2_covering.h"

namespace doris::segment_v2 {

class GeoIndexColumnWriter : public IndexColumnWriter {
public:
    static constexpr const char* S2_MIN_LEVEL = "s2_min_level"; // 默认 4
    static constexpr const char* S2_MAX_LEVEL = "s2_max_level"; // 默认 30
    static constexpr const char* LEAF_ROWS    = "leaf_rows";    // 叶子行上限，默认 65536
    static constexpr const char* MEASURES     = "measures";     // 预聚合度量集

    GeoIndexColumnWriter(IndexFileWriter* w, const TabletIndex* meta)
        : _index_file_writer(w), _index_meta(meta) {}

    Status init() override;                                  // open dir, 读 properties 配 measures
    // 写入接收两路输入：__s2 cell id 列 + 需要预聚合的 measure 列（通过 add_values 多次喂）
    Status add_values(const std::string name, const void* values, size_t count) override;
    Status add_nulls(uint32_t count) override;
    Status finish() override;                                // build HasiTree + save 进独立文件
    int64_t size() const override;
    void    close_on_error() override;
    // array 接口对 geo 不用，返回 NotSupported（同 ANN 的取舍）
    Status add_array_values(size_t, const void*, const uint8_t*, const uint8_t*, size_t) override;
    Status add_array_values(size_t, const CollectionValue*, size_t) override;
    Status add_array_nulls(const uint8_t*, size_t) override;
private:
    IndexFileWriter*     _index_file_writer;
    const TabletIndex*   _index_meta;
    std::shared_ptr<DorisFSDirectory> _dir;
    std::vector<uint64_t> _cell_ids;     // 累积 __s2
    AggBuffers            _measure_cols;  // 累积待聚合列
    HasiTree              _tree;
};

} // namespace doris::segment_v2
```
> `finish()` 对齐 `ann_index_writer.cpp` 的 `finish()`：把累积数据 build 成树后 `save(_dir.get())`。

### 4.4 读取器/迭代器/运行时（仿 ANN）
- `geo_index_reader.h` : `public IndexReader`，实现 `index_type()→GEO`、`new_iterator()`、`load_index()`；
  暴露两类查询：
  ```cpp
  // 检索：返回命中行（roaring），内部满覆盖块整体 accept，边界块走 recheck 回调
  Status range_search(const GeoSearchParams& p, roaring::Roaring* hit_rows, GeoStats* s);
  // 聚合：满覆盖节点取 sketch 直接合并；边界节点回填行号交给上层精算
  Status aggregate(const GeoSearchParams& p, NodeAgg* partial, roaring::Roaring* boundary_rows);
  ```
- `geo_index_iterator.h` : `public IndexIterator`，持 `GeoIndexReader`（同 `ann_index_iterator.h`）。
- `geo_range_runtime.h` : 仿 `ann_topn_runtime`，在 `segment_iterator.cpp` 内被
  `_apply_geo_predicate()` 调用，`evaluate(...)` 把命中写进 `&_row_bitmap`（对齐 `segment_iterator.cpp:765`）。

### 4.5 segment_iterator 读路径接入（仿 `:695`）
```cpp
// be/src/olap/rowset/segment_v2/segment_iterator.cpp
Status SegmentIterator::_apply_geo_predicate() {
    if (_geo_runtime == nullptr) return Status::OK();
    int32_t cid = _geo_runtime->src_column_idx();
    IndexIterator* it = _index_iterators[cid].get();
    if (it == nullptr || it->get_reader(GeoIndexReaderType::GEO) == nullptr) {
        return Status::OK();                       // 无 GEO 索引 -> 回落普通谓词
    }
    // 算命中行（满覆盖整块 accept + 边界 SIMD 精算），写进 _row_bitmap（与 ANN 出口一致）
    RETURN_IF_ERROR(_geo_runtime->evaluate(it, &_row_bitmap, /*stats*/));
    return Status::OK();
}
```

### 4.6 双框 + SIMD 精算 `geo_recheck_simd.h`
```cpp
// 对“边界 cell”里的候选点批量判定，避免对内接框内的点算三角函数
// inner: 圆内接正方形(经度/纬度阈值) -> 直接 accept
// outer: 圆外接框 -> 直接 reject
// 环带: 仅此处做精确 S2Earth / haversine（向量化）
inline void recheck_circle_simd(const double* lat, const double* lon, size_t n,
                                const GeoCircle& c, uint8_t* keep /*out*/);
// 多边形：covering 满覆盖 cell 已 accept；边界 cell 调 GeoPolygon::contains（点）
```

---

## 5. 查询执行流（端到端）

### 5.1 四级剪枝漏斗（万亿 → 结果）
```
分区裁剪(时间)  →  分桶裁剪(粗 cell 哈希)  →  HASI 树满覆盖跳过  →  边界叶子 SIMD 精算
   1e12              ~1e10                      ~1e8                 ~1e6 → 结果
```

### 5.2 区域聚合 `SELECT count(*), sum(amount) WHERE ST_Distance_Sphere(geo, :p) < :r`
1. FE `PushDownGeoAgg` 命中 `measures` 含 `count,sum(amount)` → 下发 `GeoSearchParams`。
2. BE `GeoIndexReader::aggregate()`：S2Covering 得 interior/boundary；
   **interior 节点直接取 sketch 合并（O(1)，不下钻、不扫描）**；boundary 行号回上层。
3. boundary 行走普通扫描 + `recheck_circle_simd` 精算后并入聚合。
4. 代价 ∝ 边界节点数 ≈ 周长，与区域内总点数无关（R7）。

### 5.3 半径/框/contains 检索（R3/R4）
`GeoIndexReader::range_search()`：interior 块整体 accept（免 recheck），boundary 块 SIMD 精算 →
命中 roaring 写 `_row_bitmap` → 后续列延迟物化。

### 5.4 kNN
best-first：按"节点到查询点最小距离"扩展 S2 cap covering，凑够 k 个剪枝（树已均衡，下钻浅）。

---

## 6. 空间换时间的账（R6）
- `__s2` 列：8B/行，排序后 delta+RLE，实测可压到 ~1–2B/行。
- HASI 树/金字塔：均衡四叉树内部节点 ≈ 叶子数/3 → 比"只存叶子聚合"贵 **+33%**；
  叶子聚合（百万~亿级 cell）相对万亿原始行本就极小 → 单 measure 集总开销 **+20%~50%**。
- 真正花钱处：**多 measure 集 × 多分辨率金字塔**，每多一组要预聚合的 `(度量, group-by)` 多一份。可配置。

---

## 7. 分阶段计划

| 阶段 | 目标 | 交付 | 主要文件 |
|---|---|---|---|
| **v0** | S2 覆盖 + 隐藏列 | `__s2` 生成 + `S2Covering` + `recheck_simd`；检索靠 `__s2` 排序键 + ZoneMap | FE 列生成、`s2_covering.*`、`geo_recheck_simd.h` |
| **v1** | 检索下推 | `IndexType::GEO` 全链路；`GeoIndex{Writer,Reader,Iterator}` + `geo_range_runtime`；命中写 `_row_bitmap` | proto/FE IndexDef/`geo_index/*`、`index_writer.cpp:49`、`column_writer.cpp:1045`、`segment_iterator.cpp:695` |
| **v2** | 聚合金字塔（灵魂） | HASI 树 + sketch + `aggregate()` + `PushDownGeoAgg`；满覆盖 O(1) | `hasi_tree.*`、`hasi_sketch.h`、`geo_agg_runtime.*`、FE rule |
| **v3** | 增量与调优 | compaction `geo_index_compaction`（子树合并 roll-up）；学习导航层；多分辨率多 measure | `inverted_index_compaction.h:35` 同级新增 |

---

## 8. 测试与验证
- **正确性**：与现有 `ST_*` 标量函数全表过滤结果对拍（regression-test 新增 `geo_index` 用例）；
  覆盖极点、反子午线 ±180°、跨子午线多边形（S2 原生处理）。
- **单测**：`be/test/olap/rowset/segment_v2/geo_index_test.cpp`（仿 ANN 单测），覆盖
  build/save/load、covering interior/boundary 划分、sketch merge 幂等、双框 prefilter 边界。
- **性能对照**：同数据集对比 ES(geo_distance/geo_bounding_box/geo aggregation) 与 PostGIS；
  指标分场景报：区域聚合(期望 10–100×)、大区域检索(数量级)、小区域高选择度点查(2–5×)。

---

## 9. 风险与边界（诚实记录）
1. **可减性**：`count/sum` 有符号 delta 易维护；`HLL/t-digest` 可并不可减 → 删除/更新走 MOW delete bitmap，
   受影响叶子在 compaction 重算 sketch；高频更新区避免不可减 sketch。
2. **倾斜**：均衡分裂是命根子；分桶 key 用"粗 cell + 时间/高基列"复合防热点 tablet。
3. **ad-hoc 度量**：金字塔只覆盖预定义 measure 集；未预聚合度量回落检索路径（满覆盖块整体流式 + SIMD，仍快于 ES）。
4. **学习导航**：对分布漂移敏感 → 只当加速层，compaction 随子树重训；正确性永远以排序数据为准。
5. **收益分层**：区域聚合/大区域 = 数量级；小区域高选择度点查 = 2–5×（ES BKD 本就强，不夸大）。

---

## 附：关键源码锚点速查
| 用途 | 位置 |
|---|---|
| 索引类型枚举(proto) | `gensrc/proto/olap_file.proto:400` |
| 索引类型/校验(FE) | `fe/.../analysis/IndexDef.java:208 / :220 / :240` |
| 写入基类/工厂 | `be/.../segment_v2/index_writer.h`、`index_writer.cpp:49` |
| 读取/迭代基类 | `be/.../segment_v2/index_reader.h`、`index_iterator.h` |
| ANN 模板 | `be/.../segment_v2/ann_index/`（writer/reader/iterator/runtime） |
| 写路径挂载 | `be/.../segment_v2/column_writer.cpp:1045 / :1062 / :1098` |
| 读路径挂载 | `be/.../segment_v2/segment_iterator.cpp:392 / :695 / :765` |
| compaction 合并 | `be/.../segment_v2/inverted_index_compaction.h:35` |
| S2 几何封装 | `be/src/geo/geo_types.h:89 / :172 / :243`；`be/src/geo/geo_types.cpp` |
| S2 头文件 | `installed/include/s2/{s2cell_id,s2region_coverer,s2cap,s2latlng,s2polygon}.h` |
| 标量 geo 函数 | `be/src/vec/functions/functions_geo.cpp`；FE `BuiltinScalarFunctions.java` |
