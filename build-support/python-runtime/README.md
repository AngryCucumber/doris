# BE 内置 Python 运行时（原型）

用来生成随 MassDB SQL BE 分发的离线 Python 运行时，供 Python UDF/UDAF/UDTF 使用（UDWF 就是 UDAF 加 `OVER`）。
产物是一个 tar.gz：解压到 BE 的 `lib/` 目录下，得到 `lib/python-runtime/`。这个目录按 BE 的
`python_env_mode = conda` 约定组织（BE 扫描 `<python_conda_root_path>/envs/*/bin/python`），不需要安装 conda。

## 目标系统要求

默认目标和 BE 一样，glibc ≥ 2.17：只使用 manylinux2014 的 wheel，检查时会强制核对 GLIBC_2.17、GLIBCXX_3.4.19
和 CXXABI_1.3.7 这三个上限。
BE 是静态链接 libstdc++ 的，本运行时则要用系统自带的这几个库：libstdc++（不低于 GCC 4.8.5，CentOS 7 满足）、
libgcc_s 和 libz.so.1。lightgbm 还要用系统的 libgomp.so.1，并且要有 `GOMP_4.5`。CentOS 7 的 libgomp 4.8.5
已经反向移植了 OpenMP 4.5，所以满足，但要确认目标机器装了 libgomp 包。检查脚本的 warning 会列出每个系统库需要的符号版本。

代价是部分依赖要停在仍提供 manylinux2014 aarch64 wheel 的最后一个版本，比如 pyarrow 20.0.0（BE 用的是 Arrow 24）、
numpy 2.2、scipy 1.16、scikit-learn 1.7。pyarrow 20 和 BE 的 Arrow 24 之间的数据往返已在 BE 上实测通过。
如果目标系统都在 glibc 2.28 以上，可以用 `--target-glibc 2.28` 换回新版本，同时要把 `pyarrow` 的锁定版本和
`target.glibcxx` / `target.cxxabi` 一起调整。

| 文件 | 作用 |
|---|---|
| `python-runtime.json` | 固定的解释器版本和 sha256、目标 glibc、依赖分层、导入和许可证策略 |
| `build-python-runtime.py` | `resolve`：联网下载解释器和 wheel，生成带哈希的 lock；`build`：只用 resolve 的产物离线安装并打包 |
| `check-python-runtime.py` | 检查 tarball 或解压后的目录，有 error 时退出码为 1 |
| `test_python_runtime.py` | 两个脚本的单元测试（用合成的 ELF 和目录） |

## 依赖分层

| 层 | 内容 |
|---|---|
| core | `python_server.py` 必需的包：numpy、pandas、pyarrow |
| common | 文本、时间、哈希、地理：jieba、pypinyin、rapidfuzz、regex、dateutil、pytz、tzdata、orjson、PyYAML、xxhash、mmh3、cryptography、phonenumbers、shapely、pyproj、h3 等 |
| analytics | scipy、scikit-learn、statsmodels，pandas 加速包 numexpr、bottleneck，networkx、sympy，模型推理 xgboost、lightgbm |
| extended | 内网 HTTP（requests）、HTML/XML（beautifulsoup4、lxml）、中文（OpenCC 繁简转换、cnlunar 农历、chinesecalendar 节假日）、langdetect、emoji、anyascii、序列化（msgpack、ujson、simplejson、protobuf）、国密 SM2/SM4（gmssl）和 pycryptodome、bcrypt、PyJWT、地理/IP/UA（geopy、pygeohash、ua-parser、user-agents、tldextract、netaddr、maxminddb、geoip2）、校验（pydantic、jsonschema、email-validator）和小工具 |
| engines | 嵌入式引擎 polars、duckdb，体积最大，不需要时可以去掉 |

使用注意：
- geoip2 / maxminddb 只是读取库，IP 归属地数据库（例如 GeoLite2）要另外准备，不随包分发。
- tldextract 在离线环境要写成 `tldextract.TLDExtract(suffix_list_urls=())`，这样只用它自带的公共后缀快照，不会尝试联网更新。
- chinesecalendar 的节假日数据跟着包版本走，每年国务院发布新安排后要升级版本并重新构建。
- SM3 用标准库 `hashlib.new('sm3', ...)` 即可（解释器内置 OpenSSL 3）；SM2/SM4 用 gmssl。
- 没有收录的包：
  - GPL 许可的 Unidecode、zhdate、lunardate，分别用 anyascii、cnlunar 代替。
  - onnxruntime 没有 glibc 2.17 的 wheel。
  - python-geohash 没有 wheel，用 pygeohash 代替。
  - catboost 单个 wheel 就有 92 MB，需要时再单独加。

## 构建

构建机要和目标 BE 的 CPU 架构相同：依赖解析时由目标解释器判断环境标记，安装时也由它做字节编译。
运行脚本本身需要 Python 3.9 及以上。

```bash
# 1. 联网执行一次。整个 resolve 目录（解释器、wheelhouse、lock、resolve.json）就是构建输入，需要归档
python3 build-support/python-runtime/build-python-runtime.py resolve \
    --output <resolve目录> --index-url https://mirrors.aliyun.com/pypi/simple/

# 2. 离线构建（pip 使用 --no-index，只安装 lock 里的文件）。同一个 resolve 目录构建出的 tarball 逐字节相同
python3 build-support/python-runtime/build-python-runtime.py build --inputs <resolve目录> --output <构建目录>

# 3. 检查。--server-script 默认是源码里的 be/src/udf/python/python_server.py
python3 build-support/python-runtime/check-python-runtime.py <构建目录>/massdb-python-runtime-*.tar.gz \
    --report check.json
```

- `--layers core,common`：只装部分分层，默认装 `defaultLayers` 里的所有层。
- `--target-glibc`：目标 BE 中最旧的 glibc 版本，默认 2.17。只会下载不高于这个版本的 manylinux wheel，
  所以构建机本身的 glibc 再新也没关系。
- 只有源码包的依赖要写进 `pureSdists` 并精确锁定版本。构建出来的必须是 `none-any` 纯 Python wheel，否则失败。
- wheel 里没带许可证正文的依赖，在 `licenseTexts` 里写上上游 URL 和 sha256，resolve 时下载并校验。

## 随发布包构建

`build-for-release.sh` 会在两次 `build.sh` 之后、组装安装包之前执行 `build-python-runtime.py release`。这一步依次做：
1. 按仓库里的 `locks/requirements-<架构>.lock` 下载解释器和 wheel，逐个核对哈希；
2. 离线构建；
3. 用刚编译出的 `be/plugins/python_udf/python_server.py` 做完整检查，有 error 时发布失败；
4. 解压到 `be/lib/python-runtime`。

检查报告、MANIFEST 和 lock 会写进审计包的 `audit/python-runtime/`。

- `MASSDB_PYPI_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/`：指定 PyPI 镜像。
- 下载好的输入会保留在 `.build-records/build-release-*/python-runtime/inputs`。以后用
  `--python-runtime-inputs <该目录>` 可以离线重建，前提是它和当前 lock 一致。
- `--no-python-runtime`：不打包运行时，比如在还没有对应 lock 的架构上。

`build.sh` 本身不下载也不构建运行时。

升级依赖或修改 `python-runtime.json` 的分层后，要重新执行 `resolve`（不带 `--lock`），把新的 `requirements.lock`
复制到 `locks/requirements-<架构>.lock` 后一起提交。单元测试会检查已提交的 lock 和配置是否一致。

## 安装到 BE

```bash
tar -xzf massdb-python-runtime-<版本>-<架构>-<lock哈希>.tar.gz -C <BE目录>/lib
```

发布包里的 `be/conf/be.conf` 已经预置了下面这些配置，只是 `enable_python_udf_support` 默认是 `false`，改成 `true` 并重启 BE 即可。
`start_be.sh` 启动时会清掉运维 shell 里的 `PYTHONHOME`、`PYTHONPATH`。手动安装时要自己加上以下配置
（运行时根目录下的 `README.txt` 和 `MANIFEST.json` 里也有同样内容）：

```properties
enable_python_udf_support = true
python_env_mode = conda
python_conda_root_path = ${DORIS_HOME}/lib/python-runtime
PYTHONNOUSERSITE = 1
```

建函数时 `"runtime_version"` 必须写完整版本号（比如 `3.12.15`），BE 是按完整版本号精确匹配的。
`envs/` 下只要有一个坏掉的环境，BE 就会启动失败。升级 Python 补丁版本时，新旧环境要同时保留，直到函数都迁移完。

## 检查项

| 检查 | error | warning / info |
|---|---|---|
| layout | `envs/*/bin/python` 缺失或不可执行，`python --version` 解析失败，site-packages 缺失，和 MANIFEST 不一致 | 存在多个环境 |
| symlinks | 绝对路径、断开、或指向运行时目录之外的符号链接 | |
| elf | 架构不对；PT_LOAD 对齐不是 `minLoadAlign`（64 KiB）的整数倍，在 64K 页内核上 glibc 会拒绝加载；需要的 GLIBC / GLIBCXX / CXXABI 版本高于目标 | 除 glibc 和 libstdc++ 外，还需要目标系统提供的库 |
| imports | `python_server.py` 依赖的模块，或任何已安装的顶层模块导入失败；`pip list`（即 `SHOW PYTHON PACKAGES`）失败 | |
| server | 启动 `python_server.py`，通过 Arrow Flight 调用一个标量 UDF 和一个 pandas 向量化 UDF，结果不对 | |
| license | 命中 deny 策略；链接了 GNU readline；`--strict-licenses` 下，许可证不明或缺正文 | 需要法务评审的许可证；wheel 内自带的原生库；解释器静态链接的组件 |

只做静态检查（比如在其他架构的机器上检查）时加 `--skip-runtime`。在 4K 页的机器上，导入和 UDF 调用
都是按 4K 页跑的，64K 页内核只能靠 ELF 对齐检查来覆盖。

## 原型还没做的

- 安装包 README 会指向运行时自带的 `MANIFEST.json` 和 `LICENSES/`。但第三方组件还没进入 `dist/licenses`、UI 版权页的组件清单
  和 `dist/reviewed-binary-artifacts.json`。
- x86_64 需要在 x86_64 主机上单独执行 resolve 和 build。
- 解释器静态链接的组件（OpenSSL、SQLite 等）的许可证正文，要从 python-build-standalone 的 full 包补齐。
