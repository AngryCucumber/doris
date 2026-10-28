# BE 内置 Python 运行时（原型）

用来生成随 MassDB SQL BE 分发的离线 Python 运行时，供 Python UDF/UDAF/UDTF 使用（UDWF 就是 UDAF 加 `OVER`）。
产物是一个 tar.gz：解压到 BE 的 `lib/` 目录下，得到 `lib/python-runtime/`。这个目录按 BE 的
`python_env_mode = conda` 约定组织（BE 扫描 `<python_conda_root_path>/envs/*/bin/python`），不需要安装 conda。

## 目标系统要求

默认目标和 BE 一样，glibc ≥ 2.17：只使用 manylinux2014 的 wheel，检查时会强制核对 GLIBC_2.17、GLIBCXX_3.4.19
和 CXXABI_1.3.7 这三个上限。
BE 是静态链接 libstdc++ 的，本运行时则要用系统自带的这几个库：libstdc++（不低于 GCC 4.8.5，CentOS 7 满足）、
libgcc_s 和 libz.so.1。

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

## 安装到 BE

```bash
tar -xzf massdb-python-runtime-<版本>-<架构>-<lock哈希>.tar.gz -C <BE目录>/lib
```

在 `be.conf` 里加入以下配置，然后重启 BE（运行时根目录下的 `README.txt` 和 `MANIFEST.json` 里也有同样内容）：

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

- 还没接入 `prepare-product-notices.py --assemble-package`。第三方许可证清单也还没进入 `dist/licenses`、UI 版权页的组件清单
  和 `dist/reviewed-binary-artifacts.json`。
- `start_be.sh` 还没有 `unset PYTHONHOME PYTHONPATH`；`be.conf` 模板也还没加上面的配置（目前要手动加）。
- x86_64 需要在 x86_64 主机上单独执行 resolve 和 build。
- 解释器静态链接的组件（OpenSSL、SQLite 等）的许可证正文，要从 python-build-standalone 的 full 包补齐。
