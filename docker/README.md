<!-- 
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->
<!-- Modified for MassDB SQL. See MODIFICATIONS.md for details. -->

## MassDB SQL UI toolchain

Use `docker/compilation/Dockerfile.ui` for Node 22.23.2, npm 10.9.9 and
Python 3.11. The legacy CentOS 7 compilation images below retain their native
compiler setup and old Node versions; they do not build the current UI.
Official Node 22 Linux binaries require a newer glibc than CentOS 7 provides.
See the [Node 22 build requirements](https://github.com/nodejs/node/blob/v22.x/BUILDING.md).

From the repository root:

```bash
docker build -f docker/compilation/Dockerfile.ui -t massdb-sql-ui-builder docker/compilation
docker run --rm --volume "$PWD:/workspace" massdb-sql-ui-builder
CUSTOM_UI_DIST="$PWD/ui/dist" bash build.sh --fe
```

The consuming FE build still requires JDK 17 and Python 3.9+, selected through
`custom_env.sh` / `MASSDB_NOTICE_PYTHON`; a compatible UI alone does not update
an old FE toolchain. Image creation and an uncached npm install need network
access. FE source material is supplied in `dist/sources/`, with no implicit
build-time download. Details are in [ui/README.md](../ui/README.md).

The following upstream native-toolchain instructions remain historical
reference material; verify their paths and tool versions before use.

## Doris Develop Environment based on docker

### Preparation

1. Download the Doris code repo

    ```console
    $ cd /to/your/workspace/
    $ git clone https://github.com/apache/doris.git
    $ cd doris
    $ git submodule update --init --recursive
    ```

    You can remove the `.git` dir in `doris/` to make the dir size smaller.
    So that the following generated docker image can be smaller.

2. Copy Dockerfile

    ```console
    $ cd /to/your/workspace/
    $ cp doris/docker/Dockerfile ./
    ```

After preparation, your workspace should like this:

```
.
├── Dockerfile
├── doris
│   ├── be
│   ├── bin
│   ├── build.sh
│   ├── conf
│   ├── DISCLAIMER-WIP
│   ├── docker
│   ├── docs
│   ├── env.sh
│   ├── fe
│   ├── ...
```

### Build docker image

```console
$ cd /to/your/workspace/
$ docker build -t doris:v1.0  .
```

> `doris` is docker image repository name and `v1.0` is tag name, you can change them to whatever you like.

### Use docker image

This docker image you just built does not contain Doris source code repo. You need
to download it first and map it to the container. (You can just use the one you
used to build this image before)

```console
$ docker run -it -v /your/local/path/doris/:/root/doris/ doris:v1.0
$ docker run -it -v /your/local/.m2:/root/.m2 -v /your/local/doris-DORIS-x.x.x-release/:/root/doris-DORIS-x.x.x-release/ doris:v1.0
```

Then you can build source code inside the container.

```console
$ cd /root/doris/
$ sh build.sh
```

**NOTICE**

The default JDK version is openjdk 11, if you want to use openjdk 8, you can run the command:

```console
$ alternatives --set java java-1.8.0-openjdk.x86_64
$ alternatives --set javac java-1.8.0-openjdk.x86_64
$ export JAVA_HOME=/usr/lib/jvm/java-1.8.0
```

The version of jdk you used to run FE must be the same version you used to compile FE.

### Latest update time

2022-1-23
