#!/usr/bin/env bash
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# Modified for MassDB SQL. See MODIFICATIONS.md for details.

##############################################################
# This script is used to build for Apache Doris Release
##############################################################

set -eo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

export DORIS_HOME="${ROOT}"

# Check args
usage() {
    echo "
Usage: $0 --version version <options>
  Optional options:
     [no option]        build with avx2
     --noavx2           build without avx2
     --tar              pack the output

  Programs and optional archives: output/
  Compressed internal records: .build-records/
  Existing output paths are never overwritten; move installed copies out first.

  Eg.
    $0 --version 1.2.0                      build with avx2
    $0 --noavx2 --version 1.2.0             build without avx2
    $0 --version 1.2.0 --tar                build with avx2 and pack the output
  "
    exit 1
}

if ! OPTS="$(getopt \
    -n "$0" \
    -o '' \
    -l 'noavx2' \
    -l 'tar' \
    -l 'version:' \
    -l 'help' \
    -- "$@")"; then
    usage
fi

eval set -- "${OPTS}"

_USE_AVX2=1
TAR=0
HELP=0
VERSION=
if [[ "$#" == 1 ]]; then
    _USE_AVX2=1
else
    while true; do
        case "$1" in
        --noavx2)
            _USE_AVX2=0
            shift
            ;;
        --tar)
            TAR=1
            shift
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --help)
            HELP=1
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Internal error"
            exit 1
            ;;
        esac
    done
fi

if [[ "${HELP}" -eq 1 ]]; then
    usage
fi

if [[ -z ${VERSION} ]]; then
    echo "Must specify version"
    usage
fi

if [[ ! "${VERSION}" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?(-([A-Za-z0-9][A-Za-z0-9.-]*))?$ ]]; then
    echo "Invalid product version: expected MAJOR.MINOR.PATCH[.HOTFIX][-SUFFIX]"
    exit 1
fi
export DORIS_BUILD_VERSION_PREFIX=massdb-sql
export DORIS_BUILD_VERSION_MAJOR="${BASH_REMATCH[1]}"
export DORIS_BUILD_VERSION_MINOR="${BASH_REMATCH[2]}"
export DORIS_BUILD_VERSION_PATCH="${BASH_REMATCH[3]}"
export DORIS_BUILD_VERSION_HOTFIX="${BASH_REMATCH[5]:-0}"
export DORIS_BUILD_VERSION_RC_VERSION="${BASH_REMATCH[7]}"

# A pending header permits review builds, but must not silently enter a release.
"${MASSDB_NOTICE_PYTHON:-python3}" "${ROOT}/build-support/check-source-headers.py" --release
"${MASSDB_NOTICE_PYTHON:-python3}" "${ROOT}/build-support/prepare-product-notices.py" --check-company-notice
"${MASSDB_NOTICE_PYTHON:-python3}" "${ROOT}/build-support/prepare-product-notices.py" --check-release-provenance

echo "Get params:
    VERSION         -- ${VERSION}
    USE_AVX2        -- ${_USE_AVX2}
    TAR             -- ${TAR}
"

ARCH="$(uname -m)"

if [[ "${ARCH}" == "aarch64" ]]; then
    ARCH="arm64"
elif [[ "${ARCH}" == "x86_64" ]]; then
    ARCH="x64"
else
    echo "Unknown arch: ${ARCH}"
    exit 1
fi

echo "ARCH: ${ARCH}"

ORI_OUTPUT="${ROOT}/output"

FE="fe"
BE="be"
CLOUD="ms"
EXT="extensions"
TOOLS="tools"
PACKAGE="massdb-sql-${VERSION}-bin-${ARCH}"

if [[ "${_USE_AVX2}" == "0" ]]; then
    PACKAGE="${PACKAGE}-noavx2"
fi

OUTPUT="${ORI_OUTPUT}/${PACKAGE}"
check_output_paths() {
    local path
    for path in "${OUTPUT}" "${OUTPUT}.tar.gz" "${OUTPUT}.tar.gz.sha256"; do
        if [[ -e "${path}" || -L "${path}" ]]; then
            echo "Output already exists: ${path}" >&2
            echo "Preserve installed data and move this output aside before rebuilding this version." >&2
            return 1
        fi
    done
}
check_output_paths
mkdir -p "${ORI_OUTPUT}" "${ROOT}/.build-records"
WORK="$(mktemp -d "${ROOT}/.build-records/build-release-XXXXXXXX")"
COMPONENTS="${WORK}/components"

OUTPUT_FE="${OUTPUT}/${FE}"
OUTPUT_EXT="${OUTPUT}/${EXT}"
OUTPUT_BE="${OUTPUT}/${BE}"
OUTPUT_CLOUD="${OUTPUT}/${CLOUD}"
OUTPUT_TOOLS="${OUTPUT}/${TOOLS}"

echo "Package Name:"
echo "FE:    ${OUTPUT_FE}"
echo "BE:    ${OUTPUT_BE}"
echo "CLOUD: ${OUTPUT_CLOUD}"
echo "JAR:   ${OUTPUT_EXT}"

bash "${ROOT}/build.sh" --clean
USE_AVX2="${_USE_AVX2}" bash "${ROOT}/build.sh" --output "${COMPONENTS}"
USE_AVX2="${_USE_AVX2}" bash "${ROOT}/build.sh" --be --meta-tool --be-extension-ignore avro-scanner --output "${COMPONENTS}"

echo "Begin to pack"
mkdir -p "${COMPONENTS}/hive-udf/lib"
cp -p "${ROOT}/fe/hive-udf/target/hive-udf.jar" "${COMPONENTS}/hive-udf/lib/"
"${MASSDB_NOTICE_PYTHON:-python3}" "${ROOT}/build-support/prepare-product-notices.py" \
    --assemble-package "${COMPONENTS}" --destination "${WORK}/${PACKAGE}" \
    --audit-directory "${WORK}/audit" --ui-dist "${ROOT}/fe/fe-core/src/main/resources/static"

compress_directory() (
    local name="$1"
    cd "${WORK}"
    # Use pigz (parallel gzip) to compress with all CPU cores; fall back to gzip if unavailable.
    if command -v pigz >/dev/null 2>&1; then
        tar -cf - "${name}" | pigz -p "$(nproc)" >"${name}".tar.gz.part
    else
        tar -czf "${name}".tar.gz.part "${name}"
    fi
    gzip -t "${name}".tar.gz.part
    mv "${name}".tar.gz.part "${name}".tar.gz
    sha256sum "${name}".tar.gz > "${name}".tar.gz.sha256
)

compress_directory audit
if [[ "${TAR}" -eq 1 ]]; then
    echo "Begin to compress"
    compress_directory "${PACKAGE}"
fi

# Publish only completed artifacts. Do not replace an installation created
# while compilation was in progress, or leave intermediate directories in output.
check_output_paths
for name in "${PACKAGE}" "${PACKAGE}.tar.gz" "${PACKAGE}.tar.gz.sha256"; do
    if [[ -e "${WORK}/${name}" ]]; then
        mv -T -n -- "${WORK}/${name}" "${ORI_OUTPUT}/${name}"
        if [[ -e "${WORK}/${name}" ]]; then
            echo "Output appeared during packaging; inputs retained at ${WORK}" >&2
            exit 1
        fi
    fi
done
rm -rf -- "${COMPONENTS}" "${WORK}/audit"

echo "Output dir: ${OUTPUT}"
echo "Internal records and debug symbols: ${WORK}/audit.tar.gz"
exit 0
