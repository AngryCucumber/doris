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

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
MASSDB_SQL_HOME="$(cd "${script_dir}/.." && pwd)"

if [[ -n "${JAVA_HOME:-}" ]]; then
    java_command="${JAVA_HOME}/bin/java"
else
    java_command="$(command -v java || true)"
fi
if [[ -z "${java_command}" || ! -x "${java_command}" ]]; then
    echo '{"ok":false,"code":"MASSDB_LICENSE_CLI_JAVA_INVALID","message":"JAVA_HOME未指向可执行JDK"}' >&2
    exit 4
fi

fe_jar="${MASSDB_SQL_HOME}/lib/doris-fe.jar"
if [[ ! -f "${fe_jar}" ]]; then
    echo '{"ok":false,"code":"MASSDB_LICENSE_CLI_PACKAGE_INVALID","message":"安装包缺少lib/doris-fe.jar"}' >&2
    exit 4
fi

classpath="${fe_jar}"
for dependency in "${MASSDB_SQL_HOME}"/lib/*.jar; do
    if [[ -f "${dependency}" && "${dependency}" != "${fe_jar}" ]]; then
        classpath="${classpath}:${dependency}"
    fi
done

main_class="org.apache.doris.massdblicense.MassDbLicenseIdentityCli"
if [[ "${1:-}" == license-* ]]; then
    main_class="org.apache.doris.massdblicense.MassDbLicenseCli"
fi

exec "${java_command}" -Dfile.encoding=UTF-8 \
    -cp "${MASSDB_SQL_HOME}/conf:${classpath}" \
    "${main_class}" "$@"
