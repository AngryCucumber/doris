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
umask 077

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
license_cli="${script_dir}/massdb-sql-license-fe.sh"

endpoint=""
key_store=""
key_store_secret_file=""
key_store_type=""
trust_store=""
trust_store_secret_file=""
trust_store_type=""
connect_timeout_ms=""
read_timeout_ms=""
plan_file=""
bootstrap_idempotency_key=""
license_file=""
license_idempotency_key=""
poll_attempts="30"
poll_interval_seconds="2"

usage() {
    cat >&2 <<'USAGE'
Usage: massdb-sql-license-bootstrap-smoke.sh \
  --endpoint https://fe.example:8050 \
  --key-store /absolute/client.p12 \
  --key-store-secret-file /absolute/client.pass \
  --trust-store /absolute/server-trust.p12 \
  --trust-store-secret-file /absolute/server-trust.pass \
  --plan-file /absolute/bootstrap-plan.json \
  --bootstrap-idempotency-key manager-installation:BOOTSTRAP_CONTROL:request \
  [--license-file /absolute/license.mlic \
   --license-idempotency-key manager-installation:LICENSE_IMPORT:request] \
  [--key-store-type PKCS12] [--trust-store-type PKCS12] \
  [--connect-timeout-ms 5000] [--read-timeout-ms 15000] \
  [--poll-attempts 30] [--poll-interval-seconds 2]

This is a no-Manager, no-Agent control-plane smoke test for a formatVersion=2
MassDB SQL bootstrap plan. It does not replace real Stream Load, query denial,
Leader failover, response-loss, restart, or snapshot/restore acceptance tests.
USAGE
}

fail_json() {
    local code="$1"
    local message="$2"
    printf '{"ok":false,"code":"%s","message":"%s"}\n' \
        "${code}" "${message}" >&2
    exit 3
}

required_value() {
    local option="$1"
    local value="${2:-}"
    if [[ -z "${value}" || "${value}" == --* ]]; then
        fail_json "MASSDB_LICENSE_SMOKE_USAGE" "${option}缺少值"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            usage
            exit 0
            ;;
        --endpoint|--key-store|--key-store-secret-file|--key-store-type|\
        --trust-store|--trust-store-secret-file|--trust-store-type|\
        --connect-timeout-ms|--read-timeout-ms|--plan-file|\
        --bootstrap-idempotency-key|--license-file|--license-idempotency-key|\
        --poll-attempts|--poll-interval-seconds)
            required_value "$1" "${2:-}"
            option_name="${1#--}"
            option_name="${option_name//-/_}"
            printf -v "${option_name}" '%s' "$2"
            shift 2
            ;;
        *)
            fail_json "MASSDB_LICENSE_SMOKE_USAGE" "存在未知参数"
            ;;
    esac
done

for required in endpoint key_store key_store_secret_file trust_store \
        trust_store_secret_file plan_file bootstrap_idempotency_key; do
    if [[ -z "${!required}" ]]; then
        fail_json "MASSDB_LICENSE_SMOKE_USAGE" "缺少必填参数"
    fi
done
if [[ -n "${license_file}" && -z "${license_idempotency_key}" \
        || -z "${license_file}" && -n "${license_idempotency_key}" ]]; then
    fail_json "MASSDB_LICENSE_SMOKE_USAGE" \
        "--license-file与--license-idempotency-key必须同时提供"
fi
if [[ ! "${poll_attempts}" =~ ^[1-9][0-9]{0,2}$ \
        || ! "${poll_interval_seconds}" =~ ^[1-9][0-9]?$ ]]; then
    fail_json "MASSDB_LICENSE_SMOKE_USAGE" "轮询参数超出允许格式"
fi
if [[ ! -x "${license_cli}" ]]; then
    fail_json "MASSDB_LICENSE_SMOKE_PACKAGE_INVALID" \
        "安装包缺少可执行License CLI包装脚本"
fi
if ! command -v jq >/dev/null 2>&1; then
    fail_json "MASSDB_LICENSE_SMOKE_JQ_REQUIRED" "Linux验收机必须安装jq"
fi
if [[ ! -f "${plan_file}" || -L "${plan_file}" ]]; then
    fail_json "MASSDB_LICENSE_SMOKE_PLAN_INVALID" \
        "bootstrap plan必须是非符号链接普通文件"
fi
if ! jq -e '.formatVersion == 2
        and .componentType == "massdb-sql"
        and (.frontends | type == "array" and length > 0)
        and (.backends | type == "array" and length > 0)
        and (.ingressNodes | type == "array" and length > 0)' \
        "${plan_file}" >/dev/null; then
    fail_json "MASSDB_LICENSE_SMOKE_PLAN_INVALID" \
        "本脚本只验收完整formatVersion=2安装计划"
fi

planned_frontends="$(jq -r '.frontends | length' "${plan_file}")"
planned_backends="$(jq -r '.backends | length' "${plan_file}")"
planned_ingress="$(jq -r '[.ingressNodes[] | select(.desired == true)] | length' \
        "${plan_file}")"

connection_args=(
    --endpoint "${endpoint}"
    --key-store "${key_store}"
    --key-store-secret-file "${key_store_secret_file}"
    --trust-store "${trust_store}"
    --trust-store-secret-file "${trust_store_secret_file}"
)
if [[ -n "${key_store_type}" ]]; then
    connection_args+=(--key-store-type "${key_store_type}")
fi
if [[ -n "${trust_store_type}" ]]; then
    connection_args+=(--trust-store-type "${trust_store_type}")
fi
if [[ -n "${connect_timeout_ms}" ]]; then
    connection_args+=(--connect-timeout-ms "${connect_timeout_ms}")
fi
if [[ -n "${read_timeout_ms}" ]]; then
    connection_args+=(--read-timeout-ms "${read_timeout_ms}")
fi

smoke_directory="$(mktemp -d "${TMPDIR:-/tmp}/massdb-sql-license-smoke.XXXXXX")"
cleanup() {
    if [[ -n "${smoke_directory:-}" && -d "${smoke_directory}" \
            && "$(basename "${smoke_directory}")" == massdb-sql-license-smoke.* ]]; then
        rm -rf -- "${smoke_directory}"
    fi
}
trap cleanup EXIT

run_cli() {
    local output_file="$1"
    shift
    "${license_cli}" "$@" "${connection_args[@]}" >"${output_file}"
}

capability_file="${smoke_directory}/capability.json"
bootstrap_status_file="${smoke_directory}/bootstrap-status.json"
bootstrap_operation_file="${smoke_directory}/bootstrap-operation.json"
topology_file="${smoke_directory}/topology.json"
license_operation_file="${smoke_directory}/license-operation.json"
license_status_file="${smoke_directory}/license-status.json"

run_cli "${capability_file}" license-capability
if ! jq -e '.supported == true and .componentType == "massdb-sql"' \
        "${capability_file}" >/dev/null; then
    fail_json "MASSDB_LICENSE_SMOKE_CAPABILITY_INVALID" \
        "组件没有返回预期License capability"
fi
run_cli "${bootstrap_status_file}" license-bootstrap-status
run_cli "${bootstrap_operation_file}" license-bootstrap-apply \
    --plan-file "${plan_file}" \
    --idempotency-key "${bootstrap_idempotency_key}"
if ! jq -e '.kind == "BOOTSTRAP_CONTROL" and .apiState == "SEALED"
        and .terminal == true' "${bootstrap_operation_file}" >/dev/null; then
    fail_json "MASSDB_LICENSE_SMOKE_BOOTSTRAP_NOT_SEALED" \
        "bootstrap operation未到达SEALED终态"
fi

topology_ready=false
for ((attempt = 1; attempt <= poll_attempts; attempt++)); do
    run_cli "${topology_file}" license-topology-minimal
    if jq -e --argjson frontends "${planned_frontends}" \
            --argjson backends "${planned_backends}" \
            --argjson ingress "${planned_ingress}" '
            .schemaVersion == "massdb-sql-minimal-topology/v1"
            and .bootstrapPhase == "SEALED"
            and .bootstrapSealGeneration == 1
            and .summary.actualFrontendCount == $frontends
            and .summary.aliveFrontendCount == $frontends
            and .summary.actualBackendCount == $backends
            and .summary.loadAvailableBackendCount == $backends
            and .summary.desiredIngressCount == $ingress
            and .summary.liveDesiredIngressCount == $ingress
            and .summary.guardReadyDesiredIngressCount == $ingress
            and ([.ingressNodes[] | select(.desired == true)
                | .identityStatus == "AUTHENTICATED"] | all)' \
            "${topology_file}" >/dev/null; then
        topology_ready=true
        break
    fi
    if ((attempt < poll_attempts)); then
        sleep "${poll_interval_seconds}"
    fi
done
if [[ "${topology_ready}" != true ]]; then
    jq -c '.' "${topology_file}" >&2 || true
    fail_json "MASSDB_LICENSE_SMOKE_TOPOLOGY_NOT_READY" \
        "多FE/BE或desired入口未在轮询窗口内全部健康"
fi

operation_id=""
if [[ -n "${license_file}" ]]; then
    run_cli "${license_operation_file}" license-import \
        --license-file "${license_file}" \
        --idempotency-key "${license_idempotency_key}"
    operation_id="$(jq -r '.operationId // empty' "${license_operation_file}")"
    if [[ -z "${operation_id}" ]]; then
        fail_json "MASSDB_LICENSE_SMOKE_OPERATION_INVALID" \
            "License import未返回operationId"
    fi
    operation_succeeded=false
    for ((attempt = 1; attempt <= poll_attempts; attempt++)); do
        run_cli "${license_operation_file}" license-operation \
            --operation-id "${operation_id}"
        if jq -e '.terminal == true and .state == "SUCCEEDED"' \
                "${license_operation_file}" >/dev/null; then
            operation_succeeded=true
            break
        fi
        if jq -e '.terminal == true and .state != "SUCCEEDED"' \
                "${license_operation_file}" >/dev/null; then
            jq -c '.' "${license_operation_file}" >&2 || true
            fail_json "MASSDB_LICENSE_SMOKE_IMPORT_FAILED" \
                "License import进入失败终态"
        fi
        if ((attempt < poll_attempts)); then
            sleep "${poll_interval_seconds}"
        fi
    done
    if [[ "${operation_succeeded}" != true ]]; then
        fail_json "MASSDB_LICENSE_SMOKE_IMPORT_TIMEOUT" \
            "License import未在轮询窗口内完成"
    fi
fi

run_cli "${license_status_file}" license-status
if [[ -n "${license_file}" ]] \
        && ! jq -e '.state == "VALID" and .licenseExpiredUnderEffectiveNow == false' \
        "${license_status_file}" >/dev/null; then
    fail_json "MASSDB_LICENSE_SMOKE_LICENSE_NOT_VALID" \
        "导入后License状态不是VALID"
fi

jq -n --arg operationId "${operation_id}" \
    --slurpfile topology "${topology_file}" \
    --slurpfile status "${license_status_file}" '
    {ok: true, componentType: "massdb-sql", bootstrapPhase: "SEALED",
     topologySummary: $topology[0].summary,
     licenseState: $status[0].state,
     licenseOperationId: (if $operationId == "" then null else $operationId end)}'
