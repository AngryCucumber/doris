#!/usr/bin/env bash
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

# Local evidence only. No service restart, configuration change, GC or heap dump.
set -u
set -o pipefail
umask 077

usage() {
    cat <<'USAGE'
Usage: bash tools/fe-stall-collect.sh --pid PID --output NEW_DIR [options]

Required:
  --pid PID          Existing FE process PID; run as its owner or with read access.
  --output NEW_DIR   New private output directory; its parent must already exist.

Options:
  --rpc-port PORT    Local TCP port for connection summary (default: 9020).
  --jvm              Run up to three jcmd PID Thread.print -l samples, 5s apart.
                     Each client call has a 15-second timeout (+1s kill grace).
                     Stop sampling after the first failed or timed-out call.
  --jcmd PATH        jcmd executable to use with --jvm (default: jcmd in PATH).
                     This option alone does not enable JVM collection.
  --http-port PORT   Fetch http://127.0.0.1:PORT/metrics once, with a 5-second
                     timeout and 16 MiB response limit. No proxy or redirects.
  --help             Show this help.

Default: /proc process status/stat/io/limits, FD/thread counts, system memory and
pressure, selected ps fields, and TCP state/queue totals for the RPC port.
The TCP summary covers this network namespace, not just the selected PID.
No process arguments/environment, credentials, FD targets, or FE log contents
are collected. No external network request, upload, GC, heap histogram/dump,
JFR, configuration change, or restart is performed. Output stays on this host.

Requires Bash and timeout. Missing optional tools/files are recorded and skipped.
Thread.print attaches to the JVM and can pause it briefly; it is opt-in. A client
timeout does not cancel work already executing in the JVM or HTTP server.
HTTP is opt-in because a blocked /metrics endpoint can queue additional work.
USAGE
}

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

pid=''
output_dir=''
rpc_port=9020
http_port=''
collect_jvm=false
jcmd_command='jcmd'
while (($#)); do
    case "$1" in
        --pid|--output|--rpc-port|--http-port|--jcmd)
            (($# >= 2)) || fail "Missing value for $1"
            case "$1" in
                --pid) pid=$2 ;;
                --output) output_dir=$2 ;;
                --rpc-port) rpc_port=$2 ;;
                --http-port) http_port=$2 ;;
                --jcmd) jcmd_command=$2 ;;
            esac
            shift 2
            ;;
        --jvm) collect_jvm=true; shift ;;
        --help) usage; exit 0 ;;
        *) fail "Unknown option: $1 (use --help)" ;;
    esac
done

[[ "$pid" =~ ^[1-9][0-9]{0,9}$ ]] || fail '--pid must be a positive numeric PID'
[[ -n "$output_dir" ]] || fail '--output is required'
valid_port() {
    [[ "$1" =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535))
}
valid_port "$rpc_port" || fail '--rpc-port must be between 1 and 65535'
rpc_port=$((10#$rpc_port))
if [[ -n "$http_port" ]]; then
    valid_port "$http_port" || fail '--http-port must be between 1 and 65535'
    http_port=$((10#$http_port))
fi
command -v timeout >/dev/null 2>&1 || fail 'timeout is required for bounded collection'
[[ -r "/proc/$pid/stat" ]] || fail 'PID is absent or /proc/PID/stat is not readable'

# Field 22 is starttime; strip through the final ") " because comm can contain spaces.
process_starttime() {
    local stat_line rest
    local -a stat_fields
    IFS= read -r stat_line < "/proc/$pid/stat" 2>/dev/null || return 1
    rest=${stat_line##*) }
    read -r -a stat_fields <<< "$rest"
    ((${#stat_fields[@]} >= 20)) || return 1
    printf '%s' "${stat_fields[19]}"
}
initial_start=$(process_starttime) || fail 'Cannot determine PID starttime'
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || fail 'Output path already exists; use a new directory'
timeout -k 1s 5s mkdir -m 700 -- "$output_dir" || fail 'Cannot create the new output directory'
output_dir=$(cd -- "$output_dir" && pwd -P) || fail 'Cannot resolve the output directory'
summary_file="$output_dir/collection.txt"

note() {
    printf '%(%Y-%m-%dT%H:%M:%S%z)T %s\n' -1 "$*" >> "$summary_file"
}
same_process() {
    local current_start
    current_start=$(process_starttime) || current_start=''
    if [[ "$current_start" != "$initial_start" ]]; then
        note 'SKIP: selected process exited or its PID was reused.'
        return 1
    fi
}

capture() {
    local filename=$1 seconds=$2 rc
    shift 2
    if ! command -v "$1" >/dev/null 2>&1; then
        note "SKIP $filename: tool $1 is unavailable"
        return 127
    fi
    note "BEGIN $filename timeout=${seconds}s"
    timeout -k 1s "${seconds}s" "$@" > "$output_dir/$filename" 2> "$output_dir/$filename.stderr"
    rc=$?
    note "END $filename exit=$rc (124=timeout; 137=kill grace exceeded)"
    return "$rc"
}
capture_proc() {
    same_process || return 0
    capture "$1" 5 cat "/proc/$pid/$2"
}

note "PID=$pid starttime_ticks=$initial_start rpc_port=$rpc_port"
note "Optional JVM=$collect_jvm HTTP_port=${http_port:-disabled}"
note 'No arguments/environment, logs, GC, dump, external requests or service changes.'
note 'Files can contain host/process details; keep the directory on the incident host.'

for proc_file in status stat io limits; do
    capture_proc "process-$proc_file.txt" "$proc_file"
done
if same_process; then
    capture process-ps.txt 5 ps -p "$pid" -o pid,ppid,nlwp,pcpu,pmem,rss,vsz,etimes,stat,wchan:32
fi
if command -v find >/dev/null 2>&1 && command -v wc >/dev/null 2>&1; then
    for proc_dir in fd task; do
        if same_process; then
            # Count entries only; never read symlink targets or individual task arguments.
            capture "process-$proc_dir-count.txt" 5 bash -c '
                set -o pipefail
                find "$1" -mindepth 1 -maxdepth 1 -printf . | wc -c
            ' -- "/proc/$pid/$proc_dir"
        fi
    done
else
    note 'SKIP FD/task counts: find or wc is unavailable'
fi

for system_file in meminfo vmstat loadavg; do
    capture "system-$system_file.txt" 5 cat "/proc/$system_file"
done
for pressure_type in cpu io memory; do
    capture "pressure-$pressure_type.txt" 5 cat "/proc/pressure/$pressure_type"
done

if command -v ss >/dev/null 2>&1 && command -v awk >/dev/null 2>&1; then
    capture rpc-connections.txt 5 bash -c '
        set -o pipefail
        ss -H -tan "( sport = :$1 or dport = :$1 )" | awk '\''
            { count[$1]++; recv[$1]+=$2; send[$1]+=$3;
              if ($2 > maxrecv[$1]) maxrecv[$1]=$2;
              if ($3 > maxsend[$1]) maxsend[$1]=$3; total++ }
            END {
                print "state count recvq_sum sendq_sum recvq_max sendq_max";
                for (state in count)
                    printf "%s %d %.0f %.0f %.0f %.0f\n", state, count[state],
                        recv[state], send[state], maxrecv[state], maxsend[state];
                printf "total_connections %d\n", total;
                print "LISTEN queues are backlog counts; other TCP queues are bytes."
            }'\''
    ' -- "$rpc_port"
else
    note 'SKIP RPC summary: ss or awk is unavailable'
fi

if "$collect_jvm"; then
    if command -v "$jcmd_command" >/dev/null 2>&1; then
        for sample in 1 2 3; do
            same_process || break
            if ! capture "jvm-threads-$sample.txt" 15 "$jcmd_command" "$pid" Thread.print -l; then
                note 'STOP JVM samples: jcmd failed or timed out; target work may still be running.'
                break
            fi
            if ((sample < 3)); then
                timeout -k 1s 6s sleep 5 || note 'Thread sample interval interrupted'
            fi
        done
    else
        note "SKIP JVM: $jcmd_command is unavailable; specify --jcmd or use the matching JDK in PATH"
    fi
fi

if [[ -n "$http_port" ]] && same_process; then
    # --disable first prevents ~/.curlrc from supplying credentials, redirects or proxies.
    capture metrics.txt 5 curl --disable --silent --show-error --fail \
        --noproxy '*' --proxy '' --connect-timeout 2 --max-time 5 \
        --max-filesize 16777216 --proto '=http' --max-redirs 0 \
        "http://127.0.0.1:$http_port/metrics"
fi
same_process || true
note 'Collection complete. Inspect each END status and corresponding .stderr file.'
printf 'Evidence saved locally: %s\n' "$output_dir"
