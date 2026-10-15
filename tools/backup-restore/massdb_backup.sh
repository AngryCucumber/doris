#!/usr/bin/env bash
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

# Requires Bash 4.4+, jq 1.6+, GNU coreutils, mysql and hdfs dfs. No Python runtime.
set -Eeuo pipefail
shopt -s inherit_errexit
umask 077

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }
fail() { log "ERROR: $*"; exit 1; }
valid_name() { [[ $1 =~ ^[A-Za-z_][A-Za-z0-9_]{0,63}$ ]] || fail "Invalid SQL identifier: $1"; }
token() { od -An -N16 -tx1 /dev/urandom | tr -d ' \n'; }
new_id() { printf '%s_%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" "$(token | cut -c1-8)"; }
now() { date -u +%FT%TZ; }

# Recovery-point inventories can exceed Linux's per-argument limit. Pass them
# through files, not --argjson, when combining whole inventories in jq.
json_file() {
    local path
    path=$(mktemp "$WORK/json.XXXXXX")
    printf '%s\n' "$1" >"$path"
    printf '%s\n' "$path"
}

usage() {
    cat <<'USAGE'
Usage: bash massdb_backup.sh --config CONFIG COMMAND [OPTIONS]
  backup [--reuse-unchanged --quiesced]   Full backups by default
  list                                  List complete recovery points
  restore --point ID|latest --table TABLE --as NEW_TABLE --output-dir DIR
                                        Restore new table; generate, never run, swap SQL
  prune [--apply]                        Preview or apply reference-aware retention
  pin --point ID|latest                  Protect a recovery point during manual restore
  unpin --point ID                       Remove that protection
--quiesced asserts that the operator has stopped writes, DDL and in-flight loads
for the WHOLE run. The script does not pause business traffic itself.
USAGE
}

# Parse mysql's escaped TSV, preserving multiline DDL and literal backslashes.
# Do not use --raw: it would turn embedded tabs/newlines into row delimiters.
mysql_json() {
    jq -Rs '
        def decode:
            [scan("\\\\.|[^\\\\]+") |
                if . == "\\n" then "\n" elif . == "\\t" then "\t"
                elif . == "\\r" then "\r" elif . == "\\0" then "\u0000"
                elif . == "\\\\" then "\\" else . end] | join("");
        split("\n") | if .[-1] == "" then .[:-1] else . end |
        if length == 0 then [] else
            (.[0] | split("\t") | map(decode)) as $keys |
            if ($keys | unique | length) != ($keys | length) then error("duplicate columns") else
                .[1:] | map(split("\t") | map(decode) |
                    if length != ($keys | length) then error("invalid TSV row") else
                        . as $row | reduce range(0; $keys|length) as $i ({}; .[$keys[$i]] = $row[$i])
                    end)
            end
        end'
}

sql() {
    local result
    # Passwords belong in the protected client option file, never argv or logs.
    result=$(printf 'SET forward_to_master = true;\n%s;\n' "$1" |
        timeout --kill-after=5s "$COMMAND_TIMEOUT" "$MYSQL" "--defaults-extra-file=$MYSQL_CNF" \
            --batch --column-names --default-character-set=utf8mb4 --connect-timeout=10 \
            "--host=$MYSQL_HOST" "--port=$MYSQL_PORT" 2>"$WORK/client.err") ||
        fail "mysql failed or timed out; inspect client/server access. A submitted job may still run."
    printf '%s' "$result" | mysql_json || fail "Cannot parse mysql output"
}

hdfs_cmd() {
    timeout --kill-after=5s "$COMMAND_TIMEOUT" "$HDFS" dfs "$@" 2>"$WORK/client.err" ||
        fail "hdfs dfs $1 failed or timed out; check HDFS access, permissions and any existing lock"
}

hdfs_names() {
    hdfs_cmd -ls -C "$1" | sed 's|.*/||' | LC_ALL=C sort
}

publish() {
    local destination=$1 source=$2 temporary
    temporary="${destination%/*}/.upload_$(token)"
    hdfs_cmd -put "$source" "$temporary" >/dev/null
    hdfs_cmd -mv "$temporary" "$destination" >/dev/null
}

# Batched reads avoid starting a Hadoop JVM for every JSON record.
documents() {
    local folder=$1 listing name batch_file expected_file offset
    local -a paths=()
    listing=$(hdfs_names "$META/$folder")
    batch_file=$(mktemp "$WORK/documents.XXXXXX")
    expected_file=$(mktemp "$WORK/expected.XXXXXX")
    while IFS= read -r name; do
        [[ -z $name || $name =~ ^\.upload_[0-9a-f]{32}(\._COPYING_)?$ ]] && continue
        [[ $name =~ ^[A-Za-z0-9_-]+\.json$ ]] || fail "Unexpected entry in metadata folder $folder"
        paths+=("$META/$folder/$name")
        printf '%s\n' "${name%.json}" >>"$expected_file"
    done <<<"$listing"
    for ((offset=0; offset<${#paths[@]}; offset+=100)); do
        hdfs_cmd -cat "${paths[@]:offset:100}" >>"$batch_file"
        printf '\n' >>"$batch_file"
    done
    jq -se --arg owner "$OWNER" --arg folder "$folder" --rawfile expected "$expected_file" '
        if (map(.id)|sort) != ($expected|split("\n")|map(select(length>0))|sort)
        then error("document ID/filename mismatch") else . end |
        if all(.[]; .format == 1 and .owner == $owner and (.completed_at|type) == "string")
        then . else error("foreign or invalid metadata") end |
        if $folder == "records" then
            if all(.[]; .id|test("^mb_" + $owner[0:12] + "_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8}$"))
            then . else error("invalid snapshot ownership") end
        else
            if all(.[]; (.id|test("^[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8}$")) and
                (.tables|type) == "object" and (.tables|length) > 0)
            then . else error("invalid recovery point") end
        end' "$batch_file" || fail "Invalid $folder metadata; no cleanup or backup reuse is allowed"
}

save_document() {
    local folder=$1 source=$2 result id
    result=$(mktemp "$WORK/publish.XXXXXX")
    jq --arg owner "$OWNER" '. + {format:1, owner:$owner}' "$source" >"$result"
    id=$(jq -er '.id' "$result")
    publish "$META/$folder/$id.json" "$result"
}

snapshot_path() {
    [[ $1 =~ ^mb_${OWNER:0:12}_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8}$ ]] || fail "Foreign snapshot label"
    printf '%s/__ss_%s\n' "$ROOT" "$1"
}

load_config() {
    local config=$1 authority path permissions
    jq -e '
        (.tables|type)=="array" and (.tables|length)>0 and
        (.tables|length)==(.tables|unique|length) and
        all(.tables[]; type=="string") and
        ([.retention_days // 30, .job_timeout_seconds // 43200,
          .run_timeout_seconds // 72000, .poll_seconds // 30, .command_timeout_seconds // 120]
          | all(.[]; type=="number" and floor==. and .>0))' "$config" >/dev/null || fail "Invalid configuration"
    DB=$(jq -er '.database' "$config"); valid_name "$DB"
    REPO=$(jq -er '.repository' "$config"); valid_name "$REPO"
    LOCATION=$(jq -er '.hdfs_location' "$config"); LOCATION=${LOCATION%/}
    [[ $LOCATION =~ ^hdfs://[A-Za-z0-9._:-]+/[A-Za-z0-9_./-]+$ ]] || fail "Use an absolute dedicated hdfs:// URI"
    authority=${LOCATION#hdfs://}; authority=${authority%%/*}
    path=${LOCATION#hdfs://$authority}
    [[ $path != / && $path != *//* && $path != */../* && $path != */./* && $path != */.. && $path != */. ]] ||
        fail "Unsafe HDFS path"
    mapfile -t TABLES < <(jq -r '.tables[]' "$config")
    local table
    for table in "${TABLES[@]}"; do valid_name "$table"; done
    MYSQL=$(jq -r '.mysql.binary // "mysql"' "$config")
    MYSQL_HOST=$(jq -er '.mysql.host' "$config")
    MYSQL_PORT=$(jq -r '.mysql.port // 9030' "$config")
    MYSQL_CNF=$(jq -er '.mysql.defaults_extra_file' "$config")
    [[ $MYSQL_CNF == /* && -f $MYSQL_CNF ]] || fail "Use an existing absolute mysql defaults_extra_file"
    permissions=$(stat -c %a "$MYSQL_CNF")
    (( (8#$permissions & 077) == 0 )) || fail "mysql defaults_extra_file must have mode 0600"
    HDFS=$(jq -r '.hdfs_binary // "hdfs"' "$config")
    ZONE=$(jq -r '.timezone // "Asia/Shanghai"' "$config")
    [[ $ZONE =~ ^[A-Za-z0-9_+/-]+$ && $ZONE != *..* && -f /usr/share/zoneinfo/$ZONE ]] || fail "Invalid timezone"
    RETENTION=$(jq -r '.retention_days // 30' "$config")
    JOB_TIMEOUT=$(jq -r '.job_timeout_seconds // 43200' "$config")
    RUN_TIMEOUT=$(jq -r '.run_timeout_seconds // 72000' "$config")
    POLL=$(jq -r '.poll_seconds // 30' "$config")
    COMMAND_TIMEOUT=$(jq -r '.command_timeout_seconds // 120' "$config")
    (( RETENTION <= 36500 && JOB_TIMEOUT >= 600 && JOB_TIMEOUT <= 604800 &&
        RUN_TIMEOUT >= 600 && RUN_TIMEOUT <= 604800 && POLL <= 300 && COMMAND_TIMEOUT <= 3600 )) || fail "Invalid time limits"
    [[ $MYSQL_PORT =~ ^[0-9]+$ ]] && (( MYSQL_PORT>0 && MYSQL_PORT<=65535 )) || fail "Invalid MySQL port"
    command -v "$MYSQL" >/dev/null || fail "mysql client not found"
    command -v "$HDFS" >/dev/null || fail "hdfs client not found"
    ROOT="$LOCATION/__palo_repository_$REPO"
    META="$ROOT/_massdb_backup"
}

check_repository() {
    local repositories row ddl location default_fs
    repositories=$(sql 'SHOW REPOSITORIES')
    row=$(jq -ce --arg name "$REPO" '[.[]|select(.RepoName==$name)] |
        if length==1 and (.[0].IsReadOnly|ascii_downcase)=="false" then .[0]
        else error("missing or read-only repository") end' <<<"$repositories") || fail "Create a writable repository first"
    ddl=$(sql "SHOW CREATE REPOSITORY \`$REPO\`" | jq -er '.[0].CreateStmt')
    [[ $ddl =~ WITH[[:space:]]+HDFS ]] || fail "Only native WITH HDFS repositories are supported"
    location=$(jq -r '.Location' <<<"$row"); location=${location%/}
    if [[ $location == /* ]]; then
        default_fs=$(jq -nr --arg ddl "$ddl" '$ddl | capture("\"fs\\.defaultFS\"\\s*=\\s*\"(?<v>[^\"\\\\]+)\"").v') ||
            fail "Repository does not expose fs.defaultFS"
        location="${default_fs%/}$location"
    fi
    [[ $location == "$LOCATION" ]] || fail "Configured HDFS location differs from repository"
    hdfs_cmd -cat "$ROOT/__repo_info" | jq -e --arg name "$REPO" '.name==$name' >/dev/null || fail "HDFS repository identity mismatch"
}

lock_repository() {
    local initialize=$1 entries file owner_file
    check_repository
    if [[ $initialize == true ]]; then hdfs_cmd -mkdir -p "$META" >/dev/null; fi
    hdfs_cmd -mkdir "$META/lock" >/dev/null
    LOCKED=true
    file="$WORK/lock-owner.json"
    jq -n --arg host "$(hostname)" --arg pid "$$" --arg time "$(now)" \
        '{host:$host,pid:$pid,started_at:$time}' >"$file"
    publish "$META/lock/owner.json" "$file"
    entries=$(hdfs_names "$META")
    if ! [[ $'\n'$entries$'\n' == *$'\nowner.json\n'* ]]; then
        [[ $initialize == true && $entries == lock ]] || fail "Metadata directory is not initialized or contains unexpected files"
        OWNER=$(token)
        jq -n --arg owner "$OWNER" --arg db "$DB" --arg repo "$REPO" --arg location "$LOCATION" \
            '{format:1,owner:$owner,database:$db,repository:$repo,hdfs_location:$location}' >"$WORK/owner.json"
        publish "$META/owner.json" "$WORK/owner.json"
    fi
    owner_file="$WORK/owner-read.json"
    hdfs_cmd -cat "$META/owner.json" >"$owner_file"
    jq -e --arg db "$DB" --arg repo "$REPO" --arg location "$LOCATION" \
        '.format==1 and .database==$db and .repository==$repo and .hdfs_location==$location and
        (.owner|test("^[0-9a-f]{32}$"))' "$owner_file" >/dev/null || fail "Repository policy identity mismatch"
    OWNER=$(jq -r .owner "$owner_file")
    hdfs_cmd -mkdir -p "$META/points" "$META/records" "$META/pins" >/dev/null
}

cleanup() {
    local status=$?
    trap - EXIT
    if [[ ${LOCKED:-false} == true ]]; then
        if ! timeout --kill-after=5s "$COMMAND_TIMEOUT" "$HDFS" dfs -rm -f "$META/lock/owner.json" \
            > /dev/null 2>"$WORK/client.err" ||
           ! timeout --kill-after=5s "$COMMAND_TIMEOUT" "$HDFS" dfs -rmdir "$META/lock" \
            > /dev/null 2>"$WORK/client.err"; then
            log "Lock release failed; inspect the owner process and database jobs before removing the stale lock"
            status=1
        fi
    fi
    [[ -z ${WORK:-} ]] || rm -rf -- "$WORK"
    exit "$status"
}

require_idle() {
    local kind rows
    for kind in BACKUP RESTORE; do
        rows=$(sql "SHOW $kind FROM \`$DB\`")
        jq -e 'all(.[]; .State=="FINISHED" or .State=="CANCELLED")' <<<"$rows" >/dev/null ||
            fail "Database has an active $kind job; inspect it before retrying"
    done
}

master() {
    sql 'SHOW FRONTENDS' | jq -ce '[.[]|select(.CurrentConnected=="Yes")] |
        if length==1 and (.[0].IsMaster|ascii_downcase)=="true" then .[0]
        else error("connected FE is not master") end' || fail "Connect directly to the current master FE"
}

observe() {
    local table=$1 front after db_id table_row table_id ddl partitions indexes temporary
    front=$(master)
    db_id=$(sql "SHOW PROC '/dbs'" | jq -er --arg db "$DB" \
        '[.[]|select(.DbName==$db)] | if length==1 then .[0].DbId else error("database missing") end')
    [[ $db_id =~ ^[0-9]+$ ]] || fail "Invalid database ID"
    table_row=$(sql "SHOW PROC '/dbs/$db_id'" | jq -ce --arg table "$table" \
        '[.[]|select(.TableName==$table)] | if length==1 and .[0].Type=="OLAP" and .[0].State=="NORMAL"
        then .[0] else error("table missing or not a normal OLAP table") end') || fail "Table $table is not a NORMAL OLAP table"
    table_id=$(jq -r .TableId <<<"$table_row")
    [[ $table_id =~ ^[0-9]+$ ]] || fail "Invalid table ID"
    ddl=$(sql "SHOW CREATE TABLE \`$DB\`.\`$table\`" | jq -er '.[0]["Create Table"]')
    partitions=$(sql "SHOW PARTITIONS FROM \`$DB\`.\`$table\`")
    jq -e 'all(.[]; .State=="NORMAL")' <<<"$partitions" >/dev/null || fail "Partition of $table is not NORMAL"
    temporary=$(sql "SHOW TEMPORARY PARTITIONS FROM \`$DB\`.\`$table\`")
    [[ $temporary == '[]' ]] || fail "Temporary partitions are not covered by this backup policy"
    indexes=$(sql "SHOW PROC '/dbs/$db_id/$table_id/index_schema'")
    after=$(master)
    jq -ne --argjson a "$front" --argjson b "$after" '$a.Name==$b.Name and $a.Version==$b.Version and $a.ClusterId==$b.ClusterId' \
        >/dev/null || fail "FE identity/version changed while reading metadata"
    jq -n --arg table_id "$table_id" --arg ddl "$ddl" --argjson parts "$partitions" --argjson indexes "$indexes" \
        --argjson row "$table_row" --argjson front "$front" \
        '{table_id:$table_id,ddl:$ddl,engine_version:$front.Version,cluster_id:$front.ClusterId,
          partitions:($parts|map({name:.PartitionName,id:(.PartitionId|tonumber),version:(.VisibleVersion|tonumber)})|sort_by(.id)),
          indexes:($indexes|sort_by(.IndexId|tonumber)),running_transactions:($row.RunningTransactionNum|tonumber)}'
}

wait_job() {
    local kind=$1 label=$2 deadline=$3 previous=${4:-'[]'} key rows count state job last=''
    key=Label; [[ $kind != BACKUP ]] || key=SnapshotName
    while (( SECONDS < deadline )); do
        rows=$(sql "SHOW $kind FROM \`$DB\`" | jq -c --arg key "$key" --arg label "$label" --argjson previous "$previous" \
            '[.[] | select(.[$key]==$label) | select(.JobId as $id | $previous|index($id)|not)]')
        count=$(jq length <<<"$rows")
        (( count <= 1 )) || fail "Ambiguous $kind job identity"
        if (( count == 1 )); then
            state=$(jq -r '.[0].State' <<<"$rows"); job=$(jq -r '.[0].JobId' <<<"$rows")
            if [[ $state != "$last" ]]; then log "$kind $label: $state (job $job)"; last=$state; fi
            [[ $state != CANCELLED ]] || fail "$kind $label CANCELLED; inspect Status and TaskErrMsg"
            [[ $state != FINISHED ]] || return 0
        fi
        sleep "$POLL"
    done
    fail "$kind $label timed out; the server job may still run. No completion recorded."
}

verify_snapshot() {
    local label=$1 table=$2 timestamp=${3:-} rows actual directory names info_name checksum
    local -a info_files=()
    directory=$(snapshot_path "$label")
    rows=$(sql "SHOW SNAPSHOT ON \`$REPO\` WHERE SNAPSHOT = '$label'")
    actual=$(jq -er 'if length==1 and .[0].Status=="OK" then .[0].Timestamp else error("snapshot unavailable") end' <<<"$rows") ||
        fail "Snapshot $label is not available"
    [[ $actual =~ ^[0-9]{4}(-[0-9]{2}){5}$ && ( -z $timestamp || $actual == "$timestamp" ) ]] || fail "Snapshot timestamp mismatch"
    names=$(hdfs_names "$directory")
    while IFS= read -r info_name; do
        [[ $info_name =~ ^__info_${actual}\.[0-9a-f]{32}$ ]] && info_files+=("$info_name")
    done <<<"$names"
    (( ${#info_files[@]} == 1 )) || fail "Native backup info is missing or ambiguous"
    [[ $names =~ __meta\.[0-9a-f]{32} ]] || fail "Native table metadata is missing"
    hdfs_cmd -cat "$directory/${info_files[0]}" >"$WORK/native-info.json"
    checksum=$(md5sum "$WORK/native-info.json"); checksum=${checksum%% *}
    [[ $checksum == "${info_files[0]##*.}" ]] || fail "Native backup info checksum mismatch"
    jq -e --arg label "$label" --arg db "$DB" --arg table "$table" \
        '.name==$label and .database==$db and .backup_result=="succeed" and .content=="ALL" and
        (.backup_objects|keys)==[$table]' "$WORK/native-info.json" >/dev/null || fail "Snapshot is not the expected complete table"
    if [[ $(jq --arg table "$table" '.backup_objects[$table].partitions|length' "$WORK/native-info.json") != 0 ]]; then
        [[ $'\n'$names$'\n' == *$'\n__ss_content\n'* ]] || fail "Snapshot data directory is missing"
    fi
    jq --arg table "$table" --arg ts "$actual" \
        '{backup_timestamp:$ts,table:.backup_objects[$table]}' "$WORK/native-info.json"
}

same_json() { jq -ne --argjson a "$1" --argjson b "$2" '$a==$b' >/dev/null; }

do_backup() {
    local started point_id deadline points records previous entries='{}' observations='{}'
    local table before after old old_entry native label remaining timeout timestamp reusable value
    [[ $REUSE == false || $QUIESCED == true ]] || fail "--reuse-unchanged requires --quiesced"
    require_idle
    started=$(now); point_id=$(new_id); deadline=$((SECONDS+RUN_TIMEOUT))
    points=$(documents points); records=$(documents records)
    previous=$(jq -c 'sort_by(.completed_at)|last|.tables // {}' <<<"$points")
    for table in "${TABLES[@]}"; do
        remaining=$((deadline-SECONDS)); (( remaining >= 600 )) || fail "Insufficient time for next backup; no complete recovery point"
        before=$(observe "$table")
        if [[ $QUIESCED == true ]]; then
            [[ $(jq .running_transactions <<<"$before") == 0 ]] || fail "$table has in-flight transactions"
        fi
        old_entry=$(jq -c --arg table "$table" '.[$table] // null' <<<"$previous")
        old=$(jq -c --argjson entry "$old_entry" '[.[]|select(.id==$entry.label)] | first // null' <<<"$records")
        if [[ $old != null ]]; then
            jq -ne --argjson old "$old" --argjson entry "$old_entry" --arg table "$table" \
                '$old.table==$table and $old.backup_timestamp==$entry.backup_timestamp' >/dev/null || fail "Previous recovery point/record mismatch"
        fi
        if [[ $REUSE == true && $old != null ]] &&
            jq -ne --argjson old "$old" --argjson observation "$before" '$old.reusable==true and $old.observation==$observation' >/dev/null; then
            label=$(jq -r .id <<<"$old"); timestamp=$(jq -r .backup_timestamp <<<"$old")
            verify_snapshot "$label" "$table" "$timestamp" >/dev/null
            after=$(observe "$table"); same_json "$before" "$after" || fail "$table changed during reuse verification"
            log "REUSE $table: $label"
        else
            label="mb_${OWNER:0:12}_$(new_id)"
            timeout=$JOB_TIMEOUT; (( timeout <= remaining )) || timeout=$remaining
            sql "BACKUP SNAPSHOT \`$DB\`.\`$label\` TO \`$REPO\` ON (\`$table\`) PROPERTIES ('type'='full','timeout'='$timeout')" >/dev/null
            wait_job BACKUP "$label" "$((SECONDS+timeout))"
            native=$(verify_snapshot "$label" "$table")
            timestamp=$(jq -r .backup_timestamp <<<"$native")
            after=$(observe "$table")
            jq -ne --argjson before "$before" --argjson after "$after" --argjson native "$native" '
                def structure: {table_id,ddl,indexes,engine_version,cluster_id};
                ($before|structure)==($after|structure) and ($before.table_id|tonumber)==$native.table.id' >/dev/null ||
                fail "Structure of $table changed during backup; no complete recovery point"
            reusable=false
            if [[ $QUIESCED == true ]]; then
                same_json "$before" "$after" || fail "$table changed in the declared quiescent window"
                jq -ne --argjson before "$before" --argjson native "$native" \
                    '$before.partitions==($native.table.partitions|to_entries|map({name:.key,id:.value.id,version:.value.version})|sort_by(.id))' \
                    >/dev/null || fail "$table native snapshot does not match observed versions"
                reusable=true
            fi
            jq -n --arg id "$label" --arg table "$table" --arg timestamp "$timestamp" --arg completed "$(now)" \
                --argjson observation "$before" --argjson reusable "$reusable" \
                '{id:$id,table:$table,backup_timestamp:$timestamp,completed_at:$completed,observation:$observation,reusable:$reusable}' \
                >"$WORK/record.json"
            save_document records "$WORK/record.json"
        fi
        entries=$(jq -c --arg table "$table" --arg label "$label" --arg ts "$timestamp" \
            '.[$table]={label:$label,backup_timestamp:$ts}' <<<"$entries")
        observations=$(jq -c --arg table "$table" --argjson value "$after" '.[$table]=$value' <<<"$observations")
    done
    if [[ $QUIESCED == true ]]; then
        for table in "${TABLES[@]}"; do
            value=$(jq -c --arg table "$table" '.[$table]' <<<"$observations")
            after=$(observe "$table"); same_json "$value" "$after" || fail "$table changed before publishing the recovery point"
        done
    fi
    jq -n --arg id "$point_id" --arg started "$started" --arg completed "$(now)" --argjson entries "$entries" \
        --argjson quiesced "$QUIESCED" \
        '{id:$id,started_at:$started,completed_at:$completed,tables:$entries,quiesced:$quiesced}' >"$WORK/point.json"
    save_document points "$WORK/point.json"
    log "COMPLETE recovery point $point_id: ${#TABLES[@]} tables"
}

find_point() {
    local points pins
    points=$(json_file "$(documents points)"); pins=$(json_file "$(documents pins)")
    jq -ne --arg name "$1" --slurpfile points "$points" --slurpfile pins "$pins" '
        $points[0] as $points | $pins[0] as $pins |
        ($points+$pins|unique_by(.id)) |
        (if $name=="latest" then sort_by(.completed_at)|last else map(select(.id==$name))|first end) |
        if . == null then error("recovery point missing") else . end' || fail "Recovery point not found; use list"
}

do_restore() {
    local point records entry record label timestamp existing previous restore_sql output
    valid_name "$TABLE"; valid_name "$TARGET"
    [[ ${TABLE,,} != "${TARGET,,}" ]] || fail "Restore to a different, nonexistent table"
    require_idle
    point=$(find_point "$POINT")
    entry=$(jq -ce --arg table "$TABLE" '.tables[$table]' <<<"$point") || fail "Table is absent from recovery point"
    records=$(documents records)
    record=$(jq -ce --argjson entry "$entry" --arg table "$TABLE" \
        '[.[]|select(.id==$entry.label and .table==$table and .backup_timestamp==$entry.backup_timestamp)] |
        if length==1 then .[0] else error("record mismatch") end' <<<"$records") || fail "Backup record mismatch"
    existing=$(sql "SHOW TABLES FROM \`$DB\`")
    jq -e --arg target "$TARGET" 'all(.[]; all(.[]; (ascii_downcase)!=($target|ascii_downcase)))' \
        <<<"$existing" >/dev/null || fail "Restore target exists"
    label=$(jq -r .label <<<"$entry"); timestamp=$(jq -r .backup_timestamp <<<"$entry")
    verify_snapshot "$label" "$TABLE" "$timestamp" >/dev/null
    mkdir -p -- "$OUTPUT"
    output=$(cd -- "$OUTPUT" && pwd)
    [[ ! -e $output/$TARGET.swap.sql && ! -e $output/$TARGET.backup-ddl.sql ]] || fail "SQL output already exists"
    previous=$(sql "SHOW RESTORE FROM \`$DB\`" | jq -c 'map(.JobId)')
    restore_sql="RESTORE SNAPSHOT \`$DB\`.\`$label\` FROM \`$REPO\` ON (\`$TABLE\` AS \`$TARGET\`) PROPERTIES ('backup_timestamp'='$timestamp','reserve_replica'='true','timeout'='$JOB_TIMEOUT')"
    sql "$restore_sql" >/dev/null
    wait_job RESTORE "$label" "$((SECONDS+JOB_TIMEOUT))" "$previous"
    observe "$TARGET" >/dev/null
    (
        set -o noclobber
        jq -r '.observation.ddl + ";"' <<<"$record" >"$output/$TARGET.backup-ddl.sql"
        {
            printf '%s\n' '-- Restore FINISHED. Validate schema, partitions and business data before executing.'
            printf '%s\n' '-- Pause writes/DDL and drain imports first. Reconcile dynamic partition/colocate settings.'
            printf 'ALTER TABLE `%s`.`%s` REPLACE WITH TABLE `%s` PROPERTIES ("swap"="true");\n' "$DB" "$TABLE" "$TARGET"
        } >"$output/$TARGET.swap.sql"
    )
    log "RESTORED $DB.$TARGET; validate it, then use $output/$TARGET.swap.sql"
}

# Pure retention planner; dates are annotated in the configured local timezone.
retention_plan() {
    local points_file records_file pins_file
    points_file=$(json_file "$1"); records_file=$(json_file "$2"); pins_file=$(json_file "$3")
    jq -ne --slurpfile points "$points_file" --slurpfile records "$records_file" --slurpfile pins "$pins_file" --arg cutoff "$4" '
        $points[0] as $points | $records[0] as $records | $pins[0] as $pins |
        if ($points|length)==0 then error("no complete recovery point") else . end |
        ($points|sort_by(.completed_at)|last) as $latest |
        ($points|map(select(._local_date >= $cutoff or .id==$latest.id))) as $keep |
        ($keep+$pins|[.[].tables|.[]|.label]|unique) as $refs |
        ($records|map({key:.id,value:.})|from_entries) as $index |
        if all(($keep+$pins)[].tables|to_entries[];
            .value as $entry | .key as $table |
            $index[$entry.label].table==$table and $index[$entry.label].backup_timestamp==$entry.backup_timestamp)
        then {latest:$latest,expired:($points|map(select(._local_date < $cutoff and .id!=$latest.id))),
              unused:($records|map(select(._local_date < $cutoff)|select(.id as $id|$refs|index($id)|not)))}
        else error("retained recovery point references missing or inconsistent backup record") end'
}

annotate_dates() {
    local rows=$1 field=$2 row value local_date output='[]'
    while IFS= read -r row; do
        value=$(jq -er --arg field "$field" '.[$field]' <<<"$row")
        [[ $value =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || fail "Invalid metadata timestamp"
        local_date=$(TZ="$ZONE" date -d "$value" +%F) || fail "Invalid metadata date"
        output=$(jq -c --argjson row "$row" --arg date "$local_date" '.+[$row+{_local_date:$date}]' <<<"$output")
    done < <(jq -c '.[]' <<<"$rows")
    printf '%s\n' "$output"
}

do_prune() {
    local points records pins cutoff plan latest completed age row id path prefix
    require_idle
    points=$(documents points)
    records=$(documents records | jq 'map({id,table,backup_timestamp,completed_at})')
    pins=$(documents pins)
    points=$(annotate_dates "$points" started_at)
    records=$(annotate_dates "$records" completed_at)
    cutoff=$(TZ="$ZONE" date -d "$(TZ="$ZONE" date +%F) 12:00:00 $((RETENTION-1)) days ago" +%F)
    plan=$(retention_plan "$points" "$records" "$pins" "$cutoff") || fail "Invalid retention references; cleanup refused"
    latest=$(jq -er '.latest.completed_at' <<<"$plan")
    completed=$(date -d "$latest" +%s); age=$(($(date +%s)-completed))
    (( age >= 0 )) || fail "Recovery point is in the future; check clocks"
    [[ $APPLY == false ]] || (( age < 129600 )) || fail "Latest complete recovery point is older than 36 hours; cleanup refused"
    prefix='WOULD DELETE'; [[ $APPLY == false ]] || prefix=DELETE
    while IFS= read -r row; do
        id=$(jq -r .id <<<"$row")
        log "$prefix recovery point $id"
        if [[ $APPLY == true ]]; then hdfs_cmd -rm "$META/points/$id.json" >/dev/null; fi
    done < <(jq -c '.expired[]' <<<"$plan")
    while IFS= read -r row; do
        id=$(jq -r .id <<<"$row"); path=$(snapshot_path "$id")
        log "$prefix unreferenced snapshot $id"
        if [[ $APPLY == true ]]; then
            # Respect HDFS Trash. -f makes a crash between snapshot/record deletion retryable.
            hdfs_cmd -rm -r -f "$path" >/dev/null
            hdfs_cmd -rm "$META/records/$id.json" >/dev/null
        fi
    done < <(jq -c '.unused[]' <<<"$plan")
    log "Cleanup apply=$APPLY: $(jq '.expired|length' <<<"$plan") points, $(jq '.unused|length' <<<"$plan") snapshots"
}

do_pin() {
    local point id pins
    point=$(find_point "$POINT"); id=$(jq -r .id <<<"$point"); pins=$(documents pins)
    if [[ $COMMAND == unpin ]]; then
        jq -e --arg id "$id" 'any(.[]; .id==$id)' <<<"$pins" >/dev/null || fail "Point is not pinned"
        hdfs_cmd -rm "$META/pins/$id.json" >/dev/null
    elif ! jq -e --arg id "$id" 'any(.[]; .id==$id)' <<<"$pins" >/dev/null; then
        printf '%s\n' "$point" >"$WORK/pin.json"
        save_document pins "$WORK/pin.json"
    fi
    log "$COMMAND $id"
}

main() {
    [[ ${1:-} != --help && ${1:-} != -h ]] || { usage; return 0; }
    [[ ${1:-} == --config && $# -ge 3 ]] || { usage >&2; return 2; }
    local config=$2 dependency initialize=false points pins
    COMMAND=$3; shift 3
    REUSE=false; QUIESCED=false; APPLY=false; POINT=''; TABLE=''; TARGET=''; OUTPUT=''; LOCKED=false
    case "$COMMAND" in backup|list|restore|prune|pin|unpin) ;; *) fail "Unknown command: $COMMAND";; esac
    while (( $# )); do
        case "$1" in
            --reuse-unchanged) [[ $COMMAND == backup ]] || fail "Invalid option"; REUSE=true; shift;;
            --quiesced) [[ $COMMAND == backup ]] || fail "Invalid option"; QUIESCED=true; shift;;
            --apply) [[ $COMMAND == prune ]] || fail "Invalid option"; APPLY=true; shift;;
            --point|--table|--as|--output-dir)
                (( $# >= 2 )) || fail "Missing option argument"
                case "$1" in --point) POINT=$2;; --table) TABLE=$2;; --as) TARGET=$2;; --output-dir) OUTPUT=$2;; esac
                shift 2;;
            *) fail "Unknown option: $1";;
        esac
    done
    [[ $REUSE == false || $QUIESCED == true ]] || fail "--reuse-unchanged requires --quiesced"
    if [[ $COMMAND == restore ]]; then
        [[ -n $POINT && -n $TABLE && -n $TARGET && -n $OUTPUT ]] || fail "restore requires --point, --table, --as and --output-dir"
    fi
    if [[ $COMMAND == pin || $COMMAND == unpin ]]; then [[ -n $POINT ]] || fail "--point is required"; fi
    for dependency in jq timeout date stat od tr sed sort cut md5sum mktemp; do
        command -v "$dependency" >/dev/null || fail "Missing dependency: $dependency"
    done
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/massdb-backup.XXXXXXXX")
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    load_config "$config"
    [[ $COMMAND != backup ]] || initialize=true
    lock_repository "$initialize"
    case "$COMMAND" in
        backup) do_backup;;
        restore) do_restore;;
        prune) do_prune;;
        pin|unpin) do_pin;;
        list)
            points=$(json_file "$(documents points)"); pins=$(json_file "$(documents pins)")
            jq -nr --slurpfile points "$points" --slurpfile pins "$pins" \
                '$points[0] as $points | $pins[0] as $pins |
                ($pins|map(.id)) as $pinned | $points+$pins|unique_by(.id)|sort_by(.completed_at)[] |
                [.id,.completed_at,(.tables|length), (if (.id as $id|$pinned|index($id))!=null then "PINNED" else "" end)]|@tsv';;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
