#!/usr/bin/env bash
# Copyright (c) 2026
# 厦门市美亚柏科信息安全研究所有限公司
# Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
# SPDX-License-Identifier: LicenseRef-MassDB-Commercial
# Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
# Upstream and third-party components retain their respective licenses.

# Offline tests: real Bash/jq parsing and workflows, with SQL/HDFS boundaries stubbed.
set -Eeuo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/massdb_backup.sh"

setup_case() {
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/massdb-backup-test.XXXXXXXX")
    trap 'rm -rf -- "$WORK"' EXIT
    OWNER=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    DB=biz; REPO=daily_repo; LOCATION=hdfs://ns/backup
    ROOT="$LOCATION/__palo_repository_$REPO"; META="$ROOT/_massdb_backup"
    TABLES=(orders); RUN_TIMEOUT=72000; JOB_TIMEOUT=43200; POLL=1; COMMAND_TIMEOUT=10
    ZONE=Asia/Shanghai; RETENTION=30; REUSE=false; QUIESCED=false; APPLY=false
    LABEL="mb_${OWNER:0:12}_20260801T020000Z_00000001"
    LABEL2="mb_${OWNER:0:12}_20260801T020000Z_00000002"
    TS=2026-10-01-02-00-00
    POINT_ID=20261001T020000Z_00000001
    OBS='{"table_id":"42","ddl":"CREATE TABLE orders (id INT) ENGINE=OLAP","partitions":[{"name":"orders","id":51,"version":3}],"indexes":[{"IndexId":"42","SchemaHash":"101","SchemaVersion":"1"}],"running_transactions":0,"engine_version":"4.0.5-build1","cluster_id":"88"}'
}

assert_fail() {
    if ( "$@" ); then fail "Expected failure: $*"; fi
}

make_record() {
    jq -n --arg id "$1" --arg ts "$TS" --arg owner "$OWNER" --argjson obs "$OBS" \
        '{id:$id,table:"orders",backup_timestamp:$ts,completed_at:"2026-08-01T00:00:00Z",
          format:1,owner:$owner,observation:$obs,reusable:true,_local_date:"2026-08-01"}'
}

make_point() {
    jq -n --arg id "$1" --arg label "$2" --arg date "$3" --arg ts "$TS" --arg owner "$OWNER" \
        '{id:$id,started_at:($date+"T00:00:00Z"),completed_at:($date+"T00:00:00Z"),
          tables:{orders:{label:$label,backup_timestamp:$ts}},owner:$owner,format:1,_local_date:$date}'
}

setup_workflow() {
    printf '[]\n' >"$WORK/points.json"
    printf '[]\n' >"$WORK/records.json"
    printf '[]\n' >"$WORK/pins.json"
    : >"$WORK/sql.log"
    require_idle() { :; }
    observe() { printf '%s\n' "$OBS"; }
    documents() { cat "$WORK/$1.json"; }
    sql() { printf '%s\n' "$1" >>"$WORK/sql.log"; printf '[]\n'; }
    wait_job() { :; }
    verify_snapshot() {
        jq -n --arg ts "$TS" '{backup_timestamp:$ts,table:{id:42,partitions:{orders:{id:51,version:3}}}}'
    }
    save_document() {
        jq --slurpfile doc "$2" '.+[$doc[0]]' "$WORK/$1.json" >"$WORK/saved.json"
        mv "$WORK/saved.json" "$WORK/$1.json"
    }
}

add_prior() {
    make_record "$LABEL" | jq -s '.' >"$WORK/records.json"
    make_point "$POINT_ID" "$LABEL" 2026-10-01 | jq -s '.' >"$WORK/points.json"
}

test_tsv_escapes() {
    local result expected
    result=$(printf '%s\t%s\n' 'Create Table' 'Value' 'CREATE TABLE x (\n`a\\b` INT\tCOMMENT "x"\n)' 'NULL' | mysql_json)
    expected=$'CREATE TABLE x (\n`a\\b` INT\tCOMMENT "x"\n)'
    jq -e --arg expected "$expected" '.[0]["Create Table"]==$expected and .[0].Value=="NULL"' <<<"$result" >/dev/null
    result=$(printf '%s\n' 'Value' 'literal\\n then newline\nend' | mysql_json)
    jq -e --arg expected $'literal\\n then newline\nend' '.[0].Value==$expected' <<<"$result" >/dev/null
}

test_tsv_malformed() {
    if printf 'a\tb\nx\n' | mysql_json; then fail 'Malformed TSV accepted'; fi
    if printf 'a\ta\nx\ty\n' | mysql_json; then fail 'Duplicate columns accepted'; fi
    [[ $(printf '' | mysql_json) == '[]' ]]
}

test_identifier_injection() {
    assert_fail valid_name 'x`; DROP TABLE t'
    assert_fail valid_name '../x'
    assert_fail valid_name 'db.table'
    valid_name orders_2026
}

test_config_paths_and_credentials() {
    printf '[client]\nuser=test\npassword=not-printed\n' >"$WORK/mysql.cnf"
    jq --arg cnf "$WORK/mysql.cnf" '.mysql.defaults_extra_file=$cnf | .mysql.binary="/usr/bin/true" |
        .hdfs_binary="/usr/bin/true"' "$SCRIPT_DIR/config.example.json" >"$WORK/config.json"
    load_config "$WORK/config.json"
    chmod 644 "$WORK/mysql.cnf"
    assert_fail load_config "$WORK/config.json"
    chmod 600 "$WORK/mysql.cnf"
    local uri
    for uri in hdfs://ns/ hdfs://ns/a/../b hdfs://ns/a//b 'hdfs://ns/a/*' file:///backup; do
        jq --arg uri "$uri" '.hdfs_location=$uri' "$WORK/config.json" >"$WORK/bad.json"
        assert_fail load_config "$WORK/bad.json"
    done
}

test_repository_namespace() {
    sql() {
        if [[ $1 == 'SHOW REPOSITORIES' ]]; then
            printf '[{"RepoName":"daily_repo","IsReadOnly":"false","Location":"/backup"}]\n'
        else
            jq -n '[{CreateStmt:"CREATE REPOSITORY daily_repo WITH HDFS PROPERTIES (\"fs.defaultFS\" = \"hdfs://wrong\")"}]'
        fi
    }
    assert_fail check_repository
}

test_documents_batch_and_partial_upload() {
    make_record "$LABEL" >"$WORK/record.json"
    hdfs_names() { printf '%s\n' ".upload_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "$LABEL.json"; }
    hdfs_cmd() { [[ $1 == -cat ]]; cat "$WORK/record.json"; }
    documents records | jq -e --arg id "$LABEL" 'length==1 and .[0].id==$id' >/dev/null
    hdfs_names() { printf 'unexpected\n'; }
    assert_fail documents records
}

test_foreign_snapshot() {
    assert_fail snapshot_path '__repo_info'
    assert_fail snapshot_path '../escape'
    assert_fail snapshot_path 'mb_bbbbbbbbbbbb_20260801T020000Z_00000001'
    [[ $(snapshot_path "$LABEL") == "$ROOT/__ss_$LABEL" ]]
}

test_retention_references() {
    local points records result old recent
    old=$(make_point "$POINT_ID" "$LABEL" 2026-08-01)
    recent=$(make_point 20261012T020000Z_00000002 "$LABEL" 2026-10-12)
    points=$(jq -n --argjson old "$old" --argjson recent "$recent" '[$old,$recent]')
    records=$( { make_record "$LABEL"; make_record "$LABEL2"; } | jq -s '.')
    result=$(retention_plan "$points" "$records" '[]' 2026-09-13)
    jq -e --arg label "$LABEL2" --arg point "$POINT_ID" \
        '.expired|length==1' <<<"$result" >/dev/null
    jq -e --arg label "$LABEL2" '.unused|length==1 and .[0].id==$label' <<<"$result" >/dev/null
}

test_pin_protects_old_snapshot() {
    local old recent records pins result
    old=$(make_point "$POINT_ID" "$LABEL" 2026-08-01)
    recent=$(make_point 20261012T020000Z_00000002 "$LABEL2" 2026-10-12 | jq -s '.')
    records=$( { make_record "$LABEL"; make_record "$LABEL2"; } | jq -s '.')
    pins=$(jq -n --argjson old "$old" '[$old]')
    result=$(retention_plan "$recent" "$records" "$pins" 2026-09-13)
    jq -e '.unused==[]' <<<"$result" >/dev/null
}

test_retention_missing_record_and_timestamp() {
    local points records
    points=$(make_point "$POINT_ID" "$LABEL" 2026-10-12 | jq -s '.')
    assert_fail retention_plan "$points" '[]' '[]' 2026-09-13
    records=$(make_record "$LABEL" | jq -s '.[0].backup_timestamp="2026-10-02-02-00-00"')
    assert_fail retention_plan "$points" "$records" '[]' 2026-09-13
}

test_calendar_boundaries() {
    local points annotated result records
    points=$(make_point "$POINT_ID" "$LABEL" 2026-09-12 | jq -s '.[0].started_at="2026-09-12T16:00:00Z"')
    annotated=$(annotate_dates "$points" started_at)
    jq -e '.[0]._local_date=="2026-09-13"' <<<"$annotated" >/dev/null
    records=$(make_record "$LABEL" | jq -s '.')
    result=$(retention_plan "$annotated" "$records" '[]' 2026-09-13)
    jq -e '.expired==[] and .unused==[]' <<<"$result" >/dev/null
}

test_default_full() {
    setup_workflow; add_prior
    do_backup
    jq -e 'length==2 and .[1].reusable==false' "$WORK/records.json" >/dev/null
    jq -e --arg old "$LABEL" 'length==2 and .[1].tables.orders.label!=$old' "$WORK/points.json" >/dev/null
    [[ $(cat "$WORK/sql.log") == BACKUP* ]]
}

test_reuse_requires_quiescence() {
    setup_workflow; REUSE=true
    assert_fail do_backup
    [[ ! -s $WORK/sql.log ]]
}

test_unchanged_reuse() {
    setup_workflow; add_prior; REUSE=true; QUIESCED=true
    do_backup
    jq -e 'length==1' "$WORK/records.json" >/dev/null
    jq -e --arg old "$LABEL" 'length==2 and .[1].tables.orders.label==$old' "$WORK/points.json" >/dev/null
    [[ ! -s $WORK/sql.log ]]
}

test_engine_change_forces_backup() {
    setup_workflow; add_prior; REUSE=true; QUIESCED=true
    OBS=$(jq '.engine_version="4.0.5-build2"' <<<"$OBS")
    do_backup
    jq -e 'length==2 and .[1].reusable==true' "$WORK/records.json" >/dev/null
    [[ -s $WORK/sql.log ]]
}

test_failed_backup_no_point() {
    setup_workflow
    wait_job() { fail 'Cancelled'; }
    assert_fail do_backup
    jq -e 'length==0' "$WORK/points.json" >/dev/null
    jq -e 'length==0' "$WORK/records.json" >/dev/null
}

test_structure_change_no_point() {
    setup_workflow
    observe() {
        if [[ -e $WORK/observed ]]; then jq '.ddl="CREATE TABLE orders (different INT)"' <<<"$OBS";
        else touch "$WORK/observed"; printf '%s\n' "$OBS"; fi
    }
    assert_fail do_backup
    jq -e 'length==0' "$WORK/points.json" >/dev/null
}

test_write_after_reuse_blocks_publication() {
    setup_workflow; add_prior; REUSE=true; QUIESCED=true
    observe() {
        local count=0
        [[ ! -e $WORK/count ]] || count=$(cat "$WORK/count")
        count=$((count+1)); printf '%s\n' "$count" >"$WORK/count"
        if ((count>=3)); then jq '.partitions[0].version=4' <<<"$OBS"; else printf '%s\n' "$OBS"; fi
    }
    assert_fail do_backup
    jq -e 'length==1' "$WORK/points.json" >/dev/null
}

test_inflight_transactions() {
    setup_workflow; add_prior; REUSE=true; QUIESCED=true
    OBS=$(jq '.running_transactions=1' <<<"$OBS")
    assert_fail do_backup
    jq -e 'length==1' "$WORK/points.json" >/dev/null
}

test_partial_run() {
    setup_workflow; TABLES=(orders customers)
    wait_job() { [[ ! -e $WORK/completed ]] || fail 'Second table failed'; touch "$WORK/completed"; }
    assert_fail do_backup
    jq -e 'length==1' "$WORK/records.json" >/dev/null
    jq -e 'length==0' "$WORK/points.json" >/dev/null
}

test_wait_ignores_old_finished() {
    sql() { jq -n --arg label "$LABEL" '[{Label:$label,JobId:"old",State:"FINISHED"},{Label:$label,JobId:"new",State:"CANCELLED"}]'; }
    assert_fail wait_job RESTORE "$LABEL" "$((SECONDS+5))" '["old"]'
    sql() { jq -n --arg label "$LABEL" '[{Label:$label,JobId:"old",State:"FINISHED"},{Label:$label,JobId:"new",State:"FINISHED"}]'; }
    wait_job RESTORE "$LABEL" "$((SECONDS+5))" '["old"]'
}

test_poll_timeout_and_failure() {
    assert_fail wait_job BACKUP "$LABEL" "$SECONDS"
    sql() { jq -n --arg label "$LABEL" '[{SnapshotName:$label,JobId:"1",State:"CANCELLED"}]'; }
    assert_fail wait_job BACKUP "$LABEL" "$((SECONDS+5))"
}

test_restore_swap_only_generated() {
    setup_workflow; add_prior
    POINT=latest; TABLE=orders; TARGET=orders_restore; OUTPUT="$WORK/restore"
    do_restore
    [[ -f $OUTPUT/$TARGET.swap.sql && -f $OUTPUT/$TARGET.backup-ddl.sql ]]
    [[ $(cat "$OUTPUT/$TARGET.swap.sql") == *'REPLACE WITH TABLE `orders_restore` PROPERTIES ("swap"="true")'* ]]
    [[ $(cat "$WORK/sql.log") != *'ALTER TABLE'* && $(cat "$WORK/sql.log") != *'DROP TABLE'* ]]
}

test_restore_failure_no_swap() {
    setup_workflow; add_prior
    POINT=latest; TABLE=orders; TARGET=orders_restore; OUTPUT="$WORK/restore"
    wait_job() { fail 'Restore failed'; }
    assert_fail do_restore
    [[ ! -e $OUTPUT/$TARGET.swap.sql ]]
}

test_restore_existing_target() {
    setup_workflow; add_prior
    POINT=latest; TABLE=orders; TARGET=orders_restore; OUTPUT="$WORK/restore"
    sql() { printf '[{"Tables_in_biz":"orders_restore"}]\n'; }
    assert_fail do_restore
    [[ ! -d $OUTPUT ]]
}

test_restore_case_variant_target() {
    setup_workflow; add_prior
    POINT=latest; TABLE=orders; TARGET=ORDERS; OUTPUT="$WORK/restore"
    assert_fail do_restore
    TARGET=ORDERS_RESTORE
    sql() { printf '[{"Tables_in_biz":"orders_restore"}]\n'; }
    assert_fail do_restore
    [[ ! -d $OUTPUT ]]
}

test_native_snapshot_validation() {
    jq -n --arg label "$LABEL" '{name:$label,database:"biz",backup_result:"succeed",content:"ALL",
        backup_objects:{orders:{id:42,partitions:{}}}}' >"$WORK/native.json"
    CHECKSUM=$(md5sum "$WORK/native.json"); CHECKSUM=${CHECKSUM%% *}
    sql() { jq -n --arg ts "$TS" '[{Status:"OK",Timestamp:$ts}]'; }
    hdfs_names() { printf '%s\n' "__info_$TS.$CHECKSUM" '__meta.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'; }
    hdfs_cmd() { [[ $1 == -cat ]]; cat "$WORK/native.json"; }
    verify_snapshot "$LABEL" orders | jq -e '.table.id==42' >/dev/null
    printf ' ' >>"$WORK/native.json"
    assert_fail verify_snapshot "$LABEL" orders
    CHECKSUM=$(md5sum "$WORK/native.json"); CHECKSUM=${CHECKSUM%% *}
    assert_fail verify_snapshot "$LABEL" other_table
    assert_fail verify_snapshot "$LABEL" orders '2026-10-02-02-00-00'
}

test_follower_rejected() {
    sql() { printf '[{"CurrentConnected":"Yes","IsMaster":"false"}]\n'; }
    assert_fail master
}

test_prune_preview_and_stale_backup() {
    setup_workflow; add_prior
    hdfs_cmd() { fail 'Preview must not delete'; }
    APPLY=false; do_prune
    APPLY=true; assert_fail do_prune
}

test_prune_delete_order_and_retry() {
    setup_workflow
    make_record "$LABEL" | jq -s '.' >"$WORK/records.json"
    make_record "$LABEL2" | jq -s '.' >"$WORK/new.json"
    jq -s 'add' "$WORK/records.json" "$WORK/new.json" >"$WORK/all.json"
    mv "$WORK/all.json" "$WORK/records.json"
    make_point "$POINT_ID" "$LABEL" "$(date -u +%F)" | jq --arg t "$(now)" '.completed_at=$t' | jq -s '.' >"$WORK/points.json"
    hdfs_cmd() { printf '%s\n' "$*" >>"$WORK/hdfs.log"; fail 'HDFS delete failed'; }
    APPLY=true; assert_fail do_prune
    [[ $(cat "$WORK/hdfs.log") == "-rm -r -f $ROOT/__ss_$LABEL2" ]]
    [[ $(cat "$WORK/hdfs.log") != *records* ]]
}

test_large_inventory() {
    local records points result
    # Exceeds Linux's 128 KiB single-argument limit: 50 tables x 30 daily versions.
    records=$(jq -n --arg label "$LABEL" --arg ts "$TS" '[range(0;1500)|
        {id:(if .==0 then $label else ("unused_"+tostring) end),table:"orders",backup_timestamp:$ts,
         completed_at:"2026-08-01T00:00:00Z",_local_date:"2026-08-01",padding:("x"*300)}]')
    points=$(make_point "$POINT_ID" "$LABEL" 2026-10-12 | jq -s '.')
    result=$(retention_plan "$points" "$records" '[]' 2026-09-13)
    jq -e '.unused|length==1499' <<<"$result" >/dev/null
}

fake_tsv() {
    jq -r 'if length==0 then empty else (.[0]|keys_unsorted) as $keys |
        $keys, (.[] | [.[$keys[]]]) | @tsv end'
}

fake_mysql() {
    local input label table=orders root="$MASSDB_BACKUP_TEST_ROOT" expression snapshot checksum
    input=$(cat)
    case "$input" in
        *'SHOW REPOSITORIES'*)
            printf '[{"RepoName":"daily_repo","IsReadOnly":"false","Location":"/backup"}]' | fake_tsv;;
        *'SHOW CREATE REPOSITORY'*)
            jq -n '[{RepoName:"daily_repo",CreateStmt:"CREATE REPOSITORY daily_repo WITH HDFS\nON LOCATION \"/backup\"\nPROPERTIES (\"fs.defaultFS\" = \"hdfs://ns\")"}]' | fake_tsv;;
        *'SHOW FRONTENDS'*)
            printf '[{"Name":"fe1","CurrentConnected":"Yes","IsMaster":"true","Version":"4.0.5-build1","ClusterId":"88"}]' | fake_tsv;;
        *"SHOW PROC '/dbs'"*) printf '[{"DbId":"100","DbName":"biz"}]' | fake_tsv;;
        *"SHOW PROC '/dbs/100'"*)
            printf '[{"TableId":"42","TableName":"orders","Type":"OLAP","State":"NORMAL","RunningTransactionNum":"0"},{"TableId":"84","TableName":"orders_restore","Type":"OLAP","State":"NORMAL","RunningTransactionNum":"0"}]' | fake_tsv;;
        *index_schema*) printf '[{"IndexId":"42","SchemaVersion":"1","SchemaHash":"101"}]' | fake_tsv;;
        *'SHOW CREATE TABLE'*)
            [[ $input != *orders_restore* ]] || table=orders_restore
            jq -n --arg table "$table" '[{"Table":$table,"Create Table":("CREATE TABLE "+$table+" (\nid INT\n) ENGINE=OLAP")}]' | fake_tsv;;
        *'SHOW TEMPORARY PARTITIONS'*) :;;
        *'SHOW PARTITIONS'*) printf '[{"PartitionName":"orders","PartitionId":"51","VisibleVersion":"3","State":"NORMAL"}]' | fake_tsv;;
        *'SHOW BACKUP'*) [[ ! -f $root/backup-job.json ]] || cat "$root/backup-job.json" | fake_tsv;;
        *'SHOW RESTORE'*) [[ ! -f $root/restore-job.json ]] || cat "$root/restore-job.json" | fake_tsv;;
        *'SHOW TABLES'*) printf '[{"Tables_in_biz":"orders"}]' | fake_tsv;;
        *'SHOW SNAPSHOT'*) printf '[{"Status":"OK","Timestamp":"2026-10-01-02-00-00"}]' | fake_tsv;;
        *'BACKUP SNAPSHOT'*)
            expression='BACKUP SNAPSHOT `biz`.`([^`]+)`'
            [[ $input =~ $expression ]] || exit 2
            label=${BASH_REMATCH[1]}
            snapshot="$root/hdfs/backup/__palo_repository_daily_repo/__ss_$label"
            mkdir -p "$snapshot/__ss_content"
            jq -n --arg label "$label" '{name:$label,database:"biz",backup_result:"succeed",content:"ALL",
                backup_objects:{orders:{id:42,partitions:{orders:{id:51,version:3}}}}}' >"$root/info.json"
            checksum=$(md5sum "$root/info.json"); checksum=${checksum%% *}
            cp "$root/info.json" "$snapshot/__info_2026-10-01-02-00-00.$checksum"
            : >"$snapshot/__meta.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            jq -n --arg label "$label" '[{SnapshotName:$label,JobId:"1",State:"FINISHED"}]' >"$root/backup-job.json"
            printf '%s\n' "$label" >>"$root/backup-count";;
        *'RESTORE SNAPSHOT'*)
            expression='RESTORE SNAPSHOT `biz`.`([^`]+)`'
            [[ $input =~ $expression ]] || exit 2
            jq -n --arg label "${BASH_REMATCH[1]}" '[{Label:$label,JobId:"2",State:"FINISHED"}]' >"$root/restore-job.json";;
        *) printf 'Unexpected test SQL\n' >&2; exit 2;;
    esac
}

fake_hdfs() {
    [[ $1 == dfs ]]; shift
    local operation=$1 value child destination
    shift
    local -a args=()
    for value in "$@"; do
        if [[ $value == hdfs://ns/* ]]; then value="$MASSDB_BACKUP_TEST_ROOT/hdfs/${value#hdfs://ns/}"; fi
        args+=("$value")
    done
    case "$operation" in
        -mkdir) mkdir "${args[@]}";;
        -ls)
            [[ ${args[0]} == -C && -d ${args[1]} ]]
            for child in "${args[1]}"/* "${args[1]}"/.[!.]*; do
                [[ ! -e $child ]] || printf '%s\n' "$child"
            done;;
        -cat) cat "${args[@]}";;
        -put) [[ ! -e ${args[1]} ]]; cp -- "${args[0]}" "${args[1]}";;
        -mv) [[ ! -e ${args[1]} ]]; mv -- "${args[0]}" "${args[1]}";;
        -rm) rm "${args[@]}";;
        -rmdir) rmdir "${args[@]}";;
        *) exit 2;;
    esac
}

test_cli_workflow() {
    export MASSDB_BACKUP_TEST_ROOT="$WORK/fixture"
    export MASSDB_BACKUP_TEST_SCRIPT="${BASH_SOURCE[0]}"
    local repository="$MASSDB_BACKUP_TEST_ROOT/hdfs/backup/__palo_repository_daily_repo" metadata
    metadata="$repository/_massdb_backup"
    mkdir -p "$repository"
    printf '{"name":"daily_repo"}\n' >"$repository/__repo_info"
    printf '[client]\nuser=backup\npassword=fixture-only\n' >"$WORK/mysql.cnf"
    cat >"$WORK/mysql" <<'CLIENT'
#!/usr/bin/env bash
exec bash "$MASSDB_BACKUP_TEST_SCRIPT" --fake-mysql "$@"
CLIENT
    cat >"$WORK/hdfs" <<'CLIENT'
#!/usr/bin/env bash
exec bash "$MASSDB_BACKUP_TEST_SCRIPT" --fake-hdfs "$@"
CLIENT
    chmod +x "$WORK/mysql" "$WORK/hdfs"
    jq --arg root "$WORK" '.database="biz" | .repository="daily_repo" | .hdfs_location="hdfs://ns/backup" |
        .tables=["orders"] | .mysql.defaults_extra_file=($root+"/mysql.cnf") |
        .mysql.binary=($root+"/mysql") | .hdfs_binary=($root+"/hdfs")' \
        "$SCRIPT_DIR/config.example.json" >"$WORK/config.json"
    bash "$SCRIPT_DIR/massdb_backup.sh" --config "$WORK/config.json" backup --reuse-unchanged --quiesced
    bash "$SCRIPT_DIR/massdb_backup.sh" --config "$WORK/config.json" backup --reuse-unchanged --quiesced
    [[ $(wc -l <"$MASSDB_BACKUP_TEST_ROOT/backup-count") == 1 ]]
    bash "$SCRIPT_DIR/massdb_backup.sh" --config "$WORK/config.json" list >"$WORK/list"
    [[ $(wc -l <"$WORK/list") == 2 ]]
    bash "$SCRIPT_DIR/massdb_backup.sh" --config "$WORK/config.json" pin --point latest
    bash "$SCRIPT_DIR/massdb_backup.sh" --config "$WORK/config.json" restore --point latest \
        --table orders --as orders_restore --output-dir "$WORK/restored"
    [[ -s $WORK/restored/orders_restore.swap.sql ]]
    bash "$SCRIPT_DIR/massdb_backup.sh" --config "$WORK/config.json" prune
    bash "$SCRIPT_DIR/massdb_backup.sh" --config "$WORK/config.json" unpin --point latest
    [[ ! -e $metadata/lock && -f $repository/__repo_info ]]
}

run_tests() {
    local case_name total=0 failed=0 output
    output=$(mktemp "${TMPDIR:-/tmp}/massdb-backup-results.XXXXXXXX")
    local -a cases=(
        tsv_escapes tsv_malformed identifier_injection config_paths_and_credentials repository_namespace
        documents_batch_and_partial_upload foreign_snapshot retention_references pin_protects_old_snapshot
        retention_missing_record_and_timestamp calendar_boundaries default_full reuse_requires_quiescence
        unchanged_reuse engine_change_forces_backup failed_backup_no_point structure_change_no_point
        write_after_reuse_blocks_publication inflight_transactions partial_run wait_ignores_old_finished
        poll_timeout_and_failure restore_swap_only_generated restore_failure_no_swap restore_existing_target restore_case_variant_target
        native_snapshot_validation follower_rejected prune_preview_and_stale_backup prune_delete_order_and_retry
        large_inventory cli_workflow
    )
    for case_name in "${cases[@]}"; do
        total=$((total+1))
        if bash "${BASH_SOURCE[0]}" --case "$case_name" >"$output" 2>&1; then
            printf 'PASS %s\n' "$case_name"
        else
            printf 'FAIL %s\n' "$case_name"
            cat "$output"
            failed=$((failed+1))
        fi
    done
    rm -f -- "$output"
    printf '%s cases, %s failures\n' "$total" "$failed"
    (( failed == 0 ))
}

case "${1:-}" in
    --case) setup_case; "test_$2";;
    --fake-mysql) shift; fake_mysql "$@";;
    --fake-hdfs) shift; fake_hdfs "$@";;
    *) run_tests;;
esac
