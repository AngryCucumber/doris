// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mysql.cj.jdbc.StatementImpl;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Explicit BEGIN uses one writer; independent observer checks committed data and rollback. */
public final class LicenseDmlTransactionFixture {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String[] SESSION_KEYS = {"group_commit", "enable_insert_strict", "enable_unique_key_partial_update"};
    private static final String[] MODEL_KEYS = {"rows", "distinct_ids", "min_id", "max_id", "sum_id", "sum_grp", "sum_v"};

    private LicenseDmlTransactionFixture() {
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    private static void save(Path path, JsonNode report) throws Exception {
        Files.write(path, (JSON.writerWithDefaultPrettyPrinter().writeValueAsString(report) + "\n")
                .getBytes(StandardCharsets.UTF_8));
    }

    private static String hex(byte[] data) {
        StringBuilder result = new StringBuilder(data.length * 2);
        for (byte value : data) {
            result.append(Character.forDigit((value >>> 4) & 15, 16)).append(Character.forDigit(value & 15, 16));
        }
        return result.toString();
    }

    private static String redact(String text, JsonNode config) {
        if (text == null) {
            return null;
        }
        String secret = System.getenv().getOrDefault(config.path("password_env").asText(), "");
        if (!secret.isEmpty()) {
            text = text.replace(secret, "<redacted>");
        }
        text = text.replaceAll("(?i)(password|pwd)\\s*[=:]\\s*[^\\s,;}]+", "$1=<redacted>");
        return text.replaceAll("(?i)(https?://|jdbc:[^:]+://)[^/\\s@]+@", "$1<redacted>@");
    }

    private static ObjectNode execute(Statement statement, String sql, JsonNode config) throws Exception {
        ObjectNode result = JSON.createObjectNode().put("sql", sql).put("started_at_utc", Instant.now().toString());
        long started = System.nanoTime();
        try {
            if (statement.execute(sql)) {
                ArrayNode rows = result.putArray("rows");
                try (ResultSet values = statement.getResultSet()) {
                    while (values.next()) {
                        require(rows.size() < 1000, "Unexpected metadata result size");
                        ObjectNode row = rows.addObject();
                        for (int column = 1; column <= values.getMetaData().getColumnCount(); column++) {
                            row.put(values.getMetaData().getColumnLabel(column), values.getString(column));
                        }
                    }
                }
            } else {
                result.put("affected_rows", statement.getUpdateCount());
                result.put("server_ok_info", redact(((StatementImpl) statement).getResultSetInternal().getServerInfo(), config));
            }
            result.put("success", true);
        } catch (SQLException error) {
            result.put("success", false).put("error_code", error.getErrorCode()).put("sql_state", error.getSQLState());
            result.put("error_message_redacted", redact(error.getMessage(), config));
        } finally {
            result.put("elapsed_nanos", System.nanoTime() - started).put("finished_at_utc", Instant.now().toString());
        }
        return result;
    }

    private static String infoField(ObjectNode result, String name) {
        Matcher match = Pattern.compile("'" + name + "':'([^']*)'").matcher(result.path("server_ok_info").asText());
        if (!match.find()) {
            return "";
        }
        String value = match.group(1);
        require(!match.find(), "Duplicate field in transaction OK info");
        return value;
    }

    private static ArrayNode query(Statement statement, String sql, JsonNode config) throws Exception {
        ObjectNode result = execute(statement, sql, config);
        require(result.path("success").asBoolean() && result.has("rows"), "Expected a successful metadata query");
        return (ArrayNode) result.get("rows");
    }

    private static ObjectNode snapshot(Statement observer, String sql) throws Exception {
        ObjectNode result = JSON.createObjectNode();
        long count = 0;
        long first = -1;
        long last = -1;
        long sumId = 0;
        long sumGrp = 0;
        long sumV = 0;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (ResultSet data = observer.executeQuery(sql)) {
            while (data.next()) {
                require(count < 1000, "Fixture snapshot exceeded bounded row count");
                long id = data.getLong(1);
                long grp = data.getLong(2);
                long value = data.getLong(3);
                String payload = data.getString(4);
                require(payload != null && (count == 0 || id > last), "Unexpected null payload or duplicate/nonordered ID");
                if (count == 0) {
                    first = id;
                }
                count++;
                last = id;
                sumId += id;
                sumGrp += grp;
                sumV += value;
                digest.update((id + "," + grp + "," + value + "," + payload + "\n").getBytes(StandardCharsets.UTF_8));
            }
        }
        result.put("rows", count).put("distinct_ids", count).put("sum_id", sumId).put("sum_grp", sumGrp).put("sum_v", sumV);
        if (count == 0) {
            result.putNull("min_id").putNull("max_id");
        } else {
            result.put("min_id", first).put("max_id", last);
        }
        result.put("canonical_csv_sha256", hex(digest.digest()));
        return result;
    }

    private static boolean sameModel(ObjectNode actual, JsonNode model) {
        for (String key : MODEL_KEYS) {
            if (actual.path(key).isNull() != model.path(key).isNull()
                    || (!actual.path(key).isNull() && actual.path(key).asLong() != model.path(key).asLong())) {
                return false;
            }
        }
        return actual.path("canonical_csv_sha256").asText().equals(model.path("canonical_csv_sha256").asText());
    }

    private static ObjectNode observe(Statement observer, String sql, JsonNode expected, boolean stable,
            JsonNode config) throws Exception {
        ObjectNode report = JSON.createObjectNode();
        report.set("expected", expected);
        ArrayNode observations = report.putArray("observations");
        long started = System.nanoTime();
        int successes = 0;
        while (true) {
            ObjectNode value = snapshot(observer, sql);
            ObjectNode item = observations.addObject().put("at_utc", Instant.now().toString());
            item.put("elapsed_nanos", System.nanoTime() - started).set("actual", value);
            boolean equal = sameModel(value, expected);
            if (stable) {
                require(equal, "Uncommitted or rolled-back data leaked to the independent observer: " + value);
            }
            if (equal && ++successes >= (stable ? 3 : 1)) {
                report.put("verified", true);
                return report;
            }
            require(System.nanoTime() - started < config.path("visibility_timeout_ms").asLong() * 1000000L,
                    "Committed data did not match the complete independent model before timeout: " + value);
            Thread.sleep(config.path("poll_interval_ms").asLong());
        }
    }

    private static ObjectNode session(Statement statement, JsonNode config) throws Exception {
        ObjectNode result = JSON.createObjectNode();
        for (String key : SESSION_KEYS) {
            ArrayNode rows = query(statement, "SHOW VARIABLES LIKE '" + key + "'", config);
            require(rows.size() == 1 && rows.get(0).has("Value"), "Missing session variable " + key);
            result.put(key, rows.get(0).get("Value").asText());
        }
        return result;
    }

    private static void runPhases(Statement writer, Statement observer, String table, JsonNode config,
            ObjectNode report, Path reportPath) throws Exception {
        JsonNode models = config.path("manifest").path("models");
        String select = "SELECT id,grp,v,payload FROM " + table + " ORDER BY id";
        ArrayNode phases = report.putArray("phases");
        for (JsonNode phase : config.path("manifest").path("phases")) {
            report.put("stage", phase.path("name").asText());
            ObjectNode result = phases.addObject().put("name", phase.path("name").asText()).put("kind", phase.path("kind").asText());
            result.set("before", observe(observer, select, models.path(phase.path("before").asText()), false, config));
            boolean explicitBegin = phase.path("begin").asText().equals("BEGIN");
            String transactionLabel = "";
            String txnId = "";
            if (phase.has("begin")) {
                ObjectNode begin = execute(writer, phase.get("begin").asText(), config);
                result.set("begin", begin);
                require(begin.path("success").asBoolean(), "Transaction begin command failed");
                transactionLabel = infoField(begin, "label");
                if (explicitBegin) {
                    require(infoField(begin, "status").equals("PREPARE") && transactionLabel.startsWith("txn_insert_"),
                            "BEGIN did not return the original explicit transaction preparation receipt");
                }
            }
            ArrayNode operations = result.putArray("operations");
            for (JsonNode operation : phase.path("operations")) {
                String sql = operation.path("sql").asText().replace("{{table}}", table);
                ObjectNode executed = execute(writer, sql, config);
                operations.add(executed);
                if (operation.has("expected_error")) {
                    require(!executed.path("success").asBoolean()
                            && executed.path("error_code").asInt() == operation.path("expected_errno").asInt()
                            && executed.path("sql_state").asText().equals(operation.path("expected_sql_state").asText())
                            && executed.path("error_message_redacted").asText().contains(operation.path("expected_error").asText()),
                            "Unsupported transaction combination did not preserve its exact original rejection");
                    executed.put("capability_status", "UNSUPPORTED_REJECTED");
                } else {
                    require(executed.path("success").asBoolean(), "Expected supported DML statement failed");
                    if (operation.has("affected_rows")) {
                        require(executed.path("affected_rows").asLong(-1) == operation.path("affected_rows").asLong(),
                                "DML affected-row count differs from the frozen workload");
                        String currentId = infoField(executed, "txnId");
                        if (currentId.matches("[1-9][0-9]*") && txnId.isEmpty()) {
                            txnId = currentId;
                        }
                        if (explicitBegin) {
                            require(infoField(executed, "status").equals("PREPARE")
                                    && infoField(executed, "label").equals(transactionLabel),
                                    "DML did not stay in the explicit transaction identified by BEGIN");
                        }
                    } else if (sql.equals("SELECT 1")) {
                        require(executed.path("rows").size() == 1
                                && executed.path("rows").get(0).path("1").asText().equals("1"), "SELECT 1 result mismatch");
                    }
                }
                save(reportPath, report);
                executed.set("observer_after_operation", observe(observer, select,
                        models.path(operation.path("visible_model").asText()), explicitBegin, config));
            }
            if (phase.has("end")) {
                ObjectNode end = execute(writer, phase.path("end").asText(), config);
                result.set("end", end);
                require(end.path("success").asBoolean(), "Explicit transaction end command failed");
                String endId = infoField(end, "txnId");
                if (endId.matches("[1-9][0-9]*")) {
                    require(txnId.isEmpty() || txnId.equals(endId), "Transaction end refers to a different root transaction");
                    txnId = endId;
                }
            }
            result.set("after", observe(observer, select, models.path(phase.path("after").asText()),
                    phase.path("end").asText().equals("ROLLBACK"), config));
            if (phase.has("transaction_status")) {
                require(txnId.matches("[1-9][0-9]*"), "A real allocated transaction ID is required");
                ArrayNode transaction = query(observer, "SHOW TRANSACTION WHERE ID = " + txnId, config);
                result.set("transaction_state", transaction);
                require(transaction.size() == 1 && transaction.get(0).path("TransactionStatus").asText()
                        .equals(phase.path("transaction_status").asText()), "Actual transaction state does not match the model");
            }
            String kind = phase.path("kind").asText();
            result.put("capability_status", kind.equals("unsupported_rejected") ? "UNSUPPORTED_REJECTED"
                    : kind.equals("unsupported_ack_only") ? "ACKNOWLEDGED_WITHOUT_TRANSACTION_SEMANTICS" : "SUPPORTED_VERIFIED");
            result.put("transaction_supported", kind.equals("supported_transaction"));
            save(reportPath, report);
        }
    }

    private static Connection connect(JsonNode config, Properties behavior) throws Exception {
        Properties properties = new Properties();
        properties.putAll(behavior);
        properties.setProperty("user", config.path("user").asText());
        properties.setProperty("password", System.getenv().getOrDefault(config.path("password_env").asText(), ""));
        return DriverManager.getConnection("jdbc:mysql://127.0.0.1:" + config.path("query_port").asInt() + "/license_perf", properties);
    }

    private static void run(JsonNode config, ObjectNode report, Path reportPath) throws Exception {
        String namespace = Files.readSymbolicLink(Paths.get("/proc/self/ns/net")).toString();
        require(namespace.equals(config.path("namespace").asText())
                && !namespace.equals(config.path("host_namespace").asText()), "Helper requires the owned private namespace");
        String name = config.path("table").asText();
        require(name.matches("dml_fixture_[a-f0-9]{12}"), "Unexpected DML fixture table");
        String table = "license_perf." + name;
        Properties properties = new Properties();
        properties.setProperty("useServerPrepStmts", "false");
        properties.setProperty("rewriteBatchedStatements", "false");
        properties.setProperty("useLocalSessionState", "true");
        properties.setProperty("useSSL", "false");
        properties.setProperty("serverTimezone", "UTC");
        properties.setProperty("connectTimeout", "10000");
        properties.setProperty("socketTimeout", "60000");
        report.set("driver_properties_without_credentials", JSON.valueToTree(properties));
        report.put("java_runtime_version", System.getProperty("java.runtime.version"));
        report.put("driver_shape", "MySQL text Statement; explicit SQL BEGIN/COMMIT/ROLLBACK on one writer connection");
        report.put("table_created", false);
        try (Connection writerConnection = connect(config, properties); Statement writer = writerConnection.createStatement();
                Connection readerConnection = connect(config, properties); Statement observer = readerConnection.createStatement()) {
            report.put("driver_version", writerConnection.getMetaData().getDriverVersion());
            report.put("writer_jdbc_auto_commit", writerConnection.getAutoCommit());
            String sourceSql = "SELECT id,grp,v,payload FROM license_perf.point_rows WHERE id >= 0 AND id < 600 ORDER BY id";
            observer.execute("SET enable_sql_cache=false");
            observer.execute("SET enable_query_cache=false");
            report.set("source_before", observe(observer, sourceSql, config.path("manifest").path("models").path("source600"), false, config));
            ObjectNode original = session(writer, config);
            report.set("session_original", original);
            String create = "CREATE TABLE " + table + " (id BIGINT NOT NULL, grp INT NOT NULL, v BIGINT NOT NULL, payload VARCHAR(128)) "
                    + "UNIQUE KEY(id) DISTRIBUTED BY HASH(id) BUCKETS 16 PROPERTIES (\"replication_num\"=\"1\","
                    + "\"enable_unique_key_merge_on_write\"=\"true\",\"store_row_column\"=\"true\","
                    + "\"light_schema_change\"=\"true\",\"enable_mow_light_delete\"=\"false\")";
            report.put("create_table_sql", create);
            writer.execute(create);
            report.put("table_created", true);
            try {
                report.set("show_create_table", query(writer, "SHOW CREATE TABLE " + table, config));
                try {
                    writer.execute("SET group_commit='off_mode'");
                    writer.execute("SET enable_insert_strict=true");
                    writer.execute("SET enable_unique_key_partial_update=false");
                    report.set("session_active", session(writer, config));
                    runPhases(writer, observer, table, config, report, reportPath);
                    report.set("source_after", observe(observer, sourceSql,
                            config.path("manifest").path("models").path("source600"), false, config));
                    report.put("source_read_only_model_unchanged", true);
                } finally {
                    ObjectNode rollback = execute(writer, "ROLLBACK", config);
                    report.set("cleanup_rollback", rollback);
                    require(rollback.path("success").asBoolean(), "Cleanup rollback failed");
                    for (String key : SESSION_KEYS) {
                        String value = original.path(key).asText();
                        require(value.matches("(?i)(true|false|0|1|off_mode|async_mode|sync_mode)"), "Unexpected session setting");
                        writer.execute("SET " + key + "='" + value + "'");
                    }
                    ObjectNode restored = session(writer, config);
                    report.set("session_restored_values", restored);
                    require(restored.equals(original), "Writer session restoration was not confirmed");
                    report.put("session_restored", true);
                }
            } finally {
                observer.execute("DROP TABLE " + table + " FORCE");
                ArrayNode remaining = query(observer, "SHOW TABLES FROM license_perf LIKE '" + name + "'", config);
                report.set("cleanup_remaining_tables", remaining);
                require(remaining.isEmpty(), "Fixture table cleanup was not confirmed");
                report.put("table_removed", true);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        JsonNode config = JSON.readTree(Paths.get(args[0]).toFile());
        Path reportPath = Paths.get(config.path("report_path").asText());
        ObjectNode report = JSON.createObjectNode().put("status", "RUNNING").put("started_at_utc", Instant.now().toString());
        boolean failed = false;
        try {
            run(config, report, reportPath);
            report.put("status", "FIXTURE_PASS");
        } catch (Exception error) {
            failed = true;
            report.put("status", "FAIL").put("error_class", error.getClass().getName());
            if (error instanceof SQLException) {
                SQLException sql = (SQLException) error;
                report.put("error_code", sql.getErrorCode()).put("sql_state", sql.getSQLState());
                report.put("error_message_redacted", redact(sql.getMessage(), config));
            } else if (error instanceof IllegalStateException) {
                report.put("failure", error.getMessage());
            }
        } finally {
            report.put("finished_at_utc", Instant.now().toString());
            save(reportPath, report);
        }
        if (failed) {
            System.exit(2);
        }
    }
}
