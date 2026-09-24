// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mysql.cj.ServerPreparedQuery;
import com.mysql.cj.jdbc.ServerPreparedStatement;
import com.mysql.cj.jdbc.StatementImpl;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/** Small original-A fixture; reads actual server OK info, not inferred INSERT success. */
public final class LicenseGroupCommitFixture {
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.ALLOW_SINGLE_QUOTES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final String[] SESSION_KEYS = {
        "group_commit", "enable_group_commit_full_prepare", "enable_server_side_prepared_statement"
    };
    private static final String[] MODEL_KEYS = {
        "n", "distinct_ids", "min_id", "max_id", "sum_id", "sum_grp", "sum_v", "bad_rows"
    };
    private static final String PADDING;

    static {
        try {
            String value = hex(MessageDigest.getInstance("SHA-256").digest("20260922".getBytes(StandardCharsets.US_ASCII)));
            PADDING = value + value;
        } catch (Exception error) {
            throw new ExceptionInInitializerError(error);
        }
    }

    private LicenseGroupCommitFixture() {
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder value = new StringBuilder(bytes.length * 2);
        for (byte item : bytes) {
            value.append(Character.forDigit((item >>> 4) & 15, 16)).append(Character.forDigit(item & 15, 16));
        }
        return value.toString();
    }

    private static void save(Path path, JsonNode value) throws Exception {
        Files.write(path, (JSON.writerWithDefaultPrettyPrinter().writeValueAsString(value) + "\n")
                .getBytes(StandardCharsets.UTF_8));
    }

    private static JsonNode serverReceipt(String info, ObjectNode result) throws Exception {
        require(info != null, "Driver did not expose server OK info");
        int brace = info.indexOf('{');
        require(brace == 0 || brace == 1, "Unexpected server OK info prefix");
        String object = info.substring(brace);
        if (brace == 1) {
            // rc02 writes lenenc info even without SESSION_TRACK. Connector/J retains that byte
            // in getServerInfo(); invalid single-byte UTF-8 becomes U+FFFD. Preserve the original.
            int bytes = object.getBytes(StandardCharsets.UTF_8).length;
            int prefix = info.charAt(0);
            require(bytes < 251 && (prefix == bytes || (bytes >= 128 && prefix == 0xfffd)),
                    "Server info prefix does not match the original one-byte length encoding");
            result.put("server_info_length_prefix_codepoint", prefix);
            result.put("server_info_object_utf8_bytes", bytes);
        }
        return JSON.readTree(object);
    }

    private static ArrayNode query(Statement statement, String sql) throws Exception {
        ArrayNode rows = JSON.createArrayNode();
        require(statement.execute(sql), "Expected a metadata result set");
        try (ResultSet values = statement.getResultSet()) {
            while (values.next()) {
                require(rows.size() < 1000, "Metadata result exceeded fixture bound");
                ObjectNode row = rows.addObject();
                for (int column = 1; column <= values.getMetaData().getColumnCount(); column++) {
                    row.put(values.getMetaData().getColumnLabel(column), values.getString(column));
                }
            }
        }
        return rows;
    }

    private static ObjectNode session(Statement statement) throws Exception {
        ObjectNode values = JSON.createObjectNode();
        for (String key : SESSION_KEYS) {
            ArrayNode rows = query(statement, "SHOW VARIABLES LIKE '" + key + "'");
            require(rows.size() == 1 && rows.get(0).has("Value"), "Missing required session variable " + key);
            values.put(key, rows.get(0).get("Value").asText());
        }
        return values;
    }

    private static void restoreSession(Statement statement, ObjectNode original, ObjectNode report) throws Exception {
        for (String key : SESSION_KEYS) {
            String value = original.get(key).asText();
            require(value.matches("(?i)(true|false|0|1|off_mode|async_mode|sync_mode)"), "Unexpected session setting");
            statement.execute("SET " + key + "='" + value + "'");
        }
        ObjectNode restored = session(statement);
        report.set("session_restored_values", restored);
        require(restored.equals(original), "Writer session restoration was not confirmed");
        report.put("session_restored", true);
    }

    private static Connection connect(JsonNode config, Properties behavior) throws Exception {
        Properties properties = new Properties();
        properties.putAll(behavior);
        properties.setProperty("user", config.path("user").asText());
        properties.setProperty("password", System.getenv().getOrDefault(config.path("password_env").asText(), ""));
        return DriverManager.getConnection("jdbc:mysql://127.0.0.1:" + config.path("query_port").asInt()
                + "/license_perf", properties);
    }

    private static ObjectNode inspectRows(Statement observer, String table, long start, int count) throws Exception {
        String sql = "SELECT id,grp,v,payload FROM " + table + " WHERE id >= " + start + " AND id < "
                + (start + count) + " ORDER BY id";
        ObjectNode result = JSON.createObjectNode();
        long n = 0;
        long first = -1;
        long previous = -1;
        long sumId = 0;
        long sumGrp = 0;
        long sumV = 0;
        MessageDigest checksum = MessageDigest.getInstance("SHA-256");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        try (ResultSet rows = observer.executeQuery(sql)) {
            while (rows.next()) {
                long id = rows.getLong(1);
                int grp = rows.getInt(2);
                long v = rows.getLong(3);
                String payload = rows.getString(4);
                require(n < count && id >= start && id < start + count && (n == 0 || id > previous),
                        "Visible rows contain duplicate or out-of-range IDs");
                String prefix = id + "," + grp + "," + v + ",";
                String expected = hex(md5.digest(Long.toString(id).getBytes(StandardCharsets.US_ASCII)));
                expected += PADDING.substring(0, 128 - prefix.length() - expected.length() - 1);
                require(grp == id % 1024 && v == id % 100000 && expected.equals(payload),
                        "Visible row differs from the independent deterministic data model");
                byte[] csv = (prefix + payload + "\n").getBytes(StandardCharsets.US_ASCII);
                require(csv.length == 128, "Visible reconstructed CSV does not have the frozen width");
                checksum.update(csv);
                if (n == 0) {
                    first = id;
                }
                n++;
                previous = id;
                sumId += id;
                sumGrp += grp;
                sumV += v;
            }
        }
        result.put("n", n).put("distinct_ids", n).put("min_id", first).put("max_id", previous);
        result.put("sum_id", sumId).put("sum_grp", sumGrp).put("sum_v", sumV).put("bad_rows", 0);
        result.put("reconstructed_csv_sha256", hex(checksum.digest()));
        return result;
    }

    private static void checkModel(ObjectNode actual, JsonNode expected, String checksum) {
        for (String key : MODEL_KEYS) {
            require(actual.path(key).asLong(Long.MIN_VALUE) == expected.path(key).asLong(Long.MAX_VALUE),
                    "Independent visible data model differs: " + key);
        }
        require(actual.path("reconstructed_csv_sha256").asText().equals(checksum), "Visible input hash mismatch");
    }

    private static void observe(Statement observer, String table, JsonNode batch, JsonNode config,
            ObjectNode result, long sent, long acknowledged) throws Exception {
        ArrayNode polls = result.putArray("visibility_polls");
        long deadline = acknowledged + config.path("visibility_timeout_ms").asLong() * 1000000L;
        while (true) {
            long pollStart = System.nanoTime();
            ObjectNode actual = inspectRows(observer, table, batch.path("id_start").asLong(), batch.path("batch_rows").asInt());
            long completed = System.nanoTime();
            ObjectNode poll = polls.addObject();
            poll.put("start_nanos_after_send", pollStart - sent).put("end_nanos_after_send", completed - sent);
            poll.put("observed_rows", actual.path("n").asLong());
            if (actual.path("n").asLong() == batch.path("batch_rows").asLong()) {
                checkModel(actual, batch.path("model"), batch.path("input_sha256").asText());
                result.set("visible_data", actual);
                result.put("first_validated_visibility_at_utc", Instant.now().toString());
                result.put("visibility_elapsed_nanos_after_send", completed - sent);
                result.put("visibility_elapsed_nanos_after_ack", completed - acknowledged);
                result.put("visibility_is_poll_observation_upper_bound", true);
                return;
            }
            require(completed < deadline, "Acknowledged Group Commit rows did not become visible before timeout");
            Thread.sleep(config.path("poll_interval_ms").asLong());
        }
    }

    private static void runBatches(JsonNode config, Properties behavior, List<String[]> input, String table,
            Statement observer, ObjectNode report, Path reportPath) throws Exception {
        ArrayNode batches = report.putArray("batches");
        Set<String> queryIds = new HashSet<>();
        try (Connection writer = connect(config, behavior); Statement settings = writer.createStatement()) {
            ObjectNode original = session(settings);
            report.set("session_original", original);
            report.put("writer_auto_commit", writer.getAutoCommit());
            try {
                settings.execute("SET group_commit='async_mode'");
                settings.execute("SET enable_server_side_prepared_statement=true");
                for (int index = 0; index < config.path("input_manifest").path("cases").size(); index += 2) {
                    JsonNode first = config.path("input_manifest").path("cases").get(index);
                    boolean fullPrepare = first.path("full_prepare").asBoolean();
                    int count = first.path("batch_rows").asInt();
                    settings.execute("SET enable_group_commit_full_prepare=" + fullPrepare);
                    ObjectNode current = session(settings);
                    require(current.path("group_commit").asText().equals("async_mode"), "Group Commit setting not active");
                    require(current.path("enable_group_commit_full_prepare").asBoolean() == fullPrepare,
                            "Full-prepare setting not active");
                    require(current.path("enable_server_side_prepared_statement").asBoolean(), "Server prepare is disabled");
                    StringBuilder text = new StringBuilder("INSERT INTO " + table + " (id,grp,v,payload) VALUES ");
                    for (int row = 0; row < count; row++) {
                        text.append(row == 0 ? "(?,?,?,?)" : ",(?,?,?,?)");
                    }
                    long prepareStarted = System.nanoTime();
                    try (PreparedStatement statement = writer.prepareStatement(text.toString())) {
                        long prepareNanos = System.nanoTime() - prepareStarted;
                        require(statement instanceof ServerPreparedStatement, "Driver silently used client-side prepare");
                        long statementId = ((ServerPreparedQuery) ((StatementImpl) statement).getQuery()).getServerStatementId();
                        for (int repeat = 0; repeat < 2; repeat++) {
                            JsonNode batch = config.path("input_manifest").path("cases").get(index + repeat);
                            ObjectNode result = batches.addObject();
                            report.put("stage", "batch_" + index + "_repeat_" + repeat);
                            result.set("input", batch);
                            result.set("session", current);
                            result.put("sql_template", text.toString()).put("placeholder_count", count * 4);
                            result.put("prepared_class", statement.getClass().getName()).put("server_statement_id", statementId);
                            result.put("prepare_elapsed_nanos", prepareNanos);
                            long bindStarted = System.nanoTime();
                            for (int row = 0; row < count; row++) {
                                String[] values = input.get(batch.path("id_start").asInt() + row);
                                statement.setLong(row * 4 + 1, Long.parseLong(values[0]));
                                statement.setInt(row * 4 + 2, Integer.parseInt(values[1]));
                                statement.setLong(row * 4 + 3, Long.parseLong(values[2]));
                                statement.setString(row * 4 + 4, values[3]);
                            }
                            result.put("parameter_binding_elapsed_nanos", System.nanoTime() - bindStarted);
                            result.put("sent_at_utc", Instant.now().toString());
                            long sent = System.nanoTime();
                            int affected = statement.executeUpdate();
                            long acknowledged = System.nanoTime();
                            result.put("acknowledged_at_utc", Instant.now().toString());
                            result.put("ack_elapsed_nanos", acknowledged - sent).put("affected_rows", affected);
                            String info = ((StatementImpl) statement).getResultSetInternal().getServerInfo();
                            result.put("server_ok_info", info);
                            JsonNode receipt = serverReceipt(info, result);
                            result.set("server_ok_fields", receipt);
                            require(affected == count, "Acknowledgment affected-row count mismatch");
                            require(receipt.path("label").asText().startsWith("group_commit_")
                                    && receipt.path("status").asText().equals("PREPARE")
                                    && receipt.path("txnId").asLong() > 0, "OK packet does not prove actual Group Commit");
                            require(!receipt.has("err") && !receipt.has("first_error_msg") && !receipt.has("err_url"),
                                    "Group Commit receipt contains a load error");
                            require(receipt.has("query_id") == fullPrepare, "Full-prepare branch marker mismatch");
                            if (fullPrepare) {
                                String queryId = receipt.path("query_id").asText();
                                require(queryId.matches("[a-f0-9]+-[a-f0-9]+") && queryIds.add(queryId),
                                        "Full-prepare query ID is malformed or repeats a previous OK receipt");
                            }
                            require(receipt.has("reuse_group_commit_plan") == (fullPrepare && repeat == 1),
                                    "Unexpected presence or absence of cached plan reuse marker");
                            require(receipt.path("reuse_group_commit_plan").asBoolean() == (fullPrepare && repeat == 1),
                                    "Full-prepare cached plan reuse was not proved by the server");
                            require(((ServerPreparedQuery) ((StatementImpl) statement).getQuery()).getServerStatementId()
                                    == statementId, "Driver changed the server statement ID");
                            ArrayNode last = query(settings, "SHOW LAST INSERT");
                            result.set("show_last_insert", last);
                            require(last.size() == 1 && last.get(0).path("FilteredRows").asLong(-1) == 0
                                    && last.get(0).path("LoadedRows").asLong(-1) == count
                                    && last.get(0).path("TransactionId").asLong() == receipt.path("txnId").asLong()
                                    && last.get(0).path("Label").asText().equals(receipt.path("label").asText())
                                    && last.get(0).path("Table").asText().equals(config.path("table").asText())
                                    && last.get(0).path("TransactionStatus").asText().equals("PREPARE"),
                                    "SHOW LAST INSERT did not confirm exact rows, zero filtering and the acknowledged transaction");
                            save(reportPath, report);
                            observe(observer, table, batch, config, result, sent, acknowledged);
                            result.put("status", "BATCH_PASS");
                            save(reportPath, report);
                        }
                    }
                }
            } finally {
                restoreSession(settings, original, report);
            }
        }
    }

    private static void execute(JsonNode config, ObjectNode report, Path reportPath) throws Exception {
        String namespace = Files.readSymbolicLink(Paths.get("/proc/self/ns/net")).toString();
        require(namespace.equals(config.path("namespace").asText())
                && !namespace.equals(config.path("host_namespace").asText()), "Helper requires the owned private namespace");
        String name = config.path("table").asText();
        require(name.matches("gc_fixture_[a-f0-9]{12}"), "Unexpected fixture table name");
        String table = "license_perf." + name;
        Path inputPath = Paths.get(config.path("input_manifest").path("input_path").asText());
        byte[] inputBytes = Files.readAllBytes(inputPath);
        require(hex(MessageDigest.getInstance("SHA-256").digest(inputBytes))
                .equals(config.path("input_manifest").path("input_sha256").asText()), "Input SHA-256 mismatch");
        List<String[]> input = new ArrayList<>();
        for (String line : new String(inputBytes, StandardCharsets.US_ASCII).split("\n")) {
            String[] values = line.split(",", -1);
            require(values.length == 4 && line.length() == 127, "Input CSV shape mismatch");
            input.add(values);
        }
        require(input.size() == config.path("input_manifest").path("rows").asInt(), "Input row count mismatch");
        Properties behavior = new Properties();
        behavior.setProperty("useServerPrepStmts", "true");
        behavior.setProperty("cachePrepStmts", "false");
        behavior.setProperty("rewriteBatchedStatements", "false");
        behavior.setProperty("useSSL", "false");
        behavior.setProperty("serverTimezone", "UTC");
        behavior.setProperty("connectTimeout", "10000");
        behavior.setProperty("socketTimeout", "60000");
        report.set("driver_properties_without_credentials", JSON.valueToTree(behavior));
        report.put("java_runtime_version", System.getProperty("java.runtime.version"));
        report.put("java_vendor", System.getProperty("java.vendor"));
        report.put("mode", "async_mode");
        report.put("batch_execution", "one multi-row VALUES server-prepared executeUpdate, twice per statement");
        report.put("visibility_contract", "Independent reader starts after ack; 100ms polls give observed upper bounds, not exact commit instants");
        report.put("stage", "connect_and_check_prerequisites");
        report.put("table_created", false);
        try (Connection control = connect(config, behavior); Statement ddl = control.createStatement();
                Connection observerConnection = connect(config, behavior); Statement observer = observerConnection.createStatement()) {
            report.put("driver_name", control.getMetaData().getDriverName());
            report.put("driver_version", control.getMetaData().getDriverVersion());
            report.put("database_version", control.getMetaData().getDatabaseProductVersion());
            ArrayNode internalWait = query(ddl, "ADMIN SHOW FRONTEND CONFIG LIKE '%wait_internal_group_commit_finish'");
            report.set("internal_group_commit_config", internalWait);
            require(internalWait.size() == 1 && internalWait.get(0).path("Value").asText().equals("false"),
                    "This async fixture requires wait_internal_group_commit_finish=false; no global config is changed");
            observer.execute("SET enable_sql_cache=false");
            observer.execute("SET enable_query_cache=false");
            String create = "CREATE TABLE " + table + " (id BIGINT NOT NULL, grp INT NOT NULL, v BIGINT NOT NULL, "
                    + "payload VARCHAR(128) NOT NULL) DUPLICATE KEY(id) DISTRIBUTED BY HASH(id) BUCKETS 16 "
                    + "PROPERTIES (\"replication_num\"=\"1\",\"light_schema_change\"=\"true\","
                    + "\"group_commit_interval_ms\"=\"" + config.path("group_commit_interval_ms").asInt() + "\","
                    + "\"group_commit_data_bytes\"=\"" + config.path("group_commit_data_bytes").asLong() + "\")";
            report.put("create_table_sql", create);
            report.put("stage", "create_private_fixture_table");
            ddl.execute(create);
            report.put("table_created", true);
            try {
                report.set("show_create_table", query(ddl, "SHOW CREATE TABLE " + table));
                runBatches(config, behavior, input, table, observer, report, reportPath);
                ObjectNode finalRows = inspectRows(observer, table, 0, input.size());
                checkModel(finalRows, config.path("input_manifest").path("model"),
                        config.path("input_manifest").path("input_sha256").asText());
                ArrayNode total = query(observer, "SELECT COUNT(*) AS n FROM " + table);
                require(total.size() == 1 && total.get(0).path("n").asLong(-1) == input.size(),
                        "Fixture table contains unexpected rows outside the input range");
                report.set("final_visible_model", finalRows);
                report.set("final_count", total);
            } finally {
                report.put("cleanup_started_at_utc", Instant.now().toString());
                ddl.execute("DROP TABLE " + table + " FORCE");
                ArrayNode remaining = query(ddl, "SHOW TABLES FROM license_perf LIKE '" + name + "'");
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
            execute(config, report, reportPath);
            report.put("status", "FIXTURE_PASS");
        } catch (Exception error) {
            failed = true;
            report.put("status", "FAIL").put("error_class", error.getClass().getName());
            if (error instanceof SQLException) {
                SQLException sql = (SQLException) error;
                report.put("sql_error_code", sql.getErrorCode()).put("sql_state", sql.getSQLState());
                String message = sql.getMessage();
                String secret = System.getenv().getOrDefault(config.path("password_env").asText(), "");
                if (message != null) {
                    if (!secret.isEmpty()) {
                        message = message.replace(secret, "<redacted>");
                    }
                    message = message.replaceAll("(?i)(password|pwd)\\s*[=:]\\s*[^\\s,;}]+", "$1=<redacted>");
                    message = message.replaceAll("(?i)(https?://|jdbc:[^:]+://)[^/\\s@]+@", "$1<redacted>@");
                    report.put("sql_error_message_redacted", message);
                }
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
