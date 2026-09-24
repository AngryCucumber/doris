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

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicIntegerArray;
import java.util.concurrent.atomic.AtomicLong;

/** Original-A UI companion. Independent connections, complete value oracles, no replay of writes. */
public final class LicenseUiBackground {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final long BILLION = 1_000_000_000L;
    private static final long WRITE_BASE = 1_000_000_000L;
    private static final String SOURCE = "license_perf.point_rows";
    private static final String[] READ_SESSION = {"SET enable_sql_cache=false", "SET enable_query_cache=false",
        "SET enable_short_circuit_query=true"};
    private static final String[] WRITE_SESSION = {"SET group_commit='off_mode'", "SET enable_insert_strict=true",
        "SET enable_unique_key_partial_update=false"};
    private final JsonNode config;
    private final Path directory;
    private final Path configurationPath;
    private final String token;
    private final String table;
    private final long pid;
    private final long startTicks;
    private final String namespace;
    private final List<Connection> connections = Collections.synchronizedList(new ArrayList<>());
    private final List<Thread> workers = new ArrayList<>();
    private final List<Thread> closingThreads = new ArrayList<>();
    private final AtomicLong errors = new AtomicLong();
    private final AtomicLong epoch = new AtomicLong();
    private final ObjectNode summary = JSON.createObjectNode();
    private volatile boolean cancelled;
    private long[] reads;
    private long[] writes;
    private int[] keys;
    private String[] payloads;
    private String[] inserts;
    private AtomicIntegerArray writeState;
    private AtomicLong[] writeAck;
    private int[] visible;
    private volatile long phaseDeadline;
    private boolean windowEnded;
    private boolean workersClosed;

    private LicenseUiBackground(Path path) throws Exception {
        configurationPath = path.toRealPath();
        config = JSON.readTree(configurationPath.toFile());
        directory = Path.of(config.path("output").asText()).toRealPath();
        require(configurationPath.getParent().equals(directory), "CONFIG_DIRECTORY");
        token = config.path("token").asText();
        table = config.path("table").asText();
        pid = ProcessHandle.current().pid();
        String stat = Files.readString(Path.of("/proc/self/stat"));
        startTicks = Long.parseLong(stat.substring(stat.lastIndexOf(')') + 1).trim().split("\\s+")[19]);
        namespace = Files.readSymbolicLink(Path.of("/proc/self/ns/net")).toString();
        require(token.matches("[a-f0-9]{32}") && table.equals("license_perf.ui_bg_" + token), "OWNED_TABLE_NAME");
        require(config.path("source_table").asText().equals(SOURCE)
                && config.path("source_rows").asInt() == 1_000_000, "SOURCE_MODEL");
        require(number("duration_seconds") == 300 && number("read_rate_per_second") > 0
                && number("read_rate_per_second") <= 1000 && number("write_batches_per_second") > 0
                && number("write_batches_per_second") <= 20 && number("write_batch_rows") > 0
                && number("write_batch_rows") <= 1000, "INPUT_BOUNDS");
        require(number("read_workers") > 0 && number("read_workers") <= 32
                && number("write_workers") > 0 && number("write_workers") <= 8
                && number("timeout_seconds") > 0 && number("timeout_seconds") <= 30, "WORKER_BOUNDS");
        summary.put("schema_version", 1).put("token", token).put("table", table).put("status", "FAIL")
                .put("pid", pid).put("start_ticks", startTicks).put("namespace", namespace)
                .put("formal_performance_pass", false).put("full_goal_complete", false)
                .put("credentials_recorded", false).put("automatic_write_replays", 0);
    }

    private static void require(boolean condition, String code) {
        if (!condition) {
            throw new IllegalStateException(code);
        }
    }

    private int number(String name) {
        return config.path(name).asInt(-1);
    }

    private static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static String md5(long id) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("MD5")
                .digest(Long.toString(id).getBytes(StandardCharsets.US_ASCII)));
    }

    private void publish(String name, JsonNode value) throws Exception {
        Path destination = directory.resolve(name);
        Path temporary = directory.resolve(name + ".tmp");
        JSON.writerWithDefaultPrettyPrinter().writeValue(temporary.toFile(), value);
        Files.move(temporary, destination, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private ObjectNode timestamp() {
        return JSON.createObjectNode().put("token", token).put("java_monotonic_ns", System.nanoTime())
                .put("pid", pid).put("start_ticks", startTicks).put("namespace", namespace)
                .put("unix_millis", System.currentTimeMillis()).put("at_utc", Instant.now().toString());
    }

    private void identity() throws Exception {
        require(Files.readSymbolicLink(Path.of("/proc/self/ns/net")).toString()
                .equals(config.path("namespace").asText()), "NAMESPACE_CHANGED");
        require(config.path("cluster_pins").isArray() && !config.path("cluster_pins").isEmpty(), "NO_CLUSTER_PINS");
        for (JsonNode pin : config.path("cluster_pins")) {
            Path process = Path.of("/proc", pin.path("pid").asText());
            String stat = Files.readString(process.resolve("stat"));
            String[] fields = stat.substring(stat.lastIndexOf(')') + 1).trim().split("\\s+");
            require(!fields[0].equals("Z") && !fields[0].equals("X")
                    && Long.parseLong(fields[19]) == pin.path("start_ticks").asLong()
                    && Files.readSymbolicLink(process.resolve("ns/net")).toString().equals(pin.path("namespace").asText())
                    && Files.readSymbolicLink(process.resolve("exe")).toString().equals(pin.path("exe").asText())
                    && digest(Files.readAllBytes(process.resolve("cmdline"))).equals(pin.path("command_sha256").asText()),
                    "CLUSTER_PIN_CHANGED");
        }
        require(System.nanoTime() < phaseDeadline, "PHASE_DEADLINE");
    }

    private Connection connect(String role) throws Exception {
        identity();
        JsonNode account = config.path(role + "_account");
        String secret = System.getenv(account.path("password_env").asText());
        require(secret != null, "EXPLICIT_CREDENTIAL_MISSING");
        Properties properties = new Properties();
        properties.setProperty("user", account.path("username").asText());
        properties.setProperty("password", secret);
        properties.setProperty("useServerPrepStmts", "true");
        properties.setProperty("autoReconnect", "false");
        properties.setProperty("allowMultiQueries", "false");
        properties.setProperty("connectTimeout", "10000");
        properties.setProperty("socketTimeout", String.valueOf(number("timeout_seconds") * 1000L));
        String host = config.path("target").path("host").asText();
        require(host.matches("[0-9.]+"), "NUMERIC_OWNED_HOST");
        int port = config.path("target").path("query_port").asInt();
        require(port > 1023 && port <= 65535, "QUERY_PORT");
        Connection connection = DriverManager.getConnection("jdbc:mariadb://" + host + ":" + port + "/", properties);
        connections.add(connection);
        connection.setAutoCommit(true);
        for (String sql : READ_SESSION) {
            execute(connection, sql);
        }
        execute(connection, "SET query_timeout=" + number("timeout_seconds"));
        execute(connection, "SET insert_timeout=" + number("timeout_seconds"));
        if (role.equals("write")) {
            for (String sql : WRITE_SESSION) {
                execute(connection, sql);
            }
        }
        return connection;
    }

    private ObjectNode session(Connection connection, boolean write) throws Exception {
        ObjectNode values = JSON.createObjectNode();
        String[][] expected = write ? new String[][] {{"enable_sql_cache", "false"}, {"enable_query_cache", "false"},
            {"enable_short_circuit_query", "true"}, {"group_commit", "off_mode"}, {"enable_insert_strict", "true"},
            {"enable_unique_key_partial_update", "false"}, {"query_timeout", Integer.toString(number("timeout_seconds"))},
            {"insert_timeout", Integer.toString(number("timeout_seconds"))}} : new String[][] {
                {"enable_sql_cache", "false"}, {"enable_query_cache", "false"}, {"enable_short_circuit_query", "true"},
                {"query_timeout", Integer.toString(number("timeout_seconds"))},
                {"insert_timeout", Integer.toString(number("timeout_seconds"))}};
        for (String[] item : expected) {
            identity();
            try (Statement statement = statement(connection); ResultSet rows = statement.executeQuery(
                    "SHOW SESSION VARIABLES LIKE '" + item[0] + "'")) {
                require(rows.next() && item[0].equalsIgnoreCase(rows.getString(1)), "SESSION_SETTING_MISSING");
                String actual = rows.getString(2).toLowerCase(java.util.Locale.ROOT);
                if ((item[1].equals("true") || item[1].equals("false")) && (actual.equals("on") || actual.equals("1"))) {
                    actual = "true";
                } else if ((item[1].equals("true") || item[1].equals("false")) && (actual.equals("off") || actual.equals("0"))) {
                    actual = "false";
                }
                require(!rows.next() && actual.equals(item[1]), "SESSION_SETTING_DIFFERS");
                values.put(item[0], actual);
            }
        }
        return values;
    }

    private Statement statement(Connection connection) throws SQLException {
        Statement statement = connection.createStatement();
        statement.setQueryTimeout(number("timeout_seconds"));
        statement.setFetchSize(1000);
        return statement;
    }

    private void execute(Connection connection, String sql) throws Exception {
        identity();
        try (Statement statement = statement(connection)) {
            require(!statement.execute(sql), "UNEXPECTED_EXECUTE_ROWS");
        }
        identity();
    }

    private boolean exists(Connection connection) throws Exception {
        identity();
        try (Statement statement = statement(connection); ResultSet rows = statement.executeQuery("SHOW TABLES FROM license_perf")) {
            int count = 0;
            while (rows.next()) {
                require(++count <= 10000, "TABLE_LIST_BOUND");
                if (rows.getString(1).equals(table.substring("license_perf.".length()))) {
                    return true;
                }
            }
            return false;
        }
    }

    private String schema(Connection connection, String name) throws Exception {
        identity();
        StringBuilder canonical = new StringBuilder();
        try (Statement statement = statement(connection); ResultSet rows = statement.executeQuery("DESCRIBE " + name)) {
            String[] expected = {"id", "grp", "v", "payload"};
            int count = 0;
            while (rows.next()) {
                require(count < expected.length && expected[count++].equals(rows.getString(1)), "SCHEMA_COLUMNS");
                for (int column = 1; column <= rows.getMetaData().getColumnCount(); column++) {
                    String value = rows.getString(column);
                    canonical.append(value == null ? "<NULL>" : value).append('\t');
                }
                canonical.append('\n');
            }
            require(count == 4, "SCHEMA_COLUMN_COUNT");
        }
        return digest(canonical.toString().getBytes(StandardCharsets.UTF_8));
    }

    private ObjectNode tableIdentity(Connection connection) throws Exception {
        identity();
        List<Long> tablets = new ArrayList<>();
        try (Statement statement = statement(connection); ResultSet rows = statement.executeQuery("SHOW TABLETS FROM " + table)) {
            while (rows.next()) {
                require(tablets.size() < 1024, "TABLET_BOUND");
                long id = rows.getLong("TabletId");
                require(!rows.wasNull() && id > 0 && !tablets.contains(id), "TABLET_IDENTITY");
                tablets.add(id);
            }
        }
        require(!tablets.isEmpty(), "NO_TABLET_IDENTITY");
        Collections.sort(tablets);
        ObjectNode result = JSON.createObjectNode().put("schema_sha256", schema(connection, table));
        ArrayNode values = result.putArray("tablet_ids");
        tablets.forEach(values::add);
        return result;
    }

    private static void columns(ResultSet rows) throws SQLException {
        String[] expected = {"id", "grp", "v", "payload"};
        require(rows.getMetaData().getColumnCount() == expected.length, "MODEL_COLUMN_COUNT");
        for (int index = 0; index < expected.length; index++) {
            require(expected[index].equals(rows.getMetaData().getColumnLabel(index + 1)), "MODEL_COLUMN_ORDER");
        }
    }

    private static long integer(ResultSet rows, int index) throws SQLException {
        Object value = rows.getObject(index);
        require(value instanceof Byte || value instanceof Short || value instanceof Integer || value instanceof Long,
                "MODEL_INTEGER_TYPE");
        return ((Number) value).longValue();
    }

    private static String modelRow(ResultSet rows, long expectedId) throws Exception {
        long id = integer(rows, 1);
        long group = integer(rows, 2);
        long value = integer(rows, 3);
        Object payload = rows.getObject(4);
        require(id == expectedId && group == id % 1024 && value == id % 100000
                && payload instanceof String && payload.equals(md5(id)), "FULL_VALUE_MODEL");
        return id + "\t" + group + "\t" + value + "\t" + payload + "\n";
    }

    private ObjectNode fullSource(Connection connection) throws Exception {
        MessageDigest observed = MessageDigest.getInstance("SHA-256");
        long next = 0;
        while (true) {
            identity();
            int count = 0;
            try (Statement statement = statement(connection); ResultSet rows = statement.executeQuery(
                    "SELECT id, grp, v, payload FROM " + SOURCE + (next == 0 ? "" : " WHERE id > " + (next - 1))
                            + " ORDER BY id LIMIT 10000")) {
                columns(rows);
                while (rows.next()) {
                    require(next < 1_000_000 && count < 10000, "SOURCE_ROW_RANGE");
                    observed.update(modelRow(rows, next++).getBytes(StandardCharsets.US_ASCII));
                    count++;
                }
            }
            if (count == 0) {
                break;
            }
        }
        require(next == 1_000_000, "SOURCE_MISSING_ROWS");
        identity();
        return JSON.createObjectNode().put("rows", next).put("full_values_verified", true)
                .put("canonical_sha256", HexFormat.of().formatHex(observed.digest()))
                .put("schema_sha256", schema(connection, SOURCE)).put("page_size", 10000)
                .put("pagination", "strict_id_keyset_no_offset");
    }

    private static long[] schedule(int rate, int seconds, long seed) {
        Random random = new Random(seed);
        long[] result = new long[1024];
        double elapsed = 0;
        int count = 0;
        while (true) {
            double uniform = random.nextDouble();
            if (uniform == 0) {
                continue;
            }
            elapsed += -StrictMath.log(uniform) * BILLION / rate;
            if (elapsed >= seconds * (double) BILLION) {
                return Arrays.copyOf(result, count);
            }
            require(count < 1_000_000, "SCHEDULE_COUNT_BOUND");
            if (count == result.length) {
                result = Arrays.copyOf(result, Math.min(1_000_000, result.length * 2));
            }
            result[count++] = (long) elapsed;
        }
    }

    private void inputs() throws Exception {
        long seed = config.path("seed").asLong();
        reads = schedule(number("read_rate_per_second"), number("duration_seconds"), seed);
        writes = schedule(number("write_batches_per_second"), number("duration_seconds"), seed ^ 0x9E3779B97F4A7C15L);
        require(reads.length > 0 && writes.length > 0 && (long) writes.length * number("write_batch_rows") <= 1_000_000,
                "ACTUAL_SCHEDULE_BOUND");
        keys = new int[reads.length];
        payloads = new String[1_000_000];
        inserts = new String[writes.length];
        writeState = new AtomicIntegerArray(writes.length);
        writeAck = new AtomicLong[writes.length];
        visible = new int[writes.length];
        Random random = new Random(seed ^ 0xD1B54A32D192ED03L);
        try (BufferedWriter read = Files.newBufferedWriter(directory.resolve("read-arrivals.tsv"));
                BufferedWriter write = Files.newBufferedWriter(directory.resolve("write-arrivals.tsv"))) {
            read.write("sequence\toffset_ns\tid\n");
            for (int index = 0; index < reads.length; index++) {
                keys[index] = random.nextInt(1_000_000);
                if (payloads[keys[index]] == null) {
                    payloads[keys[index]] = md5(keys[index]);
                }
                read.write(index + "\t" + reads[index] + "\t" + keys[index] + "\n");
            }
            write.write("sequence\toffset_ns\tfirst_id\trows\n");
            for (int index = 0; index < writes.length; index++) {
                writeAck[index] = new AtomicLong();
                long first = WRITE_BASE + (long) index * number("write_batch_rows");
                StringBuilder sql = new StringBuilder("INSERT INTO " + table + " VALUES ");
                for (int row = 0; row < number("write_batch_rows"); row++) {
                    long id = first + row;
                    if (row != 0) {
                        sql.append(',');
                    }
                    sql.append('(').append(id).append(',').append(id % 1024).append(',').append(id % 100000)
                            .append(",'").append(md5(id)).append("')");
                }
                inserts[index] = sql.toString();
                write.write(index + "\t" + writes[index] + "\t" + first + "\t" + number("write_batch_rows") + "\n");
            }
        }
        summary.put("read_schedule_sha256", digest(Files.readAllBytes(directory.resolve("read-arrivals.tsv"))))
                .put("write_schedule_sha256", digest(Files.readAllBytes(directory.resolve("write-arrivals.tsv"))))
                .put("planned_reads", reads.length).put("planned_write_batches", writes.length);
        summary.set("read_session_sql", JSON.valueToTree(READ_SESSION));
        summary.set("write_session_sql", JSON.valueToTree(WRITE_SESSION));
    }

    private static String state(SQLException error) {
        String state = error.getSQLState();
        return state != null && state.matches("[A-Za-z0-9]{1,5}") ? state : "NONE";
    }

    private void waitUntil(long at) throws InterruptedException {
        while (!cancelled && !Files.exists(directory.resolve("stop.json")) && System.nanoTime() < at) {
            TimeUnit.NANOSECONDS.sleep(Math.min(20_000_000L, Math.max(1, at - System.nanoTime())));
        }
    }

    private boolean sendable(long scheduled) {
        long now = System.nanoTime();
        return !cancelled && !Files.exists(directory.resolve("stop.json")) && now < phaseDeadline
                && now < epoch.get() + (number("duration_seconds") + number("drain_seconds")) * BILLION
                && scheduled < epoch.get() + number("duration_seconds") * BILLION;
    }

    private void worker(boolean write, int worker, int concurrency, CountDownLatch ready) {
        long[] arrivals = write ? writes : reads;
        String role = write ? "write" : "read";
        boolean announced = false;
        try (Connection connection = connect(role);
                Statement writer = write ? statement(connection) : null;
                PreparedStatement reader = write ? null : connection.prepareStatement(
                        "SELECT payload FROM " + SOURCE + " WHERE id = ?");
                BufferedWriter receipts = Files.newBufferedWriter(directory.resolve(role + "-" + worker + ".tsv"))) {
            if (reader != null) {
                reader.setQueryTimeout(number("timeout_seconds"));
            }
            publish(role + "-" + worker + "-session.json", session(connection, write));
            receipts.write("sequence\tscheduled_ns\tstarted_ns\tfinished_ns\toutcome\taffected_rows\tsql_state\terror_code\te2e_ns\n");
            ready.countDown();
            announced = true;
            while (epoch.get() == 0 && !cancelled && System.nanoTime() < phaseDeadline) {
                Thread.sleep(10);
            }
            for (int index = worker; index < arrivals.length; index += concurrency) {
                long scheduled = epoch.get() + arrivals[index];
                waitUntil(scheduled);
                long started = System.nanoTime();
                String outcome = "NOT_SENT";
                String sqlState = "NONE";
                int errorCode = 0;
                int affected = -1;
                if (epoch.get() != 0 && sendable(scheduled)) {
                    try {
                        identity();
                        if (write) {
                            // Set UNKNOWN before executing: any exception after this point must never trigger replay.
                            writeState.set(index, 2);
                            affected = writer.executeUpdate(inserts[index]);
                            outcome = "ACK";
                            writeState.set(index, 1);
                            if (affected != number("write_batch_rows")) {
                                outcome = "ACK_AFFECTED_MISMATCH";
                                errors.incrementAndGet();
                            }
                        } else {
                            reader.setLong(1, keys[index]);
                            // Same result contract as frozen LicenseJdbcBaseline: one String payload, exact MD5, one row.
                            try (ResultSet rows = reader.executeQuery()) {
                                require(rows.getMetaData().getColumnCount() == 1 && rows.next(), "POINT_ROW_SHAPE");
                                Object payload = rows.getObject(1);
                                require(payload instanceof String && payloads[keys[index]].equals(payload)
                                        && !rows.next(), "POINT_PAYLOAD_OR_ROW_COUNT");
                            }
                            outcome = "OK";
                        }
                    } catch (SQLException error) {
                        outcome = write ? "UNKNOWN" : "ERROR";
                        sqlState = state(error);
                        errorCode = error.getErrorCode();
                        errors.incrementAndGet();
                    } catch (Exception error) {
                        outcome = write && writeState.get(index) == 2 ? "UNKNOWN" : "ERROR";
                        errors.incrementAndGet();
                    }
                } else {
                    errors.incrementAndGet();
                }
                long ended = System.nanoTime();
                if (write) {
                    if (writeState.get(index) == 0) {
                        writeState.set(index, 3);
                    }
                    writeAck[index].set(ended);
                }
                long elapsed = ended - scheduled;
                if (elapsed > number(write ? "write_ack_slo_millis" : "read_slo_millis") * 1_000_000L) {
                    errors.incrementAndGet();
                }
                receipts.write(index + "\t" + scheduled + "\t" + started + "\t" + ended + "\t" + outcome
                        + "\t" + affected + "\t" + sqlState + "\t" + errorCode + "\t" + elapsed + "\n");
                receipts.flush();
            }
        } catch (Exception error) {
            errors.incrementAndGet();
        } finally {
            if (!announced) {
                ready.countDown();
            }
        }
    }

    private int batch(Connection oracle, int index) throws Exception {
        identity();
        long first = WRITE_BASE + (long) index * number("write_batch_rows");
        int count = 0;
        try (Statement statement = statement(oracle); ResultSet rows = statement.executeQuery(
                "SELECT id, grp, v, payload FROM " + table + " WHERE id >= " + first + " AND id < "
                        + (first + number("write_batch_rows")) + " ORDER BY id")) {
            columns(rows);
            while (rows.next()) {
                require(count < number("write_batch_rows"), "VISIBILITY_EXTRA_ROWS");
                modelRow(rows, first + count++);
            }
        }
        require(count == 0 || count == number("write_batch_rows"), "PARTIAL_BATCH_VISIBILITY");
        return count;
    }

    private void windowEnd() throws Exception {
        if (!windowEnded && System.nanoTime() >= epoch.get() + number("duration_seconds") * BILLION) {
            windowEnded = true;
            publish("window-end.json", timestamp().put("scheduled_window_complete", !cancelled));
        }
    }

    private void runWindow(Connection oracle) throws Exception {
        phaseDeadline = System.nanoTime() + 90 * BILLION;
        CountDownLatch ready = new CountDownLatch(number("read_workers") + number("write_workers"));
        for (boolean write : new boolean[] {false, true}) {
            int concurrency = number(write ? "write_workers" : "read_workers");
            for (int index = 0; index < concurrency; index++) {
                final int worker = index;
                Thread thread = new Thread(() -> worker(write, worker, concurrency, ready),
                        "ui-background-" + (write ? "write-" : "read-") + index);
                thread.setDaemon(true);
                workers.add(thread);
                thread.start();
            }
        }
        require(ready.await(30, TimeUnit.SECONDS) && errors.get() == 0, "CONNECTION_READINESS");
        publish("ready.json", timestamp().put("source_rows_verified", 1_000_000).put("empty_owned_target", true)
                .put("read_schedule_sha256", summary.path("read_schedule_sha256").asText())
                .put("write_schedule_sha256", summary.path("write_schedule_sha256").asText()));
        while (!Files.exists(directory.resolve("release.json"))) {
            identity();
            require(!Files.exists(directory.resolve("stop.json")), "CANCELLED_BEFORE_WINDOW");
            Thread.sleep(20);
        }
        JsonNode release = JSON.readTree(directory.resolve("release.json").toFile());
        require(release.path("token").asText().equals(token), "RELEASE_IDENTITY");
        long start = System.nanoTime() + 500_000_000L;
        phaseDeadline = start + (number("duration_seconds") + number("drain_seconds")) * BILLION;
        epoch.set(start);
        publish("window-start.json", timestamp().put("epoch_java_monotonic_ns", start)
                .put("duration_seconds", number("duration_seconds")).put("epoch_delay_millis", 500));
        long[] firstObserved = new long[writes.length];
        try (BufferedWriter evidence = Files.newBufferedWriter(directory.resolve("visibility.tsv"))) {
            evidence.write("sequence\tobserved_ns\tack_or_error_ns\trows\tstate\n");
            while (System.nanoTime() < phaseDeadline && !Files.exists(directory.resolve("stop.json"))) {
                windowEnd();
                identity();
                for (int index = 0; index < writes.length; index++) {
                    if (writeAck[index].get() == 0 || firstObserved[index] != 0 || writeState.get(index) == 3) {
                        continue;
                    }
                    int count = batch(oracle, index);
                    long now = System.nanoTime();
                    if (count != 0 || now - writeAck[index].get() >= number("visibility_timeout_seconds") * BILLION) {
                        firstObserved[index] = now;
                        visible[index] = count;
                        evidence.write(index + "\t" + now + "\t" + writeAck[index].get() + "\t" + count + "\t"
                                + (count != 0 ? "FULL_MODEL_VISIBLE" : "NOT_VISIBLE_AT_CUTOFF") + "\n");
                        evidence.flush();
                        if (count == 0 || now - writeAck[index].get() > number("visibility_slo_millis") * 1_000_000L) {
                            errors.incrementAndGet();
                        }
                    }
                }
                boolean finished = workers.stream().noneMatch(Thread::isAlive);
                boolean unresolved = false;
                for (int index = 0; index < writes.length; index++) {
                    unresolved |= writeAck[index].get() != 0 && writeState.get(index) != 3 && firstObserved[index] == 0;
                }
                if (windowEnded && finished && !unresolved) {
                    break;
                }
                Thread.sleep(number("visibility_poll_millis"));
            }
        }
        windowEnd();
        for (int index = 0; index < writes.length; index++) {
            if ((writeState.get(index) == 1 || writeState.get(index) == 2) && firstObserved[index] == 0) {
                errors.incrementAndGet();
            }
        }
        require(windowEnded && !Files.exists(directory.resolve("stop.json")), "WINDOW_INTERRUPTED");
        closeWorkers();
        require(workersClosed, "WORKERS_NOT_QUIESCENT");
    }

    private void closeWorkers() {
        cancelled = true;
        long deadline = System.nanoTime() + 5 * BILLION;
        for (Thread thread : workers) {
            thread.interrupt();
        }
        synchronized (connections) {
            for (Connection connection : connections) {
                Thread closer = new Thread(() -> {
                    try {
                        connection.close();
                    } catch (SQLException ignored) {
                        errors.incrementAndGet();
                    }
                }, "ui-background-close");
                closer.setDaemon(true);
                closingThreads.add(closer);
                closer.start();
            }
        }
        List<Thread> pending = new ArrayList<>(workers);
        pending.addAll(closingThreads);
        for (Thread thread : pending) {
            try {
                thread.join(Math.max(1, (deadline - System.nanoTime()) / 1_000_000));
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
        workersClosed = pending.stream().noneMatch(Thread::isAlive);
    }

    private ObjectNode fullTarget(Connection oracle) throws Exception {
        int[] counts = new int[writes.length];
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        long last = -1;
        long total = 0;
        while (true) {
            identity();
            int count = 0;
            try (Statement statement = statement(oracle); ResultSet rows = statement.executeQuery(
                    "SELECT id, grp, v, payload FROM " + table + (total == 0 ? "" : " WHERE id > " + last)
                            + " ORDER BY id LIMIT 10000")) {
                columns(rows);
                while (rows.next()) {
                    long id = integer(rows, 1);
                    require(id > last && id >= WRITE_BASE
                            && id < WRITE_BASE + (long) writes.length * number("write_batch_rows"), "TARGET_UNEXPECTED_ID");
                    int index = (int) ((id - WRITE_BASE) / number("write_batch_rows"));
                    require(writeState.get(index) != 3, "NOT_SENT_BATCH_BECAME_VISIBLE");
                    hash.update(modelRow(rows, id).getBytes(StandardCharsets.US_ASCII));
                    counts[index]++;
                    last = id;
                    total++;
                    require(++count <= 10000, "TARGET_PAGE_BOUND");
                }
            }
            if (count == 0) {
                break;
            }
        }
        ArrayNode batches = JSON.createArrayNode();
        for (int index = 0; index < counts.length; index++) {
            require(counts[index] == 0 || counts[index] == number("write_batch_rows"), "TARGET_PARTIAL_BATCH");
            int state = writeState.get(index);
            if (state == 1) {
                require(counts[index] == number("write_batch_rows"), "ACK_BATCH_NOT_VISIBLE");
            }
            if (state != 1) {
                errors.incrementAndGet();
            }
            batches.addObject().put("sequence", index).put("request_state", state == 1 ? "ACK"
                    : state == 2 ? "UNKNOWN" : state == 3 ? "NOT_SENT" : "NO_COMPLETION_RECEIPT")
                    .put("rows", counts[index]).put("observed_committed", counts[index] != 0)
                    .put("unknown_absence_is_rollback_proof", false);
        }
        publish("write-batch-resolution.json", batches);
        return JSON.createObjectNode().put("rows", total).put("full_values_verified", true)
                .put("canonical_sha256", HexFormat.of().formatHex(hash.digest()))
                .put("exact_id_domains_verified", true).put("exactly_once_proven_by_row_count", false);
    }

    private boolean cleanup() throws Exception {
        phaseDeadline = System.nanoTime() + number("cleanup_timeout_seconds") * BILLION;
        require(workersClosed || workers.isEmpty(), "NO_DROP_WITH_ACTIVE_WORKERS");
        try (Connection oracle = connect("oracle")) {
            if (!exists(oracle)) {
                return true;
            }
            Path receipt = directory.resolve("owner.json");
            require(Files.isRegularFile(receipt), "UNATTESTED_CREATE_REMAINS_MANUAL_CLEANUP");
            JsonNode owner = JSON.readTree(receipt.toFile());
            require(owner.path("token").asText().equals(token) && owner.path("table").asText().equals(table)
                    && owner.path("configuration_sha256").asText().equals(digest(Files.readAllBytes(configurationPath)))
                    && owner.path("create_acknowledged").asBoolean()
                    && owner.path("identity").equals(tableIdentity(oracle)), "TARGET_OWNERSHIP_CHANGED");
            execute(oracle, "DROP TABLE " + table);
            require(!exists(oracle), "OWNED_TABLE_REMAINS");
            return true;
        }
    }

    private void run(boolean cleanupOnly) throws Exception {
        if (cleanupOnly) {
            boolean cleaned = false;
            try {
                cleaned = cleanup();
            } finally {
                publish("cleanup.json", timestamp().put("cleanup_confirmed", cleaned));
            }
            return;
        }
        phaseDeadline = System.nanoTime() + number("prepare_timeout_seconds") * BILLION;
        try {
            inputs();
            try (Connection oracle = connect("oracle")) {
                summary.put("actual_driver", oracle.getMetaData().getDriverVersion())
                        .put("actual_jdk_runtime", System.getProperty("java.runtime.version"));
                summary.set("source_before", fullSource(oracle));
                require(!exists(oracle), "REFUSE_EXISTING_TARGET");
                publish("create-intent.json", timestamp().put("table", table).put("absent_before_create", true));
                // An uncertain CREATE does not produce owner.json and must never be adopted by name.
                execute(oracle, "CREATE TABLE " + table + " LIKE " + SOURCE);
                ObjectNode tableIdentity = tableIdentity(oracle);
                require(tableIdentity.path("schema_sha256").asText().equals(schema(oracle, SOURCE)), "CLONED_SCHEMA_DIFFERS");
                require(batch(oracle, 0) == 0, "TARGET_NOT_EMPTY");
                try (Statement statement = statement(oracle); ResultSet rows = statement.executeQuery("SELECT id FROM " + table + " LIMIT 1")) {
                    require(!rows.next(), "TARGET_NOT_EMPTY");
                }
                ObjectNode owner = timestamp().put("table", table).put("create_acknowledged", true)
                        .put("configuration_sha256", digest(Files.readAllBytes(configurationPath)));
                owner.set("identity", tableIdentity);
                publish("owner.json", owner);
            }
            try (Connection observer = connect("oracle")) {
                runWindow(observer);
            }
        } catch (Exception error) {
            summary.put("failure_class", error.getClass().getSimpleName());
            errors.incrementAndGet();
        } finally {
            closeWorkers();
            phaseDeadline = System.nanoTime() + number("verify_timeout_seconds") * BILLION;
            if (summary.has("source_before") && workersClosed) {
                try (Connection oracle = connect("oracle")) {
                    summary.set("source_after", fullSource(oracle));
                    require(summary.path("source_before").equals(summary.path("source_after")), "SOURCE_CHANGED");
                    summary.put("source_model_unchanged", true);
                    if (Files.exists(directory.resolve("owner.json"))) {
                        summary.set("target_after", fullTarget(oracle));
                    }
                } catch (Exception error) {
                    summary.put("verification_failure_class", error.getClass().getSimpleName());
                    errors.incrementAndGet();
                }
            }
            boolean cleaned = false;
            try {
                cleaned = cleanup();
            } catch (Exception error) {
                summary.put("cleanup_failure_class", error.getClass().getSimpleName());
                summary.put("residual_table", table).put("manual_owned_installation_cleanup_required", true)
                        .put("create_intent_present", Files.exists(directory.resolve("create-intent.json")))
                        .put("owner_receipt_present", Files.exists(directory.resolve("owner.json")));
            }
            summary.put("cleanup_confirmed", cleaned).put("workers_closed", workersClosed)
                    .put("window_complete", windowEnded).put("errors", errors.get())
                    .put("status", errors.get() == 0 && cleaned && workersClosed && windowEnded
                            && summary.path("source_model_unchanged").asBoolean()
                            && summary.has("target_after") ? "PASS" : "FAIL");
            publish("summary.json", summary);
        }
    }

    public static void main(String[] args) {
        try {
            require(args.length == 1 || (args.length == 2 && args[1].equals("--cleanup-only")), "ARGUMENTS");
            LicenseUiBackground fixture = new LicenseUiBackground(Path.of(args[0]));
            fixture.run(args.length == 2);
            if (args.length == 1 && !fixture.summary.path("status").asText().equals("PASS")) {
                System.exit(2);
            }
        } catch (Exception ignored) {
            // No JDBC, credential, SQL exception message, environment or stack trace may reach stdout/stderr.
            System.exit(2);
        }
    }
}
