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
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;

/** One G3 external JDBC sink window. Native PostgreSQL verification stays outside timed writes. */
public final class LicenseExternalWritePerformance {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final long BILLION = 1_000_000_000L;
    private static final ScheduledExecutorService TIMERS = Executors.newSingleThreadScheduledExecutor(task -> {
        Thread thread = new Thread(task, "external-write-owned-socket-deadline");
        thread.setDaemon(true);
        return thread;
    });
    private final JsonNode config;
    private final JsonNode launch;
    private final Path directory;
    private final String token;
    private final String table;
    private final String launchHash;
    private final long pid = ProcessHandle.current().pid();
    private final long startTicks;
    private final String namespace;
    private final ObjectNode summary = JSON.createObjectNode();
    private final AtomicLong failures = new AtomicLong();
    private final List<Thread> threads = new ArrayList<>();
    private Session[] sessions;
    private long[] warmup;
    private long[] measured;
    private String[] outcomes;
    private volatile boolean cancelled;
    private long phaseDeadline;
    private boolean workersClosed;
    private boolean created;
    private long tableOid;
    private String schemaHash;
    private String stage = "INPUTS";

    private LicenseExternalWritePerformance(Path path) throws Exception {
        config = JSON.readTree(path.toFile());
        directory = path.toRealPath().getParent();
        token = config.path("token").asText();
        table = "p4_sink_" + token;
        require(token.matches("[a-f0-9]{32}") && config.path("table").asText().equals("public." + table), "OWNED_TABLE");
        require(config.path("profile").asText().equals("g3_external_write_v1") && number("seed") == 20260922
                && number("rows_per_operation") == 100 && List.of(1, 8).contains(number("concurrency")), "PROFILE");
        require(config.path("license_state").asText().equals("VALID"), "VALID_WRITE_ONLY");
        require(number("max_requests") >= 2 && number("max_requests") <= 100000
                && number("max_rows") >= number("max_requests") * 100L, "DATA_BOUND");
        require(number("warmup_seconds") > 0 && number("warmup_seconds") <= 7200
                && number("duration_seconds") > 0 && number("duration_seconds") <= 604800
                && number("timeout_seconds") >= 1 && number("timeout_seconds") <= 60
                && number("drain_seconds") > 0 && number("drain_seconds") <= 120, "TIME_BOUND");
        require(config.path("qualification").asText().equals("diagnostic")
                || (config.path("qualification").asText().equals("formal") && number("warmup_seconds") >= 180
                    && number("duration_seconds") >= 600), "FORMAL_SHAPE");
        require(config.path("catalog").asText().matches("[A-Za-z_][A-Za-z0-9_]{0,127}"), "CATALOG");
        String stat = Files.readString(Path.of("/proc/self/stat"));
        startTicks = Long.parseLong(stat.substring(stat.lastIndexOf(')') + 1).trim().split("\\s+")[19]);
        namespace = Files.readSymbolicLink(Path.of("/proc/self/ns/net")).toString();
        require(namespace.equals(config.path("namespace").asText()), "NAMESPACE");
        Path launchPath = Path.of(config.path("launch").path("path").asText());
        launchHash = sha(Files.readAllBytes(launchPath));
        launch = JSON.readTree(launchPath.toFile());
        require(launchHash.equals(config.path("launch").path("sha256").asText())
                && launch.path("launch_token").asText().equals(token), "LAUNCH_BINDING");
        require(Files.readString(Path.of("/proc/sys/kernel/random/boot_id")).trim()
                .equals(launch.path("boot_id").asText()), "BOOT");
        summary.setAll(timestamp());
        summary.put("status", "INVALID_WINDOW").put("table", "public." + table)
                .put("automatic_write_replays", 0).put("formal_performance_pass", false);
    }

    private static final class CheckFailure extends IllegalStateException {
        private final String code;
        CheckFailure(String code) { super(code); this.code = code; }
    }

    private static void require(boolean condition, String code) {
        if (!condition) { throw new CheckFailure(code); }
    }

    private static void recordFailure(ObjectNode receipt, String prefix, Exception error) {
        receipt.put(prefix + "_class", error.getClass().getSimpleName());
        // Only our private fixed assertion codes are safe. Never serialize an external exception message.
        if (error instanceof CheckFailure) { receipt.put(prefix + "_reason", ((CheckFailure) error).code); }
        if (error instanceof SQLException) {
            SQLException sql = (SQLException) error; String state = sql.getSQLState();
            receipt.put(prefix + "_sql_state", state != null && state.matches("[A-Za-z0-9]{1,5}") ? state : "NONE")
                    .put(prefix + "_error_code", sql.getErrorCode());
        }
    }

    private static void verifyNativeIdentity(ResultSet rows, JsonNode account) throws Exception {
        require(rows.next() && account.path("user").asText().equals(rows.getString(1))
                && account.path("database").asText().equals(rows.getString(2))
                && account.path("host").asText().equals(rows.getString(3)) && rows.getInt(4) == account.path("port").asInt()
                && !rows.next(), "ACTUAL_NATIVE_SERVER");
    }

    private int number(String key) { return config.path(key).asInt(); }
    private static String sha(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }
    private static String payload(long id) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("MD5").digest(Long.toString(id).getBytes(StandardCharsets.US_ASCII)));
    }
    private static String model(long id) throws Exception {
        return id + "\t" + id % 1024 + "\t" + id % 100000 + "\t" + payload(id) + "\n";
    }
    private ObjectNode timestamp() {
        return JSON.createObjectNode().put("schema_version", 1).put("token", token).put("pid", pid).put("start_ticks", startTicks)
                .put("namespace", namespace).put("launch_token", token).put("launch_sha256", launchHash)
                .put("boot_id", launch.path("boot_id").asText()).put("java_monotonic_ns", System.nanoTime());
    }
    private void publish(String name, JsonNode value) throws Exception {
        Path destination = directory.resolve(name);
        require(!Files.exists(destination), "RECEIPT_EXISTS");
        Path temporary = directory.resolve(name + ".tmp");
        JSON.writerWithDefaultPrettyPrinter().writeValue(temporary.toFile(), value);
        Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE);
    }
    private void check() throws Exception {
        require(!cancelled && !Files.exists(directory.resolve("stop.json")), "OWNED_STOP");
        require(sha(Files.readAllBytes(Path.of(config.path("launch").path("path").asText()))).equals(launchHash), "LAUNCH_CHANGED");
        for (JsonNode pin : config.path("cluster_pins")) {
            Path proc = Path.of("/proc", pin.path("pid").asText());
            String stat = Files.readString(proc.resolve("stat"));
            String[] fields = stat.substring(stat.lastIndexOf(')') + 1).trim().split("\\s+");
            require(!List.of("Z", "X").contains(fields[0]) && Long.parseLong(fields[19]) == pin.path("start_ticks").asLong()
                    && Files.readSymbolicLink(proc.resolve("ns/net")).toString().equals(pin.path("namespace").asText())
                    && Files.readSymbolicLink(proc.resolve("exe")).toString().equals(pin.path("exe").asText())
                    && sha(Files.readAllBytes(proc.resolve("cmdline"))).equals(pin.path("command_sha256").asText()), "CLUSTER_LIFETIME");
        }
    }
    private JsonNode await(String name) throws Exception {
        Path path = directory.resolve(name);
        while (!Files.exists(path)) { check(); require(System.nanoTime() < phaseDeadline, "COORDINATION_TIMEOUT"); Thread.sleep(5); }
        JsonNode value = JSON.readTree(path.toFile());
        require(value.path("token").asText().equals(token) && System.nanoTime() < phaseDeadline, "MARKER_TOKEN_OR_DEADLINE");
        return value;
    }
    private static String password(JsonNode account) {
        String value = System.getenv(account.path("password_env").asText());
        require(value != null, "EXPLICIT_PASSWORD_ENV");
        return value;
    }

    /** Exact fixed-driver socket ownership prevents driver cancellation from opening an extra connection. */
    private final class Session implements AutoCloseable {
        private final org.mariadb.jdbc.Connection connection;
        private final java.net.Socket socket;
        private final long connectionId;
        private volatile boolean aborted;
        Session(JsonNode account) throws Exception {
            Properties properties = new Properties();
            properties.setProperty("user", account.path("username").asText()); properties.setProperty("password", password(account));
            properties.setProperty("autoReconnect", "false"); properties.setProperty("allowMultiQueries", "false");
            properties.setProperty("useServerPrepStmts", "false"); properties.setProperty("useSsl", "false");
            properties.setProperty("connectTimeout", "10000"); properties.setProperty("socketTimeout", "65000");
            java.util.logging.Logger.getLogger("org.mariadb.jdbc").setLevel(java.util.logging.Level.OFF);
            connection = (org.mariadb.jdbc.Connection) DriverManager.getConnection("jdbc:mariadb://"
                    + config.path("target").path("host").asText() + ":" + config.path("target").path("query_port").asInt()
                    + "/license_perf", properties);
            connectionId = connection.getThreadId();
            java.net.Socket owned;
            try {
                require(connection.getClient().getClass().getName().equals("org.mariadb.jdbc.client.impl.StandardClient"), "JDBC_CLIENT");
                java.lang.reflect.Field field = connection.getClient().getClass().getDeclaredField("socket"); field.setAccessible(true);
                owned = (java.net.Socket) field.get(connection.getClient());
            } catch (Exception error) { connection.close(); throw error; }
            socket = owned;
            try {
                require(socket.isConnected() && socket.getInetAddress().isLoopbackAddress()
                        && socket.getPort() == config.path("target").path("query_port").asInt(), "OWNED_FE_SOCKET");
                connection.setAutoCommit(true);
                try (Statement statement = connection.createStatement()) {
                    statement.setQueryTimeout(0);
                    for (String sql : List.of("SET enable_sql_cache=false", "SET enable_query_cache=false", "SET group_commit=off_mode",
                            "SET query_timeout=" + number("timeout_seconds"), "SET insert_timeout=" + number("timeout_seconds"))) {
                        statement.execute(sql);
                    }
                }
            } catch (Exception error) { abort(); connection.close(); throw error; }
        }
        private void abort() { aborted = true; try { socket.close(); } catch (Exception ignored) { } }
        ObjectNode identity(int worker) throws Exception {
            ObjectNode receipt = timestamp().put("worker", worker).put("server_connection_id", connectionId)
                    .put("driver", connection.getMetaData().getDriverVersion()).put("socket_local_port", socket.getLocalPort())
                    .put("socket_remote_port", socket.getPort()).put("connections_opened", 1).put("auto_commit", connection.getAutoCommit());
            try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(
                    "SELECT @@enable_sql_cache,@@enable_query_cache,@@group_commit,@@query_timeout,@@insert_timeout,CURRENT_USER(),@@autocommit")) {
                require(rows.next(), "SESSION_MISSING");
                ArrayNode values = receipt.putArray("actual_settings");
                for (int column = 1; column <= 7; column++) { values.add(rows.getString(column)); }
                require(values.get(6).asText().equals("1"), "SERVER_AUTOCOMMIT");
                require(!rows.next(), "SESSION_EXTRA_ROWS");
            }
            return receipt;
        }
        long write(int request, ObjectNode row) throws Exception {
            require(!aborted && !connection.isClosed() && connection.getThreadId() == connectionId, "FE_CONNECTION_CHANGED");
            row.put("server_connection_id", connectionId).put("socket_local_port", socket.getLocalPort());
            long deadline = row.path("started_ns").asLong() + 120 * BILLION;
            var timer = TIMERS.schedule(this::abort, Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            try (Statement statement = connection.createStatement()) {
                statement.setQueryTimeout(0);
                String sql = "INSERT INTO " + config.path("catalog").asText() + ".public." + table
                        + "(run_id,request_id,id,grp,v,payload) SELECT '" + token + "'," + request
                        + ",id,grp,v,payload FROM internal.license_perf.point_rows WHERE id >= 0 AND id < 100";
                row.put("sql_sha256", sha(sql.getBytes(StandardCharsets.UTF_8))).put("execute_calls", 1);
                require(!statement.execute(sql), "WRITE_RETURNED_RESULT_SET");
                long count = statement.getLargeUpdateCount();
                require(System.nanoTime() < deadline && !aborted && connection.getThreadId() == connectionId, "WRITE_DEADLINE");
                return count;
            } finally { timer.cancel(false); row.put("connection_aborted", aborted); }
        }
        public void close() throws Exception {
            var timer = TIMERS.schedule(this::abort, 5, TimeUnit.SECONDS);
            try { connection.close(); require(connection.isClosed(), "FE_CLOSE"); }
            finally { timer.cancel(false); }
        }
    }

    private Connection nativeConnection() throws Exception {
        JsonNode account = config.path("native_account");
        Properties properties = new Properties(); properties.setProperty("user", account.path("user").asText());
        properties.setProperty("password", password(account)); properties.setProperty("connectTimeout", "10");
        properties.setProperty("socketTimeout", "65"); properties.setProperty("sslmode", "disable");
        properties.setProperty("ApplicationName", "massdb_p4_" + token);
        java.util.logging.Logger.getLogger("org.postgresql").setLevel(java.util.logging.Level.OFF);
        Connection connection = DriverManager.getConnection("jdbc:postgresql://" + account.path("host").asText() + ":"
                + account.path("port").asInt() + "/" + account.path("database").asText(), properties);
        try {
            require(connection.getMetaData().getDriverVersion().equals("42.7.8"), "PG_DRIVER");
            try (Statement statement = connection.createStatement()) {
                statement.execute("SET statement_timeout='60000ms'"); statement.execute("SET lock_timeout='5000ms'");
                // PostgreSQL inet::text may include /32; host(inet) returns the actual bare host address.
                try (ResultSet rows = statement.executeQuery("SELECT current_user,current_database(),host(inet_server_addr()),inet_server_port()")) {
                    verifyNativeIdentity(rows, account);
                }
            }
            return connection;
        } catch (Exception error) { connection.close(); throw error; }
    }
    private ObjectNode nativeIdentity(Connection connection) throws Exception {
        ObjectNode receipt = JSON.createObjectNode();
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(
                "SELECT c.oid,obj_description(c.oid,'pg_class') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                + "WHERE n.nspname='public' AND c.relname='" + table + "' AND c.relkind='r'")) {
            if (!rows.next()) { return receipt.put("exists", false); }
            receipt.put("exists", true).put("oid", rows.getLong(1)).put("comment", rows.getString(2));
            require(!rows.next(), "NATIVE_DUPLICATE_TABLE");
        }
        ArrayNode columns = receipt.putArray("columns");
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(
                "SELECT attname,format_type(atttypid,atttypmod),attnotnull FROM pg_attribute WHERE attrelid="
                + receipt.path("oid").asLong() + " AND attnum>0 AND NOT attisdropped ORDER BY attnum")) {
            while (rows.next()) { columns.addArray().add(rows.getString(1)).add(rows.getString(2)).add(rows.getBoolean(3)); }
        }
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid=" + receipt.path("oid").asLong()
                + " AND contype='p'")) {
            require(rows.next(), "NATIVE_PRIMARY_KEY_MISSING"); receipt.put("primary_key", rows.getString(1));
            require(!rows.next() && receipt.path("primary_key").asText().equals("PRIMARY KEY (run_id, request_id, id)"), "NATIVE_PRIMARY_KEY");
        }
        ObjectNode schema = JSON.createObjectNode(); schema.set("columns", columns); schema.put("primary_key", receipt.path("primary_key").asText());
        receipt.put("schema_sha256", sha(JSON.writeValueAsBytes(schema)));
        return receipt;
    }
    private void owned(Connection connection) throws Exception {
        ObjectNode actual = nativeIdentity(connection);
        require(actual.path("exists").asBoolean() && actual.path("oid").asLong() == tableOid
                && actual.path("comment").asText().equals("massdb-p4-owned:" + token)
                && actual.path("schema_sha256").asText().equals(schemaHash), "NATIVE_OWNER_CHANGED");
    }
    private void createTarget() throws Exception {
        try (Connection connection = nativeConnection()) {
            require(!nativeIdentity(connection).path("exists").asBoolean(), "REFUSE_EXISTING_NATIVE_TARGET");
            publish("create-intent.json", timestamp().put("table", "public." + table).put("absent_before_create", true));
            connection.setAutoCommit(false);
            try (Statement statement = connection.createStatement()) {
                statement.execute("CREATE TABLE public." + table + "(run_id VARCHAR(32) NOT NULL,request_id BIGINT NOT NULL,"
                        + "id BIGINT NOT NULL,grp INTEGER NOT NULL,v BIGINT NOT NULL,payload VARCHAR(32) NOT NULL,"
                        + "PRIMARY KEY(run_id,request_id,id))");
                statement.execute("COMMENT ON TABLE public." + table + " IS 'massdb-p4-owned:" + token + "'");
                connection.commit(); created = true;
            } catch (Exception error) { try { connection.rollback(); } catch (Exception ignored) { } throw error; }
            ObjectNode identity = nativeIdentity(connection); tableOid = identity.path("oid").asLong();
            schemaHash = identity.path("schema_sha256").asText(); owned(connection);
            ObjectNode owner = timestamp().put("table", "public." + table).put("create_acknowledged", true)
                    .put("configuration_sha256", sha(Files.readAllBytes(directory.resolve("config.json"))));
            owner.set("identity", identity); publish("owner.json", owner);
        }
        try (Session session = new Session(config.path("oracle_account")); Statement statement = session.connection.createStatement()) {
            statement.execute("REFRESH CATALOG " + config.path("catalog").asText());
        }
    }
    private ObjectNode sourceModel() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256"); long count = 0; String sourceSchema;
        try (Session session = new Session(config.path("read_account"));
                Statement statement = session.connection.createStatement(ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY)) {
            statement.setFetchSize(1024); statement.setQueryTimeout(0);
            try (ResultSet rows = statement.executeQuery("SHOW CREATE TABLE internal.license_perf.point_rows")) {
                require(rows.next(), "SOURCE_SCHEMA_MISSING"); sourceSchema = sha(rows.getString(2).getBytes(StandardCharsets.UTF_8));
                require(!rows.next(), "SOURCE_SCHEMA_EXTRA");
            }
            try (ResultSet rows = statement.executeQuery("SELECT id,grp,v,payload FROM internal.license_perf.point_rows ORDER BY id")) {
                require(rows.getMetaData().getColumnCount() == 4, "SOURCE_COLUMNS");
                for (int column = 1; column <= 4; column++) {
                    require(rows.getMetaData().getColumnLabel(column).equals(List.of("id", "grp", "v", "payload").get(column - 1)), "SOURCE_COLUMN_ORDER");
                }
                while (rows.next()) {
                    Object id = rows.getObject(1), group = rows.getObject(2), value = rows.getObject(3), text = rows.getObject(4);
                    for (Object number : List.of(id, group, value)) {
                        require(number instanceof Byte || number instanceof Short || number instanceof Integer || number instanceof Long,
                                "SOURCE_EXACT_INTEGER_TYPE");
                    }
                    require(count < 1000000 && ((Number) id).longValue() == count && ((Number) group).longValue() == count % 1024
                            && ((Number) value).longValue() == count % 100000 && text instanceof String
                            && payload(count).equals(text), "SOURCE_FULL_MODEL");
                    digest.update(model(count++).getBytes(StandardCharsets.US_ASCII));
                }
            }
        }
        require(count == 1000000, "SOURCE_MISSING_ROWS");
        return JSON.createObjectNode().put("rows", count).put("canonical_sha256", HexFormat.of().formatHex(digest.digest()))
                .put("full_values_verified", true).put("schema_sha256", sourceSchema);
    }
    private void nativeModel() throws Exception {
        int[] counts = new int[outcomes.length]; long total = 0; int lastRequest = -1; int lastId = -1;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (Connection connection = nativeConnection(); BufferedWriter output = Files.newBufferedWriter(directory.resolve("native-target.tsv"))) {
            owned(connection); connection.setAutoCommit(false);
            try (Statement statement = connection.createStatement(ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY)) {
                statement.setFetchSize(1024);
                try (ResultSet rows = statement.executeQuery("SELECT run_id,request_id,id,grp,v,payload FROM public." + table
                        + " ORDER BY run_id,request_id,id")) {
                    require(rows.getMetaData().getColumnCount() == 6, "NATIVE_COLUMNS");
                    while (rows.next()) {
                        String run = rows.getString(1); long requestValue = rows.getLong(2);
                        require(!rows.wasNull() && requestValue >= 0 && requestValue < outcomes.length, "NATIVE_REQUEST_KEY");
                        int request = (int) requestValue; int id = rows.getInt(3);
                        require(!rows.wasNull() && id >= 0 && id < 100 && token.equals(run)
                                && (request > lastRequest || request == lastRequest && id > lastId)
                                && rows.getInt(4) == id % 1024 && !rows.wasNull() && rows.getLong(5) == id % 100000 && !rows.wasNull()
                                && payload(id).equals(rows.getString(6)) && !rows.wasNull(), "NATIVE_FULL_MODEL");
                        String line = token + "\t" + request + "\t" + model(id); output.write(line);
                        digest.update(line.getBytes(StandardCharsets.US_ASCII)); counts[request]++; total++;
                        require(total <= number("max_rows"), "NATIVE_ROW_BOUND"); lastRequest = request; lastId = id;
                    }
                }
            }
            connection.rollback();
        }
        ArrayNode resolved = JSON.createArrayNode(); boolean correct = true;
        for (int request = 0; request < counts.length; request++) {
            resolved.addObject().put("request_id", request).put("outcome", outcomes[request]).put("rows", counts[request])
                    .put("ack_upgraded_from_visibility", false).put("absence_proves_rollback", false);
            correct &= counts[request] == (outcomes[request].equals("ACK") ? 100 : 0) && outcomes[request].equals("ACK");
        }
        publish("native-resolution.json", resolved);
        summary.set("target_after", JSON.createObjectNode().put("rows", total)
                .put("canonical_sha256", HexFormat.of().formatHex(digest.digest())).put("all_acknowledged_batches_verified", correct));
        require(correct, "NATIVE_ACK_OR_UNKNOWN_BATCH");
    }
    private void disk(String label) throws Exception {
        ObjectNode receipt = timestamp().put("stage", label); ArrayNode items = receipt.putArray("paths");
        for (JsonNode item : config.path("storage_paths")) {
            Path path = Path.of(item.asText()); long available = Files.getFileStore(path).getUsableSpace();
            items.addObject().put("path", path.toRealPath().toString()).put("usable_bytes", available);
            require(available >= config.path("min_disk_free_bytes").asLong(), "DISK_RESERVATION");
        }
        publish("disk-" + label + ".json", receipt);
    }

    private long[] arrivals(int seconds) {
        Random random = new Random(20260922); List<Long> result = new ArrayList<>(); double elapsed = 0;
        while (true) {
            double uniform = random.nextDouble(); if (uniform == 0) { continue; }
            elapsed += -StrictMath.log(uniform) * BILLION / config.path("rate_per_second").asDouble();
            if (elapsed >= seconds * (double) BILLION) { break; }
            require(result.size() < number("max_requests"), "ARRIVAL_BOUND"); result.add((long) elapsed);
        }
        require(!result.isEmpty(), "EMPTY_ARRIVALS");
        return result.stream().mapToLong(Long::longValue).toArray();
    }
    private void schedules() throws Exception {
        warmup = arrivals(number("warmup_seconds")); measured = arrivals(number("duration_seconds"));
        require(warmup.length + measured.length <= number("max_requests"), "TOTAL_ARRIVAL_BOUND");
        outcomes = new String[warmup.length + measured.length]; Arrays.fill(outcomes, "NOT_SENT");
        int base = 0;
        for (String phase : List.of("warmup", "measurement")) {
            long[] schedule = phase.equals("warmup") ? warmup : measured;
            try (BufferedWriter stream = Files.newBufferedWriter(directory.resolve(phase + "-arrivals.tsv"))) {
                stream.write("sequence\toffset_ns\trequest_id\trows\n");
                for (int index = 0; index < schedule.length; index++) {
                    stream.write(index + "\t" + schedule[index] + "\t" + (base + index) + "\t100\n");
                }
            }
            summary.put(phase + "_requests", schedule.length); base += schedule.length;
        }
        summary.put("total_requests", outcomes.length);
    }
    private ObjectNode cpu() throws Exception {
        check(); ObjectNode values = JSON.createObjectNode();
        for (String role : List.of("fe", "be")) {
            JsonNode pin = config.path("cpu_services").path(role); long begin = System.nanoTime();
            String stat = Files.readString(Path.of("/proc", pin.path("pid").asText(), "stat")); long end = System.nanoTime();
            String[] fields = stat.substring(stat.lastIndexOf(')') + 1).trim().split("\\s+");
            require(Long.parseLong(fields[19]) == pin.path("start_ticks").asLong() && !List.of("Z", "X").contains(fields[0]), "CPU_GENERATION");
            values.putObject(role).put("pid", pin.path("pid").asLong()).put("start_ticks", Long.parseLong(fields[19]))
                    .put("raw_stat", stat).put("sample_started_java_ns", begin).put("sample_ended_java_ns", end);
        }
        return values;
    }
    private static void until(long deadline) throws InterruptedException {
        while (System.nanoTime() < deadline) {
            if (Thread.interrupted()) { throw new InterruptedException(); }
            LockSupport.parkNanos(Math.min(10_000_000L, deadline - System.nanoTime()));
        }
    }
    private void phase(String phase, long[] schedule, int base, int seconds) throws Exception {
        ObjectNode before = cpu(); long epoch = System.nanoTime() + 500_000_000L;
        ObjectNode start = timestamp().put("epoch_ns", epoch); start.set("cpu", before); publish(phase + "-start.json", start);
        phaseDeadline = epoch + (seconds + (long) number("drain_seconds")) * BILLION;
        AtomicLong last = new AtomicLong(epoch); AtomicLong successful = new AtomicLong(); threads.clear();
        for (int worker = 0; worker < sessions.length; worker++) {
            final int index = worker;
            Thread thread = new Thread(() -> {
                try (BufferedWriter output = Files.newBufferedWriter(directory.resolve(phase + "-" + index + ".jsonl"))) {
                    for (int sequence = index; sequence < schedule.length; sequence += sessions.length) {
                        int request = base + sequence; long scheduled = epoch + schedule[sequence]; until(scheduled);
                        long begin = System.nanoTime();
                        ObjectNode row = JSON.createObjectNode().put("worker", index).put("sequence", sequence).put("request_id", request)
                                .put("scheduled_ns", scheduled).put("started_ns", begin).put("execute_calls", 0).put("affected_rows", -1)
                                .put("sql_state", "NONE").put("error_code", 0).put("timeout", false);
                        String outcome = "NOT_SENT";
                        try {
                            if (!cancelled && !Files.exists(directory.resolve("stop.json")) && begin < phaseDeadline) {
                                outcome = "UNKNOWN";
                                long affected = sessions[index].write(request, row);
                                row.put("affected_rows", affected); outcome = "ACK"; successful.incrementAndGet();
                            }
                        } catch (Exception error) {
                            row.put("error_class", error.getClass().getSimpleName());
                            if (error instanceof SQLException) {
                                SQLException sql = (SQLException) error; String state = sql.getSQLState();
                                row.put("sql_state", state != null && state.matches("[A-Za-z0-9]{1,5}") ? state : "NONE");
                                row.put("error_code", sql.getErrorCode());
                                row.put("timeout", error instanceof java.sql.SQLTimeoutException || "HYT00".equals(state));
                            }
                            sessions[index].abort();
                        }
                        long finish = System.nanoTime(); outcomes[request] = outcome;
                        if (!outcome.equals("ACK")) { failures.incrementAndGet(); }
                        row.put("outcome", outcome).put("finished_ns", finish).put("e2e_ns", finish - scheduled)
                                .put("service_ns", finish - begin).put("queue_ns", begin - scheduled);
                        output.write(JSON.writeValueAsString(row)); output.newLine(); output.flush();
                        last.accumulateAndGet(finish, Math::max);
                    }
                } catch (Exception error) { failures.incrementAndGet(); cancelled = true; }
            }, "external-write-" + phase + "-" + index);
            threads.add(thread); thread.start();
        }
        long waitUntil = phaseDeadline + 130 * BILLION;
        for (Thread thread : threads) {
            while (thread.isAlive()) { check(); require(System.nanoTime() < waitUntil, "WORKERS_DEADLINE"); thread.join(20); }
        }
        until(epoch + seconds * BILLION);
        long intervalEnd = Math.max(epoch + seconds * BILLION, last.get());
        ObjectNode end = timestamp().put("epoch_ns", epoch).put("request_interval_end_ns", intervalEnd)
                .put("last_request_end_ns", last.get()).put("scheduled_requests", schedule.length).put("successful_requests", successful.get())
                .put("arrival_schedule_sha256", sha(Files.readAllBytes(directory.resolve(phase + "-arrivals.tsv"))));
        end.set("cpu", cpu()); end.put("java_monotonic_ns", System.nanoTime()); publish(phase + "-end.json", end);
    }
    private void closeWorkers() throws Exception {
        for (Thread thread : threads) { if (thread.isAlive()) { cancelled = true; thread.interrupt(); } }
        if (sessions != null) {
            for (int index = 0; index < sessions.length; index++) {
                Session session = sessions[index]; if (session == null) { continue; }
                if (cancelled) { session.abort(); }
                ObjectNode close = timestamp().put("worker", index).put("close_started_ns", System.nanoTime());
                session.close(); close.put("close_finished_ns", System.nanoTime()).put("connection_closed", session.connection.isClosed())
                        .put("connection_aborted", session.aborted).put("server_connection_id", session.connectionId);
                if (!Files.exists(directory.resolve("worker-" + index + "-close.json"))) { publish("worker-" + index + "-close.json", close); }
            }
        }
        for (Thread thread : threads) { thread.join(5000); require(!thread.isAlive(), "WORKER_STILL_LIVE"); }
        workersClosed = true;
    }
    private boolean cleanup() throws Exception {
        if (!created) { return false; }
        try (Connection connection = nativeConnection()) {
            connection.setAutoCommit(false);
            // Hold the owned relation against rename/drop/replacement while checking its OID and owner.
            try (Statement statement = connection.createStatement()) {
                statement.execute("LOCK TABLE public." + table + " IN ACCESS EXCLUSIVE MODE");
            }
            owned(connection);
            ObjectNode before = nativeIdentity(connection); ObjectNode receipt = timestamp().put("table", "public." + table);
            receipt.set("before", before); receipt.put("drop_started_ns", System.nanoTime());
            try (Statement statement = connection.createStatement()) { statement.execute("DROP TABLE public." + table); }
            connection.commit();
            receipt.put("drop_ack_ns", System.nanoTime()); ObjectNode after = nativeIdentity(connection); receipt.set("after", after);
            require(!after.path("exists").asBoolean(), "NATIVE_DROP_UNCONFIRMED");
            receipt.put("drop_acknowledged", true).put("absence_confirmed_ns", System.nanoTime());
            publish(Files.exists(directory.resolve("native-drop.json")) ? "native-drop-recovery.json" : "native-drop.json", receipt);
        }
        return true;
    }
    private void run() throws Exception {
        boolean clean = false; boolean verified = false;
        try {
            stage = "PREPARE"; check(); schedules(); disk("before");
            summary.set("source_before", sourceModel()); createTarget();
            sessions = new Session[number("concurrency")];
            for (int index = 0; index < sessions.length; index++) {
                sessions[index] = new Session(config.path("write_account"));
                publish("worker-" + index + "-session.json", sessions[index].identity(index));
            }
            publish("ready.json", timestamp().put("connections", sessions.length).put("source_rows_verified", 1000000));
            phaseDeadline = System.nanoTime() + number("coordination_timeout_seconds") * BILLION;
            JsonNode request = await("clock-request.json"); String nonce = request.path("nonce").asText();
            require(nonce.matches("[a-f0-9]{32}"), "CLOCK_NONCE");
            publish("p4-helper-clock.json", timestamp().put("nonce", nonce).put("jvm_sample_ns", System.nanoTime())
                    .put("helper_pid", pid).put("helper_start_ticks", startTicks));
            require(await("clock-ack.json").path("nonce").asText().equals(nonce), "CLOCK_ACK");
            stage = "WARMUP"; phase("warmup", warmup, 0, number("warmup_seconds"));
            JsonNode warmStart = JSON.readTree(directory.resolve("warmup-start.json").toFile());
            JsonNode warmEnd = JSON.readTree(directory.resolve("warmup-end.json").toFile());
            publish("measurement-ready.json", timestamp().put("ready_ns", System.nanoTime())
                    .put("warmup_start_ns", warmStart.path("epoch_ns").asLong()).put("warmup_end_ns", warmEnd.path("java_monotonic_ns").asLong()));
            phaseDeadline = System.nanoTime() + number("coordination_timeout_seconds") * BILLION; await("measurement-release.json");
            stage = "MEASUREMENT"; phase("measurement", measured, warmup.length, number("duration_seconds"));
            stage = "VERIFY"; closeWorkers(); publish("verification-ready.json", timestamp().put("workers_closed", true));
            phaseDeadline = System.nanoTime() + number("coordination_timeout_seconds") * BILLION; await("verify-release.json");
            publish("verification-start.json", timestamp()); nativeModel(); summary.set("source_after", sourceModel()); disk("after");
            require(summary.path("source_before").equals(summary.path("source_after")), "SOURCE_CHANGED"); verified = true;
        } catch (Exception error) {
            failures.incrementAndGet(); summary.put("failure_stage", stage); recordFailure(summary, "failure", error);
        } finally {
            ObjectNode lifecycle = timestamp();
            try { if (!workersClosed) { cancelled = true; closeWorkers(); } } catch (Exception error) { failures.incrementAndGet(); }
            try { clean = cleanup(); } catch (Exception error) { recordFailure(summary, "cleanup_failure", error); }
            lifecycle.put("workers_closed", workersClosed).put("cleanup_confirmed", clean).put("cleanup_end_ns", System.nanoTime());
            publish("lifecycle.json", lifecycle);
            summary.put("errors", failures.get()).put("cleanup_confirmed", clean).put("workers_closed", workersClosed)
                    .put("status", clean && workersClosed && verified && failures.get() == 0 ? "RAW_WINDOW_COMPLETE" : "INVALID_WINDOW");
            publish("summary.json", summary); TIMERS.shutdownNow();
        }
        require(summary.path("status").asText().equals("RAW_WINDOW_COMPLETE"), "WINDOW_INVALID");
    }
    private void cleanupOnly() throws Exception {
        JsonNode owner = JSON.readTree(directory.resolve("owner.json").toFile());
        require(owner.path("token").asText().equals(token) && owner.path("launch_sha256").asText().equals(launchHash)
                && owner.path("table").asText().equals("public." + table) && owner.path("create_acknowledged").asBoolean()
                && owner.path("configuration_sha256").asText().equals(sha(Files.readAllBytes(directory.resolve("config.json")))),
                "RECOVERY_OWNER_REQUIRED");
        tableOid = owner.path("identity").path("oid").asLong(); schemaHash = owner.path("identity").path("schema_sha256").asText();
        created = true;
        publish("recovery-cleanup.json", timestamp().put("cleanup_confirmed", cleanup()).put("recovery_only", true));
        TIMERS.shutdownNow();
    }
    public static void main(String[] args) throws Exception {
        require(args.length == 1 || args.length == 2, "CONFIG_REQUIRED");
        LicenseExternalWritePerformance helper = new LicenseExternalWritePerformance(Path.of(args[0]));
        if (args.length == 2) {
            if (args[1].equals("--cleanup-only")) { helper.cleanupOnly(); }
            else {
                require(args[1].equals("--plan"), "MODE"); helper.schedules();
                ObjectNode result = JSON.createObjectNode().put("status", "OFFLINE_PLAN_ONLY_NO_SQL");
                for (String phase : List.of("warmup", "measurement")) {
                    result.put(phase + "_sha256", sha(Files.readAllBytes(helper.directory.resolve(phase + "-arrivals.tsv"))));
                }
                System.out.println(result);
            }
        } else { helper.run(); }
    }
}
