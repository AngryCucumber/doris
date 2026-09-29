// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;

/** One G2 external catalog or S3 TVF complete streamed four-column read per operation. */
public final class LicenseExternalReadPerformance {
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    private static final long BILLION = 1_000_000_000L;
    private static final String MODEL = "b2b90b17ef5b149fa1deca05a37b48198d0e709790be44ea2ecb80979d9cef7c";
    private final JsonNode config;
    private final JsonNode profile;
    private final JsonNode launch;
    private final Path directory;
    private final String launchHash;
    private final long pid = ProcessHandle.current().pid();
    private final long startTicks;
    private final String namespace;
    private static final ScheduledThreadPoolExecutor TIMERS = timers();
    private static ScheduledThreadPoolExecutor timers() {
        ScheduledThreadPoolExecutor result = new ScheduledThreadPoolExecutor(1, task -> {
            Thread thread = new Thread(task, "external-jdbc-deadline");
            thread.setDaemon(true);
            return thread;
        });
        result.setRemoveOnCancelPolicy(true);
        return result;
    }
    private final AtomicLong rawBytes = new AtomicLong();
    private final List<Session> sessions = new ArrayList<>();
    private final AtomicLong failures = new AtomicLong();
    private final List<Thread> workers = new ArrayList<>();
    private volatile boolean cancelled;

    private static void require(boolean condition, String code) {
        if (!condition) {
            throw new IllegalStateException(code);
        }
    }

    private static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static long ticks(long process) throws Exception {
        String raw = Files.readString(Path.of("/proc", Long.toString(process), "stat"));
        return Long.parseLong(raw.substring(raw.lastIndexOf(')') + 1).trim().split("\\s+")[19]);
    }

    private static void validate(JsonNode value) {
        require(value.path("profile").asText().equals("g2_external_read_v1") && value.path("seed").asLong() == 20260922,
                "FIXED_PROFILE");
        require(List.of("catalog", "s3_tvf").contains(value.path("source_kind").asText()), "SOURCE_KIND");
        require(value.path("column_types").size() == 4, "FROZEN_COLUMN_TYPES");
        require(value.path("concurrency").asInt() == 1 || value.path("concurrency").asInt() == 8, "CONCURRENCY");
        require(value.path("warmup_seconds").asInt() >= 1 && value.path("warmup_seconds").asInt() <= 7200
                && value.path("duration_seconds").asInt() >= 1 && value.path("duration_seconds").asInt() <= 604800,
                "WINDOW_BOUND");
        require(value.path("qualification").asText().equals("diagnostic")
                || (value.path("qualification").asText().equals("formal")
                    && value.path("warmup_seconds").asInt() >= 180 && value.path("duration_seconds").asInt() >= 600),
                "FORMAL_SHAPE");
        double rate = value.path("rate").asDouble();
        require(Double.isFinite(rate) && rate > 0 && rate <= 1000, "RATE");
        require(value.path("max_requests").asInt() >= 2 && value.path("max_requests").asInt() <= 25000,
                "ARRIVAL_BOUND");
        require(value.path("drain_seconds").asInt() >= 1 && value.path("drain_seconds").asInt() <= 3600,
                "DRAIN_BOUND");
        require(value.path("max_raw_ledger_bytes").asLong() >= 1048576
                && value.path("max_raw_ledger_bytes").asLong() <= 8589934592L, "ARCHIVE_BOUNDS");
    }

    private static long[] arrivals(JsonNode value, String phase) {
        validate(value);
        Random random = new Random(20260922);
        double elapsed = 0;
        long cutoff = value.path(phase.equals("warmup") ? "warmup_seconds" : "duration_seconds").asLong() * BILLION;
        List<Long> result = new ArrayList<>();
        while (true) {
            double uniform = random.nextDouble();
            if (uniform == 0) {
                continue;
            }
            elapsed += -StrictMath.log(uniform) * BILLION / value.path("rate").asDouble();
            if (elapsed >= cutoff) {
                break;
            }
            require(result.size() < value.path("max_requests").asInt(), "ARRIVAL_BOUND_EXCEEDED");
            result.add((long) elapsed);
        }
        require(!result.isEmpty(), "NO_ARRIVALS");
        return result.stream().mapToLong(Long::longValue).toArray();
    }

    private static String schedule(long[] offsets) {
        StringBuilder output = new StringBuilder("sequence\toffset_ns\n");
        for (int index = 0; index < offsets.length; index++) {
            output.append(index).append('\t').append(offsets[index]).append('\n');
        }
        return output.toString();
    }

    /** Independently checks every actual field; ID-indexed arrays bound unordered-result memory. */
    private static final class RowOracle {
        private static final int ROWS = 1_000_000;
        private final java.util.BitSet seen = new java.util.BitSet(ROWS);
        private final int[] groups = new int[ROWS];
        private final long[] values = new long[ROWS];
        private final byte[] payloads = new byte[ROWS * 32];
        private final MessageDigest md5;
        private long rows;
        RowOracle() throws Exception { md5 = MessageDigest.getInstance("MD5"); }
        void reset() { seen.clear(); rows = 0; }
        void accept(long id, int group, long value, String payload) throws Exception {
            require(id >= 0 && id < ROWS, "ID_RANGE");
            int index = (int) id;
            require(!seen.get(index), "DUPLICATE_ID");
            require(group == id % 1024 && value == id % 100000, "ACTUAL_NUMERIC_VALUE");
            String expected = HexFormat.of().formatHex(md5.digest(Long.toString(id).getBytes(StandardCharsets.US_ASCII)));
            require(expected.equals(payload), "ACTUAL_COMPLETE_PAYLOAD");
            byte[] actual = payload.getBytes(StandardCharsets.US_ASCII);
            require(actual.length == 32, "ACTUAL_PAYLOAD_LENGTH");
            seen.set(index); groups[index] = group; values[index] = value;
            System.arraycopy(actual, 0, payloads, index * 32, 32); rows++;
        }
        Map<String, Object> finish() throws Exception {
            require(rows == ROWS && seen.cardinality() == ROWS, "MISSING_ROWS");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long sumId = 0, sumGroup = 0, sumValue = 0;
            for (int index = 0; index < ROWS; index++) {
                require(seen.get(index), "MISSING_ID");
                digest.update((index + "," + groups[index] + "," + values[index] + ",").getBytes(StandardCharsets.US_ASCII));
                digest.update(payloads, index * 32, 32); digest.update((byte) '\n');
                sumId += index; sumGroup += groups[index]; sumValue += values[index];
            }
            String actual = HexFormat.of().formatHex(digest.digest());
            require(actual.equals(MODEL), "ACTUAL_SORTED_FOUR_COLUMN_DIGEST");
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("rows", rows); evidence.put("distinct_ids", seen.cardinality());
            evidence.put("min_id", 0); evidence.put("max_id", ROWS - 1);
            evidence.put("sum_id", sumId); evidence.put("sum_grp", sumGroup); evidence.put("sum_v", sumValue);
            evidence.put("sha256_sorted_actual_rows", actual); evidence.put("null_fields", 0);
            return evidence;
        }
    }

    private static final class Session implements AutoCloseable {
        private final org.mariadb.jdbc.Connection connection;
        private final org.mariadb.jdbc.client.Client client;
        private final java.net.Socket socket;
        private final long serverConnectionId;
        private final JsonNode profile;
        private final String sql;
        private final String sqlHash;
        private final int worker;
        private final RowOracle oracle = new RowOracle();
        private long calls;
        private volatile boolean poisoned;
        private volatile boolean aborted;
        private volatile boolean closed;
        private final Map<String, Object> initialization = new LinkedHashMap<>();

        Session(JsonNode configuration, int worker) throws Exception {
            this.worker = worker; profile = configuration.path("profile");
            Path privatePath = Path.of(configuration.path("private_query").path("path").asText());
            require(!Files.isSymbolicLink(privatePath) && Files.size(privatePath) <= 65536
                    && Files.getPosixFilePermissions(privatePath).equals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")),
                    "PRIVATE_INPUT_PERMISSIONS_OR_BOUND");
            byte[] privateBytes = Files.readAllBytes(privatePath);
            require(sha(privateBytes).equals(configuration.path("private_query").path("sha256").asText()), "PRIVATE_INPUT_CHANGED");
            JsonNode input = JSON.readTree(privateBytes);
            require(input.size() == 2 && input.path("source_kind").asText().equals(profile.path("source_kind").asText()), "PRIVATE_SOURCE_KIND");
            sql = input.path("sql").asText(); sqlHash = sha(sql.getBytes(StandardCharsets.UTF_8));
            require(sqlHash.equals(configuration.path("sql_sha256").asText()), "PRIVATE_SQL_CHANGED");
            String password = System.getenv(configuration.path("password_env").asText());
            require(password != null, "EXPLICIT_PASSWORD_ENV_REQUIRED");
            java.util.Properties properties = new java.util.Properties();
            properties.setProperty("user", configuration.path("user").asText());
            properties.setProperty("password", password);
            properties.setProperty("autoReconnect", "false");
            properties.setProperty("allowMultiQueries", "false");
            properties.setProperty("useServerPrepStmts", "false");
            properties.setProperty("cachePrepStmts", "false");
            properties.setProperty("useSsl", "false");
            properties.setProperty("connectTimeout", "10000");
            properties.setProperty("socketTimeout", "60000");
            java.util.logging.Logger.getLogger("org.mariadb.jdbc").setLevel(java.util.logging.Level.OFF);
            String url = "jdbc:mariadb://127.0.0.1:" + configuration.path("query_port").asInt() + "/license_perf";
            require(java.sql.DriverManager.getDriver(url).getClass().getName().equals("org.mariadb.jdbc.Driver"), "ACTUAL_JDBC_DRIVER");
            java.sql.Connection opened = java.sql.DriverManager.getConnection(url, properties);
            require(opened instanceof org.mariadb.jdbc.Connection, "ACTUAL_CONNECTION_CLASS");
            connection = (org.mariadb.jdbc.Connection) opened; client = connection.getClient();
            serverConnectionId = connection.getThreadId();
            socket = ownedSocket(connection);
            try {
                require(socket != null && socket.isConnected() && !socket.isClosed()
                        && socket.getInetAddress().isLoopbackAddress()
                        && socket.getPort() == configuration.path("query_port").asInt(), "ACTUAL_OWNED_SOCKET");
                connection.setAutoCommit(true);
                try (java.sql.Statement setup = connection.createStatement()) {
                    setup.setQueryTimeout(0); // FE query timeout and socket/dispatch budgets; no driver cancel connection.
                    for (String setting : List.of("SET enable_sql_cache=false", "SET enable_query_cache=false",
                            "SET enable_file_cache=false", "SET query_timeout=60", "SET batch_size=8192",
                            "SET exec_mem_limit=536870912")) { setup.execute(setting); }
                    try (java.sql.ResultSet result = setup.executeQuery("SELECT @@enable_sql_cache, @@enable_query_cache, "
                            + "@@enable_file_cache, @@query_timeout, @@batch_size, @@exec_mem_limit")) {
                        require(result.next(), "SESSION_SETTINGS_MISSING");
                        for (int column = 1; column <= 3; column++) {
                            String value = result.getString(column);
                            require("false".equalsIgnoreCase(value) || "0".equals(value), "CACHE_NOT_DISABLED");
                        }
                        require(result.getLong(4) == 60 && result.getInt(5) == 8192 && result.getLong(6) == 536870912
                                && !result.next(), "SESSION_SETTINGS_DIFFER");
                    }
                }
                initialization.put("worker", worker); initialization.put("session_id", worker);
                initialization.put("jdbc_connections_opened", 1); initialization.put("server_connection_id", serverConnectionId);
                initialization.put("driver_class", "org.mariadb.jdbc.Driver");
                initialization.put("driver_version", connection.getMetaData().getDriverVersion());
                initialization.put("connection_class", connection.getClass().getName());
                initialization.put("client_class", client.getClass().getName());
                initialization.put("socket_local_port", socket.getLocalPort());
                initialization.put("socket_remote_port", socket.getPort());
                initialization.put("cache_readback", Map.of("enable_sql_cache", false, "enable_query_cache", false,
                        "enable_file_cache", false, "query_timeout", 60, "batch_size", 8192, "exec_mem_limit", 536870912));
                initialization.put("opened_ns", System.nanoTime());
            } catch (Exception error) {
                abortOwned();
                try { connection.close(); } catch (Exception ignored) { }
                throw error;
            }
        }

        private static java.net.Socket ownedSocket(org.mariadb.jdbc.Connection connection) throws Exception {
            try {
                Object client = connection.getClient();
                require(client.getClass().getName().equals("org.mariadb.jdbc.client.impl.StandardClient"), "ACTUAL_CLIENT_CLASS");
                java.lang.reflect.Field field = client.getClass().getDeclaredField("socket");
                field.setAccessible(true);
                return (java.net.Socket) field.get(client);
            } catch (Exception failure) {
                connection.close(); // A newly opened idle connection; preserve ownership on ABI failure.
                throw failure;
            }
        }

        void abortOwned() {
            aborted = true; poisoned = true;
            // Driver abort may create a separate cancellation connection. Close only this owned socket.
            try { socket.close(); } catch (Exception ignored) { }
        }

        void read(Map<String, Object> result) throws Exception {
            result.put("session_id", worker); result.put("session_call", ++calls);
            result.put("server_connection_id", connection.getThreadId());
            result.put("sql_sha256", sqlHash); result.put("execute_calls", 0);
            result.put("connection_reused", connection.getClient() == client && connection.getThreadId() == serverConnectionId);
            result.put("socket_local_port", socket.getLocalPort()); result.put("socket_remote_port", socket.getPort());
            require(!poisoned && !connection.isClosed() && connection.getClient() == client
                    && connection.getThreadId() == serverConnectionId, "CONNECTION_CLOSED_OR_CHANGED");
            long deadline = (long) result.get("started_ns") + 120 * BILLION;
            result.put("dispatch_deadline_ns", deadline);
            java.util.concurrent.ScheduledFuture<?> timeout = TIMERS.schedule(this::abortOwned,
                    Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            oracle.reset();
            java.sql.Statement statement = null;
            java.sql.ResultSet rows = null;
            boolean success = false;
            try {
                statement = connection.createStatement(java.sql.ResultSet.TYPE_FORWARD_ONLY, java.sql.ResultSet.CONCUR_READ_ONLY);
                statement.setFetchSize(1024); statement.setQueryTimeout(0); statement.setMaxRows(0);
                result.put("statement_class", statement.getClass().getName());
                result.put("fetch_size", statement.getFetchSize()); result.put("execute_calls", 1);
                result.put("driver_query_timeout_seconds", statement.getQueryTimeout());
                rows = statement.executeQuery(sql);
                require(rows.getClass().getName().equals("org.mariadb.jdbc.client.result.StreamingResult"), "ACTUAL_STREAMING_RESULT_REQUIRED");
                require(rows.getType() == java.sql.ResultSet.TYPE_FORWARD_ONLY && rows.getFetchSize() == 1024, "STREAMING_CONFIGURATION");
                java.sql.ResultSetMetaData metadata = rows.getMetaData();
                require(metadata.getColumnCount() == 4, "EXACT_FOUR_COLUMNS");
                List<String> labels = List.of("id", "grp", "v", "payload");
                List<Integer> types = new ArrayList<>();
                for (int column = 1; column <= 4; column++) {
                    require(metadata.getColumnLabel(column).equals(labels.get(column - 1)), "EXACT_COLUMN_LABEL");
                    int actual = metadata.getColumnType(column); types.add(actual);
                    require(actual == profile.path("column_types").get(column - 1).asInt(), "EXACT_COLUMN_TYPE");
                }
                result.put("column_labels", labels); result.put("column_types", types);
                result.put("result_class", rows.getClass().getName());
                result.put("streaming", ((org.mariadb.jdbc.client.result.StreamingResult) rows).streaming());
                require(Boolean.TRUE.equals(result.get("streaming")), "STREAMING_NOT_ACTIVE");
                while (rows.next()) {
                    long id = rows.getLong(1); require(!rows.wasNull(), "NULL_ID");
                    int group = rows.getInt(2); require(!rows.wasNull(), "NULL_GROUP");
                    long value = rows.getLong(3); require(!rows.wasNull(), "NULL_VALUE");
                    String payload = rows.getString(4); require(!rows.wasNull(), "NULL_PAYLOAD");
                    oracle.accept(id, group, value, payload);
                    if ((oracle.rows & 1023) == 0) { require(System.nanoTime() < deadline && !aborted, "DISPATCH_DEADLINE"); }
                }
                result.put("complete_unordered_set", oracle.finish());
                rows.close(); require(rows.isClosed(), "RESULT_CLOSE_NOT_CONFIRMED"); rows = null;
                statement.close(); require(statement.isClosed(), "STATEMENT_CLOSE_NOT_CONFIRMED"); statement = null;
                require(System.nanoTime() < deadline && !aborted && connection.getClient() == client
                        && connection.getThreadId() == serverConnectionId, "DISPATCH_DEADLINE_OR_CONNECTION_CHANGED");
                result.put("result_closed", true); result.put("statement_closed", true);
                result.put("rows_verified", oracle.rows); result.put("status", "READ_PASS"); success = true;
            } finally {
                if (!success) { abortOwned(); }
                if (rows != null) { try { rows.close(); } catch (Exception ignored) { } }
                if (statement != null) { try { statement.close(); } catch (Exception ignored) { } }
                timeout.cancel(false);
                result.put("rows_observed", oracle.rows);
                result.put("dispatch_deadline_exceeded", System.nanoTime() >= deadline);
                result.put("connection_aborted", aborted);
            }
        }

        public void close() throws Exception {
            java.util.concurrent.ScheduledFuture<?> timeout = TIMERS.schedule(this::abortOwned, 5, TimeUnit.SECONDS);
            long deadline = System.nanoTime() + 5 * BILLION;
            try {
                connection.close();
                require(connection.isClosed() && client.isClosed() && socket.isClosed()
                        && System.nanoTime() < deadline, "CONNECTION_CLOSE_TIMEOUT");
                closed = true;
            } finally { timeout.cancel(false); }
        }
    }

    private LicenseExternalReadPerformance(Path path) throws Exception {
        config = JSON.readTree(path.toFile());
        profile = config.path("profile");
        validate(profile);
        directory = path.toRealPath().getParent();
        launch = JSON.readTree(Path.of(config.path("launch").path("path").asText()).toFile());
        launchHash = sha(Files.readAllBytes(Path.of(config.path("launch").path("path").asText())));
        require(launchHash.equals(config.path("launch").path("sha256").asText()), "LAUNCH_CHANGED");
        require(Files.readString(Path.of("/proc/sys/kernel/random/boot_id")).trim()
                .equals(launch.path("boot_id").asText()), "BOOT_CHANGED");
        startTicks = ticks(pid);
        namespace = Files.readSymbolicLink(Path.of("/proc/self/ns/net")).toString();
        require(namespace.equals(config.path("namespace").asText()), "NETWORK_NAMESPACE_CHANGED");
        require(config.path("clock_ticks_per_second").asInt() > 0, "MISSING_CLOCK_TICKS");
        for (String portName : List.of("query_port")) {
            int port = config.path(portName).asInt();
            require(port > 0 && port < 65536, "INVALID_OWNED_PORT");
        }
        require(!namespace.equals(config.path("host_namespace").asText()), "PRIVATE_NAMESPACE_REQUIRED");
    }

    private Map<String, Object> identity() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("launch_token", launch.path("launch_token").asText());
        value.put("launch_sha256", launchHash);
        value.put("boot_id", launch.path("boot_id").asText());
        value.put("helper_pid", pid);
        value.put("helper_start_ticks", startTicks);
        value.put("namespace", namespace);
        return value;
    }

    private void publish(String name, Object value) throws Exception {
        Path target = directory.resolve(name);
        require(!Files.exists(target), "RECEIPT_ALREADY_EXISTS");
        Path temporary = directory.resolve(name + ".tmp");
        JSON.writerWithDefaultPrettyPrinter().writeValue(temporary.toFile(), value);
        Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
    }

    private JsonNode await(String name, long deadline) throws Exception {
        Path path = directory.resolve(name);
        while (!Files.exists(path)) {
            require(System.nanoTime() < deadline, "HANDSHAKE_TIMEOUT");
            Thread.sleep(2);
        }
        JsonNode value = JSON.readTree(path.toFile());
        require(value.path("launch_token").asText().equals(launch.path("launch_token").asText())
                && value.path("launch_sha256").asText().equals(launchHash), "HANDSHAKE_LAUNCH_CHANGED");
        require(sha(Files.readAllBytes(Path.of(config.path("launch").path("path").asText()))).equals(launchHash),
                "LAUNCH_CHANGED_DURING_HANDSHAKE");
        return value;
    }

    private void handshake() throws Exception {
        String readyNonce = UUID.randomUUID().toString();
        Map<String, Object> ready = identity();
        ready.put("ready_nonce", readyNonce);
        ready.put("connections", sessions.size());
        publish("p4-clock-ready.json", ready);
        long deadline = System.nanoTime() + config.path("coordination_seconds").asLong() * BILLION;
        JsonNode request = await("clock-request.json", deadline);
        require(request.path("ready_nonce").asText().equals(readyNonce)
                && request.path("nonce").asText().length() >= 16, "HANDSHAKE_NONCE");
        Map<String, Object> clock = identity();
        clock.put("schema_version", 1);
        clock.put("nonce", request.path("nonce").asText());
        clock.put("jvm_sample_ns", System.nanoTime());
        publish("p4-helper-clock.json", clock);
        JsonNode ack = await("clock-ack.json", deadline);
        require(ack.path("nonce").asText().equals(request.path("nonce").asText())
                && ack.path("helper_clock_sha256").asText().equals(sha(Files.readAllBytes(directory.resolve("p4-helper-clock.json"))))
                && ack.path("bridge_sha256").asText().equals(sha(Files.readAllBytes(directory.resolve("p4-clock-bridge.json"))))
                && System.nanoTime() < deadline, "CLOCK_ACK_INVALID_OR_EXPIRED");
    }

    private Map<String, Object> cpu() throws Exception {
        Map<String, Object> values = new LinkedHashMap<>();
        for (String role : List.of("fe", "be")) {
            JsonNode pin = config.path("services").path(role);
            long process = pin.path("pid").asLong();
            long before = System.nanoTime();
            Path proc = Path.of("/proc", Long.toString(process));
            String raw = Files.readString(proc.resolve("stat"));
            long after = System.nanoTime();
            String[] fields = raw.substring(raw.lastIndexOf(')') + 1).trim().split("\\s+");
            require(!fields[0].equals("Z") && Long.parseLong(fields[19]) == pin.path("start_ticks").asLong()
                    && Files.readSymbolicLink(proc.resolve("ns/net")).toString().equals(namespace)
                    && Files.readSymbolicLink(proc.resolve("exe")).toString().equals(pin.path("exe").asText())
                    && sha(Files.readAllBytes(proc.resolve("cmdline"))).equals(pin.path("command_sha256").asText()),
                    "SERVICE_LIFETIME_CHANGED");
            Map<String, Object> value = new LinkedHashMap<>();
            value.put("pid", process);
            value.put("start_ticks", Long.parseLong(fields[19]));
            value.put("raw_stat", raw);
            value.put("sample_started_java_ns", before);
            value.put("sample_ended_java_ns", after);
            values.put(role, value);
        }
        return values;
    }

    private static void until(long deadline) throws InterruptedException {
        while (System.nanoTime() < deadline) {
            if (Thread.interrupted()) {
                throw new InterruptedException("WORKER_INTERRUPTED");
            }
            LockSupport.parkNanos(Math.min(10_000_000L, deadline - System.nanoTime()));
        }
    }

    private static boolean timeout(Throwable error, int depth) {
        if (error == null || depth > 8) {
            return false;
        }
        if (error instanceof java.net.SocketTimeoutException || error instanceof java.sql.SQLTimeoutException || error instanceof java.util.concurrent.TimeoutException
                || error instanceof IllegalStateException && error.getMessage() != null
                && (error.getMessage().contains("TIMEOUT") || error.getMessage().contains("DEADLINE"))) {
            return true;
        }
        for (Throwable suppressed : error.getSuppressed()) {
            if (timeout(suppressed, depth + 1)) {
                return true;
            }
        }
        return timeout(error.getCause(), depth + 1);
    }

    private Map<String, Object> phase(String phase) throws Exception {
        long[] offsets = arrivals(profile, phase);
        Files.writeString(directory.resolve(phase + "-arrivals.tsv"), schedule(offsets));
        Map<String, Object> initial = identity();
        initial.put("cpu", cpu());
        long epoch = System.nanoTime() + 20_000_000L;
        long seconds = profile.path(phase.equals("warmup") ? "warmup_seconds" : "duration_seconds").asLong();
        long cutoff = epoch + seconds * BILLION;
        long drain = cutoff + profile.path("drain_seconds").asLong() * BILLION;
        initial.put("epoch_ns", epoch);
        publish(phase + "-start.json", initial);
        AtomicLong last = new AtomicLong(epoch);
        AtomicLong success = new AtomicLong();
        CountDownLatch finished = new CountDownLatch(sessions.size());
        for (int index = 0; index < sessions.size(); index++) {
            final int worker = index;
            Thread thread = new Thread(() -> {
                try (BufferedWriter output = Files.newBufferedWriter(directory.resolve(phase + "-" + worker + ".jsonl"))) {
                    for (int sequence = worker; sequence < offsets.length; sequence += sessions.size()) {
                        long scheduled = epoch + offsets[sequence];
                        until(scheduled);
                        long started = System.nanoTime();
                        Map<String, Object> receipt = new LinkedHashMap<>();
                        receipt.put("sequence", sequence);
                        receipt.put("worker", worker);
                        receipt.put("scheduled_ns", scheduled);
                        receipt.put("started_ns", started);
                        receipt.put("status", "NOT_SENT");
                        try {
                            require(!cancelled && started <= drain, "DRAIN_EXHAUSTED_NOT_SENT");
                            sessions.get(worker).read(receipt);
                            require("READ_PASS".equals(receipt.get("status")), "READ_NOT_VERIFIED");
                            success.incrementAndGet();
                        } catch (Exception error) {
                            failures.incrementAndGet();
                            receipt.put("status", "ERROR");
                            receipt.put("error_class", error.getClass().getName());
                            receipt.put("timeout", timeout(error, 0)
                                    || Boolean.TRUE.equals(receipt.get("dispatch_deadline_exceeded")));
                            if (error instanceof java.sql.SQLException) {
                                receipt.put("sql_state", ((java.sql.SQLException) error).getSQLState());
                                receipt.put("vendor_error_code", ((java.sql.SQLException) error).getErrorCode());
                            }
                            receipt.put("error_code", started > drain ? "NOT_SENT_DRAIN_EXHAUSTED" : "READ_OR_ORACLE_OR_CLOSE_FAILURE");
                        } finally {
                            long end = System.nanoTime();
                            receipt.put("finished_ns", end);
                            receipt.put("e2e_ns", end - scheduled);
                            receipt.put("service_ns", end - started);
                            receipt.put("queue_ns", started - scheduled);
                            last.accumulateAndGet(end, Math::max);
                            String encoded = JSON.writeValueAsString(receipt);
                            require(rawBytes.addAndGet(encoded.getBytes(StandardCharsets.UTF_8).length + 1)
                                    <= profile.path("max_raw_ledger_bytes").asLong(), "RAW_LEDGER_BOUND");
                            output.write(encoded);
                            output.newLine();
                        }
                    }
                } catch (Exception error) {
                    failures.incrementAndGet();
                    try {
                        publish(phase + "-" + worker + "-failure.json", Map.of("error_class", error.getClass().getName()));
                    } catch (Exception ignored) {
                        // A missing receipt is independently rejected, never upgraded to success.
                    }
                } finally {
                    finished.countDown();
                }
            }, "external-read-worker-" + worker);
            workers.add(thread);
            thread.start();
        }
        require(finished.await(seconds + profile.path("drain_seconds").asLong() + 190, TimeUnit.SECONDS), "PHASE_TIMEOUT");
        for (Thread thread : workers) {
            thread.join();
        }
        workers.clear();
        until(cutoff);
        Map<String, Object> end = identity();
        end.put("cpu", cpu());
        end.put("epoch_ns", epoch);
        end.put("last_request_end_ns", last.get());
        end.put("request_interval_end_ns", Math.max(cutoff, last.get()));
        end.put("java_monotonic_ns", System.nanoTime());
        end.put("scheduled_requests", offsets.length);
        end.put("successful_requests", success.get());
        end.put("arrival_schedule_sha256", sha(Files.readAllBytes(directory.resolve(phase + "-arrivals.tsv"))));
        publish(phase + "-end.json", end);
        return end;
    }

    private void run() throws Exception {
        Map<String, Object> summary = identity();
        summary.put("status", "INVALID_WINDOW");
        summary.put("formal_performance_pass", false);
        summary.put("harness_retries", 0);
        boolean closed = true;
        Thread shutdown = new Thread(() -> {
            cancelled = true;
            List<Thread> cleanupThreads = new ArrayList<>();
            for (Session session : sessions) {
                Thread cleanupThread = new Thread(session::abortOwned, "external-read-shutdown-owned-connection");
                cleanupThread.setDaemon(true);
                cleanupThreads.add(cleanupThread);
                cleanupThread.start();
            }
            long deadline = System.nanoTime() + 6 * BILLION;
            for (Thread cleanupThread : cleanupThreads) {
                try {
                    cleanupThread.join(Math.max(1, TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())));
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }
        }, "external-read-owned-cleanup");
        Runtime.getRuntime().addShutdownHook(shutdown);
        try {
            for (int worker = 0; worker < profile.path("concurrency").asInt(); worker++) {
                sessions.add(new Session(config, worker));
                publish("session-" + worker + "-open.json", sessions.get(worker).initialization);
            }
            handshake();
            Map<String, Object> warm = phase("warmup");
            Map<String, Object> ready = identity();
            ready.put("warmup_start_ns", warm.get("epoch_ns"));
            ready.put("warmup_end_ns", warm.get("java_monotonic_ns"));
            ready.put("ready_ns", System.nanoTime());
            publish("measurement-ready.json", ready);
            phase("measurement");
            require(failures.get() == 0, "REQUEST_FAILURES_RETAINED");
            summary.put("status", "RAW_WINDOW_COMPLETE");
        } catch (Exception error) {
            summary.put("error_class", error.getClass().getName());
            throw error;
        } finally {
            cancelled = true;
            for (Thread worker : workers) {
                worker.interrupt();
            }
            // Never close a channel while its worker still reads it; outer owner kills/waits on a stuck helper.
            for (Thread worker : workers) {
                worker.join(1000);
                closed &= !worker.isAlive();
            }
            for (int worker = 0; worker < sessions.size(); worker++) {
                Map<String, Object> receipt = new LinkedHashMap<>();
                receipt.put("worker", worker);
                receipt.put("close_started_ns", System.nanoTime());
                try {
                    require(workers.stream().noneMatch(Thread::isAlive), "LIVE_WORKER_BEFORE_CLOSE");
                    sessions.get(worker).close();
                    receipt.put("jdbc_connections_closed", 1);
                    receipt.put("jdbc_connection_closed", true);
                } catch (Exception error) {
                    closed = false;
                    receipt.put("jdbc_connection_closed", false);
                    receipt.put("error_class", error.getClass().getName());
                } finally {
                    receipt.put("close_finished_ns", System.nanoTime());
                    receipt.put("connection_aborted", sessions.get(worker).aborted);
                    try {
                        publish("session-" + worker + "-close.json", receipt);
                    } catch (Exception evidenceError) {
                        closed = false;
                        // Continue closing every remaining owned session even if one receipt cannot be written.
                    }
                }
            }
            Map<String, Object> cleanup = identity();
            cleanup.put("cleanup_end_ns", System.nanoTime());
            cleanup.put("sessions_closed", closed && sessions.size() == profile.path("concurrency").asInt());
            cleanup.put("workers_stopped", workers.stream().noneMatch(Thread::isAlive));
            publish("lifecycle.json", cleanup);
            summary.put("errors", failures.get());
            summary.put("cleanup_confirmed", cleanup.get("sessions_closed"));
            if (!closed) {
                summary.put("status", "INVALID_WINDOW");
            }
            publish("summary.json", summary);
            Runtime.getRuntime().removeShutdownHook(shutdown);
        }
    }

    private static void entry(String[] args) throws Exception {
        if (args.length == 2 && args[0].equals("--self-test")) {
            long process = ProcessHandle.current().pid();
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("helper_pid", process); evidence.put("helper_start_ticks", ticks(process));
            evidence.put("java_monotonic_ns", System.nanoTime()); evidence.put("jdk_version", System.getProperty("java.version"));
            evidence.put("network_connections_opened", 0); evidence.put("formal_performance_pass", false);
            require(org.mariadb.jdbc.client.impl.StandardClient.class.getDeclaredField("socket").getType()
                    == java.net.Socket.class, "EXACT_DRIVER_SOCKET_ABI");
            java.net.Socket unopened = new java.net.Socket();
            java.util.concurrent.ScheduledFuture<?> expired = TIMERS.schedule(() -> {
                try { unopened.close(); } catch (Exception ignored) { }
            }, 1, TimeUnit.MILLISECONDS);
            expired.get(1, TimeUnit.SECONDS);
            require(unopened.isClosed(), "OWNED_SOCKET_WATCHDOG");
            evidence.put("driver_socket_abi_verified", true); evidence.put("unopened_socket_deadline_verified", true);
            RowOracle oracle = new RowOracle();
            List<String> checks = new ArrayList<>();
            for (String mode : List.of("missing", "duplicate", "group", "value", "payload", "range")) {
                oracle.reset(); boolean rejected = false;
                try {
                    if (mode.equals("missing")) { oracle.finish(); }
                    else if (mode.equals("range")) { oracle.accept(1000000, 0, 0, ""); }
                    else {
                        oracle.accept(0, mode.equals("group") ? 1 : 0, mode.equals("value") ? 1 : 0,
                                mode.equals("payload") ? "00000000000000000000000000000000" : "cfcd208495d565ef66e7dff9f98764da");
                        if (mode.equals("duplicate")) { oracle.accept(0, 0, 0, "cfcd208495d565ef66e7dff9f98764da"); }
                    }
                } catch (IllegalStateException expected) { rejected = true; }
                require(rejected, "ORACLE_COUNTEREXAMPLE_ACCEPTED"); checks.add(mode);
            }
            oracle.reset(); MessageDigest md5 = MessageDigest.getInstance("MD5");
            for (int id = 999999; id >= 0; id--) {
                oracle.accept(id, id % 1024, id % 100000,
                        HexFormat.of().formatHex(md5.digest(Integer.toString(id).getBytes(StandardCharsets.US_ASCII))));
            }
            evidence.put("complete_reverse_model", oracle.finish()); checks.add("complete_reverse_model");
            oracle.payloads[0] ^= 1; boolean rejected = false;
            try { oracle.finish(); } catch (IllegalStateException expected) { rejected = true; }
            require(rejected, "ACTUAL_STORED_PAYLOAD_CORRUPTION_ACCEPTED"); checks.add("stored_payload_tamper");
            evidence.put("oracle_checks", checks);
            JSON.writerWithDefaultPrettyPrinter().writeValue(Path.of(args[1]).toFile(), evidence);
            return;
        }
        if (args.length == 3 && args[0].equals("--plan")) {
            JsonNode value = JSON.readTree(Path.of(args[1]).toFile());
            Path output = Path.of(args[2]);
            Files.createDirectory(output);
            for (String phase : List.of("warmup", "measurement")) {
                Files.writeString(output.resolve(phase + "-arrivals.tsv"), schedule(arrivals(value, phase)));
            }
            Files.writeString(output.resolve("plan.json"), "{\"network_clients_created\":0,\"formal_performance_pass\":false}\n");
            return;
        }
        require(args.length == 1, "USAGE_CONFIG_OR_PLAN");
        new LicenseExternalReadPerformance(Path.of(args[0])).run();
    }

    public static void main(String[] args) {
        try {
            entry(args);
        } catch (Throwable error) {
            // JDBC exceptions can contain full SQL and S3 credentials. Never print exception messages or stacks.
            System.err.println("{\"status\":\"INVALID_WINDOW\",\"error_class\":\"" + error.getClass().getName() + "\"}");
            System.exit(2);
        }
    }
}
