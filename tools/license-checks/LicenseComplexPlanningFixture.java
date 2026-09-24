// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;

/** Original FE functional adapter; fixed SQL, one JVM clock, no performance acceptance claim. */
public final class LicenseComplexPlanningFixture {
    static final ObjectMapper JSON = new ObjectMapper();
    static final Path RECORDS = Path.of("/data/project/massdb-sql/.build-records");
    static final String VIEW = "license_perf.license_complex_view";
    static final String QUERY_SHA = "df4655191fb71a17d4a7c19baa84f7cf4cd350ea9ab44418baef885a9c545a37";
    static final String CREATE = "CREATE VIEW " + VIEW
            + " AS SELECT id, grp, v, payload FROM license_perf.point_rows";
    static final String EVENT = "ALTER VIEW " + VIEW
            + " AS SELECT id, grp, v + 1 AS v, payload FROM license_perf.point_rows";
    static final String RESET = "ALTER VIEW " + VIEW
            + " AS SELECT id, grp, v, payload FROM license_perf.point_rows";
    static final String SHOW_CREATE = "SHOW CREATE VIEW " + VIEW;
    static final String LAST_ID = "SELECT last_query_id()";
    static final int MAX_REQUESTS = 20000;
    static final long MAX_LOG_BYTES = 128L * 1024 * 1024;
    static final long EVENT_OFFSET_NS = TimeUnit.SECONDS.toNanos(180);

    private LicenseComplexPlanningFixture() {
    }

    static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }

    static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    static Path directory(String text) throws IOException {
        Path path = Path.of(text);
        require(path.isAbsolute() && path.equals(path.normalize()) && path.startsWith(RECORDS)
                && !path.equals(RECORDS) && path.equals(path.toRealPath()) && Files.isDirectory(path),
                "OWNED_CANONICAL_DIRECTORY_REQUIRED");
        return path;
    }

    static Path owned(Path directory, String text, boolean exists) throws IOException {
        Path path = Path.of(text);
        require(path.isAbsolute() && path.equals(path.normalize()) && path.startsWith(directory)
                && !path.equals(directory) && path.getParent().equals(path.getParent().toRealPath()),
                "PATH_OUTSIDE_OWNED_DIRECTORY");
        if (exists) {
            require(path.equals(path.toRealPath()) && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS),
                    "CANONICAL_REGULAR_INPUT_REQUIRED");
        } else {
            require(!Files.exists(path, LinkOption.NOFOLLOW_LINKS), "OUTPUT_ALREADY_EXISTS");
        }
        return path;
    }

    static byte[] read(Path path, int maximum) throws IOException {
        require(Files.size(path) <= maximum, "INPUT_SIZE_BOUND");
        try (InputStream input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            byte[] bytes = input.readNBytes(maximum + 1);
            require(bytes.length <= maximum, "INPUT_SIZE_BOUND");
            return bytes;
        }
    }

    static void writeNew(Path path, Object value) throws IOException {
        Files.writeString(path, JSON.writerWithDefaultPrettyPrinter().writeValueAsString(value) + "\n",
                StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    static Map<String, Object> snapshot(Map<String, Object> value) {
        synchronized (value) {
            return new LinkedHashMap<>(value);
        }
    }

    static int integer(JsonNode node, String name, int minimum, int maximum) {
        JsonNode value = node.path(name);
        require(value.isIntegralNumber() && value.canConvertToInt()
                && value.asInt() >= minimum && value.asInt() <= maximum, "INVALID_" + name);
        return value.asInt();
    }

    static long[] offsets(JsonNode array, int seconds) {
        require(array.isArray() && array.size() <= MAX_REQUESTS, "INVALID_ARRIVAL_ARRAY");
        long[] result = new long[array.size()];
        long previous = -1;
        for (int index = 0; index < result.length; index++) {
            JsonNode value = array.get(index);
            require(value.isIntegralNumber() && value.canConvertToLong(), "NONINTEGER_ARRIVAL");
            long offset = value.asLong();
            require(offset >= 0 && offset > previous && offset < TimeUnit.SECONDS.toNanos(seconds),
                    "ARRIVAL_ORDER_OR_WINDOW_BOUND");
            result[index] = offset;
            previous = offset;
        }
        return result;
    }

    static void validateDefinition(JsonNode definition) throws Exception {
        require(definition.path("query_sha256_utf8").asText().equals(QUERY_SHA)
                && sha(definition.path("query_sql").asText().getBytes(StandardCharsets.UTF_8)).equals(QUERY_SHA)
                && definition.path("event_offset_seconds").asInt() == 180, "FROZEN_SQL_IDENTITY_CHANGED");
        require(definition.path("columns").size() == 33, "FROZEN_COLUMNS_CHANGED");
        for (int index = 0; index < 33; index++) {
            String name = index == 0 ? "matched_rows" : String.format(java.util.Locale.ROOT, "sum_expr_%02d", index);
            require(definition.path("columns").get(index).asText().equals(name), "FROZEN_COLUMN_ORDER_CHANGED");
        }
    }

    static String netNamespace(long pid) throws IOException {
        return Files.readSymbolicLink(Path.of("/proc", Long.toString(pid), "ns/net")).toString();
    }

    static long startTicks(long pid) throws IOException {
        String stat = Files.readString(Path.of("/proc", Long.toString(pid), "stat"));
        return Long.parseLong(stat.substring(stat.lastIndexOf(')') + 2).split(" +")[19]);
    }

    static final class Config {
        final JsonNode raw;
        final JsonNode definition;
        final Path output;
        final Path stopFile;
        final String query;
        final String readerPassword;
        final String adminPassword;
        final String caseId;
        final String mode;
        final String connectionMode;
        final String namespace;
        final String initialViewSha;
        final String clockDomain;
        final String definitionSha;
        final String arrivalSha;
        final String ownerSha;
        final long[] warmup;
        final long[] measured;
        final int warmupSeconds;
        final int windowSeconds;
        final int concurrency;
        final int timeout;
        final int drain;
        final int cleanup;
        final int sampleEvery;
        final int overlapLimit;
        final int port;

        Config(Path file) throws Exception {
            Path configDirectory = directory(file.getParent().toString());
            owned(configDirectory, file.toString(), true);
            raw = JSON.readTree(read(file, 65536));
            output = directory(raw.path("output_directory").asText());
            require(output.equals(configDirectory), "CONFIG_OUTPUT_OWNER_MISMATCH");
            stopFile = owned(output, raw.path("stop_file").asText(), false);
            caseId = raw.path("case_id").asText();
            mode = raw.path("mode").asText();
            connectionMode = raw.path("connection_mode").asText();
            require(Set.of("LP-006", "LP-007").contains(caseId)
                    && Set.of("text", "prepared").contains(mode)
                    && Set.of("reuse", "per_request").contains(connectionMode), "INVALID_MODE");
            concurrency = integer(raw, "concurrency", 1, 32);
            require(Set.of(1, 8, 32).contains(concurrency), "INVALID_CONCURRENCY");
            timeout = integer(raw, "timeout_seconds", 1, 30);
            drain = integer(raw, "drain_seconds", 1, 120);
            cleanup = integer(raw, "cleanup_seconds", 1, 60);
            sampleEvery = integer(raw, "profile_every_n", 1, MAX_REQUESTS);
            overlapLimit = integer(raw, "profile_overlap_limit", 64, 64);
            port = integer(raw, "query_port", 1, 65535);
            int limit = integer(raw, "request_limit", 1, MAX_REQUESTS);
            definition = pinnedJson("definition_file", "definition_sha256", 65536);
            validateDefinition(definition);
            definitionSha = raw.path("definition_sha256").asText();
            query = definition.path("query_sql").asText();
            JsonNode schedule = pinnedJson("arrival_file", "arrival_sha256", 1024 * 1024);
            arrivalSha = raw.path("arrival_sha256").asText();
            require(schedule.path("schema_version").asInt() == 1 && schedule.path("seed").asInt() == 20260922
                    && schedule.path("rate_per_second").isNumber()
                    && Double.isFinite(schedule.path("rate_per_second").asDouble())
                    && schedule.path("rate_per_second").asDouble() > 0, "INVALID_FROZEN_SCHEDULE");
            warmupSeconds = integer(schedule, "warmup_seconds", 0, 180);
            windowSeconds = integer(schedule, "window_seconds", 240, 600);
            warmup = offsets(schedule.path("warmup_offsets_ns"), warmupSeconds);
            measured = offsets(schedule.path("measurement_offsets_ns"), windowSeconds);
            require(measured.length > 0 && warmup.length + measured.length <= limit, "REQUEST_COUNT_BOUND");
            if (caseId.equals("LP-007")) {
                require(measured[0] < EVENT_OFFSET_NS && measured[measured.length - 1] > EVENT_OFFSET_NS,
                        "MISSING_SCHEDULED_BEFORE_AFTER_EVENT_READS");
            }
            namespace = raw.path("namespace").asText();
            initialViewSha = raw.path("expected_initial_show_create_view_sha256").asText();
            require(initialViewSha.matches("[0-9a-f]{64}")
                    && raw.path("view_owner_token").asText().matches("[0-9a-f]{32}"), "MISSING_VIEW_OWNER_IDENTITY");
            JsonNode owner = pinnedJson("owner_record_file", "controller_owner_record_sha256", 65536);
            ownerSha = raw.path("controller_owner_record_sha256").asText();
            require(owner.path("schema_version").asInt() == 1 && owner.path("view").asText().equals(VIEW)
                    && owner.path("create_success").isBoolean() && owner.path("create_success").asBoolean()
                    && owner.path("view_owner_token").asText().equals(raw.path("view_owner_token").asText())
                    && owner.path("namespace").asText().equals(namespace)
                    && owner.path("cluster_record_sha256").asText().matches("[0-9a-f]{64}")
                    && owner.path("initial_show_create_view_sha256").asText().equals(initialViewSha)
                    && owner.path("create_sql").asText().equals(CREATE), "VIEW_OWNER_RECORD_MISMATCH");
            readerPassword = password("reader_password_env");
            adminPassword = password("admin_password_env");
            require(!raw.path("reader_user").asText().isEmpty() && !raw.path("admin_user").asText().isEmpty(),
                    "MISSING_EXPLICIT_ACCOUNTS");
            require(Runtime.getRuntime().maxMemory() <= 512L * 1024 * 1024, "EXPLICIT_HEAP_AT_MOST_512_MIB_REQUIRED");
            guard();
            clockDomain = ProcessHandle.current().pid() + ":" + startTicks(ProcessHandle.current().pid())
                    + ":" + UUID.randomUUID();
            for (String name : List.of("identity.json", "ready.json", "measurement-start.json", "preflight.json",
                    "request-starts.jsonl", "requests.jsonl", "event.json", "cleanup.json", "summary.json")) {
                owned(output, output.resolve(name).toString(), false);
                require(!output.resolve(name).equals(stopFile), "STOP_FILE_ALIASES_OUTPUT");
            }
        }

        private String password(String field) {
            String name = raw.path(field).asText();
            require(name.matches("[A-Za-z_][A-Za-z0-9_]*") && System.getenv().containsKey(name),
                    "PASSWORD_ENV_MUST_EXPLICITLY_EXIST");
            return System.getenv(name);
        }

        private JsonNode pinnedJson(String fileKey, String shaKey, int bound) throws Exception {
            Path path = owned(output, raw.path(fileKey).asText(), true);
            byte[] bytes = read(path, bound);
            require(sha(bytes).equals(raw.path(shaKey).asText()), "PINNED_INPUT_DIGEST_MISMATCH_" + fileKey);
            return JSON.readTree(bytes);
        }

        void guard() throws Exception {
            require(namespace.matches("net:\\[[0-9]+\\]")
                    && raw.path("host_namespace").asText().matches("net:\\[[0-9]+\\]")
                    && namespace.equals(netNamespace(ProcessHandle.current().pid()))
                    && !namespace.equals(raw.path("host_namespace").asText()), "PRIVATE_NAMESPACE_CHANGED");
            JsonNode pins = raw.path("service_pins");
            require(pins.isArray() && pins.size() >= 3 && pins.size() <= 8, "SERVICE_PINS_REQUIRED");
            Set<Long> seen = new HashSet<>();
            for (JsonNode pin : pins) {
                long pid = pin.path("pid").asLong();
                require(pin.path("pid").isIntegralNumber() && pin.path("pid").canConvertToLong()
                        && pin.path("start_ticks").isIntegralNumber() && pin.path("start_ticks").canConvertToLong()
                        && pin.path("command_sha256").asText().matches("[0-9a-f]{64}")
                        && pid > 1 && seen.add(pid) && namespace.equals(pin.path("namespace").asText())
                        && namespace.equals(netNamespace(pid)) && startTicks(pid) == pin.path("start_ticks").asLong()
                        && Files.readSymbolicLink(Path.of("/proc", Long.toString(pid), "exe")).toString()
                        .equals(pin.path("exe").asText())
                        && sha(read(Path.of("/proc", Long.toString(pid), "cmdline"), 1024 * 1024))
                        .equals(pin.path("command_sha256").asText()), "SERVICE_IDENTITY_CHANGED");
            }
        }
    }

    static final class JsonLines implements AutoCloseable {
        private final BufferedWriter writer;
        private long bytes;
        private boolean closed;

        JsonLines(Path path) throws IOException {
            writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        }

        synchronized void append(Object value) throws IOException {
            String line = JSON.writeValueAsString(value) + "\n";
            int size = line.getBytes(StandardCharsets.UTF_8).length;
            require(!closed && size <= 16384 && bytes + size <= MAX_LOG_BYTES, "RECEIPT_LOG_BOUND");
            writer.write(line);
            writer.flush();
            bytes += size;
        }

        @Override
        public synchronized void close() throws IOException {
            closed = true;
            writer.close();
        }
    }

    static Map<String, Object> error(Throwable error) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("error_class", error.getClass().getSimpleName());
        if (error instanceof SQLException) {
            result.put("error_code", ((SQLException) error).getErrorCode());
            result.put("sql_state", ((SQLException) error).getSQLState());
        }
        // Exception messages can contain connection properties or credentials.
        return result;
    }

    static Map<String, Object> showCreate(Connection connection, int timeout) throws Exception {
        try (Statement statement = connection.createStatement()) {
            statement.setQueryTimeout(timeout);
            try (ResultSet rows = statement.executeQuery(SHOW_CREATE)) {
                require(rows.getMetaData().getColumnCount() >= 2 && rows.next(), "SHOW_CREATE_MISSING_ROW");
                String value = rows.getString(2);
                require(value != null && value.length() <= 65536 && !rows.next(), "SHOW_CREATE_SHAPE");
                return Map.of("sql", SHOW_CREATE, "create_view", value,
                        "sha256_utf8", sha(value.getBytes(StandardCharsets.UTF_8)), "observed_ns", System.nanoTime());
            }
        }
    }

    /** Target fetch and following last_query_id stay on one connection with no intervening SQL. */
    static void executeAndIdentify(Connection connection, Statement statement, String query,
            boolean prepared, int timeout, Map<String, Object> receipt) throws Exception {
        List<Map<String, String>> columns = new ArrayList<>();
        List<List<String>> values = new ArrayList<>();
        receipt.put("columns", columns);
        receipt.put("rows", values);
        receipt.put("started_ns", System.nanoTime());
        try {
            boolean result = prepared ? ((PreparedStatement) statement).execute() : statement.execute(query);
            require(result, "TARGET_DID_NOT_RETURN_ROWS");
            try (ResultSet rows = statement.getResultSet()) {
                ResultSetMetaData metadata = rows.getMetaData();
                require(metadata.getColumnCount() == 33, "TARGET_RESULT_WIDTH");
                for (int column = 1; column <= 33; column++) {
                    String name = metadata.getColumnLabel(column);
                    String type = metadata.getColumnTypeName(column);
                    require(name != null && type != null && name.length() <= 128 && type.length() <= 64,
                            "COLUMN_METADATA_BOUND");
                    columns.add(Map.of("name", name, "type", type));
                }
                while (rows.next()) {
                    require(values.size() < 2, "TARGET_ROW_BOUND");
                    List<String> row = new ArrayList<>();
                    for (int column = 1; column <= 33; column++) {
                        String value = rows.getString(column);
                        require(value == null || value.length() <= 128, "TARGET_VALUE_BOUND");
                        row.add(value);
                    }
                    values.add(row);
                }
            }
            require(values.size() == 1, "TARGET_ROW_COUNT");
            receipt.put("sql_success", true);
        } finally {
            receipt.put("finished_ns", System.nanoTime());
        }
        long begin = System.nanoTime();
        try (Statement identity = connection.createStatement()) {
            identity.setQueryTimeout(timeout);
            try (ResultSet rows = identity.executeQuery(LAST_ID)) {
                require(rows.getMetaData().getColumnCount() == 1 && rows.next(), "QUERY_ID_RESULT_SHAPE");
                String queryId = rows.getString(1);
                require(queryId != null && queryId.matches("[0-9a-f]{1,16}-[0-9a-f]{1,16}") && !rows.next(),
                        "TARGET_QUERY_ID_MISSING");
                receipt.put("query_id", queryId);
                receipt.put("query_id_sql", LAST_ID);
                receipt.put("query_id_same_connection", true);
            }
        } finally {
            receipt.put("query_id_lookup_ns", System.nanoTime() - begin);
        }
    }

    static ExecutorService pool(int count, String name) {
        AtomicInteger serial = new AtomicInteger();
        return Executors.newFixedThreadPool(count, runnable -> {
            Thread thread = new Thread(runnable, name + "-" + serial.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
    }

    static boolean awaitUntil(ExecutorService executor, long deadline) throws InterruptedException {
        long remaining = deadline - System.nanoTime();
        return executor.isTerminated() || remaining > 0 && executor.awaitTermination(remaining, TimeUnit.NANOSECONDS);
    }

    static boolean overlapsEvent(long started, long finished, Long eventStart, Long eventAcknowledged) {
        return eventStart != null && finished >= eventStart
                && (eventAcknowledged == null || started <= eventAcknowledged);
    }

    static final class Runner {
        final Config config;
        final AtomicBoolean cancelled = new AtomicBoolean();
        final AtomicBoolean finalized = new AtomicBoolean();
        final AtomicBoolean failed = new AtomicBoolean();
        final AtomicLong serial = new AtomicLong();
        final AtomicLong completed = new AtomicLong();
        final AtomicInteger postEventSamples = new AtomicInteger();
        final AtomicInteger eventOverlapRequests = new AtomicInteger();
        final AtomicInteger eventOverlapSamples = new AtomicInteger();
        final AtomicBoolean overlapCapViolation = new AtomicBoolean();
        final Set<Connection> connections = ConcurrentHashMap.newKeySet();
        final Set<Connection> abortSubmitted = ConcurrentHashMap.newKeySet();
        final Set<String> queryIds = ConcurrentHashMap.newKeySet();
        final ExecutorService workers;
        final ExecutorService administration = pool(1, "complex-event");
        final ExecutorService cleanupPool = pool(8, "complex-cleanup");
        final CountDownLatch ready;
        final CountDownLatch warmupDone;
        final CountDownLatch measuredDone;
        final CountDownLatch warmupGate = new CountDownLatch(1);
        final CountDownLatch measurementGate = new CountDownLatch(1);
        final CountDownLatch eventDone = new CountDownLatch(1);
        final Map<String, Object> event = Collections.synchronizedMap(new LinkedHashMap<>());
        final Map<String, Object> cleanup = Collections.synchronizedMap(new LinkedHashMap<>());
        final JsonLines starts;
        final JsonLines requests;
        volatile long warmupEpoch;
        volatile long epoch;
        volatile Long eventStarted;
        volatile Long eventAck;
        volatile boolean eventAttempted;
        volatile long phaseDeadline;
        volatile String failureReason = "none";
        volatile boolean eventCommitUnknown;
        Connection admin;

        Runner(Config config) throws IOException {
            this.config = config;
            workers = pool(config.concurrency, "complex-reader");
            ready = new CountDownLatch(config.concurrency);
            warmupDone = new CountDownLatch(config.concurrency);
            measuredDone = new CountDownLatch(config.concurrency);
            starts = new JsonLines(config.output.resolve("request-starts.jsonl"));
            requests = new JsonLines(config.output.resolve("requests.jsonl"));
            phaseDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        }

        void fail(String reason) {
            if (failed.compareAndSet(false, true)) {
                failureReason = reason;
            }
            cancelled.set(true);
        }

        void check() throws Exception {
            if (Files.exists(config.stopFile, LinkOption.NOFOLLOW_LINKS)) {
                fail("stop_file");
            }
            require(!cancelled.get() && System.nanoTime() < phaseDeadline, "CANCELLED_OR_PHASE_DEADLINE");
        }

        void waitUntil(long deadline) throws Exception {
            while (System.nanoTime() < deadline) {
                check();
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException();
                }
                LockSupport.parkNanos(Math.min(TimeUnit.MILLISECONDS.toNanos(50), deadline - System.nanoTime()));
            }
            check();
        }

        void await(CountDownLatch latch) throws Exception {
            while (!latch.await(100, TimeUnit.MILLISECONDS)) {
                check();
            }
            check();
        }

        Connection connect(boolean administrator, boolean forCleanup) throws Exception {
            config.guard();
            if (!forCleanup) {
                check();
            }
            Properties properties = new Properties();
            properties.setProperty("user", config.raw.path(administrator ? "admin_user" : "reader_user").asText());
            properties.setProperty("password", administrator ? config.adminPassword : config.readerPassword);
            properties.setProperty("useServerPrepStmts", "true");
            properties.setProperty("autoReconnect", "false");
            properties.setProperty("connectTimeout", "5000");
            properties.setProperty("socketTimeout", Long.toString(config.timeout * 1000L));
            Connection connection = DriverManager.getConnection("jdbc:mariadb://127.0.0.1:"
                    + config.port + "/license_perf", properties);
            connections.add(connection);
            if (!forCleanup && cancelled.get()) {
                close(connection);
                throw new InterruptedException("CANCELLED_WHILE_CONNECTING");
            }
            return connection;
        }

        void close(Connection connection) throws SQLException {
            if (connection != null) {
                try {
                    connection.close();
                } finally {
                    if (connection.isClosed()) {
                        connections.remove(connection);
                    }
                }
            }
        }

        void initialize(Connection connection) throws Exception {
            for (String sql : List.of("SET enable_sql_cache=" + config.caseId.equals("LP-007"),
                    "SET enable_query_cache=false", "SET enable_short_circuit_query=false",
                    "SET enable_profile=true")) {
                try (Statement statement = connection.createStatement()) {
                    statement.setQueryTimeout(config.timeout);
                    statement.execute(sql);
                }
            }
        }

        Statement prepare(Connection connection) throws SQLException {
            Statement statement = config.mode.equals("prepared")
                    ? connection.prepareStatement(config.query) : connection.createStatement();
            statement.setQueryTimeout(config.timeout);
            return statement;
        }

        void request(int worker, String phase, int index, long scheduled,
                Connection reused, Statement reusable) throws Exception {
            check();
            long phaseEnd = phase.equals("warmup")
                    ? warmupEpoch + TimeUnit.SECONDS.toNanos(config.warmupSeconds)
                    : epoch + TimeUnit.SECONDS.toNanos(config.windowSeconds);
            long requestStarted = System.nanoTime();
            require(requestStarted < phaseEnd, "HARD_WINDOW_CLOSED_BEFORE_REQUEST_START");
            long id = serial.incrementAndGet();
            Map<String, Object> receipt = new LinkedHashMap<>();
            receipt.put("schema_version", 1);
            receipt.put("clock_domain", config.clockDomain);
            receipt.put("request_id", id);
            receipt.put("worker", worker);
            receipt.put("phase", phase);
            receipt.put("arrival_index", index);
            receipt.put("scheduled_ns", scheduled);
            receipt.put("request_started_ns", requestStarted);
            receipt.put("utc", Instant.now().toString());
            receipt.put("query_sha256_utf8", QUERY_SHA);
            receipt.put("mode", config.mode);
            receipt.put("connection_mode", config.connectionMode);
            receipt.put("sql_success", false);
            receipt.put("success", false);
            receipt.put("query_id", null);
            receipt.put("started_ns", null);
            receipt.put("finished_ns", null);
            receipt.put("connection_ns", 0L);
            receipt.put("session_init_ns", 0L);
            receipt.put("prepare_ns", 0L);
            receipt.put("close_ns", 0L);
            receipt.put("explain_observer_ns", 0L);
            receipt.put("request_total_includes_query_id_and_explain_observers", true);
            starts.append(Map.of("request_id", id, "phase", phase, "arrival_index", index,
                    "scheduled_ns", scheduled, "request_started_ns", receipt.get("request_started_ns"),
                    "clock_domain", config.clockDomain, "query_sha256_utf8", QUERY_SHA,
                    "state", "intent_before_execute_not_execution_proof"));
            Connection connection = reused;
            Statement statement = reusable;
            int postAckOrdinal = 0;
            boolean explainSample = false;
            try {
                if (connection == null) {
                    long begin = System.nanoTime();
                    connection = connect(false, false);
                    receipt.put("connection_ns", System.nanoTime() - begin);
                    begin = System.nanoTime();
                    initialize(connection);
                    receipt.put("session_init_ns", System.nanoTime() - begin);
                    begin = System.nanoTime();
                    statement = prepare(connection);
                    receipt.put("prepare_ns", System.nanoTime() - begin);
                }
                check();
                executeAndIdentify(connection, statement, config.query, config.mode.equals("prepared"),
                        config.timeout, receipt);
                require(queryIds.add((String) receipt.get("query_id")), "DUPLICATE_OR_STALE_QUERY_ID");
                if (eventAck != null && (long) receipt.get("started_ns") > eventAck) {
                    postAckOrdinal = postEventSamples.incrementAndGet();
                }
                explainSample = config.caseId.equals("LP-007") && (index == 1 || postAckOrdinal == 2);
                if (explainSample) {
                    long begin = System.nanoTime();
                    try {
                        receipt.put("explain_file", explain(connection, id, (String) receipt.get("query_id"), phase));
                    } finally {
                        receipt.put("explain_observer_ns", System.nanoTime() - begin);
                    }
                }
                receipt.put("success", true);
            } catch (Exception error) {
                receipt.putAll(error(error));
                fail("read_or_query_identity_failure");
            } finally {
                if (reused == null) {
                    long begin = System.nanoTime();
                    try {
                        if (statement != null) {
                            statement.close();
                        }
                    } catch (SQLException error) {
                        receipt.put("statement_close_error", error(error));
                        receipt.put("success", false);
                        fail("statement_close_failure");
                    }
                    try {
                        close(connection);
                    } catch (SQLException error) {
                        receipt.put("connection_close_error", error(error));
                        receipt.put("success", false);
                        fail("connection_close_failure");
                    }
                    receipt.put("close_ns", System.nanoTime() - begin);
                }
                receipt.put("request_finished_ns", System.nanoTime());
                String reason = index == 0 ? "first_in_phase"
                        : index % config.sampleEvery == 0 ? "fixed_every_n" : "none";
                if (postAckOrdinal > 0 && postAckOrdinal <= 4) {
                    reason = "first_four_after_event_ack";
                } else if (explainSample) {
                    reason = "declared_explain_sample";
                }
                boolean overlap = receipt.get("started_ns") instanceof Long
                        && receipt.get("finished_ns") instanceof Long
                        && overlapsEvent((long) receipt.get("started_ns"), (long) receipt.get("finished_ns"),
                                eventStarted, eventAck);
                boolean overLimit = false;
                if (overlap) {
                    int ordinal = eventOverlapRequests.incrementAndGet();
                    receipt.put("event_overlap_ordinal", ordinal);
                    overLimit = ordinal > config.overlapLimit;
                    reason = overLimit ? "event_overlap_limit_violation" : "event_overlap";
                    if (overLimit) {
                        overlapCapViolation.set(true);
                        receipt.put("success", false);
                        fail("event_overlap_profile_cap_exceeded");
                    } else if (receipt.get("query_id") != null) {
                        eventOverlapSamples.incrementAndGet();
                    }
                }
                receipt.put("event_overlap", overlap);
                receipt.put("profile_overlap_cap_violation", overLimit);
                receipt.put("sample_profile", !overLimit && !reason.equals("none")
                        && receipt.get("query_id") != null);
                receipt.put("sample_reason", reason);
                receipt.put("event_started_ns_observed", eventStarted);
                receipt.put("event_commit_ack_ns_observed", eventAck);
                requests.append(receipt);
                completed.incrementAndGet();
            }
            check();
        }

        String explain(Connection connection, long requestId, String queryId, String phase) throws Exception {
            String sql = "EXPLAIN PHYSICAL PLAN " + config.query;
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("schema_version", 1);
            result.put("clock_domain", config.clockDomain);
            result.put("target_request_id", requestId);
            result.put("target_query_id", queryId);
            result.put("phase", phase);
            result.put("sql", sql);
            result.put("after_target_query_id_capture", true);
            result.put("success", false);
            List<String> lines = new ArrayList<>();
            result.put("rows", lines);
            result.put("started_ns", System.nanoTime());
            Path path = config.output.resolve("explain-request-" + requestId + ".json");
            try (Statement statement = connection.createStatement()) {
                statement.setQueryTimeout(config.timeout);
                try (ResultSet rows = statement.executeQuery(sql)) {
                    require(rows.getMetaData().getColumnCount() == 1, "EXPLAIN_WIDTH");
                    int bytes = 0;
                    while (rows.next()) {
                        String line = rows.getString(1);
                        require(line != null && line.length() <= 16384 && lines.size() < 4096, "EXPLAIN_ROW_BOUND");
                        bytes += line.getBytes(StandardCharsets.UTF_8).length;
                        require(bytes <= 1024 * 1024, "EXPLAIN_BYTE_BOUND");
                        lines.add(line);
                    }
                    require(!lines.isEmpty(), "EXPLAIN_EMPTY");
                }
                result.put("physical_sql_cache_observed",
                        lines.stream().anyMatch(line -> line.contains("PhysicalSqlCache")));
                result.put("success", true);
            } catch (Exception error) {
                result.putAll(error(error));
                throw error;
            } finally {
                result.put("finished_ns", System.nanoTime());
                writeNew(path, result);
            }
            return path.getFileName().toString();
        }

        void worker(int index) {
            Connection connection = null;
            Statement statement = null;
            boolean announced = false;
            Map<String, Object> setup = new LinkedHashMap<>();
            setup.put("schema_version", 1);
            setup.put("clock_domain", config.clockDomain);
            setup.put("worker", index);
            setup.put("connection_mode", config.connectionMode);
            setup.put("started_ns", System.nanoTime());
            setup.put("connection_ns", 0L);
            setup.put("session_init_ns", 0L);
            setup.put("prepare_ns", 0L);
            setup.put("success", false);
            try {
                if (config.connectionMode.equals("reuse")) {
                    long begin = System.nanoTime();
                    connection = connect(false, false);
                    setup.put("connection_ns", System.nanoTime() - begin);
                    begin = System.nanoTime();
                    initialize(connection);
                    setup.put("session_init_ns", System.nanoTime() - begin);
                    begin = System.nanoTime();
                    statement = prepare(connection);
                    setup.put("prepare_ns", System.nanoTime() - begin);
                }
                setup.put("finished_ns", System.nanoTime());
                setup.put("success", true);
                writeNew(config.output.resolve("worker-setup-" + index + ".json"), setup);
                ready.countDown();
                announced = true;
                await(warmupGate);
                for (int offset = index; offset < config.warmup.length; offset += config.concurrency) {
                    long scheduled = warmupEpoch + config.warmup[offset];
                    waitUntil(scheduled);
                    request(index, "warmup", offset, scheduled, connection, statement);
                }
                warmupDone.countDown();
                await(measurementGate);
                for (int offset = index; offset < config.measured.length; offset += config.concurrency) {
                    long scheduled = epoch + config.measured[offset];
                    waitUntil(scheduled);
                    request(index, "measurement", offset, scheduled, connection, statement);
                }
            } catch (Exception error) {
                fail("worker_" + error.getClass().getSimpleName());
                if (!announced) {
                    setup.put("success", false);
                    setup.put("finished_ns", System.nanoTime());
                    setup.putAll(error(error));
                    try {
                        writeNew(config.output.resolve("worker-setup-" + index + ".json"), setup);
                    } catch (IOException receiptError) {
                        fail("worker_setup_receipt_failure");
                    }
                }
            } finally {
                if (!announced) {
                    ready.countDown();
                }
                try {
                    if (statement != null) {
                        statement.close();
                    }
                    close(connection);
                } catch (SQLException error) {
                    fail("worker_cleanup_failure");
                } finally {
                    measuredDone.countDown();
                }
            }
        }

        void event() {
            event.put("schema_version", 1);
            event.put("clock_domain", config.clockDomain);
            event.put("sql", EVENT);
            event.put("scheduled_ns", epoch + EVENT_OFFSET_NS);
            event.put("scheduled_offset_seconds", 180);
            event.put("ddl_success", false);
            event.put("ddl_attempted", false);
            event.put("commit_outcome", "NOT_ATTEMPTED");
            try {
                waitUntil(epoch + EVENT_OFFSET_NS);
                config.guard();
                try (Statement statement = admin.createStatement()) {
                    statement.setQueryTimeout(config.timeout);
                    check();
                    eventAttempted = true;
                    event.put("ddl_attempted", true);
                    eventStarted = System.nanoTime();
                    event.put("started_ns", eventStarted);
                    try {
                        require(!statement.execute(EVENT), "DDL_RETURNED_RESULT_SET");
                        eventAck = System.nanoTime();
                        event.put("commit_ack_ns", eventAck);
                        event.put("ddl_success", true);
                        event.put("commit_outcome", "ACKNOWLEDGED");
                    } catch (Exception error) {
                        eventCommitUnknown = true;
                        event.put("commit_outcome", "UNKNOWN");
                        throw error;
                    }
                }
                Map<String, Object> after = showCreate(admin, config.timeout);
                event.put("show_create_after", after);
                require(!after.get("sha256_utf8").equals(config.initialViewSha), "DDL_DID_NOT_CHANGE_VIEW_DEFINITION");
                event.put("post_ddl_inspection_success", true);
            } catch (Exception error) {
                event.putAll(error(error));
                fail("ddl_or_post_ddl_inspection_failure");
            } finally {
                event.put("finished_ns", System.nanoTime());
                event.put("finished_at_utc", Instant.now().toString());
                try {
                    writeNew(config.output.resolve("event.json"), snapshot(event));
                } catch (IOException error) {
                    fail("event_receipt_failure");
                }
                eventDone.countDown();
            }
        }

        void abortOwned() {
            for (Connection connection : connections) {
                if (abortSubmitted.add(connection)) {
                    try {
                        cleanupPool.submit(() -> {
                            try {
                                connection.abort(Runnable::run);
                            } catch (Exception ignored) {
                                try {
                                    connection.close();
                                } catch (SQLException ignoredAgain) {
                                    // Final connection accounting and cleanup status retain failures.
                                }
                            } finally {
                                try {
                                    if (connection.isClosed()) {
                                        connections.remove(connection);
                                    }
                                } catch (SQLException ignored) {
                                    // Retain unresolved handles; a failed close is never successful cleanup.
                                }
                            }
                        });
                    } catch (java.util.concurrent.RejectedExecutionException error) {
                        abortSubmitted.remove(connection);
                        cleanup.put("connection_abort_submission_error", error(error));
                        fail("connection_abort_submission_failure");
                    }
                }
            }
        }

        void restore() throws Exception {
            config.guard();
            cleanup.put("restore_required", eventAttempted);
            cleanup.put("event_commit_unknown", eventCommitUnknown);
            require(eventDone.getCount() == 0, "EVENT_THREAD_STILL_ACTIVE_RESTORE_UNSAFE");
            Connection connection = connect(true, true);
            try {
                if (eventAttempted) {
                    cleanup.put("restore_sql", RESET);
                    cleanup.put("restore_started_ns", System.nanoTime());
                    cleanup.put("restore_commit_outcome", "NOT_ATTEMPTED");
                    try (Statement statement = connection.createStatement()) {
                        statement.setQueryTimeout(Math.min(config.timeout, config.cleanup));
                        cleanup.put("restore_commit_outcome", "UNKNOWN");
                        require(!statement.execute(RESET), "RESTORE_RETURNED_RESULT_SET");
                        cleanup.put("restore_acknowledged", true);
                        cleanup.put("restore_ack_ns", System.nanoTime());
                        cleanup.put("restore_commit_outcome", "ACKNOWLEDGED");
                    }
                }
                Map<String, Object> after = showCreate(connection, Math.min(config.timeout, config.cleanup));
                cleanup.put("show_create_after_restore", after);
                boolean matches = after.get("sha256_utf8").equals(config.initialViewSha);
                cleanup.put("initial_definition_matches", matches);
                require(matches, "RESTORED_VIEW_DIGEST_DIFFERS");
                cleanup.put("view_restored_at_observation", true);
            } finally {
                close(connection);
            }
        }

        void run() throws Exception {
            Map<String, Object> identity = new LinkedHashMap<>();
            identity.put("schema_version", 1);
            identity.put("pid", ProcessHandle.current().pid());
            identity.put("start_ticks", startTicks(ProcessHandle.current().pid()));
            identity.put("clock_domain", config.clockDomain);
            identity.put("namespace", config.namespace);
            identity.put("query_sha256_utf8", QUERY_SHA);
            identity.put("definition_sha256", config.definitionSha);
            identity.put("arrival_sha256", config.arrivalSha);
            identity.put("controller_owner_record_sha256", config.ownerSha);
            identity.put("view_owner_token", config.raw.path("view_owner_token").asText());
            identity.put("case_id", config.caseId);
            identity.put("mode", config.mode);
            identity.put("connection_mode", config.connectionMode);
            identity.put("concurrency", config.concurrency);
            identity.put("java_runtime_version", System.getProperty("java.runtime.version"));
            identity.put("max_heap_bytes", Runtime.getRuntime().maxMemory());
            identity.put("profile_every_n", config.sampleEvery);
            identity.put("profile_overlap_limit", config.overlapLimit);
            identity.put("profile_extra_samples", "first_in_each_phase_and_first_four_completed_after_event_ack");
            identity.put("profile_event_overlap_rule",
                    "target_finish>=event_start AND (ack_not_yet_observed OR target_start<=ack); overflow_fails");
            identity.put("session_sql", List.of("SET enable_sql_cache=" + config.caseId.equals("LP-007"),
                    "SET enable_query_cache=false", "SET enable_short_circuit_query=false", "SET enable_profile=true"));
            writeNew(config.output.resolve("identity.json"), identity);
            admin = connect(true, false);
            Map<String, Object> before = showCreate(admin, config.timeout);
            writeNew(config.output.resolve("preflight.json"), before);
            require(before.get("sha256_utf8").equals(config.initialViewSha), "INITIAL_VIEW_OWNER_DIGEST_CHANGED");
            for (int index = 0; index < config.concurrency; index++) {
                int worker = index;
                workers.submit(() -> worker(worker));
            }
            await(ready);
            warmupEpoch = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(200);
            phaseDeadline = warmupEpoch + TimeUnit.SECONDS.toNanos(config.warmupSeconds + config.drain);
            writeNew(config.output.resolve("ready.json"), Map.of("schema_version", 1,
                    "pid", ProcessHandle.current().pid(), "clock_domain", config.clockDomain,
                    "namespace", config.namespace, "warmup_start_ns", warmupEpoch,
                    "warmup_seconds", config.warmupSeconds));
            warmupGate.countDown();
            await(warmupDone);
            waitUntil(warmupEpoch + TimeUnit.SECONDS.toNanos(config.warmupSeconds));
            epoch = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(200);
            phaseDeadline = epoch + TimeUnit.SECONDS.toNanos(config.windowSeconds + config.drain);
            writeNew(config.output.resolve("measurement-start.json"), Map.of("schema_version", 1,
                    "clock_domain", config.clockDomain, "measurement_start_ns", epoch,
                    "warmup_start_ns", warmupEpoch,
                    "window_seconds", config.windowSeconds, "drain_deadline_ns", phaseDeadline,
                    "event_enabled", config.caseId.equals("LP-007"), "event_scheduled_ns", epoch + EVENT_OFFSET_NS));
            if (config.caseId.equals("LP-007")) {
                administration.submit(this::event);
            } else {
                writeNew(config.output.resolve("event.json"), Map.of("schema_version", 1,
                        "clock_domain", config.clockDomain, "ddl_attempted", false,
                        "ddl_success", false, "status", "NOT_APPLICABLE_LP006"));
                eventDone.countDown();
            }
            measurementGate.countDown();
            await(measuredDone);
            waitUntil(epoch + TimeUnit.SECONDS.toNanos(config.windowSeconds));
            await(eventDone);
        }

        synchronized void finish(String reason) {
            if (!finalized.compareAndSet(false, true)) {
                return;
            }
            if (!reason.equals("normal")) {
                fail(reason);
            }
            cancelled.set(true);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(config.cleanup);
            cleanup.put("schema_version", 1);
            cleanup.put("clock_domain", config.clockDomain);
            cleanup.put("started_ns", System.nanoTime());
            cleanup.put("success", false);
            workers.shutdownNow();
            administration.shutdownNow();
            abortOwned();
            try {
                long joinMillis = Math.min(10000, Math.max(1, config.cleanup * 1000L / 3));
                boolean readersStopped = workers.awaitTermination(joinMillis, TimeUnit.MILLISECONDS);
                boolean adminStopped = administration.awaitTermination(joinMillis, TimeUnit.MILLISECONDS);
                cleanup.put("reader_threads_terminated", readersStopped);
                cleanup.put("event_thread_terminated", adminStopped);
                if (!eventAttempted && adminStopped) {
                    eventDone.countDown();
                }
                require(readersStopped && adminStopped, "OWNED_THREADS_DID_NOT_STOP");
                Future<?> restored = cleanupPool.submit(() -> {
                    try {
                        restore();
                    } catch (Exception error) {
                        cleanup.put("restore_error", error(error));
                        throw new IllegalStateException(error.getClass().getSimpleName());
                    }
                });
                restored.get(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
                cleanup.put("success", true);
            } catch (Exception error) {
                cleanup.put("cleanup_error", error(error));
                fail("cleanup_failure");
            } finally {
                abortOwned();
                cleanupPool.shutdown();
                boolean cleanupStopped = false;
                try {
                    cleanupStopped = awaitUntil(cleanupPool, deadline);
                } catch (InterruptedException error) {
                    cleanup.put("cleanup_join_error", error(error));
                    Thread.currentThread().interrupt();
                } finally {
                    if (!cleanupStopped) {
                        cleanupPool.shutdownNow();
                    }
                }
                cleanup.put("cleanup_threads_terminated", cleanupStopped);
                cleanup.put("finished_ns", System.nanoTime());
                cleanup.put("deadline_exceeded", System.nanoTime() > deadline);
                cleanup.put("remaining_connection_handles", connections.size());
                if (!cleanupStopped || connections.size() != 0 || System.nanoTime() > deadline) {
                    cleanup.put("success", false);
                    fail("cleanup_incomplete_or_deadline");
                }
                try {
                    starts.close();
                } catch (Exception error) {
                    cleanup.put("intent_log_close_error", error(error));
                    cleanup.put("success", false);
                    fail("intent_log_close_failure");
                }
                try {
                    requests.close();
                } catch (Exception error) {
                    cleanup.put("request_log_close_error", error(error));
                    cleanup.put("success", false);
                    fail("request_log_close_failure");
                }
                try {
                    writeNew(config.output.resolve("cleanup.json"), snapshot(cleanup));
                } catch (Exception error) {
                    fail("cleanup_receipt_write_failure");
                    System.err.println("CLEANUP_RECEIPT_FAILED " + error.getClass().getSimpleName());
                }
                if (completed.get() != config.warmup.length + config.measured.length
                        || completed.get() != serial.get()) {
                    fail("incomplete_request_receipts");
                }
                try {
                    Map<String, Object> summary = new LinkedHashMap<>();
                    summary.put("schema_version", 1);
                    summary.put("clock_domain", config.clockDomain);
                    summary.put("case_id", config.caseId);
                    summary.put("success", !failed.get() && !eventCommitUnknown
                            && Boolean.TRUE.equals(cleanup.get("success")));
                    summary.put("failure_reason", failureReason);
                    summary.put("scheduled_warmup_requests", config.warmup.length);
                    summary.put("scheduled_measurement_requests", config.measured.length);
                    summary.put("request_intents", serial.get());
                    summary.put("completed_receipts", completed.get());
                    summary.put("uncompleted_intents", serial.get() - completed.get());
                    summary.put("event_attempted", eventAttempted);
                    summary.put("event_commit_unknown", eventCommitUnknown);
                    summary.put("profile_overlap_limit", config.overlapLimit);
                    summary.put("profile_overlap_requests", eventOverlapRequests.get());
                    summary.put("profile_overlap_samples", eventOverlapSamples.get());
                    summary.put("profile_overlap_cap_violation", overlapCapViolation.get());
                    summary.put("event_snapshot", snapshot(event));
                    summary.put("cleanup_success", cleanup.get("success"));
                    summary.put("value_oracle_verified", false);
                    summary.put("profile_oracle_verified", false);
                    summary.put("LP006_complete", false);
                    summary.put("LP007_complete", false);
                    summary.put("release_performance_pass", false);
                    summary.put("scope", "bounded_original_FE_functional_adapter_not_formal_measurement");
                    writeNew(config.output.resolve("summary.json"), summary);
                } catch (Exception error) {
                    fail("summary_receipt_write_failure");
                    System.err.println("RECEIPT_FINALIZATION_FAILED " + error.getClass().getSimpleName());
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        require(args.length == 1, "EXPECTED_ONE_ABSOLUTE_CONFIG_PATH");
        Config config = new Config(Path.of(args[0]));
        Runner runner = new Runner(config);
        Thread hook = new Thread(() -> runner.finish("signal_or_jvm_shutdown"), "complex-shutdown");
        Runtime.getRuntime().addShutdownHook(hook);
        Thread watchdog = new Thread(() -> {
            while (!runner.finalized.get()) {
                try {
                    Thread.sleep(250);
                    if (runner.finalized.get()) {
                        return;
                    }
                    runner.check();
                    config.guard();
                } catch (Exception error) {
                    if (runner.finalized.get()) {
                        return;
                    }
                    runner.fail("watchdog_" + error.getClass().getSimpleName());
                    runner.abortOwned();
                    return;
                }
            }
        }, "complex-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
        String reason = "normal";
        try {
            runner.run();
        } catch (Exception error) {
            reason = "run_" + error.getClass().getSimpleName();
        } finally {
            runner.finish(reason);
            Runtime.getRuntime().removeShutdownHook(hook);
        }
        // All remaining helper worker threads are daemon threads; a driver stall cannot retain this owned JVM.
        System.exit(runner.failed.get() || runner.eventCommitUnknown ? 2 : 0);
    }
}
