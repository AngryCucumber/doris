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
import java.io.BufferedWriter;
import java.math.BigDecimal;
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
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** One owned G4 DML window. Preparation/verification SELECTs require a valid certificate. */
public final class LicenseDmlPerformance {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final long BILLION = 1_000_000_000L;
    private static final String SOURCE = "license_perf.point_rows";
    private final JsonNode config;
    private final JsonNode launch;
    private final Path configurationPath;
    private final Path directory;
    private final String token;
    private final String table;
    private final String kind;
    private final String launchHash;
    private final long pid = ProcessHandle.current().pid();
    private final long startTicks;
    private final String namespace;
    private final ObjectNode summary = JSON.createObjectNode();
    private final List<Connection> connections = Collections.synchronizedList(new ArrayList<>());
    private final List<Thread> workers = new ArrayList<>();
    private final List<Thread> closingThreads = new ArrayList<>();
    private final AtomicLong errors = new AtomicLong();
    private volatile boolean cancelled;
    private volatile long phaseDeadline;
    private boolean workersClosed;
    private String stage = "INPUTS";
    private long[] warmup;
    private long[] measured;
    private String[] outcomes;
    private int[] affected;
    private Connection[] clients;

    private LicenseDmlPerformance(Path path) throws Exception {
        configurationPath = path.toRealPath();
        config = JSON.readTree(configurationPath.toFile());
        directory = Path.of(config.path("output").asText()).toRealPath();
        require(configurationPath.getParent().equals(directory), "CONFIG_DIRECTORY");
        token = config.path("token").asText();
        table = config.path("table").asText();
        kind = config.path("operation").asText();
        require(token.matches("[a-f0-9]{32}") && table.equals("license_perf.dml_perf_" + token), "OWNED_TABLE_NAME");
        require(List.of("insert_select", "update", "delete").contains(kind), "DML_OPERATION");
        require(number("concurrency") == 1 || number("concurrency") == 8, "DML_CONCURRENCY");
        require(config.path("seed").asLong() == 20260922 && number("rows_per_operation") == 100, "DML_FIXED_INPUT");
        require(number("max_requests") > 0 && number("max_requests") <= 500000, "DML_REQUEST_BOUND");
        require(number("warmup_seconds") >= 1 && number("duration_seconds") >= 1 && number("warmup_seconds") <= 1800
                        && number("duration_seconds") <= 7200,
                "DML_DURATION");
        require(config.path("qualification").asText().equals("diagnostic")
                        || (config.path("qualification").asText().equals("formal") && number("warmup_seconds") >= 180
                                && number("duration_seconds") >= 600),
                "DML_FORMAL_DURATION");
        require(number("timeout_seconds") > 0 && number("timeout_seconds") <= 30
                        && number("clock_ticks_per_second") > 0,
                "DML_TIMEOUT");
        double rate = config.path("rate_per_second").asDouble();
        require(Double.isFinite(rate) && rate > 0 && rate <= 1000, "DML_RATE");
        String stat = Files.readString(Path.of("/proc/self/stat"));
        startTicks = Long.parseLong(stat.substring(stat.lastIndexOf(')') + 1).trim().split("\\s+")[19]);
        namespace = Files.readSymbolicLink(Path.of("/proc/self/ns/net")).toString();
        JsonNode reference = config.path("launch");
        Path launchPath = Path.of(reference.path("path").asText());
        launchHash = digest(Files.readAllBytes(launchPath));
        require(launchHash.equals(reference.path("sha256").asText()), "LAUNCH_DIGEST");
        launch = JSON.readTree(launchPath.toFile());
        require(launch.path("launch_token").asText().equals(token), "LAUNCH_TOKEN");
        summary.put("status", "INVALID_WINDOW")
                .put("formal_performance_pass", false)
                .put("automatic_write_replays", 0)
                .put("token", token)
                .put("pid", pid)
                .put("start_ticks", startTicks)
                .put("namespace", namespace)
                .put("operation", kind)
                .put("table", table);
    }

    private static void require(boolean condition, String code) {
        if (!condition) {
            throw new IllegalStateException(code);
        }
    }

    static ObjectNode failureRecord(String stage, Exception error) {
        ObjectNode result = JSON.createObjectNode()
                                    .put("stage", stage.matches("[A-Z_]{1,64}") ? stage : "UNCLASSIFIED")
                                    .put("exception_class", error.getClass().getSimpleName());
        if (error instanceof SQLException) {
            SQLException sql = (SQLException) error;
            String state = sql.getSQLState();
            result.put("sql_state", state != null && state.matches("[A-Za-z0-9]{1,5}")
                            ? state : "UNSAFE_OR_MISSING")
                    .put("error_code", sql.getErrorCode());
        }
        // SQLException messages, causes, SQL text and credentials are intentionally excluded.
        return result;
    }

    private int number(String name) {
        return config.path(name).asInt(-1);
    }

    private static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static String md5(long id) throws Exception {
        return HexFormat.of().formatHex(
                MessageDigest.getInstance("MD5").digest(Long.toString(id).getBytes(StandardCharsets.US_ASCII)));
    }

    private void publish(String name, JsonNode value) throws Exception {
        Path destination = directory.resolve(name);
        Path temporary = directory.resolve(name + ".tmp");
        JSON.writerWithDefaultPrettyPrinter().writeValue(temporary.toFile(), value);
        Files.move(temporary, destination, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private void identity() throws Exception {
        require(Files.readSymbolicLink(Path.of("/proc/self/ns/net"))
                        .toString()
                        .equals(config.path("namespace").asText()),
                "NAMESPACE_CHANGED");
        require(config.path("cluster_pins").isArray() && !config.path("cluster_pins").isEmpty(), "NO_CLUSTER_PINS");
        for (JsonNode pin : config.path("cluster_pins")) {
            Path process = Path.of("/proc", pin.path("pid").asText());
            String stat = Files.readString(process.resolve("stat"));
            String[] fields = stat.substring(stat.lastIndexOf(')') + 1).trim().split("\\s+");
            require(!fields[0].equals("Z") && !fields[0].equals("X")
                            && Long.parseLong(fields[19]) == pin.path("start_ticks").asLong()
                            && Files.readSymbolicLink(process.resolve("ns/net"))
                                       .toString()
                                       .equals(pin.path("namespace").asText())
                            && Files.readSymbolicLink(process.resolve("exe"))
                                       .toString()
                                       .equals(pin.path("exe").asText())
                            && digest(Files.readAllBytes(process.resolve("cmdline")))
                                       .equals(pin.path("command_sha256").asText()),
                    "CLUSTER_PIN_CHANGED");
        }
        require(System.nanoTime() < phaseDeadline, "PHASE_DEADLINE");
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
        try (Statement statement = statement(connection);
                ResultSet rows = statement.executeQuery("SHOW TABLES FROM license_perf")) {
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
        try (Statement statement = statement(connection);
                ResultSet rows = statement.executeQuery("SHOW TABLETS FROM " + table)) {
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
        require(id == expectedId && group == id % 1024 && value == id % 100000 && payload instanceof String
                        && payload.equals(md5(id)),
                "FULL_VALUE_MODEL");
        return id + "\t" + group + "\t" + value + "\t" + payload + "\n";
    }

    private ObjectNode fullSource(Connection connection) throws Exception {
        MessageDigest observed = MessageDigest.getInstance("SHA-256");
        long next = 0;
        while (true) {
            identity();
            int count = 0;
            try (Statement statement = statement(connection);
                    ResultSet rows = statement.executeQuery("SELECT id, grp, v, payload FROM " + SOURCE
                            + (next == 0 ? "" : " WHERE id > " + (next - 1)) + " ORDER BY id LIMIT 10000")) {
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
        return JSON.createObjectNode()
                .put("rows", next)
                .put("full_values_verified", true)
                .put("canonical_sha256", HexFormat.of().formatHex(observed.digest()))
                .put("schema_sha256", schema(connection, SOURCE))
                .put("page_size", 10000)
                .put("pagination", "strict_id_keyset_no_offset");
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
                            && owner.path("configuration_sha256")
                                       .asText()
                                       .equals(digest(Files.readAllBytes(configurationPath)))
                            && owner.path("create_acknowledged").asBoolean()
                            && owner.path("identity").equals(tableIdentity(oracle)),
                    "TARGET_OWNERSHIP_CHANGED");
            execute(oracle, "DROP TABLE " + table + " FORCE");
            require(!exists(oracle), "OWNED_TABLE_REMAINS");
            return true;
        }
    }

    private ObjectNode timestamp() {
        return JSON.createObjectNode()
                .put("schema_version", 1)
                .put("token", token)
                .put("pid", pid)
                .put("start_ticks", startTicks)
                .put("namespace", namespace)
                .put("java_monotonic_ns", System.nanoTime())
                .put("launch_token", token)
                .put("launch_sha256", launchHash)
                .put("boot_id", launch.path("boot_id").asText());
    }

    private Connection connect(String role) throws Exception {
        identity();
        JsonNode account = config.path(role + "_account");
        String secret = System.getenv(account.path("password_env").asText());
        require(secret != null, "EXPLICIT_CREDENTIAL_MISSING");
        Properties properties = new Properties();
        properties.setProperty("user", account.path("username").asText());
        properties.setProperty("password", secret);
        properties.setProperty("useServerPrepStmts", "false");
        properties.setProperty("rewriteBatchedStatements", "false");
        properties.setProperty("useLocalSessionState", "true");
        properties.setProperty("autoReconnect", "false");
        properties.setProperty("allowMultiQueries", "false");
        properties.setProperty("useSSL", "false");
        properties.setProperty("serverTimezone", "UTC");
        properties.setProperty("connectTimeout", "10000");
        properties.setProperty("socketTimeout", Long.toString(number("timeout_seconds") * 1000L));
        String host = config.path("target").path("host").asText();
        int port = config.path("target").path("query_port").asInt();
        require(host.matches("[0-9.]+") && port > 1023 && port <= 65535, "NUMERIC_OWNED_ENDPOINT");
        Connection connection =
                DriverManager.getConnection("jdbc:mysql://" + host + ":" + port + "/license_perf", properties);
        connections.add(connection);
        connection.setAutoCommit(true);
        for (String sql : new String[] {"SET enable_sql_cache=false", "SET enable_query_cache=false",
                     "SET group_commit='off_mode'", "SET enable_insert_strict=true",
                     "SET enable_unique_key_partial_update=false", "SET query_timeout=" + number("timeout_seconds"),
                     "SET insert_timeout=" + number("timeout_seconds")}) {
            execute(connection, sql);
        }
        return connection;
    }

    private ObjectNode session(Connection connection) throws Exception {
        ObjectNode result = JSON.createObjectNode()
                                    .put("auto_commit", connection.getAutoCommit())
                                    .put("driver", connection.getMetaData().getDriverVersion())
                                    .put("jdk", System.getProperty("java.runtime.version"));
        require(connection.getAutoCommit(), "STANDALONE_AUTOCOMMIT");
        for (String[] pair : new String[][] {{"enable_sql_cache", "false"}, {"enable_query_cache", "false"},
                     {"group_commit", "off_mode"}, {"enable_insert_strict", "true"},
                     {"enable_unique_key_partial_update", "false"},
                     {"query_timeout", Integer.toString(number("timeout_seconds"))},
                     {"insert_timeout", Integer.toString(number("timeout_seconds"))}}) {
            try (Statement statement = statement(connection);
                    ResultSet rows = statement.executeQuery("SHOW SESSION VARIABLES LIKE '" + pair[0] + "'")) {
                require(rows.next() && pair[0].equalsIgnoreCase(rows.getString(1)), "SESSION_VALUE_MISSING");
                String value = rows.getString(2).toLowerCase(java.util.Locale.ROOT);
                if (pair[1].equals("true") || pair[1].equals("false")) {
                    if (value.equals("on") || value.equals("1")) {
                        value = "true";
                    }
                    if (value.equals("off") || value.equals("0")) {
                        value = "false";
                    }
                }
                require(value.equals(pair[1]) && !rows.next(), "SESSION_VALUE_CHANGED");
                result.put(pair[0], value);
            }
        }
        return result;
    }

    private long[] arrivals(int seconds) throws Exception {
        Random random = new Random(20260922);
        List<Long> values = new ArrayList<>();
        double elapsed = 0;
        while (true) {
            double uniform = random.nextDouble();
            if (uniform == 0) {
                continue;
            }
            elapsed += -StrictMath.log(uniform) * BILLION / config.path("rate_per_second").asDouble();
            if (elapsed >= seconds * (double) BILLION) {
                break;
            }
            require(values.size() < number("max_requests"), "SCHEDULE_REQUEST_BOUND");
            values.add((long) elapsed);
        }
        require(!values.isEmpty(), "EMPTY_SCHEDULE");
        return values.stream().mapToLong(Long::longValue).toArray();
    }

    private void inputs() throws Exception {
        warmup = arrivals(number("warmup_seconds"));
        measured = arrivals(number("duration_seconds"));
        int total = warmup.length + measured.length;
        require(total <= number("max_requests") && total * 100L <= config.path("max_rows").asLong(),
                "TOTAL_DATA_BOUND");
        outcomes = new String[total];
        Arrays.fill(outcomes, "NOT_SENT");
        affected = new int[total];
        Arrays.fill(affected, -1);
        int base = 0;
        for (String name : new String[] {"warmup", "measurement"}) {
            long[] values = name.equals("warmup") ? warmup : measured;
            try (BufferedWriter output = Files.newBufferedWriter(directory.resolve(name + "-arrivals.tsv"))) {
                output.write("sequence\toffset_ns\tfirst_id\trows\n");
                for (int index = 0; index < values.length; index++) {
                    output.write(index + "\t" + values[index] + "\t" + (base + index) * 100L + "\t100\n");
                }
            }
            summary.put(name + "_schedule_sha256",
                           digest(Files.readAllBytes(directory.resolve(name + "-arrivals.tsv"))))
                    .put(name + "_requests", values.length);
            base += values.length;
        }
        summary.put("total_target_domains", total).put("maximum_target_rows", total * 100L);
        publish("plan.json", summary.deepCopy().put("status", "PLANNED_NOT_RUN"));
    }

    private static String projection(String expression) {
        return expression + ",CAST((" + expression + ")%1024 AS INT),(" + expression + ")%100000,MD5(CAST(("
                + expression + ") AS STRING))";
    }

    private String operation(int domain) {
        long first = domain * 100L, end = first + 100;
        if (kind.equals("insert_select")) {
            return "INSERT INTO " + table + " SELECT " + projection(first + "+id") + " FROM " + SOURCE
                    + " WHERE id>=0 AND id<100";
        }
        return (kind.equals("update") ? "UPDATE " + table + " SET v=v+1000000,payload=CONCAT('u_',payload)"
                                      : "DELETE FROM " + table)
                + " WHERE id>=" + first + " AND id<" + end;
    }

    private void disk(String phase) throws Exception {
        ObjectNode receipt = timestamp().put("phase", phase);
        ArrayNode values = receipt.putArray("storage");
        boolean enough = true;
        require(config.path("storage_paths").isArray() && !config.path("storage_paths").isEmpty(),
                "STORAGE_PATHS_MISSING");
        for (JsonNode item : config.path("storage_paths")) {
            Path path = Path.of(item.asText()).toRealPath();
            long free = Files.getFileStore(path).getUsableSpace();
            values.addObject().put("path", path.toString()).put("usable_bytes", free);
            enough &= free >= config.path("min_disk_free_bytes").asLong();
        }
        try (BufferedWriter output = Files.newBufferedWriter(directory.resolve("storage.jsonl"),
                     java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND)) {
            output.write(JSON.writeValueAsString(receipt));
            output.newLine();
        }
        require(enough, "RESOURCE_DISK_RESERVE");
    }

    private void quota(Connection oracle) throws Exception {
        ArrayNode values = JSON.createArrayNode();
        long lower = -1, replicaLeft = -1;
        try (Statement statement = statement(oracle);
                ResultSet rows = statement.executeQuery("SHOW DATA")) {
            require(rows.getMetaData().getColumnCount() == 4, "QUOTA_METADATA_SHAPE");
            while (rows.next()) {
                require(values.size() < 10000, "QUOTA_METADATA_BOUND");
                ArrayNode row = values.addArray();
                for (int index = 1; index <= 4; index++) {
                    row.add(rows.getString(index));
                }
                if (rows.getString(1).equals("Left")) {
                    require(lower == -1, "DUPLICATE_QUOTA_LEFT");
                    Matcher match =
                            Pattern.compile("([0-9]+(?:\\.[0-9]{1,3})?) (B|KB|MB|GB|TB|PB)").matcher(rows.getString(2));
                    require(match.matches(), "QUOTA_FORMAT");
                    int exponent = List.of("B", "KB", "MB", "GB", "TB", "PB").indexOf(match.group(2));
                    lower = new BigDecimal(match.group(1))
                                    .subtract(new BigDecimal("0.001"))
                                    .max(BigDecimal.ZERO)
                                    .multiply(BigDecimal.valueOf(1024).pow(exponent))
                                    .longValue();
                    replicaLeft = rows.getLong(3);
                }
            }
        }
        // Rounded SHOW DATA is a conservative lower bound, never an exact byte claim.
        publish("quota-before.json",
                timestamp()
                        .put("remaining_bytes_lower_bound", lower)
                        .put("remaining_replica_count", replicaLeft)
                        .set("raw_rows", values));
        require(lower >= outcomes.length * 100L * 1024L && replicaLeft >= 16, "RESOURCE_QUOTA_RESERVE");
    }

    private ObjectNode targetModel(Connection oracle, boolean finalState) throws Exception {
        int[] counts = new int[outcomes.length];
        byte[] versions = new byte[outcomes.length];
        Arrays.fill(versions, (byte) -1);
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        long previous = -1, total = 0;
        while (true) {
            int count = 0;
            identity();
            try (Statement statement = statement(oracle);
                    ResultSet rows = statement.executeQuery("SELECT id,grp,v,payload FROM " + table + " WHERE id>"
                            + previous + " ORDER BY id LIMIT 10000")) {
                columns(rows);
                while (rows.next()) {
                    long id = integer(rows, 1), group = integer(rows, 2), value = integer(rows, 3);
                    Object payload = rows.getObject(4);
                    require(id > previous && id >= 0 && id < outcomes.length * 100L && count < 10000,
                            "TARGET_ID_DOMAIN");
                    int domain = (int) (id / 100), version;
                    require(group == id % 1024 && payload instanceof String, "TARGET_FULL_VALUE");
                    if (value == id % 100000 && payload.equals(md5(id))) {
                        version = 0;
                    } else {
                        require(kind.equals("update") && finalState && value == id % 100000 + 1000000
                                        && payload.equals("u_" + md5(id)),
                                "TARGET_FULL_VALUE");
                        version = 1;
                    }
                    require(versions[domain] < 0 || versions[domain] == version, "PARTIAL_UPDATE_BATCH");
                    versions[domain] = (byte) version;
                    counts[domain]++;
                    previous = id;
                    total++;
                    count++;
                    hash.update((id + "\t" + group + "\t" + value + "\t" + payload + "\n")
                                        .getBytes(StandardCharsets.US_ASCII));
                }
            }
            if (count == 0) {
                break;
            }
        }
        ArrayNode resolution = JSON.createArrayNode();
        for (int domain = 0; domain < outcomes.length; domain++) {
            require(counts[domain] == 0 || counts[domain] == 100, "PARTIAL_OR_DUPLICATE_BATCH");
            boolean committed = kind.equals("insert_select") ? counts[domain] == 100
                    : kind.equals("delete")                  ? counts[domain] == 0
                                                             : counts[domain] == 100 && versions[domain] == 1;
            boolean original =
                    kind.equals("insert_select") ? counts[domain] == 0 : counts[domain] == 100 && versions[domain] == 0;
            require(committed || original, "INVALID_BATCH_FINAL_STATE");
            if (!finalState || outcomes[domain].equals("NOT_SENT") || outcomes[domain].equals("ERROR")) {
                require(original, "UNSENT_BATCH_CHANGED");
            } else if (outcomes[domain].equals("ACK")) {
                require(committed, "ACK_BATCH_NOT_COMMITTED");
            }
            resolution.addObject()
                    .put("domain", domain)
                    .put("request_outcome", outcomes[domain])
                    .put("rows", counts[domain])
                    .put("observed_committed", committed)
                    .put("version", versions[domain])
                    .put("unknown_absence_is_rollback_proof", false);
        }
        if (finalState) {
            publish("batch-resolution.json", resolution);
        }
        return JSON.createObjectNode()
                .put("rows", total)
                .put("full_values_verified", true)
                .put("exact_id_domains_verified", true)
                .put("canonical_sha256", HexFormat.of().formatHex(hash.digest()));
    }

    private void prepare() throws Exception {
        phaseDeadline = System.nanoTime() + number("prepare_timeout_seconds") * BILLION;
        stage = "PREPARE_DISK";
        disk("prepare");
        stage = "PREPARE_CONNECT";
        try (Connection oracle = connect("oracle")) {
            stage = "PREPARE_QUOTA";
            quota(oracle);
            stage = "PREPARE_SOURCE_ORACLE";
            summary.set("source_before", fullSource(oracle));
            stage = "PREPARE_TARGET_ABSENCE";
            require(!exists(oracle), "REFUSE_EXISTING_TARGET");
            publish("create-intent.json", timestamp().put("table", table).put("absent_before_create", true));
            stage = "PREPARE_CREATE_TARGET";
            execute(oracle,
                    "CREATE TABLE " + table
                            + " (id BIGINT NOT NULL,grp INT NOT NULL,v BIGINT NOT NULL,payload VARCHAR(128))"
                            + " UNIQUE KEY(id) DISTRIBUTED BY HASH(id) BUCKETS 16"
                            + " PROPERTIES (\"replication_num\"=\"1\","
                            + "\"enable_unique_key_merge_on_write\"=\"true\",\"store_row_column\"=\"true\","
                            + "\"light_schema_change\"=\"true\",\"enable_mow_light_delete\"=\"false\")");
            stage = "PREPARE_TARGET_IDENTITY";
            publish("owner.json",
                    timestamp()
                            .put("table", table)
                            .put("create_acknowledged", true)
                            .put("configuration_sha256", digest(Files.readAllBytes(configurationPath)))
                            .set("identity", tableIdentity(oracle)));
            if (!kind.equals("insert_select")) {
                stage = "PREPARE_PRELOAD_TARGET";
                for (long first = 0; first < outcomes.length * 100L; first += 10000) {
                    long count = Math.min(10000, outcomes.length * 100L - first);
                    try (Statement statement = statement(oracle)) {
                        require(statement.executeUpdate("INSERT INTO " + table + " SELECT "
                                        + projection(first + "+number") + " FROM numbers(\"number\"=\"" + count + "\")")
                                        == count,
                                "PRELOAD_AFFECTED_ROWS");
                    }
                    disk("preload");
                }
            }
            stage = "PREPARE_TARGET_ORACLE";
            summary.set("target_before", targetModel(oracle, false));
        }
        clients = new Connection[number("concurrency")];
        for (int index = 0; index < clients.length; index++) {
            stage = "PREPARE_WORKER_CONNECT";
            clients[index] = connect("write");
            stage = "PREPARE_WORKER_SESSION";
            publish("worker-" + index + "-session.json", session(clients[index]));
        }
        stage = "PREPARE_READY";
        publish("ready.json",
                timestamp()
                        .put("connections", clients.length)
                        .put("source_rows_verified", 1000000)
                        .put("prepared_target_rows", summary.path("target_before").path("rows").asLong()));
    }

    private JsonNode waitMarker(String name) throws Exception {
        while (!Files.exists(directory.resolve(name))) {
            identity();
            require(!Files.exists(directory.resolve("stop.json")), "CONTROLLER_CANCELLED");
            Thread.sleep(10);
        }
        JsonNode value = JSON.readTree(directory.resolve(name).toFile());
        require(value.path("token").asText().equals(token), "MARKER_TOKEN");
        return value;
    }

    private void bridge() throws Exception {
        phaseDeadline = System.nanoTime() + number("coordination_timeout_seconds") * BILLION;
        JsonNode request = waitMarker("clock-request.json");
        String nonce = request.path("nonce").asText();
        require(nonce.matches("[a-f0-9]{32}"), "CLOCK_NONCE");
        long sample = System.nanoTime();
        publish("p4-helper-clock.json",
                timestamp()
                        .put("nonce", nonce)
                        .put("jvm_sample_ns", sample)
                        .put("helper_pid", pid)
                        .put("helper_start_ticks", startTicks));
        require(waitMarker("clock-ack.json").path("nonce").asText().equals(nonce), "CLOCK_ACK_NONCE");
    }

    private ObjectNode cpu() throws Exception {
        identity();
        ObjectNode result = JSON.createObjectNode();
        for (String role : new String[] {"fe", "be"}) {
            JsonNode pin = config.path("cpu_services").path(role);
            long before = System.nanoTime();
            String stat = Files.readString(Path.of("/proc", pin.path("pid").asText(), "stat"));
            long after = System.nanoTime();
            String[] fields = stat.substring(stat.lastIndexOf(')') + 1).trim().split("\\s+");
            require(Long.parseLong(fields[19]) == pin.path("start_ticks").asLong(), "CPU_PROCESS_LIFETIME");
            result.putObject(role)
                    .put("pid", pin.path("pid").asLong())
                    .put("start_ticks", Long.parseLong(fields[19]))
                    .put("cpu_seconds",
                            (Long.parseLong(fields[11]) + Long.parseLong(fields[12]))
                                    / (double) number("clock_ticks_per_second"))
                    .put("sample_started_java_ns", before)
                    .put("sample_ended_java_ns", after);
        }
        identity();
        return result;
    }

    private static String field(String info, String key) {
        Matcher match = Pattern.compile("'" + key + "':'([^']*)'").matcher(info);
        require(match.find(), "ACK_FIELD_MISSING");
        String value = match.group(1);
        require(!match.find(), "ACK_FIELD_DUPLICATE");
        return value;
    }

    private void phase(String name, long[] schedule, int base, int duration) throws Exception {
        phaseDeadline =
                System.nanoTime() + (duration + number("drain_seconds") + number("timeout_seconds") + 5L) * BILLION;
        AtomicLong last = new AtomicLong(), successes = new AtomicLong();
        ObjectNode firstCpu = cpu();
        long epoch = System.nanoTime() + 500_000_000L;
        publish(name + "-start.json", timestamp().put("epoch_ns", epoch).set("cpu", firstCpu));
        List<Thread> active = new ArrayList<>();
        for (int worker = 0; worker < clients.length; worker++) {
            final int slot = worker;
            Thread thread = new Thread(() -> {
                try (Statement statement = statement(clients[slot]);
                        BufferedWriter output =
                                Files.newBufferedWriter(directory.resolve(name + "-" + slot + ".tsv"))) {
                    output.write(
                            "sequence\tdomain\tscheduled_ns\tstarted_ns\tfinished_ns\te2e_ns\toutcome"
                            + "\taffected_rows\tsql_state\terror_code\tok_info_b64\n");
                    for (int index = slot; index < schedule.length; index += clients.length) {
                        long scheduled = epoch + schedule[index];
                        while (!cancelled && !Files.exists(directory.resolve("stop.json"))
                                && System.nanoTime() < scheduled) {
                            Thread.sleep(0, (int) Math.min(999999, Math.max(1, scheduled - System.nanoTime())));
                        }
                        int domain = base + index;
                        long started = System.nanoTime();
                        String outcome = "NOT_SENT", state = "NONE", info = "";
                        int count = -1, code = 0;
                        boolean sent = false, returned = false;
                        if (!cancelled && !Files.exists(directory.resolve("stop.json"))
                                && started < epoch + (duration + number("drain_seconds")) * BILLION) {
                            try {
                                identity();
                                String sql = operation(domain);
                                sent = true;
                                count = statement.executeUpdate(sql);
                                returned = true;
                                info = ((StatementImpl) statement).getResultSetInternal().getServerInfo();
                                require(info != null && info.length() <= 4096, "ACK_INFO_BOUND");
                                require(count == 100 && field(info, "txnId").matches("[1-9][0-9]{0,18}")
                                                && field(info, "label").matches("[A-Za-z0-9_]{1,128}")
                                                && List.of("VISIBLE", "COMMITTED").contains(field(info, "status")),
                                        "ACK_TRANSACTION_RECEIPT");
                                outcome = "ACK";
                                successes.incrementAndGet();
                            } catch (Exception error) {
                                outcome = returned ? "ACK_INVALID" : sent ? "UNKNOWN" : "ERROR";
                                if (error instanceof SQLException) {
                                    SQLException sql = (SQLException) error;
                                    code = sql.getErrorCode();
                                    if (sql.getSQLState() != null && sql.getSQLState().matches("[A-Za-z0-9]{1,5}")) {
                                        state = sql.getSQLState();
                                    }
                                }
                                if (info == null || info.length() > 4096) {
                                    info = "";
                                }
                                errors.incrementAndGet();
                            }
                        } else {
                            errors.incrementAndGet();
                        }
                        long ended = System.nanoTime();
                        outcomes[domain] = outcome;
                        affected[domain] = count;
                        last.accumulateAndGet(ended, Math::max);
                        output.write(index + "\t" + domain + "\t" + scheduled + "\t" + started + "\t" + ended + "\t"
                                + (ended - scheduled) + "\t" + outcome + "\t" + count + "\t" + state + "\t" + code
                                + "\t" + Base64.getEncoder().encodeToString(info.getBytes(StandardCharsets.UTF_8))
                                + "\n");
                        output.flush();
                    }
                } catch (Exception error) {
                    errors.incrementAndGet();
                }
            }, "dml-" + name + "-" + worker);
            thread.setDaemon(true);
            workers.add(thread);
            active.add(thread);
            thread.start();
        }
        long nextDisk = 0;
        while (System.nanoTime() < epoch + duration * BILLION || active.stream().anyMatch(Thread::isAlive)) {
            identity();
            require(!Files.exists(directory.resolve("stop.json")), "CONTROLLER_CANCELLED");
            if (System.nanoTime() >= nextDisk) {
                disk(name);
                nextDisk = System.nanoTime() + BILLION;
            }
            Thread.sleep(10);
        }
        for (Thread thread : active) {
            thread.join();
        }
        long end = Math.max(epoch + duration * BILLION, last.get());
        publish(name + "-end.json",
                timestamp()
                        .put("epoch_ns", epoch)
                        .put("request_interval_end_ns", end)
                        .put("last_request_end_ns", last.get())
                        .put("scheduled_requests", schedule.length)
                        .put("successful_requests", successes.get())
                        .set("cpu", cpu()));
        require(successes.get() == schedule.length, "REQUEST_FAILURES_RETAINED");
    }

    private void run(boolean cleanupOnly) throws Exception {
        if (cleanupOnly) {
            publish("cleanup.json", timestamp().put("cleanup_confirmed", cleanup()));
            return;
        }
        try {
            inputs();
            prepare();
            stage = "CLOCK_BRIDGE";
            bridge();
            stage = "WARMUP";
            phase("warmup", warmup, 0, number("warmup_seconds"));
            JsonNode warmStart = JSON.readTree(directory.resolve("warmup-start.json").toFile());
            JsonNode warmEnd = JSON.readTree(directory.resolve("warmup-end.json").toFile());
            phaseDeadline = System.nanoTime() + number("coordination_timeout_seconds") * BILLION;
            publish("measurement-ready.json",
                    timestamp()
                            .put("warmup_start_ns", warmStart.path("epoch_ns").asLong())
                            .put("warmup_end_ns", warmEnd.path("java_monotonic_ns").asLong())
                            .put("ready_ns", System.nanoTime()));
            stage = "MEASUREMENT_RELEASE";
            waitMarker("measurement-release.json");
            stage = "MEASUREMENT";
            phase("measurement", measured, warmup.length, number("duration_seconds"));
            summary.put("measurement_complete", true);
        } catch (Exception error) {
            summary.put("failure_class", error.getClass().getSimpleName());
            summary.set("failure_diagnostic", failureRecord(stage, error));
            errors.incrementAndGet();
            if (error instanceof IllegalStateException && error.getMessage().matches("[A-Z0-9_]{1,80}")) {
                summary.put("failure_code", error.getMessage());
            }
        } finally {
            closeWorkers();
            summary.put("workers_closed", workersClosed);
            phaseDeadline = System.nanoTime() + number("verify_timeout_seconds") * BILLION;
            if (workersClosed && Files.exists(directory.resolve("owner.json"))) {
                try {
                    publish("verification-ready.json", timestamp().put("workers_closed", true));
                    stage = "VERIFICATION_RELEASE";
                    waitMarker("verify-release.json");
                    publish("verification-start.json", timestamp());
                    stage = "VERIFICATION_CONNECT";
                    try (Connection oracle = connect("oracle")) {
                        stage = "VERIFICATION_SOURCE_ORACLE";
                        summary.set("source_after", fullSource(oracle));
                        require(summary.path("source_before").equals(summary.path("source_after")), "SOURCE_CHANGED");
                        stage = "VERIFICATION_TARGET_ORACLE";
                        summary.set("target_after", targetModel(oracle, true));
                        summary.put("full_model_verified", true);
                    }
                } catch (Exception error) {
                    errors.incrementAndGet();
                    summary.put("verification_failure_class", error.getClass().getSimpleName());
                    summary.set("verification_failure_diagnostic", failureRecord(stage, error));
                }
            }
            boolean clean = false;
            try {
                stage = "CLEANUP";
                clean = cleanup();
            } catch (Exception error) {
                summary.put("cleanup_failure_class", error.getClass().getSimpleName());
                summary.set("cleanup_failure_diagnostic", failureRecord(stage, error));
            }
            publish("lifecycle.json",
                    timestamp()
                            .put("cleanup_end_ns", System.nanoTime())
                            .put("cleanup_confirmed", clean)
                            .put("workers_closed", workersClosed));
            summary.put("cleanup_confirmed", clean)
                    .put("errors", errors.get())
                    .put("status",
                            errors.get() == 0 && clean && workersClosed
                                            && summary.path("measurement_complete").asBoolean()
                                            && summary.path("full_model_verified").asBoolean()
                                    ? "RAW_WINDOW_COMPLETE"
                                    : "INVALID_WINDOW");
            publish("summary.json", summary);
        }
    }

    public static void main(String[] arguments) throws Exception {
        try {
            LicenseDmlPerformance driver = new LicenseDmlPerformance(Path.of(arguments[0]));
            if (arguments.length == 2 && arguments[1].equals("--plan-only")) {
                driver.inputs();
                return;
            }
            driver.run(arguments.length == 2 && arguments[1].equals("--cleanup-only"));
            if (driver.summary.path("status").asText().equals("INVALID_WINDOW") && arguments.length == 1) {
                System.exit(2);
            }
        } catch (Exception ignored) {
            System.exit(2);
        }
    }
}
