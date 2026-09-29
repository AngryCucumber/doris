// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLTimeoutException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

/** Deterministic open-loop JDBC A/A workload. No database setup or service mutation. */
public final class LicenseJdbcBaseline {
    private static final long POINT_STREAM_SALT = 0xD1B54A32D192ED03L;
    private static final long WARMUP_STREAM_SALT = 0x9E3779B97F4A7C15L;

    private LicenseJdbcBaseline() {
    }

    private static final class Query {
        private final String sql;
        private final boolean prepared;
        private final long expectedRows;
        private final String[] parameters;
        private final boolean point;
        private final String[] pointPayloads;
        private final ResultOracle oracle;

        private Query(String line) throws Exception {
            String[] fields = line.split("\t", -1);
            sql = new String(Base64.getDecoder().decode(fields[0]), StandardCharsets.UTF_8);
            prepared = fields[1].equals("prepared");
            expectedRows = Long.parseLong(fields[2]);
            boolean hasOracle = fields.length > 3 && fields[fields.length - 1].startsWith("o");
            parameters = java.util.Arrays.copyOfRange(fields, 3, fields.length - (hasOracle ? 1 : 0));
            oracle = hasOracle ? new ResultOracle(Base64.getDecoder().decode(
                    fields[fields.length - 1].substring(1))) : null;
            point = false;
            pointPayloads = null;
        }

        private Query(String table, String mode) {
            if (!table.matches("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)?")
                    || !(mode.equals("text") || mode.equals("prepared"))) {
                throw new IllegalArgumentException("Invalid controlled point workload");
            }
            sql = "SELECT payload FROM " + table + " WHERE id = ?";
            prepared = mode.equals("prepared");
            expectedRows = 1;
            parameters = new String[0];
            point = true;
            pointPayloads = new String[1_000_000];
            oracle = null;
        }

        private int preparePointOracle(int[] measured, int[] warmup) throws Exception {
            java.security.MessageDigest md5 = java.security.MessageDigest.getInstance("MD5");
            int unique = 0;
            for (int[] sequence : new int[][] {measured, warmup}) {
                for (int key : sequence) {
                    if (pointPayloads[key] == null) {
                        pointPayloads[key] = java.util.HexFormat.of().formatHex(
                                md5.digest(Integer.toString(key).getBytes(StandardCharsets.US_ASCII)));
                        unique++;
                    }
                }
            }
            return unique;
        }
    }

    private static final class ResultOracle {
        private final boolean ordered;
        private final String[] labels;
        private final int[] types;
        private final List<List<String>> rows = new ArrayList<>();
        private final Map<List<String>, Integer> counts = new LinkedHashMap<>();

        private ResultOracle(byte[] bytes) throws Exception {
            if (bytes.length > 16 * 1024 * 1024) {
                throw new IllegalArgumentException("Result oracle exceeds limit");
            }
            try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes))) {
                ordered = input.readBoolean();
                int columns = input.readInt();
                int rowCount = input.readInt();
                if (columns < 1 || columns > 1024 || rowCount < 0 || rowCount > 100000) {
                    throw new IllegalArgumentException("Invalid result oracle shape");
                }
                labels = new String[columns];
                types = new int[columns];
                for (int i = 0; i < columns; i++) {
                    labels[i] = readString(input);
                    types[i] = input.readInt();
                }
                for (int r = 0; r < rowCount; r++) {
                    List<String> row = new ArrayList<>();
                    for (int c = 0; c < columns; c++) {
                        row.add(readString(input));
                    }
                    rows.add(row);
                    counts.merge(row, 1, Integer::sum);
                }
                if (input.available() != 0) {
                    throw new IllegalArgumentException("Trailing result oracle bytes");
                }
            }
        }

        private static String readString(DataInputStream input) throws Exception {
            int length = input.readInt();
            if (length == -1) {
                return null;
            }
            if (length < 0 || length > input.available()) {
                throw new IllegalArgumentException("Invalid oracle string length");
            }
            return new String(input.readNBytes(length), StandardCharsets.UTF_8);
        }
    }

    private static String quoted(String value) {
        // Values here are Java class names / fixed enums, never SQL or arbitrary server strings.
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String classCounts(Map<String, Long> counts) {
        List<String> values = new ArrayList<>();
        counts.forEach((name, count) -> values.add(quoted(name) + ":" + count));
        return "{" + String.join(",", values) + "}";
    }

    private static final class DriverEvidence {
        private final boolean reuse;
        private final boolean[] prepared;
        private final Statement[] reused;
        private final long[] statements;
        private final long[] warmup;
        private final long[] measured;
        private final List<Map<String, Long>> statementClasses = new ArrayList<>();
        private final Map<String, Long> connectionClasses = new LinkedHashMap<>();
        private String driverClass = "";
        private boolean sameReusedStatement = true;

        private DriverEvidence(boolean reuse, List<Query> queries) {
            this.reuse = reuse;
            prepared = new boolean[queries.size()];
            reused = new Statement[queries.size()];
            statements = new long[queries.size()];
            warmup = new long[queries.size()];
            measured = new long[queries.size()];
            for (int i = 0; i < queries.size(); i++) {
                prepared[i] = queries.get(i).prepared;
                statementClasses.add(new LinkedHashMap<>());
            }
        }

        private void connection(Connection connection, Properties configuration) throws SQLException {
            connectionClasses.merge(connection.getClass().getName(), 1L, Long::sum);
            driverClass = DriverManager.getDriver(configuration.getProperty("url")).getClass().getName();
        }

        private void prepared(int index, Statement statement) {
            statements[index]++;
            statementClasses.get(index).merge(statement.getClass().getName(), 1L, Long::sum);
            if (reuse) {
                if (reused[index] != null && reused[index] != statement) {
                    sameReusedStatement = false;
                }
                reused[index] = statement;
            }
        }

        private void execute(int index, Statement statement, boolean warming) {
            (warming ? warmup : measured)[index]++;
            if (reuse && reused[index] != statement) {
                sameReusedStatement = false;
            }
        }

        private String json(int worker) {
            List<String> queries = new ArrayList<>();
            for (int index = 0; index < prepared.length; index++) {
                queries.add("{\"query_index\":" + index + ",\"prepared\":" + prepared[index]
                        + ",\"statement_count\":" + statements[index] + ",\"warmup_execute_attempts\":"
                        + warmup[index] + ",\"measured_execute_attempts\":" + measured[index]
                        + ",\"same_reused_statement\":" + (reuse && sameReusedStatement)
                        + ",\"statement_classes\":" + classCounts(statementClasses.get(index)) + "}");
            }
            return "{\"worker\":" + worker + ",\"connection_mode\":" + quoted(reuse ? "reuse" : "per_request")
                    + ",\"driver_class\":" + quoted(driverClass) + ",\"connection_classes\":"
                    + classCounts(connectionClasses) + ",\"queries\":[" + String.join(",", queries)
                    + "],\"fe_fast_path_proven\":false,\"harness_retries\":0}";
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 5 && args[0].equals("--schedule-only")) {
            writeSchedule(Path.of(args[4]), poissonSchedule(Double.parseDouble(args[1]),
                    Long.parseLong(args[2]), Long.parseLong(args[3])));
            return;
        }
        if (args.length == 4 && args[0].equals("--point-keys-only")) {
            writeKeys(Path.of(args[3]), pointKeys(Integer.parseInt(args[1]), Long.parseLong(args[2])));
            return;
        }
        Properties configuration = new Properties();
        try (java.io.Reader reader = Files.newBufferedReader(Path.of(args[0]), StandardCharsets.UTF_8)) {
            configuration.load(reader);
        }
        List<Query> queries = new ArrayList<>();
        boolean point = configuration.containsKey("point_table");
        if (point) {
            queries.add(new Query(configuration.getProperty("point_table"), configuration.getProperty("point_mode")));
        } else {
            for (String line : Files.readAllLines(Path.of(configuration.getProperty("queries")))) {
                queries.add(new Query(line));
            }
        }
        if (queries.isEmpty()) {
            throw new IllegalArgumentException("No read queries");
        }
        List<String> sessionSql = new ArrayList<>();
        for (String line : Files.readAllLines(Path.of(configuration.getProperty("session")))) {
            sessionSql.add(new String(Base64.getDecoder().decode(line), StandardCharsets.UTF_8));
        }
        int concurrency = Integer.parseInt(configuration.getProperty("concurrency"));
        double rate = Double.parseDouble(configuration.getProperty("rate"));
        long duration = Long.parseLong(configuration.getProperty("duration_seconds"));
        long warmup = Long.parseLong(configuration.getProperty("warmup_seconds"));
        long seed = Long.parseLong(configuration.getProperty("seed"));
        int timeout = Integer.parseInt(configuration.getProperty("timeout_seconds"));
        long coordination = Long.parseLong(configuration.getProperty("coordination_timeout_seconds", "30"));
        long drain = Long.parseLong(configuration.getProperty("drain_timeout_seconds", "30"));
        if (concurrency <= 0 || concurrency > 1024 || duration <= 0 || warmup < 0
                || timeout <= 0 || coordination <= 0 || drain <= 0) {
            throw new IllegalArgumentException("Invalid bounded workload configuration");
        }
        String connectionMode = configuration.getProperty("connection_mode", "reuse");
        if (!connectionMode.equals("reuse") && !connectionMode.equals("per_request")) {
            throw new IllegalArgumentException("Unknown connection mode");
        }
        boolean perRequest = connectionMode.equals("per_request");
        Path output = Path.of(configuration.getProperty("output"));
        Files.createDirectories(output);
        long[] arrivals = poissonSchedule(rate, duration, seed);
        long[] warmupArrivals = poissonSchedule(rate, warmup, seed ^ 0x5DEECE66DL);
        writeSchedule(output.resolve("arrivals.bin"), arrivals);
        writeSchedule(output.resolve("warmup-arrivals.bin"), warmupArrivals);
        Files.writeString(output.resolve("arrival-count"), String.valueOf(arrivals.length) + "\n");
        long keySeed = point ? Long.parseLong(configuration.getProperty("point_seed")) : 0;
        int[] keys = point ? pointKeys(arrivals.length, keySeed) : null;
        int[] warmupKeys = point ? pointKeys(warmupArrivals.length, keySeed ^ WARMUP_STREAM_SALT) : null;
        if (point) {
            writeKeys(output.resolve("point-keys.bin"), keys);
            writeKeys(output.resolve("warmup-point-keys.bin"), warmupKeys);
            int unique = queries.get(0).preparePointOracle(keys, warmupKeys);
            Files.writeString(output.resolve("point-result-oracle.json"),
                    "{\"algorithm\":\"lowercase_md5_ascii_decimal_id\",\"unique_precomputed_keys\":"
                    + unique + ",\"comparison_inside_request_timing\":true,"
                    + "\"precomputation_before_connections\":true}\n");
        }
        CountDownLatch connectionsReady = new CountDownLatch(concurrency);
        CountDownLatch warmupStart = new CountDownLatch(1);
        CountDownLatch ready = new CountDownLatch(concurrency);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch measuredDone = new CountDownLatch(concurrency);
        CountDownLatch cleanup = new CountDownLatch(1);
        CountDownLatch cleaned = new CountDownLatch(concurrency);
        AtomicLong warmupEpoch = new AtomicLong();
        AtomicLong epoch = new AtomicLong();
        long[] lastRequestEnd = new long[concurrency];
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicBoolean cancelled = new AtomicBoolean();
        List<Thread> workers = new ArrayList<>();
        long gateTimeout = Math.addExact(Math.addExact(warmup, duration), Math.addExact(drain, 4 * coordination));
        for (int worker = 0; worker < concurrency; worker++) {
            final int workerId = worker;
            Thread thread = new Thread(() -> {
                Connection connection = null;
                List<Statement> statements = new ArrayList<>();
                DriverEvidence evidence = new DriverEvidence(!perRequest, queries);
                try (BufferedWriter writer = Files.newBufferedWriter(output.resolve("worker-" + workerId + ".csv"))) {
                    if (!perRequest) {
                        connection = openConnection(configuration, timeout);
                        evidence.connection(connection, configuration);
                        initialize(connection, sessionSql);
                        for (Query query : queries) {
                            Statement statement = prepare(connection, query, timeout);
                            evidence.prepared(statements.size(), statement);
                            statements.add(statement);
                        }
                    }
                    connectionsReady.countDown();
                    awaitGate(warmupStart, gateTimeout, cancelled);
                    for (int index = workerId; index < warmupArrivals.length; index += concurrency) {
                        waitUntil(warmupEpoch.get() + warmupArrivals[index]);
                        int queryIndex = index % queries.size();
                        int key = point ? warmupKeys[index] : -1;
                        RequestResult result = perRequest
                                ? executeNewConnection(configuration, sessionSql, queries.get(queryIndex), timeout, key,
                                        evidence, queryIndex, true)
                                : executeReused(statements.get(queryIndex), queries.get(queryIndex), key,
                                        evidence, queryIndex, true);
                        if (result.error != 0) {
                            publish(output.resolve("warmup-failure-" + workerId + ".json"), "{\"index\":" + index
                                    + ",\"query_index\":" + queryIndex + ",\"error_code\":" + result.error
                                    + ",\"sql_state\":" + quoted(result.state) + ",\"error_class\":"
                                    + quoted(result.errorClass) + ",\"scheduled_ns\":" + warmupArrivals[index]
                                    + ",\"start_ns\":" + (result.start - warmupEpoch.get()) + ",\"end_ns\":"
                                    + (result.end - warmupEpoch.get()) + "}");
                            throw new SQLException("Warmup request failed");
                        }
                    }
                    waitUntil(warmupEpoch.get() + TimeUnit.SECONDS.toNanos(warmup));
                    writer.write("index,query_index,scheduled_ns,start_ns,end_ns,rows,error_code,sql_state,error_class"
                            + (point ? ",point_key" : "")
                            + (perRequest ? ",connection_ns,session_init_ns,prepare_ns,execute_ns,close_ns" : "")
                            + "\n");
                    ready.countDown();
                    awaitGate(start, gateTimeout, cancelled);
                    long last = 0;
                    for (int index = workerId; index < arrivals.length; index += concurrency) {
                        long scheduled = epoch.get() + arrivals[index];
                        waitUntil(scheduled);
                        int queryIndex = index % queries.size();
                        int key = point ? keys[index] : -1;
                        RequestResult result = perRequest
                                ? executeNewConnection(configuration, sessionSql, queries.get(queryIndex), timeout, key,
                                        evidence, queryIndex, false)
                                : executeReused(statements.get(queryIndex), queries.get(queryIndex), key,
                                        evidence, queryIndex, false);
                        last = result.end;
                        writer.write(index + "," + queryIndex + "," + (scheduled - epoch.get()) + ","
                                + (result.start - epoch.get()) + "," + (result.end - epoch.get()) + ","
                                + result.rows + "," + result.error + "," + result.state + "," + result.errorClass
                                + (point ? "," + key : "")
                                + (perRequest ? "," + result.connectionNanos + "," + result.sessionNanos + ","
                                        + result.prepareNanos + "," + result.executeNanos + ","
                                        + result.closeNanos : "")
                                + "\n");
                    }
                    lastRequestEnd[workerId] = last;
                    measuredDone.countDown();
                    // Keep reused connections/statements alive, and do not flush/close the CSV,
                    // until the coordinator has captured CPU and acknowledged the end boundary.
                    awaitGate(cleanup, gateTimeout, cancelled);
                } catch (Throwable exception) {
                    failure.compareAndSet(null, exception);
                } finally {
                    try {
                        for (Statement statement : statements) {
                            try {
                                statement.close();
                            } catch (SQLException exception) {
                                failure.compareAndSet(null, exception);
                            }
                        }
                        if (connection != null) {
                            connection.close();
                        }
                    } catch (Throwable exception) {
                        failure.compareAndSet(null, exception);
                    } finally {
                        try {
                            publish(output.resolve("driver-worker-" + workerId + ".json"), evidence.json(workerId));
                        } catch (Throwable exception) {
                            failure.compareAndSet(null, exception);
                        }
                        cleaned.countDown();
                    }
                }
            }, "license-baseline-" + worker);
            // A broken JDBC driver must not keep the process alive after the bounded coordinator fails.
            thread.setDaemon(true);
            workers.add(thread);
            thread.start();
        }
        String phase = "connections";
        try {
            awaitWorkers(connectionsReady, coordination, failure);
            phase = "clock_handshake";
            clockHandshake(configuration, output, coordination, failure);
            warmupEpoch.set(System.nanoTime());
            warmupStart.countDown();
            phase = "warmup";
            awaitWorkers(ready, Math.addExact(warmup, drain), failure);
            long warmupEnd = System.nanoTime();
            phase = "start_ack";
            String warmupReceipt = configuration.containsKey("p4_launch")
                    ? ",\"warmup_start_ns\":" + warmupEpoch.get() + ",\"warmup_end_ns\":" + warmupEnd
                            + ",\"launch_token\":" + quoted(configuration.getProperty("p4_launch_token"))
                            + ",\"launch_sha256\":" + quoted(configuration.getProperty("p4_launch_sha256")) : "";
            publish(output.resolve("measurement-ready.json"), "{\"ready_ns\":" + System.nanoTime()
                    + warmupReceipt + "}");
            awaitMarker(output.resolve("measurement-start-ack"), coordination, failure);
            // /proc sampling is performed in this JVM so the recorded CPU boundaries and request
            // timestamps use the same monotonic clock. Python provides the trusted PID/HZ inputs.
            String cpuStart = sampleServices(configuration);
            epoch.set(System.nanoTime());
            start.countDown();
            publish(output.resolve("measurement-start.json"), "{\"epoch_ns\":" + epoch.get()
                    + ",\"cpu\":" + cpuStart + "}");
            // Retain the existence marker consumed by older read-only run monitors.
            Files.writeString(output.resolve("measurement-start"), "ready\n");
            phase = "requests";
            awaitWorkers(measuredDone, Math.addExact(duration, drain), failure);
            waitUntil(epoch.get() + TimeUnit.SECONDS.toNanos(duration));
            long last = Arrays.stream(lastRequestEnd).max().orElse(0);
            long intervalEnd = Math.max(epoch.get() + TimeUnit.SECONDS.toNanos(duration), last);
            String cpuEnd = sampleServices(configuration);
            long measuredEnd = System.nanoTime();
            publish(output.resolve("measurement-end.json"), "{\"epoch_ns\":" + epoch.get()
                    + ",\"last_request_end_ns\":" + last + ",\"request_interval_end_ns\":" + intervalEnd
                    + ",\"measurement_end_ns\":" + measuredEnd + ",\"cpu\":" + cpuEnd + "}");
            phase = "end_ack";
            awaitMarker(output.resolve("measurement-end-ack"), coordination, failure);
            long cleanupStart = System.nanoTime();
            cleanup.countDown();
            phase = "cleanup";
            awaitWorkers(cleaned, coordination, failure);
            publish(output.resolve("lifecycle.json"), "{\"completed\":true,\"cleanup_start_ns\":"
                    + cleanupStart + ",\"cleanup_end_ns\":" + System.nanoTime() + "}");
        } catch (Throwable exception) {
            publish(output.resolve("client-failure.json"), "{\"phase\":\"" + phase
                    + "\",\"exception\":\"" + exception.getClass().getSimpleName() + "\"}");
            // Do not print SQL, connection URLs, credentials, or server error messages.
            throw new IllegalStateException("Baseline client failed in " + phase + ": "
                    + exception.getClass().getSimpleName());
        } finally {
            cancelled.set(true);
            warmupStart.countDown();
            start.countDown();
            cleanup.countDown();
            for (Thread worker : workers) {
                worker.interrupt();
            }
        }
    }

    private static String sha256(Path path) throws Exception {
        return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest(Files.readAllBytes(path)));
    }

    private static void requireClock(boolean valid) {
        if (!valid) {
            throw new IllegalStateException("Invalid lifecycle handshake");
        }
    }

    private static Properties clockProperties(Path path, long deadline, AtomicReference<Throwable> failure)
            throws Exception {
        while (!Files.exists(path)) {
            if (failure.get() != null || System.nanoTime() >= deadline) {
                throw new java.util.concurrent.TimeoutException("Lifecycle handshake expired");
            }
            Thread.sleep(2);
        }
        Properties value = new Properties();
        try (java.io.InputStream stream = Files.newInputStream(path)) {
            value.load(stream);
        }
        requireClock(System.nanoTime() < deadline);
        return value;
    }

    private static void clockHandshake(Properties configuration, Path output, long seconds,
            AtomicReference<Throwable> failure) throws Exception {
        if (!configuration.containsKey("p4_launch")) {
            return;
        }
        Path launch = Path.of(configuration.getProperty("p4_launch"));
        String token = configuration.getProperty("p4_launch_token");
        String digest = configuration.getProperty("p4_launch_sha256");
        String boot = Files.readString(Path.of("/proc/sys/kernel/random/boot_id")).trim();
        requireClock(token != null && token.matches("[a-f0-9]{64}") && digest != null
                && digest.matches("[a-f0-9]{64}") && sha256(launch).equals(digest)
                && boot.equals(configuration.getProperty("p4_boot_id")));
        long pid = ProcessHandle.current().pid();
        String stat = Files.readString(Path.of("/proc/self/stat"));
        long ticks = Long.parseLong(stat.substring(stat.lastIndexOf(')') + 1).trim().split("\\s+")[19]);
        String identity = "{\"schema_version\":1,\"launch_token\":" + quoted(token)
                + ",\"launch_sha256\":" + quoted(digest) + ",\"boot_id\":" + quoted(boot)
                + ",\"helper_pid\":" + pid + ",\"helper_start_ticks\":" + ticks;
        String readyNonce = java.util.UUID.randomUUID().toString();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
        publish(output.resolve("p4-clock-ready.json"), identity + ",\"ready_nonce\":" + quoted(readyNonce) + "}");
        Properties request = clockProperties(output.resolve("p4-clock-request.properties"), deadline, failure);
        for (String key : new String[] {"p4_launch", "p4_launch_token", "p4_launch_sha256", "p4_boot_id"}) {
            requireClock(configuration.getProperty(key).equals(request.getProperty(key)));
        }
        String nonce = request.getProperty("nonce");
        requireClock(readyNonce.equals(request.getProperty("ready_nonce"))
                && nonce != null && nonce.matches("[a-f0-9]{64}"));
        long sample = System.nanoTime();
        Path helperClock = output.resolve("p4-helper-clock.json");
        publish(helperClock, identity + ",\"nonce\":" + quoted(nonce) + ",\"jvm_sample_ns\":" + sample + "}");
        Properties ack = clockProperties(output.resolve("p4-clock-ack.properties"), deadline, failure);
        for (String key : request.stringPropertyNames()) {
            requireClock(request.getProperty(key).equals(ack.getProperty(key)));
        }
        requireClock(sha256(helperClock).equals(ack.getProperty("helper_clock_sha256"))
                && sha256(output.resolve("p4-clock-bridge.json")).equals(ack.getProperty("bridge_sha256"))
                && sha256(launch).equals(digest) && System.nanoTime() < deadline);
    }

    private static void publish(Path path, String json) throws Exception {
        Path temporary = path.resolveSibling(path.getFileName() + ".tmp");
        Files.writeString(temporary, json + "\n");
        Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    private static void awaitGate(CountDownLatch latch, long seconds, AtomicBoolean cancelled) throws Exception {
        if (!latch.await(seconds, TimeUnit.SECONDS) || cancelled.get()) {
            throw new java.util.concurrent.TimeoutException("Worker gate closed");
        }
    }

    private static void awaitWorkers(CountDownLatch latch, long seconds, AtomicReference<Throwable> failure)
            throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
        while (!latch.await(10, TimeUnit.MILLISECONDS)) {
            if (failure.get() != null) {
                throw new IllegalStateException("Worker failed");
            }
            if (System.nanoTime() >= deadline) {
                throw new java.util.concurrent.TimeoutException("Worker deadline elapsed");
            }
        }
        if (failure.get() != null) {
            throw new IllegalStateException("Worker failed");
        }
    }

    private static void awaitMarker(Path marker, long seconds, AtomicReference<Throwable> failure) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
        while (!Files.exists(marker)) {
            if (failure.get() != null || System.nanoTime() >= deadline) {
                throw new java.util.concurrent.TimeoutException("Coordinator acknowledgement missing");
            }
            Thread.sleep(2);
        }
    }

    private static String sampleServices(Properties configuration) throws Exception {
        long ticks = Long.parseLong(configuration.getProperty("clock_ticks_per_second"));
        long pageSize = Long.parseLong(configuration.getProperty("page_size"));
        StringBuilder result = new StringBuilder("{");
        for (String name : new String[] {"fe", "be"}) {
            long pid = Long.parseLong(configuration.getProperty(name + "_pid"));
            long before = System.nanoTime();
            String stat = Files.readString(Path.of("/proc", String.valueOf(pid), "stat"));
            long after = System.nanoTime();
            String[] fields = stat.substring(stat.lastIndexOf(')') + 1).trim().split("\\s+");
            if (result.length() > 1) {
                result.append(',');
            }
            result.append('"').append(name).append("\":{")
                    .append("\"cpu_seconds\":").append((Long.parseLong(fields[11]) + Long.parseLong(fields[12]))
                            / (double) ticks)
                    .append(",\"rss_bytes\":").append(Long.parseLong(fields[21]) * pageSize)
                    .append(",\"start_ticks\":").append(Long.parseLong(fields[19]))
                    .append(",\"sample_started_ns\":").append(before)
                    .append(",\"sample_ended_ns\":").append(after).append('}');
        }
        return result.append('}').toString();
    }

    private static Connection openConnection(Properties configuration, int timeout) throws SQLException {
        Properties properties = new Properties();
        properties.setProperty("user", configuration.getProperty("user"));
        properties.setProperty("password", System.getenv().getOrDefault("MASSDB_BASELINE_PASSWORD", ""));
        properties.setProperty("useServerPrepStmts", "true");
        properties.setProperty("connectTimeout", "10000");
        properties.setProperty("socketTimeout", String.valueOf(timeout * 1000L));
        return DriverManager.getConnection(configuration.getProperty("url"), properties);
    }

    private static void initialize(Connection connection, List<String> sessionSql) throws SQLException {
        for (String sql : sessionSql) {
            try (Statement statement = connection.createStatement()) {
                statement.execute(sql);
            }
        }
    }

    private static Statement prepare(Connection connection, Query query, int timeout) throws SQLException {
        Statement statement = query.prepared ? connection.prepareStatement(query.sql) : connection.createStatement();
        statement.setQueryTimeout(timeout);
        if (query.prepared) {
            PreparedStatement prepared = (PreparedStatement) statement;
            for (int index = 0; index < query.parameters.length; index++) {
                String value = query.parameters[index];
                switch (value.charAt(0)) {
                    case 'i': prepared.setLong(index + 1, Long.parseLong(value.substring(1))); break;
                    case 's': prepared.setString(index + 1, new String(Base64.getDecoder().decode(value.substring(1)),
                            StandardCharsets.UTF_8)); break;
                    case 'n': prepared.setNull(index + 1, java.sql.Types.NULL); break;
                    default: throw new IllegalArgumentException("Unsupported parameter type");
                }
            }
        }
        return statement;
    }

    private static RequestResult executeReused(Statement statement, Query query, int key,
            DriverEvidence evidence, int queryIndex, boolean warming) {
        RequestResult result = new RequestResult();
        result.start = System.nanoTime();
        try {
            evidence.execute(queryIndex, statement, warming);
            result.rows = execute(statement, query, key);
            if (result.rows != query.expectedRows) {
                result.error = -1;
                result.state = "ROWS";
                result.errorClass = "RESULT_MISMATCH";
            }
        } catch (SQLException exception) {
            result.fail(exception);
        }
        result.end = System.nanoTime();
        return result;
    }

    private static final class RequestResult {
        long start;
        long end;
        long rows = -1;
        int error;
        String state = "00000";
        String errorClass = "NONE";
        long connectionNanos;
        long sessionNanos;
        long prepareNanos;
        long executeNanos;
        long closeNanos;

        void fail(SQLException exception) {
            if (error == 0) {
                error = exception.getErrorCode() == 0 ? -2 : exception.getErrorCode();
                state = String.valueOf(exception.getSQLState()).replaceAll("[^A-Za-z0-9]", "_");
                errorClass = exception instanceof SQLTimeoutException || state.equals("HYT00")
                        || state.equals("HYT01") || state.equals("S1T00") ? "SQL_TIMEOUT"
                        : state.equals("VALUE") ? "RESULT_MISMATCH"
                        : state.startsWith("08") ? "CONNECTION_ERROR" : "SQL_ERROR";
            }
        }
    }

    private static RequestResult executeNewConnection(Properties configuration, List<String> sessionSql,
            Query query, int timeout, int key, DriverEvidence evidence, int queryIndex, boolean warming) {
        RequestResult result = new RequestResult();
        result.start = System.nanoTime();
        Connection connection = null;
        Statement statement = null;
        long phaseStart = result.start;
        int phase = 0;
        try {
            connection = openConnection(configuration, timeout);
            evidence.connection(connection, configuration);
            result.connectionNanos = System.nanoTime() - phaseStart;
            phaseStart = System.nanoTime();
            phase = 1;
            initialize(connection, sessionSql);
            result.sessionNanos = System.nanoTime() - phaseStart;
            phaseStart = System.nanoTime();
            phase = 2;
            statement = prepare(connection, query, timeout);
            evidence.prepared(queryIndex, statement);
            result.prepareNanos = System.nanoTime() - phaseStart;
            phaseStart = System.nanoTime();
            phase = 3;
            evidence.execute(queryIndex, statement, warming);
            result.rows = execute(statement, query, key);
            result.executeNanos = System.nanoTime() - phaseStart;
            phase = 4;
            if (result.rows != query.expectedRows) {
                result.error = -1;
                result.state = "ROWS";
                result.errorClass = "RESULT_MISMATCH";
            }
        } catch (SQLException exception) {
            long failedPhaseNanos = System.nanoTime() - phaseStart;
            switch (phase) {
                case 0: result.connectionNanos = failedPhaseNanos; break;
                case 1: result.sessionNanos = failedPhaseNanos; break;
                case 2: result.prepareNanos = failedPhaseNanos; break;
                case 3: result.executeNanos = failedPhaseNanos; break;
                default: break;
            }
            result.fail(exception);
        } finally {
            long closeStart = System.nanoTime();
            try {
                if (statement != null) {
                    statement.close();
                }
            } catch (SQLException exception) {
                result.fail(exception);
            }
            try {
                if (connection != null) {
                    connection.close();
                }
            } catch (SQLException exception) {
                result.fail(exception);
            }
            result.closeNanos = System.nanoTime() - closeStart;
            result.end = System.nanoTime();
        }
        return result;
    }

    private static void waitUntil(long scheduled) throws InterruptedException {
        long left;
        while ((left = scheduled - System.nanoTime()) > 0) {
            if (Thread.interrupted()) {
                throw new InterruptedException();
            }
            LockSupport.parkNanos(left);
        }
    }

    private static long[] poissonSchedule(double rate, long durationSeconds, long seed) {
        if (!Double.isFinite(rate) || rate <= 0 || rate > 100000 || durationSeconds < 0) {
            throw new IllegalArgumentException("Invalid arrival rate or duration");
        }
        long durationNanos = Math.multiplyExact(durationSeconds, 1_000_000_000L);
        Random random = new Random(seed);
        long[] arrivals = new long[1024];
        int count = 0;
        double elapsedNanos = 0;
        while (true) {
            double uniform;
            do {
                uniform = random.nextDouble();
            } while (uniform == 0);
            elapsedNanos += -StrictMath.log(uniform) * 1_000_000_000.0 / rate;
            if (elapsedNanos >= durationNanos) {
                return Arrays.copyOf(arrivals, count);
            }
            if (count >= 10_000_000) {
                throw new IllegalArgumentException("Schedule exceeds the declared client memory bound");
            }
            if (count == arrivals.length) {
                arrivals = Arrays.copyOf(arrivals, Math.min(10_000_000, arrivals.length * 2));
            }
            arrivals[count++] = (long) elapsedNanos;
        }
    }

    private static void writeSchedule(Path path, long[] arrivals) throws Exception {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        try (DataOutputStream stream = new DataOutputStream(new BufferedOutputStream(
                new java.security.DigestOutputStream(Files.newOutputStream(path), digest)))) {
            for (long offset : arrivals) {
                stream.writeLong(offset);
            }
        }
        Files.writeString(path.resolveSibling(path.getFileName() + ".sha256"),
                HexFormat.of().formatHex(digest.digest()) + "\n");
    }

    private static int[] pointKeys(int count, long seed) {
        if (count < 0 || count > 10_000_000) {
            throw new IllegalArgumentException("Invalid point key count");
        }
        Random random = new Random(seed ^ POINT_STREAM_SALT);
        int[] keys = new int[count];
        for (int index = 0; index < count; index++) {
            keys[index] = random.nextInt(1_000_000);
        }
        return keys;
    }

    private static void writeKeys(Path path, int[] keys) throws Exception {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        try (DataOutputStream stream = new DataOutputStream(new BufferedOutputStream(
                new java.security.DigestOutputStream(Files.newOutputStream(path), digest)))) {
            for (int key : keys) {
                stream.writeInt(key);
            }
        }
        Files.writeString(path.resolveSibling(path.getFileName() + ".sha256"),
                HexFormat.of().formatHex(digest.digest()) + "\n");
    }

    private static long execute(Statement statement, Query query, int key) throws SQLException {
        String sql = query.sql;
        if (query.point) {
            if (key < 0 || key >= 1_000_000) {
                throw new IllegalArgumentException("Point key out of range");
            }
            if (query.prepared) {
                ((PreparedStatement) statement).setLong(1, key);
            } else {
                sql = query.sql.substring(0, query.sql.length() - 1) + key;
            }
        }
        boolean hasRows = query.prepared ? ((PreparedStatement) statement).execute() : statement.execute(sql);
        long rows = 0;
        if (!hasRows && query.oracle != null) {
            throw new SQLException("Expected a result set", "VALUE", -3);
        }
        if (hasRows) {
            try (ResultSet result = statement.getResultSet()) {
                int columns = result.getMetaData().getColumnCount();
                if (query.point && columns != 1) {
                    throw new SQLException("Point result must contain exactly one payload column", "VALUE", -3);
                }
                ResultOracle oracle = query.oracle;
                Map<List<String>, Integer> remaining = oracle != null && !oracle.ordered
                        ? new LinkedHashMap<>(oracle.counts) : null;
                if (oracle != null) {
                    if (columns != oracle.labels.length) {
                        throw new SQLException("Result column count differs from oracle", "VALUE", -3);
                    }
                    for (int column = 1; column <= columns; column++) {
                        if (!Objects.equals(oracle.labels[column - 1], result.getMetaData().getColumnLabel(column))
                                || oracle.types[column - 1] != result.getMetaData().getColumnType(column)) {
                            throw new SQLException("Result column structure differs from oracle", "VALUE", -3);
                        }
                    }
                }
                while (result.next()) {
                    if (oracle != null && rows >= oracle.rows.size()) {
                        throw new SQLException("Unexpected additional result row", "VALUE", -3);
                    }
                    List<String> actual = remaining == null ? null : new ArrayList<>(columns);
                    for (int column = 1; column <= columns; column++) {
                        Object value = oracle == null ? result.getObject(column) : result.getString(column);
                        if (query.point && (query.pointPayloads[key] == null
                                || !query.pointPayloads[key].equals(value))) {
                            throw new SQLException("Point payload differs from the deterministic key model", "VALUE", -3);
                        }
                        if (oracle != null) {
                            if (actual != null) {
                                actual.add((String) value);
                            } else if (!Objects.equals(oracle.rows.get((int) rows).get(column - 1), value)) {
                                throw new SQLException("Result value differs from oracle", "VALUE", -3);
                            }
                        }
                    }
                    if (actual != null) {
                        Integer count = remaining.get(actual);
                        if (count == null || count == 0) {
                            throw new SQLException("Unordered result row differs from oracle", "VALUE", -3);
                        }
                        if (count == 1) {
                            remaining.remove(actual);
                        } else {
                            remaining.put(actual, count - 1);
                        }
                    }
                    rows++;
                }
                if (oracle != null && (rows != oracle.rows.size() || remaining != null && !remaining.isEmpty())) {
                    throw new SQLException("Missing expected result rows", "VALUE", -3);
                }
            }
        }
        return rows;
    }
}
