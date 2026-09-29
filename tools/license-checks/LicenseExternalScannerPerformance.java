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
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;

/** One G3 fresh FE-plan plus complete original BE scanner operation per scheduled request. */
public final class LicenseExternalScannerPerformance {
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    private static final long BILLION = 1_000_000_000L;
    private static final String MODEL = "d07f615ccea4c0f21cc4a7505c400a0b47d454eaa06521092e607aa646c21a68";
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
            Thread thread = new Thread(task, "scanner-http-deadline");
            thread.setDaemon(true);
            return thread;
        });
        result.setRemoveOnCancelPolicy(true);
        return result;
    }
    private final Set<String> contexts = ConcurrentHashMap.newKeySet();
    private final AtomicLong privateBytes = new AtomicLong();
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
        require(value.path("profile").asText().equals("g3_scanner_v1") && value.path("seed").asLong() == 20260922,
                "FIXED_PROFILE");
        require(value.path("batch_size").asInt() == 1024 || value.path("batch_size").asInt() == 8192, "BATCH_SIZE");
        require(value.path("concurrency").asInt() == 1 || value.path("concurrency").asInt() == 8, "CONCURRENCY");
        require(value.path("warmup_seconds").asInt() >= 1 && value.path("warmup_seconds").asInt() <= 7200
                && value.path("duration_seconds").asInt() >= 1 && value.path("duration_seconds").asInt() <= 86400,
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
        require(value.path("max_private_plan_bytes").asLong() >= 1048576
                && value.path("max_private_plan_bytes").asLong() <= 2147483648L
                && value.path("max_raw_ledger_bytes").asLong() >= 1048576
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

    /** One persistent FE HTTP connection manager and explicit scanner registry per worker. */
    private static final class Session implements AutoCloseable {
        private final JsonNode configuration;
        private final int worker;
        private final LicenseExternalScannerFixture.HandleRegistry handles = new LicenseExternalScannerFixture.HandleRegistry();
        private final org.apache.http.impl.conn.BasicHttpClientConnectionManager manager;
        private final org.apache.http.impl.client.CloseableHttpClient http;
        private final Set<String> contexts;
        private final Path output;
        private final AtomicLong privateBytes;
        private final long privateLimit;
        private int generation;
        private long calls;
        private volatile org.apache.http.client.methods.HttpPost activeRequest;
        private Map<String, Object> cleanup = Map.of("cleanup_verified", false);

        Session(JsonNode configuration, int worker, Set<String> contexts, Path output, AtomicLong privateBytes) throws Exception {
            this.configuration = configuration;
            this.worker = worker;
            this.contexts = contexts;
            this.output = output;
            this.privateBytes = privateBytes;
            privateLimit = configuration.path("profile").path("max_private_plan_bytes").asLong();
            org.apache.http.conn.socket.PlainConnectionSocketFactory sockets = new org.apache.http.conn.socket.PlainConnectionSocketFactory() {
                @Override
                public java.net.Socket connectSocket(int timeout, java.net.Socket socket, org.apache.http.HttpHost host,
                        java.net.InetSocketAddress remote, java.net.InetSocketAddress local,
                        org.apache.http.protocol.HttpContext context) throws java.io.IOException {
                    require(host.getHostName().equals("127.0.0.1")
                            && host.getPort() == configuration.path("fe_http_port").asInt(), "UNOWNED_FE_SOCKET");
                    java.net.Socket actual = super.connectSocket(timeout, socket, host, remote, local, context);
                    generation++;
                    return actual;
                }
            };
            manager = new org.apache.http.impl.conn.BasicHttpClientConnectionManager(
                    org.apache.http.config.RegistryBuilder.<org.apache.http.conn.socket.ConnectionSocketFactory>create()
                            .register("http", sockets).build());
            manager.setConnectionConfig(org.apache.http.config.ConnectionConfig.custom().setMessageConstraints(
                    org.apache.http.config.MessageConstraints.custom().setMaxHeaderCount(64).setMaxLineLength(16384).build()).build());
            http = org.apache.http.impl.client.HttpClients.custom().setConnectionManager(manager)
                    .disableAutomaticRetries().disableRedirectHandling().disableCookieManagement().disableContentCompression()
                    .setRoutePlanner(new org.apache.http.impl.conn.DefaultRoutePlanner(org.apache.http.impl.conn.DefaultSchemePortResolver.INSTANCE))
                    .setDefaultRequestConfig(org.apache.http.client.config.RequestConfig.custom()
                            .setConnectTimeout(5000).setSocketTimeout(5000).setConnectionRequestTimeout(5000).build()).build();
            require(System.getenv(configuration.path("password_env").asText()) != null, "EXPLICIT_PASSWORD_ENV_REQUIRED");
        }

        private JsonNode freshPlan(Map<String, Object> result, String phase, int sequence, long operationDeadline) throws Exception {
            int beforeGeneration = generation;
            long started = System.nanoTime();
            long deadline = Math.min(operationDeadline, started + 15 * BILLION);
            org.apache.http.client.methods.HttpPost request = new org.apache.http.client.methods.HttpPost(
                    "http://127.0.0.1:" + configuration.path("fe_http_port").asInt()
                            + "/api/license_perf/point_rows/_query_plan");
            String credential = configuration.path("user").asText() + ":"
                    + System.getenv(configuration.path("password_env").asText());
            request.setHeader("Authorization", "Basic " + java.util.Base64.getEncoder()
                    .encodeToString(credential.getBytes(StandardCharsets.UTF_8)));
            request.setHeader("Content-Type", "application/json");
            request.setHeader("Connection", "keep-alive");
            request.setEntity(new org.apache.http.entity.StringEntity(
                    "{\"sql\":\"SELECT id,payload FROM license_perf.point_rows\"}", StandardCharsets.UTF_8));
            activeRequest = request;
            result.put("fe_plan_requests", 1);
            result.put("fe_request_started_ns", started);
            java.util.concurrent.ScheduledFuture<?> cancel = TIMERS.schedule(request::abort,
                    Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            try (org.apache.http.client.methods.CloseableHttpResponse response = http.execute(request)) {
                result.put("fe_http_status", response.getStatusLine().getStatusCode());
                require(response.getStatusLine().getStatusCode() == 200, "FE_HTTP_NOT_200");
                require(response.getEntity() != null, "FE_BODY_ABSENT");
                byte[] raw;
                try (java.io.InputStream body = response.getEntity().getContent()) {
                    raw = body.readNBytes(2 * 1024 * 1024 + 1);
                    result.put("fe_response_bytes_read", raw.length);
                    if (raw.length > 2 * 1024 * 1024) {
                        request.abort(); // Do not drain an oversized untrusted body while returning the connection.
                        require(false, "FE_BODY_SIZE_BOUND");
                    }
                }
                require(raw.length <= 2 * 1024 * 1024 && System.nanoTime() < deadline, "FE_BODY_BOUND_OR_TIMEOUT");
                require(privateBytes.addAndGet(raw.length) <= privateLimit, "PRIVATE_PLAN_ARCHIVE_BOUND");
                Path privateFile = output.resolve(phase + "-" + worker + "-" + sequence + "-plan.private.json");
                Files.createFile(privateFile, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                        java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")));
                Files.write(privateFile, raw);
                result.put("fe_response_private", Map.of("name", privateFile.getFileName().toString(), "sha256", sha(raw), "bytes", raw.length));
                JsonNode body = JSON.readTree(raw);
                require(body.path("code").isInt() && body.path("code").asInt() == 0
                        && body.path("data").path("status").isInt()
                        && body.path("data").path("status").asInt() == 200, "FE_BUSINESS_STATUS");
                JsonNode data = body.path("data");
                require(data.path("opaqued_query_plan").isTextual(), "OPAQUE_PLAN_NOT_STRING");
                String opaque = data.path("opaqued_query_plan").asText();
                require(!opaque.isEmpty() && opaque.length() <= 2 * 1024 * 1024
                        && java.util.Base64.getDecoder().decode(opaque).length > 0, "INVALID_OPAQUE_PLAN");
                JsonNode partitions = data.path("partitions");
                require(partitions.isObject() && partitions.size() == 16, "EXPECTED_16_TABLETS");
                List<Long> ids = new ArrayList<>();
                java.util.Iterator<String> keys = partitions.fieldNames();
                while (keys.hasNext()) {
                    String key = keys.next();
                    require(key.matches("[1-9][0-9]*"), "INVALID_TABLET_ID");
                    long id = Long.parseLong(key);
                    JsonNode routes = partitions.path(key).path("routings");
                    require(id > 0 && routes.isArray() && routes.size() == 1
                            && routes.get(0).asText().equals("127.0.0.1:" + configuration.path("be_port").asInt()), "UNOWNED_TABLET_ROUTE");
                    ids.add(id);
                }
                java.util.Collections.sort(ids);
                com.fasterxml.jackson.databind.node.ObjectNode scan = configuration.deepCopy();
                scan.put("opaque_plan", opaque);
                com.fasterxml.jackson.databind.node.ArrayNode tablets = scan.putArray("tablets");
                for (long id : ids) {
                    tablets.addObject().put("tablet_id", id).put("host", "127.0.0.1").put("port", configuration.path("be_port").asInt());
                }
                scan.put("expected_sha256", MODEL);
                scan.set("service_pins", JSON.valueToTree(List.of(configuration.path("services").path("fe"),
                        configuration.path("services").path("be"))));
                result.put("fe_business_code", 0);
                result.put("fe_data_status", 200);
                result.put("fe_plan_sha256", sha(opaque.getBytes(StandardCharsets.US_ASCII)));
                result.put("fe_tablet_ids", ids);
                require(System.nanoTime() < deadline, "FE_PLAN_DEADLINE_EXCEEDED");
                return scan;
            } finally {
                cancel.cancel(false);
                activeRequest = null;
                result.put("fe_request_finished_ns", System.nanoTime());
                result.put("http_connection_generation", generation);
                result.put("http_transport_reused", beforeGeneration > 0 && generation == beforeGeneration);
                result.put("fe_deadline_exceeded", System.nanoTime() >= deadline);
            }
        }

        void read(int batch, Map<String, Object> result, String phase, int sequence) throws Exception {
            result.put("session_id", worker);
            result.put("session_call", ++calls);
            long deadline = ((Number) result.get("started_ns")).longValue() + 120 * BILLION;
            result.put("dispatch_deadline_ns", deadline);
            try {
                JsonNode scan = freshPlan(result, phase, sequence, deadline);
                LicenseExternalScannerFixture.scanOnce(scan, batch, contexts, result, deadline, handles, true);
                require(System.nanoTime() < deadline, "DISPATCH_DEADLINE_EXCEEDED");
                result.put("scanner_close_verified", true);
            } finally {
                result.put("dispatch_deadline_exceeded", System.nanoTime() >= deadline);
            }
        }

        public void close() throws Exception {
            cleanup = handles.closeOwned();
            try {
                http.close();
            } finally {
                manager.close();
            }
            require(Boolean.TRUE.equals(cleanup.get("cleanup_verified")), "SCANNER_CONTEXT_CLEANUP_UNKNOWN");
        }

        void abortOwned() {
            org.apache.http.client.methods.HttpPost request = activeRequest;
            if (request != null) {
                request.abort();
            }
            cleanup = handles.closeOwned();
        }
    }

    private LicenseExternalScannerPerformance(Path path) throws Exception {
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
        for (String portName : List.of("fe_http_port", "be_port")) {
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
        if (error instanceof java.net.SocketTimeoutException || error instanceof java.util.concurrent.TimeoutException
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
                            sessions.get(worker).read(profile.path("batch_size").asInt(), receipt, phase, sequence);
                            require("READ_PASS".equals(receipt.get("status")), "READ_NOT_VERIFIED");
                            success.incrementAndGet();
                        } catch (Exception error) {
                            failures.incrementAndGet();
                            receipt.put("status", "ERROR");
                            receipt.put("error_class", error.getClass().getName());
                            receipt.put("timeout", timeout(error, 0)
                                    || Boolean.TRUE.equals(receipt.get("fe_deadline_exceeded"))
                                    || Boolean.TRUE.equals(receipt.get("dispatch_deadline_exceeded")));
                            if (error instanceof IllegalStateException) {
                                receipt.put("assertion", error.getMessage());
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
            }, "scanner-worker-" + worker);
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
                Thread cleanupThread = new Thread(session::abortOwned, "scanner-shutdown-owned-context");
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
        }, "scanner-window-owned-cleanup");
        Runtime.getRuntime().addShutdownHook(shutdown);
        try {
            for (int worker = 0; worker < profile.path("concurrency").asInt(); worker++) {
                sessions.add(new Session(config, worker, contexts, directory, privateBytes));
                publish("session-" + worker + "-open.json", Map.of("worker", worker, "session_id", worker,
                        "opened_ns", System.nanoTime(), "http_connection_managers", 1));
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
                    receipt.put("http_connection_managers_closed", 1);
                    receipt.put("http_and_contexts_closed", true);
                } catch (Exception error) {
                    closed = false;
                    receipt.put("http_and_contexts_closed", false);
                    receipt.put("error_class", error.getClass().getName());
                } finally {
                    receipt.put("close_finished_ns", System.nanoTime());
                    receipt.put("scanner_registry", sessions.get(worker).cleanup);
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
            require(LicenseExternalScannerFixture.HandleRegistry.class != null, "SCANNER_OPERATION_ABI");
            long process = ProcessHandle.current().pid();
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("helper_pid", process);
            evidence.put("helper_start_ticks", ticks(process));
            evidence.put("java_monotonic_ns", System.nanoTime());
            evidence.put("jdk_version", System.getProperty("java.version"));
            evidence.put("namespace", Files.readSymbolicLink(Path.of("/proc/self/ns/net")).toString());
            evidence.put("unopened_socket_test_objects", 2);
            evidence.put("formal_performance_pass", false);
            LicenseExternalScannerFixture.HandleRegistry first = new LicenseExternalScannerFixture.HandleRegistry();
            LicenseExternalScannerFixture.HandleRegistry second = new LicenseExternalScannerFixture.HandleRegistry();
            require(Boolean.TRUE.equals(first.closeOwned().get("cleanup_verified")), "EMPTY_REGISTRY_NOT_CLEAN");
            first.submitted();
            require(Boolean.TRUE.equals(first.closeOwned().get("unknown_open"))
                    && Boolean.FALSE.equals(first.closeOwned().get("cleanup_verified")), "UNKNOWN_OPEN_WAS_CLEARED");
            require(Boolean.TRUE.equals(second.closeOwned().get("cleanup_verified")), "WORKER_REGISTRIES_ALIAS");
            boolean rejected = false;
            try {
                first.submitted();
            } catch (IllegalStateException expected) {
                rejected = true;
            }
            require(rejected, "UNKNOWN_CONTEXT_ALLOWED_NEW_OPEN");
            evidence.put("registry_checks", List.of("empty_clean", "unknown_open_sticky", "independent_workers", "unconfirmed_reopen_rejected"));
            evidence.put("bounded_checks", LicenseExternalScannerFixture.boundedSelfTest());
            evidence.put("network_connections_opened", 0);
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
            require(LicenseExternalScannerFixture.HandleRegistry.class != null, "SCANNER_OPERATION_ABI");
            Files.writeString(output.resolve("plan.json"), "{\"network_clients_created\":0,\"formal_performance_pass\":false}\n");
            return;
        }
        require(args.length == 1, "USAGE_CONFIG_OR_PLAN");
        new LicenseExternalScannerPerformance(Path.of(args[0])).run();
    }

    public static void main(String[] args) {
        try {
            entry(args);
        } catch (Throwable error) {
            // Remote Thrift/HTTP exceptions can contain opaque plans. Never print exception messages or stacks.
            System.err.println("{\"status\":\"INVALID_WINDOW\",\"error_class\":\"" + error.getClass().getName() + "\"}");
            System.exit(2);
        }
    }
}
