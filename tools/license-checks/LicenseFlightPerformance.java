// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;

/** One G2 Flight window. Reuses the unchanged functional fixture's complete read and close implementation. */
public final class LicenseFlightPerformance {
    private static final ObjectMapper JSON = new ObjectMapper();
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
        require(value.path("profile").asText().equals("g2_flight_v1") && value.path("seed").asLong() == 20260922,
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
        require(value.path("max_requests").asInt() >= 2 && value.path("max_requests").asInt() <= 250000,
                "ARRIVAL_BOUND");
        require(value.path("drain_seconds").asInt() >= 1 && value.path("drain_seconds").asInt() <= 3600,
                "DRAIN_BOUND");
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

    /** Reflection keeps the original private Session/read implementation byte-for-byte unchanged. */
    private static final class Session implements AutoCloseable {
        private static final Class<?> TYPE;
        private static final Constructor<?> CONSTRUCTOR;
        private static final Method READ;
        private static final Method CLOSE;
        private static final Field FRONTEND;
        private static final Field BACKEND;
        static {
            try {
                TYPE = Class.forName("LicenseFlightFixture$Session");
                CONSTRUCTOR = TYPE.getDeclaredConstructor(JsonNode.class);
                READ = TYPE.getDeclaredMethod("read", int.class, String.class, Map.class);
                CLOSE = TYPE.getDeclaredMethod("close");
                FRONTEND = TYPE.getDeclaredField("frontend");
                BACKEND = TYPE.getDeclaredField("backend");
                CONSTRUCTOR.setAccessible(true);
                READ.setAccessible(true);
                CLOSE.setAccessible(true);
                FRONTEND.setAccessible(true);
                BACKEND.setAccessible(true);
            } catch (ReflectiveOperationException error) {
                throw new ExceptionInInitializerError(error);
            }
        }
        private final Object delegate;
        private final Object frontend;
        private Object backend;
        private final int worker;
        private long calls;

        Session(JsonNode configuration, int worker) throws Exception {
            delegate = CONSTRUCTOR.newInstance(configuration);
            frontend = FRONTEND.get(delegate);
            this.worker = worker;
        }

        void read(int batch, Map<String, Object> result) throws Exception {
            require(FRONTEND.get(delegate) == frontend, "FRONTEND_CHANNEL_CHANGED");
            result.put("session_id", worker);
            result.put("session_call", ++calls);
            result.put("fe_execute_calls", 1);
            Object previousBackend = BACKEND.get(delegate);
            try {
                READ.invoke(delegate, batch, MODEL, result);
            } catch (InvocationTargetException error) {
                Throwable cause = error.getCause();
                if (cause instanceof Exception) {
                    throw (Exception) cause;
                }
                throw error;
            }
            Object actual = BACKEND.get(delegate);
            require(actual != null && (backend == null || backend == actual), "BACKEND_CHANNEL_CHANGED");
            backend = actual;
            result.put("backend_channels_created", previousBackend == null ? 1 : 0);
            result.put("frontend_channel_reused", true);
            result.put("backend_channel_reused", true);
            // READ_PASS can only return after the original try-with-resources stream close succeeded.
            require("Schema<id: Int(64, true) not null, payload: Utf8>".equals(result.get("schema")), "EXACT_ARROW_SCHEMA");
            result.put("stream_close_completed", true);
            result.put("complete_model_rows", 1000000);
        }

        public void close() throws Exception {
            CLOSE.invoke(delegate);
        }
    }

    private LicenseFlightPerformance(Path path) throws Exception {
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
        for (String role : List.of("fe", "be")) {
            int port = config.path(role + "_flight_port").asInt();
            require(port > 0 && port < 65536, "INVALID_OWNED_PORT");
        }
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
                            sessions.get(worker).read(profile.path("batch_size").asInt(), receipt);
                            require("READ_PASS".equals(receipt.get("status")), "READ_NOT_VERIFIED");
                            success.incrementAndGet();
                        } catch (Exception error) {
                            failures.incrementAndGet();
                            receipt.put("status", "ERROR");
                            receipt.put("error_class", error.getClass().getName());
                            if (error instanceof IllegalStateException) {
                                receipt.put("assertion", error.getMessage());
                            }
                            if (error instanceof org.apache.arrow.flight.FlightRuntimeException) {
                                receipt.put("flight_error_code", ((org.apache.arrow.flight.FlightRuntimeException) error).status().code().name());
                            }
                            receipt.put("error_code", started > drain ? "NOT_SENT_DRAIN_EXHAUSTED" : "READ_OR_ORACLE_OR_CLOSE_FAILURE");
                        } finally {
                            long end = System.nanoTime();
                            receipt.put("finished_ns", end);
                            receipt.put("e2e_ns", end - scheduled);
                            receipt.put("service_ns", end - started);
                            receipt.put("queue_ns", started - scheduled);
                            last.accumulateAndGet(end, Math::max);
                            output.write(JSON.writeValueAsString(receipt));
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
            }, "flight-worker-" + worker);
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
        try {
            for (int worker = 0; worker < profile.path("concurrency").asInt(); worker++) {
                sessions.add(new Session(config, worker));
                publish("session-" + worker + "-open.json", Map.of("worker", worker, "session_id", worker,
                        "opened_ns", System.nanoTime(), "frontend_channels", 1));
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
                    int backends = Session.BACKEND.get(sessions.get(worker).delegate) == null ? 0 : 1;
                    sessions.get(worker).close();
                    receipt.put("frontend_channels_closed", 1);
                    receipt.put("backend_channels_closed", backends);
                    receipt.put("channels_and_allocator_closed", true);
                } catch (Exception error) {
                    closed = false;
                    receipt.put("channels_and_allocator_closed", false);
                    receipt.put("error_class", error.getClass().getName());
                } finally {
                    receipt.put("close_finished_ns", System.nanoTime());
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
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 2 && args[0].equals("--self-test")) {
            require(Session.READ != null && Session.CLOSE != null, "FIXTURE_REFLECTION_ABI");
            long process = ProcessHandle.current().pid();
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("helper_pid", process);
            evidence.put("helper_start_ticks", ticks(process));
            evidence.put("java_monotonic_ns", System.nanoTime());
            evidence.put("jdk_version", System.getProperty("java.version"));
            evidence.put("namespace", Files.readSymbolicLink(Path.of("/proc/self/ns/net")).toString());
            evidence.put("network_clients_created", 0);
            evidence.put("formal_performance_pass", false);
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
            // Resolving the unchanged fixture's private signatures creates no allocator/channel or network client.
            require(Session.READ != null && Session.CLOSE != null, "FIXTURE_REFLECTION_ABI");
            Files.writeString(output.resolve("plan.json"), "{\"network_clients_created\":0,\"formal_performance_pass\":false}\n");
            return;
        }
        require(args.length == 1, "USAGE_CONFIG_OR_PLAN");
        new LicenseFlightPerformance(Path.of(args[0])).run();
    }
}
