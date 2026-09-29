// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/** Explicit current G2 entry: original SQL/DDL/workers; no timed query-ID, Profile or EXPLAIN SQL. */
public final class LicenseComplexPerformance {
    private LicenseComplexPerformance() {
    }

    static void initializeSession(Connection connection, boolean cached, int timeout) throws Exception {
        for (String sql : List.of("SET enable_sql_cache=" + cached,
                "SET enable_query_cache=false", "SET enable_short_circuit_query=false", "SET enable_profile=false")) {
            try (Statement statement = connection.createStatement()) {
                statement.setQueryTimeout(timeout);
                LicenseComplexPlanningFixture.require(!statement.execute(sql), "P4_SESSION_SET_RETURNED_ROWS");
            }
        }
    }

    static final class Runner extends LicenseComplexPlanningFixture.Runner {
        final JsonNode launch;
        final String launchHash;
        final String token;
        final int coordination;
        final Map<String, Long> lastFinished = new java.util.concurrent.ConcurrentHashMap<>();

        Runner(LicenseComplexPlanningFixture.Config config) throws Exception {
            super(config);
            JsonNode binding = config.raw.path("p4_launch");
            byte[] bytes = Files.readAllBytes(Path.of(binding.path("path").asText()));
            launchHash = LicenseComplexPlanningFixture.sha(bytes);
            LicenseComplexPlanningFixture.require(launchHash.equals(binding.path("sha256").asText()), "P4_LAUNCH_HASH");
            launch = LicenseComplexPlanningFixture.JSON.readTree(bytes);
            token = launch.path("launch_token").asText();
            coordination = LicenseComplexPlanningFixture.integer(config.raw, "coordination_timeout_seconds", 10, 1800);
            LicenseComplexPlanningFixture.require(token.matches("[a-f0-9]{32}")
                    && config.raw.path("qualification").asText().matches("formal|diagnostic"), "P4_LAUNCH_MODE");
            LicenseComplexPlanningFixture.require(config.raw.path("qualification").asText().equals("diagnostic")
                    || config.warmupSeconds >= 180 && config.windowSeconds >= 600, "P4_FORMAL_DURATION");
        }

        Map<String, Object> receipt() throws Exception {
            Map<String, Object> value = new LinkedHashMap<>();
            value.put("schema_version", 1);
            value.put("launch_token", token);
            value.put("launch_sha256", launchHash);
            value.put("boot_id", launch.path("boot_id").asText());
            value.put("pid", ProcessHandle.current().pid());
            value.put("start_ticks", LicenseComplexPlanningFixture.startTicks(ProcessHandle.current().pid()));
            value.put("namespace", config.namespace);
            value.put("clock_domain", config.clockDomain);
            value.put("java_monotonic_ns", System.nanoTime());
            return value;
        }

        void publish(String name, Map<String, Object> value) throws Exception {
            Path destination = config.output.resolve(name);
            LicenseComplexPlanningFixture.require(!Files.exists(destination), "P4_DUPLICATE_RECEIPT");
            Path temporary = config.output.resolve(name + ".tmp");
            LicenseComplexPlanningFixture.writeNew(temporary, value);
            Files.move(temporary, destination, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        }

        JsonNode waitMarker(String name) throws Exception {
            Path path = config.output.resolve(name);
            while (!Files.exists(path)) {
                check();
                Thread.sleep(10);
            }
            JsonNode value = LicenseComplexPlanningFixture.JSON.readTree(Files.readAllBytes(path));
            LicenseComplexPlanningFixture.require(value.path("token").asText().equals(token), "P4_MARKER_TOKEN");
            return value;
        }

        void bridge() throws Exception {
            phaseDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(coordination);
            JsonNode request = waitMarker("clock-request.json");
            long sample = System.nanoTime();
            String nonce = request.path("nonce").asText();
            LicenseComplexPlanningFixture.require(nonce.matches("[a-f0-9]{32}"), "P4_CLOCK_NONCE");
            Map<String, Object> value = receipt();
            value.put("nonce", nonce);
            value.put("jvm_sample_ns", sample);
            value.put("helper_pid", ProcessHandle.current().pid());
            value.put("helper_start_ticks", LicenseComplexPlanningFixture.startTicks(ProcessHandle.current().pid()));
            publish("p4-helper-clock.json", value);
            LicenseComplexPlanningFixture.require(waitMarker("clock-ack.json").path("nonce").asText().equals(nonce),
                    "P4_CLOCK_ACK");
        }

        Map<String, Object> cpu() throws Exception {
            Map<String, Object> values = new LinkedHashMap<>();
            int ticks = LicenseComplexPlanningFixture.integer(config.raw, "clock_ticks_per_second", 1, 1000000);
            for (String role : List.of("fe", "be")) {
                JsonNode pin = config.raw.path("cpu_services").path(role);
                long before = System.nanoTime();
                String stat = Files.readString(Path.of("/proc", pin.path("pid").asText(), "stat"));
                String[] fields = stat.substring(stat.lastIndexOf(')') + 1).trim().split("\\s+");
                long after = System.nanoTime();
                LicenseComplexPlanningFixture.require(!Set.of("Z", "X").contains(fields[0])
                        && Long.parseLong(fields[19]) == pin.path("start_ticks").asLong(), "P4_CPU_LIFETIME");
                values.put(role, Map.of("pid", pin.path("pid").asLong(), "start_ticks", Long.parseLong(fields[19]),
                        "cpu_seconds", (Long.parseLong(fields[11]) + Long.parseLong(fields[12])) / (double) ticks,
                        "sample_started_java_ns", before, "sample_ended_java_ns", after));
            }
            return values;
        }

        @Override
        void initialize(Connection connection) throws Exception {
            initializeSession(connection, config.caseId.equals("LP-007"), config.timeout);
        }

        @SuppressWarnings("unchecked")
        void verifyValues(Map<String, Object> record) {
            List<Map<String, String>> columns = (List<Map<String, String>>) record.get("columns");
            List<List<String>> rows = (List<List<String>>) record.get("rows");
            LicenseComplexPlanningFixture.require(columns.size() == 33 && rows.size() == 1, "P4_ORACLE_SHAPE");
            boolean initial = true;
            boolean changed = true;
            for (int index = 0; index < 33; index++) {
                String name = config.definition.path("columns").get(index).asText();
                String value = rows.get(0).get(index);
                LicenseComplexPlanningFixture.require(columns.get(index).get("name").equals(name)
                        && Set.of("BIGINT", "LARGEINT", "INTEGER", "INT", "SMALLINT", "TINYINT", "DECIMAL", "NUMERIC")
                           .contains(columns.get(index).get("type").toUpperCase(java.util.Locale.ROOT))
                        && value != null && value.matches("0|-?[1-9][0-9]*"), "P4_ORACLE_COLUMN_OR_INTEGER");
                initial &= value.equals(config.definition.path("initial").path(name).asText());
                changed &= value.equals(config.definition.path("changed").path(name).asText());
            }
            long start = (long) record.get("started_ns");
            long end = (long) record.get("finished_ns");
            Long begun = eventStarted;
            Long acknowledged = eventAck;
            boolean permitted = begun == null || end < begun ? initial
                    : acknowledged != null && start > acknowledged ? changed : initial || changed;
            LicenseComplexPlanningFixture.require(permitted, "P4_FULL_RESULT_MODEL");
            record.put("online_model", initial ? "initial" : "changed");
            record.put("columns_verified", 33);
        }

        @Override
        void request(int worker, String phase, int index, long scheduled,
                Connection reused, Statement reusable) throws Exception {
            check();
            long id = serial.incrementAndGet();
            Map<String, Object> value = receipt();
            value.put("request_id", id);
            value.put("worker", worker);
            value.put("phase", phase);
            value.put("arrival_index", index);
            value.put("scheduled_ns", scheduled);
            value.put("request_started_ns", System.nanoTime());
            value.put("query_sha256_utf8", LicenseComplexPlanningFixture.QUERY_SHA);
            value.put("connection_mode", config.connectionMode);
            value.put("success", false);
            value.put("timed_auxiliary_query_count", 0);
            for (String name : List.of("connection_ns", "session_init_ns", "prepare_ns", "close_ns")) value.put(name, 0L);
            starts.append(Map.of("request_id", id, "worker", worker, "phase", phase, "arrival_index", index,
                    "scheduled_ns", scheduled, "request_started_ns", value.get("request_started_ns"),
                    "clock_domain", config.clockDomain));
            Connection connection = reused;
            Statement statement = reusable;
            try {
                if (connection == null) {
                    long begin = System.nanoTime();
                    connection = connect(false, false);
                    value.put("connection_ns", System.nanoTime() - begin);
                    begin = System.nanoTime();
                    initialize(connection);
                    value.put("session_init_ns", System.nanoTime() - begin);
                    begin = System.nanoTime();
                    statement = prepare(connection);
                    value.put("prepare_ns", System.nanoTime() - begin);
                }
                LicenseComplexPlanningFixture.executeTarget(statement, config.query, false, value);
                verifyValues(value);
                value.put("success", true);
            } catch (Exception error) {
                value.putAll(LicenseComplexPlanningFixture.error(error));
                fail("performance_request_failure");
            } finally {
                if (reused == null) {
                    long begin = System.nanoTime();
                    try {
                        if (statement != null) statement.close();
                        close(connection);
                    } catch (Exception error) {
                        value.putAll(LicenseComplexPlanningFixture.error(error));
                        value.put("success", false);
                        fail("performance_connection_close_failure");
                    }
                    value.put("close_ns", System.nanoTime() - begin);
                }
                long ended = System.nanoTime();
                value.put("request_finished_ns", ended);
                lastFinished.merge(phase, ended, Math::max);
                requests.append(value);
                completed.incrementAndGet();
            }
            check();
        }

        void beginPhase(String name, long phaseEpoch, Map<String, Object> firstCpu) throws Exception {
            Map<String, Object> value = receipt();
            value.put("epoch_ns", phaseEpoch);
            value.put("cpu", firstCpu);
            publish(name + "-start.json", value);
        }

        void endPhase(String name, long phaseEpoch, int seconds) throws Exception {
            long last = lastFinished.getOrDefault(name, phaseEpoch);
            long end = Math.max(last, phaseEpoch + TimeUnit.SECONDS.toNanos(seconds));
            Map<String, Object> value = receipt();
            value.put("epoch_ns", phaseEpoch);
            value.put("last_request_end_ns", last);
            value.put("request_interval_end_ns", end);
            value.put("cpu", cpu());
            publish(name + "-end.json", value);
        }

        @Override
        void run() throws Exception {
            phaseDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(coordination);
            Map<String, Object> identity = receipt();
            identity.put("performance_profile", "g2_complex_performance_v1");
            identity.put("query_sha256_utf8", LicenseComplexPlanningFixture.QUERY_SHA);
            identity.put("arrival_sha256", config.arrivalSha);
            identity.put("definition_sha256", config.definitionSha);
            identity.put("java_runtime_version", System.getProperty("java.runtime.version"));
            identity.put("mode", "text");
            identity.put("connection_mode", config.connectionMode);
            identity.put("concurrency", config.concurrency);
            identity.put("profile_enabled", false);
            identity.put("timed_query_identity_or_explain_queries", 0);
            publish("identity.json", identity);
            admin = connect(true, false);
            Map<String, Object> before = LicenseComplexPlanningFixture.showCreate(admin, config.timeout);
            publish("preflight.json", before);
            LicenseComplexPlanningFixture.require(before.get("sha256_utf8").equals(config.initialViewSha), "P4_VIEW_OWNER");
            for (int index = 0; index < config.concurrency; index++) {
                final int worker = index;
                workers.submit(() -> worker(worker));
            }
            await(ready);
            publish("ready.json", receipt());
            bridge();
            Map<String, Object> firstCpu = cpu();
            warmupEpoch = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500);
            phaseDeadline = warmupEpoch + TimeUnit.SECONDS.toNanos(config.warmupSeconds + config.drain);
            beginPhase("warmup", warmupEpoch, firstCpu);
            warmupGate.countDown();
            await(warmupDone);
            waitUntil(warmupEpoch + TimeUnit.SECONDS.toNanos(config.warmupSeconds));
            endPhase("warmup", warmupEpoch, config.warmupSeconds);
            phaseDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(coordination);
            publish("measurement-ready.json", receipt());
            waitMarker("measurement-release.json");
            firstCpu = cpu();
            epoch = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500);
            phaseDeadline = epoch + TimeUnit.SECONDS.toNanos(config.windowSeconds + config.drain);
            beginPhase("measurement", epoch, firstCpu);
            if (config.caseId.equals("LP-007")) administration.submit(this::event);
            else {
                publish("event.json", Map.of("clock_domain", config.clockDomain, "ddl_attempted", false,
                        "ddl_success", false, "status", "NOT_APPLICABLE_COLD"));
                eventDone.countDown();
            }
            measurementGate.countDown();
            await(measuredDone);
            waitUntil(epoch + TimeUnit.SECONDS.toNanos(config.windowSeconds));
            await(eventDone);
            endPhase("measurement", epoch, config.windowSeconds);
        }
    }

    public static void main(String[] args) throws Exception {
        LicenseComplexPlanningFixture.require(args.length == 1, "ONE_CONFIG_REQUIRED");
        LicenseComplexPlanningFixture.Config config = new LicenseComplexPlanningFixture.Config(Path.of(args[0]), true);
        Runner runner = new Runner(config);
        Thread hook = new Thread(() -> runner.finish("signal_or_jvm_shutdown"), "complex-performance-shutdown");
        Runtime.getRuntime().addShutdownHook(hook);
        Thread watchdog = new Thread(() -> {
            while (!runner.finalized.get()) {
                try {
                    Thread.sleep(250);
                    if (runner.finalized.get()) return;
                    runner.check();
                    config.guard();
                } catch (Exception error) {
                    if (runner.finalized.get()) return;
                    runner.fail("performance_watchdog");
                    runner.abortOwned();
                    return;
                }
            }
        }, "complex-performance-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
        String reason = "normal";
        try {
            runner.run();
        } catch (Exception error) {
            reason = "performance_" + error.getClass().getSimpleName();
        } finally {
            runner.finish(reason);
            Map<String, Object> finalReceipt = runner.receipt();
            finalReceipt.put("success", !runner.failed.get());
            finalReceipt.put("workers_closed", runner.connections.isEmpty());
            runner.publish("p4-helper-finished.json", finalReceipt);
            Runtime.getRuntime().removeShutdownHook(hook);
        }
        if (runner.failed.get()) System.exit(2);
    }
}
