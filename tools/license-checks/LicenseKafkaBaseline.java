// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.admin.OffsetSpec;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.Metric;
import org.apache.kafka.common.MetricName;
import org.apache.kafka.common.TopicPartition;

import java.io.BufferedWriter;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** One real Kafka JVM across a visibility barrier; no JDBC results or Kafka ACKs are synthesized. */
public final class LicenseKafkaBaseline {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int PARTITIONS = 8;
    private static final long MEASURE_ROWS = 10000000L;
    private static final long WARM_ROWS = 3000000L;
    private static final long SECOND = 1000000000L;
    private final JsonNode config;
    private final Path output;
    private final String clock = "System.nanoTime:" + UUID.randomUUID();
    private final AtomicReference<Throwable> failure = new AtomicReference<>();
    private final CountDownLatch ready;
    private final CountDownLatch warmGo = new CountDownLatch(1);
    private final CountDownLatch warmDone;
    private final CountDownLatch measureGo = new CountDownLatch(1);
    private final CountDownLatch measureDone;
    private final List<Map<String, Object>> metrics = Collections.synchronizedList(new ArrayList<>());
    private volatile long warmEpoch;
    private volatile long measureEpoch;

    private LicenseKafkaBaseline(JsonNode config) throws Exception {
        this.config = config;
        output = Paths.get(config.path("output").asText()).toRealPath();
        Path root = Paths.get(config.path("checkout").asText()).toRealPath().resolve(".build-records");
        int workers = config.path("workers").asInt();
        int batch = config.path("batch_rows").asInt();
        String ns = Files.readSymbolicLink(Paths.get("/proc/self/ns/net")).toString();
        if (!output.startsWith(root) || !ns.equals(config.path("namespace").asText())
                || ns.equals(config.path("host_namespace").asText())
                || !System.getProperty("java.runtime.version").equals("17.0.4+8")
                || !org.apache.kafka.common.utils.AppInfoParser.getVersion().equals("3.9.2")
                || !(workers == 1 || workers == 8 || workers == 32) || !(batch == 1000 || batch == 10000)
                || !config.path("topic").asText().matches("lp013_[a-f0-9]{16}")
                || !config.path("bootstrap").asText().matches("127\\.0\\.0\\.1:[0-9]{4,5}")
                || !config.path("owner_token").asText().matches("[a-f0-9]{32}")) {
            throw new IllegalArgumentException("Unowned namespace/path or unfrozen Kafka/JDK/load shape");
        }
        ready = new CountDownLatch(workers);
        warmDone = new CountDownLatch(workers);
        measureDone = new CountDownLatch(workers);
    }

    private Map<String, Object> receipt() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("schema_version", 1);
        value.put("clock_domain", clock);
        value.put("owner_token", config.path("owner_token").asText());
        value.put("configuration_sha256", config.path("configuration_sha256").asText());
        value.put("java_runtime", System.getProperty("java.runtime.version"));
        value.put("kafka_client_version", org.apache.kafka.common.utils.AppInfoParser.getVersion());
        return value;
    }

    private void save(String name, Map<String, Object> value) throws Exception {
        Path temporary = output.resolve(name + ".tmp");
        Files.write(temporary, JSON.writeValueAsBytes(value), StandardOpenOption.CREATE_NEW);
        Files.move(temporary, output.resolve(name), StandardCopyOption.ATOMIC_MOVE);
    }

    private Properties properties() {
        Properties value = new Properties();
        value.setProperty("bootstrap.servers", config.path("bootstrap").asText());
        value.setProperty("security.protocol", "PLAINTEXT");
        value.setProperty("request.timeout.ms", "10000");
        value.setProperty("default.api.timeout.ms", "30000");
        return value;
    }

    private List<TopicPartition> partitions() {
        List<TopicPartition> result = new ArrayList<>();
        for (int p = 0; p < PARTITIONS; p++) {
            result.add(new TopicPartition(config.path("topic").asText(), p));
        }
        return result;
    }

    private Map<String, Long> offsets(boolean beginning) throws Exception {
        Map<TopicPartition, OffsetSpec> request = new LinkedHashMap<>();
        for (TopicPartition partition : partitions()) {
            request.put(partition, beginning ? OffsetSpec.earliest() : OffsetSpec.latest());
        }
        Map<String, Long> result = new LinkedHashMap<>();
        AdminClient admin = AdminClient.create(properties());
        Throwable primary = null;
        try {
            admin.listOffsets(request).all().get(35, TimeUnit.SECONDS).forEach((p, v) ->
                    result.put(Integer.toString(p.partition()), v.offset()));
        } catch (Exception | Error error) {
            primary = error;
            throw error;
        } finally {
            closeBounded(() -> admin.close(Duration.ofSeconds(5)), primary);
        }
        return result;
    }

    private static void expectOffsets(Map<String, Long> values, long rows) {
        if (values.size() != PARTITIONS || values.values().stream().anyMatch(v -> v != rows / PARTITIONS)) {
            throw new IllegalStateException("Actual physical offset range differs from the fixed input");
        }
    }

    private void initialize() throws Exception {
        AdminClient admin = AdminClient.create(properties());
        Throwable primary = null;
        try {
            NewTopic topic = new NewTopic(config.path("topic").asText(), PARTITIONS, (short) 1);
            topic.configs(Collections.singletonMap("cleanup.policy", "delete"));
            admin.createTopics(Collections.singletonList(topic)).all().get(60, TimeUnit.SECONDS);
            org.apache.kafka.clients.admin.TopicDescription actual = admin.describeTopics(
                    Collections.singletonList(topic.name())).allTopicNames().get(30, TimeUnit.SECONDS).get(topic.name());
            if (actual.partitions().size() != PARTITIONS
                    || actual.partitions().stream().anyMatch(p -> p.replicas().size() != 1)) {
                throw new IllegalStateException("Unexpected actual topic shape");
            }
        } catch (Exception | Error error) {
            primary = error;
            throw error;
        } finally {
            closeBounded(() -> admin.close(Duration.ofSeconds(5)), primary);
        }
        Map<String, Object> value = receipt();
        Map<String, Long> start = offsets(true);
        Map<String, Long> end = offsets(false);
        expectOffsets(start, 0);
        expectOffsets(end, 0);
        value.put("begin_offsets", start);
        value.put("end_offsets_exclusive", end);
        save("kafka-init.json", value);
    }

    private void checkpoint() throws Exception {
        if (Thread.currentThread().isInterrupted() || failure.get() != null || Files.exists(output.resolve("stop"))) {
            throw new InterruptedException("Cancelled or a worker failed; no application replay");
        }
    }

    private void until(long deadline) throws Exception {
        while (System.nanoTime() < deadline) {
            checkpoint();
            TimeUnit.NANOSECONDS.sleep(Math.min(10000000L, Math.max(1, deadline - System.nanoTime())));
        }
        checkpoint();
    }

    private void await(CountDownLatch latch, long deadline) throws Exception {
        while (latch.getCount() != 0) {
            checkpoint();
            if (System.nanoTime() >= deadline) {
                throw new IllegalStateException("Bounded phase/visibility/cleanup deadline expired");
            }
            latch.await(10, TimeUnit.MILLISECONDS);
        }
        checkpoint();
    }

    private static long identifier(long index, long rows, long base) {
        long multiplier = (20260922L * 2 + 1) % rows;
        while (gcd(multiplier, rows) != 1) {
            multiplier = (multiplier + 2) % rows;
        }
        return base + (index * multiplier + 20260922L % rows) % rows;
    }

    private static long gcd(long a, long b) {
        while (b != 0) {
            long remainder = a % b;
            a = b;
            b = remainder;
        }
        return a;
    }

    private static void closeBounded(Runnable close, Throwable primary) {
        try {
            close.run();
        } catch (RuntimeException | Error cleanup) {
            if (primary == null) {
                throw cleanup;
            }
            primary.addSuppressed(cleanup);
        }
    }

    private static String digest(byte[] bytes) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(bytes)) {
            result.append(Character.forDigit((b & 255) >>> 4, 16));
            result.append(Character.forDigit(b & 15, 16));
        }
        return result.toString();
    }

    private static final class Pending {
        private final long index;
        private final long id;
        private final String hash;
        private final long sent;
        private volatile long ack;
        private final CompletableFuture<RecordMetadata> future = new CompletableFuture<>();

        private Pending(long index, long id, String hash, long sent) {
            this.index = index;
            this.id = id;
            this.hash = hash;
            this.sent = sent;
        }
    }

    private void phase(String phase, int worker, KafkaProducer<String, String> producer,
            BufferedWriter acks, BufferedWriter batches) throws Exception {
        boolean warm = phase.equals("warmup");
        long rows = warm ? WARM_ROWS : MEASURE_ROWS;
        long base = warm ? MEASURE_ROWS : 0;
        long epoch = warm ? warmEpoch : measureEpoch;
        long duration = (warm ? 180L : 600L) * SECOND;
        int batchRows = config.path("batch_rows").asInt();
        int workers = config.path("workers").asInt();
        Path input = Paths.get(config.path(phase + "_input").asText()).toRealPath();
        Path root = Paths.get(config.path("checkout").asText()).toRealPath().resolve(".build-records");
        if (!input.startsWith(root) || Files.size(input) != rows * 128L) {
            throw new IllegalStateException("Input path or byte size differs from the fixed phase");
        }
        try (RandomAccessFile source = new RandomAccessFile(input.toFile(), "r")) {
            for (long batch = worker; batch < rows / batchRows; batch += workers) {
                long scheduled = epoch + batch * duration / (rows / batchRows);
                until(scheduled);
                long started = System.nanoTime();
                long deadline = scheduled + 60L * SECOND;
                Map<String, Object> value = receipt();
                value.put("phase", phase);
                value.put("batch_index", batch);
                value.put("worker", worker);
                value.put("scheduled_ns", scheduled);
                value.put("started_ns", started);
                value.put("rows", batchRows);
                int acknowledged = 0;
                List<Pending> pending = new ArrayList<>();
                try {
                    if (started >= deadline) {
                        throw new IllegalStateException("Offered batch missed its sixty-second total deadline");
                    }
                    source.seek(batch * batchRows * 128L);
                    for (long index = batch * batchRows; index < (batch + 1) * batchRows; index++) {
                        checkpoint();
                        if (System.nanoTime() >= deadline) {
                            throw new IllegalStateException("Batch send deadline expired");
                        }
                        byte[] bytes = new byte[128];
                        source.readFully(bytes);
                        String row = new String(bytes, 0, 127, StandardCharsets.US_ASCII);
                        long id = Long.parseLong(row.substring(0, row.indexOf(',')));
                        if (bytes[127] != '\n' || id != identifier(index, rows, base)) {
                            throw new IllegalStateException("Input order/ID/width changed");
                        }
                        Pending item = new Pending(index, id, digest(row.getBytes(StandardCharsets.US_ASCII)),
                                System.nanoTime());
                        pending.add(item);
                        producer.send(new ProducerRecord<>(config.path("topic").asText(), (int) (id % 8),
                                Long.toString(id), row), (metadata, error) -> {
                                    item.ack = System.nanoTime();
                                    if (error == null) {
                                        item.future.complete(metadata);
                                    } else {
                                        item.future.completeExceptionally(error);
                                    }
                                });
                    }
                    for (Pending item : pending) {
                        checkpoint();
                        long remaining = deadline - System.nanoTime();
                        if (remaining <= 0) {
                            throw new IllegalStateException("Batch acknowledgement deadline expired");
                        }
                        RecordMetadata metadata = item.future.get(remaining, TimeUnit.NANOSECONDS);
                        if (metadata.partition() != item.id % 8 || metadata.offset() < 0 || item.ack > deadline) {
                            throw new IllegalStateException("Invalid/late broker acknowledgement");
                        }
                        acks.write(phase + "," + item.index + "," + item.id + "," + worker + "," + batch
                                + "," + metadata.partition() + "," + metadata.offset() + "," + item.sent
                                + "," + item.ack + "," + item.hash + "\n");
                        acknowledged++;
                    }
                    value.put("success", true);
                } catch (Throwable error) {
                    value.put("success", false);
                    value.put("commit_state", "UNKNOWN_OR_PARTIAL_ACK_NO_REPLAY");
                    value.put("error_class", error.getClass().getName());
                    throw error;
                } finally {
                    value.put("finished_ns", System.nanoTime());
                    value.put("acknowledged_rows", acknowledged);
                    value.put("sent_rows", pending.size());
                    batches.write(JSON.writeValueAsString(value));
                    batches.newLine();
                    batches.flush();
                    acks.flush();
                }
            }
        }
    }

    private void worker(int worker) {
        Properties settings = properties();
        settings.setProperty("client.id", "lp013-baseline-" + worker);
        settings.setProperty("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        settings.setProperty("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        settings.setProperty("acks", "all");
        settings.setProperty("enable.idempotence", "true");
        settings.setProperty("max.in.flight.requests.per.connection", "1");
        settings.setProperty("compression.type", "none");
        settings.setProperty("delivery.timeout.ms", "30000");
        settings.setProperty("max.block.ms", "10000");
        settings.setProperty("buffer.memory", "2097152");
        settings.setProperty("linger.ms", "0");
        KafkaProducer<String, String> producer = null;
        try (BufferedWriter acks = Files.newBufferedWriter(output.resolve("acks-" + worker + ".csv"),
                StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
                BufferedWriter batches = Files.newBufferedWriter(output.resolve("batches-" + worker + ".jsonl"),
                        StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW)) {
            acks.write("phase,index,id,worker,batch_index,partition,offset,sent_ns,ack_ns,value_sha256\n");
            producer = new KafkaProducer<>(settings);
            ready.countDown();
            await(warmGo, System.nanoTime() + 120L * SECOND);
            phase("warmup", worker, producer, acks, batches);
            warmDone.countDown();
            await(measureGo, System.nanoTime() + 720L * SECOND);
            phase("measurement", worker, producer, acks, batches);
            Map<String, Object> values = new LinkedHashMap<>();
            values.put("worker", worker);
            for (Map.Entry<MetricName, ? extends Metric> item : producer.metrics().entrySet()) {
                String name = item.getKey().name();
                if (item.getKey().group().equals("producer-metrics") && (name.equals("record-error-total")
                        || name.equals("record-retry-total") || name.equals("record-send-total"))) {
                    values.put(name, item.getValue().metricValue());
                }
            }
            metrics.add(values);
            measureDone.countDown();
        } catch (Throwable error) {
            failure.compareAndSet(null, error);
        } finally {
            if (producer != null) {
                try {
                    producer.close(Duration.ofSeconds(5));
                } catch (Throwable error) {
                    failure.compareAndSet(null, error);
                }
            }
        }
    }

    private void produce() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(config.path("workers").asInt(), runnable -> {
            Thread thread = new Thread(runnable, "lp013-baseline-producer");
            thread.setDaemon(true);
            return thread;
        });
        Map<String, Object> summary = receipt();
        boolean success = false;
        try {
            for (int worker = 0; worker < config.path("workers").asInt(); worker++) {
                final int id = worker;
                pool.submit(() -> worker(id));
            }
            await(ready, System.nanoTime() + 60L * SECOND);
            warmEpoch = System.nanoTime() + 2L * SECOND;
            Map<String, Object> start = receipt();
            start.put("warmup_start_ns", warmEpoch);
            start.put("warmup_end_ns", warmEpoch + 180L * SECOND);
            save("warmup-start.json", start);
            warmGo.countDown();
            await(warmDone, warmEpoch + 300L * SECOND);
            until(warmEpoch + 180L * SECOND);
            Map<String, Long> end = offsets(false);
            expectOffsets(end, WARM_ROWS);
            Map<String, Object> barrier = receipt();
            barrier.put("warmup_start_ns", warmEpoch);
            barrier.put("completed_ns", System.nanoTime());
            barrier.put("end_offsets_exclusive", end);
            barrier.put("acknowledged_rows", WARM_ROWS);
            save("warmup-complete.json", barrier);
            long visibilityDeadline = System.nanoTime() + 600L * SECOND;
            while (!Files.exists(output.resolve("measurement-go.json"))) {
                checkpoint();
                if (System.nanoTime() >= visibilityDeadline) {
                    throw new IllegalStateException("Warmup visibility barrier was never acknowledged");
                }
                TimeUnit.MILLISECONDS.sleep(50);
            }
            Path goPath = output.resolve("measurement-go.json");
            if (Files.isSymbolicLink(goPath) || Files.size(goPath) > 4096) {
                throw new IllegalStateException("Invalid barrier file");
            }
            JsonNode go = JSON.readTree(goPath.toFile());
            if (!go.path("owner_token").asText().equals(config.path("owner_token").asText())
                    || !go.path("configuration_sha256").asText().equals(config.path("configuration_sha256").asText())
                    || !go.path("warmup_visible").asBoolean() || !go.path("clock_domain").asText().equals(clock)) {
                throw new IllegalStateException("Visibility barrier belongs to a different run");
            }
            measureEpoch = System.nanoTime() + 2L * SECOND;
            Map<String, Object> measured = receipt();
            measured.put("warmup_start_ns", warmEpoch);
            measured.put("measurement_start_ns", measureEpoch);
            measured.put("measurement_end_ns", measureEpoch + 600L * SECOND);
            measured.put("barrier_received_ns", System.nanoTime());
            measured.put("warmup_end_offsets_exclusive", end);
            save("measurement-start.json", measured);
            measureGo.countDown();
            await(measureDone, measureEpoch + 720L * SECOND);
            until(measureEpoch + 600L * SECOND);
            Map<String, Long> finalOffsets = offsets(false);
            expectOffsets(finalOffsets, MEASURE_ROWS + WARM_ROWS);
            summary.put("end_offsets_exclusive", finalOffsets);
            summary.put("warmup_rows", WARM_ROWS);
            summary.put("measurement_rows", MEASURE_ROWS);
            summary.put("warmup_start_ns", warmEpoch);
            summary.put("measurement_start_ns", measureEpoch);
            success = true;
        } catch (Throwable error) {
            failure.compareAndSet(null, error);
        } finally {
            Shutdown shutdown = closeWorkers(pool, !success, failure);
            summary.put("workers_terminated", shutdown.terminated);
            summary.put("cleanup_interrupted", shutdown.interrupted);
            summary.put("actual_client_metrics", metrics);
            summary.put("success", success && shutdown.terminated && failure.get() == null);
            summary.put("unknown_or_partial", !success || !shutdown.terminated || failure.get() != null);
            summary.put("finished_ns", System.nanoTime());
            if (failure.get() != null) {
                summary.put("error_class", failure.get().getClass().getName());
            }
            try {
                save("kafka-produce.json", summary);
            } finally {
                if (shutdown.interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        if (!Boolean.TRUE.equals(summary.get("success"))) {
            throw new IllegalStateException("Produce failed; retain all partial evidence", failure.get());
        }
    }

    private static final class Shutdown {
        private boolean interrupted;
        private boolean terminated;
    }

    private static Shutdown closeWorkers(ExecutorService pool, boolean abort, AtomicReference<Throwable> failure) {
        Shutdown result = new Shutdown();
        result.interrupted = Thread.interrupted();
        if (result.interrupted) {
            failure.compareAndSet(null, new InterruptedException("Interrupted before cleanup"));
        }
        try {
            pool.shutdown();
            long deadline = System.nanoTime() + 20L * SECOND;
            if (abort || result.interrupted) {
                pool.shutdownNow();
            }
            while (!(result.terminated = pool.isTerminated()) && System.nanoTime() < deadline) {
                try {
                    pool.awaitTermination(Math.min(SECOND, Math.max(1, deadline - System.nanoTime())), TimeUnit.NANOSECONDS);
                } catch (InterruptedException error) {
                    result.interrupted = true;
                    failure.compareAndSet(null, error);
                    pool.shutdownNow();
                }
                if (deadline - System.nanoTime() <= 10L * SECOND) {
                    pool.shutdownNow();
                }
            }
        } catch (Throwable error) {
            failure.compareAndSet(null, error);
            try {
                pool.shutdownNow();
            } catch (Throwable secondary) {
                error.addSuppressed(secondary);
            }
        }
        return result;
    }

    private void verify() throws Exception {
        Map<String, Long> begin = offsets(true);
        Map<String, Long> end = offsets(false);
        expectOffsets(begin, 0);
        expectOffsets(end, MEASURE_ROWS + WARM_ROWS);
        Properties settings = properties();
        settings.setProperty("key.deserializer", "org.apache.kafka.common.serialization.ByteArrayDeserializer");
        settings.setProperty("value.deserializer", "org.apache.kafka.common.serialization.ByteArrayDeserializer");
        settings.setProperty("enable.auto.commit", "false");
        settings.setProperty("auto.offset.reset", "none");
        settings.setProperty("max.poll.records", "10000");
        settings.setProperty("fetch.max.bytes", "8388608");
        settings.setProperty("max.partition.fetch.bytes", "1048576");
        long count = 0;
        long[] next = new long[PARTITIONS];
        long deadline = System.nanoTime() + 900L * SECOND;
        KafkaConsumer<byte[], byte[]> consumer = new KafkaConsumer<>(settings);
        Throwable primary = null;
        try (BufferedWriter writer = Files.newBufferedWriter(output.resolve("consumer-records.csv"),
                        StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW)) {
            consumer.assign(partitions());
            for (TopicPartition partition : partitions()) {
                consumer.seek(partition, 0);
            }
            writer.write("partition,offset,key_base64,value_base64\n");
            while (count < MEASURE_ROWS + WARM_ROWS) {
                checkpoint();
                if (System.nanoTime() >= deadline) {
                    throw new IllegalStateException("Independent physical consumer deadline expired");
                }
                for (ConsumerRecord<byte[], byte[]> row : consumer.poll(Duration.ofMillis(500))) {
                    if (row.partition() < 0 || row.partition() >= PARTITIONS
                            || row.offset() != next[row.partition()] || row.offset() >= end.get("" + row.partition())
                            || row.key() == null || row.key().length > 8 || row.value() == null || row.value().length != 127) {
                        throw new IllegalStateException("Missing, duplicated, out-of-domain or malformed physical record");
                    }
                    writer.write(row.partition() + "," + row.offset() + ","
                            + Base64.getEncoder().encodeToString(row.key()) + ","
                            + Base64.getEncoder().encodeToString(row.value()) + "\n");
                    next[row.partition()]++;
                    count++;
                }
            }
        } catch (Exception | Error error) {
            primary = error;
            throw error;
        } finally {
            closeBounded(() -> consumer.close(Duration.ofSeconds(5)), primary);
        }
        Map<String, Object> value = receipt();
        value.put("records", count);
        value.put("begin_offsets", begin);
        value.put("end_offsets_exclusive", end);
        value.put("finished_ns", System.nanoTime());
        save("kafka-verify.json", value);
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("selfcheck")) {
            selfcheck();
            return;
        }
        if (args.length != 2) {
            throw new IllegalArgumentException("Expected init|produce|verify and absolute frozen config");
        }
        Path path = Paths.get(args[1]);
        if (!path.isAbsolute() || Files.isSymbolicLink(path) || Files.size(path) > 65536) {
            throw new IllegalArgumentException("Expected bounded absolute config");
        }
        LicenseKafkaBaseline fixture = new LicenseKafkaBaseline(JSON.readTree(path.toFile()));
        switch (args[0]) {
            case "init": fixture.initialize(); break;
            case "produce": fixture.produce(); break;
            case "verify": fixture.verify(); break;
            default: throw new IllegalArgumentException("Unknown Kafka action");
        }
    }

    private static void selfcheck() {
        int checks = 0;
        for (long rows : new long[] {WARM_ROWS, MEASURE_ROWS}) {
            java.util.BitSet seen = new java.util.BitSet((int) rows);
            long base = rows == WARM_ROWS ? MEASURE_ROWS : 0;
            long[] counts = new long[8];
            for (long index = 0; index < rows; index++) {
                long id = identifier(index, rows, base);
                int position = (int) (id - base);
                if (position < 0 || position >= rows || seen.get(position)) {
                    throw new AssertionError("Permutation repeated or escaped the independent phase domain");
                }
                seen.set(position);
                counts[(int) (id % 8)]++;
            }
            if (seen.cardinality() != rows) {
                throw new AssertionError("Incomplete phase ID domain");
            }
            for (long count : counts) {
                if (count != rows / 8) {
                    throw new AssertionError("Unequal partition population");
                }
            }
            checks++;
            for (int batch : new int[] {1000, 10000}) {
                for (int workers : new int[] {1, 8, 32}) {
                    long previous = -1;
                    long total = 0;
                    long duration = (rows == WARM_ROWS ? 180L : 600L) * SECOND;
                    for (long index = 0; index < rows / batch; index++) {
                        long offset = index * duration / (rows / batch);
                        if (offset <= previous || offset >= duration || index % workers >= workers) {
                            throw new AssertionError("Non-monotonic/out-of-window offered batch schedule");
                        }
                        previous = offset;
                        total += batch;
                    }
                    if (total != rows) {
                        throw new AssertionError("Incomplete scheduled input");
                    }
                    checks++;
                }
            }
        }
        for (boolean interrupted : new boolean[] {false, true}) {
            ExecutorService pool = Executors.newSingleThreadExecutor();
            CountDownLatch entered = new CountDownLatch(1);
            pool.submit(() -> {
                entered.countDown();
                try {
                    Thread.sleep(60000);
                } catch (InterruptedException expected) {
                    Thread.currentThread().interrupt();
                }
            });
            try {
                if (!entered.await(2, TimeUnit.SECONDS)) {
                    throw new AssertionError("Selfcheck worker did not start");
                }
            } catch (InterruptedException error) {
                throw new AssertionError(error);
            }
            AtomicReference<Throwable> failure = new AtomicReference<>();
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
            Shutdown result = closeWorkers(pool, true, failure);
            if (!result.terminated || result.interrupted != interrupted || (failure.get() != null) != interrupted) {
                throw new AssertionError("Forced/interrupted cleanup lost termination or cancellation state");
            }
            checks++;
        }
        RuntimeException primary = new RuntimeException("initial operation failure");
        closeBounded(() -> { throw new IllegalStateException("secondary close failure"); }, primary);
        if (primary.getSuppressed().length != 1 || !(primary.getSuppressed()[0] instanceof IllegalStateException)) {
            throw new AssertionError("Bounded close lost the first operation failure");
        }
        checks++;
        System.out.println("{\"selfcheck\":\"PASS\",\"scenarios\":" + checks
                + ",\"rows_examined_without_io_or_network\":13000000}");
    }
}
