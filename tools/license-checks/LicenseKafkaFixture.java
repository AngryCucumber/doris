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
import org.apache.kafka.clients.admin.TopicDescription;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.Metric;
import org.apache.kafka.common.MetricName;
import org.apache.kafka.common.TopicPartition;

import java.io.BufferedWriter;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** Real broker/producer/consumer fixture; reports physical offsets, never simulated consumption. */
public final class LicenseKafkaFixture {
    private static final int PARTITIONS = 8;
    private static final int ROW_BYTES = 128;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private LicenseKafkaFixture() {
    }

    private static Properties properties(JsonNode config) {
        Properties result = new Properties();
        result.setProperty("bootstrap.servers", config.path("bootstrap").asText());
        result.setProperty("security.protocol", "PLAINTEXT");
        result.setProperty("request.timeout.ms", "10000");
        result.setProperty("default.api.timeout.ms", "60000");
        return result;
    }

    private static List<TopicPartition> partitions(String topic) {
        List<TopicPartition> result = new ArrayList<>();
        for (int partition = 0; partition < PARTITIONS; partition++) {
            result.add(new TopicPartition(topic, partition));
        }
        return result;
    }

    private static Map<String, Long> offsets(AdminClient admin, String topic, boolean beginning) throws Exception {
        Map<TopicPartition, OffsetSpec> request = new LinkedHashMap<>();
        for (TopicPartition partition : partitions(topic)) {
            request.put(partition, beginning ? OffsetSpec.earliest() : OffsetSpec.latest());
        }
        Map<String, Long> result = new LinkedHashMap<>();
        admin.listOffsets(request).all().get(30, TimeUnit.SECONDS).forEach((partition, value) ->
                result.put(Integer.toString(partition.partition()), value.offset()));
        return result;
    }

    private static Map<String, Object> initialize(JsonNode config) throws Exception {
        String topic = config.path("topic").asText();
        try (AdminClient admin = AdminClient.create(properties(config))) {
            NewTopic declaration = new NewTopic(topic, PARTITIONS, (short) 1);
            declaration.configs(Collections.singletonMap("cleanup.policy", "delete"));
            admin.createTopics(Collections.singletonList(declaration)).all().get(60, TimeUnit.SECONDS);
            TopicDescription description = admin.describeTopics(Collections.singletonList(topic))
                    .allTopicNames().get(30, TimeUnit.SECONDS).get(topic);
            if (description.partitions().size() != PARTITIONS
                    || description.partitions().stream().anyMatch(partition -> partition.replicas().size() != 1)) {
                throw new IllegalStateException("Topic shape mismatch");
            }
            Map<String, Object> report = new LinkedHashMap<>();
            report.put("partitions", description.partitions().size());
            report.put("replication_factor", 1);
            report.put("begin_offsets", offsets(admin, topic, true));
            report.put("end_offsets_exclusive", offsets(admin, topic, false));
            return report;
        }
    }

    private static String digest(byte[] value) throws Exception {
        StringBuilder hex = new StringBuilder();
        for (byte item : MessageDigest.getInstance("SHA-256").digest(value)) {
            hex.append(Character.forDigit((item & 255) >>> 4, 16));
            hex.append(Character.forDigit(item & 15, 16));
        }
        return hex.toString();
    }

    private static final class Pending {
        private final int index;
        private final long id;
        private final String sha256;
        private final Future<RecordMetadata> future;

        private Pending(int index, long id, String sha256, Future<RecordMetadata> future) {
            this.index = index;
            this.id = id;
            this.sha256 = sha256;
            this.future = future;
        }
    }

    private static long acknowledge(List<Pending> pending, BufferedWriter writer, int worker) throws Exception {
        for (Pending request : pending) {
            RecordMetadata metadata = request.future.get(35, TimeUnit.SECONDS);
            if (metadata.partition() != request.id % PARTITIONS || metadata.offset() < 0) {
                throw new IllegalStateException("Producer acknowledgement partition/offset mismatch");
            }
            synchronized (writer) {
                writer.write(request.index + "," + request.id + "," + metadata.partition() + ","
                        + metadata.offset() + "," + metadata.timestamp() + "," + worker + ","
                        + request.sha256 + "\n");
            }
        }
        int count = pending.size();
        pending.clear();
        synchronized (writer) {
            writer.flush();
        }
        return count;
    }

    private static Map<String, Object> produceWorker(JsonNode config, int worker, BufferedWriter writer)
            throws Exception {
        int rows = config.path("rows").asInt();
        int workers = config.path("workers").asInt();
        int batchRows = config.path("batch_rows").asInt();
        Properties settings = properties(config);
        settings.setProperty("client.id", "lp013-producer-" + worker);
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
        long acknowledged = 0;
        KafkaProducer<String, String> producer = new KafkaProducer<>(settings);
        try (RandomAccessFile source = new RandomAccessFile(config.path("input").asText(), "r")) {
            List<Pending> pending = new ArrayList<>();
            byte[] bytes = new byte[ROW_BYTES];
            for (int start = 0; start < rows; start += batchRows) {
                for (int index = start + worker; index < Math.min(start + batchRows, rows); index += workers) {
                    if (Thread.currentThread().isInterrupted()) {
                        throw new InterruptedException("Producer was cancelled");
                    }
                    source.seek((long) index * ROW_BYTES);
                    source.readFully(bytes);
                    if (bytes[ROW_BYTES - 1] != '\n') {
                        throw new IllegalStateException("Input has lost fixed-width row boundaries");
                    }
                    String value = new String(bytes, 0, ROW_BYTES - 1, StandardCharsets.US_ASCII);
                    long id = Long.parseLong(value.substring(0, value.indexOf(',')));
                    if (id < 0 || id >= rows) {
                        throw new IllegalStateException("Input ID is outside the fixture domain");
                    }
                    ProducerRecord<String, String> record = new ProducerRecord<>(config.path("topic").asText(),
                            (int) (id % PARTITIONS), Long.toString(id), value);
                    pending.add(new Pending(index, id, digest(value.getBytes(StandardCharsets.US_ASCII)),
                            producer.send(record)));
                }
                acknowledged += acknowledge(pending, writer, worker);
            }
            Map<String, Object> report = new LinkedHashMap<>();
            report.put("worker", worker);
            report.put("acknowledged_rows", acknowledged);
            report.put("max_in_flight_row_batch", (batchRows + workers - 1) / workers);
            Map<String, Object> metrics = new LinkedHashMap<>();
            for (Map.Entry<MetricName, ? extends Metric> entry : producer.metrics().entrySet()) {
                String name = entry.getKey().name();
                if (entry.getKey().group().equals("producer-metrics")
                        && (name.equals("record-error-total") || name.equals("record-retry-total")
                        || name.equals("record-send-total") || name.equals("requests-in-flight"))) {
                    metrics.put(name, entry.getValue().metricValue());
                }
            }
            report.put("actual_client_metrics", metrics);
            return report;
        } finally {
            producer.close(Duration.ofSeconds(5));
        }
    }

    private static Map<String, Object> produce(JsonNode config) throws Exception {
        int workers = config.path("workers").asInt();
        ExecutorService executor = Executors.newFixedThreadPool(workers, action -> {
            Thread thread = new Thread(action, "lp013-producer");
            thread.setDaemon(true);
            return thread;
        });
        Path output = Paths.get(config.path("output").asText(), "producer-acks.csv");
        long start = System.nanoTime();
        long deadline = start + TimeUnit.SECONDS.toNanos(config.path("timeout_seconds").asLong());
        try (BufferedWriter writer = Files.newBufferedWriter(output, StandardCharsets.UTF_8)) {
            writer.write("index,id,partition,offset,timestamp_ms,worker,value_sha256\n");
            List<Future<Map<String, Object>>> futures = new ArrayList<>();
            for (int worker = 0; worker < workers; worker++) {
                final int id = worker;
                futures.add(executor.submit(() -> produceWorker(config, id, writer)));
            }
            List<Map<String, Object>> results = new ArrayList<>();
            long acknowledged = 0;
            for (Future<Map<String, Object>> future : futures) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    throw new IllegalStateException("Producer deadline expired");
                }
                Map<String, Object> result = future.get(remaining, TimeUnit.NANOSECONDS);
                acknowledged += ((Number) result.get("acknowledged_rows")).longValue();
                results.add(result);
            }
            Map<String, Object> report = new LinkedHashMap<>();
            report.put("acknowledged_rows", acknowledged);
            report.put("workers", results);
            report.put("elapsed_nanos_including_input_and_receipts", System.nanoTime() - start);
            report.put("fixed_rate", false);
            return report;
        } finally {
            executor.shutdownNow();
            executor.awaitTermination(10, TimeUnit.SECONDS);
        }
    }

    private static Map<String, Object> verify(JsonNode config) throws Exception {
        String topic = config.path("topic").asText();
        Properties settings = properties(config);
        settings.setProperty("client.id", "lp013-independent-oracle");
        settings.setProperty("enable.auto.commit", "false");
        settings.setProperty("auto.offset.reset", "none");
        settings.setProperty("isolation.level", "read_committed");
        settings.setProperty("key.deserializer", "org.apache.kafka.common.serialization.ByteArrayDeserializer");
        settings.setProperty("value.deserializer", "org.apache.kafka.common.serialization.ByteArrayDeserializer");
        Map<String, Object> report = new LinkedHashMap<>();
        Map<String, Long> begin;
        Map<String, Long> end;
        try (AdminClient admin = AdminClient.create(properties(config))) {
            begin = offsets(admin, topic, true);
            end = offsets(admin, topic, false);
        }
        report.put("begin_offsets", begin);
        report.put("end_offsets_exclusive", end);
        long wanted = end.values().stream().mapToLong(Long::longValue).sum();
        if (begin.values().stream().anyMatch(value -> value != 0) || wanted != config.path("rows").asLong()) {
            throw new IllegalStateException("Frozen topic offset range differs from the input");
        }
        long consumed = 0;
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(120);
        Map<Integer, Long> next = new LinkedHashMap<>();
        try (KafkaConsumer<byte[], byte[]> consumer = new KafkaConsumer<>(settings);
                BufferedWriter writer = Files.newBufferedWriter(Paths.get(config.path("output").asText(),
                        "consumer-records.csv"), StandardCharsets.UTF_8)) {
            consumer.assign(partitions(topic));
            for (TopicPartition partition : partitions(topic)) {
                consumer.seek(partition, 0);
                next.put(partition.partition(), 0L);
            }
            writer.write("partition,offset,key_base64,value_base64\n");
            while (consumed < wanted) {
                if (System.nanoTime() > deadline) {
                    throw new IllegalStateException("Independent consumer deadline expired");
                }
                for (ConsumerRecord<byte[], byte[]> record : consumer.poll(Duration.ofMillis(500))) {
                    if (record.offset() != next.get(record.partition()) || record.key() == null
                            || record.value() == null || record.offset() >= end.get(Integer.toString(record.partition()))) {
                        throw new IllegalStateException("Unexpected, repeated, skipped or null broker record");
                    }
                    next.put(record.partition(), record.offset() + 1);
                    writer.write(record.partition() + "," + record.offset() + ","
                            + Base64.getEncoder().encodeToString(record.key()) + ","
                            + Base64.getEncoder().encodeToString(record.value()) + "\n");
                    consumed++;
                }
            }
        }
        report.put("records", consumed);
        return report;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("Expected init|produce|verify and a frozen JSON config");
        }
        JsonNode config = MAPPER.readTree(new File(args[1]));
        int rows = config.path("rows").asInt();
        int workers = config.path("workers").asInt();
        int batch = config.path("batch_rows").asInt();
        if (!System.getProperty("java.runtime.version").equals(config.path("java_runtime").asText())
                || !(rows == 10000 || rows == 100000) || !(workers == 1 || workers == 8 || workers == 32)
                || !(batch == 1000 || batch == 10000) || !config.path("topic").asText().matches("lp013_[0-9a-f]{16}")) {
            throw new IllegalArgumentException("Unexpected fixture/JDK configuration");
        }
        Map<String, Object> report;
        switch (args[0]) {
            case "init":
                report = initialize(config);
                break;
            case "produce":
                report = produce(config);
                break;
            case "verify":
                report = verify(config);
                break;
            default:
                throw new IllegalArgumentException("Unknown fixture action");
        }
        report.put("java_runtime", System.getProperty("java.runtime.version"));
        report.put("kafka_client_version", org.apache.kafka.common.utils.AppInfoParser.getVersion());
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(Paths.get(config.path("output").asText(),
                "kafka-" + args[0] + ".json").toFile(), report);
    }
}
