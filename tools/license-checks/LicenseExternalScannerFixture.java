// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.arrow.memory.RootAllocator;
import org.apache.arrow.vector.FieldVector;
import org.apache.arrow.vector.ipc.ArrowStreamReader;
import org.apache.arrow.vector.types.pojo.ArrowType;
import org.apache.doris.thrift.TDorisExternalService;
import org.apache.doris.thrift.TScanBatchResult;
import org.apache.doris.thrift.TScanCloseParams;
import org.apache.doris.thrift.TScanCloseResult;
import org.apache.doris.thrift.TScanNextBatchParams;
import org.apache.doris.thrift.TScanOpenParams;
import org.apache.doris.thrift.TScanOpenResult;
import org.apache.doris.thrift.TStatus;
import org.apache.doris.thrift.TStatusCode;
import org.apache.thrift.TConfiguration;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.transport.TSocket;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Original external scanner protocol, with complete unordered synthetic data and cleanup oracles. */
public final class LicenseExternalScannerFixture {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int ROWS = 1000000;
    private static final int TABLETS = 16;
    private static final int MAX_IPC_BYTES = 16 * 1024 * 1024;
    private static final int MAX_CALLS_PER_TABLET = 4096;
    private static final int[] BATCH_SIZES = {1024, 8192};
    private static volatile Handle activeHandle;

    private static void require(boolean value, String message) {
        if (!value) {
            throw new IllegalStateException(message);
        }
    }

    private static String sha256(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static String payload(long id) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("MD5")
                .digest(Long.toString(id).getBytes(StandardCharsets.US_ASCII)));
    }

    private static void guard(JsonNode config) throws Exception {
        String namespace = Files.readSymbolicLink(Path.of("/proc/self/ns/net")).toString();
        require(namespace.equals(config.path("namespace").asText())
                && !namespace.equals(config.path("host_namespace").asText()), "NAMESPACE_CHANGED");
        for (JsonNode pin : config.path("service_pins")) {
            int pid = pin.path("pid").asInt();
            require(pid > 1, "INVALID_OWNED_PID");
            require(namespace.equals(Files.readSymbolicLink(Path.of("/proc/" + pid + "/ns/net")).toString()),
                    "SERVICE_NAMESPACE_CHANGED");
            String stat = Files.readString(Path.of("/proc/" + pid + "/stat"));
            String[] fields = stat.substring(stat.lastIndexOf(')') + 2).trim().split(" +");
            require(Long.parseLong(fields[19]) == pin.path("start_ticks").asLong(), "SERVICE_PID_REUSED");
        }
        require(config.path("service_pins").size() == 2, "MISSING_SERVICE_PINS");
    }

    private static TSocket socket(JsonNode config, int timeoutMillis) throws Exception {
        guard(config);
        int port = config.path("be_port").asInt();
        require(port > 0 && port < 65536, "INVALID_OWNED_BE_PORT");
        TConfiguration thrift = new TConfiguration(MAX_IPC_BYTES, MAX_IPC_BYTES, 64);
        TSocket socket = new TSocket(thrift, "127.0.0.1", port, timeoutMillis);
        socket.open();
        return socket;
    }

    private static void status(TStatus value) {
        require(value != null && value.getStatusCode() == TStatusCode.OK,
                "BE_STATUS_" + (value == null ? "ABSENT" : value.getStatusCode()));
    }

    private static final class Handle implements AutoCloseable {
        private final JsonNode config;
        private final String context;
        private final Map<String, Object> step;
        private boolean closed;

        Handle(JsonNode config, String context, Map<String, Object> step) {
            this.config = config;
            this.context = context;
            this.step = step;
        }

        @Override
        public synchronized void close() throws Exception {
            if (closed) {
                return;
            }
            // A separate bounded connection also works after the read socket has timed out.
            step.put("close_attempted", true);
            try (TSocket closeSocket = socket(config, 5000)) {
                TDorisExternalService.Client client =
                        new TDorisExternalService.Client(new TBinaryProtocol(closeSocket));
                TScanCloseResult result = client.closeScanner(new TScanCloseParams().setContextId(context));
                step.put("close_status", result.getStatus().getStatusCode().name());
                status(result.getStatus());
                closed = true;
                step.put("closed", true);
            } catch (Exception error) {
                step.put("close_error_class", error.getClass().getName());
                throw error;
            }
        }
    }

    private static final class RowSetOracle {
        private final int expectedRows;
        private final BitSet ids;
        private final byte[] actualPayloads;
        private final MessageDigest md5;
        private int count;
        private long sum;

        RowSetOracle(int expectedRows) throws Exception {
            this.expectedRows = expectedRows;
            ids = new BitSet(expectedRows);
            actualPayloads = new byte[Math.multiplyExact(expectedRows, 32)];
            md5 = MessageDigest.getInstance("MD5");
        }

        void accept(long id, String value) {
            require(id >= 0 && id < expectedRows, "ID_OUT_OF_RANGE");
            int index = Math.toIntExact(id);
            require(!ids.get(index), "DUPLICATE_ID_ACROSS_TABLETS_OR_BATCHES");
            require(value != null, "NULL_PAYLOAD");
            String expected = HexFormat.of().formatHex(
                    md5.digest(Long.toString(id).getBytes(StandardCharsets.US_ASCII)));
            require(value.equals(expected), "PAYLOAD_MODEL_MISMATCH_AT_ID_" + id);
            byte[] actual = value.getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(actual, 0, actualPayloads, index * 32, 32);
            ids.set(index);
            count++;
            sum += id;
        }

        Map<String, Object> finish() throws Exception {
            require(count == expectedRows && ids.cardinality() == expectedRows
                    && ids.nextClearBit(0) == expectedRows, "INCOMPLETE_UNORDERED_ID_SET");
            require(sum == (long) expectedRows * (expectedRows - 1) / 2, "ID_SUM_MISMATCH");
            // The payload bytes came from the actual responses, indexed by validated id, not from the model.
            MessageDigest checksum = MessageDigest.getInstance("SHA-256");
            for (int id = 0; id < expectedRows; id++) {
                checksum.update((id + ",").getBytes(StandardCharsets.US_ASCII));
                checksum.update(actualPayloads, id * 32, 32);
                checksum.update((byte) '\n');
            }
            return Map.of("rows", count, "distinct_ids", ids.cardinality(), "min_id", 0,
                    "max_id", expectedRows - 1, "sum_id", sum, "sha256_sorted_actual_rows",
                    HexFormat.of().formatHex(checksum.digest()));
        }
    }

    private static int decode(byte[] data, int batchSize, RowSetOracle oracle,
            RootAllocator allocator, Map<String, Object> batch) throws Exception {
        require(data != null && data.length > 0 && data.length <= MAX_IPC_BYTES, "ARROW_IPC_SIZE_BOUND");
        batch.put("arrow_ipc_bytes", data.length);
        int count = 0;
        int recordBatches = 0;
        long min = Long.MAX_VALUE;
        long max = Long.MIN_VALUE;
        long sum = 0;
        try (ArrowStreamReader reader = new ArrowStreamReader(new ByteArrayInputStream(data), allocator)) {
            while (reader.loadNextBatch()) {
                require(++recordBatches == 1, "MULTIPLE_ARROW_BATCHES_IN_ONE_GET_NEXT");
                List<FieldVector> columns = reader.getVectorSchemaRoot().getFieldVectors();
                require(columns.size() == 2 && columns.get(0).getName().equals("id")
                        && columns.get(1).getName().equals("payload"), "UNEXPECTED_SCAN_COLUMNS");
                require(columns.get(0).getField().getType().equals(new ArrowType.Int(64, true))
                        && columns.get(1).getField().getType().equals(ArrowType.Utf8.INSTANCE),
                        "UNEXPECTED_SCAN_TYPES");
                int rows = reader.getVectorSchemaRoot().getRowCount();
                batch.put("arrow_rows", rows);
                batch.put("schema", reader.getVectorSchemaRoot().getSchema().toString());
                require(rows > 0 && rows <= batchSize, "BATCH_SIZE_CONTRACT_EXCEEDED");
                for (int row = 0; row < rows; row++) {
                    require(!columns.get(0).isNull(row) && !columns.get(1).isNull(row), "NULL_SCAN_VALUE");
                    Object value = columns.get(0).getObject(row);
                    require(value instanceof Number, "NONINTEGER_SCAN_ID");
                    long id = ((Number) value).longValue();
                    oracle.accept(id, columns.get(1).getObject(row).toString());
                    min = Math.min(min, id);
                    max = Math.max(max, id);
                    sum += id;
                    count++;
                }
            }
        }
        require(recordBatches == 1 && count > 0, "EMPTY_NON_EOS_ARROW_STREAM");
        batch.put("rows", count);
        batch.put("min_id", min);
        batch.put("max_id", max);
        batch.put("sum_id", sum);
        return count;
    }

    private static void scanTablet(JsonNode config, JsonNode tablet, int batchSize, RowSetOracle oracle,
            RootAllocator allocator, Set<String> contextHashes, List<Map<String, Object>> steps,
            long deadline) throws Exception {
        require(System.nanoTime() < deadline, "MATRIX_DEADLINE_EXCEEDED");
        require(tablet.path("host").asText().equals("127.0.0.1")
                && tablet.path("port").asInt() == config.path("be_port").asInt(), "UNOWNED_TABLET_ROUTE");
        Map<String, Object> step = new LinkedHashMap<>();
        steps.add(step);
        step.put("tablet_id", tablet.path("tablet_id").asLong());
        step.put("closed", false);
        step.put("close_attempted", false);
        List<Map<String, Object>> batches = new ArrayList<>();
        step.put("batches", batches);
        Handle handle = null;
        Exception primary = null;
        try (TSocket readSocket = socket(config, 10000)) {
            TDorisExternalService.Client client = new TDorisExternalService.Client(new TBinaryProtocol(readSocket));
            TScanOpenParams params = new TScanOpenParams("default_cluster", "license_perf", "point_rows",
                    List.of(tablet.path("tablet_id").asLong()), config.path("opaque_plan").asText());
            // Do not set a row limit: every row of every returned tablet must be read.
            params.setBatchSize(batchSize).setUser(config.path("user").asText())
                    .setPasswd(System.getenv().getOrDefault(config.path("password_env").asText(), ""))
                    .setKeepAliveMin((short) 1).setExecutionTimeout(60).setMemLimit(268435456L);
            step.put("open_attempted", true);
            TScanOpenResult opened = client.openScanner(params);
            String context = opened.getContextId();
            if (context != null && !context.isEmpty()) {
                handle = new Handle(config, context, step);
                activeHandle = handle;
                String contextHash = sha256(context.getBytes(StandardCharsets.UTF_8));
                step.put("context_id_sha256", contextHash);
                require(contextHashes.add(contextHash), "CONTEXT_REUSED_ACROSS_OPENS");
            }
            step.put("open_status", opened.getStatus().getStatusCode().name());
            status(opened.getStatus());
            require(handle != null, "SUCCESS_WITHOUT_CONTEXT_ID");
            long offset = 0;
            boolean eos = false;
            for (int call = 0; !eos && call < MAX_CALLS_PER_TABLET; call++) {
                require(System.nanoTime() < deadline, "MATRIX_DEADLINE_EXCEEDED");
                guard(config);
                Map<String, Object> batch = new LinkedHashMap<>();
                batches.add(batch);
                batch.put("request_offset", offset);
                TScanBatchResult next = client.getNext(new TScanNextBatchParams()
                        .setContextId(context).setOffset(offset));
                batch.put("status", next.getStatus().getStatusCode().name());
                status(next.getStatus());
                require(next.isSetEos(), "EOS_FLAG_ABSENT");
                eos = next.isEos();
                batch.put("eos", eos);
                if (eos) {
                    require(!next.isSetRows() || next.getRows().length == 0, "EOS_WITH_UNCONSUMED_ROWS");
                    batch.put("rows", 0);
                } else {
                    offset += decode(next.getRows(), batchSize, oracle, allocator, batch);
                }
                require(offset <= ROWS, "TABLET_ROW_BOUND_EXCEEDED");
                batch.put("next_offset", offset);
                step.put("rows", offset);
                step.put("eos", eos);
            }
            require(eos, "GET_NEXT_CALL_BOUND_EXCEEDED");
        } catch (Exception error) {
            primary = error;
            throw error;
        } finally {
            try {
                if (handle != null) {
                    handle.close();
                } else {
                    step.put("cleanup_boundary", "No context ID received; explicit close cannot be confirmed");
                }
            } catch (Exception closeError) {
                if (primary != null) {
                    primary.addSuppressed(closeError);
                } else {
                    throw closeError;
                }
            } finally {
                activeHandle = null;
            }
        }
    }

    private static void scan(JsonNode config, int batchSize, int attempt, Set<String> contextHashes,
            Map<String, Object> result, long deadline) throws Exception {
        result.put("batch_size", batchSize);
        result.put("attempt", attempt);
        result.put("mode", attempt == 0 ? "first_open" : "same_plan_reopen_after_close");
        result.put("plan_sha256", sha256(config.path("opaque_plan").asText().getBytes(StandardCharsets.US_ASCII)));
        result.put("status", "FAIL");
        long started = System.nanoTime();
        List<Map<String, Object>> steps = new ArrayList<>();
        result.put("tablets", steps);
        RowSetOracle oracle = new RowSetOracle(ROWS);
        try (RootAllocator allocator = new RootAllocator(128L * 1024 * 1024)) {
            for (JsonNode tablet : config.path("tablets")) {
                scanTablet(config, tablet, batchSize, oracle, allocator, contextHashes, steps, deadline);
            }
            Map<String, Object> actual = oracle.finish();
            result.put("complete_unordered_set", actual);
            require(actual.get("sha256_sorted_actual_rows").equals(config.path("expected_sha256").asText()),
                    "INDEPENDENT_PYTHON_MODEL_DIGEST_MISMATCH");
            require(steps.size() == TABLETS && steps.stream().allMatch(step -> Boolean.TRUE.equals(step.get("closed"))),
                    "SCANNER_CLEANUP_NOT_CONFIRMED");
            result.put("status", "READ_PASS");
        } finally {
            result.put("rows_verified", oracle.count);
            result.put("elapsed_nanos_with_complete_oracle", System.nanoTime() - started);
        }
    }

    @FunctionalInterface
    private interface CheckedAction {
        void run() throws Exception;
    }

    private static void reject(CheckedAction action, String prefix) throws Exception {
        try {
            action.run();
        } catch (IllegalStateException error) {
            require(error.getMessage().startsWith(prefix), "SELF_TEST_WRONG_FAILURE");
            return;
        }
        throw new IllegalStateException("SELF_TEST_EXPECTED_REJECTION");
    }

    private static void selfTest(Path output) throws Exception {
        List<String> passed = new ArrayList<>();
        RowSetOracle shuffled = new RowSetOracle(8);
        for (int id : new int[] {7, 0, 4, 2, 6, 1, 5, 3}) {
            shuffled.accept(id, payload(id));
        }
        Map<String, Object> result = shuffled.finish();
        // Build a separate ascending CSV oracle, not the tested indexed byte storage.
        StringBuilder expected = new StringBuilder();
        for (int id = 0; id < 8; id++) {
            expected.append(id).append(',').append(payload(id)).append('\n');
        }
        require(result.get("sha256_sorted_actual_rows").equals(sha256(expected.toString()
                .getBytes(StandardCharsets.US_ASCII))), "SELF_TEST_UNORDERED_DIGEST");
        passed.add("shuffled_complete_actual_rows_digest");
        reject(() -> shuffled.accept(3, payload(3)), "DUPLICATE_ID");
        passed.add("duplicate_id_across_batches_rejected");
        RowSetOracle missing = new RowSetOracle(8);
        for (int id = 0; id < 7; id++) {
            missing.accept(id, payload(id));
        }
        reject(missing::finish, "INCOMPLETE_UNORDERED_ID_SET");
        passed.add("missing_id_rejected");
        reject(() -> missing.accept(-1, payload(0)), "ID_OUT_OF_RANGE");
        passed.add("negative_id_rejected");
        reject(() -> missing.accept(8, payload(8)), "ID_OUT_OF_RANGE");
        passed.add("upper_bound_id_rejected");
        reject(() -> missing.accept(7, null), "NULL_PAYLOAD");
        passed.add("null_payload_rejected");
        reject(() -> missing.accept(7, payload(6)), "PAYLOAD_MODEL_MISMATCH");
        passed.add("shifted_payload_rejected");
        reject(() -> missing.accept(7, ""), "PAYLOAD_MODEL_MISMATCH");
        passed.add("empty_payload_rejected");
        // Rejections cannot mark a row as present or contaminate the subsequent valid digest.
        missing.accept(7, payload(7));
        require(missing.finish().equals(result), "SELF_TEST_REJECTION_CONTAMINATED_ORACLE");
        passed.add("rejected_rows_do_not_advance_coverage");
        RowSetOracle reopened = new RowSetOracle(8);
        reject(reopened::finish, "INCOMPLETE_UNORDERED_ID_SET");
        passed.add("reopen_starts_with_independent_empty_coverage");
        JSON.writerWithDefaultPrettyPrinter().writeValue(output.toFile(),
                Map.of("status", "SELF_TEST_PASS", "passed", passed, "count", passed.size(),
                        "network_requests", 0, "complete_unordered_set", result));
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 2 && args[0].equals("--self-test")) {
            selfTest(Path.of(args[1]));
            return;
        }
        JsonNode config = JSON.readTree(Files.readAllBytes(Path.of(args[0])));
        Path output = Path.of(args[1]);
        Map<String, Object> report = new LinkedHashMap<>();
        List<Map<String, Object>> runs = new ArrayList<>();
        Set<String> contexts = new HashSet<>();
        report.put("started_at_utc", Instant.now().toString());
        report.put("status", "FAIL");
        report.put("runs", runs);
        report.put("scope", "Original scanner functional fixture; no expiry or performance qualification");
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            Handle handle = activeHandle;
            if (handle != null) {
                try {
                    handle.close();
                } catch (Exception ignored) {
                    // Bounded best effort on termination; the normal report requires confirmed close.
                }
            }
        }, "external-scanner-fixture-cleanup"));
        try {
            guard(config);
            require(config.path("tablets").size() == TABLETS, "EXPECTED_16_TABLETS");
            Set<Long> tablets = new HashSet<>();
            for (JsonNode tablet : config.path("tablets")) {
                require(tablet.path("tablet_id").asLong() > 0
                        && tablets.add(tablet.path("tablet_id").asLong()), "INVALID_OR_DUPLICATE_TABLET_ID");
            }
            long deadline = System.nanoTime() + 300L * 1000000000L;
            for (int batchSize : BATCH_SIZES) {
                for (int attempt = 0; attempt < 2; attempt++) {
                    Map<String, Object> result = new LinkedHashMap<>();
                    runs.add(result);
                    try {
                        scan(config, batchSize, attempt, contexts, result, deadline);
                    } catch (Exception error) {
                        result.put("status", "FAIL");
                        result.put("error_class", error.getClass().getName());
                        if (error instanceof IllegalStateException) {
                            result.put("assertion", error.getMessage());
                        }
                    }
                    JSON.writerWithDefaultPrettyPrinter().writeValue(output.toFile(), report);
                }
            }
            require(runs.size() == 4 && runs.stream().allMatch(run -> "READ_PASS".equals(run.get("status")))
                    && contexts.size() == 4 * TABLETS, "INCOMPLETE_OR_FAILED_SCANNER_MATRIX");
            report.put("unique_context_count", contexts.size());
            report.put("status", "FIXTURE_PASS");
        } finally {
            report.put("finished_at_utc", Instant.now().toString());
            JSON.writerWithDefaultPrettyPrinter().writeValue(output.toFile(), report);
        }
    }
}
