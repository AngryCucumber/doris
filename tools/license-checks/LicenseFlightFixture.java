// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.arrow.flight.CallOptions;
import org.apache.arrow.flight.FlightClient;
import org.apache.arrow.flight.FlightEndpoint;
import org.apache.arrow.flight.FlightInfo;
import org.apache.arrow.flight.FlightRuntimeException;
import org.apache.arrow.flight.FlightStream;
import org.apache.arrow.flight.Location;
import org.apache.arrow.flight.grpc.CredentialCallOption;
import org.apache.arrow.flight.sql.FlightSqlClient;
import org.apache.arrow.memory.ArrowBuf;
import org.apache.arrow.memory.RootAllocator;
import org.apache.arrow.vector.FieldVector;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** Bounded original-build Flight fixture; checks each streamed value against its independent model. */
public final class LicenseFlightFixture {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int[] BATCH_SIZES = {1024, 8192, 65535};

    private static void require(boolean value, String message) {
        if (!value) {
            throw new IllegalStateException(message);
        }
    }

    private static String hex(byte[] data) {
        return HexFormat.of().formatHex(data);
    }

    private static String sql(int size) {
        return "SELECT /*+ SET_VAR(batch_size=" + size
                + ",enable_short_circuit_query=false,enable_sql_cache=false,enable_query_cache=false,"
                + "query_timeout=60) */ id,payload FROM license_perf.point_rows ORDER BY id";
    }

    private static Map<String, Object> bufferEvidence(ArrowBuf buffer, int limit, boolean offsets) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("capacity_bytes", buffer.capacity());
        result.put("reader_index", buffer.readerIndex());
        result.put("writer_index", buffer.writerIndex());
        result.put("readable_bytes", buffer.readableBytes());
        // Inspect the bounded raw capacity even if malformed offsets produced a zero writer index.
        byte[] prefix = new byte[(int) Math.min(buffer.capacity(), limit)];
        buffer.getBytes(0, prefix);
        result.put("prefix_source", "absolute buffer offset zero, bounded by capacity, not writer index");
        result.put("prefix_bytes", prefix.length);
        result.put("prefix_hex", hex(prefix));
        if (offsets) {
            ByteBuffer decoded = ByteBuffer.wrap(prefix).order(ByteOrder.LITTLE_ENDIAN);
            List<Long> unsigned32 = new ArrayList<>();
            List<Long> signed64 = new ArrayList<>();
            for (int offset = 0; offset + Integer.BYTES <= prefix.length; offset += Integer.BYTES) {
                unsigned32.add(Integer.toUnsignedLong(decoded.getInt(offset)));
            }
            for (int offset = 0; offset + Long.BYTES <= prefix.length; offset += Long.BYTES) {
                signed64.add(decoded.getLong(offset));
            }
            result.put("uint32_little_endian", unsigned32);
            result.put("int64_little_endian", signed64);
        }
        return result;
    }

    private static Map<String, Object> batchEvidence(List<FieldVector> columns, int rows,
            String schema, int batchIndex) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("batch_index", batchIndex);
        result.put("rows", rows);
        result.put("schema", schema);
        List<Map<String, Object>> vectors = new ArrayList<>();
        result.put("vectors", vectors);
        for (FieldVector column : columns) {
            Map<String, Object> vector = new LinkedHashMap<>();
            vectors.add(vector);
            try {
                vector.put("name", column.getName());
                vector.put("vector_class", column.getClass().getName());
                vector.put("arrow_type", column.getField().getType().toString());
                vector.put("value_count", column.getValueCount());
                if (column.getName().equals("payload")) {
                    // This fixture queries only its synthetic MD5 payload, never arbitrary user data.
                    vector.put("offset_buffer", bufferEvidence(column.getOffsetBuffer(), 16, true));
                    vector.put("data_buffer", bufferEvidence(column.getDataBuffer(), 32, false));
                }
            } catch (Exception error) {
                // Diagnostics must preserve the original oracle failure, including its exception.
                vector.put("diagnostic_error_class", error.getClass().getName());
            }
        }
        return result;
    }

    private static final class Session implements AutoCloseable {
        private final RootAllocator allocator;
        private final FlightClient frontend;
        private final FlightSqlClient sqlClient;
        private final CredentialCallOption credential;
        private final int bePort;
        private FlightClient backend;
        private String backendLocation;

        Session(JsonNode config) throws Exception {
            allocator = new RootAllocator(256L * 1024 * 1024);
            bePort = config.path("be_flight_port").asInt();
            frontend = FlightClient.builder(allocator,
                    Location.forGrpcInsecure("127.0.0.1", config.path("fe_flight_port").asInt())).build();
            try {
                credential = frontend.authenticateBasicToken(config.path("user").asText(),
                        System.getenv().getOrDefault(config.path("password_env").asText(), ""))
                        .orElseThrow(() -> new IllegalStateException("No FE authentication token"));
                sqlClient = new FlightSqlClient(frontend);
            } catch (Exception error) {
                frontend.close();
                allocator.close();
                throw error;
            }
        }

        void read(int size, String expectedDigest, Map<String, Object> result) throws Exception {
            long started = System.nanoTime();
            List<Integer> batchRows = new ArrayList<>();
            result.put("actual_record_batch_rows", batchRows);
            long count = 0;
            try {
                FlightInfo info = sqlClient.execute(sql(size), credential, CallOptions.timeout(90, TimeUnit.SECONDS));
                require(info.getEndpoints().size() == 1, "ORDER BY fixture requires one ordered result endpoint");
                FlightEndpoint endpoint = info.getEndpoints().get(0);
                require(endpoint.getLocations().size() == 1, "Expected exactly one explicit BE endpoint");
                Location location = endpoint.getLocations().get(0);
                URI uri = location.getUri();
                require("127.0.0.1".equals(uri.getHost()) && uri.getPort() == bePort
                        && "grpc+tcp".equals(uri.getScheme()), "Endpoint is outside the owned BE Flight service");
                if (backend == null) {
                    backend = FlightClient.builder(allocator, location).build();
                    backendLocation = uri.toString();
                }
                require(uri.toString().equals(backendLocation), "BE endpoint changed during reused session");
                result.put("endpoint", backendLocation);
                result.put("ticket_sha256",
                        hex(MessageDigest.getInstance("SHA-256").digest(endpoint.getTicket().getBytes())));
                MessageDigest checksum = MessageDigest.getInstance("SHA-256");
                MessageDigest md5 = MessageDigest.getInstance("MD5");
                String schema = null;
                try (FlightStream stream = backend.getStream(endpoint.getTicket(), credential,
                        CallOptions.timeout(90, TimeUnit.SECONDS))) {
                    while (stream.next()) {
                        require(batchRows.size() < 20000, "Too many Flight record batches");
                        String currentSchema = stream.getRoot().getSchema().toString();
                        if (schema == null) {
                            schema = currentSchema;
                            result.put("schema", schema);
                        }
                        List<FieldVector> columns = stream.getRoot().getFieldVectors();
                        int rows = stream.getRoot().getRowCount();
                        batchRows.add(rows);
                        if (batchRows.size() == 1) {
                            result.put("first_record_batch", batchEvidence(columns, rows, currentSchema, 0));
                        }
                        int row = -1;
                        try {
                            require(schema.equals(currentSchema), "Schema changed within stream");
                            require(columns.size() == 2 && columns.get(0).getName().equals("id")
                                    && columns.get(1).getName().equals("payload"), "Unexpected Flight schema");
                            for (row = 0; row < rows; row++) {
                                require(count < 1000000 && !columns.get(0).isNull(row) && !columns.get(1).isNull(row),
                                        "Unexpected null or excess row");
                                Object identifier = columns.get(0).getObject(row);
                                require(identifier instanceof Number && ((Number) identifier).longValue() == count,
                                        "Flight ID order, duplication or completeness mismatch");
                                String payload = columns.get(1).getObject(row).toString();
                                String expected = hex(md5.digest(
                                        Long.toString(count).getBytes(StandardCharsets.US_ASCII)));
                                require(payload.equals(expected), "Flight payload mismatch: requested_batch=" + size
                                        + ", batch_index=" + (batchRows.size() - 1) + ", row_in_batch=" + row
                                        + ", id=" + count + ", actual_length=" + payload.length()
                                        + ", expected=" + expected
                                        + ", actual_sha256=" + hex(MessageDigest.getInstance("SHA-256")
                                                .digest(payload.getBytes(StandardCharsets.UTF_8))));
                                checksum.update((count + "," + payload + "\n").getBytes(StandardCharsets.US_ASCII));
                                count++;
                            }
                        } catch (Exception error) {
                            result.put("failed_record_batch",
                                    batchEvidence(columns, rows, currentSchema, batchRows.size() - 1));
                            result.put("failure_row_in_batch", row);
                            throw error;
                        }
                    }
                }
                String actualDigest = hex(checksum.digest());
                require(count == 1000000 && actualDigest.equals(expectedDigest),
                        "Complete Flight model digest mismatch");
                result.put("requested_session_batch_size", size);
                result.put("actual_record_batch_rows", batchRows);
                result.put("rows", count);
                result.put("schema", schema);
                result.put("sha256", actualDigest);
                result.put("elapsed_nanos_with_complete_oracle", System.nanoTime() - started);
                result.put("status", "READ_PASS");
            } finally {
                result.put("rows_verified", count);
                result.put("elapsed_nanos_with_oracle_and_diagnostics", System.nanoTime() - started);
            }
        }

        Map<String, Object> rejectInvalidBatch() throws Exception {
            try {
                sqlClient.execute(sql(65536), credential, CallOptions.timeout(30, TimeUnit.SECONDS));
                throw new IllegalStateException("Invalid session batch size unexpectedly accepted");
            } catch (FlightRuntimeException error) {
                String description = error.status().description();
                require(description != null && (description.contains("batch_size should be between 1 and 65535")
                        || description.contains("Can not set session variable 'batch_size' = '65536'")),
                        "Expected original parameter range rejection, not unrelated Flight failure");
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("requested_session_batch_size", 65536);
                result.put("flight_error_code", error.status().code().name());
                result.put("error_description", description);
                result.put("expected_parameter_range_error", true);
                result.put("be_doget_requested", false);
                return result;
            }
        }

        @Override
        public void close() throws Exception {
            try {
                if (backend != null) {
                    backend.close();
                }
            } finally {
                try {
                    frontend.close();
                } finally {
                    allocator.close();
                }
            }
        }
    }

    private static void recordRead(Session session, int size, int repeat, String mode,
            String expectedDigest, List<Map<String, Object>> queries) {
        Map<String, Object> query = new LinkedHashMap<>();
        query.put("requested_session_batch_size", size);
        query.put("connection_mode", mode);
        query.put("repeat", repeat);
        queries.add(query);
        try {
            session.read(size, expectedDigest, query);
        } catch (Exception error) {
            query.put("status", "FAIL");
            query.put("error_class", error.getClass().getName());
            if (error instanceof IllegalStateException) {
                query.put("assertion", error.getMessage());
            } else if (error instanceof FlightRuntimeException) {
                query.put("flight_error_code", ((FlightRuntimeException) error).status().code().name());
            }
        }
    }

    public static void main(String[] args) throws Exception {
        JsonNode config = JSON.readTree(Files.readAllBytes(Path.of(args[0])));
        Map<String, Object> report = new LinkedHashMap<>();
        List<Map<String, Object>> queries = new ArrayList<>();
        report.put("queries", queries);
        report.put("scope",
                "Original Flight functional fixture; complete oracle cost included; not performance evidence");
        report.put("status", "FAIL");
        try {
            try (Session session = new Session(config)) {
                report.put("invalid_batch", session.rejectInvalidBatch());
                for (int size : BATCH_SIZES) {
                    for (int repeat = 0; repeat < 2; repeat++) {
                        recordRead(session, size, repeat, "reuse_fe_and_be_channels",
                                config.path("expected_sha256").asText(), queries);
                    }
                }
            }
            for (int size : BATCH_SIZES) {
                for (int repeat = 0; repeat < 2; repeat++) {
                    try (Session session = new Session(config)) {
                        recordRead(session, size, repeat, "new_fe_and_be_channels_per_query",
                                config.path("expected_sha256").asText(), queries);
                    }
                }
            }
            require(queries.size() == 12 && queries.stream().allMatch(query -> "READ_PASS".equals(query.get("status"))),
                    "One or more cases in the fixed connection/batch matrix failed");
            report.put("status", "FIXTURE_PASS");
        } catch (Exception error) {
            report.put("error_class", error.getClass().getName());
            if (error instanceof IllegalStateException) {
                report.put("assertion", error.getMessage());
            }
            throw error;
        } finally {
            JSON.writerWithDefaultPrettyPrinter().writeValue(Path.of(args[1]).toFile(), report);
        }
    }
}
