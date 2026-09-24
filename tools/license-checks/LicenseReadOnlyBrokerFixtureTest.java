// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import org.apache.doris.thrift.TBrokerCloseReaderRequest;
import org.apache.doris.thrift.TBrokerCloseWriterRequest;
import org.apache.doris.thrift.TBrokerDeletePathRequest;
import org.apache.doris.thrift.TBrokerFD;
import org.apache.doris.thrift.TBrokerListPathRequest;
import org.apache.doris.thrift.TBrokerOpenReaderRequest;
import org.apache.doris.thrift.TBrokerOpenReaderResponse;
import org.apache.doris.thrift.TBrokerOpenWriterRequest;
import org.apache.doris.thrift.TBrokerOperationStatus;
import org.apache.doris.thrift.TBrokerOperationStatusCode;
import org.apache.doris.thrift.TBrokerPReadRequest;
import org.apache.doris.thrift.TBrokerPWriteRequest;
import org.apache.doris.thrift.TBrokerReadResponse;
import org.apache.doris.thrift.TBrokerRenamePathRequest;
import org.apache.doris.thrift.TBrokerVersion;
import org.apache.thrift.TDeserializer;
import org.apache.thrift.TSerializer;
import org.apache.thrift.protocol.TBinaryProtocol;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

/** Future standalone, socket-free checks of range semantics, ownership, bounds and cleanup accounting. */
public final class LicenseReadOnlyBrokerFixtureTest {
    private static final TBrokerVersion VERSION = TBrokerVersion.VERSION_ONE;
    private static final String SECRET = "must-not-appear-in-broker-evidence";

    private LicenseReadOnlyBrokerFixtureTest() {
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void status(TBrokerOperationStatus actual, TBrokerOperationStatusCode expected) {
        check(actual.getStatusCode() == expected, "Unexpected status: " + actual.getStatusCode() + " / " + expected);
    }

    private static TBrokerOpenReaderResponse open(LicenseReadOnlyBrokerFixture.Handler handler) {
        return handler.openReader(new TBrokerOpenReaderRequest(VERSION, LicenseReadOnlyBrokerFixture.CSV_URI,
                0, SECRET, Map.of("password", SECRET)));
    }

    private static TBrokerReadResponse read(LicenseReadOnlyBrokerFixture.Handler handler, TBrokerFD fd,
            long offset, long length) {
        return handler.pread(new TBrokerPReadRequest(VERSION, fd, offset, length));
    }

    private static void data(TBrokerReadResponse response, String expected) throws Exception {
        status(response.getOpStatus(), TBrokerOperationStatusCode.OK);
        check(new String(response.getData(), StandardCharsets.US_ASCII).equals(expected), "Range bytes differ");
        // Generated response serialization must preserve the original Thrift binary/status fields.
        TBrokerReadResponse roundTrip = new TBrokerReadResponse();
        new TDeserializer(new TBinaryProtocol.Factory()).deserialize(roundTrip,
                new TSerializer(new TBinaryProtocol.Factory()).serialize(response));
        check(roundTrip.equals(response), "Thrift response round trip differs");
    }

    private static void expectRejected(Runnable operation) {
        try {
            operation.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Expected ownership or digest rejection");
    }

    public static void main(String[] args) throws Exception {
        check(args.length == 1, "Supply one existing empty owned .build-records directory");
        Path output = LicenseReadOnlyBrokerFixture.ownedDirectory(args[0]);
        try (Stream<Path> children = Files.list(output)) {
            check(children.findAny().isEmpty(), "Test directory must be empty");
        }
        Path csv = output.resolve("rows.csv");
        Path parquet = output.resolve("rows.parquet");
        byte[] csvBytes = "1,lp026-a\n2,lp026-b\n".getBytes(StandardCharsets.US_ASCII);
        Files.write(csv, csvBytes, StandardOpenOption.CREATE_NEW);
        // Handler semantics do not interpret formats. Actual Parquet full-value validation belongs
        // to LicenseReadOnlyBrokerInputs and the controller; these bytes are explicitly a unit input.
        byte[] unitBytes = "PAR1-unit-test-only-PAR1".getBytes(StandardCharsets.US_ASCII);
        Files.write(parquet, unitBytes, StandardOpenOption.CREATE_NEW);
        Path manifest = output.resolve("input-manifest.json");
        Map<String, Object> csvEntry = Map.of("uri", LicenseReadOnlyBrokerFixture.CSV_URI, "path", csv.toString(),
                "format", "CSV", "size", csvBytes.length, "sha256", LicenseReadOnlyBrokerFixture.sha256(csvBytes));
        Map<String, Object> parquetEntry = Map.of("uri", LicenseReadOnlyBrokerFixture.PARQUET_URI,
                "path", parquet.toString(), "format", "PARQUET", "size", unitBytes.length,
                "sha256", LicenseReadOnlyBrokerFixture.sha256(unitBytes));
        LicenseReadOnlyBrokerFixture.writeNewJson(manifest,
                Map.of("schema_version", 1, "files", List.of(csvEntry, parquetEntry)));
        Map<String, LicenseReadOnlyBrokerFixture.Input> inputs =
                LicenseReadOnlyBrokerFixture.loadInputs(output, manifest);
        Files.writeString(csv, "changed after snapshot", StandardCharsets.US_ASCII);
        try {
            LicenseReadOnlyBrokerFixture.loadInputs(output, manifest);
            throw new AssertionError("Changed file digest was accepted");
        } catch (IllegalArgumentException expected) {
            // Frozen bytes already loaded must still be served, while a new load must fail.
        }
        expectRejected(() -> {
            try {
                LicenseReadOnlyBrokerFixture.ownedFile(output, "/etc/passwd", true);
            } catch (java.io.IOException error) {
                throw new AssertionError(error);
            }
        });
        Path symlink = output.resolve("input-link");
        Files.createSymbolicLink(symlink, csv.getFileName());
        expectRejected(() -> {
            try {
                LicenseReadOnlyBrokerFixture.ownedFile(output, symlink.toString(), true);
            } catch (java.io.IOException error) {
                throw new AssertionError(error);
            }
        });
        AtomicBoolean stopping = new AtomicBoolean();
        Path evidence = output.resolve("requests.jsonl");
        LicenseReadOnlyBrokerFixture.Handler handler =
                new LicenseReadOnlyBrokerFixture.Handler(inputs, evidence, stopping);
        try {
            status(handler.listPath(new TBrokerListPathRequest(VERSION, "/etc/passwd", false, Map.of())).getOpStatus(),
                    TBrokerOperationStatusCode.INVALID_INPUT_FILE_PATH);
            status(handler.listPath(new TBrokerListPathRequest(VERSION, LicenseReadOnlyBrokerFixture.CSV_URI,
                    true, Map.of())).getOpStatus(), TBrokerOperationStatusCode.INVALID_ARGUMENT);
            check(handler.listPath(new TBrokerListPathRequest(VERSION, LicenseReadOnlyBrokerFixture.CSV_URI,
                    false, Map.of())).getFiles().get(0).getSize() == csvBytes.length, "List size differs");
            TBrokerOpenReaderResponse first = open(handler);
            status(first.getOpStatus(), TBrokerOperationStatusCode.OK);
            TBrokerFD fd = first.getFd();
            TBrokerFD second = open(handler).getFd();
            check(!fd.equals(second), "Independent handles aliased");
            data(read(handler, fd, 10, 10), "2,lp026-b\n");
            data(read(handler, fd, 0, 10), "1,lp026-a\n");
            data(read(handler, fd, 10, 10), "2,lp026-b\n");
            data(read(handler, second, 2, 5), "lp026");
            data(read(handler, fd, 17, 100), "-b\n");
            data(read(handler, fd, 20, 0), "");
            status(read(handler, fd, 20, 1).getOpStatus(), TBrokerOperationStatusCode.END_OF_FILE);
            status(read(handler, fd, -1, 1).getOpStatus(), TBrokerOperationStatusCode.INVALID_INPUT_OFFSET);
            status(read(handler, fd, Long.MAX_VALUE, 1).getOpStatus(),
                    TBrokerOperationStatusCode.INVALID_INPUT_OFFSET);
            status(read(handler, fd, 0, -1).getOpStatus(), TBrokerOperationStatusCode.INVALID_ARGUMENT);
            status(read(handler, fd, 0, Long.MAX_VALUE).getOpStatus(), TBrokerOperationStatusCode.INVALID_ARGUMENT);
            status(read(handler, new TBrokerFD(1, 2), 0, 1).getOpStatus(),
                    TBrokerOperationStatusCode.INVALID_ARGUMENT);
            byte[] detached = read(handler, fd, 0, 1).getData();
            detached[0] = '!';
            data(read(handler, fd, 0, 1), "1");
            status(handler.closeReader(new TBrokerCloseReaderRequest(VERSION, fd)), TBrokerOperationStatusCode.OK);
            status(read(handler, fd, 0, 1).getOpStatus(), TBrokerOperationStatusCode.INVALID_ARGUMENT);
            status(handler.closeReader(new TBrokerCloseReaderRequest(VERSION, fd)),
                    TBrokerOperationStatusCode.INVALID_ARGUMENT);
            status(handler.deletePath(new TBrokerDeletePathRequest()), TBrokerOperationStatusCode.OPERATION_NOT_SUPPORTED);
            status(handler.renamePath(new TBrokerRenamePathRequest()), TBrokerOperationStatusCode.OPERATION_NOT_SUPPORTED);
            status(handler.openWriter(new TBrokerOpenWriterRequest()).getOpStatus(),
                    TBrokerOperationStatusCode.OPERATION_NOT_SUPPORTED);
            status(handler.pwrite(new TBrokerPWriteRequest()), TBrokerOperationStatusCode.OPERATION_NOT_SUPPORTED);
            status(handler.closeWriter(new TBrokerCloseWriterRequest()), TBrokerOperationStatusCode.OPERATION_NOT_SUPPORTED);
            List<TBrokerFD> retained = new ArrayList<>();
            retained.add(second);
            while (retained.size() < LicenseReadOnlyBrokerFixture.MAX_HANDLES) {
                TBrokerOpenReaderResponse response = open(handler);
                status(response.getOpStatus(), TBrokerOperationStatusCode.OK);
                retained.add(response.getFd());
            }
            status(open(handler).getOpStatus(), TBrokerOperationStatusCode.OPERATION_NOT_SUPPORTED);
            check(!stopping.get(), "Handle bound unexpectedly stopped the server");
            Map<String, Object> summary = handler.finish("unit-test-no-server");
            check(summary.get("active_readers_before_cleanup").equals(16), "Leaked handles were hidden");
            check(summary.get("cleanup_closed_readers").equals(16)
                    && summary.get("active_readers").equals(0), "Cleanup left readers active");
            check(summary.get("opened_readers").equals(17L) && summary.get("closed_readers").equals(1L),
                    "Client closes and cleanup closes were conflated");
            check(!Files.readString(evidence).contains(SECRET), "Credential canary leaked into evidence");
            LicenseReadOnlyBrokerFixture.writeNewJson(output.resolve("self-check.json"),
                    Map.of("status", "passed", "scope", "socket-free handler and ownership checks",
                            "broker_network_tested", false, "original_fe_tested", false, "summary", summary));
        } finally {
            handler.close();
        }
    }
}
