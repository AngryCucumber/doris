// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.doris.thrift.TBrokerCheckPathExistRequest;
import org.apache.doris.thrift.TBrokerCheckPathExistResponse;
import org.apache.doris.thrift.TBrokerCloseReaderRequest;
import org.apache.doris.thrift.TBrokerCloseWriterRequest;
import org.apache.doris.thrift.TBrokerDeletePathRequest;
import org.apache.doris.thrift.TBrokerFD;
import org.apache.doris.thrift.TBrokerFileSizeRequest;
import org.apache.doris.thrift.TBrokerFileSizeResponse;
import org.apache.doris.thrift.TBrokerFileStatus;
import org.apache.doris.thrift.TBrokerIsSplittableRequest;
import org.apache.doris.thrift.TBrokerIsSplittableResponse;
import org.apache.doris.thrift.TBrokerListPathRequest;
import org.apache.doris.thrift.TBrokerListResponse;
import org.apache.doris.thrift.TBrokerOpenReaderRequest;
import org.apache.doris.thrift.TBrokerOpenReaderResponse;
import org.apache.doris.thrift.TBrokerOpenWriterRequest;
import org.apache.doris.thrift.TBrokerOpenWriterResponse;
import org.apache.doris.thrift.TBrokerOperationStatus;
import org.apache.doris.thrift.TBrokerOperationStatusCode;
import org.apache.doris.thrift.TBrokerPReadRequest;
import org.apache.doris.thrift.TBrokerPWriteRequest;
import org.apache.doris.thrift.TBrokerPingBrokerRequest;
import org.apache.doris.thrift.TBrokerReadResponse;
import org.apache.doris.thrift.TBrokerRenamePathRequest;
import org.apache.doris.thrift.TBrokerSeekRequest;
import org.apache.doris.thrift.TBrokerVersion;
import org.apache.doris.thrift.TPaloBrokerService;
import org.apache.thrift.TException;
import org.apache.thrift.TProcessor;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.server.TThreadPoolServer;
import org.apache.thrift.transport.TServerSocket;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransportException;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** LP026's bounded, read-only implementation of the existing Doris broker Thrift service. */
public final class LicenseReadOnlyBrokerFixture {
    static final ObjectMapper JSON = new ObjectMapper();
    static final Path RECORDS = Path.of("/data/project/massdb-sql/.build-records");
    static final String CSV_URI = "lp026://fixture/rows.csv";
    static final String PARQUET_URI = "lp026://fixture/rows.parquet";
    static final int MAX_FILE_BYTES = 8 * 1024 * 1024;
    static final int MAX_READ_BYTES = 1024 * 1024;
    static final int MAX_MESSAGE_BYTES = 2 * 1024 * 1024;
    static final int MAX_HANDLES = 16;
    static final int MAX_REQUESTS = 10000;
    static final long MAX_RETURNED_BYTES = 64L * 1024 * 1024;

    private LicenseReadOnlyBrokerFixture() {
    }

    static void require(boolean value, String message) {
        if (!value) {
            throw new IllegalArgumentException(message);
        }
    }

    static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

    static Path ownedDirectory(String value) throws IOException {
        Path path = Path.of(value);
        require(path.isAbsolute() && path.equals(path.normalize()), "ABSOLUTE_CANONICAL_DIRECTORY_REQUIRED");
        require(path.startsWith(RECORDS) && !path.equals(RECORDS), "OUTSIDE_CHECKOUT_RECORDS");
        require(path.equals(path.toRealPath()) && Files.isDirectory(path), "SYMLINK_OR_MISSING_DIRECTORY");
        return path;
    }

    static Path ownedFile(Path directory, String value, boolean existing) throws IOException {
        Path path = Path.of(value);
        require(path.isAbsolute() && path.equals(path.normalize()) && path.startsWith(directory)
                && !path.equals(directory), "FILE_OUTSIDE_OWNED_DIRECTORY");
        require(path.getParent().equals(path.getParent().toRealPath()), "SYMLINK_PARENT");
        if (existing) {
            require(path.equals(path.toRealPath()) && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS),
                    "INPUT_NOT_CANONICAL_REGULAR_FILE");
        } else {
            require(!Files.exists(path, LinkOption.NOFOLLOW_LINKS), "OUTPUT_ALREADY_EXISTS");
        }
        return path;
    }

    static byte[] boundedRead(Path path, int maximum) throws IOException {
        require(Files.size(path) <= maximum, "FILE_SIZE_BOUND");
        try (InputStream input = Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            byte[] value = input.readNBytes(maximum + 1);
            require(value.length <= maximum, "FILE_GREW_BEYOND_BOUND");
            return value;
        }
    }

    static void writeNewJson(Path path, Object value) throws IOException {
        Files.writeString(path, JSON.writerWithDefaultPrettyPrinter().writeValueAsString(value) + "\n",
                StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    static String namespace() throws IOException {
        return Files.readSymbolicLink(Path.of("/proc/self/ns/net")).toString();
    }

    static void guardNamespace(JsonNode config) throws IOException {
        String expected = config.path("namespace").asText();
        String host = config.path("host_namespace").asText();
        require(expected.matches("net:\\[[0-9]+\\]") && host.matches("net:\\[[0-9]+\\]"),
                "MISSING_NAMESPACE_IDENTITIES");
        require(namespace().equals(expected) && !expected.equals(host), "PRIVATE_NAMESPACE_REQUIRED");
    }

    static Map<String, Object> bounds() {
        return Map.of("max_file_bytes", MAX_FILE_BYTES, "max_read_bytes", MAX_READ_BYTES,
                "max_message_bytes", MAX_MESSAGE_BYTES, "max_handles", MAX_HANDLES,
                "max_requests", MAX_REQUESTS, "max_returned_bytes", MAX_RETURNED_BYTES,
                "worker_threads", 4, "max_connections", 8, "socket_timeout_millis", 3000);
    }

    static final class Input {
        final String uri;
        final byte[] bytes;

        Input(String uri, byte[] bytes) {
            this.uri = uri;
            this.bytes = bytes;
        }
    }

    static Map<String, Input> loadInputs(Path directory, Path manifest) throws IOException {
        JsonNode root = JSON.readTree(boundedRead(manifest, 65536));
        require(root.path("schema_version").asInt() == 1 && root.path("files").isArray()
                && root.path("files").size() == 2, "EXACT_TWO_FILE_MANIFEST_REQUIRED");
        Map<String, Input> inputs = new LinkedHashMap<>();
        for (JsonNode entry : root.path("files")) {
            String uri = entry.path("uri").asText();
            String format = entry.path("format").asText();
            require((uri.equals(CSV_URI) && format.equals("CSV"))
                    || (uri.equals(PARQUET_URI) && format.equals("PARQUET")), "UNEXPECTED_INPUT_URI_OR_FORMAT");
            Path path = ownedFile(directory, entry.path("path").asText(), true);
            require(entry.path("size").isIntegralNumber() && entry.path("size").asLong() > 0
                    && entry.path("size").asLong() <= MAX_FILE_BYTES, "INVALID_MANIFEST_SIZE");
            byte[] bytes = boundedRead(path, MAX_FILE_BYTES);
            require(bytes.length == entry.path("size").asLong()
                    && sha256(bytes).equals(entry.path("sha256").asText()), "INPUT_DIGEST_OR_SIZE_MISMATCH");
            require(inputs.put(uri, new Input(uri, bytes)) == null, "DUPLICATE_INPUT_URI");
        }
        require(inputs.containsKey(CSV_URI) && inputs.containsKey(PARQUET_URI), "MISSING_FORMAT");
        // Requests read immutable snapshots of the actual digest-verified file bytes. Client paths
        // are never converted to host paths, and later file replacement cannot change these bytes.
        return inputs;
    }

    static final class Handler implements TPaloBrokerService.Iface, AutoCloseable {
        final Map<String, Input> inputs;
        final Map<TBrokerFD, Input> readers = new LinkedHashMap<>();
        final Map<String, Long> counts = new LinkedHashMap<>();
        final Map<String, Long> statusCounts = new LinkedHashMap<>();
        final AtomicBoolean stopRequested;
        final BufferedWriter evidence;
        long requests;
        long returnedBytes;
        long opened;
        long closed;
        long protocolErrors;
        boolean evidenceError;
        volatile String stopReason = "stop_file";

        Handler(Map<String, Input> inputs, Path requestsFile, AtomicBoolean stopRequested) throws IOException {
            this.inputs = inputs;
            this.stopRequested = stopRequested;
            evidence = Files.newBufferedWriter(requestsFile, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        }

        private TBrokerOperationStatusCode validate(TBrokerVersion version) {
            if (stopRequested.get() || requests >= MAX_REQUESTS) {
                stopReason = requests >= MAX_REQUESTS ? "request_bound" : stopReason;
                stopRequested.set(true);
                return TBrokerOperationStatusCode.OPERATION_NOT_SUPPORTED;
            }
            return version == TBrokerVersion.VERSION_ONE ? TBrokerOperationStatusCode.OK
                    : TBrokerOperationStatusCode.INVALID_ARGUMENT;
        }

        private TBrokerOperationStatusCode path(TBrokerVersion version, String uri) {
            TBrokerOperationStatusCode result = validate(version);
            return result != TBrokerOperationStatusCode.OK ? result : inputs.containsKey(uri)
                    ? result : TBrokerOperationStatusCode.INVALID_INPUT_FILE_PATH;
        }

        private TBrokerOperationStatusCode handle(TBrokerVersion version, TBrokerFD fd) {
            TBrokerOperationStatusCode result = validate(version);
            return result != TBrokerOperationStatusCode.OK ? result : readers.containsKey(fd)
                    ? result : TBrokerOperationStatusCode.INVALID_ARGUMENT;
        }

        private TBrokerOperationStatus record(String method, TBrokerOperationStatusCode code,
                String uri, TBrokerFD fd, Long offset, Long length, int bytes) {
            if (requests >= MAX_REQUESTS) {
                stopReason = "request_bound";
                stopRequested.set(true);
                return new TBrokerOperationStatus(TBrokerOperationStatusCode.OPERATION_NOT_SUPPORTED)
                        .setMessage("FIXTURE_REQUEST_BOUND");
            }
            requests++;
            returnedBytes += bytes;
            counts.merge(method, 1L, Long::sum);
            statusCounts.merge(code.name(), 1L, Long::sum);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("schema_version", 1);
            row.put("request_id", requests);
            row.put("utc", Instant.now().toString());
            row.put("monotonic_nanos", System.nanoTime());
            row.put("method", method);
            row.put("status_code", code.getValue());
            row.put("status_name", code.name());
            row.put("allowed_uri", inputs.containsKey(uri) ? uri : null);
            row.put("requested_path_sha256", uri == null ? null : sha256(uri.getBytes(StandardCharsets.UTF_8)));
            row.put("handle_high", fd == null ? null : fd.getHigh());
            row.put("handle_low", fd == null ? null : fd.getLow());
            row.put("offset", offset);
            row.put("length", length);
            row.put("returned_bytes", bytes);
            row.put("active_readers", readers.size());
            row.put("state", stopRequested.get() ? "stopping" : "serving");
            try {
                evidence.write(JSON.writeValueAsString(row));
                evidence.newLine();
                evidence.flush();
            } catch (IOException error) {
                evidenceError = true;
                stopReason = "evidence_error";
                stopRequested.set(true);
                return new TBrokerOperationStatus(TBrokerOperationStatusCode.TARGET_STORAGE_SERVICE_ERROR)
                        .setMessage("FIXTURE_EVIDENCE_UNAVAILABLE");
            }
            if (requests == MAX_REQUESTS) {
                stopReason = "request_bound";
                stopRequested.set(true);
            }
            return new TBrokerOperationStatus(code).setMessage(code == TBrokerOperationStatusCode.OK
                    ? "OK" : "FIXTURE_" + code.name());
        }

        private TBrokerListResponse list(String method, TBrokerListPathRequest request) {
            TBrokerOperationStatusCode code = path(request.getVersion(), request.getPath());
            if (code == TBrokerOperationStatusCode.OK && request.isIsRecursive()) {
                code = TBrokerOperationStatusCode.INVALID_ARGUMENT;
            }
            List<TBrokerFileStatus> files = new ArrayList<>();
            if (code == TBrokerOperationStatusCode.OK) {
                Input input = inputs.get(request.getPath());
                String name = request.isFileNameOnly() ? input.uri.substring(input.uri.lastIndexOf('/') + 1)
                        : input.uri;
                files.add(new TBrokerFileStatus(name, false, input.bytes.length, true));
            }
            return new TBrokerListResponse(record(method, code, request.getPath(), null, null, null, 0))
                    .setFiles(files);
        }

        @Override
        public synchronized TBrokerListResponse listPath(TBrokerListPathRequest request) {
            return list("listPath", request);
        }

        @Override
        public synchronized TBrokerListResponse listLocatedFiles(TBrokerListPathRequest request) {
            return list("listLocatedFiles", request);
        }

        @Override
        public synchronized TBrokerOpenReaderResponse openReader(TBrokerOpenReaderRequest request) {
            TBrokerOperationStatusCode code = path(request.getVersion(), request.getPath());
            Input input = inputs.get(request.getPath());
            TBrokerFD fd = null;
            if (code == TBrokerOperationStatusCode.OK
                    && (request.getStartOffset() < 0 || request.getStartOffset() > input.bytes.length)) {
                code = TBrokerOperationStatusCode.INVALID_INPUT_OFFSET;
            }
            if (code == TBrokerOperationStatusCode.OK && readers.size() >= MAX_HANDLES) {
                code = TBrokerOperationStatusCode.OPERATION_NOT_SUPPORTED;
            }
            if (code == TBrokerOperationStatusCode.OK) {
                do {
                    UUID value = UUID.randomUUID();
                    fd = new TBrokerFD(value.getMostSignificantBits(), value.getLeastSignificantBits());
                } while (readers.containsKey(fd));
                readers.put(fd.deepCopy(), input);
                opened++;
            }
            TBrokerOpenReaderResponse response = new TBrokerOpenReaderResponse(record("openReader", code,
                    request.getPath(), fd, request.getStartOffset(), null, 0));
            if (fd != null) {
                response.setFd(fd).setSize(input.bytes.length);
            }
            return response;
        }

        @Override
        public synchronized TBrokerReadResponse pread(TBrokerPReadRequest request) {
            TBrokerOperationStatusCode code = handle(request.getVersion(), request.getFd());
            Input input = readers.get(request.getFd());
            long offset = request.getOffset();
            long length = request.getLength();
            byte[] data = null;
            if (code == TBrokerOperationStatusCode.OK) {
                if (offset < 0 || offset > input.bytes.length) {
                    code = TBrokerOperationStatusCode.INVALID_INPUT_OFFSET;
                } else if (length < 0 || length > MAX_READ_BYTES) {
                    code = TBrokerOperationStatusCode.INVALID_ARGUMENT;
                } else if (length > 0 && offset == input.bytes.length) {
                    code = TBrokerOperationStatusCode.END_OF_FILE;
                } else {
                    int size = (int) Math.min(length, input.bytes.length - offset);
                    if (returnedBytes + size > MAX_RETURNED_BYTES) {
                        stopReason = "response_byte_bound";
                        stopRequested.set(true);
                        code = TBrokerOperationStatusCode.OPERATION_NOT_SUPPORTED;
                    } else {
                        data = Arrays.copyOfRange(input.bytes, (int) offset, (int) offset + size);
                    }
                }
            }
            TBrokerOperationStatus status = record("pread", code, input == null ? null : input.uri,
                    request.getFd(), offset, length, data == null ? 0 : data.length);
            TBrokerReadResponse response = new TBrokerReadResponse(status);
            if (status.getStatusCode() == TBrokerOperationStatusCode.OK) {
                response.setData(data);
            }
            return response;
        }

        @Override
        public synchronized TBrokerOperationStatus closeReader(TBrokerCloseReaderRequest request) {
            TBrokerOperationStatusCode code = handle(request.getVersion(), request.getFd());
            Input input = readers.get(request.getFd());
            if (code == TBrokerOperationStatusCode.OK) {
                readers.remove(request.getFd());
                closed++;
            }
            return record("closeReader", code, input == null ? null : input.uri,
                    request.getFd(), null, null, 0);
        }

        @Override
        public synchronized TBrokerOperationStatus seek(TBrokerSeekRequest request) {
            TBrokerOperationStatusCode code = handle(request.getVersion(), request.getFd());
            Input input = readers.get(request.getFd());
            if (code == TBrokerOperationStatusCode.OK
                    && (request.getOffset() < 0 || request.getOffset() > input.bytes.length)) {
                code = TBrokerOperationStatusCode.INVALID_INPUT_OFFSET;
            }
            // pread always uses its explicit absolute offset; seek does not alter or alias another handle.
            return record("seek", code, input == null ? null : input.uri, request.getFd(), request.getOffset(), null, 0);
        }

        @Override
        public synchronized TBrokerOperationStatus ping(TBrokerPingBrokerRequest request) {
            return record("ping", validate(request.getVersion()), null, null, null, null, 0);
        }

        @Override
        public synchronized TBrokerCheckPathExistResponse checkPathExist(TBrokerCheckPathExistRequest request) {
            TBrokerOperationStatusCode code = path(request.getVersion(), request.getPath());
            return new TBrokerCheckPathExistResponse(record("checkPathExist", code, request.getPath(),
                    null, null, null, 0), code == TBrokerOperationStatusCode.OK);
        }

        @Override
        public synchronized TBrokerFileSizeResponse fileSize(TBrokerFileSizeRequest request) {
            TBrokerOperationStatusCode code = path(request.getVersion(), request.getPath());
            TBrokerFileSizeResponse response = new TBrokerFileSizeResponse(record("fileSize", code,
                    request.getPath(), null, null, null, 0));
            if (code == TBrokerOperationStatusCode.OK) {
                response.setFileSize(inputs.get(request.getPath()).bytes.length);
            }
            return response;
        }

        @Override
        public synchronized TBrokerIsSplittableResponse isSplittable(TBrokerIsSplittableRequest request) {
            TBrokerOperationStatusCode code = path(request.getVersion(), request.getPath());
            return new TBrokerIsSplittableResponse().setOpStatus(record("isSplittable", code,
                    request.getPath(), null, null, null, 0)).setSplittable(code == TBrokerOperationStatusCode.OK);
        }

        private TBrokerOperationStatus unsupported(String method) {
            return record(method, TBrokerOperationStatusCode.OPERATION_NOT_SUPPORTED, null, null, null, null, 0);
        }

        @Override
        public synchronized TBrokerOperationStatus deletePath(TBrokerDeletePathRequest request) {
            return unsupported("deletePath");
        }

        @Override
        public synchronized TBrokerOperationStatus renamePath(TBrokerRenamePathRequest request) {
            return unsupported("renamePath");
        }

        @Override
        public synchronized TBrokerOpenWriterResponse openWriter(TBrokerOpenWriterRequest request) {
            return new TBrokerOpenWriterResponse(unsupported("openWriter"));
        }

        @Override
        public synchronized TBrokerOperationStatus pwrite(TBrokerPWriteRequest request) {
            return unsupported("pwrite");
        }

        @Override
        public synchronized TBrokerOperationStatus closeWriter(TBrokerCloseWriterRequest request) {
            return unsupported("closeWriter");
        }

        synchronized void protocolFailure() {
            protocolErrors++;
            stopReason = "protocol_error";
            stopRequested.set(true);
        }

        synchronized Map<String, Object> finish(String namespace) throws IOException {
            int leaked = readers.size();
            List<Map<String, Object>> remaining = new ArrayList<>();
            readers.forEach((fd, input) -> remaining.add(Map.of("handle_high", fd.getHigh(),
                    "handle_low", fd.getLow(), "uri", input.uri)));
            readers.clear();
            try {
                evidence.close();
            } catch (IOException error) {
                evidenceError = true;
                stopReason = "evidence_close_error";
            }
            Map<String, Object> summary = new LinkedHashMap<>();
            summary.put("schema_version", 1);
            summary.put("pid", ProcessHandle.current().pid());
            summary.put("namespace", namespace);
            summary.put("stop_reason", stopReason);
            summary.put("requests", requests);
            summary.put("returned_bytes", returnedBytes);
            summary.put("opened_readers", opened);
            summary.put("closed_readers", closed);
            summary.put("active_readers_before_cleanup", leaked);
            summary.put("readers_before_cleanup", remaining);
            summary.put("cleanup_closed_readers", leaked);
            summary.put("active_readers", 0);
            summary.put("counts", new LinkedHashMap<>(counts));
            summary.put("status_counts", new LinkedHashMap<>(statusCounts));
            summary.put("protocol_errors", protocolErrors);
            summary.put("evidence_error", evidenceError);
            summary.put("finished_at_utc", Instant.now().toString());
            summary.put("bounds", bounds());
            summary.put("LP026_complete", false);
            summary.put("release_performance_pass", false);
            return summary;
        }

        @Override
        public synchronized void close() throws IOException {
            readers.clear();
            evidence.close();
        }
    }

    private static final class BoundedSocket extends TServerSocket {
        final Set<Socket> clients = new HashSet<>();

        BoundedSocket(int port) throws TTransportException {
            super(new InetSocketAddress("127.0.0.1", port), 3000);
        }

        @Override
        public TSocket accept() throws TTransportException {
            try {
                Socket socket = getServerSocket().accept();
                synchronized (clients) {
                    clients.removeIf(Socket::isClosed);
                    if (clients.size() >= 8 || !socket.getInetAddress().isLoopbackAddress()) {
                        socket.close();
                        throw new TTransportException("FIXTURE_CONNECTION_BOUND");
                    }
                    clients.add(socket);
                }
                TSocket thrift = new TSocket(socket);
                thrift.setTimeout(3000);
                thrift.getConfiguration().setMaxMessageSize(MAX_MESSAGE_BYTES);
                thrift.getConfiguration().setMaxFrameSize(MAX_MESSAGE_BYTES);
                thrift.getConfiguration().setRecursionLimit(32);
                thrift.updateKnownMessageSize(0);
                return thrift;
            } catch (IOException error) {
                throw new TTransportException(error);
            }
        }

        void closeClients() {
            synchronized (clients) {
                for (Socket client : clients) {
                    try {
                        client.close();
                    } catch (IOException ignored) {
                        // Socket closure is independently checked by the owning controller.
                    }
                }
                clients.clear();
            }
        }
    }

    public static void main(String[] args) throws Exception {
        require(args.length == 1, "EXPECTED_ONE_ABSOLUTE_CONFIG_PATH");
        Path configPath = Path.of(args[0]);
        Path configDirectory = ownedDirectory(configPath.getParent().toString());
        ownedFile(configDirectory, args[0], true);
        JsonNode config = JSON.readTree(boundedRead(configPath, 65536));
        Path output = ownedDirectory(config.path("output_directory").asText());
        require(configDirectory.equals(output), "CONFIG_MUST_BELONG_TO_OUTPUT_DIRECTORY");
        guardNamespace(config);
        String namespace = namespace();
        Path manifest = ownedFile(output, config.path("input_manifest").asText(), true);
        Path ready = ownedFile(output, config.path("ready_file").asText(), false);
        Path requests = ownedFile(output, config.path("requests_file").asText(), false);
        Path summary = ownedFile(output, config.path("summary_file").asText(), false);
        Path stop = ownedFile(output, config.path("stop_file").asText(), false);
        require(Set.of(configPath, manifest, ready, requests, summary, stop).size() == 6, "ALIASED_CONTROL_FILES");
        int timeout = config.path("timeout_seconds").asInt();
        int port = config.path("port").asInt(0);
        require(timeout >= 1 && timeout <= 900 && port >= 0 && port <= 65535, "INVALID_BOUND_OR_PORT");
        String manifestSha = sha256(boundedRead(manifest, 65536));
        Map<String, Input> inputs = loadInputs(output, manifest);
        require(sha256(boundedRead(manifest, 65536)).equals(manifestSha), "MANIFEST_CHANGED_DURING_LOAD");
        AtomicBoolean stopRequested = new AtomicBoolean();
        Handler handler = new Handler(inputs, requests, stopRequested);
        BoundedSocket socket;
        try {
            socket = new BoundedSocket(port);
        } catch (TTransportException error) {
            handler.stopReason = "bind_failed";
            writeNewJson(summary, handler.finish(namespace));
            throw error;
        }
        ThreadPoolExecutor workers = new ThreadPoolExecutor(4, 4, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(4), runnable -> {
                    Thread thread = new Thread(runnable, "lp026-broker-worker");
                    thread.setDaemon(true);
                    return thread;
                });
        TPaloBrokerService.Processor<Handler> delegate = new TPaloBrokerService.Processor<>(handler);
        TProcessor processor = (input, result) -> {
            try {
                delegate.process(input, result);
            } catch (TTransportException error) {
                // Idle pooled connections may time out or close between ordinary requests.
                if (error.getType() != TTransportException.END_OF_FILE
                        && error.getType() != TTransportException.TIMED_OUT && !stopRequested.get()) {
                    handler.protocolFailure();
                }
                throw error;
            } catch (TException | RuntimeException error) {
                handler.protocolFailure();
                throw error;
            }
        };
        TThreadPoolServer server = new TThreadPoolServer(new TThreadPoolServer.Args(socket)
                .processor(processor).protocolFactory(new TBinaryProtocol.Factory(false, true, MAX_MESSAGE_BYTES, 128))
                .executorService(workers).stopTimeoutVal(3).stopTimeoutUnit(TimeUnit.SECONDS));
        Thread serverThread = new Thread(server::serve, "lp026-broker-server");
        serverThread.setDaemon(true);
        AtomicBoolean cleaned = new AtomicBoolean();
        Runnable cleanup = () -> {
            if (!cleaned.compareAndSet(false, true)) {
                return;
            }
            stopRequested.set(true);
            server.stop();
            socket.close();
            socket.closeClients();
            workers.shutdownNow();
            try {
                boolean terminated = workers.awaitTermination(3, TimeUnit.SECONDS);
                Map<String, Object> report = handler.finish(namespace);
                report.put("worker_threads_terminated", terminated);
                report.put("input_manifest_sha256", manifestSha);
                writeNewJson(summary, report);
            } catch (Exception error) {
                // Only an exception class is printed: paths/properties and client secrets are never echoed.
                System.err.println("BROKER_CLEANUP_FAILED " + error.getClass().getSimpleName());
            }
        };
        Thread shutdownHook = new Thread(() -> {
            if (!stopRequested.get()) {
                handler.stopReason = "signal_or_jvm_shutdown";
            }
            cleanup.run();
        }, "lp026-broker-shutdown");
        Runtime.getRuntime().addShutdownHook(shutdownHook);
        try {
            serverThread.start();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeout);
            long startDeadline = Math.min(deadline, System.nanoTime() + TimeUnit.SECONDS.toNanos(3));
            while (!server.isServing() && serverThread.isAlive() && System.nanoTime() < startDeadline) {
                Thread.sleep(20);
            }
            require(server.isServing(), "BROKER_START_FAILED");
            Map<String, Object> report = new LinkedHashMap<>();
            report.put("schema_version", 1);
            report.put("pid", ProcessHandle.current().pid());
            String stat = Files.readString(Path.of("/proc/self/stat"));
            report.put("start_ticks", Long.parseLong(stat.substring(stat.lastIndexOf(')') + 2).split(" +")[19]));
            report.put("namespace", namespace);
            report.put("port", socket.getServerSocket().getLocalPort());
            report.put("bind_address", "127.0.0.1");
            report.put("input_manifest_sha256", manifestSha);
            report.put("bounds", bounds());
            report.put("ready_at_utc", Instant.now().toString());
            writeNewJson(ready, report);
            while (!stopRequested.get() && !Files.exists(stop, LinkOption.NOFOLLOW_LINKS)
                    && serverThread.isAlive() && System.nanoTime() < deadline) {
                guardNamespace(config);
                Thread.sleep(100);
            }
            if (System.nanoTime() >= deadline) {
                handler.stopReason = "deadline";
            } else if (!serverThread.isAlive()) {
                handler.stopReason = "server_exit";
            }
        } catch (Exception error) {
            handler.stopReason = "main_error_" + error.getClass().getSimpleName();
            throw error;
        } finally {
            cleanup.run();
            Runtime.getRuntime().removeShutdownHook(shutdownHook);
        }
    }
}
