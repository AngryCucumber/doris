// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.common.util.NetUtils;
import org.apache.doris.service.ExecuteEnv;
import org.apache.doris.system.Backend;
import org.apache.doris.system.Frontend;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.net.HostAndPort;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/** FE-only, management-time proof of the running package and installed public trust. */
public final class LicenseFeCompatibility {
    private static final Logger LOG = LogManager.getLogger(LicenseFeCompatibility.class);
    public static final String CLUSTER_TOKEN_HEADER = "X-MassDB-License-Cluster-Token";
    private static final int MAX_CAPABILITY_BYTES = 64 * 1024;
    private static final long PROBE_BUDGET_NANOS = TimeUnit.SECONDS.toNanos(10);
    private static final DiagnosticLimiter DIAGNOSTICS = new DiagnosticLimiter();
    private static final List<Integer> OPCODES = Arrays.asList(6200, 6201, 6202, 6203, 6204, 6205);
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build());

    private LicenseFeCompatibility() {
    }

    // Deliberately lazy: creating a checkpoint Env never hashes a deployment package or starts a probe.
    private static final class PackageDigest {
        private static final String VALUE = packageDigest();
    }

    public static Map<String, Object> localCapability(Env env, String trustDigest) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schema_version", 1);
        result.put("format_version", 1);
        result.put("module", "massdbLicenseV1");
        result.put("journal_opcodes", OPCODES);
        result.put("fe_node_name", env.getNodeName());
        result.put("fe_host", env.getSelfNode() == null ? null : env.getSelfNode().getHost());
        result.put("edit_log_port", env.getSelfNode() == null ? 0 : env.getSelfNode().getPort());
        result.put("process_uuid", ExecuteEnv.getInstance().getProcessUUID());
        result.put("package_sha256", PackageDigest.VALUE);
        result.put("trust_sha256", trustDigest);
        result.put("trust_ready", trustDigest != null);
        return Collections.unmodifiableMap(result);
    }

    /** Registered FE identity proof is independent of BE capacity and heartbeat liveness. */
    public static long frontendVersion(Env env) {
        return membershipVersion(frontendIdentities(env.getFrontends(null)));
    }

    public static LicenseManager.Membership membership(Env env) {
        List<String> identities = frontendIdentities(env.getFrontends(null));
        int feCount = identities.size();
        List<Long> backendIds = env.getClusterInfo().getAllBackendIds(false);
        for (Long id : backendIds) {
            Backend backend = env.getClusterInfo().getBackend(id);
            if (backend == null) {
                // The caller retries if membership changes across verification/commit.
                identities.add("be:" + id + ":removed");
            } else {
                identities.add("be:" + id + ":" + backend.getHost() + ":" + backend.getHeartbeatPort());
            }
        }
        Collections.sort(identities);
        return new LicenseManager.Membership(feCount, backendIds.size(), membershipVersion(identities));
    }

    public static boolean checkAll(Env env, Map<String, Object> local) {
        return checkAll(env, local, DIAGNOSTICS);
    }

    static boolean checkAll(Env env, Map<String, Object> local, DiagnosticLimiter diagnostics) {
        if (!isDigest(local.get("package_sha256"))) {
            return reject(env, null, "LOCAL_PACKAGE_UNAVAILABLE", "package_sha256", 0, diagnostics);
        }
        if (env.getNodeName() == null) {
            return reject(env, null, "LOCAL_IDENTITY_UNAVAILABLE", "fe_node_name", 0, diagnostics);
        }
        Object trustDigest = local.get("trust_sha256");
        if (trustDigest != null && !isDigest(trustDigest)) {
            return reject(env, null, "LOCAL_TRUST_INVALID", "trust_sha256", 0, diagnostics);
        }
        List<Frontend> frontends = env.getFrontends(null);
        List<String> before = frontendIdentities(frontends);
        if (frontends.isEmpty()) {
            return reject(env, null, "EMPTY_MEMBERSHIP", "membership", 0, diagnostics);
        }
        Map<String, Integer> ports;
        try {
            ports = managementPorts(Config.massdb_license_fe_management_ports);
        } catch (IOException e) {
            return reject(env, null, "MANAGEMENT_PORTS_INVALID", "massdb_license_fe_management_ports", 0, diagnostics);
        }
        Map<String, Integer> hostCounts = new LinkedHashMap<>();
        for (Frontend frontend : frontends) {
            hostCounts.merge(frontend.getHost(), 1, Integer::sum);
        }
        long deadline = System.nanoTime() + PROBE_BUDGET_NANOS;
        boolean foundSelf = false;
        for (Frontend frontend : frontends) {
            if (frontend.getNodeName().equals(env.getNodeName())) {
                foundSelf = true;
                String mismatch = mismatchField(JSON.valueToTree(local), frontend, local, false);
                if (mismatch != null) {
                    return reject(env, frontend, "CAPABILITY_MISMATCH", mismatch, 0, diagnostics);
                }
                continue;
            }
            try {
                int defaultPort = Config.enable_https ? Config.https_port : Config.http_port;
                int port = managementPort(frontend, defaultPort, ports);
                // The legacy heartbeat treats all same-host FE identities as self. The fresh endpoint proof
                // remains authoritative for these identities, including their distinct edit-log ports.
                boolean reliableHeartbeat = hostCounts.get(frontend.getHost()) == 1;
                String mismatch = mismatchField(probe(frontend, env.getToken(), deadline, port), frontend,
                        local, reliableHeartbeat);
                if (mismatch != null) {
                    return reject(env, frontend, "CAPABILITY_MISMATCH", mismatch, 0, diagnostics);
                }
            } catch (ProbeFailure e) {
                return reject(env, frontend, e.reason, "probe", e.httpStatus, diagnostics);
            } catch (SocketTimeoutException e) {
                return reject(env, frontend, "PROBE_TIMEOUT", "probe", 0, diagnostics);
            } catch (JsonProcessingException e) {
                return reject(env, frontend, "INVALID_CAPABILITY_JSON", "response", 0, diagnostics);
            } catch (IOException | RuntimeException e) {
                // An old FE, missing trust, offline member or authentication failure cannot prove compatibility.
                return reject(env, frontend, "PROBE_UNAVAILABLE", "probe", 0, diagnostics);
            }
        }
        if (!foundSelf) {
            return reject(env, null, "SELF_NOT_REGISTERED", "membership", 0, diagnostics);
        }
        return before.equals(frontendIdentities(env.getFrontends(null)))
                || reject(env, null, "MEMBERSHIP_CHANGED", "membership", 0, diagnostics);
    }

    static boolean matches(JsonNode capability, Frontend frontend, Map<String, Object> local,
            boolean checkHeartbeatProcess) {
        return mismatchField(capability, frontend, local, checkHeartbeatProcess) == null;
    }

    private static String mismatchField(JsonNode capability, Frontend frontend, Map<String, Object> local,
            boolean checkHeartbeatProcess) {
        if (capability == null || !capability.isObject()) {
            return "response";
        }
        if (!capability.path("schema_version").isIntegralNumber()
                || !capability.path("schema_version").canConvertToInt()
                || capability.path("schema_version").asInt() != 1) {
            return "schema_version";
        }
        if (!capability.path("format_version").isIntegralNumber()
                || !capability.path("format_version").canConvertToInt()
                || capability.path("format_version").asInt() != 1) {
            return "format_version";
        }
        if (!"massdbLicenseV1".equals(capability.path("module").asText())) {
            return "module";
        }
        if (!JSON.valueToTree(OPCODES).equals(capability.path("journal_opcodes"))) {
            return "journal_opcodes";
        }
        if (!frontend.getNodeName().equals(capability.path("fe_node_name").asText())) {
            return "fe_node_name";
        }
        if (!frontend.getHost().equals(capability.path("fe_host").asText())) {
            return "fe_host";
        }
        if (!capability.path("edit_log_port").isIntegralNumber()
                || !capability.path("edit_log_port").canConvertToInt()
                || frontend.getEditLogPort() != capability.path("edit_log_port").asInt()) {
            return "edit_log_port";
        }
        if (!capability.path("process_uuid").isIntegralNumber()
                || !capability.path("process_uuid").canConvertToLong()
                || capability.path("process_uuid").asLong() == 0) {
            return "process_uuid";
        }
        if (!Objects.equals(local.get("package_sha256"), nullableText(capability.get("package_sha256")))) {
            return "package_sha256";
        }
        if (!capability.has("trust_sha256")
                || !Objects.equals(local.get("trust_sha256"), nullableText(capability.get("trust_sha256")))) {
            return "trust_sha256";
        }
        if (!capability.path("trust_ready").isBoolean()
                || capability.path("trust_ready").asBoolean() != (local.get("trust_sha256") != null)) {
            return "trust_ready";
        }
        return !checkHeartbeatProcess || frontend.getProcessUUID() == 0
                || frontend.getProcessUUID() == capability.path("process_uuid").asLong() ? null : "process_uuid";
    }

    private static boolean reject(Env env, Frontend frontend, String reason, String field, int httpStatus,
            DiagnosticLimiter diagnostics) {
        if (diagnostics.acquire(System.nanoTime())) {
            String node = frontend == null ? env.getNodeName() : frontend.getNodeName();
            String host = frontend == null ? env.getSelfNode() == null ? null : env.getSelfNode().getHost()
                    : frontend.getHost();
            int port = frontend == null ? env.getSelfNode() == null ? 0 : env.getSelfNode().getPort()
                    : frontend.getEditLogPort();
            // Never include a capability value, cluster token, HTTP body or exception/provider message.
            LOG.warn("License FE compatibility proof failed: node={}, host={}, editLogPort={}, "
                            + "reason={}, field={}, httpStatus={}",
                    safeIdentity(node), safeIdentity(host), port, reason, field, httpStatus);
        }
        return false;
    }

    private static String safeIdentity(String value) {
        if (value == null) {
            return "unavailable";
        }
        StringBuilder safe = new StringBuilder(Math.min(value.length(), 128));
        for (int i = 0; i < value.length() && i < 128; i++) {
            char c = value.charAt(i);
            safe.append(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
                    || c == '_' || c == '-' || c == '.' || c == ':' || c == '%' ? c : '_');
        }
        return safe.toString();
    }

    /** A single bounded warning stream per FE process; only management-time failures enter this lock. */
    static final class DiagnosticLimiter {
        private boolean emitted;
        private long lastNanos;

        synchronized boolean acquire(long nowNanos) {
            if (emitted && nowNanos - lastNanos < TimeUnit.SECONDS.toNanos(60)) {
                return false;
            }
            emitted = true;
            lastNanos = nowNanos;
            return true;
        }
    }

    private static final class ProbeFailure extends IOException {
        private final String reason;
        private final int httpStatus;

        private ProbeFailure(String reason, int httpStatus) {
            super(reason);
            this.reason = reason;
            this.httpStatus = httpStatus;
        }
    }

    static Map<String, Integer> managementPorts(String[] entries) throws IOException {
        if (entries == null || entries.length > 1024) {
            throw new IOException("Invalid license FE management port map");
        }
        Map<String, Integer> ports = new LinkedHashMap<>();
        for (String entry : entries) {
            try {
                if (entry == null || entry.length() > 1024) {
                    throw new IllegalArgumentException();
                }
                int separator = entry.indexOf('=');
                if (separator < 1 || separator != entry.lastIndexOf('=')) {
                    throw new IllegalArgumentException();
                }
                String identity = entry.substring(0, separator).trim();
                HostAndPort address = HostAndPort.fromString(identity).requireBracketsForIPv6();
                String host = address.getHost();
                if (!address.hasPort() || address.getPort() < 1 || host.isEmpty()
                        || !host.matches("[A-Za-z0-9_.:%-]+")
                        || !identity.equals(NetUtils.getHostPortInAccessibleFormat(host, address.getPort()))) {
                    throw new IllegalArgumentException();
                }
                String value = entry.substring(separator + 1).trim();
                if (!value.matches("[0-9]{1,5}")) {
                    throw new IllegalArgumentException();
                }
                int port = Integer.parseInt(value);
                if (port < 1 || port > 65535 || ports.put(identity, port) != null) {
                    throw new IllegalArgumentException();
                }
            } catch (IllegalArgumentException e) {
                throw new IOException("Invalid license FE management port map");
            }
        }
        return Collections.unmodifiableMap(ports);
    }

    public static int managementPort(Frontend frontend, int defaultPort) throws IOException {
        return managementPort(frontend, defaultPort, managementPorts(Config.massdb_license_fe_management_ports));
    }

    static int managementPort(Frontend frontend, int defaultPort, Map<String, Integer> ports) {
        String identity = NetUtils.getHostPortInAccessibleFormat(frontend.getHost(), frontend.getEditLogPort());
        return ports.getOrDefault(identity, defaultPort);
    }

    private static JsonNode probe(Frontend frontend, String token, long deadline, int port) throws IOException {
        long remainingMillis = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
        if (remainingMillis <= 0) {
            throw new ProbeFailure("PROBE_DEADLINE", 0);
        }
        if (token == null || token.isEmpty()) {
            throw new ProbeFailure("CLUSTER_TOKEN_UNAVAILABLE", 0);
        }
        String scheme = Config.enable_https ? "https" : "http";
        URL url = new URL(scheme + "://" + NetUtils.getHostPortInAccessibleFormat(frontend.getHost(), port)
                + "/api/license/capability");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
        try {
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout((int) Math.min(2000, remainingMillis));
            connection.setReadTimeout((int) Math.min(2000, remainingMillis));
            connection.setRequestProperty(CLUSTER_TOKEN_HEADER, token);
            connection.setRequestProperty("Accept", "application/json");
            int status = connection.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                throw new ProbeFailure("HTTP_STATUS", status);
            }
            if (connection.getContentLengthLong() > MAX_CAPABILITY_BYTES) {
                throw new ProbeFailure("CAPABILITY_TOO_LARGE", status);
            }
            try (InputStream input = connection.getInputStream()) {
                try (JsonParser parser = JSON.createParser(readBounded(input, deadline))) {
                    JsonNode result = JSON.readTree(parser);
                    if (parser.nextToken() != null) {
                        throw new ProbeFailure("INVALID_CAPABILITY_JSON", 0);
                    }
                    return result;
                }
            }
        } finally {
            connection.disconnect();
        }
    }

    static byte[] readBounded(InputStream input, long deadline) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = input.read(buffer)) != -1) {
            if (System.nanoTime() > deadline) {
                throw new ProbeFailure("PROBE_DEADLINE", 0);
            }
            if (output.size() + read > MAX_CAPABILITY_BYTES) {
                throw new ProbeFailure("CAPABILITY_TOO_LARGE", 0);
            }
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    private static List<String> frontendIdentities(List<Frontend> frontends) {
        List<String> result = new ArrayList<>();
        for (Frontend frontend : frontends) {
            String name = frontend.getNodeName();
            String host = frontend.getHost();
            result.add("fe:" + name.length() + ":" + name + host.length() + ":" + host + ":"
                    + frontend.getEditLogPort() + ":" + frontend.getRole());
        }
        Collections.sort(result);
        return result;
    }

    static long membershipVersion(List<String> identities) {
        MessageDigest digest = sha256();
        for (String identity : identities) {
            digest.update(identity.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
        }
        byte[] bytes = digest.digest();
        long result = 0;
        for (int i = 0; i < Long.BYTES; i++) {
            result = (result << 8) | (bytes[i] & 0xffL);
        }
        return result & Long.MAX_VALUE;
    }

    private static String packageDigest() {
        try {
            Path path = Paths.get(LicenseFeCompatibility.class.getProtectionDomain().getCodeSource()
                    .getLocation().toURI());
            if (!Files.isRegularFile(path) || !path.getFileName().toString().endsWith(".jar")) {
                return null;
            }
            MessageDigest digest = sha256();
            try (InputStream input = Files.newInputStream(path)) {
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    digest.update(buffer, 0, read);
                }
            }
            StringBuilder result = new StringBuilder(64);
            for (byte value : digest.digest()) {
                result.append(Character.forDigit((value >>> 4) & 15, 16));
                result.append(Character.forDigit(value & 15, 16));
            }
            return result.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK SHA-256 unavailable", e);
        }
    }

    private static boolean isDigest(Object value) {
        return value instanceof String && ((String) value).matches("[0-9a-f]{64}");
    }

    private static String nullableText(JsonNode value) {
        return value == null || value.isNull() ? null : value.isTextual() ? value.textValue() : "invalid";
    }
}
