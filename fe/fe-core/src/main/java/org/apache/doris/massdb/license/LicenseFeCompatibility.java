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
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.net.HostAndPort;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
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
    public static final String CLUSTER_TOKEN_HEADER = "X-MassDB-License-Cluster-Token";
    private static final int MAX_CAPABILITY_BYTES = 64 * 1024;
    private static final long PROBE_BUDGET_NANOS = TimeUnit.SECONDS.toNanos(10);
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
        if (!isDigest(local.get("package_sha256")) || env.getNodeName() == null) {
            return false;
        }
        Object trustDigest = local.get("trust_sha256");
        if (trustDigest != null && !isDigest(trustDigest)) {
            return false;
        }
        List<Frontend> frontends = env.getFrontends(null);
        List<String> before = frontendIdentities(frontends);
        if (frontends.isEmpty()) {
            return false;
        }
        Map<String, Integer> ports;
        try {
            ports = managementPorts(Config.massdb_license_fe_management_ports);
        } catch (IOException e) {
            return false;
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
                if (!matches(JSON.valueToTree(local), frontend, local, false)) {
                    return false;
                }
                continue;
            }
            try {
                int defaultPort = Config.enable_https ? Config.https_port : Config.http_port;
                int port = managementPort(frontend, defaultPort, ports);
                // The legacy heartbeat treats all same-host FE identities as self. The fresh endpoint proof
                // remains authoritative for these identities, including their distinct edit-log ports.
                boolean reliableHeartbeat = hostCounts.get(frontend.getHost()) == 1;
                if (!matches(probe(frontend, env.getToken(), deadline, port), frontend, local, reliableHeartbeat)) {
                    return false;
                }
            } catch (IOException | RuntimeException e) {
                // An old FE, missing trust, offline member or authentication failure cannot prove compatibility.
                return false;
            }
        }
        return foundSelf && before.equals(frontendIdentities(env.getFrontends(null)));
    }

    static boolean matches(JsonNode capability, Frontend frontend, Map<String, Object> local,
            boolean checkHeartbeatProcess) {
        if (capability == null || !capability.isObject()
                || !capability.path("schema_version").isIntegralNumber()
                || !capability.path("schema_version").canConvertToInt()
                || capability.path("schema_version").asInt() != 1
                || !capability.path("format_version").isIntegralNumber()
                || !capability.path("format_version").canConvertToInt()
                || capability.path("format_version").asInt() != 1
                || !"massdbLicenseV1".equals(capability.path("module").asText())
                || !JSON.valueToTree(OPCODES).equals(capability.path("journal_opcodes"))
                || !frontend.getNodeName().equals(capability.path("fe_node_name").asText())
                || !frontend.getHost().equals(capability.path("fe_host").asText())
                || !capability.path("edit_log_port").isIntegralNumber()
                || !capability.path("edit_log_port").canConvertToInt()
                || frontend.getEditLogPort() != capability.path("edit_log_port").asInt()
                || !capability.path("process_uuid").isIntegralNumber()
                || !capability.path("process_uuid").canConvertToLong()
                || capability.path("process_uuid").asLong() == 0
                || !Objects.equals(local.get("package_sha256"), nullableText(capability.get("package_sha256")))
                || !capability.has("trust_sha256")
                || !Objects.equals(local.get("trust_sha256"), nullableText(capability.get("trust_sha256")))
                || !capability.path("trust_ready").isBoolean()
                || capability.path("trust_ready").asBoolean() != (local.get("trust_sha256") != null)) {
            return false;
        }
        return !checkHeartbeatProcess || frontend.getProcessUUID() == 0
                || frontend.getProcessUUID() == capability.path("process_uuid").asLong();
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
        if (remainingMillis <= 0 || token == null || token.isEmpty()) {
            throw new IOException("License compatibility proof unavailable");
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
            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK
                    || connection.getContentLengthLong() > MAX_CAPABILITY_BYTES) {
                throw new IOException("License compatibility proof unavailable");
            }
            try (InputStream input = connection.getInputStream()) {
                try (JsonParser parser = JSON.createParser(readBounded(input, deadline))) {
                    JsonNode result = JSON.readTree(parser);
                    if (parser.nextToken() != null) {
                        throw new IOException("Trailing license capability content");
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
            if (System.nanoTime() > deadline || output.size() + read > MAX_CAPABILITY_BYTES) {
                throw new IOException("License compatibility proof exceeds resource limit");
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
