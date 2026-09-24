// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import org.apache.doris.massdb.license.LicenseException;
import org.apache.doris.massdb.license.LicenseTrustStore;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** Read-only public manifest review against the explicitly selected delivered FE classes. */
public final class LicensePublicTrustProbe {
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build());

    private LicensePublicTrustProbe() {
    }

    private static byte[] bounded(Path path, int limit) throws Exception {
        try (InputStream input = Files.newInputStream(path)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                if (output.size() + read > limit) {
                    throw new IllegalArgumentException("INPUT_BOUND");
                }
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }

    private static String sha(byte[] bytes) throws Exception {
        StringBuilder value = new StringBuilder();
        for (byte item : MessageDigest.getInstance("SHA-256").digest(bytes)) {
            value.append(String.format("%02x", item & 255));
        }
        return value.toString();
    }

    private static Set<String> dependencies(JsonNode root, String field) {
        JsonNode values = root.get(field);
        if (values == null || !values.isArray() || values.size() > 32) {
            throw new IllegalArgumentException("DEPENDENCY_BOUND");
        }
        Set<String> result = new HashSet<>();
        for (JsonNode value : values) {
            if (!value.isTextual() || !result.add(value.textValue())) {
                throw new IllegalArgumentException("DEPENDENCY_TYPE_OR_DUPLICATE");
            }
        }
        return result;
    }

    private static Map<String, Object> classIdentity(Class<?> type) throws Exception {
        String resource = "/" + type.getName().replace('.', '/') + ".class";
        byte[] bytes;
        try (InputStream input = type.getResourceAsStream(resource)) {
            if (input == null) {
                throw new IllegalStateException("MISSING_LOADED_CLASS");
            }
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                if (output.size() + read > 2 * 1024 * 1024) {
                    throw new IllegalStateException("CLASS_BOUND");
                }
                output.write(buffer, 0, read);
            }
            bytes = output.toByteArray();
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("sha256", sha(bytes));
        result.put("major", ((bytes[6] & 255) << 8) | (bytes[7] & 255));
        result.put("source", Paths.get(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
        return result;
    }

    public static void main(String[] args) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        int exit = 0;
        try {
            if (args.length != 3 || args[1].equals("-") != args[2].equals("-")) {
                throw new IllegalArgumentException("ARGUMENTS");
            }
            byte[] currentBytes = bounded(Paths.get(args[0]), 65536);
            LicenseTrustStore current = LicenseTrustStore.parse(currentBytes);
            current.newLicenseVerifier();
            new org.apache.doris.massdb.license.LicenseClockRepairVerifier(
                    current.getKeys(LicenseTrustStore.Purpose.TIME_REPAIR));
            result.put("license_verifier_constructed", true);
            result.put("repair_verifier_constructed", true);
            List<Map<String, Object>> keys = new ArrayList<>();
            for (LicenseTrustStore.Purpose purpose : LicenseTrustStore.Purpose.values()) {
                for (Map.Entry<String, PublicKey> key : new TreeMap<>(current.getKeys(purpose)).entrySet()) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("kid", key.getKey());
                    entry.put("purpose", purpose == LicenseTrustStore.Purpose.LICENSE ? "license" : "time_repair");
                    entry.put("spki_sha256", sha(key.getValue().getEncoded()));
                    entry.put("spki_bytes", key.getValue().getEncoded().length);
                    keys.add(entry);
                }
            }
            result.put("keys", keys);
            result.put("manifest_sha256", sha(currentBytes));
            result.put("rotation_checked", !args[1].equals("-"));
            if (!args[1].equals("-")) {
                byte[] previous = bounded(Paths.get(args[1]), 65536);
                byte[] dependencyBytes = bounded(Paths.get(args[2]), 65536);
                JsonNode required;
                try (com.fasterxml.jackson.core.JsonParser parser = JSON.createParser(dependencyBytes)) {
                    required = JSON.readTree(parser);
                    if (parser.nextToken() != null) {
                        throw new IllegalArgumentException("DEPENDENCY_TRAILING_INPUT");
                    }
                }
                if (!required.isObject() || required.size() != 4
                        || !required.path("schema_version").isIntegralNumber()
                        || !required.path("schema_version").canConvertToInt()
                        || required.path("schema_version").intValue() != 1
                        || !sha(previous).equals(required.path("previous_manifest_sha256").textValue())) {
                    throw new IllegalArgumentException("DEPENDENCY_IDENTITY");
                }
                LicenseTrustStore.parse(previous).requireSafeReplacement(current, Collections.emptyList(),
                        dependencies(required, "license_kids"), dependencies(required, "time_repair_kids"));
                result.put("previous_manifest_sha256", sha(previous));
                result.put("retention_sha256", sha(dependencyBytes));
            }
            Map<String, Object> classes = new LinkedHashMap<>();
            for (Class<?> type : new Class<?>[] {LicenseTrustStore.class, LicenseTrustStore.Purpose.class,
                    LicenseException.class,
                    org.apache.doris.massdb.license.LicenseText.class,
                    org.apache.doris.massdb.license.LicenseDocument.class,
                    org.apache.doris.massdb.license.LicenseErrorCode.class,
                    org.apache.doris.massdb.license.LicenseVerifier.class,
                    org.apache.doris.massdb.license.LicenseClockRepairVerifier.class,
                    ObjectMapper.class, JsonFactory.class}) {
                classes.put(type.getName(), classIdentity(type));
            }
            result.put("loaded_classes", classes);
            result.put("java_runtime_version", System.getProperty("java.runtime.version"));
            result.put("java_vendor", System.getProperty("java.vendor"));
            result.put("os_arch", System.getProperty("os.arch"));
            result.put("ed25519_provider", Signature.getInstance("Ed25519").getProvider().getName());
            result.put("status", "PUBLIC_MANIFEST_ACCEPTED");
        } catch (LicenseException error) {
            result.clear();
            result.put("status", "REJECTED");
            result.put("error_code", error.getErrorCode().name());
            exit = 2;
        } catch (Exception error) {
            result.clear();
            result.put("status", "ERROR");
            result.put("error_class", error.getClass().getSimpleName());
            exit = 3;
        }
        System.out.write(JSON.writeValueAsBytes(result));
        System.out.write('\n');
        System.out.flush();
        System.exit(exit);
    }
}
