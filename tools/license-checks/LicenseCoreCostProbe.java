// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import org.apache.doris.massdb.license.LicenseClock;
import org.apache.doris.massdb.license.LicenseDocument;
import org.apache.doris.massdb.license.LicenseSnapshot;
import org.apache.doris.massdb.license.LicenseTrustStore;
import org.apache.doris.massdb.license.LicenseVerifier;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Simple bounded P1 cost harness. Not JMH, a release performance gate, or an SQL A/B benchmark. */
public final class LicenseCoreCostProbe {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static volatile long consumed;
    private static volatile Object retainedManagementResult;
    private volatile LicenseSnapshot[] valid;
    private volatile LicenseSnapshot[] mixed;
    private volatile String[] certificates;
    private volatile byte[][] manifests;
    private final LicenseVerifier verifier;
    private final LicenseClock clock;
    private final long now;
    private final AllocationMeter allocations = new AllocationMeter();

    private interface Task {
        long apply(int input) throws Exception;
    }

    private LicenseCoreCostProbe() throws Exception {
        now = System.currentTimeMillis() / 1000;
        clock = new LicenseClock(new LicenseClock.Facts(0, 0, now * 1000, 0), LicenseClock.SYSTEM);
        UUID deployment = UUID.randomUUID();
        KeyPair licenseKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        KeyPair repairKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        verifier = new LicenseVerifier(Collections.singletonMap("cost-license", licenseKey.getPublic()));
        valid = new LicenseSnapshot[16];
        mixed = new LicenseSnapshot[16];
        certificates = new String[16];
        manifests = new byte[16][];
        for (int i = 0; i < 16; i++) {
            ObjectNode claims = JSON.createObjectNode();
            claims.put("schema_version", 1);
            claims.put("policy_version", 1);
            claims.put("product", "MassDB SQL");
            claims.put("deployment_id", deployment.toString());
            claims.put("license_id", "ephemeral-cost-" + i);
            claims.put("issuer", "Cost Probe");
            claims.put("customer_id", "Ephemeral customer " + i);
            claims.put("edition", "Enterprise");
            claims.put("issued_at", now - 7200);
            claims.put("not_before", now - 3600);
            claims.put("expires_at", now + 86400L * (365 + i));
            claims.put("sequence", i + 1);
            claims.putArray("features").add("DATA_QUERY");
            ObjectNode limits = claims.putObject("limits");
            limits.put("max_fe_nodes", 3 + i);
            limits.put("max_be_nodes", 8 + i);
            ObjectNode header = JSON.createObjectNode();
            header.put("typ", "massdb-license+jws");
            header.put("alg", "Ed25519");
            header.put("kid", "cost-license");
            String input = encode(JSON.writeValueAsBytes(header)) + "." + encode(JSON.writeValueAsBytes(claims));
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(licenseKey.getPrivate());
            signature.update(input.getBytes(StandardCharsets.US_ASCII));
            certificates[i] = input + "." + encode(signature.sign());
            LicenseDocument document = verifier.verify(certificates[i]);
            valid[i] = new LicenseSnapshot(deployment, document, null, document, 1 + i % 3, 1 + i % 8,
                    true, false, false, i + 1, i + 1);
            mixed[i] = new LicenseSnapshot(deployment, i % 4 == 0 ? null : document, null, document,
                    i % 4 == 1 ? 100 : 1, 1, i % 4 != 2, false, false, i + 1, i + 1);
            ObjectNode manifest = JSON.createObjectNode();
            manifest.put("schema_version", 1);
            ObjectNode publicLicense = manifest.putArray("keys").addObject();
            publicLicense.put("kid", "cost-license-" + i);
            publicLicense.put("purpose", "license");
            publicLicense.put("public_key_spki", encode(licenseKey.getPublic().getEncoded()));
            ObjectNode publicRepair = ((com.fasterxml.jackson.databind.node.ArrayNode) manifest.get("keys"))
                    .addObject();
            publicRepair.put("kid", "cost-repair-" + i);
            publicRepair.put("purpose", "time_repair");
            publicRepair.put("public_key_spki", encode(repairKey.getPublic().getEncoded()));
            manifests[i] = JSON.writeValueAsBytes(manifest);
        }
        // Setup-only ephemeral private keys are not written or included in reports.
    }

    public static void main(String[] args) throws Exception {
        int hotOperations = Integer.parseInt(args[0]);
        int managementOperations = Integer.parseInt(args[1]);
        int warmupRounds = Integer.parseInt(args[2]);
        int samples = Integer.parseInt(args[3]);
        LicenseCoreCostProbe probe = new LicenseCoreCostProbe();
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("harness", "bounded single-thread simple harness; not JMH or end-to-end A/B");
        report.put("java_runtime", System.getProperty("java.runtime.version"));
        report.put("java_vendor", System.getProperty("java.vendor"));
        report.put("os_arch", System.getProperty("os.arch"));
        report.put("jvm_arguments", ManagementFactory.getRuntimeMXBean().getInputArguments());
        report.put("thread_allocation_supported", probe.allocations.supported());
        report.put("fixture_count", 16);
        List<Map<String, Object>> results = new ArrayList<>();
        results.add(probe.measure("harness_input_control", input -> input & 15,
                hotOperations, warmupRounds, samples));
        results.add(probe.measure("snapshot_status_long_valid", input ->
                probe.valid[index(input)].queryStatus(probe.now + (input & 31)).ordinal(),
                hotOperations, warmupRounds, samples));
        results.add(probe.measure("snapshot_status_long_mixed", input ->
                probe.mixed[index(input)].queryStatus(probe.now + (input & 31)).ordinal(),
                hotOperations, warmupRounds, samples));
        results.add(probe.measure("trusted_clock_seconds", input -> probe.clock.trustedNowSeconds(),
                hotOperations, warmupRounds, samples));
        results.add(probe.measure("snapshot_status_live_clock_valid", input ->
                probe.valid[index(input)].queryStatus(probe.clock).ordinal(),
                hotOperations, warmupRounds, samples));
        results.add(probe.measure("license_verification_management", probe::verifyManagement,
                managementOperations, warmupRounds, samples));
        results.add(probe.measure("trust_manifest_parse_management", probe::parseTrustManagement,
                managementOperations, warmupRounds, samples));
        report.put("measurements", results);
        report.put("consumed_checksum", consumed);
        report.put("clock_suspect_at_end", probe.clock.isSuspect());
        System.out.println(JSON.writeValueAsString(report));
    }

    private long verifyManagement(int input) throws Exception {
        LicenseDocument document = verifier.verify(certificates[index(input)]);
        retainedManagementResult = document;
        return document.getSequence();
    }

    private long parseTrustManagement(int input) throws Exception {
        LicenseTrustStore trust = LicenseTrustStore.parse(manifests[index(input)]);
        retainedManagementResult = trust;
        return trust.getKeys(LicenseTrustStore.Purpose.LICENSE).size();
    }

    private Map<String, Object> measure(String name, Task task, int operations, int warmupRounds, int samples)
            throws Exception {
        int warmupOperations = Math.max(1, operations / 2);
        for (int round = 0; round < warmupRounds; round++) {
            consume(task, warmupOperations, round);
        }
        List<Map<String, Object>> results = new ArrayList<>();
        for (int round = 0; round < samples; round++) {
            long[] gcBefore = gc();
            long allocatedBefore = allocations.bytes();
            long start = System.nanoTime();
            consume(task, operations, round + warmupRounds);
            long elapsed = System.nanoTime() - start;
            long allocatedAfter = allocations.bytes();
            long[] gcAfter = gc();
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("operations", operations);
            result.put("elapsed_nanos", elapsed);
            result.put("ns_per_operation", (double) elapsed / operations);
            result.put("thread_allocated_bytes", allocatedBefore < 0 ? null : allocatedAfter - allocatedBefore);
            result.put("allocated_bytes_per_operation", allocatedBefore < 0 ? null
                    : (double) (allocatedAfter - allocatedBefore) / operations);
            result.put("gc_collections", gcAfter[0] - gcBefore[0]);
            result.put("gc_millis", gcAfter[1] - gcBefore[1]);
            results.add(result);
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", name);
        result.put("warmup_rounds", warmupRounds);
        result.put("warmup_operations_per_round", warmupOperations);
        result.put("samples", results);
        return result;
    }

    private static void consume(Task task, int operations, int salt) throws Exception {
        long checksum = 0;
        for (int i = 0; i < operations; i++) {
            checksum += task.apply(i ^ (salt * 0x45d9f3b));
        }
        consumed ^= checksum;
    }

    private static int index(int input) {
        return (input ^ (input >>> 13)) & 15;
    }

    private static long[] gc() {
        long collections = 0;
        long millis = 0;
        for (GarbageCollectorMXBean collector : ManagementFactory.getGarbageCollectorMXBeans()) {
            collections += Math.max(0, collector.getCollectionCount());
            millis += Math.max(0, collector.getCollectionTime());
        }
        return new long[] {collections, millis};
    }

    private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static final class AllocationMeter {
        private final Object bean = ManagementFactory.getThreadMXBean();
        private final Method allocated;
        private final long thread = Thread.currentThread().getId();

        private AllocationMeter() throws Exception {
            Class<?> type = Class.forName("com.sun.management.ThreadMXBean");
            if (type.isInstance(bean) && (boolean) type.getMethod("isThreadAllocatedMemorySupported").invoke(bean)) {
                type.getMethod("setThreadAllocatedMemoryEnabled", boolean.class).invoke(bean, true);
                allocated = type.getMethod("getThreadAllocatedBytes", long.class);
            } else {
                allocated = null;
            }
        }

        private boolean supported() {
            return allocated != null;
        }

        private long bytes() throws Exception {
            return allocated == null ? -1 : (long) allocated.invoke(bean, thread);
        }
    }
}
