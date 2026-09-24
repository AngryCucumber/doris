// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import org.apache.doris.massdb.license.LicenseClock;
import org.apache.doris.massdb.license.LicenseDocument;
import org.apache.doris.massdb.license.LicenseErrorCode;
import org.apache.doris.massdb.license.LicenseException;
import org.apache.doris.massdb.license.LicenseQueryStatus;
import org.apache.doris.massdb.license.LicenseSnapshot;
import org.apache.doris.massdb.license.LicenseVerifier;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Bounded, instrumented P1 primitive windows; this is not an SQL or full LP023 performance gate. */
public final class LicensePrimitiveCostProbe {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int SIGNIFICANT_BITS = 12;
    private static final int HALF_BUCKET = 1 << (SIGNIFICANT_BITS - 1);
    private static final int HISTOGRAM_SIZE = 64 * HALF_BUCKET;
    private final LicenseVerifier verifier;
    private final LicenseClock clock;
    private volatile LicenseSnapshot[] snapshots;
    private volatile String certificate;
    private final String operation;
    private final long at;
    private final long timeoutSeconds;
    private final String expectedCpuAffinity;

    private LicensePrimitiveCostProbe(JsonNode config) throws Exception {
        byte[] spki = Files.readAllBytes(Paths.get(config.get("public_key").asText()));
        PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
        verifier = new LicenseVerifier(Collections.singletonMap("a", key));
        certificate = new String(Files.readAllBytes(Paths.get(config.get("certificate").asText())),
                StandardCharsets.US_ASCII);
        operation = config.get("operation").asText();
        timeoutSeconds = config.get("timeout_seconds").asLong();
        expectedCpuAffinity = config.get("expected_cpu_affinity").asText();
        at = System.currentTimeMillis() / 1000;
        clock = new LicenseClock(new LicenseClock.Facts(0, 0, at * 1000, 0), LicenseClock.SYSTEM);
        if ("license_rejection_management".equals(operation)) {
            try {
                verifier.verify(certificate);
                throw new IllegalArgumentException("Negative fixture was accepted");
            } catch (LicenseException failure) {
                if (failure.getErrorCode() != LicenseErrorCode.INVALID_CLAIMS) {
                    throw failure;
                }
            }
        } else {
            LicenseDocument document = verifier.verify(certificate);
            snapshots = new LicenseSnapshot[16];
            for (int index = 0; index < snapshots.length; index++) {
                snapshots[index] = new LicenseSnapshot(document.getDeploymentId(), document, null, document,
                        1, 1, true, false, false, index + 1, index + 1);
                if (snapshots[index].queryStatus(clock) != LicenseQueryStatus.VALID) {
                    throw new IllegalArgumentException("Positive fixture must currently be VALID");
                }
            }
        }
    }

    private long invoke(Worker worker, long index) throws Exception {
        switch (operation) {
            case "harness_input_control":
                return index & 15;
            case "snapshot_status_long_valid":
                return requireValid(snapshots[(int) (index & 15)].queryStatus(at + (index & 31)));
            case "snapshot_status_live_clock_valid":
                return requireValid(snapshots[(int) (index & 15)].queryStatus(clock));
            case "trusted_clock_seconds":
                return clock.trustedNowSeconds();
            case "license_verification_management":
                LicenseDocument document = verifier.verify(certificate);
                worker.retained = document;
                return document.getSequence();
            case "license_rejection_management":
                try {
                    verifier.verify(certificate);
                    throw new IllegalStateException("Negative fixture was accepted during measurement");
                } catch (LicenseException failure) {
                    if (failure.getErrorCode() != LicenseErrorCode.INVALID_CLAIMS) {
                        throw failure;
                    }
                    return 1;
                }
            default:
                throw new IllegalArgumentException("Unsupported P1 primitive");
        }
    }

    private static long requireValid(LicenseQueryStatus status) {
        if (status != LicenseQueryStatus.VALID) {
            throw new IllegalStateException("Snapshot changed out of VALID");
        }
        return status.ordinal() + 1;
    }

    static int bucket(long value) {
        if (value < 0) {
            throw new IllegalArgumentException("Negative latency");
        }
        int shift = Math.max(0, 64 - Long.numberOfLeadingZeros(value) - SIGNIFICANT_BITS);
        return (int) (value >>> shift) + shift * HALF_BUCKET;
    }

    static long lower(int index) {
        int shift = Math.max(0, index / HALF_BUCKET - 1);
        return ((long) index - shift * HALF_BUCKET) << shift;
    }

    static long upper(int index) {
        int shift = Math.max(0, index / HALF_BUCKET - 1);
        return lower(index) + (1L << shift) - 1;
    }

    private final class Worker extends Thread {
        private final long minimum;
        private final boolean record;
        private final Phase phase;
        private final long[] histogram = new long[HISTOGRAM_SIZE];
        private volatile Object retained;
        private long operations;
        private long firstStart;
        private long lastEnd;
        private long checksum;
        private String cpusBefore;
        private String cpusAfter;

        private Worker(int id, long minimum, boolean record, Phase phase) {
            super("lp023-" + id);
            this.minimum = minimum;
            this.record = record;
            this.phase = phase;
            setDaemon(true);
        }

        @Override
        public void run() {
            boolean ready = false;
            try {
                cpusBefore = cpuAffinity("/proc/thread-self/status");
                requireCpuAffinity(cpusBefore, expectedCpuAffinity);
                phase.ready.countDown();
                ready = true;
                await(phase.start, timeoutSeconds);
                do {
                    if (phase.failure.get() != null) {
                        break;
                    }
                    long begin = System.nanoTime();
                    if (operations == 0) {
                        firstStart = begin;
                    }
                    checksum += invoke(this, operations);
                    lastEnd = System.nanoTime();
                    if (record) {
                        histogram[bucket(lastEnd - begin)]++;
                    }
                    operations++;
                } while (operations < minimum || lastEnd < phase.deadline);
            } catch (Throwable failure) {
                phase.failure.compareAndSet(null, failure);
            } finally {
                if (!ready) {
                    phase.ready.countDown();
                }
                try {
                    cpusAfter = cpuAffinity("/proc/thread-self/status");
                    requireCpuAffinity(cpusAfter, expectedCpuAffinity);
                } catch (Throwable failure) {
                    phase.failure.compareAndSet(null, failure);
                }
                phase.done.countDown();
                try {
                    await(phase.release, timeoutSeconds);
                } catch (Exception failure) {
                    phase.failure.compareAndSet(null, failure);
                }
            }
        }
    }

    private static final class Phase {
        private final CountDownLatch ready;
        private final CountDownLatch start = new CountDownLatch(1);
        private final CountDownLatch done;
        private final CountDownLatch release = new CountDownLatch(1);
        private final AtomicReference<Throwable> failure = new AtomicReference<>();
        private long epoch;
        private long deadline;

        private Phase(int workers) {
            ready = new CountDownLatch(workers);
            done = new CountDownLatch(workers);
        }
    }

    private static void await(CountDownLatch latch, long timeout) throws Exception {
        if (!latch.await(timeout, TimeUnit.SECONDS)) {
            throw new IllegalStateException("Bounded worker lifecycle timeout");
        }
    }

    private Map<String, Object> phase(int threads, long minimum, long durationNanos, boolean record)
            throws Exception {
        Phase phase = new Phase(threads);
        List<Worker> workers = new ArrayList<>();
        for (int index = 0; index < threads; index++) {
            Worker worker = new Worker(index, minimum / threads + (index < minimum % threads ? 1 : 0),
                    record, phase);
            workers.add(worker);
            worker.start();
        }
        Counters counters = new Counters();
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            await(phase.ready, timeoutSeconds);
            long[] gcBefore = gc();
            Map<String, Long> rssBefore = memory();
            long allocatedBefore = counters.allocations(workers);
            long cpuStartBegin = System.nanoTime();
            long cpuBefore = counters.processCpu();
            long cpuStartEnd = System.nanoTime();
            phase.epoch = System.nanoTime();
            phase.deadline = phase.epoch + durationNanos;
            phase.start.countDown();
            await(phase.done, timeoutSeconds);
            long cpuEndBegin = System.nanoTime();
            long cpuAfter = counters.processCpu();
            long cpuEndEnd = System.nanoTime();
            long allocatedAfter = counters.allocations(workers);
            Map<String, Long> rssAfter = memory();
            long[] gcAfter = gc();
            long count = 0;
            long end = phase.epoch;
            long[] histogram = new long[HISTOGRAM_SIZE];
            List<Map<String, Object>> details = new ArrayList<>();
            for (Worker worker : workers) {
                count += worker.operations;
                end = Math.max(end, worker.lastEnd);
                Map<String, Object> detail = new LinkedHashMap<>();
                detail.put("operations", worker.operations);
                detail.put("first_start_ns", worker.firstStart);
                detail.put("last_end_ns", worker.lastEnd);
                detail.put("checksum", worker.checksum);
                detail.put("cpus_allowed_list_before", worker.cpusBefore);
                detail.put("cpus_allowed_list_after", worker.cpusAfter);
                details.add(detail);
                if (record) {
                    for (int index = 0; index < histogram.length; index++) {
                        histogram[index] += worker.histogram[index];
                    }
                }
            }
            List<long[]> buckets = new ArrayList<>();
            for (int index = 0; index < histogram.length; index++) {
                if (histogram[index] != 0) {
                    buckets.add(new long[] {index, lower(index), upper(index), histogram[index]});
                }
            }
            result.put("completed", phase.failure.get() == null);
            result.put("error_class", phase.failure.get() == null ? null : phase.failure.get().getClass().getName());
            result.put("operations", count);
            result.put("epoch_ns", phase.epoch);
            result.put("last_request_end_ns", end);
            result.put("process_cpu_start_ns", cpuBefore);
            result.put("process_cpu_end_ns", cpuAfter);
            result.put("cpu_start_sample_begin_ns", cpuStartBegin);
            result.put("cpu_start_sample_end_ns", cpuStartEnd);
            result.put("cpu_end_sample_begin_ns", cpuEndBegin);
            result.put("cpu_end_sample_end_ns", cpuEndEnd);
            result.put("worker_allocated_bytes", allocatedAfter - allocatedBefore);
            result.put("gc_collections", gcAfter[0] - gcBefore[0]);
            result.put("gc_millis", gcAfter[1] - gcBefore[1]);
            result.put("memory_before", rssBefore);
            result.put("memory_after", rssAfter);
            result.put("workers", details);
            result.put("latency_histogram", buckets);
        } finally {
            phase.start.countDown();
            phase.release.countDown();
            for (Worker worker : workers) {
                worker.join(1000);
                if (worker.isAlive()) {
                    throw new IllegalStateException("Worker did not terminate after release");
                }
            }
        }
        result.put("cleanup_end_ns", System.nanoTime());
        return result;
    }

    private static final class Counters {
        private final Object threadBean = ManagementFactory.getThreadMXBean();
        private final Object osBean = ManagementFactory.getOperatingSystemMXBean();
        private final Method allocated;
        private final Method processCpu;

        private Counters() throws Exception {
            Class<?> threads = Class.forName("com.sun.management.ThreadMXBean");
            if (!(boolean) threads.getMethod("isThreadAllocatedMemorySupported").invoke(threadBean)) {
                throw new IllegalStateException("Thread allocation accounting is required");
            }
            threads.getMethod("setThreadAllocatedMemoryEnabled", boolean.class).invoke(threadBean, true);
            allocated = threads.getMethod("getThreadAllocatedBytes", long.class);
            processCpu = Class.forName("com.sun.management.OperatingSystemMXBean").getMethod("getProcessCpuTime");
        }

        private long allocations(List<Worker> workers) throws Exception {
            long total = 0;
            for (Worker worker : workers) {
                long value = (long) allocated.invoke(threadBean, worker.getId());
                if (value < 0) {
                    throw new IllegalStateException("Missing live worker allocation counter");
                }
                total += value;
            }
            return total;
        }

        private long processCpu() throws Exception {
            long value = (long) processCpu.invoke(osBean);
            if (value < 0) {
                throw new IllegalStateException("Missing process CPU counter");
            }
            return value;
        }
    }

    private static long[] gc() {
        long count = 0;
        long millis = 0;
        for (GarbageCollectorMXBean bean : ManagementFactory.getGarbageCollectorMXBeans()) {
            count += Math.max(0, bean.getCollectionCount());
            millis += Math.max(0, bean.getCollectionTime());
        }
        return new long[] {count, millis};
    }

    private static Map<String, Long> memory() throws Exception {
        Map<String, Long> result = new LinkedHashMap<>();
        for (String line : Files.readAllLines(Paths.get("/proc/self/status"), StandardCharsets.US_ASCII)) {
            if (line.startsWith("VmRSS:") || line.startsWith("VmHWM:")) {
                String[] fields = line.trim().split("\\s+");
                result.put(fields[0].substring(0, fields[0].length() - 1), Long.parseLong(fields[1]) * 1024);
            }
        }
        return result;
    }

    private static String cpuAffinity(String statusPath) throws Exception {
        for (String line : Files.readAllLines(Paths.get(statusPath), StandardCharsets.US_ASCII)) {
            if (line.startsWith("Cpus_allowed_list:")) {
                return line.substring(line.indexOf(':') + 1).trim();
            }
        }
        throw new IllegalStateException("Cpus_allowed_list is missing from " + statusPath);
    }

    private static void requireCpuAffinity(String actual, String expected) {
        if (!"0-4".equals(expected) || !expected.equals(actual)) {
            throw new IllegalStateException("Actual CPUs_allowed_list=" + actual + "; required=" + expected);
        }
    }

    public static void main(String[] args) throws Exception {
        JsonNode config = JSON.readTree(Files.readAllBytes(Paths.get(args[0])));
        String cpusBefore = cpuAffinity("/proc/self/status");
        requireCpuAffinity(cpusBefore, config.get("expected_cpu_affinity").asText());
        LicensePrimitiveCostProbe probe = new LicensePrimitiveCostProbe(config);
        int threads = config.get("threads").asInt();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("java_runtime", System.getProperty("java.runtime.version"));
        result.put("java_vendor", System.getProperty("java.vendor"));
        result.put("operation", probe.operation);
        result.put("threads", threads);
        result.put("actual_cpu_affinity_before", cpusBefore);
        result.put("warmup", probe.phase(threads, config.get("warmup_operations").asLong(),
                config.get("warmup_nanos").asLong(), false));
        if (!Boolean.TRUE.equals(((Map<?, ?>) result.get("warmup")).get("completed"))) {
            throw new IllegalStateException("Warmup failed");
        }
        result.put("measurement", probe.phase(threads, config.get("minimum_operations").asLong(),
                config.get("duration_nanos").asLong(), true));
        result.put("clock_suspect_at_end", probe.clock.isSuspect());
        String cpusAfter = cpuAffinity("/proc/self/status");
        result.put("actual_cpu_affinity_after", cpusAfter);
        requireCpuAffinity(cpusAfter, probe.expectedCpuAffinity);
        System.out.println(JSON.writeValueAsString(result));
        if (!Boolean.TRUE.equals(((Map<?, ?>) result.get("measurement")).get("completed"))
                || probe.clock.isSuspect()) {
            System.exit(2);
        }
    }
}
