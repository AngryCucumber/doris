// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package org.apache.doris.metric;

import org.apache.doris.common.Config;
import org.apache.doris.common.FeConstants;
import org.apache.doris.common.util.DebugPointUtil;
import org.apache.doris.common.util.JsonUtil;
import org.apache.doris.metric.Metric.MetricUnit;
import org.apache.doris.monitor.jvm.JvmService;
import org.apache.doris.monitor.jvm.JvmStats;

import com.codahale.metrics.Histogram;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public class MetricsTest {

    @BeforeClass
    public static void setUp() {
        FeConstants.runningUnitTest = true;
        MetricRepo.init();
    }

    @Test
    public void testTcpMetrics() {
        List<Metric> metrics = MetricRepo.getMetricsByName("snmp");
        Assert.assertEquals(4, metrics.size());
        for (Metric metric : metrics) {
            GaugeMetric<Long> gm = (GaugeMetric<Long>) metric;
            String metricName = gm.getLabels().get(0).getValue();
            if (metricName.equals("tcp_retrans_segs")) {
                Assert.assertEquals(Long.valueOf(826271L), (Long) gm.getValue());
            } else if (metricName.equals("tcp_in_errs")) {
                Assert.assertEquals(Long.valueOf(12712L), (Long) gm.getValue());
            } else if (metricName.equals("tcp_in_segs")) {
                Assert.assertEquals(Long.valueOf(1034019111L), (Long) gm.getValue());
            } else if (metricName.equals("tcp_out_segs")) {
                Assert.assertEquals(Long.valueOf(1166716939L), (Long) gm.getValue());
            } else {
                Assert.fail();
            }
        }
    }

    @Test
    public void testUserQueryMetrics() {
        MetricRepo.USER_COUNTER_QUERY_ALL.getOrAdd("test_user").increase(1L);
        MetricRepo.USER_COUNTER_QUERY_ERR.getOrAdd("test_user").increase(1L);
        MetricRepo.USER_HISTO_QUERY_LATENCY.getOrAdd("test_user").update(10L);
        MetricVisitor visitor = new PrometheusMetricVisitor();
        MetricRepo.DORIS_METRIC_REGISTER.accept(visitor);
        SortedMap<String, Histogram> histograms = MetricRepo.METRIC_REGISTER.getHistograms();
        for (Map.Entry<String, Histogram> entry : histograms.entrySet()) {
            visitor.visitHistogram(MetricVisitor.FE_PREFIX, entry.getKey(), entry.getValue());
        }
        String metricResult = visitor.finish();
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_query_total counter"));
        Assert.assertTrue(metricResult.contains("doris_fe_query_total{user=\"test_user\"} 1"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_query_err counter"));
        Assert.assertTrue(metricResult.contains("doris_fe_query_err{user=\"test_user\"} 1"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_query_latency_ms summary"));
        Assert.assertTrue(metricResult.contains("doris_fe_query_latency_ms{quantile=\"0.999\"} 0.0"));
        Assert.assertTrue(metricResult.contains("doris_fe_query_latency_ms{quantile=\"0.999\",user=\"test_user\"} 10.0"));

    }

    @Test
    public void testGc() {
        PrometheusMetricVisitor visitor = new PrometheusMetricVisitor();
        JvmService jvmService = new JvmService();
        JvmStats jvmStats = jvmService.stats();
        visitor.visitJvm(jvmStats);
        String metric = MetricRepo.getMetric(visitor);
        List<GarbageCollectorMXBean> gcMxBeans = ManagementFactory.getGarbageCollectorMXBeans();
        String finalMetricPrometheus = metric;
        gcMxBeans.forEach(gcMxBean -> {
            String name = gcMxBean.getName();
            Assert.assertTrue(finalMetricPrometheus.contains("jvm_gc{name=\"" + name + " Count\", type=\"count\"} "));
            Assert.assertTrue(finalMetricPrometheus.contains("jvm_gc{name=\"" + name + " Time\", type=\"time\"} "));
        });

        JsonMetricVisitor jsonMetricVisitor = new JsonMetricVisitor();
        jsonMetricVisitor.visitJvm(jvmStats);
        metric = MetricRepo.getMetric(jsonMetricVisitor);
        String finalMetricJson = metric;
        AtomicInteger size = new AtomicInteger(JsonUtil.parseArray(finalMetricJson).size());
        gcMxBeans.forEach(gcMxBean -> JsonUtil.parseArray(finalMetricJson).forEach(json -> {
            ObjectNode jsonObject = JsonUtil.parseObject(json.toString());
            String name = gcMxBean.getName();
            if (jsonObject.findValue("tags").findValue("metric").asText().equals("jvm_gc")
                    && jsonObject.findValue("tags").findValue("name").asText().contains(name + " Count")) {
                size.getAndDecrement();
                Assert.assertTrue(jsonObject.findValue("tags").findValue("name").asText().contains(name + " Count")
                        || jsonObject.findValue("tags").findValue("name").asText().contains(name + " Time"));
            }

        }));
        Assert.assertTrue(size.get() < JsonUtil.parseArray(finalMetricJson).size());

    }

    @Test
    public void testCatalogAndDatabaseMetrics() {
        List<Metric> catalogMetrics = MetricRepo.getMetricsByName("catalog_num");
        Assert.assertEquals(1, catalogMetrics.size());
        GaugeMetric<Integer> catalogMetric = (GaugeMetric<Integer>) catalogMetrics.get(0);
        Assert.assertEquals("catalog_num", catalogMetric.getName());
        Assert.assertEquals(MetricUnit.NOUNIT, catalogMetric.getUnit());
        Assert.assertEquals("total catalog num", catalogMetric.getDescription());

        List<Metric> dbMetrics = MetricRepo.getMetricsByName("internal_database_num");
        Assert.assertEquals(1, dbMetrics.size());
        GaugeMetric<Integer> dbMetric = (GaugeMetric<Integer>) dbMetrics.get(0);
        Assert.assertEquals("internal_database_num", dbMetric.getName());
        Assert.assertEquals(MetricUnit.NOUNIT, dbMetric.getUnit());
        Assert.assertEquals("total internal database num", dbMetric.getDescription());

        List<Metric> tableMetrics = MetricRepo.getMetricsByName("internal_table_num");
        Assert.assertEquals(1, tableMetrics.size());
        GaugeMetric<Integer> tableMetric = (GaugeMetric<Integer>) tableMetrics.get(0);
        Assert.assertEquals("internal_table_num", tableMetric.getName());
        Assert.assertEquals(MetricUnit.NOUNIT, tableMetric.getUnit());
        Assert.assertEquals("total internal table num", tableMetric.getDescription());

        // Test metrics in Prometheus format
        MetricVisitor visitor = new PrometheusMetricVisitor();
        MetricRepo.DORIS_METRIC_REGISTER.accept(visitor);
        String metricResult = visitor.finish();

        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_catalog_num gauge"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_internal_database_num gauge"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_internal_table_num gauge"));

        // Test metrics in JSON format
        JsonMetricVisitor jsonVisitor = new JsonMetricVisitor();
        MetricRepo.DORIS_METRIC_REGISTER.accept(jsonVisitor);
        String jsonResult = jsonVisitor.finish();

        Assert.assertTrue(jsonResult.contains("\"metric\":\"doris_fe_catalog_num\""));
        Assert.assertTrue(jsonResult.contains("\"metric\":\"doris_fe_internal_database_num\""));
        Assert.assertTrue(jsonResult.contains("\"metric\":\"doris_fe_internal_table_num\""));
    }

    @Test
    public void testMTMVMetrics() {
        // Test metrics in Prometheus format
        MetricVisitor visitor = new PrometheusMetricVisitor();
        // doris metrics and system metrics.
        MetricRepo.DORIS_METRIC_REGISTER.accept(visitor);
        // histogram
        SortedMap<String, Histogram> histograms = MetricRepo.METRIC_REGISTER.getHistograms();
        for (Map.Entry<String, Histogram> entry : histograms.entrySet()) {
            visitor.visitHistogram(MetricVisitor.FE_PREFIX, entry.getKey(), entry.getValue());
        }
        String metricResult = visitor.finish();

        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_async_materialized_view_task_failed_num counter"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_async_materialized_view_task_success_num counter"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_async_materialized_view_task_pending_num gauge"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_async_materialized_view_task_skip_num counter"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_async_materialized_view_task_running_num gauge"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_async_materialized_view_num gauge"));
        Assert.assertTrue(
                metricResult.contains("# TYPE doris_fe_async_materialized_view_task_duration_ms summary"));
    }

    @Test
    public void testStatisticsMetrics() {
        // Test metrics in Prometheus format
        MetricVisitor visitor = new PrometheusMetricVisitor();
        // doris metrics and system metrics.
        MetricRepo.DORIS_METRIC_REGISTER.accept(visitor);
        // histogram
        SortedMap<String, Histogram> histograms = MetricRepo.METRIC_REGISTER.getHistograms();
        for (Map.Entry<String, Histogram> entry : histograms.entrySet()) {
            visitor.visitHistogram(MetricVisitor.FE_PREFIX, entry.getKey(), entry.getValue());
        }
        String metricResult = visitor.finish();

        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_statistics_succeed_analyze_job counter"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_statistics_failed_analyze_job counter"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_statistics_succeed_analyze_task counter"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_statistics_failed_analyze_task counter"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_statistics_invalid_stats counter"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_statistics_unhealthy_table_rate gauge"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_statistics_unhealthy_column_rate gauge"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_statistics_unhealthy_table_num gauge"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_statistics_unhealthy_column_num gauge"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_statistics_not_analyzed_table_num gauge"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_statistics_empty_table_num gauge"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_statistics_high_priority_queue_length gauge"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_statistics_mid_priority_queue_length gauge"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_statistics_low_priority_queue_length gauge"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_statistics_very_low_priority_queue_length gauge"));
    }

    @Test
    public void testSqlCacheMetrics() {
        // Test metrics in Prometheus format
        MetricVisitor visitor = new PrometheusMetricVisitor();
        // doris metrics and system metrics.
        MetricRepo.DORIS_METRIC_REGISTER.accept(visitor);
        // histogram
        SortedMap<String, Histogram> histograms = MetricRepo.METRIC_REGISTER.getHistograms();
        for (Map.Entry<String, Histogram> entry : histograms.entrySet()) {
            visitor.visitHistogram(MetricVisitor.FE_PREFIX, entry.getKey(), entry.getValue());
        }
        String metricResult = visitor.finish();

        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_sql_cache_num gauge"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_sql_cache_added counter"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_sql_cache_hit counter"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_sql_cache_total_search_times counter"));
    }

    @Test
    public void testPlanMetrics() {
        // Test metrics in Prometheus format
        MetricVisitor visitor = new PrometheusMetricVisitor();
        // doris metrics and system metrics.
        MetricRepo.DORIS_METRIC_REGISTER.accept(visitor);
        // histogram
        SortedMap<String, Histogram> histograms = MetricRepo.METRIC_REGISTER.getHistograms();
        for (Map.Entry<String, Histogram> entry : histograms.entrySet()) {
            visitor.visitHistogram(MetricVisitor.FE_PREFIX, entry.getKey(), entry.getValue());
        }
        String metricResult = visitor.finish();

        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_num gauge"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_parse_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_analyze_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_rewrite_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_fold_const_by_be_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_optimize_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_translate_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_init_scan_node_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_finalize_scan_node_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_create_scan_range_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_distribute_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_external_catalog_meta_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_external_tvf_init_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_lock_tables_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_partition_prune_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_cloud_meta_duration_ms summary"));
        Assert.assertTrue(metricResult.contains("# TYPE doris_fe_plan_materialized_view_rewrite_duration_ms summary"));
    }

    private static final String SLOW_METRIC_DEBUG_POINT = "MetricRepo.computeMetric.sleep";

    private static long elapsedMs(long startNs) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);
    }

    // not the common pool: it may have a single thread and run the requests one by one
    private static final ExecutorService METRIC_REQUEST_POOL = Executors.newCachedThreadPool(r -> {
        Thread thread = new Thread(r, "metrics-test-request");
        thread.setDaemon(true);
        return thread;
    });

    private static CompletableFuture<String> getMetricAsync() {
        return CompletableFuture.supplyAsync(() -> MetricRepo.getMetric(new PrometheusMetricVisitor()),
                METRIC_REQUEST_POOL);
    }

    private static void runWithSlowMetric(long computeMs, long cacheMs, long lockWaitMs, Runnable test) {
        boolean oldEnableDebugPoints = Config.enable_debug_points;
        long oldCacheMs = Config.metrics_result_cache_ms;
        long oldLockWaitMs = Config.metrics_lock_wait_ms;
        try {
            MetricRepo.clearMetricResults();
            Config.enable_debug_points = true;
            Config.metrics_result_cache_ms = cacheMs;
            Config.metrics_lock_wait_ms = lockWaitMs;
            DebugPointUtil.addDebugPointWithValue(SLOW_METRIC_DEBUG_POINT, computeMs);
            test.run();
        } finally {
            DebugPointUtil.removeDebugPoint(SLOW_METRIC_DEBUG_POINT);
            Config.enable_debug_points = oldEnableDebugPoints;
            Config.metrics_result_cache_ms = oldCacheMs;
            Config.metrics_lock_wait_ms = oldLockWaitMs;
            MetricRepo.clearMetricResults();
        }
    }

    @Test
    public void testSlowMetricDoesNotBlockWaitersForever() {
        runWithSlowMetric(2000, 0, 300, () -> {
            CompletableFuture<String> first = getMetricAsync();
            sleepMs(200);

            // no earlier result: give up after metrics_lock_wait_ms and return null
            long start = System.nanoTime();
            Assert.assertNull(MetricRepo.getMetric(new PrometheusMetricVisitor()));
            long waited = elapsedMs(start);
            Assert.assertTrue("waited " + waited + " ms", waited >= 250 && waited < 1500);

            // getMetricsByName() is not blocked by a running computation
            start = System.nanoTime();
            Assert.assertEquals(4, MetricRepo.getMetricsByName("snmp").size());
            Assert.assertTrue(elapsedMs(start) < 200);

            String firstResult = first.join();
            Assert.assertTrue(firstResult.contains("jvm_gc"));

            // with an earlier result: give up and return the earlier result
            CompletableFuture<String> second = getMetricAsync();
            sleepMs(200);
            start = System.nanoTime();
            Assert.assertSame(firstResult, MetricRepo.getMetric(new PrometheusMetricVisitor()));
            waited = elapsedMs(start);
            Assert.assertTrue("waited " + waited + " ms", waited >= 250 && waited < 1500);
            Assert.assertNotSame(firstResult, second.join());
        });
    }

    @Test
    public void testConcurrentRequestsShareComputation() {
        runWithSlowMetric(1000, 0, 10000, () -> {
            long start = System.nanoTime();
            CompletableFuture<String> first = getMetricAsync();
            sleepMs(200);
            // these arrive while the first computation is running: one of them computes again,
            // the others take its result instead of computing one by one
            List<CompletableFuture<String>> waiters = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                waiters.add(getMetricAsync());
            }
            String firstResult = first.join();
            String waiterResult = waiters.get(0).join();
            for (CompletableFuture<String> waiter : waiters) {
                Assert.assertSame(waiterResult, waiter.join());
            }
            Assert.assertNotSame(firstResult, waiterResult);
            long elapsed = elapsedMs(start);
            Assert.assertTrue("took " + elapsed + " ms", elapsed < 3500);
        });
    }

    @Test
    public void testMetricResultCache() {
        runWithSlowMetric(500, 60000, 3000, () -> {
            String firstResult = MetricRepo.getMetric(new PrometheusMetricVisitor());
            long start = System.nanoTime();
            Assert.assertSame(firstResult, MetricRepo.getMetric(new PrometheusMetricVisitor()));
            Assert.assertTrue(elapsedMs(start) < 200);
            // results are kept per format
            String jsonResult = MetricRepo.getMetric(new JsonMetricVisitor());
            Assert.assertNotEquals(firstResult, jsonResult);
            Assert.assertSame(jsonResult, MetricRepo.getMetric(new JsonMetricVisitor()));
        });
    }

    private static void sleepMs(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
