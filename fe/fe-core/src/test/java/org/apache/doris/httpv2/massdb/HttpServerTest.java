// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.httpv2.massdb;

import org.apache.doris.httpv2.HttpServer;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.util.unit.DataSize;

import java.util.HashMap;
import java.util.Map;

public class HttpServerTest {

    // bind the jetty properties the same way Spring Boot configures the embedded Jetty
    private static ServerProperties bind(HttpServer httpServer) {
        return bind(httpServer, 96);
    }

    private static ServerProperties bind(HttpServer httpServer, int cores) {
        Map<String, Object> properties = new HashMap<>();
        httpServer.addJettyProperties(properties, cores);
        // nothing is bound when every setting falls back to the defaults
        ServerProperties serverProperties = new ServerProperties();
        return new Binder(new MapConfigurationPropertySource(properties))
                .bind("server", Bindable.ofInstance(serverProperties)).orElse(serverProperties);
    }

    private static void assertSpringBootDefaultPool(ServerProperties.Jetty.Threads threads) {
        Assert.assertEquals(Integer.valueOf(200), threads.getMax());
        Assert.assertEquals(Integer.valueOf(8), threads.getMin());
    }

    private static HttpServer newHttpServer(int maxThreads, int minThreads, int acceptors, int selectors) {
        HttpServer httpServer = new HttpServer();
        httpServer.setMaxThreads(maxThreads);
        httpServer.setMinThreads(minThreads);
        httpServer.setAcceptors(acceptors);
        httpServer.setSelectors(selectors);
        httpServer.setMaxHttpPostSize(100 * 1024 * 1024);
        httpServer.setMaxHttpHeaderSize(1048576);
        return httpServer;
    }

    @Test
    public void testThreadPoolIsBound() {
        ServerProperties.Jetty.Threads threads = bind(newHttpServer(64, 10, -1, -1)).getJetty().getThreads();
        Assert.assertEquals(Integer.valueOf(64), threads.getMax());
        Assert.assertEquals(Integer.valueOf(10), threads.getMin());
        // left to Jetty
        Assert.assertEquals(Integer.valueOf(-1), threads.getAcceptors());
        Assert.assertEquals(Integer.valueOf(-1), threads.getSelectors());
    }

    @Test
    public void testAcceptorsAndSelectorsAreBoundWhenSet() {
        ServerProperties.Jetty.Threads threads = bind(newHttpServer(400, 20, 2, 6)).getJetty().getThreads();
        Assert.assertEquals(Integer.valueOf(2), threads.getAcceptors());
        Assert.assertEquals(Integer.valueOf(6), threads.getSelectors());
    }

    @Test
    public void testInvalidThreadPoolFallsBackToDefaults() {
        // max below the default min (20): Jetty would fail with "max threads (16) less than min threads (20)"
        assertSpringBootDefaultPool(bind(newHttpServer(16, 20, -1, -1)).getJetty().getThreads());
        assertSpringBootDefaultPool(bind(newHttpServer(40, 50, -1, -1)).getJetty().getThreads());
        assertSpringBootDefaultPool(bind(newHttpServer(0, 20, -1, -1)).getJetty().getThreads());
        assertSpringBootDefaultPool(bind(newHttpServer(400, -1, -1, -1)).getJetty().getThreads());
    }

    @Test
    public void testThreadPoolTooSmallForConnectors() {
        // 1 acceptor + 1 selector + 1 reserved thread leave no thread out of 3: "Insufficient configured threads"
        assertSpringBootDefaultPool(bind(newHttpServer(2, 1, -1, -1)).getJetty().getThreads());
        assertSpringBootDefaultPool(bind(newHttpServer(3, 1, -1, -1)).getJetty().getThreads());
        ServerProperties.Jetty.Threads threads = bind(newHttpServer(4, 1, -1, -1)).getJetty().getThreads();
        Assert.assertEquals(Integer.valueOf(4), threads.getMax());
        Assert.assertEquals(Integer.valueOf(1), threads.getMin());
    }

    @Test
    public void testTooManyAcceptorsAndSelectorsAreIgnored() {
        // 8 acceptors + 16 selectors + 2 reserved threads exceed the 20 threads (Jetty reports required=26):
        // let Jetty decide, keep the valid pool
        ServerProperties.Jetty.Threads threads = bind(newHttpServer(20, 10, 8, 16)).getJetty().getThreads();
        Assert.assertEquals(Integer.valueOf(20), threads.getMax());
        Assert.assertEquals(Integer.valueOf(-1), threads.getAcceptors());
        Assert.assertEquals(Integer.valueOf(-1), threads.getSelectors());
        // with an unusable pool the defaults (200 threads) apply, and 2 + 4 + 32 reserved threads fit in them
        threads = bind(newHttpServer(16, 20, 2, 4)).getJetty().getThreads();
        assertSpringBootDefaultPool(threads);
        Assert.assertEquals(Integer.valueOf(2), threads.getAcceptors());
        Assert.assertEquals(Integer.valueOf(4), threads.getSelectors());
    }

    @Test
    public void testHugeAcceptorsAndSelectorsDoNotOverflow() {
        // the sum must not wrap around to a negative number and pass the check: Jetty would allocate arrays of
        // that size and the FE would exit with OutOfMemoryError
        int[][] cases = {{Integer.MAX_VALUE, 1}, {1, Integer.MAX_VALUE}, {Integer.MAX_VALUE, Integer.MAX_VALUE},
                {1 << 30, 1 << 30}};
        for (int[] c : cases) {
            ServerProperties.Jetty.Threads threads = bind(newHttpServer(400, 20, c[0], c[1])).getJetty().getThreads();
            Assert.assertEquals(Integer.valueOf(400), threads.getMax());
            Assert.assertEquals(Integer.valueOf(-1), threads.getAcceptors());
            Assert.assertEquals(Integer.valueOf(-1), threads.getSelectors());
        }
        // the same with the largest thread pool
        ServerProperties.Jetty.Threads threads = bind(newHttpServer(Integer.MAX_VALUE, 20, Integer.MAX_VALUE, 1))
                .getJetty().getThreads();
        Assert.assertEquals(Integer.valueOf(Integer.MAX_VALUE), threads.getMax());
        Assert.assertEquals(Integer.valueOf(-1), threads.getAcceptors());
    }

    @Test
    public void testHttpsConnectorIsCounted() {
        // the https connector holds 2 + 6 threads, the added plain http connector 1 + 1, plus 1 reserved: 11 of 10
        HttpServer https = newHttpServer(10, 5, 2, 6);
        https.setEnableHttps(true);
        ServerProperties.Jetty.Threads threads = bind(https, 10).getJetty().getThreads();
        Assert.assertEquals(Integer.valueOf(10), threads.getMax());
        Assert.assertEquals(Integer.valueOf(-1), threads.getAcceptors());
        Assert.assertEquals(Integer.valueOf(-1), threads.getSelectors());
        // without https the same settings leave 1 thread
        threads = bind(newHttpServer(10, 5, 2, 6), 10).getJetty().getThreads();
        Assert.assertEquals(Integer.valueOf(2), threads.getAcceptors());
        Assert.assertEquals(Integer.valueOf(6), threads.getSelectors());
    }

    @Test
    public void testHeaderAndFormLimitsKeepJettyDefaults() {
        ServerProperties serverProperties = bind(newHttpServer(400, 20, -1, -1));
        Assert.assertEquals(DataSize.ofKilobytes(8), serverProperties.getMaxHttpRequestHeaderSize());
        Assert.assertEquals(DataSize.ofBytes(200000), serverProperties.getJetty().getMaxHttpFormPostSize());
    }
}
