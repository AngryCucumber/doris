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

package org.apache.doris.httpv2;

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
