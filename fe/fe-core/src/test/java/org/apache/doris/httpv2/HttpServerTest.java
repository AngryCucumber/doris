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
        Map<String, Object> properties = new HashMap<>();
        httpServer.addJettyProperties(properties);
        return new Binder(new MapConfigurationPropertySource(properties))
                .bind("server", Bindable.ofInstance(new ServerProperties())).get();
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
    public void testHeaderAndFormLimitsKeepJettyDefaults() {
        ServerProperties serverProperties = bind(newHttpServer(400, 20, -1, -1));
        Assert.assertEquals(DataSize.ofKilobytes(8), serverProperties.getMaxHttpRequestHeaderSize());
        Assert.assertEquals(DataSize.ofBytes(200000), serverProperties.getJetty().getMaxHttpFormPostSize());
    }
}
