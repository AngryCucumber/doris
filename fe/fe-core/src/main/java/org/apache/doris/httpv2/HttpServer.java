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
// Modified for MassDB SQL. See MODIFICATIONS.md for details.

package org.apache.doris.httpv2;

import org.apache.doris.DorisFE;
import org.apache.doris.common.Config;
import org.apache.doris.common.FeConstants;
import org.apache.doris.httpv2.config.SpringLog4j2Config;
import org.apache.doris.service.FrontendOptions;

import com.google.common.annotations.VisibleForTesting;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.ServletComponentScan;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@EnableConfigurationProperties
@ServletComponentScan
public class HttpServer extends SpringBootServletInitializer {
    private static final Logger LOG = LogManager.getLogger(HttpServer.class);
    // Spring Boot's default for server.jetty.threads.max, in effect while the old property names were ignored
    private static final int SPRING_BOOT_DEFAULT_MAX_THREADS = 200;
    private ConfigurableApplicationContext applicationContext;
    private int port;
    private int httpsPort;
    private int acceptors;
    private int selectors;
    private int maxHttpPostSize;
    private int workers;

    private String keyStorePath;
    private String keyStorePassword;
    private String keyStoreType;
    private String keyStoreAlias;
    private boolean enableHttps;

    private int minThreads;
    private int maxThreads;
    private int maxHttpHeaderSize;

    public int getMaxHttpHeaderSize() {
        return maxHttpHeaderSize;
    }

    public void setMaxHttpHeaderSize(int maxHttpHeaderSize) {
        this.maxHttpHeaderSize = maxHttpHeaderSize;
    }

    public int getMinThreads() {
        return minThreads;
    }

    public void setMinThreads(int minThreads) {
        this.minThreads = minThreads;
    }

    public int getMaxThreads() {
        return maxThreads;
    }

    public void setMaxThreads(int maxThreads) {
        this.maxThreads = maxThreads;
    }

    public void setWorkers(int workers) {
        this.workers = workers;
    }

    public void setAcceptors(int acceptors) {
        this.acceptors = acceptors;
    }

    public void setSelectors(int selectors) {
        this.selectors = selectors;
    }

    public void setMaxHttpPostSize(int maxHttpPostSize) {
        this.maxHttpPostSize = maxHttpPostSize;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setHttpsPort(int httpsPort) {
        this.httpsPort = httpsPort;
    }

    public void setKeyStorePath(String keyStorePath) {
        this.keyStorePath = keyStorePath;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public void setKeyStoreAlias(String keyStoreAlias) {
        this.keyStoreAlias = keyStoreAlias;
    }

    public void setEnableHttps(boolean enableHttps) {
        this.enableHttps = enableHttps;
    }

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(HttpServer.class);
    }

    public void start() {
        Map<String, Object> properties = new HashMap<>();
        if (enableHttps) {
            properties.put("server.http.port", port);
            properties.put("server.port", httpsPort);
            // ssl config
            properties.put("server.ssl.key-store", keyStorePath);
            properties.put("server.ssl.key-store-password", keyStorePassword);
            properties.put("server.ssl.key-store-type", keyStoreType);
            properties.put("server.ssl.keyalias", keyStoreAlias);
            properties.put("server.ssl.enabled", enableHttps);
        } else {
            properties.put("server.port", port);
            properties.put("server.ssl.enabled", enableHttps);
        }
        if (FrontendOptions.isBindIPV6()) {
            properties.put("server.address", "::0");
        } else {
            properties.put("server.address", "0.0.0.0");
        }
        properties.put("spring.resources.static-locations", "classpath:/static/");
        properties.put("server.servlet.context-path", "/");
        properties.put("server.servlet.encoding.charset", "UTF-8");
        properties.put("server.servlet.encoding.enabled", true);
        properties.put("server.servlet.encoding.force", true);
        addJettyProperties(properties);
        // This is to disable the spring-boot-devtools restart feature.
        // To avoid some unexpected behavior.
        System.setProperty("spring.devtools.restart.enabled", "false");
        // Value of `DORIS_HOME_DIR` is null in unit test.
        if (DorisFE.DORIS_HOME_DIR != null) {
            System.setProperty("spring.http.multipart.location", DorisFE.DORIS_HOME_DIR);
        }
        System.setProperty("spring.banner.image.location", "doris-logo.png");
        if (FeConstants.runningUnitTest) {
            // this is currently only used for unit test
            properties.put("logging.config", getClass().getClassLoader().getResource("log4j2.xml").getPath());
        } else {
            properties.put("logging.config", Config.custom_config_dir + "/" + SpringLog4j2Config.SPRING_LOG_XML_FILE);
        }
        // Disable automatic shutdown hook registration
        // This prevents Spring Boot from responding to SIGTERM automatically
        // allowing the main process (DorisFE) to control when the HTTP server shuts down
        this.applicationContext = new SpringApplicationBuilder()
                .sources(HttpServer.class)
                .properties(properties)
                // Disable the automatic shutdown hook registration, there is a shutdown hook in DorisFE.
                .registerShutdownHook(false)
                .run();
    }

    @VisibleForTesting
    void addJettyProperties(Map<String, Object> properties) {
        addJettyProperties(properties, Runtime.getRuntime().availableProcessors());
    }

    @VisibleForTesting
    public void addJettyProperties(Map<String, Object> properties, int cores) {
        // enable jetty config, with the property names of Spring Boot 3.
        // These settings were ignored while the old property names were used, so a value Jetty cannot run with never
        // mattered. Jetty refuses to start with such values and the FE would not start: use the defaults instead.
        boolean usePool = this.minThreads >= 0 && this.maxThreads > 0 && this.minThreads <= this.maxThreads
                && leasedThreads(-1, -1, this.maxThreads, cores) < this.maxThreads;
        if (usePool) {
            properties.put("server.jetty.threads.max", this.maxThreads);
            properties.put("server.jetty.threads.min", this.minThreads);
        } else {
            LOG.warn("ignore jetty_threadPool_maxThreads = {} and jetty_threadPool_minThreads = {}: Jetty needs"
                    + " 0 <= min <= max and max above the {} threads its connectors hold, use the defaults instead",
                    this.maxThreads, this.minThreads, leasedThreads(-1, -1, this.maxThreads, cores));
        }
        int poolMax = usePool ? this.maxThreads : SPRING_BOOT_DEFAULT_MAX_THREADS;
        // a non-positive value lets Jetty decide by the number of cpu cores and the max thread count
        if (this.acceptors > 0 || this.selectors > 0) {
            long leased = leasedThreads(this.acceptors, this.selectors, poolMax, cores);
            if (leased < poolMax) {
                if (this.acceptors > 0) {
                    properties.put("server.jetty.threads.acceptors", this.acceptors);
                }
                if (this.selectors > 0) {
                    properties.put("server.jetty.threads.selectors", this.selectors);
                }
            } else {
                LOG.warn("ignore jetty_server_acceptors = {} and jetty_server_selectors = {}: the connectors would hold"
                        + " {} of the {} http server threads, let Jetty decide instead",
                        this.acceptors, this.selectors, leased, poolMax);
            }
        }
        // NOTE: Spring Boot 3 does not bind these two old names, so Jetty keeps its defaults (200KB form body,
        // 8KB request header). Binding them would raise both limits a lot, which needs its own evaluation.
        properties.put("server.jetty.max-http-post-size", this.maxHttpPostSize);
        properties.put("server.max-http-header-size", this.maxHttpHeaderSize);
        // Worker thread pool is not set by default, set according to your needs
        if (this.workers > 0) {
            properties.put("server.jetty.workers", this.workers);
        }
    }

    /**
     * Threads Jetty leases out of the pool: acceptors and selectors of each connector and the reserved threads; it
     * fails to start unless they are fewer than the max thread count. With https a plain http connector with Jetty's
     * defaults is added as well, see {@link org.apache.doris.httpv2.config.WebServerFactoryCustomizerConfig}.
     */
    private long leasedThreads(int acceptors, int selectors, int maxThreads, int cores) {
        // Jetty's defaults: 1 acceptor, selectors from SelectorManager.defaultSelectors() and reserved threads from
        // ReservedThreadExecutor.reservedThreads()
        int defaultSelectors = Math.max(1, Math.min(cores / 2, maxThreads / 16));
        int reserved = Math.max(1, ceilToPowerOfTwo(Math.min(cores, maxThreads / 8)));
        // in long, huge values in fe.conf must not overflow to a small sum
        long leased = (acceptors > 0 ? (long) acceptors : 1L) + (selectors > 0 ? selectors : defaultSelectors)
                + reserved;
        if (this.enableHttps) {
            leased += 1 + defaultSelectors;
        }
        return leased;
    }

    private static int ceilToPowerOfTwo(int value) {
        return value <= 1 ? 1 : Integer.highestOneBit(value - 1) << 1;
    }

    /**
     * Explicitly shutdown the HTTP server.
     * This method should be called by the main process (DorisFE) after its graceful shutdown is complete.
     */
    public void shutdown() {
        if (applicationContext != null) {
            LOG.info("Shutting down HTTP server gracefully...");
            applicationContext.close();
            LOG.info("HTTP server shutdown complete");
        }
    }
}
