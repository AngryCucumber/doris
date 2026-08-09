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

import org.apache.doris.DorisFE;
import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.common.FeConstants;
import org.apache.doris.httpv2.config.SpringLog4j2Config;
import org.apache.doris.massdblicense.MassDbLicenseJettyIdentityController;
import org.apache.doris.service.FrontendOptions;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.embedded.jetty.JettyWebServer;
import org.springframework.boot.web.servlet.ServletComponentScan;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.ConfigurableApplicationContext;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.net.ssl.SSLContext;

@SpringBootApplication
@EnableConfigurationProperties
@ServletComponentScan
public class HttpServer extends SpringBootServletInitializer {
    private static final Logger LOG = LogManager.getLogger(HttpServer.class);
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
    private MassDbLicenseJettyIdentityController licenseIdentityController;

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
            if (Config.massdb_license_role_mtls_enabled
                    && Config.massdb_license_role_mtls_development_keystore_enabled) {
                if (!Config.enable_debug_points) {
                    throw new IllegalStateException(
                            "Development License role key stores require enable_debug_points");
                }
                if (Config.massdb_license_role_mtls_trust_store_path == null
                        || Config.massdb_license_role_mtls_trust_store_path.trim().isEmpty()) {
                    throw new IllegalStateException(
                            "massdb_license_role_mtls_trust_store_path must be configured");
                }
                // WANT preserves ordinary HTTPS clients; the internal controller still requires
                // a chain-verified certificate and exact MassDB SQL FE SPIFFE identity.
                properties.put("server.ssl.client-auth", "want");
                properties.put("server.ssl.trust-store",
                        Config.massdb_license_role_mtls_trust_store_path);
                properties.put("server.ssl.trust-store-password",
                        Config.massdb_license_role_mtls_trust_store_password);
                properties.put("server.ssl.trust-store-type",
                        Config.massdb_license_role_mtls_trust_store_type);
            }
        } else {
            if (Config.massdb_license_role_mtls_enabled) {
                throw new IllegalStateException(
                        "MassDB License role mTLS requires enable_https=true");
            }
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
        // enable jetty config
        properties.put("server.jetty.acceptors", this.acceptors);
        properties.put("server.jetty.max-http-post-size", this.maxHttpPostSize);
        properties.put("server.jetty.selectors", this.selectors);
        properties.put("server.jetty.threadPool.maxThreads", this.maxThreads);
        properties.put("server.jetty.threadPool.minThreads", this.minThreads);
        properties.put("server.max-http-header-size", this.maxHttpHeaderSize);
        // Worker thread pool is not set by default, set according to your needs
        if (this.workers > 0) {
            properties.put("server.jetty.workers", this.workers);
        }
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
        if (enableHttps && Config.massdb_license_role_mtls_enabled) {
            bindMassDbLicenseRoleIdentity();
        }
        Env.getServingEnv().markMassDbLicenseQueryGuardInstalled();
    }

    private void bindMassDbLicenseRoleIdentity() {
        MassDbLicenseJettyIdentityController controller =
                Env.getServingEnv().getMassDbLicenseJettyIdentityController();
        if (controller == null) {
            LOG.error("MassDB License Jetty角色身份控制器未初始化，普通HTTPS继续运行");
            return;
        }
        try {
            if (!(applicationContext instanceof ServletWebServerApplicationContext)) {
                throw new IllegalStateException("Spring servlet web server context unavailable");
            }
            org.springframework.boot.web.server.WebServer webServer =
                    ((ServletWebServerApplicationContext) applicationContext).getWebServer();
            if (!(webServer instanceof JettyWebServer)) {
                throw new IllegalStateException("embedded Jetty web server unavailable");
            }
            JettyRoleTlsTarget target = JettyRoleTlsTarget.find(
                    ((JettyWebServer) webServer).getServer());
            controller.bind(target, Instant.now().getEpochSecond());
            controller.startPolling();
            licenseIdentityController = controller;
        } catch (Exception error) {
            controller.close();
            LOG.error("MassDB License Jetty角色身份接线失败，普通HTTPS继续运行", error);
        }
    }

    /**
     * Explicitly shutdown the HTTP server.
     * This method should be called by the main process (DorisFE) after its graceful shutdown is complete.
     */
    public void shutdown() {
        if (licenseIdentityController != null) {
            licenseIdentityController.close();
            licenseIdentityController = null;
        }
        if (applicationContext != null) {
            LOG.info("Shutting down HTTP server gracefully...");
            applicationContext.close();
            LOG.info("HTTP server shutdown complete");
        }
    }

    /** Atomically switches Jetty between component identity and the original HTTPS context. */
    static final class JettyRoleTlsTarget
            implements MassDbLicenseJettyIdentityController.ServerTlsTarget {
        private final SslContextFactory.Server contextFactory;
        private final SSLContext ordinaryHttpsContext;
        private boolean roleIdentityEnabled;
        private long generation;

        JettyRoleTlsTarget(SslContextFactory.Server contextFactory) {
            this.contextFactory = Objects.requireNonNull(contextFactory, "contextFactory");
            this.ordinaryHttpsContext = Objects.requireNonNull(
                    contextFactory.getSslContext(), "ordinaryHttpsContext");
            this.roleIdentityEnabled = contextFactory.getNeedClientAuth()
                    || contextFactory.getWantClientAuth();
        }

        static JettyRoleTlsTarget find(Server server) {
            SslContextFactory.Server selected = null;
            for (Connector connector : server.getConnectors()) {
                SslConnectionFactory ssl = connector.getConnectionFactory(
                        SslConnectionFactory.class);
                if (ssl == null) {
                    continue;
                }
                if (selected != null) {
                    throw new IllegalStateException(
                            "MassDB License requires exactly one Jetty HTTPS connector");
                }
                selected = ssl.getSslContextFactory();
            }
            if (selected == null) {
                throw new IllegalStateException("Jetty HTTPS connector not found");
            }
            return new JettyRoleTlsTarget(selected);
        }

        @Override
        public synchronized void enableRoleIdentity(long replacementGeneration,
                SSLContext sslContext) throws Exception {
            if (replacementGeneration <= 0) {
                throw new IllegalArgumentException("identity generation must be positive");
            }
            SSLContext replacement = Objects.requireNonNull(sslContext, "sslContext");
            contextFactory.reload(factory -> {
                factory.setSslContext(replacement);
                SslContextFactory.Server server = (SslContextFactory.Server) factory;
                server.setNeedClientAuth(false);
                server.setWantClientAuth(true);
            });
            generation = replacementGeneration;
            roleIdentityEnabled = true;
        }

        @Override
        public synchronized void disableRoleIdentity() throws Exception {
            if (!roleIdentityEnabled) {
                return;
            }
            contextFactory.reload(factory -> {
                factory.setSslContext(ordinaryHttpsContext);
                SslContextFactory.Server server = (SslContextFactory.Server) factory;
                server.setNeedClientAuth(false);
                server.setWantClientAuth(false);
            });
            generation = 0;
            roleIdentityEnabled = false;
        }

        boolean isRoleIdentityEnabled() {
            return roleIdentityEnabled;
        }

        long getGeneration() {
            return generation;
        }
    }
}
