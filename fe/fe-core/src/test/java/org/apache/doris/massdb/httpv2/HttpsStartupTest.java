// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.httpv2;

import org.apache.doris.common.Config;
import org.apache.doris.common.FeConstants;
import org.apache.doris.httpv2.HttpServer;
import org.apache.doris.massdb.license.LicenseTlsTestKeyStores;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

/**
 * The FE web server with enable_https on. Since the Spring Boot 3 / Jetty 12 port the HTTPS customizer replaced
 * the configuration list, dropping Spring Boot's WebSocket configuration, and every FE exited at startup with
 * "WebSocketComponents has not been created" (found with review L11, whose retest needs HTTPS).
 */
public class HttpsStartupTest {
    @Test
    void frontendWebServerStartsWithHttpsAndKeepsTheHttpPort() throws Exception {
        LicenseTlsTestKeyStores stores = LicenseTlsTestKeyStores.get();
        int httpPort = freePort();
        int httpsPort = freePort();
        Config.enable_https = true;
        Config.http_port = httpPort;
        Config.https_port = httpsPort;
        FeConstants.runningUnitTest = true;
        HttpServer server = new HttpServer();
        server.setPort(httpPort);
        server.setHttpsPort(httpsPort);
        // Signed for 127.0.0.1: Jetty 12 answers "400 Invalid SNI" when the certificate does not name the host.
        server.setKeyStorePath(stores.peer.toString());
        server.setKeyStorePassword(LicenseTlsTestKeyStores.PASSWORD);
        server.setKeyStoreType("JKS");
        server.setKeyStoreAlias(LicenseTlsTestKeyStores.ALIAS);
        server.setEnableHttps(true);
        server.setMaxHttpPostSize(100 * 1024 * 1024);
        server.setAcceptors(2);
        server.setSelectors(4);
        server.setWorkers(0);
        server.start();

        HttpsURLConnection secure = (HttpsURLConnection) new URL("https://127.0.0.1:" + httpsPort
                + "/api/bootstrap").openConnection(Proxy.NO_PROXY);
        secure.setSSLSocketFactory(LicenseTlsTestKeyStores.clientContext(stores.local).getSocketFactory());
        try {
            Assertions.assertEquals(200, secure.getResponseCode());
        } finally {
            secure.disconnect();
        }

        // The HTTP port still listens (FEs fetch images and journals from it) and sends GET /api/* to HTTPS.
        HttpURLConnection plain = (HttpURLConnection) new URL("http://127.0.0.1:" + httpPort
                + "/api/bootstrap").openConnection(Proxy.NO_PROXY);
        plain.setInstanceFollowRedirects(false);
        try {
            Assertions.assertEquals(302, plain.getResponseCode());
            Assertions.assertEquals("https://127.0.0.1:" + httpsPort + "/api/bootstrap",
                    plain.getHeaderField("Location"));
        } finally {
            plain.disconnect();
        }
    }

    private static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return socket.getLocalPort();
        }
    }
}
