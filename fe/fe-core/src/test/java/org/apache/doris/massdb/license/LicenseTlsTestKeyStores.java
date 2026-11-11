// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * FE key stores for the HTTPS tests, made once per test JVM with the JDK's keytool (JKS, password {@link #PASSWORD},
 * key alias doris_ssl_certificate). Nothing is checked in, so no certificate can expire in the repository.
 */
public final class LicenseTlsTestKeyStores {
    public static final String PASSWORD = "massdb-test";
    public static final String ALIAS = "doris_ssl_certificate";
    private static LicenseTlsTestKeyStores instance;

    /** One self-signed key pair naming no host, copied to every FE (the Doris HTTPS guide's setup). */
    public final Path shared;
    /** This FE: its key pair signed by the test CA for 127.0.0.2, and the CA as a trusted certificate entry. */
    public final Path local;
    /** A peer signed by the same CA for 127.0.0.1, the address the tests register it under. */
    public final Path peer;
    /** A peer signed by the same CA for 127.0.0.9 only. */
    public final Path wrongName;
    /** A peer that names 127.0.0.1 but is self-signed and in nobody's key store. */
    public final Path rogue;

    private final Path directory;
    private final String keytool;

    private LicenseTlsTestKeyStores() throws IOException, InterruptedException {
        directory = Files.createTempDirectory("massdb-license-tls");
        directory.toFile().deleteOnExit();
        keytool = System.getProperty("java.home") + File.separator + "bin" + File.separator + "keytool";
        shared = file("shared.keystore");
        keyPair(shared, "CN=MassDB Test FE", null, false);
        Path authority = file("ca.p12");
        keyPair(authority, "CN=MassDB Test CA", null, true);
        Path authorityPem = file("ca.pem");
        run("-exportcert", "-rfc", "-alias", ALIAS, "-keystore", authority.toString(), "-storepass", PASSWORD,
                "-file", authorityPem.toString());
        local = signed("local", "127.0.0.2", authority, authorityPem);
        peer = signed("peer", "127.0.0.1", authority, authorityPem);
        wrongName = signed("wrong-name", "127.0.0.9", authority, authorityPem);
        rogue = file("rogue.keystore");
        keyPair(rogue, "CN=rogue", "SAN=IP:127.0.0.1", false);
    }

    public static synchronized LicenseTlsTestKeyStores get() throws IOException, InterruptedException {
        if (instance == null) {
            instance = new LicenseTlsTestKeyStores();
        }
        return instance;
    }

    /** A server context presenting the key pair of the given key store. */
    public static SSLContext serverContext(Path keyStore) throws Exception {
        KeyStore store = KeyStore.getInstance("JKS");
        try (InputStream input = Files.newInputStream(keyStore)) {
            store.load(input, PASSWORD.toCharArray());
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), null, null);
        return context;
    }

    /** A client context trusting the certificates of the given key store, for tests that are not the FE. */
    public static SSLContext clientContext(Path keyStore) throws Exception {
        KeyStore store = KeyStore.getInstance("JKS");
        try (InputStream input = Files.newInputStream(keyStore)) {
            store.load(input, PASSWORD.toCharArray());
        }
        TrustManagerFactory trust = TrustManagerFactory.getInstance("PKIX");
        trust.init(store);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trust.getTrustManagers(), null);
        return context;
    }

    private Path signed(String name, String ip, Path authority, Path authorityPem)
            throws IOException, InterruptedException {
        Path store = file(name + ".keystore");
        keyPair(store, "CN=" + name, null, false);
        Path request = file(name + ".csr");
        Path certificate = file(name + ".pem");
        run("-certreq", "-alias", ALIAS, "-keystore", store.toString(), "-storepass", PASSWORD,
                "-file", request.toString());
        run("-gencert", "-alias", ALIAS, "-keystore", authority.toString(), "-storepass", PASSWORD,
                "-infile", request.toString(), "-outfile", certificate.toString(), "-rfc", "-validity", "3650",
                "-ext", "SAN=IP:" + ip);
        run("-importcert", "-alias", "test-ca", "-file", authorityPem.toString(), "-keystore", store.toString(),
                "-storepass", PASSWORD, "-noprompt");
        run("-importcert", "-alias", ALIAS, "-file", certificate.toString(), "-keystore", store.toString(),
                "-storepass", PASSWORD, "-noprompt");
        return store;
    }

    private void keyPair(Path store, String subject, String extension, boolean authority)
            throws IOException, InterruptedException {
        List<String> arguments = new ArrayList<>(Arrays.asList("-genkeypair", "-alias", ALIAS, "-keyalg", "EC",
                "-groupname", "secp256r1", "-validity", "3650", "-dname", subject, "-keystore", store.toString(),
                "-storetype", store.toString().endsWith(".p12") ? "PKCS12" : "JKS", "-storepass", PASSWORD,
                "-keypass", PASSWORD, "-noprompt"));
        if (extension != null) {
            arguments.addAll(Arrays.asList("-ext", extension));
        }
        if (authority) {
            arguments.addAll(Arrays.asList("-ext", "bc:c"));
        }
        run(arguments.toArray(new String[0]));
    }

    private Path file(String name) {
        Path path = directory.resolve(name);
        path.toFile().deleteOnExit();
        return path;
    }

    private void run(String... arguments) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(keytool);
        command.addAll(Arrays.asList(arguments));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (InputStream input = process.getInputStream()) {
            byte[] buffer = new byte[4096];
            int read;
            while ((read = input.read(buffer)) != -1) {
                output.write(buffer, 0, read);
            }
        }
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            process.destroyForcibly();
            throw new IOException("keytool " + arguments[0] + " failed: "
                    + new String(output.toByteArray(), StandardCharsets.UTF_8));
        }
    }
}
