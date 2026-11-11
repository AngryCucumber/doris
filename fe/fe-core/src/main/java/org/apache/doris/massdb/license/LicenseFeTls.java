// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.common.Config;

import org.apache.http.conn.ssl.DefaultHostnameVerifier;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * TLS for the license module's calls to other FEs when enable_https is on: the capability and clock probes and the
 * forwards to the master (review L11). With the JVM default trust store alone, the self-signed or private-CA
 * certificates FEs usually carry failed every call, so License could not initialize and no follower could forward.
 *
 * <p>A peer is trusted when its chain ends at a certificate of this FE's own key store (key_store_path: the chains of
 * its key entries and its trusted certificate entries) or of the JVM default trust store, and its certificate names
 * the registered host or IP (subject alternative names; the common name only when it has none). Jetty 12 already
 * answers "400 Invalid SNI" to any HTTPS request whose host the server certificate does not name, so a certificate
 * that names no FE address cannot serve the web UI or these calls either way.
 *
 * <p>The key store is read again when its file changes, so a certificate added as a trusted entry takes effect
 * without a restart. Jetty still serves the certificate it loaded at startup.
 */
final class LicenseFeTls {
    /** Probe and forward failure reasons; never a provider message, which may name hosts or certificate fields. */
    static final String TRUST_UNAVAILABLE = "TLS_TRUST_UNAVAILABLE";
    static final String UNTRUSTED = "TLS_UNTRUSTED_CERTIFICATE";
    static final String HOSTNAME_MISMATCH = "TLS_HOSTNAME_MISMATCH";
    static final String HANDSHAKE_FAILED = "TLS_HANDSHAKE_FAILED";

    private static final DefaultHostnameVerifier STRICT = new DefaultHostnameVerifier();
    private static Trust cached;

    private LicenseFeTls() {
    }

    /** The context and a fresh name check for one call. */
    static Call call() throws TrustUnavailable {
        Trust trust = trust();
        return new Call(trust.context, new Verifier());
    }

    /** One of the reasons above for a failed call, or null when the failure is not about TLS. */
    static String failureReason(Throwable failure, Call call) {
        if (failure instanceof TrustUnavailable) {
            return TRUST_UNAVAILABLE;
        }
        if (call != null && call.verifier.rejected) {
            return HOSTNAME_MISMATCH;
        }
        if (!(failure instanceof SSLException)) {
            return null;
        }
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof CertificateException) {
                return UNTRUSTED;
            }
        }
        return HANDSHAKE_FAILED;
    }

    /** This FE's key store could not be read; nothing was sent. */
    static final class TrustUnavailable extends IOException {
        private TrustUnavailable() {
            super(TRUST_UNAVAILABLE, null);
        }
    }

    static final class Call {
        final SSLContext context;
        final Verifier verifier;

        private Call(SSLContext context, Verifier verifier) {
            this.context = context;
            this.verifier = verifier;
        }
    }

    /**
     * The name check, remembering a rejection: HttpsURLConnection reports it as a plain IOException. That client
     * asks this verifier only after its own check failed, the Apache client always.
     */
    static final class Verifier implements HostnameVerifier {
        private volatile boolean rejected;

        private Verifier() {
        }

        @Override
        public boolean verify(String host, SSLSession session) {
            if (STRICT.verify(host, session)) {
                return true;
            }
            rejected = true;
            return false;
        }
    }

    private static Trust trust() throws TrustUnavailable {
        Path path;
        String location = Config.key_store_path;
        try {
            path = location.startsWith("file:") ? Paths.get(URI.create(location)) : Paths.get(location);
        } catch (RuntimeException e) {
            throw new TrustUnavailable();
        }
        String identity;
        try {
            BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class);
            identity = path.toAbsolutePath() + "\n" + attributes.lastModifiedTime().toMillis() + "\n"
                    + attributes.size() + "\n" + Config.key_store_type + "\n" + Config.key_store_password.hashCode();
        } catch (IOException | RuntimeException e) {
            throw new TrustUnavailable();
        }
        synchronized (LicenseFeTls.class) {
            if (cached != null && cached.identity.equals(identity)) {
                return cached;
            }
        }
        Trust loaded = load(path, identity);
        synchronized (LicenseFeTls.class) {
            cached = loaded;
        }
        return loaded;
    }

    private static Trust load(Path path, String identity) throws TrustUnavailable {
        try {
            KeyStore store = KeyStore.getInstance(Config.key_store_type);
            try (InputStream input = Files.newInputStream(path)) {
                store.load(input, Config.key_store_password.toCharArray());
            }
            KeyStore anchors = KeyStore.getInstance("PKCS12");
            anchors.load(null, null);
            int count = 0;
            for (Enumeration<String> aliases = store.aliases(); aliases.hasMoreElements(); ) {
                String alias = aliases.nextElement();
                Certificate[] certificates;
                if (store.isKeyEntry(alias)) {
                    certificates = store.getCertificateChain(alias);
                } else {
                    Certificate certificate = store.getCertificate(alias);
                    certificates = certificate == null ? null : new Certificate[] {certificate};
                }
                for (Certificate certificate : certificates == null ? new Certificate[0] : certificates) {
                    if (certificate instanceof X509Certificate) {
                        anchors.setCertificateEntry("fe-" + count++, certificate);
                    }
                }
            }
            for (X509Certificate certificate : systemAnchors()) {
                anchors.setCertificateEntry("jvm-" + count++, certificate);
            }
            // PKIX only checks the chain: neither client sets an endpoint identification algorithm, so the name is
            // checked by Verifier.
            TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
            factory.init(anchors);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, factory.getTrustManagers(), null);
            return new Trust(identity, context);
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            // Wrong password or type, or a damaged file: report it without the provider's message.
            throw new TrustUnavailable();
        }
    }

    private static List<X509Certificate> systemAnchors() throws GeneralSecurityException {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        List<X509Certificate> result = new ArrayList<>();
        for (TrustManager manager : factory.getTrustManagers()) {
            if (manager instanceof X509TrustManager) {
                result.addAll(Arrays.asList(((X509TrustManager) manager).getAcceptedIssuers()));
            }
        }
        return result;
    }

    private static final class Trust {
        private final String identity;
        private final SSLContext context;

        private Trust(String identity, SSLContext context) {
            this.identity = identity;
            this.context = context;
        }
    }
}
