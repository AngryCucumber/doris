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

package org.apache.doris.massdblicense;

import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.InfoSchemaDb;
import org.apache.doris.catalog.MysqlDb;
import org.apache.doris.common.FeConstants;
import org.apache.doris.ha.FrontendNodeType;
import org.apache.doris.system.Frontend;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.HttpsURLConnection;

/** Production catalog view and direct FE-to-FE mTLS client for the upgrade fence. */
public final class MassDbLicenseUpgradeRuntime implements
        MassDbLicenseUpgradeCore.ClusterView,
        MassDbLicenseUpgradeCore.AttestationClient {
    private static final int MAX_RESPONSE_BYTES = 256 * 1024;

    private final Env env;
    private final MassDbLicenseLocalSnapshotStore store;
    private final MassDbLicenseFeRoleIdentityProvider identityProvider;
    private final int timeoutMillis;

    public MassDbLicenseUpgradeRuntime(Env env, MassDbLicenseLocalSnapshotStore store,
            MassDbLicenseFeRoleIdentityProvider identityProvider, int timeoutMillis) {
        if (env == null || store == null || identityProvider == null || timeoutMillis <= 0) {
            throw new IllegalArgumentException("upgrade runtime依赖或超时无效");
        }
        this.env = env;
        this.store = store;
        this.identityProvider = identityProvider;
        this.timeoutMillis = timeoutMillis;
    }

    @Override
    public boolean isReadyLeader() {
        return env.isReady() && env.isMaster();
    }

    @Override
    public boolean hasExistingBusinessMetadata() {
        for (String database : env.getInternalCatalog().getDbNames()) {
            if (!InfoSchemaDb.DATABASE_NAME.equals(database)
                    && !MysqlDb.DATABASE_NAME.equals(database)
                    && !FeConstants.INTERNAL_DB_NAME.equals(database)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String localNodeUuid() {
        return store.getNodeUuid();
    }

    @Override
    public List<MassDbLicenseUpgradeCore.PersistentFrontend> persistentFrontends() {
        List<MassDbLicenseUpgradeCore.PersistentFrontend> result = new ArrayList<>();
        for (Frontend frontend : env.getFrontends(null)) {
            String role = frontend.getRole() == FrontendNodeType.OBSERVER
                    ? "OBSERVER" : "VOTER";
            result.add(new MassDbLicenseUpgradeCore.PersistentFrontend(
                    role, frontend.getHost(), frontend.getEditLogPort()));
        }
        return result;
    }

    @Override
    public MassDbLicenseUpgradeProtocol.Response attest(
            MassDbLicenseUpgradeCore.UpgradeFrontend frontend,
            MassDbLicenseUpgradeProtocol.Request request, long now) throws Exception {
        MassDbLicenseFeRoleIdentityProvider.Snapshot identity =
                identityProvider.current(now);
        if (!identity.identity.nodeUuid.equals(request.requesterNodeUuid)
                || !identity.identity.deploymentUuid.equals(request.deploymentUuid)
                || !"massdb-sql".equals(identity.identity.component)
                || !"fe".equals(identity.identity.role)) {
            fail("MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH",
                    "Leader FE身份与upgrade请求不匹配");
        }
        URL endpoint = new URL(frontend.httpsEndpoint
                + MassDbLicenseUpgradeProtocol.PATH);
        HttpsURLConnection connection = (HttpsURLConnection) endpoint.openConnection();
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(timeoutMillis);
        connection.setReadTimeout(timeoutMillis);
        connection.setSSLSocketFactory(identity.clientSslContext.getSocketFactory());
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Accept", "application/json");
        connection.setDoOutput(true);
        byte[] encoded = MassDbLicenseUpgradeProtocol.encode(request);
        connection.setFixedLengthStreamingMode(encoded.length);
        try {
            try (OutputStream output = connection.getOutputStream()) {
                output.write(encoded);
            }
            int status = connection.getResponseCode();
            Certificate[] serverCertificates = connection.getServerCertificates();
            if (serverCertificates.length == 0
                    || !(serverCertificates[0] instanceof X509Certificate)) {
                fail("MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH",
                        "目标FE没有提供可验证的服务端证书");
            }
            MassDbLicenseSpiffeIdentity.Identity server =
                    MassDbLicenseSpiffeIdentity.parsePeerCertificate(
                            (X509Certificate) serverCertificates[0]);
            identity.requireAllowedServer((X509Certificate) serverCertificates[0],
                    request.deploymentUuid);
            if (!frontend.nodeUuid.equals(server.nodeUuid)) {
                fail("MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH",
                        "目标FE证书node UUID与upgrade plan不匹配");
            }
            byte[] response = readBounded(status >= 400
                    ? connection.getErrorStream() : connection.getInputStream());
            if (status != 200) {
                fail("MASSDB_LICENSE_UPGRADE_ATTESTATION_FAILED",
                        "目标FE拒绝upgrade attestation，HTTP " + status);
            }
            return MassDbLicenseUpgradeProtocol.decode(
                    response, MassDbLicenseUpgradeProtocol.Response.class);
        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
            connection.disconnect();
        }
    }

    private static byte[] readBounded(InputStream input) throws IOException {
        if (input == null) {
            return new byte[0];
        }
        try (InputStream source = input;
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = source.read(buffer)) >= 0) {
                if (count == 0) {
                    continue;
                }
                if (output.size() + count > MAX_RESPONSE_BYTES) {
                    fail("MASSDB_LICENSE_UPGRADE_ATTESTATION_FAILED",
                            "目标FE attestation响应过大");
                }
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }
}
