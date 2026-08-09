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

package org.apache.doris.httpv2.rest;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.massdblicense.MassDbLicenseException;
import org.apache.doris.massdblicense.MassDbLicenseJettyIdentityController;
import org.apache.doris.massdblicense.MassDbLicenseSpiffeIdentity;
import org.apache.doris.massdblicense.MassDbLicenseUpgradeCore;
import org.apache.doris.massdblicense.MassDbLicenseUpgradeProtocol;

import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Instant;

/** All FE roles expose this mTLS-only, read-only pre-journal upgrade attestation path. */
@RestController
public class MassDbLicenseUpgradeAttestationAction {
    private static final int MAX_REQUEST_BYTES = 16 * 1024;

    @PostMapping(path = MassDbLicenseUpgradeProtocol.PATH,
            consumes = "application/json", produces = "application/json")
    public Object attest(HttpServletRequest request) {
        if (!Config.massdb_license_role_mtls_enabled) {
            return error(HttpStatus.NOT_FOUND,
                    "MASSDB_LICENSE_ROLE_TRANSPORT_UNAVAILABLE");
        }
        if (!request.isSecure()) {
            return error(HttpStatus.UPGRADE_REQUIRED, "MASSDB_LICENSE_MTLS_REQUIRED");
        }
        Env env = Env.getServingEnv();
        MassDbLicenseJettyIdentityController identityController =
                env.getMassDbLicenseJettyIdentityController();
        MassDbLicenseUpgradeCore core = env.getMassDbLicenseUpgradeCore();
        if (identityController == null || !identityController.isAvailable() || core == null) {
            return error(HttpStatus.SERVICE_UNAVAILABLE,
                    "MASSDB_LICENSE_UPGRADE_ATTESTATION_UNAVAILABLE");
        }
        X509Certificate[] chain = peerCertificates(request);
        if (chain == null || chain.length == 0) {
            return error(HttpStatus.UNAUTHORIZED, "MASSDB_LICENSE_MTLS_REQUIRED");
        }
        try {
            long now = Instant.now().getEpochSecond();
            MassDbLicenseSpiffeIdentity.Identity client =
                    identityController.requireAllowedClient(chain, now);
            MassDbLicenseUpgradeProtocol.Request body =
                    MassDbLicenseUpgradeProtocol.decode(
                            readBounded(request),
                            MassDbLicenseUpgradeProtocol.Request.class);
            String localNodeUuid = identityController.requireLocalFeIdentity(
                    body.deploymentUuid, now);
            return ResponseEntity.ok(core.attestLocal(
                    env.getMassDbLicenseManager().snapshot(), client,
                    localNodeUuid, body, now));
        } catch (MassDbLicenseException failure) {
            HttpStatus status = failure.getCode().startsWith("MASSDB_LICENSE_MTLS_")
                    || "MASSDB_LICENSE_ROLE_IDENTITY_REVOKED".equals(failure.getCode())
                    ? HttpStatus.FORBIDDEN : HttpStatus.CONFLICT;
            return error(status, failure.getCode());
        } catch (IOException | RuntimeException failure) {
            return error(HttpStatus.BAD_REQUEST,
                    "MASSDB_LICENSE_UPGRADE_ATTESTATION_INVALID");
        }
    }

    private static byte[] readBounded(HttpServletRequest request) throws IOException {
        long declared = request.getContentLengthLong();
        if (declared <= 0 || declared > MAX_REQUEST_BYTES) {
            throw new IOException("invalid upgrade attestation request length");
        }
        try (ServletInputStream input = request.getInputStream();
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count == 0) {
                    continue;
                }
                if (output.size() + count > MAX_REQUEST_BYTES) {
                    throw new IOException("upgrade attestation request too large");
                }
                output.write(buffer, 0, count);
            }
            if (output.size() == 0) {
                throw new IOException("empty upgrade attestation request");
            }
            return output.toByteArray();
        }
    }

    private static X509Certificate[] peerCertificates(HttpServletRequest request) {
        Object value = request.getAttribute("jakarta.servlet.request.X509Certificate");
        if (!(value instanceof X509Certificate[])) {
            value = request.getAttribute("javax.servlet.request.X509Certificate");
        }
        return value instanceof X509Certificate[] ? (X509Certificate[]) value : null;
    }

    private static ResponseEntity<ErrorBody> error(HttpStatus status, String code) {
        return ResponseEntity.status(status).body(new ErrorBody(code));
    }

    public static final class ErrorBody {
        public final String code;

        private ErrorBody(String code) {
            this.code = code;
        }
    }
}
