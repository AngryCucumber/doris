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
import org.apache.doris.massdblicense.MassDbLicenseFeRoleProtocol;
import org.apache.doris.massdblicense.MassDbLicenseFeRoleTransport;
import org.apache.doris.massdblicense.MassDbLicenseJettyIdentityController;
import org.apache.doris.massdblicense.MassDbLicenseSpiffeIdentity;

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

/** Path-level mTLS endpoint used only by MassDB SQL FE License roles. */
@RestController
public class MassDbLicenseFeRoleAction {
    private static final int MAX_REQUEST_BYTES = 256 * 1024;

    @PostMapping(path = MassDbLicenseFeRoleProtocol.PATH,
            consumes = "application/json", produces = "application/json")
    public Object exchange(HttpServletRequest request) {
        if (!Config.massdb_license_role_mtls_enabled) {
            return error(HttpStatus.NOT_FOUND,
                    "MASSDB_LICENSE_ROLE_TRANSPORT_UNAVAILABLE");
        }
        if (!request.isSecure()) {
            return error(HttpStatus.UPGRADE_REQUIRED,
                    "MASSDB_LICENSE_MTLS_REQUIRED");
        }
        Env env = Env.getServingEnv();
        MassDbLicenseJettyIdentityController identityController =
                env.getMassDbLicenseJettyIdentityController();
        if (identityController == null || !identityController.isAvailable()) {
            return error(HttpStatus.SERVICE_UNAVAILABLE,
                    "MASSDB_LICENSE_ROLE_TRANSPORT_UNAVAILABLE");
        }
        X509Certificate[] chain = peerCertificates(request);
        if (chain == null || chain.length == 0) {
            return error(HttpStatus.UNAUTHORIZED,
                    "MASSDB_LICENSE_MTLS_REQUIRED");
        }
        if (!env.isReady() || !env.isMaster()) {
            return error(HttpStatus.CONFLICT, "MASSDB_LICENSE_NOT_LEADER");
        }
        MassDbLicenseFeRoleTransport transport = env.getMassDbLicenseFeRoleTransport();
        if (transport == null || !transport.isAvailable()) {
            return error(HttpStatus.SERVICE_UNAVAILABLE,
                    "MASSDB_LICENSE_ROLE_TRANSPORT_UNAVAILABLE");
        }
        try {
            long nowEpochSecond = Instant.now().getEpochSecond();
            MassDbLicenseSpiffeIdentity.Identity identity =
                    identityController.requireAllowedClient(chain, nowEpochSecond);
            byte[] body = readBounded(request);
            MassDbLicenseFeRoleProtocol.ExchangeRequest exchange =
                    MassDbLicenseFeRoleProtocol.decode(body,
                    MassDbLicenseFeRoleProtocol.ExchangeRequest.class);
            return ResponseEntity.ok(transport.exchange(
                    identity, exchange, nowEpochSecond));
        } catch (MassDbLicenseException error) {
            HttpStatus status;
            if ("MASSDB_LICENSE_ROLE_TRANSPORT_UNAVAILABLE".equals(error.getCode())) {
                status = HttpStatus.SERVICE_UNAVAILABLE;
            } else if (error.getCode().startsWith("MASSDB_LICENSE_MTLS_")
                    || "MASSDB_LICENSE_ROLE_IDENTITY_REVOKED".equals(error.getCode())) {
                status = HttpStatus.FORBIDDEN;
            } else {
                status = HttpStatus.BAD_REQUEST;
            }
            return error(status, error.getCode());
        } catch (IOException | RuntimeException error) {
            return error(HttpStatus.BAD_REQUEST,
                    "MASSDB_LICENSE_ROLE_PROTOCOL_INVALID");
        }
    }

    private static X509Certificate[] peerCertificates(HttpServletRequest request) {
        Object value = request.getAttribute("jakarta.servlet.request.X509Certificate");
        if (!(value instanceof X509Certificate[])) {
            value = request.getAttribute("javax.servlet.request.X509Certificate");
        }
        return value instanceof X509Certificate[] ? (X509Certificate[]) value : null;
    }

    private static byte[] readBounded(HttpServletRequest request) throws IOException {
        long declared = request.getContentLengthLong();
        if (declared <= 0 || declared > MAX_REQUEST_BYTES) {
            throw new IOException("invalid MassDB License role request length");
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
                    throw new IOException("MassDB License role request too large");
                }
                output.write(buffer, 0, count);
            }
            if (output.size() == 0) {
                throw new IOException("empty MassDB License role request");
            }
            return output.toByteArray();
        }
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
