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

import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/** Strict parser for component X.509-SVID URI SANs used by internal License ACK RPC. */
public final class MassDbLicenseSpiffeIdentity {
    public static final String TRUST_DOMAIN = "massdb.internal";

    private MassDbLicenseSpiffeIdentity() {
    }

    public static Identity parseUnique(List<String> uriSans) {
        if (uriSans == null || uriSans.size() != 1) {
            fail("mTLS证书必须且只能包含一个URI SAN");
        }
        return parse(uriSans.get(0));
    }

    /** Called only after the HTTPS/mTLS stack has chain-verified the peer certificate. */
    public static Identity parsePeerCertificate(X509Certificate certificate) {
        return parse(requireUniqueUriSan(certificate));
    }

    /** Returns the exact, unique URI SAN so other frozen License identities can share parsing. */
    public static String requireUniqueUriSan(X509Certificate certificate) {
        if (certificate == null) {
            fail("mTLS对端证书为空");
        }
        final Collection<List<?>> subjectAlternativeNames;
        try {
            subjectAlternativeNames = certificate.getSubjectAlternativeNames();
        } catch (CertificateParsingException error) {
            fail("无法解析mTLS证书SAN");
            return null;
        }
        List<String> uriSans = new ArrayList<>();
        if (subjectAlternativeNames != null) {
            for (List<?> item : subjectAlternativeNames) {
                if (item == null || item.size() < 2 || !(item.get(0) instanceof Integer)) {
                    fail("mTLS证书SAN结构非法");
                }
                if (((Integer) item.get(0)) == 6) {
                    if (!(item.get(1) instanceof String)) {
                        fail("mTLS证书URI SAN类型非法");
                    }
                    uriSans.add((String) item.get(1));
                }
            }
        }
        if (uriSans.size() != 1) {
            fail("mTLS证书必须且只能包含一个URI SAN");
        }
        return uriSans.get(0);
    }

    public static Identity requireNode(List<String> uriSans, String expectedComponent,
            String expectedDeploymentUuid, String expectedRole, String expectedNodeUuid) {
        Identity identity = parseUnique(uriSans);
        if (!identity.component.equals(expectedComponent)
                || !identity.deploymentUuid.equals(expectedDeploymentUuid)
                || !identity.role.equals(expectedRole)
                || !identity.nodeUuid.equals(expectedNodeUuid)) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH",
                    "mTLS URI SAN与目标组件、部署、角色或持久node UUID不一致");
        }
        return identity;
    }

    static Identity parse(String raw) {
        if (raw == null || raw.indexOf('%') >= 0) {
            fail("SPIFFE ID为空或包含转义路径");
        }
        final URI uri;
        try {
            uri = new URI(raw);
        } catch (URISyntaxException error) {
            fail("SPIFFE ID语法非法");
            return null;
        }
        if (!"spiffe".equals(uri.getScheme())
                || !TRUST_DOMAIN.equals(uri.getRawAuthority())
                || uri.getUserInfo() != null || uri.getPort() != -1
                || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            fail("SPIFFE ID scheme、trust domain或附加字段非法");
        }
        String[] segments = uri.getRawPath().split("/", -1);
        if (segments.length != 7 || !segments[0].isEmpty()
                || !"license".equals(segments[1])
                || !"component".equals(segments[2])
                || !isSupportedRole(segments[3], segments[5])
                || !isCanonicalVersion4Uuid(segments[4])
                || !isCanonicalVersion4Uuid(segments[6])) {
            fail("SPIFFE ID组件路径不符合冻结模板");
        }
        return new Identity(segments[3], segments[4], segments[5], segments[6]);
    }

    private static boolean isSupportedRole(String component, String role) {
        if ("massdb-sql".equals(component)) {
            return "fe".equals(role);
        }
        if ("massdb-oss".equals(component)) {
            return "master".equals(role) || "filer".equals(role)
                    || "s3".equals(role) || "webdav".equals(role);
        }
        if ("massdb-graph".equals(component)) {
            return "graphd".equals(role) || "metad".equals(role);
        }
        return false;
    }

    static boolean isCanonicalVersion4Uuid(String value) {
        if (value == null || value.length() != 36) {
            return false;
        }
        try {
            UUID parsed = UUID.fromString(value);
            return parsed.version() == 4 && parsed.variant() == 2
                    && parsed.toString().equals(value);
        } catch (IllegalArgumentException error) {
            return false;
        }
    }

    private static void fail(String message) {
        throw new MassDbLicenseException("MASSDB_LICENSE_MTLS_IDENTITY_INVALID", message);
    }

    public static final class Identity {
        public final String component;
        public final String deploymentUuid;
        public final String role;
        public final String nodeUuid;

        private Identity(String component, String deploymentUuid,
                String role, String nodeUuid) {
            this.component = component;
            this.deploymentUuid = deploymentUuid;
            this.role = role;
            this.nodeUuid = nodeUuid;
        }
    }
}
