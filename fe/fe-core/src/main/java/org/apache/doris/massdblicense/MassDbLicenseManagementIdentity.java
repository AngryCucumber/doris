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
import java.security.cert.X509Certificate;
import java.util.regex.Pattern;

/** Strict parser and RBAC principal for component-native License management clients. */
public final class MassDbLicenseManagementIdentity {
    private static final String PREFIX = "spiffe://" + MassDbLicenseSpiffeIdentity.TRUST_DOMAIN;
    private static final Pattern ATOM = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");

    public enum Role {
        VIEW,
        ADMIN,
        CORRECTION,
        ROUTING_ADAPTER
    }

    private MassDbLicenseManagementIdentity() {
    }

    public static Principal parsePeerCertificate(X509Certificate certificate) {
        return parse(MassDbLicenseSpiffeIdentity.requireUniqueUriSan(certificate));
    }

    public static Principal parse(String raw) {
        URI uri = strictUri(raw);
        String[] segments = uri.getRawPath().split("/", -1);
        if (segments.length == 6 && segments[0].isEmpty()
                && "license".equals(segments[1]) && "manager".equals(segments[2])
                && MassDbLicenseSpiffeIdentity.isCanonicalVersion4Uuid(segments[3])
                && isUserRole(segments[4]) && isAtom(segments[5])) {
            return new Principal(raw, "manager", segments[3], role(segments[4]),
                    segments[5], null);
        }
        if (segments.length == 5 && segments[0].isEmpty()
                && "license".equals(segments[1]) && "operator".equals(segments[2])
                && isAtom(segments[3]) && isUserRole(segments[4])) {
            return new Principal(raw, "operator", null, role(segments[4]),
                    segments[3], null);
        }
        if (segments.length == 5 && segments[0].isEmpty()
                && "license".equals(segments[1]) && "routing-adapter".equals(segments[2])
                && isAtom(segments[3]) && isAtom(segments[4])) {
            return new Principal(raw, "routing-adapter", null,
                    Role.ROUTING_ADAPTER, segments[3] + "/" + segments[4], segments[3]);
        }
        fail("SPIFFE ID管理身份路径不符合冻结模板");
        return null;
    }

    static void validateKnownIdentity(String raw) {
        if (raw != null && raw.startsWith(PREFIX + "/license/component/")) {
            MassDbLicenseSpiffeIdentity.parse(raw);
        } else {
            parse(raw);
        }
    }

    private static URI strictUri(String raw) {
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
                || !MassDbLicenseSpiffeIdentity.TRUST_DOMAIN.equals(uri.getRawAuthority())
                || uri.getUserInfo() != null || uri.getPort() != -1
                || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            fail("SPIFFE ID scheme、trust domain或附加字段非法");
        }
        return uri;
    }

    private static boolean isUserRole(String value) {
        return "view".equals(value) || "admin".equals(value)
                || "correction".equals(value);
    }

    private static Role role(String value) {
        if ("view".equals(value)) {
            return Role.VIEW;
        }
        if ("admin".equals(value)) {
            return Role.ADMIN;
        }
        return Role.CORRECTION;
    }

    private static boolean isAtom(String value) {
        return value != null && ATOM.matcher(value).matches();
    }

    private static void fail(String message) {
        throw new MassDbLicenseException("MASSDB_LICENSE_MTLS_IDENTITY_INVALID", message);
    }

    public static final class Principal {
        public final String spiffeId;
        public final String subjectKind;
        public final String managerInstallationUuid;
        public final Role role;
        public final String subjectId;
        public final String routingAdapterType;

        private Principal(String spiffeId, String subjectKind,
                String managerInstallationUuid, Role role, String subjectId,
                String routingAdapterType) {
            this.spiffeId = spiffeId;
            this.subjectKind = subjectKind;
            this.managerInstallationUuid = managerInstallationUuid;
            this.role = role;
            this.subjectId = subjectId;
            this.routingAdapterType = routingAdapterType;
        }

        public boolean canRead() {
            return role == Role.VIEW || role == Role.ADMIN;
        }

        public boolean canAdminister() {
            return role == Role.ADMIN;
        }

        public boolean canApproveCorrection() {
            return role == Role.CORRECTION;
        }

        public boolean canObserveRoutingEvidence() {
            return role == Role.ROUTING_ADAPTER;
        }
    }
}
