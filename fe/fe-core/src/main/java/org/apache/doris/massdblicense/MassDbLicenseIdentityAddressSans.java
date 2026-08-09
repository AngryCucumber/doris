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

import java.net.IDN;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** Canonical DNS/IP SANs requested by one component-generated identity CSR. */
final class MassDbLicenseIdentityAddressSans {
    private static final int MAX_ADDRESS_SANS = 16;

    private MassDbLicenseIdentityAddressSans() {
    }

    static AddressSans normalize(Collection<String> dnsValues,
            Collection<String> ipValues, boolean requireAddress) {
        if (dnsValues == null || ipValues == null) {
            fail("DNS/IP SAN集合不能为空");
        }
        Set<String> dns = new TreeSet<>();
        for (String value : dnsValues) {
            String canonical = canonicalDns(value);
            if (!dns.add(canonical)) {
                fail("DNS SAN规范化后不能重复");
            }
        }
        Set<String> ips = new TreeSet<>();
        for (String value : ipValues) {
            String canonical = canonicalIp(value);
            if (!ips.add(canonical)) {
                fail("IP SAN规范化后不能重复");
            }
        }
        if (dns.size() + ips.size() > MAX_ADDRESS_SANS) {
            fail("DNS/IP SAN总数不能超过16");
        }
        if (requireAddress && dns.isEmpty() && ips.isEmpty()) {
            fail("共享HTTPS身份CSR至少需要一个DNS或IP SAN");
        }
        return new AddressSans(new ArrayList<>(dns), new ArrayList<>(ips));
    }

    static void requireCertificateMatches(X509Certificate certificate, AddressSans expected) {
        Objects.requireNonNull(certificate, "certificate");
        Objects.requireNonNull(expected, "expected");
        List<String> dns = new ArrayList<>();
        List<String> ips = new ArrayList<>();
        int uriCount = 0;
        try {
            Collection<List<?>> values = certificate.getSubjectAlternativeNames();
            if (values == null) {
                fail("身份leaf缺少Subject Alternative Name");
            }
            for (List<?> entry : values) {
                if (entry == null || entry.size() != 2 || !(entry.get(0) instanceof Integer)) {
                    fail("身份leaf包含无法解析的Subject Alternative Name");
                }
                int type = (Integer) entry.get(0);
                Object value = entry.get(1);
                if (type == 6 && value instanceof String) {
                    uriCount++;
                } else if (type == 2 && value instanceof String) {
                    dns.add(canonicalDns((String) value));
                } else if (type == 7 && value instanceof String) {
                    ips.add(canonicalIp((String) value));
                } else {
                    fail("身份leaf只能包含URI、DNS和IP SAN");
                }
            }
        } catch (CertificateParsingException error) {
            fail("身份leaf的Subject Alternative Name无法解析");
        }
        if (uriCount != 1) {
            fail("身份leaf必须只包含一个URI SAN");
        }
        AddressSans actual = normalize(dns, ips, false);
        if (!actual.equals(expected)) {
            fail("身份leaf的DNS/IP SAN与本机CSR不一致");
        }
    }

    static byte[] ipBytes(String canonical) {
        try {
            return InetAddress.getByName(canonical).getAddress();
        } catch (UnknownHostException error) {
            fail("IP SAN无法编码");
            return null;
        }
    }

    private static String canonicalDns(String value) {
        if (value == null || value.isEmpty() || !value.equals(value.trim())
                || value.indexOf('*') >= 0 || value.endsWith(".")) {
            fail("DNS SAN不能为空、通配、带空白或尾随点");
        }
        final String ascii;
        try {
            ascii = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES)
                    .toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException error) {
            fail("DNS SAN格式无效");
            return null;
        }
        if (ascii.isEmpty() || ascii.length() > 253 || looksLikeIpv4(ascii)) {
            fail("DNS SAN长度无效或误用了IP地址");
        }
        String[] labels = ascii.split("\\.", -1);
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63 || label.startsWith("-")
                    || label.endsWith("-")) {
                fail("DNS SAN标签格式无效");
            }
        }
        return ascii;
    }

    private static String canonicalIp(String value) {
        if (value == null || value.isEmpty() || !value.equals(value.trim())
                || value.indexOf('%') >= 0) {
            fail("IP SAN不能为空、带空白或zone id");
        }
        try {
            if (value.indexOf(':') >= 0) {
                for (int index = 0; index < value.length(); index++) {
                    char item = value.charAt(index);
                    if (item != ':' && item != '.' && !isHex(item)) {
                        fail("IPv6 SAN只能包含十六进制、冒号和点");
                    }
                }
                InetAddress address = InetAddress.getByName(value);
                if (!(address instanceof Inet6Address)) {
                    fail("IPv6 SAN格式无效");
                }
                return address.getHostAddress().toLowerCase(Locale.ROOT);
            }
            String[] parts = value.split("\\.", -1);
            if (parts.length != 4) {
                fail("IPv4 SAN必须是四段十进制地址");
            }
            byte[] encoded = new byte[4];
            for (int index = 0; index < parts.length; index++) {
                String part = parts[index];
                if (part.isEmpty() || part.length() > 3
                        || part.length() > 1 && part.charAt(0) == '0') {
                    fail("IPv4 SAN必须使用无前导零的规范十进制格式");
                }
                int number = 0;
                for (int offset = 0; offset < part.length(); offset++) {
                    char item = part.charAt(offset);
                    if (item < '0' || item > '9') {
                        fail("IPv4 SAN包含非数字字符");
                    }
                    number = number * 10 + item - '0';
                }
                if (number > 255) {
                    fail("IPv4 SAN段值超过255");
                }
                encoded[index] = (byte) number;
            }
            InetAddress address = InetAddress.getByAddress(encoded);
            if (!(address instanceof Inet4Address)) {
                fail("IPv4 SAN格式无效");
            }
            return address.getHostAddress();
        } catch (UnknownHostException error) {
            fail("IP SAN格式无效");
            return null;
        }
    }

    private static boolean looksLikeIpv4(String value) {
        if (value.indexOf('.') < 0) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (item != '.' && (item < '0' || item > '9')) {
                return false;
            }
        }
        return true;
    }

    private static boolean isHex(char value) {
        return value >= '0' && value <= '9'
                || value >= 'a' && value <= 'f'
                || value >= 'A' && value <= 'F';
    }

    private static void fail(String message) {
        throw new MassDbLicenseException(
                "MASSDB_LICENSE_ROLE_IDENTITY_ADDRESS_SAN_INVALID", message);
    }

    static final class AddressSans {
        private final List<String> dnsNames;
        private final List<String> ipAddresses;

        private AddressSans(List<String> dnsNames, List<String> ipAddresses) {
            this.dnsNames = Collections.unmodifiableList(dnsNames);
            this.ipAddresses = Collections.unmodifiableList(ipAddresses);
        }

        List<String> dnsNames() {
            return dnsNames;
        }

        List<String> ipAddresses() {
            return ipAddresses;
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof AddressSans)) {
                return false;
            }
            AddressSans that = (AddressSans) other;
            return dnsNames.equals(that.dnsNames) && ipAddresses.equals(that.ipAddresses);
        }

        @Override
        public int hashCode() {
            return 31 * dnsNames.hashCode() + ipAddresses.hashCode();
        }
    }
}
