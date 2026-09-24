// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.catalog.Env;
import org.apache.doris.ha.FrontendNodeType;
import org.apache.doris.system.Backend;
import org.apache.doris.system.Frontend;
import org.apache.doris.system.SystemInfoService;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

class LicenseFeCompatibilityTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String PACKAGE = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final String TRUST = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    @Test
    void allMembersMustProveIdenticalPackageTrustAndFormat() {
        Map<String, Object> local = capability(TRUST);
        Frontend member = member();
        ObjectNode remote = JSON.valueToTree(local);
        Assertions.assertTrue(LicenseFeCompatibility.matches(remote, member, local, true));
        for (String field : new String[] {"package_sha256", "trust_sha256", "module", "fe_node_name", "fe_host"}) {
            ObjectNode altered = remote.deepCopy();
            altered.put(field, "different");
            Assertions.assertFalse(LicenseFeCompatibility.matches(altered, member, local, true), field);
        }
        for (String field : new String[] {"schema_version", "format_version", "edit_log_port", "process_uuid"}) {
            ObjectNode altered = remote.deepCopy();
            altered.put(field, 0);
            Assertions.assertFalse(LicenseFeCompatibility.matches(altered, member, local, true), field);
        }
        ObjectNode altered = remote.deepCopy();
        altered.putArray("journal_opcodes").add(6200);
        Assertions.assertFalse(LicenseFeCompatibility.matches(altered, member, local, true));
    }

    @Test
    void missingOrCoercedIdentityIsNotProof() {
        Map<String, Object> local = capability(TRUST);
        ObjectNode remote = JSON.valueToTree(local);
        for (String field : new String[] {"schema_version", "format_version", "module", "journal_opcodes",
                "fe_node_name", "fe_host", "edit_log_port", "process_uuid", "package_sha256", "trust_sha256",
                "trust_ready"}) {
            ObjectNode altered = remote.deepCopy();
            altered.remove(field);
            Assertions.assertFalse(LicenseFeCompatibility.matches(altered, member(), local, true), field);
        }
        remote.put("format_version", "1");
        Assertions.assertFalse(LicenseFeCompatibility.matches(remote, member(), local, true));
    }

    @Test
    void unconfiguredTrustCanInitializeIdentityButCannotMatchInstalledTrust() {
        Map<String, Object> absent = capability(null);
        ObjectNode remote = JSON.valueToTree(absent);
        Assertions.assertTrue(LicenseFeCompatibility.matches(remote, member(), absent, true));
        Assertions.assertFalse(LicenseFeCompatibility.matches(remote, member(), capability(TRUST), true));
        remote.put("trust_ready", true);
        Assertions.assertFalse(LicenseFeCompatibility.matches(remote, member(), absent, true));
    }

    @Test
    void capabilityResponseBodyAndDeadlineAreBounded() throws Exception {
        long future = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        byte[] exact = new byte[64 * 1024];
        Assertions.assertArrayEquals(exact,
                LicenseFeCompatibility.readBounded(new ByteArrayInputStream(exact), future));
        Assertions.assertThrows(IOException.class, () -> LicenseFeCompatibility.readBounded(
                new ByteArrayInputStream(new byte[exact.length + 1]), future));
        Assertions.assertThrows(IOException.class, () -> LicenseFeCompatibility.readBounded(
                new ByteArrayInputStream(new byte[1]), System.nanoTime() - 1));
    }

    @Test
    void membershipVersionDistinguishesReplacementWithSameNodeCount() {
        long initial = LicenseFeCompatibility.membershipVersion(Arrays.asList("fe:a", "be:1"));
        Assertions.assertEquals(initial, LicenseFeCompatibility.membershipVersion(Arrays.asList("fe:a", "be:1")));
        Assertions.assertNotEquals(initial, LicenseFeCompatibility.membershipVersion(Arrays.asList("fe:a", "be:2")));
        Assertions.assertNotEquals(initial, LicenseFeCompatibility.membershipVersion(Arrays.asList("fe:b", "be:1")));
        Assertions.assertNotEquals(LicenseFeCompatibility.membershipVersion(Arrays.asList("ab", "c")),
                LicenseFeCompatibility.membershipVersion(Arrays.asList("a", "bc")));
        Assertions.assertTrue(initial >= 0);
    }

    @Test
    void frontendProofTracksRegisteredIdentityButNotOrderOrLiveness() {
        Env env = Mockito.mock(Env.class);
        Frontend first = new Frontend(FrontendNodeType.FOLLOWER, "first", "127.0.0.1", 9010);
        Frontend second = new Frontend(FrontendNodeType.OBSERVER, "second", "127.0.0.2", 9110);
        first.setIsAlive(true);
        second.setIsAlive(true);
        Mockito.when(env.getFrontends(null)).thenReturn(Arrays.asList(first, second));
        long accepted = LicenseFeCompatibility.frontendVersion(env);
        first.setIsAlive(false);
        second.setIsAlive(false);
        Mockito.when(env.getFrontends(null)).thenReturn(Arrays.asList(second, first));
        Assertions.assertEquals(accepted, LicenseFeCompatibility.frontendVersion(env));
        for (Frontend replacement : Arrays.asList(
                new Frontend(FrontendNodeType.FOLLOWER, "renamed", "127.0.0.1", 9010),
                new Frontend(FrontendNodeType.FOLLOWER, "first", "127.0.0.3", 9010),
                new Frontend(FrontendNodeType.FOLLOWER, "first", "127.0.0.1", 9210),
                new Frontend(FrontendNodeType.OBSERVER, "first", "127.0.0.1", 9010))) {
            Mockito.when(env.getFrontends(null)).thenReturn(Arrays.asList(replacement, second));
            Assertions.assertNotEquals(accepted, LicenseFeCompatibility.frontendVersion(env));
        }
        Mockito.when(env.getFrontends(null)).thenReturn(Collections.singletonList(first));
        Assertions.assertNotEquals(accepted, LicenseFeCompatibility.frontendVersion(env));
        Mockito.verify(env, Mockito.never()).getClusterInfo();
    }

    @Test
    void frontendProofSeparatesNodeNameAndIpv6HostBoundaries() {
        Env env = Mockito.mock(Env.class);
        Mockito.when(env.getFrontends(null)).thenReturn(Collections.singletonList(
                new Frontend(FrontendNodeType.FOLLOWER, "node:2001", "db8::1", 9010)));
        long proof = LicenseFeCompatibility.frontendVersion(env);
        Mockito.when(env.getFrontends(null)).thenReturn(Collections.singletonList(
                new Frontend(FrontendNodeType.FOLLOWER, "node", "2001:db8::1", 9010)));
        Assertions.assertNotEquals(proof, LicenseFeCompatibility.frontendVersion(env));
    }

    @Test
    void backendAddOrDropChangesCapacityMembershipWithoutInvalidatingFrontendProof() {
        Env env = Mockito.mock(Env.class);
        SystemInfoService backends = Mockito.mock(SystemInfoService.class);
        Mockito.when(env.getFrontends(null)).thenReturn(Collections.singletonList(member()));
        Mockito.when(env.getClusterInfo()).thenReturn(backends);
        Mockito.when(backends.getAllBackendIds(false)).thenReturn(Collections.singletonList(1L));
        Mockito.when(backends.getBackend(1L)).thenReturn(new Backend(1L, "127.0.0.3", 9050));
        Mockito.when(backends.getBackend(2L)).thenReturn(new Backend(2L, "127.0.0.4", 9050));
        long proof = LicenseFeCompatibility.frontendVersion(env);
        LicenseManager.Membership before = LicenseFeCompatibility.membership(env);
        Mockito.when(backends.getAllBackendIds(false)).thenReturn(Arrays.asList(1L, 2L));
        LicenseManager.Membership after = LicenseFeCompatibility.membership(env);
        Assertions.assertEquals(1, before.beNodes);
        Assertions.assertEquals(2, after.beNodes);
        Assertions.assertNotEquals(before.version, after.version);
        Assertions.assertEquals(proof, LicenseFeCompatibility.frontendVersion(env));
        Mockito.when(backends.getAllBackendIds(false)).thenReturn(Collections.emptyList());
        Assertions.assertEquals(0, LicenseFeCompatibility.membership(env).beNodes);
        Assertions.assertEquals(proof, LicenseFeCompatibility.frontendVersion(env));
    }

    @Test
    void registeredIdentitiesOnOneHostCanUseSeparateManagementPorts() throws Exception {
        Map<String, Integer> ports = LicenseFeCompatibility.managementPorts(new String[] {
                "127.0.0.2:9010=8030", "127.0.0.2:9110=8130", "future-fe:9210=8230"});
        Frontend first = new Frontend(FrontendNodeType.FOLLOWER, "first", "127.0.0.2", 9010);
        Frontend second = new Frontend(FrontendNodeType.OBSERVER, "second", "127.0.0.2", 9110);
        Frontend other = new Frontend(FrontendNodeType.FOLLOWER, "other", "127.0.0.3", 9010);
        Assertions.assertEquals(8030, LicenseFeCompatibility.managementPort(first, 8050, ports));
        Assertions.assertEquals(8130, LicenseFeCompatibility.managementPort(second, 8050, ports));
        Assertions.assertEquals(8050, LicenseFeCompatibility.managementPort(other, 8050, ports));
        Assertions.assertEquals(8050,
                LicenseFeCompatibility.managementPort(first, 8050,
                        LicenseFeCompatibility.managementPorts(new String[0])));
    }

    @Test
    void managementPortMappingSupportsBracketedIpv6() throws Exception {
        Map<String, Integer> ports = LicenseFeCompatibility.managementPorts(new String[] {"[::1]:9010=8130"});
        Frontend member = new Frontend(FrontendNodeType.FOLLOWER, "ipv6", "::1", 9010);
        Assertions.assertEquals(8130, LicenseFeCompatibility.managementPort(member, 8050, ports));
    }

    @Test
    void managementPortMappingCannotRewriteAHostUrlOrAmbiguousIdentity() {
        for (String invalid : new String[] {"", "127.0.0.2=8030", "127.0.0.2:9010=0",
                "127.0.0.2:9010=65536", "127.0.0.2:0=8030", "127.0.0.2:9010=-1",
                "127.0.0.2:9010=http://other-host:8030", "http://127.0.0.2:9010=8030",
                "user@127.0.0.2:9010=8030", "127.0.0.2:9010/path=8030", "127.0.0.2:9010=8030=8031",
                "::1:9010=8030"}) {
            Assertions.assertThrows(IOException.class,
                    () -> LicenseFeCompatibility.managementPorts(new String[] {invalid}), invalid);
        }
        Assertions.assertThrows(IOException.class, () -> LicenseFeCompatibility.managementPorts(new String[] {
                "127.0.0.2:9010=8030", "127.0.0.2:9010=8130"}));
        Assertions.assertThrows(IOException.class, () -> LicenseFeCompatibility.managementPorts(new String[1025]));
    }

    private static Frontend member() {
        return new Frontend(FrontendNodeType.FOLLOWER, "fe-member", "127.0.0.2", 9010);
    }

    private static Map<String, Object> capability(String trust) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schema_version", 1);
        result.put("format_version", 1);
        result.put("module", "massdbLicenseV1");
        result.put("journal_opcodes", Arrays.asList(6200, 6201, 6202, 6203, 6204, 6205));
        result.put("fe_node_name", "fe-member");
        result.put("fe_host", "127.0.0.2");
        result.put("edit_log_port", 9010);
        result.put("process_uuid", 123456789L);
        result.put("package_sha256", PACKAGE);
        result.put("trust_sha256", trust);
        result.put("trust_ready", trust != null);
        return result;
    }
}
