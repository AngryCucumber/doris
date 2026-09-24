// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.DdlException;
import org.apache.doris.common.jmockit.Deencapsulation;
import org.apache.doris.ha.BDBHA;
import org.apache.doris.ha.FrontendNodeType;
import org.apache.doris.metric.MetricRepo;
import org.apache.doris.persist.EditLog;
import org.apache.doris.resource.Tag;
import org.apache.doris.system.Backend;
import org.apache.doris.system.Frontend;
import org.apache.doris.system.SystemInfoService;
import org.apache.doris.system.SystemInfoService.HostInfo;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** Entry-point ordering tests complement the real serialized manager admission tests. */
class LicenseMembershipIntegrationTest {
    @Test
    void rejectedFrontendAdmissionRunsBeforeBdbAndMemberSideEffects() throws Exception {
        Env env = new Env(true);
        LicenseManager manager = Mockito.mock(LicenseManager.class);
        BDBHA ha = Mockito.mock(BDBHA.class);
        EditLog journal = Mockito.mock(EditLog.class);
        Deencapsulation.setField(env, "licenseManager", manager);
        Deencapsulation.setField(env, "haProtocol", ha);
        Deencapsulation.setField(env, "editLog", journal);
        Mockito.doThrow(new DdlException("LICENSE_FE_LIMIT_EXCEEDED")).when(manager)
                .runMembershipMutation(Mockito.eq(1), Mockito.eq(0), Mockito.any());
        Assertions.assertThrows(DdlException.class,
                () -> env.addFrontend(FrontendNodeType.FOLLOWER, "127.0.0.2", 9010));
        Assertions.assertTrue(env.getFrontends(null).isEmpty());
        Mockito.verifyNoInteractions(ha, journal);
    }

    @Test
    void frontendDropRetainsOriginalQuorumCheckAndFailedJournalKeepsRegistration() throws Exception {
        Env env = new Env(true);
        LicenseManager manager = inlineManager();
        BDBHA ha = Mockito.mock(BDBHA.class);
        EditLog journal = Mockito.mock(EditLog.class);
        Deencapsulation.setField(env, "licenseManager", manager);
        Deencapsulation.setField(env, "haProtocol", ha);
        Deencapsulation.setField(env, "editLog", journal);
        Deencapsulation.setField(env, "selfNode", new HostInfo("127.0.0.1", 9010));
        Frontend alive = new Frontend(FrontendNodeType.FOLLOWER, "follower", "127.0.0.2", 9010);
        alive.setIsAlive(true);
        env.replayAddFrontend(alive);
        Assertions.assertThrows(DdlException.class,
                () -> env.dropFrontend(FrontendNodeType.FOLLOWER, alive.getHost(), alive.getEditLogPort()));
        Mockito.verify(journal, Mockito.never()).logRemoveFrontend(Mockito.any());
        Assertions.assertEquals(1, env.getFrontends(null).size());
        alive.setIsAlive(false);
        Mockito.doThrow(new IllegalStateException("Journal acknowledgement lost"))
                .when(journal).logRemoveFrontend(alive);
        Assertions.assertThrows(IllegalStateException.class,
                () -> env.dropFrontend(FrontendNodeType.FOLLOWER, alive.getHost(), alive.getEditLogPort()));
        Assertions.assertEquals(1, env.getFrontends(null).size());
        Mockito.verify(ha, Mockito.never()).removeElectableNode(Mockito.anyString());
    }

    @Test
    void registeredIdentitiesIncludeOfflineObserverComputeAndSameHostMembers() {
        Env env = Mockito.mock(Env.class);
        SystemInfoService backends = new SystemInfoService();
        Frontend follower = new Frontend(FrontendNodeType.FOLLOWER, "one", "127.0.0.1", 9010);
        Frontend observer = new Frontend(FrontendNodeType.OBSERVER, "two", "127.0.0.1", 9011);
        Mockito.when(env.getFrontends(null)).thenReturn(Arrays.asList(follower, observer));
        Mockito.when(env.getClusterInfo()).thenReturn(backends);
        Backend storage = new Backend(1, "127.0.0.1", 9050);
        Backend compute = new Backend(2, "127.0.0.1", 9051);
        Map<String, String> tags = new HashMap<>(Tag.DEFAULT_BACKEND_TAG.toMap());
        tags.put(Tag.TYPE_ROLE, Tag.VALUE_COMPUTATION);
        compute.setTagMap(tags);
        backends.replayAddBackend(storage);
        backends.replayAddBackend(compute);
        LicenseManager.Membership offline = LicenseFeCompatibility.membership(env);
        Assertions.assertEquals(2, offline.feNodes);
        Assertions.assertEquals(2, offline.beNodes);
        Assertions.assertTrue(compute.isComputeNode());
        follower.setIsAlive(true);
        observer.setIsAlive(true);
        storage.setAlive(true);
        compute.setAlive(true);
        storage.setDecommissioned(true);
        Assertions.assertEquals(offline.version, LicenseFeCompatibility.membership(env).version);
        backends.replayAddBackend(compute);
        Assertions.assertEquals(2, LicenseFeCompatibility.membership(env).beNodes);
        backends.replayDropBackend(storage);
        backends.replayDropBackend(storage);
        Assertions.assertEquals(1, LicenseFeCompatibility.membership(env).beNodes);
    }

    @Test
    void backendBatchCapacityRejectsBeforeIdsJournalAndRegistration() throws Exception {
        Env env = Mockito.mock(Env.class);
        EditLog journal = Mockito.mock(EditLog.class);
        LicenseManager manager = Mockito.mock(LicenseManager.class);
        Mockito.when(env.getLicenseManager()).thenReturn(manager);
        Mockito.when(env.getEditLog()).thenReturn(journal);
        Mockito.doThrow(new DdlException("LICENSE_BE_LIMIT_EXCEEDED")).when(manager)
                .runMembershipMutation(Mockito.eq(0), Mockito.eq(2), Mockito.any());
        SystemInfoService backends = new SystemInfoService();
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            Assertions.assertThrows(DdlException.class, () -> backends.addBackends(Arrays.asList(
                    new HostInfo("127.0.0.1", 9050), new HostInfo("127.0.0.1", 9051)),
                    Tag.DEFAULT_BACKEND_TAG.toMap()));
        }
        Assertions.assertTrue(backends.getAllBackendIds(false).isEmpty());
        Mockito.verify(env, Mockito.never()).getNextId();
        Mockito.verifyNoInteractions(journal);
    }

    @Test
    void backendDropReleasesOnlyAfterJournalAndReplayIsIdempotent() throws Exception {
        Env env = Mockito.mock(Env.class);
        EditLog journal = Mockito.mock(EditLog.class);
        LicenseManager manager = inlineManager();
        Mockito.when(env.getLicenseManager()).thenReturn(manager);
        Mockito.when(env.getEditLog()).thenReturn(journal);
        SystemInfoService backends = new SystemInfoService();
        Backend member = new Backend(1, "127.0.0.1", 9050);
        backends.replayAddBackend(member);
        Mockito.doAnswer(invocation -> {
            Assertions.assertSame(member, backends.getBackend(1));
            throw new IllegalStateException("Journal acknowledgement lost");
        }).when(journal).logDropBackend(member);
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class);
                MockedStatic<MetricRepo> metrics = Mockito.mockStatic(MetricRepo.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            Assertions.assertThrows(IllegalStateException.class, () -> backends.dropBackend(1));
            Assertions.assertSame(member, backends.getBackend(1));
            Mockito.doAnswer(invocation -> {
                Assertions.assertSame(member, backends.getBackend(1));
                return null;
            }).when(journal).logDropBackend(member);
            backends.dropBackend(1);
            Assertions.assertNull(backends.getBackend(1));
            Assertions.assertThrows(DdlException.class, () -> backends.dropBackend(1));
            metrics.verify(MetricRepo::generateBackendsTabletMetrics, Mockito.times(1));
        }
        backends.replayDropBackend(member);
        Assertions.assertTrue(backends.getAllBackendIds(false).isEmpty());
    }

    @Test
    void queuedDropByIdCannotDeleteANewMemberAtTheSameAddress() throws Exception {
        Env env = Mockito.mock(Env.class);
        EditLog journal = Mockito.mock(EditLog.class);
        LicenseManager manager = Mockito.mock(LicenseManager.class);
        Mockito.when(env.getLicenseManager()).thenReturn(manager);
        Mockito.when(env.getEditLog()).thenReturn(journal);
        SystemInfoService backends = new SystemInfoService();
        Backend old = new Backend(1, "127.0.0.1", 9050);
        Backend replacement = new Backend(2, "127.0.0.1", 9050);
        backends.replayAddBackend(old);
        CountDownLatch queued = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Mockito.doAnswer(invocation -> {
            queued.countDown();
            Assertions.assertTrue(release.await(5, TimeUnit.SECONDS));
            LicenseManager.MembershipMutation mutation = invocation.getArgument(2);
            mutation.run();
            return null;
        }).when(manager).runMembershipMutation(Mockito.eq(0), Mockito.eq(0), Mockito.any());
        ExecutorService client = Executors.newSingleThreadExecutor();
        try {
            Future<String> dropped = client.submit(() -> {
                try (MockedStatic<Env> current = Mockito.mockStatic(Env.class);
                        MockedStatic<MetricRepo> metrics = Mockito.mockStatic(MetricRepo.class)) {
                    current.when(Env::getCurrentEnv).thenReturn(env);
                    try {
                        backends.dropBackend(1);
                        return "unexpected success";
                    } catch (DdlException e) {
                        return e.getDetailMessage();
                    }
                }
            });
            Assertions.assertTrue(queued.await(5, TimeUnit.SECONDS));
            backends.replayDropBackend(old);
            backends.replayAddBackend(replacement);
            release.countDown();
            Assertions.assertEquals("Backend[1] does not exist", dropped.get(5, TimeUnit.SECONDS));
            Assertions.assertSame(replacement, backends.getBackend(2));
            Mockito.verify(journal, Mockito.never()).logDropBackend(Mockito.any());
        } finally {
            release.countDown();
            client.shutdownNow();
        }
    }

    @Test
    void duplicateBackendBatchFailsBeforeAnyRegistration() throws Exception {
        Env env = Mockito.mock(Env.class);
        LicenseManager manager = inlineManager();
        Mockito.when(env.getLicenseManager()).thenReturn(manager);
        SystemInfoService backends = new SystemInfoService();
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            Assertions.assertThrows(DdlException.class, () -> backends.addBackends(Arrays.asList(
                    new HostInfo("127.0.0.1", 9050), new HostInfo("127.0.0.1", 9050)),
                    Tag.DEFAULT_BACKEND_TAG.toMap()));
        }
        Assertions.assertTrue(backends.getAllBackendIds(false).isEmpty());
        Mockito.verify(env, Mockito.never()).getNextId();
        Mockito.verify(env, Mockito.never()).getEditLog();
    }

    @Test
    void backendMidBatchJournalFailureRetainsExistingPartialRegistration() throws Exception {
        Env env = Mockito.mock(Env.class);
        LicenseManager manager = inlineManager();
        EditLog journal = Mockito.mock(EditLog.class);
        Mockito.when(env.getLicenseManager()).thenReturn(manager);
        Mockito.when(env.getEditLog()).thenReturn(journal);
        AtomicLong ids = new AtomicLong();
        Mockito.when(env.getNextId()).thenAnswer(invocation -> ids.incrementAndGet());
        AtomicInteger writes = new AtomicInteger();
        Mockito.doAnswer(invocation -> {
            if (writes.incrementAndGet() == 2) {
                throw new IllegalStateException("Second member journal failed");
            }
            return null;
        }).when(journal).logAddBackend(Mockito.any());
        SystemInfoService backends = new SystemInfoService();
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class);
                MockedStatic<MetricRepo> metrics = Mockito.mockStatic(MetricRepo.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            Assertions.assertThrows(IllegalStateException.class, () -> backends.addBackends(Arrays.asList(
                    new HostInfo("127.0.0.1", 9050), new HostInfo("127.0.0.1", 9051)),
                    Tag.DEFAULT_BACKEND_TAG.toMap()));
            metrics.verify(MetricRepo::generateBackendsTabletMetrics, Mockito.times(1));
        }
        Assertions.assertEquals(2, backends.getAllBackendIds(false).size());
        Assertions.assertEquals(2, writes.get());
    }

    @Test
    void recoveryNotifiesOnlyTheOwningEnvSnapshot() {
        Env first = new Env(true);
        Env second = new Env(true);
        Backend member = new Backend(11, "127.0.0.1", 9050);
        first.getClusterInfo().replayAddBackend(member);
        Assertions.assertEquals(1, first.getLicenseManager().getSnapshot().getRegisteredBe());
        Assertions.assertEquals(0, second.getLicenseManager().getSnapshot().getRegisteredBe());
        first.getClusterInfo().replayDropBackend(member);
        first.getClusterInfo().replayDropBackend(member);
        Assertions.assertEquals(0, first.getLicenseManager().getSnapshot().getRegisteredBe());
        Frontend observer = new Frontend(FrontendNodeType.OBSERVER, "observer", "127.0.0.1", 9010);
        second.replayAddFrontend(observer);
        Assertions.assertEquals(1, second.getLicenseManager().getSnapshot().getRegisteredFe());
        Assertions.assertEquals(0, first.getLicenseManager().getSnapshot().getRegisteredFe());
        second.replayDropFrontend(observer);
        second.replayDropFrontend(observer);
        Assertions.assertEquals(0, second.getLicenseManager().getSnapshot().getRegisteredFe());
    }

    private static LicenseManager inlineManager() throws DdlException {
        LicenseManager manager = Mockito.mock(LicenseManager.class);
        Mockito.doAnswer(invocation -> {
            LicenseManager.MembershipMutation action = invocation.getArgument(2);
            action.run();
            return null;
        }).when(manager).runMembershipMutation(Mockito.anyInt(), Mockito.anyInt(), Mockito.any());
        return manager;
    }
}
