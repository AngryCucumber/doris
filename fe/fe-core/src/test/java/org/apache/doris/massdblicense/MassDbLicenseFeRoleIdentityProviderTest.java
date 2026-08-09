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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLContext;

class MassDbLicenseFeRoleIdentityProviderTest {
    private static final long NOW = 1_767_225_600L;
    private static final String DEPLOYMENT = "00000000-0000-4000-8000-000000000001";
    private static final String NODE = "00000000-0000-4000-8000-000000000002";

    @TempDir
    Path temporaryDirectory;

    @Test
    void publishesStrictlyIncreasingGenerationAndFailsClosedAfterClose() {
        MassDbLicenseFeRoleIdentityProvider.Rotating provider =
                new MassDbLicenseFeRoleIdentityProvider.Rotating(snapshot(1, NOW + 60));
        Assertions.assertEquals(1, provider.current(NOW).generation);

        provider.publish(snapshot(2, NOW + 120));
        Assertions.assertEquals(2, provider.current(NOW).generation);

        MassDbLicenseException rollback = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> provider.publish(snapshot(2, NOW + 180)));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_GENERATION_ROLLBACK",
                rollback.getCode());

        provider.close();
        MassDbLicenseException closed = Assertions.assertThrows(
                MassDbLicenseException.class, () -> provider.current(NOW));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_UNAVAILABLE", closed.getCode());
    }

    @Test
    void rejectsExpiredOrNotYetValidIdentityBeforeOpeningConnection() {
        MassDbLicenseFeRoleIdentityProvider.Rotating expired =
                new MassDbLicenseFeRoleIdentityProvider.Rotating(snapshot(1, NOW));
        MassDbLicenseException expiredError = Assertions.assertThrows(
                MassDbLicenseException.class, () -> expired.current(NOW));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_EXPIRED",
                expiredError.getCode());

        MassDbLicenseFeRoleIdentityProvider.Snapshot future =
                new MassDbLicenseFeRoleIdentityProvider.Snapshot(
                        1, sslContext(), identity(), NOW + 1, NOW + 60);
        MassDbLicenseFeRoleIdentityProvider.Rotating notYetValid =
                new MassDbLicenseFeRoleIdentityProvider.Rotating(future);
        MassDbLicenseException futureError = Assertions.assertThrows(
                MassDbLicenseException.class, () -> notYetValid.current(NOW));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_NOT_YET_VALID",
                futureError.getCode());
    }

    @Test
    void roleExchangeUsesThePublishedGenerationAsOneImmutableRequestSnapshot()
            throws Exception {
        MassDbLicenseLocalSnapshotStore store = new MassDbLicenseLocalSnapshotStore(
                temporaryDirectory.resolve("role"));
        MassDbLicenseState state = MassDbLicenseState.empty().bootstrap(true, repeat('a'));
        String deploymentUuid = state.getLicenseControlDeploymentUuid();
        MassDbLicenseSpiffeIdentity.Identity roleIdentity = identity(
                deploymentUuid, store.getNodeUuid());
        MassDbLicenseFeRoleIdentityProvider.Rotating provider =
                new MassDbLicenseFeRoleIdentityProvider.Rotating(
                        snapshot(1, roleIdentity, NOW + 60));
        AtomicLong observedGeneration = new AtomicLong();
        MassDbLicenseManager manager = new MassDbLicenseManager(state, ignored -> { });
        manager.transition(current -> current.advanceMaxSeenWallClock(NOW));
        MassDbLicenseFeRoleClient roleClient = new MassDbLicenseFeRoleClient(
                manager,
                new MassDbLicenseImportCore(1, roots()), store,
                new MassDbLicenseEnforcementCore(),
                new MassDbLicenseFeRoleClient.EndpointProvider() {
                    @Override
                    public String masterHost() {
                        return "leader.example";
                    }

                    @Override
                    public int httpsPort() {
                        return 8050;
                    }
                },
                new MassDbLicenseFeRoleClient.ExchangeClient() {
                    @Override
                    public MassDbLicenseFeRoleProtocol.ExchangeResponse exchange(
                            String host, int port,
                            MassDbLicenseFeRoleProtocol.ExchangeRequest request,
                            MassDbLicenseFeRoleIdentityProvider.Snapshot requestIdentity) {
                        observedGeneration.set(requestIdentity.generation);
                        Assertions.assertSame(requestIdentity.clientSslContext,
                                provider.current(NOW).clientSslContext);
                        return new MassDbLicenseFeRoleProtocol.ExchangeResponse(
                                deploymentUuid, NOW, null,
                                MassDbLicenseFeRoleProtocol.ControlPlaneSync.from(
                                        manager.snapshot(), request.status.reportSequence, NOW),
                                Collections.emptyList(),
                                Collections.emptyList());
                    }
                }, provider, 1_000);

        Assertions.assertEquals(MassDbLicenseFeRoleClient.Outcome.EXCHANGED,
                roleClient.cycle(NOW));
        Assertions.assertEquals(1, observedGeneration.get());

        provider.publish(snapshot(2, roleIdentity, NOW + 120));
        Assertions.assertEquals(MassDbLicenseFeRoleClient.Outcome.EXCHANGED,
                roleClient.cycle(NOW));
        Assertions.assertEquals(2, observedGeneration.get());
    }

    @Test
    void storeBackedProviderReloadsAtomicallyAndNeverFallsBackAfterCorruption() {
        FakeActiveIdentitySource source = new FakeActiveIdentitySource(
                "revision-1", snapshot(1, NOW + 60));
        MassDbLicenseFeRoleIdentityProvider.StoreBacked provider =
                new MassDbLicenseFeRoleIdentityProvider.StoreBacked(source, NOW);
        Assertions.assertEquals(1, provider.current(NOW).generation);

        source.replace("revision-2", snapshot(2, NOW + 120));
        Assertions.assertEquals(2, provider.current(NOW).generation);

        source.corrupt("revision-corrupt");
        MassDbLicenseException corrupt = Assertions.assertThrows(
                MassDbLicenseException.class, () -> provider.current(NOW));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT",
                corrupt.getCode());

        source.replace("revision-3", snapshot(3, NOW + 180));
        Assertions.assertEquals(3, provider.current(NOW).generation);

        source.replace("revision-rollback", snapshot(2, NOW + 180));
        MassDbLicenseException rollback = Assertions.assertThrows(
                MassDbLicenseException.class, () -> provider.current(NOW));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_GENERATION_ROLLBACK",
                rollback.getCode());

        provider.close();
        Assertions.assertTrue(source.closed.get());
        MassDbLicenseException closed = Assertions.assertThrows(
                MassDbLicenseException.class, () -> provider.current(NOW));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_UNAVAILABLE", closed.getCode());
    }

    @Test
    void deferredStoreProviderDoesNotBlockProcessConstructionForExpiredIdentity() {
        FakeActiveIdentitySource source = new FakeActiveIdentitySource(
                "revision-expired", snapshot(1, NOW));

        MassDbLicenseFeRoleIdentityProvider.StoreBacked provider =
                new MassDbLicenseFeRoleIdentityProvider.StoreBacked(source);

        MassDbLicenseException expired = Assertions.assertThrows(
                MassDbLicenseException.class, () -> provider.current(NOW));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_IDENTITY_EXPIRED", expired.getCode());
        source.replace("revision-renewed", snapshot(2, NOW + 120));
        Assertions.assertEquals(2, provider.current(NOW).generation);
        provider.close();
    }

    private static MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot(
            long generation, long notAfter) {
        return snapshot(generation, identity(), notAfter);
    }

    private static MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot(
            long generation, MassDbLicenseSpiffeIdentity.Identity identity, long notAfter) {
        return new MassDbLicenseFeRoleIdentityProvider.Snapshot(
                generation, sslContext(), identity, NOW - 60, notAfter);
    }

    private static MassDbLicenseSpiffeIdentity.Identity identity() {
        return identity(DEPLOYMENT, NODE);
    }

    private static MassDbLicenseSpiffeIdentity.Identity identity(
            String deploymentUuid, String nodeUuid) {
        return MassDbLicenseSpiffeIdentity.parseUnique(Collections.singletonList(
                "spiffe://massdb.internal/license/component/massdb-sql/"
                        + deploymentUuid + "/fe/" + nodeUuid));
    }

    private static SSLContext sslContext() {
        try {
            return SSLContext.getDefault();
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException(error);
        }
    }

    private static Map<String, PublicKey> roots() {
        return Collections.singletonMap("massdb-test-root-1",
                MassDbLicenseProtocolV1.parsePublicKeyPem(
                        MassDbLicenseProtocolV1Test.decode(
                                MassDbLicenseProtocolV1Test.ROOT_PUBLIC)));
    }

    private static String repeat(char value) {
        return String.join("", Collections.nCopies(64, String.valueOf(value)));
    }

    private static final class FakeActiveIdentitySource implements
            MassDbLicenseFeRoleIdentityProvider.StoreBacked.ActiveIdentitySource {
        private String revision;
        private MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot;
        private boolean corrupt;
        private final AtomicBoolean closed = new AtomicBoolean(false);

        private FakeActiveIdentitySource(String revision,
                MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot) {
            this.revision = revision;
            this.snapshot = snapshot;
        }

        private void replace(String newRevision,
                MassDbLicenseFeRoleIdentityProvider.Snapshot replacement) {
            revision = newRevision;
            snapshot = replacement;
            corrupt = false;
        }

        private void corrupt(String newRevision) {
            revision = newRevision;
            corrupt = true;
        }

        @Override
        public String activeRevision() {
            return revision;
        }

        @Override
        public MassDbLicenseFeRoleIdentityProvider.Snapshot loadActive(long nowEpochSecond) {
            if (corrupt) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "test corruption");
            }
            return snapshot;
        }

        @Override
        public void close() {
            closed.set(true);
        }
    }
}
