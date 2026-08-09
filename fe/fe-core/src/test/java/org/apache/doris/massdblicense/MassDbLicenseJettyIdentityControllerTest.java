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

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import javax.net.ssl.SSLContext;

class MassDbLicenseJettyIdentityControllerTest {
    private static final long NOW = 1_767_225_600L;
    private static final String DEPLOYMENT = "00000000-0000-4000-8000-000000000301";
    private static final String NODE = "00000000-0000-4000-8000-000000000302";

    @Test
    void rotatesAndRestoresOrdinaryHttpsWhenIdentityBecomesUnavailable() {
        MutableProvider provider = new MutableProvider(snapshot(1));
        FakeTarget target = new FakeTarget();
        MassDbLicenseJettyIdentityController controller =
                new MassDbLicenseJettyIdentityController(provider, 1_000);

        controller.bind(target, NOW);
        Assertions.assertTrue(controller.isAvailable());
        Assertions.assertEquals(1, controller.appliedGeneration());
        Assertions.assertEquals(1, target.generation);

        provider.replace(snapshot(2));
        controller.refreshNow(NOW);
        Assertions.assertEquals(2, controller.appliedGeneration());
        Assertions.assertEquals(2, target.generation);

        provider.fail = true;
        controller.refreshNow(NOW);
        Assertions.assertFalse(controller.isAvailable());
        Assertions.assertTrue(target.ordinaryHttpsSelected);
        Assertions.assertEquals(1, target.disableCount);

        provider.fail = false;
        provider.replace(snapshot(3));
        controller.refreshNow(NOW);
        Assertions.assertTrue(controller.isAvailable());
        Assertions.assertEquals(3, target.generation);
        controller.close();
        Assertions.assertTrue(target.ordinaryHttpsSelected);
    }

    @Test
    void rejectsNewGenerationUntilJettyReloadHasSucceeded() {
        MutableProvider provider = new MutableProvider(snapshot(1));
        FakeTarget target = new FakeTarget();
        MassDbLicenseJettyIdentityController controller =
                new MassDbLicenseJettyIdentityController(provider, 1_000);
        controller.bind(target, NOW);

        provider.replace(snapshot(2));
        MassDbLicenseException notApplied = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> controller.requireAllowedClient(new X509Certificate[0], NOW));
        Assertions.assertEquals("MASSDB_LICENSE_ROLE_TRANSPORT_UNAVAILABLE",
                notApplied.getCode());

        target.failNextEnable = true;
        controller.refreshNow(NOW);
        Assertions.assertFalse(controller.isAvailable());
        Assertions.assertTrue(target.ordinaryHttpsSelected);

        controller.refreshNow(NOW);
        Assertions.assertTrue(controller.isAvailable());
        Assertions.assertEquals(2, controller.appliedGeneration());
        controller.close();
    }

    private static MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot(long generation) {
        MassDbLicenseSpiffeIdentity.Identity identity =
                MassDbLicenseSpiffeIdentity.parseUnique(Collections.singletonList(
                        "spiffe://massdb.internal/license/component/massdb-sql/"
                                + DEPLOYMENT + "/fe/" + NODE));
        return new MassDbLicenseFeRoleIdentityProvider.Snapshot(
                generation, sslContext(), identity, NOW - 60, NOW + 600);
    }

    private static SSLContext sslContext() {
        try {
            return SSLContext.getDefault();
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException(error);
        }
    }

    private static final class MutableProvider
            implements MassDbLicenseFeRoleIdentityProvider {
        private MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot;
        private boolean fail;

        private MutableProvider(MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot) {
            this.snapshot = snapshot;
        }

        private void replace(MassDbLicenseFeRoleIdentityProvider.Snapshot replacement) {
            snapshot = replacement;
        }

        @Override
        public MassDbLicenseFeRoleIdentityProvider.Snapshot current(long nowEpochSecond) {
            if (fail) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_ROLE_IDENTITY_STORE_CORRUPT", "test corruption");
            }
            snapshot.requireUsable(nowEpochSecond);
            return snapshot;
        }
    }

    private static final class FakeTarget
            implements MassDbLicenseJettyIdentityController.ServerTlsTarget {
        private long generation;
        private int disableCount;
        private boolean ordinaryHttpsSelected = true;
        private boolean failNextEnable;

        @Override
        public void enableRoleIdentity(long replacementGeneration, SSLContext sslContext)
                throws Exception {
            if (failNextEnable) {
                failNextEnable = false;
                throw new Exception("test reload failure");
            }
            generation = replacementGeneration;
            ordinaryHttpsSelected = false;
        }

        @Override
        public void disableRoleIdentity() {
            generation = 0;
            disableCount++;
            ordinaryHttpsSelected = true;
        }
    }
}
