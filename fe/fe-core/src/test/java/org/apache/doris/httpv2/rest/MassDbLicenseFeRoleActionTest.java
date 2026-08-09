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
import org.apache.doris.massdblicense.MassDbLicenseJettyIdentityController;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

class MassDbLicenseFeRoleActionTest {
    @Test
    void rejectsUnavailableIdentityAndMissingClientCertificateBeforeReadingBody() {
        boolean previous = Config.massdb_license_role_mtls_enabled;
        Config.massdb_license_role_mtls_enabled = true;
        try {
            MassDbLicenseFeRoleAction action = new MassDbLicenseFeRoleAction();
            HttpServletRequest plain = Mockito.mock(HttpServletRequest.class);
            Mockito.when(plain.isSecure()).thenReturn(false);
            ResponseEntity<?> plainResult = (ResponseEntity<?>) action.exchange(plain);
            Assertions.assertEquals(HttpStatus.UPGRADE_REQUIRED, plainResult.getStatusCode());
            Mockito.verify(plain, Mockito.never()).getInputStream();

            Env env = Mockito.mock(Env.class);
            MassDbLicenseJettyIdentityController controller =
                    Mockito.mock(MassDbLicenseJettyIdentityController.class);
            Mockito.when(env.getMassDbLicenseJettyIdentityController()).thenReturn(controller);
            try (MockedStatic<Env> servingEnv = Mockito.mockStatic(Env.class)) {
                servingEnv.when(Env::getServingEnv).thenReturn(env);

                HttpServletRequest unavailable = Mockito.mock(HttpServletRequest.class);
                Mockito.when(unavailable.isSecure()).thenReturn(true);
                ResponseEntity<?> unavailableResult =
                        (ResponseEntity<?>) action.exchange(unavailable);
                Assertions.assertEquals(HttpStatus.SERVICE_UNAVAILABLE,
                        unavailableResult.getStatusCode());
                Assertions.assertEquals("MASSDB_LICENSE_ROLE_TRANSPORT_UNAVAILABLE",
                        ((MassDbLicenseFeRoleAction.ErrorBody)
                                unavailableResult.getBody()).code);
                Mockito.verify(unavailable, Mockito.never()).getInputStream();

                Mockito.when(controller.isAvailable()).thenReturn(true);
                HttpServletRequest noCertificate = Mockito.mock(HttpServletRequest.class);
                Mockito.when(noCertificate.isSecure()).thenReturn(true);
                ResponseEntity<?> certificateResult =
                        (ResponseEntity<?>) action.exchange(noCertificate);
                Assertions.assertEquals(HttpStatus.UNAUTHORIZED,
                        certificateResult.getStatusCode());
                Assertions.assertEquals("MASSDB_LICENSE_MTLS_REQUIRED",
                        ((MassDbLicenseFeRoleAction.ErrorBody)
                                certificateResult.getBody()).code);
                Mockito.verify(noCertificate, Mockito.never()).getInputStream();
            }
        } catch (java.io.IOException impossible) {
            throw new AssertionError(impossible);
        } finally {
            Config.massdb_license_role_mtls_enabled = previous;
        }
    }

    @Test
    void disabledRoleChannelDoesNotExposeInternalProtocol() {
        boolean previous = Config.massdb_license_role_mtls_enabled;
        Config.massdb_license_role_mtls_enabled = false;
        try {
            HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
            ResponseEntity<?> result = (ResponseEntity<?>)
                    new MassDbLicenseFeRoleAction().exchange(request);
            Assertions.assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
            Mockito.verifyNoInteractions(request);
        } finally {
            Config.massdb_license_role_mtls_enabled = previous;
        }
    }
}
