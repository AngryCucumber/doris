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

package org.apache.doris.httpv2;

import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.net.ssl.SSLContext;

class HttpServerJettyIdentityTest {
    @Test
    void atomicallyReloadsRoleContextAndRestoresOrdinaryHttps() throws Exception {
        SSLContext ordinary = sslContext();
        SSLContext role = sslContext();
        SslContextFactory.Server contextFactory = new SslContextFactory.Server();
        contextFactory.setSslContext(ordinary);
        contextFactory.setNeedClientAuth(false);
        contextFactory.setWantClientAuth(false);
        contextFactory.start();
        try {
            HttpServer.JettyRoleTlsTarget target =
                    new HttpServer.JettyRoleTlsTarget(contextFactory);

            target.enableRoleIdentity(2, role);
            Assertions.assertSame(role, contextFactory.getSslContext());
            Assertions.assertTrue(contextFactory.getWantClientAuth());
            Assertions.assertFalse(contextFactory.getNeedClientAuth());
            Assertions.assertTrue(contextFactory.newSSLEngine().getWantClientAuth());
            Assertions.assertTrue(target.isRoleIdentityEnabled());
            Assertions.assertEquals(2, target.getGeneration());

            target.disableRoleIdentity();
            Assertions.assertSame(ordinary, contextFactory.getSslContext());
            Assertions.assertFalse(contextFactory.getWantClientAuth());
            Assertions.assertFalse(contextFactory.getNeedClientAuth());
            Assertions.assertFalse(contextFactory.newSSLEngine().getWantClientAuth());
            Assertions.assertFalse(target.isRoleIdentityEnabled());
            Assertions.assertEquals(0, target.getGeneration());
        } finally {
            contextFactory.stop();
        }
    }

    private static SSLContext sslContext() throws GeneralSecurityException {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, null, new SecureRandom());
        return context;
    }
}
