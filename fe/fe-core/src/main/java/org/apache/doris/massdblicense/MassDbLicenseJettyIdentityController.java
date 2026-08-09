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

import org.apache.doris.common.util.MasterDaemon;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;

/**
 * Publishes the component-native identity to Jetty without making ordinary HTTPS depend on it.
 * The target retains the original HTTPS context and restores it whenever the role identity is
 * missing, expired, corrupt, rolled back, or cannot be installed.
 */
public final class MassDbLicenseJettyIdentityController extends MasterDaemon
        implements AutoCloseable {
    private static final Logger LOG = LogManager.getLogger(
            MassDbLicenseJettyIdentityController.class);
    private static final String UNAVAILABLE = "MASSDB_LICENSE_ROLE_TRANSPORT_UNAVAILABLE";

    /** Jetty-specific implementation atomically reloads new connections or restores HTTPS. */
    public interface ServerTlsTarget {
        void enableRoleIdentity(long generation, SSLContext sslContext) throws Exception;

        void disableRoleIdentity() throws Exception;
    }

    private final MassDbLicenseFeRoleIdentityProvider identityProvider;
    private final AtomicReference<AppliedIdentity> applied = new AtomicReference<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private ServerTlsTarget target;
    private boolean fallbackSelected;
    private String lastFailure;

    public MassDbLicenseJettyIdentityController(
            MassDbLicenseFeRoleIdentityProvider identityProvider, long intervalMillis) {
        super("massdb-license-jetty-identity", intervalMillis);
        if (intervalMillis <= 0) {
            throw new IllegalArgumentException("identity refresh interval must be positive");
        }
        this.identityProvider = Objects.requireNonNull(identityProvider, "identityProvider");
    }

    /** Binds exactly one running HTTPS connector and performs the first fail-closed refresh. */
    public synchronized void bind(ServerTlsTarget replacement, long nowEpochSecond) {
        if (closed.get() || target != null) {
            throw new IllegalStateException("MassDB License Jetty identity target already bound");
        }
        target = Objects.requireNonNull(replacement, "replacement");
        fallbackSelected = false;
        refreshNow(nowEpochSecond);
    }

    /** Starts component-internal polling after Jetty has been bound. */
    public synchronized void startPolling() {
        if (closed.get() || target == null) {
            throw new IllegalStateException("MassDB License Jetty identity target not bound");
        }
        start();
    }

    @Override
    protected void runAfterCatalogReady() {
        refreshNow(Instant.now().getEpochSecond());
    }

    synchronized void refreshNow(long nowEpochSecond) {
        if (closed.get() || target == null) {
            return;
        }
        try {
            MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot =
                    identityProvider.current(nowEpochSecond);
            AppliedIdentity current = applied.get();
            if (current == null || current.generation != snapshot.generation) {
                target.enableRoleIdentity(snapshot.generation, snapshot.clientSslContext);
            }
            applied.set(new AppliedIdentity(snapshot.generation));
            fallbackSelected = false;
            if (lastFailure != null) {
                LOG.info("MassDB License Jetty角色身份已恢复 generation={}",
                        snapshot.generation);
                lastFailure = null;
            }
        } catch (Exception error) {
            applied.set(null);
            String failure = failureCode(error);
            if (!fallbackSelected) {
                try {
                    target.disableRoleIdentity();
                    fallbackSelected = true;
                } catch (Exception fallbackError) {
                    failure = failure + ":HTTPS_FALLBACK_FAILED";
                }
            }
            if (!failure.equals(lastFailure)) {
                LOG.warn("MassDB License Jetty角色身份不可用，普通HTTPS保持回退 code={}",
                        failure);
                lastFailure = failure;
            }
        }
    }

    /**
     * Revalidates the request chain against the currently signed trust bundle. This closes the
     * keep-alive window where a connection authenticated by a removed root survives Jetty reload.
     */
    public MassDbLicenseSpiffeIdentity.Identity requireAllowedClient(
            X509Certificate[] chain, long nowEpochSecond) {
        return currentAppliedSnapshot(nowEpochSecond).requireAllowedClient(
                chain, nowEpochSecond);
    }

    public MassDbLicenseManagementIdentity.Principal requireAllowedManagementClient(
            X509Certificate[] chain, long nowEpochSecond) {
        return currentAppliedSnapshot(nowEpochSecond).requireAllowedManagementClient(
                chain, nowEpochSecond);
    }

    /** Proves that the currently applied FE identity belongs to this bootstrap deployment. */
    public String requireLocalFeIdentity(String deploymentUuid, long nowEpochSecond) {
        MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot =
                currentAppliedSnapshot(nowEpochSecond);
        MassDbLicenseSpiffeIdentity.Identity identity = snapshot.identity;
        if (!"massdb-sql".equals(identity.component) || !"fe".equals(identity.role)
                || !identity.deploymentUuid.equals(deploymentUuid)) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_BOOTSTRAP_IDENTITY_MISMATCH",
                    "当前Jetty FE身份与bootstrap deployment UUID不匹配");
        }
        return identity.nodeUuid;
    }

    private MassDbLicenseFeRoleIdentityProvider.Snapshot currentAppliedSnapshot(
            long nowEpochSecond) {
        if (closed.get() || target == null) {
            failUnavailable();
        }
        final MassDbLicenseFeRoleIdentityProvider.Snapshot snapshot;
        try {
            snapshot = identityProvider.current(nowEpochSecond);
        } catch (MassDbLicenseException error) {
            failUnavailable();
            return null;
        }
        AppliedIdentity current = applied.get();
        if (current == null || current.generation != snapshot.generation) {
            failUnavailable();
        }
        return snapshot;
    }

    public boolean isAvailable() {
        return !closed.get() && target != null && applied.get() != null;
    }

    long appliedGeneration() {
        AppliedIdentity current = applied.get();
        return current == null ? 0 : current.generation;
    }

    @Override
    public synchronized void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        exit();
        applied.set(null);
        if (target != null && !fallbackSelected) {
            try {
                target.disableRoleIdentity();
                fallbackSelected = true;
            } catch (Exception error) {
                LOG.warn("关闭MassDB License Jetty角色身份时无法恢复普通HTTPS");
            }
        }
    }

    private static String failureCode(Throwable error) {
        return error instanceof MassDbLicenseException
                ? ((MassDbLicenseException) error).getCode()
                : error.getClass().getSimpleName();
    }

    private static void failUnavailable() {
        throw new MassDbLicenseException(UNAVAILABLE, "Jetty角色身份尚未安全应用");
    }

    private static final class AppliedIdentity {
        private final long generation;

        private AppliedIdentity(long generation) {
            this.generation = generation;
        }
    }
}
