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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;

/**
 * Supplies one immutable client identity and trust context for a complete FE role exchange.
 *
 * <p>The provider is deliberately independent from a concrete certificate delivery mechanism.
 * A production component-native issuer/import implementation can publish a new generation after
 * it has validated and durably installed a replacement. The current request keeps using the
 * snapshot it acquired before the connection was opened, avoiding mixed identity/TLS generations.
 */
public interface MassDbLicenseFeRoleIdentityProvider extends AutoCloseable {
    Snapshot current(long nowEpochSecond);

    @Override
    default void close() {
    }

    /** Immutable identity material used by exactly one role exchange. */
    final class Snapshot {
        final long generation;
        final SSLContext clientSslContext;
        final MassDbLicenseSpiffeIdentity.Identity identity;
        final long notBeforeEpochSecond;
        final long notAfterEpochSecond;
        final Set<String> revokedSpiffeIds;
        final List<X509Certificate> trustRoots;

        public Snapshot(long generation, SSLContext clientSslContext,
                MassDbLicenseSpiffeIdentity.Identity identity,
                long notBeforeEpochSecond, long notAfterEpochSecond) {
            this(generation, clientSslContext, identity,
                    notBeforeEpochSecond, notAfterEpochSecond,
                    Collections.emptySet(), Collections.emptyList());
        }

        public Snapshot(long generation, SSLContext clientSslContext,
                MassDbLicenseSpiffeIdentity.Identity identity,
                long notBeforeEpochSecond, long notAfterEpochSecond,
                Set<String> revokedSpiffeIds) {
            this(generation, clientSslContext, identity,
                    notBeforeEpochSecond, notAfterEpochSecond,
                    revokedSpiffeIds, Collections.emptyList());
        }

        public Snapshot(long generation, SSLContext clientSslContext,
                MassDbLicenseSpiffeIdentity.Identity identity,
                long notBeforeEpochSecond, long notAfterEpochSecond,
                Set<String> revokedSpiffeIds, List<X509Certificate> trustRoots) {
            if (generation <= 0 || notBeforeEpochSecond < 0
                    || notAfterEpochSecond <= notBeforeEpochSecond
                    || revokedSpiffeIds == null || trustRoots == null) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_ROLE_IDENTITY_INVALID",
                        "FE角色身份generation或有效期无效");
            }
            this.generation = generation;
            this.clientSslContext = Objects.requireNonNull(
                    clientSslContext, "clientSslContext");
            this.identity = Objects.requireNonNull(identity, "identity");
            this.notBeforeEpochSecond = notBeforeEpochSecond;
            this.notAfterEpochSecond = notAfterEpochSecond;
            Set<String> validatedRevocations = new HashSet<>();
            for (String revoked : revokedSpiffeIds) {
                MassDbLicenseManagementIdentity.validateKnownIdentity(revoked);
                if (!validatedRevocations.add(revoked)) {
                    throw new MassDbLicenseException(
                            "MASSDB_LICENSE_ROLE_IDENTITY_INVALID",
                            "FE角色身份吊销表包含重复项");
                }
            }
            this.revokedSpiffeIds = Collections.unmodifiableSet(validatedRevocations);
            List<X509Certificate> validatedRoots = new ArrayList<>(trustRoots.size());
            for (X509Certificate root : trustRoots) {
                if (root == null || root.getBasicConstraints() < 0) {
                    throw new MassDbLicenseException(
                            "MASSDB_LICENSE_ROLE_IDENTITY_INVALID",
                            "FE角色身份trust bundle包含非CA证书");
                }
                validatedRoots.add(root);
            }
            this.trustRoots = Collections.unmodifiableList(validatedRoots);
        }

        void requireUsable(long nowEpochSecond) {
            if (nowEpochSecond < notBeforeEpochSecond) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_ROLE_IDENTITY_NOT_YET_VALID",
                        "FE角色身份尚未生效");
            }
            if (nowEpochSecond >= notAfterEpochSecond) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_ROLE_IDENTITY_EXPIRED",
                        "FE角色身份已过期");
            }
        }

        void requireAllowedServer(X509Certificate certificate, String deploymentUuid) {
            MassDbLicenseSpiffeIdentity.Identity server =
                    MassDbLicenseSpiffeIdentity.parsePeerCertificate(certificate);
            requireAllowedFeIdentity(server, deploymentUuid, "Leader");
        }

        MassDbLicenseSpiffeIdentity.Identity requireAllowedClient(
                X509Certificate[] chain, long nowEpochSecond) {
            if (trustRoots.isEmpty()) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_ROLE_IDENTITY_INVALID",
                        "服务端角色身份缺少当前签名trust bundle");
            }
            MassDbLicenseIdentityKeyMaterial.validatePeerChain(
                    chain, trustRoots, nowEpochSecond);
            MassDbLicenseSpiffeIdentity.Identity client =
                    MassDbLicenseSpiffeIdentity.parsePeerCertificate(chain[0]);
            requireAllowedFeIdentity(client, identity.deploymentUuid, "客户端");
            return client;
        }

        MassDbLicenseManagementIdentity.Principal requireAllowedManagementClient(
                X509Certificate[] chain, long nowEpochSecond) {
            if (trustRoots.isEmpty()) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_ROLE_IDENTITY_INVALID",
                        "服务端管理身份缺少当前签名trust bundle");
            }
            MassDbLicenseIdentityKeyMaterial.validateManagementPeerChain(
                    chain, trustRoots, nowEpochSecond);
            String raw = MassDbLicenseSpiffeIdentity.requireUniqueUriSan(chain[0]);
            MassDbLicenseManagementIdentity.Principal client =
                    MassDbLicenseManagementIdentity.parse(raw);
            if (revokedSpiffeIds.contains(raw)) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_ROLE_IDENTITY_REVOKED",
                        "管理工作负载身份已被签名吊销表撤销");
            }
            return client;
        }

        private void requireAllowedFeIdentity(MassDbLicenseSpiffeIdentity.Identity peer,
                String deploymentUuid, String label) {
            if (!"massdb-sql".equals(peer.component)
                    || !"fe".equals(peer.role)
                    || !deploymentUuid.equals(peer.deploymentUuid)) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH",
                        label + "证书URI SAN与当前MassDB SQL部署不匹配");
            }
            if (revokedSpiffeIds.contains(spiffeId(peer))) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_ROLE_IDENTITY_REVOKED",
                        label + "工作负载身份已被签名吊销表撤销");
            }
        }

        private static String spiffeId(MassDbLicenseSpiffeIdentity.Identity value) {
            return "spiffe://" + MassDbLicenseSpiffeIdentity.TRUST_DOMAIN
                    + "/license/component/" + value.component + "/"
                    + value.deploymentUuid + "/" + value.role + "/" + value.nodeUuid;
        }
    }

    /**
     * Atomic publication boundary shared by development stores and the future component-native
     * enrollment source. Generation rollback and replacement after close are both rejected.
     */
    final class Rotating implements MassDbLicenseFeRoleIdentityProvider {
        private final AtomicReference<Snapshot> snapshot = new AtomicReference<>();
        private final AtomicBoolean closed = new AtomicBoolean(false);

        public Rotating(Snapshot initial) {
            snapshot.set(Objects.requireNonNull(initial, "initial"));
        }

        public synchronized void publish(Snapshot replacement) {
            Objects.requireNonNull(replacement, "replacement");
            if (closed.get()) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_UNAVAILABLE",
                        "FE角色身份provider已关闭");
            }
            Snapshot existing = snapshot.get();
            if (replacement.generation <= existing.generation) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_GENERATION_ROLLBACK",
                        "FE角色身份generation必须严格递增");
            }
            snapshot.set(replacement);
        }

        @Override
        public Snapshot current(long nowEpochSecond) {
            if (closed.get()) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_UNAVAILABLE",
                        "FE角色身份provider已关闭");
            }
            Snapshot current = snapshot.get();
            if (current == null) {
                fail("MASSDB_LICENSE_ROLE_IDENTITY_UNAVAILABLE",
                        "FE角色身份尚未就绪");
            }
            current.requireUsable(nowEpochSecond);
            return current;
        }

        @Override
        public synchronized void close() {
            closed.set(true);
            snapshot.set(null);
        }

        private static void fail(String code, String message) {
            throw new MassDbLicenseException(code, message);
        }
    }

    /**
     * Reloads an atomically selected component-native identity before each new exchange. A broken
     * or rolled-back pointer fails the new request closed; the previously loaded snapshot is never
     * used as a silent fallback.
     */
    final class StoreBacked implements MassDbLicenseFeRoleIdentityProvider {
        private static final long MAINTENANCE_INTERVAL_SECONDS = 60 * 60;
        private static final long MAINTENANCE_RETRY_SECONDS = 60;

        interface ActiveIdentitySource extends AutoCloseable {
            String activeRevision();

            Snapshot loadActive(long nowEpochSecond);

            default void cleanupRetired(long nowEpochSecond) {
            }

            @Override
            void close();
        }

        private final ActiveIdentitySource source;
        private Rotating rotating;
        private String activeRevision;
        private long activeGeneration;
        private long nextMaintenanceAt;
        private final AtomicBoolean closed = new AtomicBoolean(false);

        StoreBacked(ActiveIdentitySource source) {
            this.source = Objects.requireNonNull(source, "source");
        }

        StoreBacked(ActiveIdentitySource source, long nowEpochSecond) {
            this(source);
            Loaded loaded = loadCoherently(nowEpochSecond);
            this.rotating = new Rotating(loaded.snapshot);
            this.activeRevision = loaded.revision;
            this.activeGeneration = loaded.snapshot.generation;
        }

        static StoreBacked open(MassDbLicenseIdentityStore store, long nowEpochSecond) {
            Objects.requireNonNull(store, "store");
            return new StoreBacked(new ActiveIdentitySource() {
                @Override
                public String activeRevision() {
                    return store.activeRevision();
                }

                @Override
                public Snapshot loadActive(long now) {
                    return store.loadActive(now);
                }

                @Override
                public void cleanupRetired(long now) {
                    store.cleanupRetired(now);
                }

                @Override
                public void close() {
                    store.close();
                }
            }, nowEpochSecond);
        }

        static StoreBacked openDeferred(MassDbLicenseIdentityStore store) {
            Objects.requireNonNull(store, "store");
            return new StoreBacked(new ActiveIdentitySource() {
                @Override
                public String activeRevision() {
                    return store.activeRevision();
                }

                @Override
                public Snapshot loadActive(long now) {
                    return store.loadActive(now);
                }

                @Override
                public void cleanupRetired(long now) {
                    store.cleanupRetired(now);
                }

                @Override
                public void close() {
                    store.close();
                }
            });
        }

        @Override
        public synchronized Snapshot current(long nowEpochSecond) {
            requireOpen();
            maintainBestEffort(nowEpochSecond);
            if (rotating == null) {
                Loaded initial = loadCoherently(nowEpochSecond);
                rotating = new Rotating(initial.snapshot);
                activeRevision = initial.revision;
                activeGeneration = initial.snapshot.generation;
                return rotating.current(nowEpochSecond);
            }
            String observed = source.activeRevision();
            if (!observed.equals(activeRevision)) {
                Loaded replacement = loadCoherently(nowEpochSecond);
                if (replacement.snapshot.generation <= activeGeneration) {
                    throw new MassDbLicenseException(
                            "MASSDB_LICENSE_ROLE_IDENTITY_GENERATION_ROLLBACK",
                            "身份库active pointer不能切换到相同或更低generation");
                }
                rotating.publish(replacement.snapshot);
                activeRevision = replacement.revision;
                activeGeneration = replacement.snapshot.generation;
            }
            return rotating.current(nowEpochSecond);
        }

        @Override
        public synchronized void close() {
            if (closed.compareAndSet(false, true)) {
                if (rotating != null) {
                    rotating.close();
                    rotating = null;
                }
                source.close();
                activeRevision = null;
                activeGeneration = 0;
                nextMaintenanceAt = 0;
            }
        }

        private void maintainBestEffort(long nowEpochSecond) {
            if (nowEpochSecond < nextMaintenanceAt) {
                return;
            }
            try {
                source.cleanupRetired(nowEpochSecond);
                nextMaintenanceAt = saturatedAdd(
                        nowEpochSecond, MAINTENANCE_INTERVAL_SECONDS);
            } catch (MassDbLicenseException ignored) {
                // Cleanup never changes the selected active pointer. Identity service remains
                // fail-closed independently and retries bounded maintenance after one minute.
                nextMaintenanceAt = saturatedAdd(
                        nowEpochSecond, MAINTENANCE_RETRY_SECONDS);
            }
        }

        private static long saturatedAdd(long left, long right) {
            return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
        }

        private Loaded loadCoherently(long nowEpochSecond) {
            String before = source.activeRevision();
            Snapshot snapshot = source.loadActive(nowEpochSecond);
            String after = source.activeRevision();
            if (!before.equals(after)) {
                before = after;
                snapshot = source.loadActive(nowEpochSecond);
                after = source.activeRevision();
                if (!before.equals(after)) {
                    throw new MassDbLicenseException(
                            "MASSDB_LICENSE_ROLE_IDENTITY_STORE_CHANGED",
                            "身份库active generation在读取期间持续变化");
                }
            }
            return new Loaded(after, snapshot);
        }

        private void requireOpen() {
            if (closed.get()) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_ROLE_IDENTITY_UNAVAILABLE",
                        "FE角色身份provider已关闭");
            }
        }

        private static final class Loaded {
            private final String revision;
            private final Snapshot snapshot;

            private Loaded(String revision, Snapshot snapshot) {
                this.revision = Objects.requireNonNull(revision, "revision");
                this.snapshot = Objects.requireNonNull(snapshot, "snapshot");
            }
        }
    }
}
