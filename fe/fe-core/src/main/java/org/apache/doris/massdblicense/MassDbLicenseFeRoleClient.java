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

import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.common.util.MasterDaemon;
import org.apache.doris.qe.QeProcessorImpl;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Every FE role polls the current Leader over mTLS and persists commands before ACKing. */
public final class MassDbLicenseFeRoleClient extends MasterDaemon {
    private static final Logger LOG = LogManager.getLogger(MassDbLicenseFeRoleClient.class);
    private static final int MAX_RESPONSE_BYTES = 256 * 1024;

    enum Outcome {
        NOT_INITIALIZED,
        EXCHANGED,
        APPLIED_DECISION,
        PREPARED_ACK
    }

    interface EndpointProvider {
        String masterHost();

        int httpsPort();
    }

    interface ExchangeClient {
        MassDbLicenseFeRoleProtocol.ExchangeResponse exchange(String host, int port,
                MassDbLicenseFeRoleProtocol.ExchangeRequest request,
                MassDbLicenseFeRoleIdentityProvider.Snapshot identity) throws Exception;
    }

    private final MassDbLicenseManager manager;
    private final MassDbLicenseImportCore importCore;
    private final MassDbLicenseLocalSnapshotStore store;
    private final MassDbLicenseEnforcementCore enforcementCore;
    private final MassDbLicenseKeysetControlCore keysetCore;
    private final EndpointProvider endpointProvider;
    private final ExchangeClient exchangeClient;
    private final MassDbLicenseFeRoleIdentityProvider identityProvider;
    private final QueryMonitor queryMonitor;
    private final String processInstanceUuid = UUID.randomUUID().toString();
    private final AtomicLong reportSequence = new AtomicLong();
    private final long monotonicBootWallClock = Instant.now().getEpochSecond();
    private final long monotonicBootNanos = System.nanoTime();
    private volatile boolean queryGuardInstalled;
    private volatile MassDbLicenseLocalSnapshotStore.QueryDecision localQueryDecision =
            MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                    "MASSDB_LICENSE_CONTROL_PLANE_STALE");
    private String lastFailure;

    public static MassDbLicenseFeRoleClient createConfigured(
            MassDbLicenseManager manager, MassDbLicenseImportCore importCore,
            MassDbLicenseLocalSnapshotStore store) {
        if (!Config.massdb_license_role_mtls_enabled) {
            return null;
        }
        if (!Config.enable_https || Config.massdb_license_role_exchange_interval_ms <= 0
                || Config.massdb_license_role_request_timeout_ms <= 0) {
            fail("MassDB License角色mTLS需要HTTPS且周期/超时必须大于0");
        }
        MassDbLicenseFeRoleIdentityProvider identityProvider;
        if (Config.massdb_license_role_mtls_development_keystore_enabled) {
            requireDevelopmentKeyStoreAllowed();
            identityProvider = new MassDbLicenseFeRoleIdentityProvider.Rotating(
                    ConfiguredTls.load());
        } else {
            identityProvider = MassDbLicenseIdentityRuntime.openConfigured(
                    Config.massdb_license_identity_store_dir,
                    Config.massdb_license_identity_artifact_root_dir,
                    Config.massdb_license_identity_secret_file,
                    Config.meta_dir);
        }
        EndpointProvider endpoint = new EndpointProvider() {
            @Override
            public String masterHost() {
                return Env.getServingEnv().getMasterHost();
            }

            @Override
            public int httpsPort() {
                return Config.https_port;
            }
        };
        return new MassDbLicenseFeRoleClient(manager, importCore, store,
                new MassDbLicenseEnforcementCore(), endpoint,
                new HttpsExchangeClient(Config.massdb_license_role_request_timeout_ms),
                identityProvider, Config.massdb_license_role_exchange_interval_ms);
    }

    static void requireDevelopmentKeyStoreAllowed() {
        if (!Config.enable_debug_points
                || !Config.massdb_license_role_mtls_development_keystore_enabled) {
            fail("磁盘key store仅允许显式debug开发测试；生产必须使用组件内可轮换身份provider");
        }
    }

    MassDbLicenseFeRoleClient(MassDbLicenseManager manager,
            MassDbLicenseImportCore importCore, MassDbLicenseLocalSnapshotStore store,
            MassDbLicenseEnforcementCore enforcementCore, EndpointProvider endpointProvider,
            ExchangeClient exchangeClient,
            MassDbLicenseFeRoleIdentityProvider identityProvider,
            long intervalMillis) {
        super("massdb-license-fe-role-client", intervalMillis);
        this.manager = Objects.requireNonNull(manager, "manager");
        this.importCore = Objects.requireNonNull(importCore, "importCore");
        this.store = Objects.requireNonNull(store, "store");
        this.enforcementCore = Objects.requireNonNull(enforcementCore, "enforcementCore");
        this.keysetCore = importCore.createKeysetControlCore();
        this.endpointProvider = Objects.requireNonNull(endpointProvider, "endpointProvider");
        this.exchangeClient = Objects.requireNonNull(exchangeClient, "exchangeClient");
        this.identityProvider = Objects.requireNonNull(identityProvider, "identityProvider");
        this.queryMonitor = new QueryMonitor(this);
    }

    public MassDbLicenseFeRoleIdentityProvider getIdentityProvider() {
        return identityProvider;
    }

    /** Called only after all public MassDB SQL business-read entrypoints install the local guard. */
    public void markQueryGuardInstalled() {
        queryGuardInstalled = true;
        refreshLocalDecisionAndCancel();
    }

    /** Component-public query gates call this one-second cached decision; it never asks Manager or Leader. */
    public MassDbLicenseLocalSnapshotStore.QueryDecision evaluateLocalQuery() {
        return localQueryDecision;
    }

    private MassDbLicenseLocalSnapshotStore.QueryDecision computeLocalQueryDecision() {
        MassDbLicenseState state = manager.snapshot();
        if (!state.isInitialized() || state.getLicenseControlDeploymentUuid() == null) {
            // A legacy cluster must be able to roll every persisted FE onto the capable binary,
            // install local identities and collect the upgrade fence before the first new journal
            // record exists. UNINITIALIZED therefore preserves the pre-License query behavior;
            // fresh deployments enter initialized ENFORCING/OPEN before serving business data.
            return MassDbLicenseLocalSnapshotStore.QueryDecision.allow();
        }
        return MassDbLicenseFeRoleRuntime.evaluate(store, importCore,
                state.getLicenseControlDeploymentUuid(), Instant.now().getEpochSecond(),
                monotonicEpochSeconds()).queryDecision;
    }

    @Override
    public synchronized void start() {
        queryMonitor.start();
        super.start();
    }

    @Override
    public void exit() {
        queryMonitor.exit();
        super.exit();
    }

    @Override
    protected void runAfterCatalogReady() {
        try {
            cycle(Instant.now().getEpochSecond(), monotonicEpochSeconds());
            if (lastFailure != null) {
                LOG.info("MassDB License FE角色mTLS通道已恢复");
                lastFailure = null;
            }
        } catch (Throwable error) {
            String failure = error instanceof MassDbLicenseException
                    ? ((MassDbLicenseException) error).getCode()
                    : error.getClass().getSimpleName();
            if (!failure.equals(lastFailure)) {
                LOG.warn("MassDB License FE角色mTLS交换失败，本地pending保持不变 code={}",
                        failure);
                lastFailure = failure;
            }
        }
    }

    private void refreshLocalDecisionAndCancel() {
        MassDbLicenseLocalSnapshotStore.QueryDecision decision;
        try {
            decision = computeLocalQueryDecision();
        } catch (RuntimeException error) {
            decision = MassDbLicenseLocalSnapshotStore.QueryDecision.deny(
                    "MASSDB_LICENSE_INVALID");
            LOG.warn("MassDB License本地裁决异常，已失败关闭业务查询 code={}",
                    error.getClass().getSimpleName());
        }
        localQueryDecision = decision;
        if (!queryGuardInstalled) {
            return;
        }
        if (!decision.allowed) {
            String errorCode = decision.errorCode == null
                    ? "MASSDB_LICENSE_INVALID" : decision.errorCode;
            QeProcessorImpl.INSTANCE.cancelMassDbLicenseProtectedReads(errorCode);
        }
    }

    Outcome cycle(long now) throws Exception {
        return cycle(now, now);
    }

    Outcome cycle(long wallClock, long monotonicNow) throws Exception {
        MassDbLicenseState state = manager.snapshot();
        if (!state.isInitialized() || state.getLicenseControlDeploymentUuid() == null) {
            return Outcome.NOT_INITIALIZED;
        }
        MassDbLicenseFeRoleIdentityProvider.Snapshot identity = identityProvider.current(wallClock);
        requireConfiguredIdentity(identity.identity, state.getLicenseControlDeploymentUuid());
        String host = endpointProvider.masterHost();
        int port = endpointProvider.httpsPort();
        if (host == null || host.trim().isEmpty() || port <= 0 || port > 65_535) {
            throw new IOException("MassDB License Leader HTTPS endpoint unavailable");
        }

        MassDbLicenseFeRoleProtocol.ExchangeRequest request = buildRequest(
                state.getLicenseControlDeploymentUuid(), wallClock, monotonicNow);
        MassDbLicenseFeRoleProtocol.ExchangeResponse response = exchangeClient.exchange(
                host, port, request, identity);
        validateResponse(response, state.getLicenseControlDeploymentUuid(),
                request.status.reportSequence);
        applyIdentityConflict(response.identityConflict, state.getLicenseControlDeploymentUuid());
        boolean applied = applyDecisions(response.decisions, wallClock);
        boolean prepared = applyCommands(response.commands, wallClock);
        MassDbLicenseFeRoleRuntime.applyControlPlaneSync(store, importCore,
                state.getLicenseControlDeploymentUuid(), response.controlPlaneSync,
                wallClock, monotonicNow, request.status.reportSequence);
        applied = applyControlDecisions(response.decisions) || applied;
        if (prepared) {
            return Outcome.PREPARED_ACK;
        }
        return applied ? Outcome.APPLIED_DECISION : Outcome.EXCHANGED;
    }

    private MassDbLicenseFeRoleProtocol.ExchangeRequest buildRequest(
            String deploymentUuid, long wallClock, long monotonicNow) {
        long sequence = reportSequence.updateAndGet(value -> {
            if (value == Long.MAX_VALUE) {
                protocolFail("FE角色report sequence已耗尽");
            }
            return value + 1;
        });
        MassDbLicenseFeRoleRuntime.Evaluation evaluation =
                MassDbLicenseFeRoleRuntime.evaluate(
                        store, importCore, deploymentUuid, wallClock, monotonicNow);
        localQueryDecision = evaluation.queryDecision;
        MassDbLicenseFeRoleProtocol.RoleStatus status = evaluation.toRoleStatus(sequence);
        boolean identityBlocked = status.identityConflict
                || "MASSDB_LICENSE_LOCAL_STATE_CORRUPT".equals(status.localStateErrorCode)
                || "MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH".equals(
                        status.localStateErrorCode);
        status.guardReady = queryGuardInstalled && !identityBlocked;
        return new MassDbLicenseFeRoleProtocol.ExchangeRequest(
                deploymentUuid, store.getNodeUuid(), processInstanceUuid, status,
                identityBlocked ? null
                        : MassDbLicenseFeRoleProtocol.ActivationAck.from(
                                store.loadActivationAck()),
                identityBlocked ? null
                        : MassDbLicenseFeRoleProtocol.LicenseAck.from(
                                store.loadLicenseAck()),
                identityBlocked ? null
                        : MassDbLicenseFeRoleProtocol.ControlAck.from(
                                store.loadControlAck()));
    }

    String getProcessInstanceUuid() {
        return processInstanceUuid;
    }

    private static final class QueryMonitor extends MasterDaemon {
        private static final long INTERVAL_MILLIS = 1_000L;
        private final MassDbLicenseFeRoleClient client;

        private QueryMonitor(MassDbLicenseFeRoleClient client) {
            super("massdb-license-query-monitor", INTERVAL_MILLIS);
            this.client = client;
        }

        @Override
        protected void runAfterCatalogReady() {
            client.refreshLocalDecisionAndCancel();
        }
    }

    private void applyIdentityConflict(MassDbLicenseFeRoleProtocol.IdentityConflict command,
            String deploymentUuid) {
        if (command == null) {
            return;
        }
        if (!deploymentUuid.equals(command.deploymentUuid)
                || command.controlPlaneRevision <= 0) {
            protocolFail("重复node UUID命令与当前部署或revision不匹配");
        }
        store.applyIdentityConflict(
                new MassDbLicenseLocalSnapshotStore.IdentityConflictSnapshot(
                        command.active, command.controlPlaneRevision, command.deploymentUuid,
                        "fe", store.getNodeUuid(), command.detectedAt,
                        command.lastObservedAt, command.clearEligibleAt, command.resolvedAt));
    }

    private boolean applyDecisions(List<MassDbLicenseFeRoleProtocol.Decision> decisions, long now) {
        List<MassDbLicenseFeRoleProtocol.Decision> safe = decisions == null
                ? Collections.emptyList() : decisions;
        if (safe.size() > 3) {
            protocolFail("Leader返回过多终态决议");
        }
        boolean applied = false;
        for (MassDbLicenseFeRoleProtocol.Decision decision : safe) {
            if (decision == null || decision.operationId == null) {
                protocolFail("Leader终态决议无效");
            }
            MassDbLicenseLocalSnapshotStore.ActivationPending activation = store.loadPending();
            MassDbLicenseLocalSnapshotStore.LicensePending license = store.loadLicensePending();
            MassDbLicenseLocalSnapshotStore.ControlPending control =
                    store.loadControlPending();
            if (activation != null && activation.operationId.equals(decision.operationId)) {
                applyActivationDecision(activation, decision, now);
                applied = true;
            } else if (license != null && license.operationId.equals(decision.operationId)) {
                applyLicenseDecision(license, decision, now);
                applied = true;
            } else if (control != null && control.operationId.equals(decision.operationId)) {
                // A successful keyset decision is clearable only after controlPlaneSync below.
                continue;
            } else {
                protocolFail("Leader返回了与本地pending不匹配的终态决议");
            }
        }
        return applied;
    }

    private boolean applyControlDecisions(
            List<MassDbLicenseFeRoleProtocol.Decision> decisions) {
        MassDbLicenseLocalSnapshotStore.ControlPending pending = store.loadControlPending();
        if (pending == null) {
            return false;
        }
        for (MassDbLicenseFeRoleProtocol.Decision decision : decisions == null
                ? Collections.<MassDbLicenseFeRoleProtocol.Decision>emptyList() : decisions) {
            if (decision == null || !pending.operationId.equals(decision.operationId)) {
                continue;
            }
            if (!pending.kind.name().equals(decision.kind)
                    || !pending.kind.name().equals(decision.action)) {
                protocolFail("keyset终态决议与本地pending不匹配");
            }
            if (decision.succeeded()) {
                store.finishControlPending(pending.operationId, true);
            } else if (decision.failedOrAborted()) {
                store.finishControlPending(pending.operationId, false);
            } else {
                protocolFail("keyset决议不是终态");
            }
            return true;
        }
        return false;
    }

    private void applyActivationDecision(
            MassDbLicenseLocalSnapshotStore.ActivationPending pending,
            MassDbLicenseFeRoleProtocol.Decision decision, long now) {
        if (!MassDbLicenseState.MutationKind.ENFORCEMENT.name().equals(decision.kind)
                || !MassDbLicenseFeRoleProtocol.COMMAND_ENFORCEMENT.equals(decision.action)
                || !pending.activeSha256.equals(decision.contentSha256)
                || decision.targetEnforcementEpoch == null
                || pending.targetEnforcementEpoch != decision.targetEnforcementEpoch) {
            protocolFail("activation终态决议与本地pending不匹配");
        }
        if (decision.succeeded()) {
            store.commitActivation(pending.operationId, pending.targetEnforcementEpoch, now);
        } else if (decision.failedOrAborted()) {
            store.abortActivation(pending.operationId);
        } else {
            protocolFail("activation决议不是终态");
        }
    }

    private void applyLicenseDecision(MassDbLicenseLocalSnapshotStore.LicensePending pending,
            MassDbLicenseFeRoleProtocol.Decision decision, long now) {
        if (!MassDbLicenseState.MutationKind.LICENSE.name().equals(decision.kind)
                || (!"ACTIVATE".equals(decision.action) && !"REPAIR".equals(decision.action))
                || !pending.contentSha256.equals(decision.contentSha256)
                || decision.targetLicenseExpiresAt == null
                || pending.expiresAt != decision.targetLicenseExpiresAt) {
            protocolFail("NORMAL终态决议与本地pending不匹配");
        }
        if (decision.succeeded()) {
            store.commitLicense(pending.operationId, pending.contentSha256, now);
        } else if (decision.failedOrAborted()) {
            store.abortLicense(pending.operationId);
        } else {
            protocolFail("NORMAL决议不是终态");
        }
    }

    private boolean applyCommands(List<MassDbLicenseFeRoleProtocol.Command> commands, long now) {
        List<MassDbLicenseFeRoleProtocol.Command> safe = commands == null
                ? Collections.emptyList() : commands;
        if (safe.size() > 1) {
            protocolFail("Leader同时返回了多个角色命令");
        }
        if (safe.isEmpty()) {
            return false;
        }
        MassDbLicenseLocalSnapshotStore.IdentityConflictSnapshot conflict =
                store.loadIdentityConflict();
        if (conflict != null && conflict.active) {
            protocolFail("重复node UUID期间Leader不能下发prepare命令");
        }
        MassDbLicenseFeRoleProtocol.Command command = safe.get(0);
        if (command == null || command.operationId == null
                || now >= command.deadlineAt
                || command.requiredAckNodeUuids == null
                || !command.requiredAckNodeUuids.contains(store.getNodeUuid())
                || command.deferredNodeUuids != null
                        && command.deferredNodeUuids.contains(store.getNodeUuid())) {
            protocolFail("Leader角色命令已过期或不包含本FE");
        }
        if (MassDbLicenseFeRoleProtocol.COMMAND_NORMAL.equals(command.type)) {
            MassDbLicenseState localJournal = manager.snapshot();
            MassDbLicenseImportCore.RedriveResult redrive =
                    importCore.recoverNormal(localJournal, command.operationId, now);
            if (redrive.terminal || redrive.plan == null
                    || !command.samePayload(
                            MassDbLicenseFeRoleProtocol.Command.normal(redrive.plan))) {
                protocolFail("NORMAL命令与本FE journal prepared计划不匹配");
            }
            importCore.prepareLocalAck(store, redrive.plan, localJournal, now);
            return true;
        }
        if (MassDbLicenseFeRoleProtocol.COMMAND_ENFORCEMENT.equals(command.type)) {
            MassDbLicenseEnforcementCore.RedriveResult redrive = enforcementCore.recover(
                    manager.snapshot(), command.operationId, now);
            if (redrive.terminal || redrive.plan == null
                    || !command.samePayload(
                            MassDbLicenseFeRoleProtocol.Command.enforcement(redrive.plan))) {
                protocolFail("enforcement命令与本FE journal prepared计划不匹配");
            }
            enforcementCore.prepareLocalAck(store, redrive.plan);
            return true;
        }
        if (MassDbLicenseFeRoleProtocol.COMMAND_KEYSET.equals(command.type)) {
            MassDbLicenseKeysetControlCore.RedriveResult redrive = keysetCore.recover(
                    manager.snapshot(), command.operationId, now);
            if (redrive.terminal || redrive.plan == null
                    || !command.samePayload(
                            MassDbLicenseFeRoleProtocol.Command.keyset(redrive.plan))) {
                protocolFail("keyset命令与本FE journal prepared计划不匹配");
            }
            keysetCore.prepareLocalAck(store, redrive.plan, now);
            return true;
        }
        protocolFail("Leader角色命令类型不受支持");
        return false;
    }

    private void requireConfiguredIdentity(MassDbLicenseSpiffeIdentity.Identity identity,
            String deploymentUuid) {
        if (!"massdb-sql".equals(identity.component)
                || !"fe".equals(identity.role)
                || !deploymentUuid.equals(identity.deploymentUuid)
                || !store.getNodeUuid().equals(identity.nodeUuid)) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH",
                    "FE角色证书URI SAN与当前部署或本地node UUID不匹配");
        }
    }

    private static void validateResponse(MassDbLicenseFeRoleProtocol.ExchangeResponse response,
            String deploymentUuid, long reportSequence) {
        if (response == null || response.protocolVersion != MassDbLicenseFeRoleProtocol.VERSION
                || !deploymentUuid.equals(response.deploymentUuid)
                || response.serverTime <= 0 || response.controlPlaneSync == null
                || response.controlPlaneSync.reportSequence != reportSequence) {
            protocolFail("Leader角色响应协议或部署标识无效");
        }
    }

    /** Epoch-shaped monotonic clock: immune to wall-clock rollback during this FE process. */
    private long monotonicEpochSeconds() {
        long elapsedNanos = System.nanoTime() - monotonicBootNanos;
        if (elapsedNanos < 0) {
            return monotonicBootWallClock;
        }
        return saturatedAdd(monotonicBootWallClock, elapsedNanos / 1_000_000_000L);
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static void protocolFail(String message) {
        throw new MassDbLicenseException("MASSDB_LICENSE_ROLE_PROTOCOL_INVALID", message);
    }

    private static void fail(String message) {
        throw new MassDbLicenseException("MASSDB_LICENSE_ROLE_MTLS_CONFIG_INVALID", message);
    }

    private static final class HttpsExchangeClient implements ExchangeClient {
        private final int timeoutMillis;

        private HttpsExchangeClient(int timeoutMillis) {
            this.timeoutMillis = timeoutMillis;
        }

        @Override
        public MassDbLicenseFeRoleProtocol.ExchangeResponse exchange(String host, int port,
                MassDbLicenseFeRoleProtocol.ExchangeRequest request,
                MassDbLicenseFeRoleIdentityProvider.Snapshot identity) throws Exception {
            URL endpoint = new URL("https", host, port, MassDbLicenseFeRoleProtocol.PATH);
            HttpsURLConnection connection = (HttpsURLConnection) endpoint.openConnection();
            connection.setSSLSocketFactory(identity.clientSslContext.getSocketFactory());
            connection.setConnectTimeout(timeoutMillis);
            connection.setReadTimeout(timeoutMillis);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "application/json");
            connection.setDoOutput(true);
            byte[] body = MassDbLicenseFeRoleProtocol.encode(request);
            connection.setFixedLengthStreamingMode(body.length);
            try {
                connection.connect();
                Certificate[] serverCertificates = connection.getServerCertificates();
                if (serverCertificates.length == 0
                        || !(serverCertificates[0] instanceof X509Certificate)) {
                    throw new IOException("MassDB License Leader certificate unavailable");
                }
                identity.requireAllowedServer((X509Certificate) serverCertificates[0],
                        request.deploymentUuid);
                try (OutputStream output = connection.getOutputStream()) {
                    output.write(body);
                }
                int status = connection.getResponseCode();
                InputStream stream = status >= 200 && status < 300
                        ? connection.getInputStream() : connection.getErrorStream();
                byte[] response = readBounded(stream);
                if (status != 200) {
                    throw new IOException("MassDB License role endpoint returned HTTP " + status);
                }
                return MassDbLicenseFeRoleProtocol.decode(response,
                        MassDbLicenseFeRoleProtocol.ExchangeResponse.class);
            } finally {
                connection.disconnect();
            }
        }

        private static byte[] readBounded(InputStream stream) throws IOException {
            if (stream == null) {
                return new byte[0];
            }
            try (InputStream input = stream;
                    ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int count;
                while ((count = input.read(buffer)) >= 0) {
                    if (count == 0) {
                        continue;
                    }
                    if (output.size() + count > MAX_RESPONSE_BYTES) {
                        throw new IOException("MassDB License role response too large");
                    }
                    output.write(buffer, 0, count);
                }
                return output.toByteArray();
            }
        }
    }

    private static final class ConfiguredTls {
        private static MassDbLicenseFeRoleIdentityProvider.Snapshot load() {
            char[] keyPassword = null;
            char[] trustPassword = null;
            try {
                Path keyStorePath = secureStorePath(
                        Config.massdb_license_role_mtls_key_store_path, "key store");
                Path trustStorePath = secureStorePath(
                        Config.massdb_license_role_mtls_trust_store_path, "trust store");
                keyPassword = safePassword(
                        Config.massdb_license_role_mtls_key_store_password);
                trustPassword = safePassword(
                        Config.massdb_license_role_mtls_trust_store_password);
                KeyStore keyStore = loadStore(keyStorePath,
                        Config.massdb_license_role_mtls_key_store_type, keyPassword);
                KeyStore trustStore = loadStore(trustStorePath,
                        Config.massdb_license_role_mtls_trust_store_type, trustPassword);
                X509Certificate roleCertificate = uniquePrivateKeyCertificate(keyStore);
                MassDbLicenseSpiffeIdentity.Identity identity =
                        MassDbLicenseSpiffeIdentity.parsePeerCertificate(roleCertificate);

                KeyManagerFactory keys = KeyManagerFactory.getInstance(
                        KeyManagerFactory.getDefaultAlgorithm());
                keys.init(keyStore, keyPassword);
                TrustManagerFactory trust = TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm());
                trust.init(trustStore);
                SSLContext context = SSLContext.getInstance("TLS");
                context.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
                return new MassDbLicenseFeRoleIdentityProvider.Snapshot(
                        1L, context, identity,
                        roleCertificate.getNotBefore().toInstant().getEpochSecond(),
                        roleCertificate.getNotAfter().toInstant().getEpochSecond(),
                        Collections.emptySet(), trustRoots(trustStore));
            } catch (GeneralSecurityException | IOException | RuntimeException error) {
                if (error instanceof MassDbLicenseException) {
                    throw (MassDbLicenseException) error;
                }
                fail("无法加载FE角色mTLS key/trust store");
                return null;
            } finally {
                if (keyPassword != null) {
                    Arrays.fill(keyPassword, '\0');
                }
                if (trustPassword != null) {
                    Arrays.fill(trustPassword, '\0');
                }
            }
        }

        private static Path secureStorePath(String raw, String label) throws IOException {
            if (raw == null || raw.trim().isEmpty()) {
                fail(label + "路径未配置");
            }
            Path path = Paths.get(raw.trim());
            if (!path.isAbsolute() || Files.isSymbolicLink(path)
                    || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                fail(label + "必须是非符号链接的绝对普通文件");
            }
            try {
                Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(
                        path, LinkOption.NOFOLLOW_LINKS);
                if (permissions.contains(PosixFilePermission.GROUP_WRITE)
                        || permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
                    fail(label + "不能被组或其他用户写入");
                }
            } catch (UnsupportedOperationException ignored) {
                // Non-POSIX platforms still get absolute-path and symlink checks.
            }
            return path;
        }

        private static KeyStore loadStore(Path path, String type, char[] password)
                throws GeneralSecurityException, IOException {
            if (type == null || type.trim().isEmpty()) {
                fail("mTLS store类型未配置");
            }
            KeyStore store = KeyStore.getInstance(type.trim());
            try (InputStream input = Files.newInputStream(path)) {
                store.load(input, password);
            }
            return store;
        }

        private static X509Certificate uniquePrivateKeyCertificate(KeyStore store)
                throws GeneralSecurityException {
            Enumeration<String> aliases = store.aliases();
            X509Certificate result = null;
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (!store.isKeyEntry(alias)) {
                    continue;
                }
                Certificate certificate = store.getCertificate(alias);
                if (!(certificate instanceof X509Certificate) || result != null) {
                    fail("FE角色key store必须且只能包含一个X.509私钥条目");
                }
                result = (X509Certificate) certificate;
            }
            if (result == null) {
                fail("FE角色key store不包含X.509私钥条目");
            }
            return result;
        }

        private static List<X509Certificate> trustRoots(KeyStore store)
                throws GeneralSecurityException {
            List<X509Certificate> result = new ArrayList<>();
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                Certificate certificate = store.getCertificate(aliases.nextElement());
                if (certificate instanceof X509Certificate
                        && ((X509Certificate) certificate).getBasicConstraints() >= 0) {
                    result.add((X509Certificate) certificate);
                }
            }
            if (result.isEmpty()) {
                fail("FE角色trust store必须包含至少一个X.509 CA证书");
            }
            return result;
        }

        private static char[] safePassword(String value) {
            return value == null ? new char[0] : value.toCharArray();
        }
    }
}
