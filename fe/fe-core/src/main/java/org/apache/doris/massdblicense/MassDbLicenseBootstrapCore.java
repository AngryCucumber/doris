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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/** Transport-independent first-install bootstrap for trust root output and query ingress topology. */
public final class MassDbLicenseBootstrapCore {
    public static final int MAX_BOOTSTRAP_PLAN_BYTES = 128 * 1024;
    public static final int MAX_INGRESS_NODES = 128;
    public static final int MAX_FRONTENDS = 32;
    public static final int MAX_BACKENDS = 1024;
    public static final int MAX_INGEST_ROUTES = 128;
    public static final String MINIMUM_WRITE_HEALTH = "FE_LEADER_READY";
    public static final String FULL_MINIMUM_WRITE_HEALTH =
            "ALL_PLANNED_MEMBERS_ALIVE_AND_INGEST_READY";

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT);

    public interface WriteHealth {
        String requireLocalFeIdentity(String deploymentUuid, long now);

        default void requireFullPlanCompatible(InstallationPlan plan, long now) {
            fail("MASSDB_LICENSE_BOOTSTRAP_RUNTIME_UNAVAILABLE",
                    "完整bootstrap运行时未实现只读计划核验");
        }

        default InstallationHealth reconcileAndRequireFullHealth(
                InstallationPlan plan, long now) {
            fail("MASSDB_LICENSE_BOOTSTRAP_RUNTIME_UNAVAILABLE",
                    "完整bootstrap运行时未实现成员、账号和路由收敛");
            return null;
        }
    }

    /** Minimal, non-business health proof returned by the component bootstrap runtime. */
    public static final class InstallationHealth {
        public final int plannedFrontends;
        public final int aliveFrontends;
        public final int plannedBackends;
        public final int aliveBackends;
        public final int readyIngestRoutes;
        public final boolean ingestAccountReady;

        public InstallationHealth(int plannedFrontends, int aliveFrontends,
                int plannedBackends, int aliveBackends, int readyIngestRoutes,
                boolean ingestAccountReady) {
            this.plannedFrontends = plannedFrontends;
            this.aliveFrontends = aliveFrontends;
            this.plannedBackends = plannedBackends;
            this.aliveBackends = aliveBackends;
            this.readyIngestRoutes = readyIngestRoutes;
            this.ingestAccountReady = ingestAccountReady;
        }
    }

    public static final class BootstrapStatus {
        public final String bootstrapPhase;
        public final long bootstrapSealGeneration;
        public final String bootstrapPlanSha256;
        public final String bootstrapMarkerId;
        public final String licenseControlDeploymentUuid;
        public final long markerCreatedAt;
        public final long markerConsumedAt;
        public final String localMarkerStatus;
        public final String localMarkerReasonCode;
        public final String bootstrapClaimId;
        public final long claimCreatedAt;
        public final long claimOpenRecordedAt;

        private BootstrapStatus(MassDbLicenseState state,
                MassDbLicenseBootstrapMarker.Attestation attestation) {
            this.bootstrapPhase = state.getBootstrapPhase();
            this.bootstrapSealGeneration = state.getBootstrapSealGeneration();
            this.bootstrapPlanSha256 = state.getBootstrapPlanSha256();
            this.bootstrapMarkerId = state.getBootstrapMarkerId();
            this.licenseControlDeploymentUuid = state.getLicenseControlDeploymentUuid();
            this.markerCreatedAt = state.getBootstrapMarkerCreatedAt();
            this.markerConsumedAt = state.getBootstrapMarkerConsumedAt();
            boolean consumed = "SEALED".equals(state.getBootstrapPhase())
                    && state.getBootstrapMarkerConsumedAt() > 0;
            this.localMarkerStatus = consumed ? "CONSUMED"
                    : attestation == null ? "UNCONFIGURED"
                    : !"ABSENT".equals(attestation.localClaimStatus)
                    ? attestation.localClaimStatus : attestation.status.name();
            this.localMarkerReasonCode = consumed || attestation == null
                    || (state.isInitialized()
                            && "OPEN_RECORDED".equals(attestation.localClaimStatus))
                    ? null : attestation.reasonCode;
            this.bootstrapClaimId = attestation == null
                    ? null : attestation.bootstrapClaimId;
            this.claimCreatedAt = attestation == null ? 0 : attestation.claimedAt;
            this.claimOpenRecordedAt = attestation == null
                    ? 0 : attestation.openRecordedAt;
        }
    }

    public static final class ValidateResult {
        public final boolean readyForApply;
        public final String action;
        public final String bootstrapPhase;
        public final long bootstrapSealGeneration;
        public final String bootstrapPlanSha256;
        public final String keysetSha256;
        public final long keysetVersion;
        public final String inventorySha256;
        public final int desiredIngressNodes;
        public final int planFormatVersion;
        public final String minimumWriteHealth;
        public final int plannedFrontends;
        public final int plannedBackends;
        public final int plannedIngestRoutes;
        public final String ingestAccount;
        public final String localNodeUuid;
        public final String preconditionToken;
        public final long tokenExpiresAt;

        private ValidateResult(ParsedPlan plan, long keysetVersion,
                String localNodeUuid, String token, long tokenExpiresAt) {
            this.readyForApply = true;
            this.action = "SEAL";
            this.bootstrapPhase = "OPEN";
            this.bootstrapSealGeneration = 0;
            this.bootstrapPlanSha256 = plan.planSha256;
            this.keysetSha256 = plan.keysetSha256;
            this.keysetVersion = keysetVersion;
            this.inventorySha256 = plan.inventory.configuredDigest();
            this.desiredIngressNodes = plan.inventory.getNodes().size();
            this.planFormatVersion = plan.formatVersion;
            this.minimumWriteHealth = plan.minimumWriteHealth;
            this.plannedFrontends = plan.installationPlan == null
                    ? 0 : plan.installationPlan.getFrontends().size();
            this.plannedBackends = plan.installationPlan == null
                    ? 0 : plan.installationPlan.getBackends().size();
            this.plannedIngestRoutes = plan.installationPlan == null
                    ? 0 : plan.installationPlan.getIngestRoutes().size();
            this.ingestAccount = plan.installationPlan == null
                    ? null : plan.installationPlan.getIngestAccount().getQualifiedName();
            this.localNodeUuid = localNodeUuid;
            this.preconditionToken = token;
            this.tokenExpiresAt = tokenExpiresAt;
        }
    }

    public static final class ApplyResult {
        public final MassDbLicenseState state;
        public final String operationId;
        public final boolean replayed;

        private ApplyResult(MassDbLicenseState state, String operationId, boolean replayed) {
            this.state = state;
            this.operationId = operationId;
            this.replayed = replayed;
        }
    }

    public static final class PlanSummary {
        public final String planSha256;
        public final String keysetSha256;
        public final String inventorySha256;
        public final int desiredIngressNodes;
        public final int formatVersion;
        public final String minimumWriteHealth;
        public final int plannedFrontends;
        public final int plannedBackends;
        public final int plannedIngestRoutes;

        private PlanSummary(ParsedPlan plan) {
            this.planSha256 = plan.planSha256;
            this.keysetSha256 = plan.keysetSha256;
            this.inventorySha256 = plan.inventory.configuredDigest();
            this.desiredIngressNodes = plan.inventory.getNodes().size();
            this.formatVersion = plan.formatVersion;
            this.minimumWriteHealth = plan.minimumWriteHealth;
            this.plannedFrontends = plan.installationPlan == null
                    ? 0 : plan.installationPlan.getFrontends().size();
            this.plannedBackends = plan.installationPlan == null
                    ? 0 : plan.installationPlan.getBackends().size();
            this.plannedIngestRoutes = plan.installationPlan == null
                    ? 0 : plan.installationPlan.getIngestRoutes().size();
        }
    }

    private final MassDbLicenseImportCore importCore;

    public MassDbLicenseBootstrapCore(MassDbLicenseImportCore importCore) {
        if (importCore == null) {
            throw new IllegalArgumentException("importCore不能为空");
        }
        this.importCore = importCore;
    }

    public BootstrapStatus status(MassDbLicenseState state,
            MassDbLicenseBootstrapMarker.Attestation attestation) {
        return new BootstrapStatus(requireState(state), attestation);
    }

    public ValidateResult validate(MassDbLicenseState state, byte[] planBytes,
            WriteHealth health, long now) {
        MassDbLicenseState current = requireState(state);
        ParsedPlan plan = parse(planBytes);
        requireOpenPlan(current, plan);
        if (current.getActiveKeyset() != null
                || current.getActiveLicense() != null
                || !current.getIngressInventory().getNodes().isEmpty()
                || current.getMutation() != null) {
            fail("MASSDB_LICENSE_BOOTSTRAP_STATE_CONFLICT", "OPEN状态已存在控制面数据或mutation");
        }
        MassDbLicenseProtocolV1.VerifiedKeyset keyset =
                importCore.verifyControlPlaneKeyset(plan.keysetArtifact, now);
        String localNodeUuid = requireWriteHealth(health, current, plan, now);
        if (plan.installationPlan != null) {
            health.requireFullPlanCompatible(plan.installationPlan, now);
        }
        long expiresAt = saturatedAdd(now, MassDbLicenseBootstrapToken.MAX_TTL_SECONDS);
        MassDbLicenseBootstrapToken.Claims claims = new MassDbLicenseBootstrapToken.Claims(
                current.getBootstrapMarkerId(), current.getLicenseControlDeploymentUuid(),
                plan.planSha256, plan.keysetSha256, plan.inventory.configuredDigest(),
                current.getTopologyRevision(), current.getBootstrapSealGeneration(),
                now, expiresAt, UUID.randomUUID().toString());
        String token = MassDbLicenseBootstrapToken.issue(
                current.getPreconditionHmacKey(), claims);
        return new ValidateResult(plan, keyset.getPayload().getKeysetVersion(),
                localNodeUuid, token, expiresAt);
    }

    public ApplyResult apply(MassDbLicenseState state, byte[] planBytes,
            String contentSha256, String preconditionToken, String idempotencyKey,
            String operationId, WriteHealth health, long now) {
        MassDbLicenseState current = requireState(state);
        requireContentDigest(contentSha256, planBytes);
        ParsedPlan plan = parse(planBytes);
        String requestHash = requestHash(plan);
        String replayOperation = current.findOperationIdByIdempotency(
                idempotencyKey, requestHash);
        if (replayOperation != null) {
            return new ApplyResult(current, replayOperation, true);
        }
        if ("SEALED".equals(current.getBootstrapPhase())) {
            MassDbLicenseState aliased = current.sealBootstrap(operationId,
                    idempotencyKey, requestHash, current.getBootstrapMarkerId(),
                    plan.planSha256, null, null, now);
            MassDbLicenseState.OperationView replay =
                    aliased.findOperationByIdempotencyKey(idempotencyKey);
            return new ApplyResult(aliased, replay.operationId, true);
        }
        requireOpenPlan(current, plan);
        MassDbLicenseBootstrapToken.Claims claims = MassDbLicenseBootstrapToken.verify(
                current.getPreconditionHmacKey(), preconditionToken, now);
        if (!claims.bootstrapMarkerId.equals(current.getBootstrapMarkerId())
                || !claims.deploymentUuid.equals(current.getLicenseControlDeploymentUuid())
                || !claims.planSha256.equals(plan.planSha256)
                || !claims.keysetSha256.equals(plan.keysetSha256)
                || !claims.inventorySha256.equals(plan.inventory.configuredDigest())
                || claims.topologyRevision != current.getTopologyRevision()
                || claims.bootstrapSealGeneration != current.getBootstrapSealGeneration()) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PRECONDITION_FAILED",
                    "bootstrap token与当前marker、plan或topology不匹配");
        }
        MassDbLicenseProtocolV1.VerifiedKeyset verified =
                importCore.verifyControlPlaneKeyset(plan.keysetArtifact, now);
        requireWriteHealth(health, current, plan, now);
        if (plan.installationPlan != null) {
            InstallationHealth installationHealth =
                    health.reconcileAndRequireFullHealth(plan.installationPlan, now);
            requireCompleteHealth(plan.installationPlan, installationHealth);
        }
        MassDbLicenseState.ActiveKeyset activeKeyset = new MassDbLicenseState.ActiveKeyset(
                verified.getPayload().getKeysetVersion(), verified.getSha256(),
                plan.keysetArtifact);
        MassDbLicenseState sealed = current.sealBootstrap(operationId, idempotencyKey,
                requestHash, current.getBootstrapMarkerId(), plan.planSha256,
                activeKeyset, plan.inventory, now);
        return new ApplyResult(sealed, operationId, false);
    }

    /** Structural canonicalization used by the pre-start marker-create CLI. */
    public static PlanSummary summarize(byte[] planBytes) {
        return new PlanSummary(parse(planBytes));
    }

    private static String requireWriteHealth(WriteHealth health,
            MassDbLicenseState state, ParsedPlan plan, long now) {
        if (health == null) {
            fail("MASSDB_LICENSE_BOOTSTRAP_WRITE_HEALTH_FAILED", "FE Leader写健康检查器未就绪");
        }
        String localNodeUuid = health.requireLocalFeIdentity(
                state.getLicenseControlDeploymentUuid(), now);
        MassDbLicenseIngressInventory.IngressNode local =
                plan.inventory.getNodes().get(localNodeUuid);
        if (local == null || !local.isDesired()) {
            fail("MASSDB_LICENSE_BOOTSTRAP_IDENTITY_MISMATCH",
                    "当前FE身份node UUID不在desired入口清单中");
        }
        return localNodeUuid;
    }

    private static void requireCompleteHealth(InstallationPlan plan,
            InstallationHealth health) {
        if (health == null
                || health.plannedFrontends != plan.getFrontends().size()
                || health.aliveFrontends != health.plannedFrontends
                || health.plannedBackends != plan.getBackends().size()
                || health.aliveBackends != health.plannedBackends
                || health.readyIngestRoutes != plan.getIngestRoutes().size()
                || !health.ingestAccountReady) {
            fail("MASSDB_LICENSE_BOOTSTRAP_NOT_READY",
                    "计划成员、纯写账号或入库路由尚未全部健康");
        }
    }

    private static void requireOpenPlan(MassDbLicenseState state, ParsedPlan plan) {
        if (!state.isInitialized() || !"OPEN".equals(state.getBootstrapPhase())
                || state.getBootstrapSealGeneration() != 0
                || state.getBootstrapMarkerId() == null) {
            fail("MASSDB_LICENSE_BOOTSTRAP_SEALED", "bootstrap不处于OPEN generation 0");
        }
        if (!plan.planSha256.equals(state.getBootstrapPlanSha256())) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_MISMATCH", "bootstrap plan与首启marker不匹配");
        }
    }

    private static ParsedPlan parse(byte[] encoded) {
        if (encoded == null || encoded.length == 0 || encoded.length > MAX_BOOTSTRAP_PLAN_BYTES) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "bootstrap plan为空或超过131072字节");
        }
        final Plan wire;
        try {
            wire = MAPPER.readValue(encoded, Plan.class);
        } catch (IOException failure) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "bootstrap plan JSON非法");
            return null;
        }
        if (wire == null || (wire.formatVersion != 1 && wire.formatVersion != 2)
                || !"massdb-sql".equals(wire.componentType)
                || !"SEALED".equals(wire.targetPhase)
                || wire.ingressNodes == null || wire.ingressNodes.isEmpty()
                || wire.ingressNodes.size() > MAX_INGRESS_NODES) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "bootstrap plan固定字段或入口数量非法");
        }
        byte[] keyset = decodeKeyset(wire.keysetArtifactBase64);
        String keysetSha = sha256(keyset);
        IngressResult ingressResult = parseIngress(wire.ingressNodes);
        InstallationPlan installationPlan = null;
        String canonicalInstallation = "";
        if (wire.formatVersion == 1) {
            if (!MINIMUM_WRITE_HEALTH.equals(wire.minimumWriteHealth)
                    || wire.frontends != null || wire.backends != null
                    || wire.ingestAccount != null || wire.ingestRoutes != null) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID",
                        "v1 plan只能使用Leader最小健康子集");
            }
        } else {
            if (!FULL_MINIMUM_WRITE_HEALTH.equals(wire.minimumWriteHealth)) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID",
                        "v2 plan必须使用完整成员与入库健康谓词");
            }
            FullPlanResult full = parseFullPlan(wire, ingressResult);
            installationPlan = full.installationPlan;
            canonicalInstallation = full.canonical;
        }
        String canonical = wire.formatVersion + "\nmassdb-sql\nSEALED\n"
                + wire.minimumWriteHealth + "\n" + keysetSha + "\n"
                + ingressResult.inventory.configuredDigest() + "\n"
                + ingressResult.canonical + canonicalInstallation;
        return new ParsedPlan(wire.formatVersion, wire.minimumWriteHealth,
                keyset, keysetSha, ingressResult.inventory,
                sha256(canonical.getBytes(StandardCharsets.UTF_8)), installationPlan);
    }

    private static IngressResult parseIngress(List<Ingress> ingressNodes) {
        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty();
        List<Ingress> sorted = new ArrayList<>(ingressNodes);
        for (Ingress ingress : sorted) {
            if (ingress == null || ingress.nodeUuid == null) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "入口对象或nodeUuid不能为空");
            }
        }
        Collections.sort(sorted, Comparator.comparing(value -> value.nodeUuid));
        Set<String> nodeUuids = new HashSet<>();
        Set<String> endpoints = new HashSet<>();
        StringBuilder canonicalNodes = new StringBuilder();
        for (Ingress ingress : sorted) {
            if (ingress == null || !ingress.desired) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "首启入口必须全部desired=true");
            }
            requireUuidV4(ingress.nodeUuid);
            requireHttpsEndpoint(ingress.endpoint);
            if (!nodeUuids.add(ingress.nodeUuid) || !endpoints.add(ingress.endpoint)) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "入口node UUID或endpoint重复");
            }
            inventory = inventory.upsertConfigured(
                    ingress.nodeUuid, ingress.endpoint, true);
            canonicalNodes.append(ingress.nodeUuid).append('\t')
                    .append(ingress.endpoint).append("\ttrue\n");
        }
        return new IngressResult(inventory, canonicalNodes.toString());
    }

    private static FullPlanResult parseFullPlan(Plan wire, IngressResult ingressResult) {
        if (wire.frontends == null || wire.frontends.isEmpty()
                || wire.frontends.size() > MAX_FRONTENDS
                || wire.backends == null || wire.backends.isEmpty()
                || wire.backends.size() > MAX_BACKENDS
                || wire.ingestAccount == null || wire.ingestRoutes == null
                || wire.ingestRoutes.isEmpty()
                || wire.ingestRoutes.size() > MAX_INGEST_ROUTES) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID",
                    "v2 plan成员、纯写账号或入库路由数量非法");
        }
        List<FrontendMember> frontends = parseFrontends(wire.frontends, ingressResult.inventory);
        Set<String> allNodeUuids = new HashSet<>();
        for (FrontendMember frontend : frontends) {
            allNodeUuids.add(frontend.nodeUuid);
        }
        List<BackendMember> backends = parseBackends(wire.backends, allNodeUuids);
        IngestAccount account = parseIngestAccount(wire.ingestAccount);
        List<IngestRoute> routes = parseIngestRoutes(
                wire.ingestRoutes, frontends, ingressResult.inventory);
        StringBuilder canonical = new StringBuilder("FRONTENDS\n");
        for (FrontendMember frontend : frontends) {
            canonical.append(frontend.nodeUuid).append('\t').append(frontend.role)
                    .append('\t').append(frontend.host).append('\t')
                    .append(frontend.editLogPort).append('\t')
                    .append(frontend.queryPort).append('\t')
                    .append(frontend.httpsPort).append('\n');
        }
        canonical.append("BACKENDS\n");
        for (BackendMember backend : backends) {
            canonical.append(backend.nodeUuid).append('\t').append(backend.host)
                    .append('\t').append(backend.heartbeatPort).append('\t')
                    .append(backend.bePort).append('\t').append(backend.httpPort)
                    .append('\t').append(backend.brpcPort).append('\n');
        }
        canonical.append("INGEST_ACCOUNT\n").append(account.username).append('\t')
                .append(account.hostPattern).append('\t').append(account.privilege)
                .append('\t').append(account.passwordHashSha256).append('\n')
                .append("INGEST_ROUTES\n");
        for (IngestRoute route : routes) {
            canonical.append(route.kind).append('\t').append(route.feNodeUuid)
                    .append('\t').append(route.endpoint).append("\ttrue\n");
        }
        return new FullPlanResult(new InstallationPlan(
                frontends, backends, account, routes), canonical.toString());
    }

    private static List<FrontendMember> parseFrontends(List<FrontendWire> values,
            MassDbLicenseIngressInventory inventory) {
        List<FrontendWire> sorted = new ArrayList<>(values);
        for (FrontendWire value : sorted) {
            if (value == null || value.nodeUuid == null) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "FE成员或nodeUuid不能为空");
            }
        }
        Collections.sort(sorted, Comparator.comparing(value -> value.nodeUuid));
        Set<String> nodes = new HashSet<>();
        Set<String> editEndpoints = new HashSet<>();
        List<FrontendMember> result = new ArrayList<>();
        int masters = 0;
        for (FrontendWire value : sorted) {
            requireUuidV4(value.nodeUuid);
            requireHost(value.host, "FE host");
            requirePort(value.editLogPort, "FE editLogPort");
            requirePort(value.queryPort, "FE queryPort");
            requirePort(value.httpsPort, "FE httpsPort");
            if (!"MASTER".equals(value.role) && !"FOLLOWER".equals(value.role)
                    && !"OBSERVER".equals(value.role)) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "FE role非法");
            }
            if ("MASTER".equals(value.role)) {
                masters++;
            }
            String expectedIngress = httpsEndpoint(value.host, value.httpsPort);
            MassDbLicenseIngressInventory.IngressNode ingress =
                    inventory.getNodes().get(value.nodeUuid);
            if (ingress == null || !expectedIngress.equals(ingress.getEndpoint())
                    || !nodes.add(value.nodeUuid)
                    || !editEndpoints.add(value.host + "\t" + value.editLogPort)) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID",
                        "FE成员必须与唯一desired HTTPS入口精确对应");
            }
            result.add(new FrontendMember(value.nodeUuid, value.role, value.host,
                    value.editLogPort, value.queryPort, value.httpsPort));
        }
        if (masters != 1 || nodes.size() != inventory.getNodes().size()) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID",
                    "v2 plan必须且只能包含一个MASTER并覆盖全部入口FE");
        }
        return Collections.unmodifiableList(result);
    }

    private static List<BackendMember> parseBackends(List<BackendWire> values,
            Set<String> allNodeUuids) {
        List<BackendWire> sorted = new ArrayList<>(values);
        for (BackendWire value : sorted) {
            if (value == null || value.nodeUuid == null) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "BE成员或nodeUuid不能为空");
            }
        }
        Collections.sort(sorted, Comparator.comparing(value -> value.nodeUuid));
        Set<String> heartbeatEndpoints = new HashSet<>();
        List<BackendMember> result = new ArrayList<>();
        for (BackendWire value : sorted) {
            requireUuidV4(value.nodeUuid);
            requireHost(value.host, "BE host");
            requirePort(value.heartbeatPort, "BE heartbeatPort");
            requirePort(value.bePort, "BE bePort");
            requirePort(value.httpPort, "BE httpPort");
            requirePort(value.brpcPort, "BE brpcPort");
            if (!allNodeUuids.add(value.nodeUuid)
                    || !heartbeatEndpoints.add(value.host + "\t" + value.heartbeatPort)) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "BE UUID或heartbeat endpoint重复");
            }
            result.add(new BackendMember(value.nodeUuid, value.host,
                    value.heartbeatPort, value.bePort, value.httpPort, value.brpcPort));
        }
        return Collections.unmodifiableList(result);
    }

    private static IngestAccount parseIngestAccount(IngestAccountWire value) {
        if (!"massdb_ingest".equals(value.username)
                || value.hostPattern == null
                || !value.hostPattern.matches("[A-Za-z0-9._:%-]{1,255}")
                || !"GLOBAL_LOAD_ONLY".equals(value.privilege)) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID",
                    "纯写账号必须是massdb_ingest且只授予GLOBAL_LOAD_ONLY");
        }
        byte[] passwordHash;
        try {
            passwordHash = Base64.getDecoder().decode(value.passwordHashBase64);
        } catch (NullPointerException | IllegalArgumentException failure) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "纯写账号密码hash base64非法");
            return null;
        }
        String canonicalBase64 = Base64.getEncoder().encodeToString(passwordHash);
        String passwordText = new String(passwordHash, StandardCharsets.US_ASCII);
        if (!canonicalBase64.equals(value.passwordHashBase64)
                || !passwordText.matches("\\*[0-9A-F]{40}")) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID",
                    "纯写账号只能携带canonical MySQL 4.1 password hash");
        }
        return new IngestAccount(value.username, value.hostPattern, value.privilege,
                passwordHash, sha256(passwordHash));
    }

    private static List<IngestRoute> parseIngestRoutes(List<IngestRouteWire> values,
            List<FrontendMember> frontends, MassDbLicenseIngressInventory inventory) {
        List<IngestRouteWire> sorted = new ArrayList<>(values);
        for (IngestRouteWire value : sorted) {
            if (value == null || value.feNodeUuid == null || value.endpoint == null) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "入库路由字段不能为空");
            }
        }
        Collections.sort(sorted, Comparator
                .comparing((IngestRouteWire value) -> value.feNodeUuid)
                .thenComparing(value -> value.endpoint));
        Set<String> frontendNodes = new HashSet<>();
        String masterNode = null;
        for (FrontendMember frontend : frontends) {
            frontendNodes.add(frontend.nodeUuid);
            if ("MASTER".equals(frontend.role)) {
                masterNode = frontend.nodeUuid;
            }
        }
        Set<String> routeNodes = new HashSet<>();
        List<IngestRoute> result = new ArrayList<>();
        for (IngestRouteWire value : sorted) {
            requireUuidV4(value.feNodeUuid);
            requireHttpsEndpoint(value.endpoint);
            MassDbLicenseIngressInventory.IngressNode ingress =
                    inventory.getNodes().get(value.feNodeUuid);
            if (!value.desired || !"STREAM_LOAD_HTTPS".equals(value.kind)
                    || !frontendNodes.contains(value.feNodeUuid)
                    || ingress == null || !value.endpoint.equals(ingress.getEndpoint())
                    || !routeNodes.add(value.feNodeUuid)) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID",
                        "入库路由必须是唯一FE上的desired STREAM_LOAD_HTTPS");
            }
            result.add(new IngestRoute(value.kind, value.feNodeUuid, value.endpoint));
        }
        if (routeNodes.size() != 1 || !routeNodes.contains(masterNode)) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID",
                    "v2首启只允许当前MASTER的一条STREAM_LOAD_HTTPS路由");
        }
        return Collections.unmodifiableList(result);
    }

    private static byte[] decodeKeyset(String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "keysetArtifactBase64不能为空");
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(encoded);
            if (decoded.length == 0 || decoded.length > MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES
                    || !encoded.equals(Base64.getEncoder().encodeToString(decoded))) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "keyset base64非canonical或超过上限");
            }
            return decoded;
        } catch (IllegalArgumentException failure) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "keyset base64非法");
            return null;
        }
    }

    private static void requireHttpsEndpoint(String value) {
        try {
            URI endpoint = new URI(value);
            if (!"https".equals(endpoint.getScheme()) || endpoint.getHost() == null
                    || endpoint.getPort() <= 0 || endpoint.getUserInfo() != null
                    || endpoint.getQuery() != null || endpoint.getFragment() != null
                    || (endpoint.getPath() != null && !endpoint.getPath().isEmpty())
                    || !endpoint.toASCIIString().equals(value)) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID",
                        "入口endpoint必须是无path的canonical HTTPS host:port");
            }
        } catch (NullPointerException | URISyntaxException failure) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "入口endpoint非法");
        }
    }

    private static void requireHost(String value, String label) {
        if (value == null || value.isEmpty() || value.length() > 253
                || !value.equals(value.trim())
                || !value.equals(value.toLowerCase(Locale.ROOT))
                || !value.matches("[a-z0-9._:-]+") || value.contains("..")
                || value.startsWith(".") || value.endsWith(".")) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID",
                    label + "必须是canonical ASCII host/IP");
        }
    }

    private static void requirePort(int value, String label) {
        if (value <= 0 || value > 65535) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", label + "必须在1至65535之间");
        }
    }

    private static String httpsEndpoint(String host, int port) {
        String endpoint = "https://" + (host.indexOf(':') >= 0 ? "[" + host + "]" : host)
                + ":" + port;
        requireHttpsEndpoint(endpoint);
        return endpoint;
    }

    private static void requireUuidV4(String value) {
        try {
            UUID uuid = UUID.fromString(value);
            if (uuid.version() != 4 || !uuid.toString().equals(value)) {
                fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "入口nodeUuid必须是canonical UUIDv4");
            }
        } catch (NullPointerException | IllegalArgumentException failure) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "入口nodeUuid必须是canonical UUIDv4");
        }
    }

    private static String requestHash(ParsedPlan plan) {
        return sha256(("BOOTSTRAP_CONTROL\nSEAL\n" + plan.planSha256 + "\n"
                + plan.keysetSha256 + "\n" + plan.inventory.configuredDigest() + "\n"
                + plan.minimumWriteHealth).getBytes(StandardCharsets.US_ASCII));
    }

    private static void requireContentDigest(String supplied, byte[] planBytes) {
        if (supplied == null || !supplied.matches("[0-9a-fA-F]{64}")
                || !MessageDigest.isEqual(supplied.toLowerCase(Locale.ROOT)
                                .getBytes(StandardCharsets.US_ASCII),
                        sha256(planBytes).getBytes(StandardCharsets.US_ASCII))) {
            fail("MASSDB_LICENSE_CONTENT_SHA256_MISMATCH", "Content-SHA256与bootstrap plan不一致");
        }
    }

    private static MassDbLicenseState requireState(MassDbLicenseState state) {
        if (state == null) {
            fail("MASSDB_LICENSE_MANAGEMENT_API_UNAVAILABLE", "License state未就绪");
        }
        return state;
    }

    private static String sha256(byte[] value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            StringBuilder result = new StringBuilder(64);
            for (byte item : digest) {
                result.append(String.format(Locale.ROOT, "%02x", item & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    public static final class Plan {
        public int formatVersion;
        public String componentType;
        public String targetPhase;
        public String keysetArtifactBase64;
        public List<Ingress> ingressNodes;
        public String minimumWriteHealth;
        public List<FrontendWire> frontends;
        public List<BackendWire> backends;
        public IngestAccountWire ingestAccount;
        public List<IngestRouteWire> ingestRoutes;

        public Plan() {
        }
    }

    public static final class Ingress {
        public String nodeUuid;
        public String endpoint;
        public boolean desired;

        public Ingress() {
        }
    }

    public static final class FrontendWire {
        public String nodeUuid;
        public String role;
        public String host;
        public int editLogPort;
        public int queryPort;
        public int httpsPort;

        public FrontendWire() {
        }
    }

    public static final class BackendWire {
        public String nodeUuid;
        public String host;
        public int heartbeatPort;
        public int bePort;
        public int httpPort;
        public int brpcPort;

        public BackendWire() {
        }
    }

    public static final class IngestAccountWire {
        public String username;
        public String hostPattern;
        public String passwordHashBase64;
        public String privilege;

        public IngestAccountWire() {
        }
    }

    public static final class IngestRouteWire {
        public String kind;
        public String feNodeUuid;
        public String endpoint;
        public boolean desired;

        public IngestRouteWire() {
        }
    }

    /** Strict, canonicalized v2 plan passed only to the component-native runtime. */
    public static final class InstallationPlan {
        private final List<FrontendMember> frontends;
        private final List<BackendMember> backends;
        private final IngestAccount ingestAccount;
        private final List<IngestRoute> ingestRoutes;

        private InstallationPlan(List<FrontendMember> frontends,
                List<BackendMember> backends, IngestAccount ingestAccount,
                List<IngestRoute> ingestRoutes) {
            this.frontends = frontends;
            this.backends = backends;
            this.ingestAccount = ingestAccount;
            this.ingestRoutes = ingestRoutes;
        }

        public List<FrontendMember> getFrontends() {
            return frontends;
        }

        public List<BackendMember> getBackends() {
            return backends;
        }

        public IngestAccount getIngestAccount() {
            return ingestAccount;
        }

        public List<IngestRoute> getIngestRoutes() {
            return ingestRoutes;
        }
    }

    public static final class FrontendMember {
        public final String nodeUuid;
        public final String role;
        public final String host;
        public final int editLogPort;
        public final int queryPort;
        public final int httpsPort;

        private FrontendMember(String nodeUuid, String role, String host,
                int editLogPort, int queryPort, int httpsPort) {
            this.nodeUuid = nodeUuid;
            this.role = role;
            this.host = host;
            this.editLogPort = editLogPort;
            this.queryPort = queryPort;
            this.httpsPort = httpsPort;
        }
    }

    public static final class BackendMember {
        public final String nodeUuid;
        public final String host;
        public final int heartbeatPort;
        public final int bePort;
        public final int httpPort;
        public final int brpcPort;

        private BackendMember(String nodeUuid, String host, int heartbeatPort,
                int bePort, int httpPort, int brpcPort) {
            this.nodeUuid = nodeUuid;
            this.host = host;
            this.heartbeatPort = heartbeatPort;
            this.bePort = bePort;
            this.httpPort = httpPort;
            this.brpcPort = brpcPort;
        }
    }

    public static final class IngestAccount {
        public final String username;
        public final String hostPattern;
        public final String privilege;
        public final String passwordHashSha256;
        private final byte[] passwordHash;

        private IngestAccount(String username, String hostPattern, String privilege,
                byte[] passwordHash, String passwordHashSha256) {
            this.username = username;
            this.hostPattern = hostPattern;
            this.privilege = privilege;
            this.passwordHash = passwordHash.clone();
            this.passwordHashSha256 = passwordHashSha256;
        }

        public byte[] getPasswordHash() {
            return passwordHash.clone();
        }

        public String getQualifiedName() {
            return "'" + username + "'@'" + hostPattern + "'";
        }
    }

    public static final class IngestRoute {
        public final String kind;
        public final String feNodeUuid;
        public final String endpoint;

        private IngestRoute(String kind, String feNodeUuid, String endpoint) {
            this.kind = kind;
            this.feNodeUuid = feNodeUuid;
            this.endpoint = endpoint;
        }
    }

    private static final class IngressResult {
        private final MassDbLicenseIngressInventory inventory;
        private final String canonical;

        private IngressResult(MassDbLicenseIngressInventory inventory, String canonical) {
            this.inventory = inventory;
            this.canonical = canonical;
        }
    }

    private static final class FullPlanResult {
        private final InstallationPlan installationPlan;
        private final String canonical;

        private FullPlanResult(InstallationPlan installationPlan, String canonical) {
            this.installationPlan = installationPlan;
            this.canonical = canonical;
        }
    }

    private static final class ParsedPlan {
        private final int formatVersion;
        private final String minimumWriteHealth;
        private final byte[] keysetArtifact;
        private final String keysetSha256;
        private final MassDbLicenseIngressInventory inventory;
        private final String planSha256;
        private final InstallationPlan installationPlan;

        private ParsedPlan(int formatVersion, String minimumWriteHealth,
                byte[] keysetArtifact, String keysetSha256,
                MassDbLicenseIngressInventory inventory, String planSha256,
                InstallationPlan installationPlan) {
            this.formatVersion = formatVersion;
            this.minimumWriteHealth = minimumWriteHealth;
            this.keysetArtifact = keysetArtifact;
            this.keysetSha256 = keysetSha256;
            this.inventory = inventory;
            this.planSha256 = planSha256;
            this.installationPlan = installationPlan;
        }
    }
}
