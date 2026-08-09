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
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Existing-cluster fence that requires a fresh mTLS proof from every persisted FE. */
public final class MassDbLicenseUpgradeCore {
    public static final int MAX_UPGRADE_PLAN_BYTES = 128 * 1024;
    public static final int MAX_FRONTENDS = 128;
    public static final long MAX_ATTESTATION_SKEW_SECONDS = 120;
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT);
    private static final SecureRandom RANDOM = new SecureRandom();

    public interface ClusterView {
        boolean isReadyLeader();

        boolean hasExistingBusinessMetadata();

        String localNodeUuid();

        List<PersistentFrontend> persistentFrontends();
    }

    public interface AttestationClient {
        MassDbLicenseUpgradeProtocol.Response attest(UpgradeFrontend frontend,
                MassDbLicenseUpgradeProtocol.Request request, long now) throws Exception;
    }

    public static final class PersistentFrontend {
        public final String role;
        public final String host;
        public final int editLogPort;

        public PersistentFrontend(String role, String host, int editLogPort) {
            this.role = role;
            this.host = host;
            this.editLogPort = editLogPort;
        }
    }

    public static final class UpgradeFrontend {
        public final String nodeUuid;
        public final String role;
        public final String host;
        public final int editLogPort;
        public final String httpsEndpoint;

        private UpgradeFrontend(String nodeUuid, String role, String host,
                int editLogPort, String httpsEndpoint) {
            this.nodeUuid = nodeUuid;
            this.role = role;
            this.host = host;
            this.editLogPort = editLogPort;
            this.httpsEndpoint = httpsEndpoint;
        }
    }

    public static final class PlanSummary {
        public final String planSha256;
        public final String membershipSha256;
        public final String keysetSha256;
        public final String inventorySha256;
        public final String minimumEnforcementVersion;
        public final int requiredFrontends;
        public final MassDbLicenseBuildIdentity requiredBuild;
        private final List<UpgradeFrontend> frontends;

        private PlanSummary(ParsedPlan plan) {
            this.planSha256 = plan.planSha256;
            this.membershipSha256 = plan.membershipSha256;
            this.keysetSha256 = plan.keysetSha256;
            this.inventorySha256 = plan.inventory.configuredDigest();
            this.minimumEnforcementVersion = plan.requiredBuild.componentVersion;
            this.requiredFrontends = plan.frontends.size();
            this.requiredBuild = plan.requiredBuild;
            this.frontends = immutableCopy(plan.frontends);
        }

        public boolean containsNodeUuid(String nodeUuid) {
            for (UpgradeFrontend frontend : frontends) {
                if (frontend.nodeUuid.equals(nodeUuid)) {
                    return true;
                }
            }
            return false;
        }
    }

    public static final class ValidateResult {
        public final boolean readyForApply;
        public final String action;
        public final String targetMode;
        public final String upgradeSessionId;
        public final String licenseControlDeploymentUuid;
        public final String planSha256;
        public final String membershipSha256;
        public final String keysetSha256;
        public final String inventorySha256;
        public final String minimumEnforcementVersion;
        public final int requiredFrontends;
        public final int attestedFrontends;
        public final String attestationSha256;
        public final String preconditionToken;
        public final long tokenExpiresAt;

        private ValidateResult(MassDbLicenseUpgradeMarker.Attestation marker,
                ParsedPlan plan, AttestationSet attestations,
                String token, long tokenExpiresAt) {
            this.readyForApply = true;
            this.action = "INITIALIZE_OBSERVE";
            this.targetMode = "OBSERVE";
            this.upgradeSessionId = marker.upgradeSessionId;
            this.licenseControlDeploymentUuid = marker.licenseControlDeploymentUuid;
            this.planSha256 = plan.planSha256;
            this.membershipSha256 = plan.membershipSha256;
            this.keysetSha256 = plan.keysetSha256;
            this.inventorySha256 = plan.inventory.configuredDigest();
            this.minimumEnforcementVersion = plan.requiredBuild.componentVersion;
            this.requiredFrontends = plan.frontends.size();
            this.attestedFrontends = attestations.count;
            this.attestationSha256 = attestations.sha256;
            this.preconditionToken = token;
            this.tokenExpiresAt = tokenExpiresAt;
        }
    }

    public static final class PreparedApply {
        private final ParsedPlan plan;
        private final String requestHash;
        private final String attestationSha256;
        private final String replayOperationId;

        private PreparedApply(ParsedPlan plan, String requestHash,
                String attestationSha256, String replayOperationId) {
            this.plan = plan;
            this.requestHash = requestHash;
            this.attestationSha256 = attestationSha256;
            this.replayOperationId = replayOperationId;
        }

        public boolean isReplay() {
            return replayOperationId != null;
        }

        public String getReplayOperationId() {
            return replayOperationId;
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

    private final MassDbLicenseImportCore importCore;
    private final MassDbLicenseUpgradeMarker.Attestation marker;
    private final MassDbLicenseBuildIdentity localBuild;
    private final ClusterView cluster;
    private final AttestationClient attestationClient;

    public MassDbLicenseUpgradeCore(MassDbLicenseImportCore importCore,
            MassDbLicenseUpgradeMarker.Attestation marker,
            MassDbLicenseBuildIdentity localBuild, ClusterView cluster,
            AttestationClient attestationClient) {
        if (importCore == null || localBuild == null || cluster == null
                || attestationClient == null) {
            throw new IllegalArgumentException("upgrade core依赖不能为空");
        }
        this.importCore = importCore;
        this.marker = marker;
        this.localBuild = localBuild;
        this.cluster = cluster;
        this.attestationClient = attestationClient;
    }

    public static PlanSummary summarize(byte[] planBytes) {
        return new PlanSummary(parse(planBytes));
    }

    public ValidateResult validate(MassDbLicenseState state, byte[] planBytes, long now) {
        ParsedPlan plan = requireReady(state, planBytes, now);
        AttestationSet attestations = collectAttestations(plan, now);
        long expiresAt = saturatedAdd(now, MassDbLicenseUpgradeToken.MAX_TTL_SECONDS);
        MassDbLicenseUpgradeToken.Claims claims = new MassDbLicenseUpgradeToken.Claims(
                marker.upgradeSessionId, marker.licenseControlDeploymentUuid,
                plan.planSha256, plan.membershipSha256, plan.keysetSha256,
                plan.inventory.configuredDigest(), attestations.sha256, now, expiresAt,
                UUID.randomUUID().toString());
        String token = MassDbLicenseUpgradeToken.issue(
                marker.preconditionHmacKey(), claims);
        return new ValidateResult(marker, plan, attestations, token, expiresAt);
    }

    public PreparedApply prepareApply(MassDbLicenseState state, byte[] planBytes,
            String contentSha256, String preconditionToken,
            String idempotencyKey, long now) {
        requireContentDigest(contentSha256, planBytes);
        ParsedPlan plan = parse(planBytes);
        String requestHash = requestHashForReplay(state, plan);
        String replay = state.findOperationIdByIdempotency(idempotencyKey, requestHash);
        if (replay != null) {
            return new PreparedApply(plan, requestHash, null, replay);
        }
        ParsedPlan ready = requireReady(state, planBytes, now);
        MassDbLicenseUpgradeToken.Claims claims = MassDbLicenseUpgradeToken.verify(
                marker.preconditionHmacKey(), preconditionToken, now);
        if (!claims.upgradeSessionId.equals(marker.upgradeSessionId)
                || !claims.deploymentUuid.equals(marker.licenseControlDeploymentUuid)
                || !claims.planSha256.equals(ready.planSha256)
                || !claims.membershipSha256.equals(ready.membershipSha256)
                || !claims.keysetSha256.equals(ready.keysetSha256)
                || !claims.inventorySha256.equals(ready.inventory.configuredDigest())) {
            fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED",
                    "upgrade token与当前marker、plan或成员关系不匹配");
        }
        AttestationSet attestations = collectAttestations(ready, now);
        return new PreparedApply(ready, requestHash, attestations.sha256, null);
    }

    public ApplyResult commit(MassDbLicenseState state, PreparedApply prepared,
            String idempotencyKey, String operationId, long now) {
        if (prepared == null) {
            fail("MASSDB_LICENSE_UPGRADE_PRECONDITION_FAILED", "upgrade准备结果为空");
        }
        if (prepared.replayOperationId != null) {
            return new ApplyResult(state, prepared.replayOperationId, true);
        }
        requireClusterState(state, prepared.plan, now);
        MassDbLicenseProtocolV1.VerifiedKeyset verified =
                importCore.verifyControlPlaneKeyset(prepared.plan.keysetArtifact, now);
        MassDbLicenseState.ActiveKeyset keyset = new MassDbLicenseState.ActiveKeyset(
                verified.getPayload().getKeysetVersion(), verified.getSha256(),
                prepared.plan.keysetArtifact);
        MassDbLicenseState initialized = state.initializeObserve(
                operationId, idempotencyKey, prepared.requestHash,
                marker.upgradeSessionId, marker.licenseControlDeploymentUuid,
                prepared.plan.planSha256, marker.createdAt,
                prepared.plan.requiredBuild.componentVersion,
                prepared.attestationSha256, keyset,
                prepared.plan.inventory, now);
        return new ApplyResult(initialized, operationId, false);
    }

    public MassDbLicenseUpgradeProtocol.Response attestLocal(
            MassDbLicenseState state, MassDbLicenseSpiffeIdentity.Identity authenticatedClient,
            String localIdentityNodeUuid, MassDbLicenseUpgradeProtocol.Request request,
            long now) {
        MassDbLicenseUpgradeMarker.Attestation localMarker = markerRequired();
        if (state == null || state.isInitialized()) {
            fail("MASSDB_LICENSE_UPGRADE_ALREADY_INITIALIZED",
                    "License一致性状态已经初始化");
        }
        if (authenticatedClient == null || request == null
                || request.protocolVersion != MassDbLicenseUpgradeProtocol.VERSION
                || !"massdb-sql".equals(authenticatedClient.component)
                || !"fe".equals(authenticatedClient.role)
                || !localMarker.licenseControlDeploymentUuid.equals(
                        authenticatedClient.deploymentUuid)
                || !authenticatedClient.nodeUuid.equals(request.requesterNodeUuid)) {
            fail("MASSDB_LICENSE_MTLS_IDENTITY_MISMATCH",
                    "upgrade attestation请求与FE mTLS身份不匹配");
        }
        validateUuid(request.upgradeSessionId, "upgradeSessionId");
        validateUuid(request.deploymentUuid, "deploymentUuid");
        validateUuid(request.requesterNodeUuid, "requesterNodeUuid");
        validateUuid(request.expectedNodeUuid, "expectedNodeUuid");
        requireSha256(request.planSha256, "planSha256");
        requireSha256(request.membershipSha256, "membershipSha256");
        requireSha256(request.challenge, "challenge");
        if (request.requestedAt <= 0
                || absoluteDifference(request.requestedAt, now)
                        > MAX_ATTESTATION_SKEW_SECONDS) {
            fail("MASSDB_LICENSE_UPGRADE_ATTESTATION_STALE",
                    "upgrade attestation challenge超出允许时间窗口");
        }
        if (!localMarker.upgradeSessionId.equals(request.upgradeSessionId)
                || !localMarker.licenseControlDeploymentUuid.equals(request.deploymentUuid)
                || !localMarker.upgradePlanSha256.equals(request.planSha256)
                || !localMarker.localNodeUuid.equals(request.expectedNodeUuid)
                || !localMarker.localNodeUuid.equals(localIdentityNodeUuid)
                || !localBuild.sameAs(localMarker.buildIdentity)) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_MISMATCH",
                    "本FE marker、身份、构建或请求不匹配");
        }
        String membership = currentMembershipSha256();
        if (!membership.equals(request.membershipSha256)) {
            fail("MASSDB_LICENSE_UPGRADE_MEMBERSHIP_CHANGED",
                    "本FE持久成员关系与upgrade plan不一致");
        }
        return new MassDbLicenseUpgradeProtocol.Response(localMarker, localBuild,
                membership, request.challenge, now);
    }

    private ParsedPlan requireReady(MassDbLicenseState state, byte[] planBytes, long now) {
        ParsedPlan plan = parse(planBytes);
        requireClusterState(state, plan, now);
        importCore.verifyControlPlaneKeyset(plan.keysetArtifact, now);
        return plan;
    }

    private void requireClusterState(MassDbLicenseState state, ParsedPlan plan, long now) {
        if (state == null || state.isInitialized()) {
            fail("MASSDB_LICENSE_UPGRADE_ALREADY_INITIALIZED",
                    "License一致性状态已经初始化");
        }
        MassDbLicenseUpgradeMarker.Attestation localMarker = markerRequired();
        if (now <= 0 || !cluster.isReadyLeader()) {
            fail("MASSDB_LICENSE_NOT_LEADER", "upgrade只能由就绪的FE Leader执行");
        }
        if (!cluster.hasExistingBusinessMetadata()) {
            fail("MASSDB_LICENSE_UPGRADE_NOT_EXISTING_CLUSTER",
                    "upgrade只接受确有既有业务元数据的存量集群");
        }
        if (!localMarker.upgradePlanSha256.equals(plan.planSha256)
                || !localMarker.localNodeUuid.equals(cluster.localNodeUuid())
                || !localBuild.sameAs(localMarker.buildIdentity)
                || !localBuild.sameAs(plan.requiredBuild)) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_MISMATCH",
                    "Leader本地marker、节点身份、构建或plan不匹配");
        }
        requireExactMembership(plan);
    }

    private AttestationSet collectAttestations(ParsedPlan plan, long now) {
        String requesterNodeUuid = cluster.localNodeUuid();
        StringBuilder canonical = new StringBuilder();
        int count = 0;
        for (UpgradeFrontend frontend : plan.frontends) {
            String challenge = randomSha256();
            MassDbLicenseUpgradeProtocol.Request request =
                    new MassDbLicenseUpgradeProtocol.Request(
                            marker.upgradeSessionId,
                            marker.licenseControlDeploymentUuid,
                            plan.planSha256, plan.membershipSha256,
                            requesterNodeUuid, frontend.nodeUuid, challenge, now);
            final MassDbLicenseUpgradeProtocol.Response response;
            try {
                response = attestationClient.attest(frontend, request, now);
            } catch (MassDbLicenseException failure) {
                throw failure;
            } catch (Exception failure) {
                fail("MASSDB_LICENSE_UPGRADE_ATTESTATION_FAILED",
                        "无法取得全部持久FE的mTLS升级证明");
                return null;
            }
            validateResponse(frontend, request, response, plan, now);
            canonical.append(frontend.nodeUuid).append('\t')
                    .append(response.challenge).append('\t')
                    .append(response.observedAt).append('\t')
                    .append(response.componentVersion).append('\t')
                    .append(response.capabilityVersion).append('\t')
                    .append(response.stateFormatVersion).append('\t')
                    .append(response.journalOperationType).append('\t')
                    .append(response.snapshotFormat).append('\t')
                    .append(response.binarySha256).append('\n');
            count++;
        }
        return new AttestationSet(count,
                sha256(canonical.toString().getBytes(StandardCharsets.UTF_8)));
    }

    private void validateResponse(UpgradeFrontend frontend,
            MassDbLicenseUpgradeProtocol.Request request,
            MassDbLicenseUpgradeProtocol.Response response,
            ParsedPlan plan, long now) {
        if (response == null
                || response.protocolVersion != MassDbLicenseUpgradeProtocol.VERSION
                || !marker.upgradeSessionId.equals(response.upgradeSessionId)
                || !marker.licenseControlDeploymentUuid.equals(response.deploymentUuid)
                || !plan.planSha256.equals(response.planSha256)
                || !plan.membershipSha256.equals(response.membershipSha256)
                || !frontend.nodeUuid.equals(response.nodeUuid)
                || !request.challenge.equals(response.challenge)
                || response.observedAt <= 0
                || absoluteDifference(response.observedAt, now)
                        > MAX_ATTESTATION_SKEW_SECONDS
                || !plan.requiredBuild.componentType.equals(response.componentType)
                || !plan.requiredBuild.componentVersion.equals(response.componentVersion)
                || !plan.requiredBuild.capabilityVersion.equals(response.capabilityVersion)
                || plan.requiredBuild.stateFormatVersion != response.stateFormatVersion
                || plan.requiredBuild.journalOperationType != response.journalOperationType
                || !plan.requiredBuild.snapshotFormat.equals(response.snapshotFormat)
                || !plan.requiredBuild.binarySha256.equals(response.binarySha256)) {
            fail("MASSDB_LICENSE_UPGRADE_ATTESTATION_MISMATCH",
                    "FE mTLS升级证明与目标节点、challenge或精确构建不匹配");
        }
    }

    private void requireExactMembership(ParsedPlan plan) {
        List<PersistentFrontend> actual = safeFrontends(cluster.persistentFrontends());
        if (actual.size() != plan.frontends.size()) {
            fail("MASSDB_LICENSE_UPGRADE_MEMBERSHIP_CHANGED",
                    "持久FE成员数量与upgrade plan不一致");
        }
        Map<String, UpgradeFrontend> expected = new LinkedHashMap<>();
        for (UpgradeFrontend frontend : plan.frontends) {
            expected.put(memberKey(frontend.host, frontend.editLogPort), frontend);
        }
        for (PersistentFrontend frontend : actual) {
            UpgradeFrontend planned = expected.remove(
                    memberKey(frontend.host, frontend.editLogPort));
            if (planned == null || !planned.role.equals(frontend.role)) {
                fail("MASSDB_LICENSE_UPGRADE_MEMBERSHIP_CHANGED",
                        "持久FE成员地址或角色与upgrade plan不一致");
            }
        }
        if (!expected.isEmpty()
                || !plan.membershipSha256.equals(membershipSha256(actual))) {
            fail("MASSDB_LICENSE_UPGRADE_MEMBERSHIP_CHANGED",
                    "持久FE成员摘要与upgrade plan不一致");
        }
    }

    private String currentMembershipSha256() {
        List<PersistentFrontend> actual = safeFrontends(cluster.persistentFrontends());
        if (actual.isEmpty()) {
            fail("MASSDB_LICENSE_UPGRADE_MEMBERSHIP_CHANGED", "持久FE成员关系为空");
        }
        return membershipSha256(actual);
    }

    private MassDbLicenseUpgradeMarker.Attestation markerRequired() {
        if (marker == null || !marker.isEligible()) {
            fail("MASSDB_LICENSE_UPGRADE_MARKER_REQUIRED",
                    marker == null ? "未配置组件本地upgrade marker"
                            : "组件本地upgrade marker不可用: " + marker.reasonCode);
        }
        return marker;
    }

    private static ParsedPlan parse(byte[] encoded) {
        if (encoded == null || encoded.length == 0
                || encoded.length > MAX_UPGRADE_PLAN_BYTES) {
            fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID",
                    "upgrade plan为空或超过131072字节");
        }
        final Plan wire;
        try {
            wire = MAPPER.readValue(encoded, Plan.class);
        } catch (IOException failure) {
            fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", "upgrade plan JSON非法");
            return null;
        }
        if (wire == null || wire.formatVersion != 1
                || !"massdb-sql".equals(wire.componentType)
                || !"OBSERVE".equals(wire.targetMode)
                || wire.requiredBuild == null || wire.frontends == null
                || wire.frontends.isEmpty() || wire.frontends.size() > MAX_FRONTENDS) {
            fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", "upgrade plan固定字段或成员数量非法");
        }
        MassDbLicenseBuildIdentity build = parseBuild(wire.requiredBuild);
        byte[] keyset = decodeKeyset(wire.keysetArtifactBase64);
        String keysetSha256 = sha256(keyset);
        List<FrontendWire> sorted = new ArrayList<>(wire.frontends);
        for (FrontendWire frontend : sorted) {
            if (frontend == null || frontend.host == null) {
                fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", "upgrade FE成员为空");
            }
        }
        sorted.sort(Comparator.comparing((FrontendWire value) -> value.host)
                .thenComparingInt(value -> value.editLogPort));
        List<UpgradeFrontend> frontends = new ArrayList<>();
        MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty();
        Set<String> nodes = new HashSet<>();
        Set<String> memberKeys = new HashSet<>();
        Set<String> endpoints = new HashSet<>();
        StringBuilder canonicalMembers = new StringBuilder();
        StringBuilder canonicalPlanNodes = new StringBuilder();
        for (FrontendWire frontend : sorted) {
            validateUuid(frontend.nodeUuid, "nodeUuid");
            if (!"VOTER".equals(frontend.role) && !"OBSERVER".equals(frontend.role)) {
                fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", "FE role只允许VOTER或OBSERVER");
            }
            requireHost(frontend.host);
            requirePort(frontend.editLogPort, "editLogPort");
            requireHttpsEndpoint(frontend.httpsEndpoint, frontend.host);
            String memberKey = memberKey(frontend.host, frontend.editLogPort);
            if (!nodes.add(frontend.nodeUuid) || !memberKeys.add(memberKey)
                    || !endpoints.add(frontend.httpsEndpoint)) {
                fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID",
                        "FE node UUID、成员地址或HTTPS endpoint重复");
            }
            inventory = inventory.upsertConfigured(
                    frontend.nodeUuid, frontend.httpsEndpoint, true);
            frontends.add(new UpgradeFrontend(frontend.nodeUuid, frontend.role,
                    frontend.host, frontend.editLogPort, frontend.httpsEndpoint));
            canonicalMembers.append(frontend.role).append('\t')
                    .append(frontend.host).append('\t')
                    .append(frontend.editLogPort).append('\n');
            canonicalPlanNodes.append(frontend.nodeUuid).append('\t')
                    .append(frontend.role).append('\t').append(frontend.host).append('\t')
                    .append(frontend.editLogPort).append('\t')
                    .append(frontend.httpsEndpoint).append("\ttrue\n");
        }
        String membershipSha256 = sha256(
                canonicalMembers.toString().getBytes(StandardCharsets.UTF_8));
        String canonical = "1\nmassdb-sql\nOBSERVE\n" + keysetSha256 + "\n"
                + build.componentVersion + "\n" + build.capabilityVersion + "\n"
                + build.stateFormatVersion + "\n" + build.journalOperationType + "\n"
                + build.snapshotFormat + "\n" + build.binarySha256 + "\n"
                + membershipSha256 + "\n" + inventory.configuredDigest() + "\n"
                + canonicalPlanNodes;
        return new ParsedPlan(keyset, keysetSha256, build, frontends, inventory,
                membershipSha256,
                sha256(canonical.getBytes(StandardCharsets.UTF_8)));
    }

    private static MassDbLicenseBuildIdentity parseBuild(BuildWire wire) {
        if (!"massdb-sql".equals(wire.componentType)) {
            fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", "requiredBuild组件类型非法");
        }
        return new MassDbLicenseBuildIdentity(wire.componentVersion,
                wire.capabilityVersion, wire.stateFormatVersion,
                wire.journalOperationType, wire.snapshotFormat,
                requireSha256(wire.binarySha256, "binarySha256"));
    }

    private static byte[] decodeKeyset(String value) {
        if (value == null || value.isEmpty()) {
            fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", "keyset工件为空");
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            if (decoded.length == 0
                    || decoded.length > MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES
                    || !Base64.getEncoder().encodeToString(decoded).equals(value)) {
                fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", "keyset base64不是canonical编码");
            }
            return decoded;
        } catch (IllegalArgumentException failure) {
            fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", "keyset base64非法");
            return null;
        }
    }

    private static String membershipSha256(List<PersistentFrontend> frontends) {
        List<PersistentFrontend> sorted = new ArrayList<>(frontends);
        sorted.sort(Comparator.comparing((PersistentFrontend value) -> value.host)
                .thenComparingInt(value -> value.editLogPort));
        Set<String> keys = new HashSet<>();
        StringBuilder canonical = new StringBuilder();
        for (PersistentFrontend frontend : sorted) {
            if (frontend == null
                    || (!"VOTER".equals(frontend.role)
                            && !"OBSERVER".equals(frontend.role))) {
                fail("MASSDB_LICENSE_UPGRADE_MEMBERSHIP_CHANGED", "持久FE成员角色非法");
            }
            requireHost(frontend.host);
            requirePort(frontend.editLogPort, "editLogPort");
            if (!keys.add(memberKey(frontend.host, frontend.editLogPort))) {
                fail("MASSDB_LICENSE_UPGRADE_MEMBERSHIP_CHANGED", "持久FE成员地址重复");
            }
            canonical.append(frontend.role).append('\t').append(frontend.host)
                    .append('\t').append(frontend.editLogPort).append('\n');
        }
        return sha256(canonical.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static List<PersistentFrontend> safeFrontends(
            List<PersistentFrontend> frontends) {
        if (frontends == null || frontends.isEmpty() || frontends.size() > MAX_FRONTENDS) {
            fail("MASSDB_LICENSE_UPGRADE_MEMBERSHIP_CHANGED", "持久FE成员关系为空或过大");
        }
        return new ArrayList<>(frontends);
    }

    private String requestHashForReplay(MassDbLicenseState state, ParsedPlan plan) {
        if (marker != null && marker.isEligible()) {
            return requestHash(marker.upgradeSessionId,
                    marker.licenseControlDeploymentUuid, plan);
        }
        if (state != null && state.isInitialized()
                && "EXISTING_UPGRADE".equals(state.getInitializationSource())) {
            return requestHash(state.getBootstrapMarkerId(),
                    state.getLicenseControlDeploymentUuid(), plan);
        }
        MassDbLicenseUpgradeMarker.Attestation required = markerRequired();
        return requestHash(required.upgradeSessionId,
                required.licenseControlDeploymentUuid, plan);
    }

    private static String requestHash(String upgradeSessionId,
            String deploymentUuid, ParsedPlan plan) {
        String canonical = "INITIALIZE_OBSERVE\n" + upgradeSessionId + "\n"
                + deploymentUuid + "\n" + plan.planSha256 + "\n"
                + plan.membershipSha256 + "\n" + plan.keysetSha256 + "\n"
                + plan.inventory.configuredDigest();
        return sha256(canonical.getBytes(StandardCharsets.UTF_8));
    }

    private static void requireContentDigest(String supplied, byte[] value) {
        requireSha256(supplied, "Content-SHA256");
        if (!MessageDigest.isEqual(supplied.toLowerCase(Locale.ROOT)
                        .getBytes(StandardCharsets.US_ASCII),
                sha256(value).getBytes(StandardCharsets.US_ASCII))) {
            fail("MASSDB_LICENSE_CONTENT_SHA256_MISMATCH",
                    "Content-SHA256与实际upgrade plan不一致");
        }
    }

    private static void requireHttpsEndpoint(String value, String host) {
        try {
            URI uri = new URI(value);
            if (!"https".equals(uri.getScheme()) || uri.getUserInfo() != null
                    || uri.getHost() == null || !uri.getHost().equalsIgnoreCase(host)
                    || uri.getPort() <= 0 || uri.getPort() > 65_535
                    || uri.getRawPath() != null && !uri.getRawPath().isEmpty()
                            && !"/".equals(uri.getRawPath())
                    || uri.getRawQuery() != null || uri.getRawFragment() != null) {
                fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", "FE HTTPS endpoint非法");
            }
            String canonical = "https://" + (host.indexOf(':') >= 0
                    ? "[" + host + "]" : host) + ":" + uri.getPort();
            if (!canonical.equals(value)) {
                fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", "FE HTTPS endpoint不是canonical编码");
            }
        } catch (URISyntaxException failure) {
            fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", "FE HTTPS endpoint非法");
        }
    }

    private static void requireHost(String value) {
        if (value == null || value.isEmpty() || value.length() > 255
                || !value.equals(value.trim()) || value.indexOf('/') >= 0
                || value.indexOf('@') >= 0 || value.indexOf('?') >= 0
                || value.indexOf('#') >= 0 || value.indexOf('[') >= 0
                || value.indexOf(']') >= 0) {
            fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", "FE host非法");
        }
    }

    private static void requirePort(int value, String field) {
        if (value <= 0 || value > 65_535) {
            fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", field + "非法");
        }
    }

    private static void validateUuid(String value, String field) {
        try {
            UUID parsed = UUID.fromString(value);
            if (parsed.version() != 4 || parsed.variant() != 2
                    || !parsed.toString().equals(value)) {
                fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", field + "必须是canonical UUIDv4");
            }
        } catch (NullPointerException | IllegalArgumentException failure) {
            fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", field + "必须是canonical UUIDv4");
        }
    }

    private static String requireSha256(String value, String field) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            fail("MASSDB_LICENSE_UPGRADE_PLAN_INVALID", field + "必须是小写SHA-256");
        }
        return value;
    }

    private static String memberKey(String host, int editLogPort) {
        return host.toLowerCase(Locale.ROOT) + "\t" + editLogPort;
    }

    private static String randomSha256() {
        byte[] value = new byte[32];
        RANDOM.nextBytes(value);
        return hex(value);
    }

    private static long absoluteDifference(long left, long right) {
        return left >= right ? left - right : right - left;
    }

    private static long saturatedAdd(long left, long right) {
        return left > Long.MAX_VALUE - right ? Long.MAX_VALUE : left + right;
    }

    private static String sha256(byte[] value) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(String.format(Locale.ROOT, "%02x", item & 0xff));
        }
        return result.toString();
    }

    private static <T> List<T> immutableCopy(List<T> values) {
        return Collections.unmodifiableList(new ArrayList<>(values));
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    public static final class Plan {
        public int formatVersion;
        public String componentType;
        public String targetMode;
        public String keysetArtifactBase64;
        public BuildWire requiredBuild;
        public List<FrontendWire> frontends;

        public Plan() {
        }
    }

    public static final class BuildWire {
        public String componentType;
        public String componentVersion;
        public String capabilityVersion;
        public int stateFormatVersion;
        public int journalOperationType;
        public String snapshotFormat;
        public String binarySha256;

        public BuildWire() {
        }
    }

    public static final class FrontendWire {
        public String nodeUuid;
        public String role;
        public String host;
        public int editLogPort;
        public String httpsEndpoint;

        public FrontendWire() {
        }
    }

    private static final class ParsedPlan {
        private final byte[] keysetArtifact;
        private final String keysetSha256;
        private final MassDbLicenseBuildIdentity requiredBuild;
        private final List<UpgradeFrontend> frontends;
        private final MassDbLicenseIngressInventory inventory;
        private final String membershipSha256;
        private final String planSha256;

        private ParsedPlan(byte[] keysetArtifact, String keysetSha256,
                MassDbLicenseBuildIdentity requiredBuild,
                List<UpgradeFrontend> frontends,
                MassDbLicenseIngressInventory inventory,
                String membershipSha256, String planSha256) {
            this.keysetArtifact = keysetArtifact.clone();
            this.keysetSha256 = keysetSha256;
            this.requiredBuild = requiredBuild;
            this.frontends = immutableCopy(frontends);
            this.inventory = inventory.copy();
            this.membershipSha256 = membershipSha256;
            this.planSha256 = planSha256;
        }
    }

    private static final class AttestationSet {
        private final int count;
        private final String sha256;

        private AttestationSet(int count, String sha256) {
            this.count = count;
            this.sha256 = sha256;
        }
    }
}
