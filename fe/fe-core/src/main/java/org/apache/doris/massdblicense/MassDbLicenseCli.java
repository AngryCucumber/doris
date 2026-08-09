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

import org.apache.doris.httpv2.rest.MassDbLicenseAction;
import org.apache.doris.persist.gson.GsonUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Component-local marker creator and mTLS-only License management CLI. */
public final class MassDbLicenseCli {
    private static final int EXIT_USAGE = 2;
    private static final int EXIT_REJECTED = 3;
    private static final int EXIT_INTERNAL = 4;
    private static final int MAX_RESPONSE_BYTES = 1024 * 1024;
    private static final int MAX_STORE_BYTES = 4 * 1024 * 1024;
    private static final int MAX_SECRET_BYTES = 4096;
    private static final Pattern PATH_VALUE =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,190}");

    private MassDbLicenseCli() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err, null));
    }

    static int run(String[] args, PrintStream output, PrintStream error,
            Transport injectedTransport) {
        Objects.requireNonNull(args, "args");
        Objects.requireNonNull(output, "output");
        Objects.requireNonNull(error, "error");
        try {
            Options options = Options.parse(args);
            options.requireOnly(allowedOptions(options.command));
            if ("license-node-uuid-init".equals(options.command)) {
                return initializeNodeUuid(options, output);
            }
            if ("license-bootstrap-marker-create".equals(options.command)) {
                return createBootstrapMarker(options, output);
            }
            if ("license-upgrade-build-identity".equals(options.command)) {
                return printUpgradeBuildIdentity(output);
            }
            if ("license-upgrade-marker-create".equals(options.command)) {
                return createUpgradeMarker(options, output);
            }
            Transport transport = injectedTransport == null
                    ? HttpsTransport.open(options) : injectedTransport;
            switch (options.command) {
                case "license-capability":
                    printSuccess(output, requireSuccess(transport.request(
                            "GET", "/capability", Collections.emptyMap(), null)));
                    return 0;
                case "license-status":
                    printSuccess(output, requireSuccess(transport.request(
                            "GET", "/status", Collections.emptyMap(), null)));
                    return 0;
                case "license-metrics":
                    printSuccess(output, requireSuccess(transport.request(
                            "GET", "/metrics", Collections.emptyMap(), null)));
                    return 0;
                case "license-diagnostic-events":
                    printSuccess(output, requireSuccess(transport.request(
                            "GET", "/diagnostic-events?pageSize=200",
                            Collections.emptyMap(), null)));
                    return 0;
                case "license-topology-minimal":
                    printSuccess(output, requireSuccess(transport.request(
                            "GET", "/topology/minimal", Collections.emptyMap(), null)));
                    return 0;
                case "license-upgrade-observe-preflight":
                    printSuccess(output, requireSuccess(transport.request(
                            "GET", "/upgrade/observe/preflight",
                            Collections.emptyMap(), null)));
                    return 0;
                case "license-upgrade-observe-validate":
                    byte[] validateUpgradePlan = readUpgradePlan(options);
                    try {
                        printSuccess(output, requireSuccess(validateUpgrade(
                                transport, validateUpgradePlan)));
                    } finally {
                        Arrays.fill(validateUpgradePlan, (byte) 0);
                    }
                    return 0;
                case "license-upgrade-observe-apply":
                    byte[] applyUpgradePlan = readUpgradePlan(options);
                    try {
                        String upgradeIdempotencyKey = requirePathValue(
                                options.requiredOne("idempotency-key"), "idempotency-key");
                        Response validation = validateUpgrade(transport, applyUpgradePlan);
                        String upgradePrecondition = upgradePrecondition(validation);
                        Map<String, String> headers = upgradePlanHeaders(applyUpgradePlan);
                        headers.put("Idempotency-Key", upgradeIdempotencyKey);
                        if (upgradePrecondition != null) {
                            headers.put("If-Match", quoteEtag(upgradePrecondition));
                        }
                        printSuccess(output, requireSuccess(transport.request(
                                "POST", "/upgrade/observe/apply", headers,
                                applyUpgradePlan)));
                    } finally {
                        Arrays.fill(applyUpgradePlan, (byte) 0);
                    }
                    return 0;
                case "license-bootstrap-status":
                    printSuccess(output, requireSuccess(transport.request(
                            "GET", "/bootstrap/status", Collections.emptyMap(), null)));
                    return 0;
                case "license-bootstrap-validate":
                    byte[] validatePlan = readBootstrapPlan(options);
                    try {
                        printSuccess(output, requireSuccess(validateBootstrap(
                                transport, validatePlan)));
                    } finally {
                        Arrays.fill(validatePlan, (byte) 0);
                    }
                    return 0;
                case "license-bootstrap-apply":
                    byte[] applyPlan = readBootstrapPlan(options);
                    try {
                        String bootstrapIdempotencyKey = requirePathValue(
                                options.requiredOne("idempotency-key"), "idempotency-key");
                        Response validation = validateBootstrap(transport, applyPlan);
                        String preconditionToken = bootstrapPrecondition(validation);
                        Map<String, String> headers = bootstrapPlanHeaders(applyPlan);
                        headers.put("Idempotency-Key", bootstrapIdempotencyKey);
                        if (preconditionToken != null) {
                            headers.put("If-Match", quoteEtag(preconditionToken));
                        }
                        printSuccess(output, requireSuccess(transport.request(
                                "POST", "/bootstrap/apply", headers, applyPlan)));
                    } finally {
                        Arrays.fill(applyPlan, (byte) 0);
                    }
                    return 0;
                case "license-validate":
                    byte[] validateArtifact = readArtifact(options);
                    try {
                        printSuccess(output, requireSuccess(validate(
                                transport, validateArtifact, intent(options))));
                    } finally {
                        Arrays.fill(validateArtifact, (byte) 0);
                    }
                    return 0;
                case "license-import":
                    byte[] importArtifact = readArtifact(options);
                    try {
                        String idempotencyKey = requirePathValue(
                                options.requiredOne("idempotency-key"), "idempotency-key");
                        String intent = intent(options);
                        Response validation = requireSuccess(validate(
                                transport, importArtifact, intent));
                        ValidationBody validationBody = GsonUtils.GSON.fromJson(
                                validation.body, ValidationBody.class);
                        if (validationBody == null || !validationBody.readyForImport
                                || validationBody.preconditionToken == null
                                || validationBody.preconditionToken.isEmpty()) {
                            throw new MassDbLicenseException(
                                    "MASSDB_LICENSE_IMPORT_NOT_READY",
                                    "validate未返回可导入的新鲜precondition token");
                        }
                        Map<String, String> headers = artifactHeaders(importArtifact, intent);
                        headers.put("Idempotency-Key", idempotencyKey);
                        headers.put("If-Match", quoteEtag(
                                validationBody.preconditionToken));
                        printSuccess(output, requireSuccess(transport.request(
                                "POST", "/import", headers, importArtifact)));
                    } finally {
                        Arrays.fill(importArtifact, (byte) 0);
                    }
                    return 0;
                case "license-correction-propose":
                    printSuccess(output, correctionPropose(transport, options));
                    return 0;
                case "license-correction-approve":
                    printSuccess(output, correctionProposalAction(
                            transport, options, "approve"));
                    return 0;
                case "license-correction-prepare":
                    printSuccess(output, correctionPrepare(transport, options));
                    return 0;
                case "license-correction-import":
                    printSuccess(output, correctionImport(transport, options));
                    return 0;
                case "license-correction-cancel":
                    printSuccess(output, correctionProposalAction(
                            transport, options, "cancel"));
                    return 0;
                case "license-ingress-list":
                    printSuccess(output, requireSuccess(transport.request(
                            "GET", "/ingress", Collections.emptyMap(), null)));
                    return 0;
                case "license-ingress-apply":
                    printSuccess(output, ingressApply(transport, options));
                    return 0;
                case "license-routing-evidence-observe":
                    printSuccess(output, routingEvidenceObserve(transport, options));
                    return 0;
                case "license-enforcement-validate":
                    printSuccess(output, requireSuccess(transport.request(
                            "POST", "/enforcement/validate",
                            Collections.emptyMap(), null)));
                    return 0;
                case "license-enforcement-activate":
                    printSuccess(output, enforcementActivate(transport, options));
                    return 0;
                case "license-clock-challenge-create":
                    printSuccess(output, requireSuccess(transport.request(
                            "POST", "/clock-recovery/challenge",
                            idempotencyHeader(options), null)));
                    return 0;
                case "license-clock-challenge-cancel":
                    String challengeId = requirePathValue(
                            options.requiredOne("challenge-id"), "challenge-id");
                    printSuccess(output, requireSuccess(transport.request(
                            "POST", "/clock-recovery/challenge/" + challengeId + "/cancel",
                            idempotencyHeader(options), null)));
                    return 0;
                case "license-clock-validate":
                    printSuccess(output, validateControlArtifact(
                            transport, options, "/clock-recovery/validate"));
                    return 0;
                case "license-clock-import":
                    printSuccess(output, importControlArtifact(transport, options,
                            "/clock-recovery/validate", "/clock-recovery/import"));
                    return 0;
                case "license-keyset-status":
                    printSuccess(output, requireSuccess(transport.request(
                            "GET", "/keyset/status", Collections.emptyMap(), null)));
                    return 0;
                case "license-keyset-validate":
                    printSuccess(output, validateControlArtifact(
                            transport, options, "/keyset/validate"));
                    return 0;
                case "license-keyset-import":
                    printSuccess(output, importControlArtifact(transport, options,
                            "/keyset/validate", "/keyset/import"));
                    return 0;
                case "license-keyset-bundle-validate":
                    printSuccess(output, validateControlArtifact(transport, options,
                            "/keyset/recovery-bundle/validate"));
                    return 0;
                case "license-keyset-bundle-import":
                    printSuccess(output, importControlArtifact(transport, options,
                            "/keyset/recovery-bundle/validate",
                            "/keyset/recovery-bundle/import"));
                    return 0;
                case "license-operation":
                    String operationId = requirePathValue(
                            options.requiredOne("operation-id"), "operation-id");
                    printSuccess(output, requireSuccess(transport.request(
                            "GET", "/operations/" + operationId,
                            Collections.emptyMap(), null)));
                    return 0;
                case "license-operation-by-key":
                    String lookupKey = requirePathValue(
                            options.requiredOne("idempotency-key"), "idempotency-key");
                    printSuccess(output, requireSuccess(transport.request(
                            "GET", "/operations/by-idempotency-key/" + lookupKey,
                            Collections.emptyMap(), null)));
                    return 0;
                case "license-abort":
                    String abortId = requirePathValue(
                            options.requiredOne("operation-id"), "operation-id");
                    printSuccess(output, requireSuccess(transport.request(
                            "POST", "/operations/" + abortId + "/abort",
                            Collections.emptyMap(), null)));
                    return 0;
                default:
                    throw new UsageException("未知命令: " + options.command);
            }
        } catch (UsageException failure) {
            error.println(errorJson("MASSDB_LICENSE_CLI_USAGE", failure.getMessage()));
            return EXIT_USAGE;
        } catch (HttpFailure failure) {
            error.println(failure.response.body == null
                    || failure.response.body.trim().isEmpty()
                    ? errorJson("MASSDB_LICENSE_HTTP_REJECTED",
                            "License管理API返回HTTP " + failure.response.status)
                    : failure.response.body);
            return EXIT_REJECTED;
        } catch (MassDbLicenseException failure) {
            error.println(errorJson(failure.getCode(), failure.getMessage()));
            return EXIT_REJECTED;
        } catch (RuntimeException failure) {
            error.println(errorJson("MASSDB_LICENSE_CLI_INTERNAL",
                    "License命令执行失败，请检查本地凭据、网络和组件日志"));
            return EXIT_INTERNAL;
        }
    }

    private static Response validate(Transport transport, byte[] artifact, String intent) {
        return transport.request("POST", "/validate",
                artifactHeaders(artifact, intent), artifact);
    }

    private static String intent(Options options) {
        String value = options.oneOrDefault("intent", "NORMAL");
        if (!"NORMAL".equals(value)
                && !"REPLACE_WITH_SHORTER".equals(value)
                && !"KEY_ROTATION_REPLACEMENT".equals(value)) {
            throw new UsageException("--intent必须是NORMAL、REPLACE_WITH_SHORTER或"
                    + "KEY_ROTATION_REPLACEMENT");
        }
        return value;
    }

    private static Response correctionPropose(Transport transport, Options options) {
        byte[] artifact = readArtifact(options);
        try {
            String idempotencyKey = requirePathValue(
                    options.requiredOne("idempotency-key"), "idempotency-key");
            Response validation = requireSuccess(validate(
                    transport, artifact, "REPLACE_WITH_SHORTER"));
            ValidationBody body = GsonUtils.GSON.fromJson(
                    validation.body, ValidationBody.class);
            requireFreshToken(body, "correction validate");
            Map<String, String> headers = artifactHeaders(
                    artifact, "REPLACE_WITH_SHORTER");
            headers.put("Idempotency-Key", idempotencyKey);
            headers.put("If-Match", quoteEtag(body.preconditionToken));
            return requireSuccess(transport.request(
                    "POST", "/corrections/proposals", headers, artifact));
        } finally {
            Arrays.fill(artifact, (byte) 0);
        }
    }

    private static Response correctionProposalAction(Transport transport,
            Options options, String action) {
        String proposalId = requirePathValue(
                options.requiredOne("proposal-id"), "proposal-id");
        return requireSuccess(transport.request("POST",
                "/corrections/" + proposalId + "/" + action,
                idempotencyHeader(options), null));
    }

    private static Response correctionPrepare(Transport transport, Options options) {
        byte[] artifact = readArtifact(options);
        try {
            String proposalId = requirePathValue(
                    options.requiredOne("proposal-id"), "proposal-id");
            return requireSuccess(transport.request("POST",
                    "/corrections/" + proposalId + "/prepare-import",
                    artifactHeaders(artifact, "REPLACE_WITH_SHORTER"), artifact));
        } finally {
            Arrays.fill(artifact, (byte) 0);
        }
    }

    private static Response correctionImport(Transport transport, Options options) {
        byte[] artifact = readArtifact(options);
        try {
            String proposalId = requirePathValue(
                    options.requiredOne("proposal-id"), "proposal-id");
            String idempotencyKey = requirePathValue(
                    options.requiredOne("idempotency-key"), "idempotency-key");
            Response preparation = requireSuccess(transport.request("POST",
                    "/corrections/" + proposalId + "/prepare-import",
                    artifactHeaders(artifact, "REPLACE_WITH_SHORTER"), artifact));
            ValidationBody body = GsonUtils.GSON.fromJson(
                    preparation.body, ValidationBody.class);
            requireFreshToken(body, "correction prepare-import");
            Map<String, String> headers = artifactHeaders(
                    artifact, "REPLACE_WITH_SHORTER");
            headers.put("Idempotency-Key", idempotencyKey);
            headers.put("X-MassDB-License-Correction-Proposal", proposalId);
            headers.put("X-MassDB-License-Correction-Execution-Token",
                    body.preconditionToken);
            return requireSuccess(transport.request("POST", "/import", headers, artifact));
        } finally {
            Arrays.fill(artifact, (byte) 0);
        }
    }

    private static Response ingressApply(Transport transport, Options options) {
        String action = options.requiredOne("action");
        String nodeUuid = requirePathValue(
                options.requiredOne("node-uuid"), "node-uuid");
        StringBuilder jsonBody = new StringBuilder("{\"action\":\"")
                .append(json(action)).append("\",\"nodeUuid\":\"")
                .append(json(nodeUuid)).append('"');
        appendJsonString(jsonBody, "endpoint", options.oneOrDefault("ingress-endpoint", null));
        appendJsonString(jsonBody, "routingState", options.oneOrDefault("routing-state", null));
        String ttl = options.oneOrDefault("evidence-ttl-seconds", null);
        if (ttl != null) {
            jsonBody.append(",\"evidenceTtlSeconds\":")
                    .append(positiveLong(ttl, "evidence-ttl-seconds"));
        }
        jsonBody.append('}');
        byte[] body = jsonBody.toString().getBytes(StandardCharsets.UTF_8);
        Response validation = requireSuccess(transport.request(
                "POST", "/ingress/validate", jsonHeaders(body), body));
        ControlValidationBody validated = GsonUtils.GSON.fromJson(
                validation.body, ControlValidationBody.class);
        if (validated == null || !validated.readyForApply
                || validated.preconditionToken == null
                || validated.preconditionToken.isEmpty()) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_IMPORT_NOT_READY", "ingress validate未返回可应用token");
        }
        Map<String, String> headers = jsonHeaders(body);
        headers.putAll(idempotencyHeader(options));
        headers.put("If-Match", quoteEtag(validated.preconditionToken));
        return requireSuccess(transport.request("POST", "/ingress/apply", headers, body));
    }

    private static Response routingEvidenceObserve(Transport transport, Options options) {
        String bodyText = "{\"nodeUuid\":\""
                + json(requirePathValue(options.requiredOne("node-uuid"), "node-uuid"))
                + "\",\"adapterType\":\"" + json(options.requiredOne("adapter-type"))
                + "\",\"objectIdentity\":\"" + json(options.requiredOne("object-identity"))
                + "\",\"objectRevision\":"
                + positiveLong(options.requiredOne("object-revision"), "object-revision")
                + ",\"routingState\":\"" + json(options.requiredOne("routing-state"))
                + "\",\"evidenceDigest\":\"" + json(options.requiredOne("evidence-digest"))
                + "\",\"observedAt\":"
                + positiveLong(options.requiredOne("observed-at"), "observed-at") + "}";
        byte[] body = bodyText.getBytes(StandardCharsets.UTF_8);
        return requireSuccess(transport.request("POST",
                "/ingress/routing-evidence/observe", jsonHeaders(body), body));
    }

    private static Response enforcementActivate(Transport transport, Options options) {
        Response validation = requireSuccess(transport.request(
                "POST", "/enforcement/validate", Collections.emptyMap(), null));
        EnforcementValidationBody body = GsonUtils.GSON.fromJson(
                validation.body, EnforcementValidationBody.class);
        if (body == null || !body.readyForActivation
                || body.preconditionToken == null || body.preconditionToken.isEmpty()) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_IMPORT_NOT_READY", "enforcement validate未返回可激活token");
        }
        Map<String, String> headers = idempotencyHeader(options);
        headers.put("If-Match", quoteEtag(body.preconditionToken));
        return requireSuccess(transport.request(
                "POST", "/enforcement/activate", headers, null));
    }

    private static Response validateControlArtifact(Transport transport,
            Options options, String path) {
        byte[] artifact = readControlArtifact(options);
        try {
            return requireSuccess(transport.request(
                    "POST", path, binaryHeaders(artifact), artifact));
        } finally {
            Arrays.fill(artifact, (byte) 0);
        }
    }

    private static Response importControlArtifact(Transport transport, Options options,
            String validatePath, String importPath) {
        byte[] artifact = readControlArtifact(options);
        try {
            Response validation = requireSuccess(transport.request(
                    "POST", validatePath, binaryHeaders(artifact), artifact));
            ValidationBody body = GsonUtils.GSON.fromJson(
                    validation.body, ValidationBody.class);
            requireFreshToken(body, "control artifact validate");
            Map<String, String> headers = binaryHeaders(artifact);
            headers.putAll(idempotencyHeader(options));
            headers.put("If-Match", quoteEtag(body.preconditionToken));
            return requireSuccess(transport.request("POST", importPath, headers, artifact));
        } finally {
            Arrays.fill(artifact, (byte) 0);
        }
    }

    private static void requireFreshToken(ValidationBody body, String label) {
        if (body == null || !body.readyForImport
                || body.preconditionToken == null || body.preconditionToken.isEmpty()) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_IMPORT_NOT_READY", label + "未返回可导入token");
        }
    }

    private static Map<String, String> idempotencyHeader(Options options) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Idempotency-Key", requirePathValue(
                options.requiredOne("idempotency-key"), "idempotency-key"));
        return headers;
    }

    private static Map<String, String> jsonHeaders(byte[] body) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Content-SHA256", sha256(body));
        return headers;
    }

    private static Map<String, String> binaryHeaders(byte[] artifact) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/octet-stream");
        headers.put("Content-SHA256", sha256(artifact));
        return headers;
    }

    private static void appendJsonString(StringBuilder target,
            String name, String value) {
        if (value != null) {
            target.append(",\"").append(name).append("\":\"")
                    .append(json(value)).append('"');
        }
    }

    private static long positiveLong(String value, String label) {
        try {
            long result = Long.parseLong(value);
            if (result <= 0) {
                throw new NumberFormatException();
            }
            return result;
        } catch (NumberFormatException failure) {
            throw new UsageException("--" + label + "必须是正整数");
        }
    }

    private static int createBootstrapMarker(Options options, PrintStream output) {
        byte[] plan = readBootstrapPlan(options);
        try {
            MassDbLicenseBootstrapCore.PlanSummary summary =
                    MassDbLicenseBootstrapCore.summarize(plan);
            MassDbLicenseBootstrapMarker.Attestation marker =
                    MassDbLicenseBootstrapMarker.create(
                            absolutePath(options.requiredOne("marker-file"), "marker-file"),
                            absolutePath(options.requiredOne("meta-dir"), "meta-dir"),
                            summary.planSha256, System.currentTimeMillis() / 1000L);
            output.println("{\"status\":\"" + marker.status.name()
                    + "\",\"bootstrapMarkerId\":\"" + json(marker.bootstrapMarkerId)
                    + "\",\"licenseControlDeploymentUuid\":\""
                    + json(marker.licenseControlDeploymentUuid)
                    + "\",\"bootstrapPlanSha256\":\""
                    + json(marker.bootstrapPlanSha256) + "\",\"planFormatVersion\":"
                    + summary.formatVersion + ",\"minimumWriteHealth\":\""
                    + json(summary.minimumWriteHealth) + "\",\"desiredIngressNodes\":"
                    + summary.desiredIngressNodes + ",\"plannedFrontends\":"
                    + summary.plannedFrontends + ",\"plannedBackends\":"
                    + summary.plannedBackends + ",\"plannedIngestRoutes\":"
                    + summary.plannedIngestRoutes + ",\"createdAt\":"
                    + marker.createdAt + "}");
            return 0;
        } finally {
            Arrays.fill(plan, (byte) 0);
        }
    }

    private static int initializeNodeUuid(Options options, PrintStream output) {
        Path metaDirectory = absolutePath(options.requiredOne("meta-dir"), "meta-dir");
        String nodeUuid = new MassDbLicenseLocalSnapshotStore(
                metaDirectory.resolve("massdb-license")).getNodeUuid();
        output.println("{\"ok\":true,\"component\":\"massdb-sql\",\"role\":\"fe\""
                + ",\"nodeUuid\":\"" + json(nodeUuid) + "\"}");
        return 0;
    }

    private static int printUpgradeBuildIdentity(PrintStream output) {
        MassDbLicenseBuildIdentity build = MassDbLicenseBuildIdentity.current();
        output.println("{\"componentType\":\"" + json(build.componentType)
                + "\",\"componentVersion\":\"" + json(build.componentVersion)
                + "\",\"capabilityVersion\":\"" + json(build.capabilityVersion)
                + "\",\"stateFormatVersion\":" + build.stateFormatVersion
                + ",\"journalOperationType\":" + build.journalOperationType
                + ",\"snapshotFormat\":\"" + json(build.snapshotFormat)
                + "\",\"binarySha256\":\"" + json(build.binarySha256) + "\"}");
        return 0;
    }

    private static int createUpgradeMarker(Options options, PrintStream output) {
        byte[] plan = readUpgradePlan(options);
        try {
            MassDbLicenseBuildIdentity build = MassDbLicenseBuildIdentity.current();
            MassDbLicenseUpgradeCore.PlanSummary summary =
                    MassDbLicenseUpgradeCore.summarize(plan);
            MassDbLicenseUpgradeMarker.Attestation marker =
                    MassDbLicenseUpgradeMarker.create(
                            absolutePath(options.requiredOne("marker-file"), "marker-file"),
                            absolutePath(options.requiredOne("meta-dir"), "meta-dir"),
                            summary, build,
                            options.oneOrDefault("upgrade-session-id", null),
                            options.oneOrDefault("deployment-uuid", null),
                            System.currentTimeMillis() / 1000L);
            output.println("{\"status\":\"" + marker.status.name()
                    + "\",\"upgradeSessionId\":\"" + json(marker.upgradeSessionId)
                    + "\",\"licenseControlDeploymentUuid\":\""
                    + json(marker.licenseControlDeploymentUuid)
                    + "\",\"upgradePlanSha256\":\""
                    + json(marker.upgradePlanSha256) + "\",\"localNodeUuid\":\""
                    + json(marker.localNodeUuid) + "\",\"membershipSha256\":\""
                    + json(summary.membershipSha256)
                    + "\",\"minimumEnforcementVersion\":\""
                    + json(summary.minimumEnforcementVersion)
                    + "\",\"requiredFrontends\":" + summary.requiredFrontends
                    + ",\"createdAt\":" + marker.createdAt + "}");
            return 0;
        } finally {
            Arrays.fill(plan, (byte) 0);
        }
    }

    private static Response validateBootstrap(Transport transport, byte[] plan) {
        return transport.request(
                "POST", "/bootstrap/validate", bootstrapPlanHeaders(plan), plan);
    }

    private static Response validateUpgrade(Transport transport, byte[] plan) {
        return transport.request(
                "POST", "/upgrade/observe/validate", upgradePlanHeaders(plan), plan);
    }

    private static String upgradePrecondition(Response validation) {
        if (validation.status >= 200 && validation.status < 300) {
            UpgradeValidationBody body = GsonUtils.GSON.fromJson(
                    validation.body, UpgradeValidationBody.class);
            if (body == null || !body.readyForApply
                    || body.preconditionToken == null
                    || body.preconditionToken.isEmpty()) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_UPGRADE_NOT_READY",
                        "upgrade validate未返回可执行的新鲜precondition token");
            }
            return body.preconditionToken;
        }
        if (validation.status == 409 && hasErrorCode(
                validation.body, "MASSDB_LICENSE_UPGRADE_ALREADY_INITIALIZED")) {
            return null;
        }
        throw new HttpFailure(validation);
    }

    /**
     * An uninitialized upgrade requires a fresh token. An already-initialized response permits
     * one direct apply solely to resolve a lost terminal response by canonical request hash.
     */
    private static String bootstrapPrecondition(Response validation) {
        if (validation.status >= 200 && validation.status < 300) {
            BootstrapValidationBody body = GsonUtils.GSON.fromJson(
                    validation.body, BootstrapValidationBody.class);
            if (body == null || !body.readyForApply
                    || body.preconditionToken == null
                    || body.preconditionToken.isEmpty()) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_BOOTSTRAP_NOT_READY",
                        "bootstrap validate未返回可应用的新鲜precondition token");
            }
            return body.preconditionToken;
        }
        if (validation.status == 409 && hasErrorCode(
                validation.body, "MASSDB_LICENSE_BOOTSTRAP_SEALED")) {
            return null;
        }
        throw new HttpFailure(validation);
    }

    private static boolean hasErrorCode(String body, String expected) {
        try {
            ServerErrorBody error = GsonUtils.GSON.fromJson(body, ServerErrorBody.class);
            return error != null && expected.equals(error.code);
        } catch (RuntimeException failure) {
            return false;
        }
    }

    private static Map<String, String> bootstrapPlanHeaders(byte[] plan) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Content-SHA256", sha256(plan));
        return headers;
    }

    private static Map<String, String> upgradePlanHeaders(byte[] plan) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Content-SHA256", sha256(plan));
        return headers;
    }

    private static Map<String, String> artifactHeaders(byte[] artifact, String intent) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/octet-stream");
        headers.put("Content-SHA256", sha256(artifact));
        headers.put("X-MassDB-License-Intent", intent);
        return headers;
    }

    private static byte[] readArtifact(Options options) {
        return readStableFile(absolutePath(
                options.requiredOne("license-file"), "license-file"),
                MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES, "License工件", true);
    }

    private static byte[] readControlArtifact(Options options) {
        return readStableFile(absolutePath(
                options.requiredOne("artifact-file"), "artifact-file"),
                MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES, "License控制工件", true);
    }

    private static byte[] readBootstrapPlan(Options options) {
        return readStableFile(absolutePath(
                options.requiredOne("plan-file"), "plan-file"),
                MassDbLicenseBootstrapCore.MAX_BOOTSTRAP_PLAN_BYTES,
                "bootstrap plan", true);
    }

    private static byte[] readUpgradePlan(Options options) {
        return readStableFile(absolutePath(
                options.requiredOne("plan-file"), "plan-file"),
                MassDbLicenseUpgradeCore.MAX_UPGRADE_PLAN_BYTES,
                "upgrade plan", true);
    }

    private static Response requireSuccess(Response response) {
        if (response.status < 200 || response.status >= 300) {
            throw new HttpFailure(response);
        }
        return response;
    }

    private static void printSuccess(PrintStream output, Response response) {
        output.println(response.body == null || response.body.trim().isEmpty()
                ? "{}" : response.body);
    }

    private static String requirePathValue(String value, String label) {
        if (value == null || !PATH_VALUE.matcher(value).matches()) {
            throw new UsageException("--" + label + "不符合冻结的路径段格式");
        }
        return value;
    }

    private static List<String> connectionNames() {
        return Arrays.asList("endpoint", "key-store", "key-store-secret-file",
                "key-store-type", "trust-store", "trust-store-secret-file",
                "trust-store-type", "connect-timeout-ms", "read-timeout-ms");
    }

    private static List<String> withConnection(String... additions) {
        List<String> result = new ArrayList<>(connectionNames());
        result.addAll(Arrays.asList(additions));
        return result;
    }

    private static List<String> allowedOptions(String command) {
        switch (command) {
            case "license-capability":
            case "license-status":
            case "license-metrics":
            case "license-diagnostic-events":
            case "license-topology-minimal":
            case "license-upgrade-observe-preflight":
            case "license-bootstrap-status":
            case "license-ingress-list":
            case "license-enforcement-validate":
            case "license-keyset-status":
                return connectionNames();
            case "license-upgrade-build-identity":
                return Collections.emptyList();
            case "license-bootstrap-marker-create":
                return Arrays.asList("plan-file", "marker-file", "meta-dir");
            case "license-upgrade-marker-create":
                return Arrays.asList("plan-file", "marker-file", "meta-dir",
                        "upgrade-session-id", "deployment-uuid");
            case "license-node-uuid-init":
                return Collections.singletonList("meta-dir");
            case "license-bootstrap-validate":
                return withConnection("plan-file");
            case "license-bootstrap-apply":
                return withConnection("plan-file", "idempotency-key");
            case "license-upgrade-observe-validate":
                return withConnection("plan-file");
            case "license-upgrade-observe-apply":
                return withConnection("plan-file", "idempotency-key");
            case "license-validate":
                return withConnection("license-file", "intent");
            case "license-import":
                return withConnection("license-file", "intent", "idempotency-key");
            case "license-correction-propose":
                return withConnection("license-file", "idempotency-key");
            case "license-correction-approve":
            case "license-correction-cancel":
                return withConnection("proposal-id", "idempotency-key");
            case "license-correction-prepare":
                return withConnection("proposal-id", "license-file");
            case "license-correction-import":
                return withConnection("proposal-id", "license-file", "idempotency-key");
            case "license-ingress-apply":
                return withConnection("action", "node-uuid", "ingress-endpoint",
                        "routing-state", "evidence-ttl-seconds", "idempotency-key");
            case "license-routing-evidence-observe":
                return withConnection("node-uuid", "adapter-type", "object-identity",
                        "object-revision", "routing-state", "evidence-digest",
                        "observed-at");
            case "license-enforcement-activate":
            case "license-clock-challenge-create":
                return withConnection("idempotency-key");
            case "license-clock-challenge-cancel":
                return withConnection("challenge-id", "idempotency-key");
            case "license-clock-validate":
            case "license-keyset-validate":
            case "license-keyset-bundle-validate":
                return withConnection("artifact-file");
            case "license-clock-import":
            case "license-keyset-import":
            case "license-keyset-bundle-import":
                return withConnection("artifact-file", "idempotency-key");
            case "license-operation":
            case "license-abort":
                return withConnection("operation-id");
            case "license-operation-by-key":
                return withConnection("idempotency-key");
            default:
                throw new UsageException("未知命令: " + command);
        }
    }

    private static Path absolutePath(String value, String label) {
        try {
            Path path = Paths.get(value);
            if (!path.isAbsolute()) {
                throw new UsageException("--" + label + "必须是绝对路径");
            }
            return path.normalize();
        } catch (InvalidPathException failure) {
            throw new UsageException("--" + label + "路径无效");
        }
    }

    private static byte[] readStableFile(Path path, int maximum,
            String label, boolean rejectGroupOrOtherWrite) {
        byte[] result = null;
        try {
            BasicFileAttributes before = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (Files.isSymbolicLink(path) || !before.isRegularFile()
                    || before.size() <= 0 || before.size() > maximum) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_CLI_FILE_INVALID",
                        label + "必须是非符号链接普通文件且不超过上限");
            }
            if (rejectGroupOrOtherWrite) {
                rejectGroupOrOtherWrite(path, label);
            }
            result = new byte[(int) before.size()];
            try (SeekableByteChannel input = Files.newByteChannel(path,
                    StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                ByteBuffer target = ByteBuffer.wrap(result);
                while (target.hasRemaining()) {
                    if (input.read(target) < 0) {
                        throw new IOException("truncated file");
                    }
                }
                if (input.read(ByteBuffer.allocate(1)) != -1) {
                    throw new IOException("growing file");
                }
            }
            BasicFileAttributes after = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!after.isRegularFile() || before.size() != after.size()
                    || !before.lastModifiedTime().equals(after.lastModifiedTime())
                    || !Objects.equals(before.fileKey(), after.fileKey())) {
                throw new IOException("changed file");
            }
            byte[] complete = result;
            result = null;
            return complete;
        } catch (MassDbLicenseException failure) {
            throw failure;
        } catch (IOException | SecurityException failure) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_CLI_FILE_INVALID", "无法安全读取" + label);
        } finally {
            if (result != null) {
                Arrays.fill(result, (byte) 0);
            }
        }
    }

    private static void rejectGroupOrOtherWrite(Path path, String label)
            throws IOException {
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(
                    path, LinkOption.NOFOLLOW_LINKS);
            if (permissions.contains(PosixFilePermission.GROUP_WRITE)
                    || permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_CLI_FILE_INVALID",
                        label + "不能被组或其他用户写入");
            }
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX platforms retain the no-symlink and stable-read checks.
        }
    }

    private static char[] readSecret(Path path, String label) {
        requirePrivatePermissions(path, label);
        byte[] bytes = readStableFile(path, MAX_SECRET_BYTES, label, true);
        try {
            String value = new String(bytes, StandardCharsets.UTF_8);
            while (value.endsWith("\n") || value.endsWith("\r")) {
                value = value.substring(0, value.length() - 1);
            }
            if (value.isEmpty() || value.indexOf('\0') >= 0) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_CLI_CREDENTIAL_INVALID", label + "为空或包含NUL");
            }
            return value.toCharArray();
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static void requirePrivatePermissions(Path path, String label) {
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(
                    path, LinkOption.NOFOLLOW_LINKS);
            for (PosixFilePermission permission : permissions) {
                if (permission != PosixFilePermission.OWNER_READ
                        && permission != PosixFilePermission.OWNER_WRITE) {
                    throw new MassDbLicenseException(
                            "MASSDB_LICENSE_CLI_CREDENTIAL_INVALID",
                            label + "权限必须收敛为0400或0600");
                }
            }
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX platforms retain the no-symlink and stable-read checks.
        } catch (IOException | SecurityException failure) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_CLI_CREDENTIAL_INVALID",
                    "无法验证" + label + "文件权限");
        }
    }

    private static KeyStore loadStore(Path path, String type,
            char[] password, String label) {
        byte[] bytes = readStableFile(path, MAX_STORE_BYTES, label, true);
        try (InputStream input = new java.io.ByteArrayInputStream(bytes)) {
            KeyStore store = KeyStore.getInstance(type);
            store.load(input, password);
            return store;
        } catch (Exception failure) {
            throw new MassDbLicenseException(
                    "MASSDB_LICENSE_CLI_CREDENTIAL_INVALID", "无法加载" + label);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
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

    private static String quoteEtag(String value) {
        return "\"" + value + "\"";
    }

    private static String errorJson(String code, String message) {
        return "{\"ok\":false,\"code\":\"" + json(code)
                + "\",\"message\":\"" + json(message) + "\"}";
    }

    private static String json(String value) {
        StringBuilder result = new StringBuilder(value.length() + 16);
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (item == '\\' || item == '"') {
                result.append('\\').append(item);
            } else if (item == '\n') {
                result.append("\\n");
            } else if (item == '\r') {
                result.append("\\r");
            } else if (item == '\t') {
                result.append("\\t");
            } else if (item < 0x20) {
                result.append(String.format(Locale.ROOT, "\\u%04x", (int) item));
            } else {
                result.append(item);
            }
        }
        return result.toString();
    }

    interface Transport {
        Response request(String method, String path,
                Map<String, String> headers, byte[] body);
    }

    static final class Response {
        final int status;
        final String body;

        Response(int status, String body) {
            this.status = status;
            this.body = body;
        }
    }

    private static final class HttpsTransport implements Transport {
        private final String endpoint;
        private final SSLContext sslContext;
        private final int connectTimeoutMillis;
        private final int readTimeoutMillis;

        private HttpsTransport(String endpoint, SSLContext sslContext,
                int connectTimeoutMillis, int readTimeoutMillis) {
            this.endpoint = endpoint;
            this.sslContext = sslContext;
            this.connectTimeoutMillis = connectTimeoutMillis;
            this.readTimeoutMillis = readTimeoutMillis;
        }

        static HttpsTransport open(Options options) {
            String endpoint = strictEndpoint(options.requiredOne("endpoint"));
            Path keyStorePath = absolutePath(
                    options.requiredOne("key-store"), "key-store");
            Path keySecretPath = absolutePath(
                    options.requiredOne("key-store-secret-file"),
                    "key-store-secret-file");
            Path trustStorePath = absolutePath(
                    options.requiredOne("trust-store"), "trust-store");
            Path trustSecretPath = absolutePath(
                    options.requiredOne("trust-store-secret-file"),
                    "trust-store-secret-file");
            char[] keyPassword = readSecret(keySecretPath, "key store secret");
            char[] trustPassword = readSecret(trustSecretPath, "trust store secret");
            try {
                KeyStore keyStore = loadStore(keyStorePath,
                        storeType(options.oneOrDefault("key-store-type", "PKCS12"),
                                "key-store-type"),
                        keyPassword, "client key store");
                KeyStore trustStore = loadStore(trustStorePath,
                        storeType(options.oneOrDefault("trust-store-type", "PKCS12"),
                                "trust-store-type"),
                        trustPassword, "server trust store");
                validateClientKeyStore(keyStore, keyPassword);
                validateServerTrustStore(trustStore);
                KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(
                        KeyManagerFactory.getDefaultAlgorithm());
                keyManagers.init(keyStore, keyPassword);
                TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm());
                trustManagers.init(trustStore);
                SSLContext context = SSLContext.getInstance("TLS");
                context.init(keyManagers.getKeyManagers(),
                        trustManagers.getTrustManagers(), null);
                return new HttpsTransport(endpoint, context,
                        positiveInteger(options.oneOrDefault(
                                "connect-timeout-ms", "5000"), "connect-timeout-ms"),
                        positiveInteger(options.oneOrDefault(
                                "read-timeout-ms", "15000"), "read-timeout-ms"));
            } catch (MassDbLicenseException failure) {
                throw failure;
            } catch (Exception failure) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_CLI_CREDENTIAL_INVALID",
                        "无法初始化mTLS客户端身份");
            } finally {
                Arrays.fill(keyPassword, '\0');
                Arrays.fill(trustPassword, '\0');
            }
        }

        private static String storeType(String value, String label) {
            String normalized = value.toUpperCase(Locale.ROOT);
            if (!"PKCS12".equals(normalized) && !"JKS".equals(normalized)) {
                throw new UsageException("--" + label + "只允许PKCS12或JKS");
            }
            return normalized;
        }

        private static void validateClientKeyStore(KeyStore store, char[] password)
                throws Exception {
            String privateAlias = null;
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (store.isKeyEntry(alias)) {
                    if (privateAlias != null) {
                        throw new MassDbLicenseException(
                                "MASSDB_LICENSE_CLI_CREDENTIAL_INVALID",
                                "client key store必须且只能包含一个私钥条目");
                    }
                    privateAlias = alias;
                }
            }
            if (privateAlias == null
                    || !(store.getKey(privateAlias, password) instanceof PrivateKey)
                    || !(store.getCertificate(privateAlias) instanceof X509Certificate)) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_CLI_CREDENTIAL_INVALID",
                        "client key store缺少唯一X.509私钥身份");
            }
            X509Certificate leaf = (X509Certificate) store.getCertificate(privateAlias);
            leaf.checkValidity(new Date());
            MassDbLicenseIdentityKeyMaterial.requireLeafUsage(leaf, false);
            MassDbLicenseManagementIdentity.parsePeerCertificate(leaf);
        }

        private static void validateServerTrustStore(KeyStore store) throws Exception {
            int roots = 0;
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (store.isKeyEntry(alias)
                        || !(store.getCertificate(alias) instanceof X509Certificate)
                        || ((X509Certificate) store.getCertificate(alias))
                                .getBasicConstraints() < 0) {
                    throw new MassDbLicenseException(
                            "MASSDB_LICENSE_CLI_CREDENTIAL_INVALID",
                            "server trust store只能包含X.509 CA证书");
                }
                roots++;
            }
            if (roots == 0) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_CLI_CREDENTIAL_INVALID",
                        "server trust store不能为空");
            }
        }

        @Override
        public Response request(String method, String path,
                Map<String, String> headers, byte[] body) {
            HttpsURLConnection connection = null;
            try {
                connection = (HttpsURLConnection) new URL(
                        endpoint + MassDbLicenseAction.BASE_PATH + path).openConnection();
                connection.setSSLSocketFactory(sslContext.getSocketFactory());
                connection.setInstanceFollowRedirects(false);
                connection.setConnectTimeout(connectTimeoutMillis);
                connection.setReadTimeout(readTimeoutMillis);
                connection.setRequestMethod(method);
                connection.setRequestProperty("Accept", "application/json");
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    connection.setRequestProperty(header.getKey(), header.getValue());
                }
                if (body != null) {
                    connection.setDoOutput(true);
                    connection.setFixedLengthStreamingMode(body.length);
                    try (OutputStream output = connection.getOutputStream()) {
                        output.write(body);
                    }
                }
                int status = connection.getResponseCode();
                InputStream response = status >= HttpURLConnection.HTTP_BAD_REQUEST
                        ? connection.getErrorStream() : connection.getInputStream();
                return new Response(status, readResponse(response));
            } catch (IOException failure) {
                throw new MassDbLicenseException(
                        "MASSDB_LICENSE_CLI_NETWORK_FAILED",
                        "无法完成mTLS License管理请求");
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
        }

        private static String strictEndpoint(String value) {
            try {
                URI uri = new URI(value);
                String path = uri.getRawPath();
                if (!"https".equals(uri.getScheme()) || uri.getHost() == null
                        || uri.getUserInfo() != null || uri.getRawQuery() != null
                        || uri.getRawFragment() != null
                        || (path != null && !path.isEmpty() && !"/".equals(path))) {
                    throw new UsageException(
                            "--endpoint必须是不带路径、用户信息和查询的https://host:port");
                }
                String result = uri.toASCIIString();
                return result.endsWith("/")
                        ? result.substring(0, result.length() - 1) : result;
            } catch (URISyntaxException failure) {
                throw new UsageException("--endpoint不是合法HTTPS URI");
            }
        }

        private static int positiveInteger(String value, String label) {
            try {
                int result = Integer.parseInt(value);
                if (result <= 0 || result > 300_000) {
                    throw new NumberFormatException();
                }
                return result;
            } catch (NumberFormatException failure) {
                throw new UsageException("--" + label + "必须是1至300000的整数");
            }
        }

        private static String readResponse(InputStream input) throws IOException {
            if (input == null) {
                return "";
            }
            try (InputStream response = input;
                    ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int count;
                while ((count = response.read(buffer)) >= 0) {
                    if (count == 0) {
                        continue;
                    }
                    if (output.size() + count > MAX_RESPONSE_BYTES) {
                        throw new IOException("response too large");
                    }
                    output.write(buffer, 0, count);
                }
                return new String(output.toByteArray(), StandardCharsets.UTF_8);
            }
        }
    }

    private static final class Options {
        private final String command;
        private final Map<String, List<String>> values;

        private Options(String command, Map<String, List<String>> values) {
            this.command = command;
            this.values = values;
        }

        private static Options parse(String[] args) {
            if (args.length == 0 || args[0] == null || args[0].trim().isEmpty()) {
                throw new UsageException("缺少命令");
            }
            Map<String, List<String>> values = new LinkedHashMap<>();
            for (int index = 1; index < args.length; index += 2) {
                if (args[index] == null || !args[index].startsWith("--")
                        || args[index].length() <= 2 || index + 1 >= args.length) {
                    throw new UsageException("参数必须使用 --name value 成对提供");
                }
                String name = args[index].substring(2);
                String value = args[index + 1];
                if (value == null || value.isEmpty()) {
                    throw new UsageException("--" + name + "不能为空");
                }
                values.computeIfAbsent(name, ignored -> new ArrayList<>()).add(value);
            }
            for (Map.Entry<String, List<String>> entry : values.entrySet()) {
                if (entry.getValue().size() != 1) {
                    throw new UsageException("--" + entry.getKey() + "不能重复");
                }
            }
            return new Options(args[0], values);
        }

        private String requiredOne(String name) {
            List<String> found = values.get(name);
            if (found == null || found.size() != 1) {
                throw new UsageException("缺少 --" + name);
            }
            return found.get(0);
        }

        private String oneOrDefault(String name, String fallback) {
            List<String> found = values.get(name);
            return found == null ? fallback : found.get(0);
        }

        private void requireOnly(List<String> allowed) {
            for (String name : values.keySet()) {
                if (!allowed.contains(name)) {
                    throw new UsageException("当前命令不接受 --" + name);
                }
            }
        }
    }

    private static final class ValidationBody {
        private boolean readyForImport;
        private String preconditionToken;
    }

    private static final class ControlValidationBody {
        private boolean readyForApply;
        private String preconditionToken;
    }

    private static final class EnforcementValidationBody {
        private boolean readyForActivation;
        private String preconditionToken;
    }

    private static final class BootstrapValidationBody {
        private boolean readyForApply;
        private String preconditionToken;
    }

    private static final class UpgradeValidationBody {
        private boolean readyForApply;
        private String preconditionToken;
    }

    private static final class ServerErrorBody {
        private String code;
    }

    private static final class HttpFailure extends RuntimeException {
        private final Response response;

        private HttpFailure(Response response) {
            this.response = response;
        }
    }

    private static final class UsageException extends RuntimeException {
        private UsageException(String message) {
            super(message);
        }
    }
}
