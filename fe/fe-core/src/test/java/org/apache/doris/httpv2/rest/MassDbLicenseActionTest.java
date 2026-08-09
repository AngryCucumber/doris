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

import org.apache.doris.massdblicense.MassDbLicenseBootstrapCore;
import org.apache.doris.massdblicense.MassDbLicenseImportCore;
import org.apache.doris.massdblicense.MassDbLicenseIngressInventory;
import org.apache.doris.massdblicense.MassDbLicenseJettyIdentityController;
import org.apache.doris.massdblicense.MassDbLicenseLocalAudit;
import org.apache.doris.massdblicense.MassDbLicenseManagementIdentity;
import org.apache.doris.massdblicense.MassDbLicenseManager;
import org.apache.doris.massdblicense.MassDbLicenseProtocolV1;
import org.apache.doris.massdblicense.MassDbLicenseProtocolV1Test;
import org.apache.doris.massdblicense.MassDbLicenseReadApiCore;
import org.apache.doris.massdblicense.MassDbLicenseState;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

class MassDbLicenseActionTest {
    @TempDir
    Path temporaryDirectory;

    private static final long NOW = 1_767_225_600L;
    private static final long MAX_TERM = 31_536_000L;
    private static final String LICENSE_SHA =
            "b3f71e8f014c7eaf0f81db83a13803b34648617d3baf2e38b3e44ef0700e1745";
    private static final String BOOTSTRAP_MARKER_ID =
            "00000000-0000-4000-8000-000000000051";
    private static final String BOOTSTRAP_DEPLOYMENT_ID =
            "00000000-0000-4000-8000-000000000052";
    private static final String BOOTSTRAP_NODE_ID =
            "00000000-0000-4000-8000-000000000053";
    private static final MassDbLicenseManagementIdentity.Principal VIEW =
            MassDbLicenseManagementIdentity.parse(
                    "spiffe://massdb.internal/license/operator/alice/view");
    private static final MassDbLicenseManagementIdentity.Principal ADMIN =
            MassDbLicenseManagementIdentity.parse(
                    "spiffe://massdb.internal/license/operator/alice/admin");

    @Test
    void disabledAndUnauthorizedRequestsNeverReadArtifactBody() throws Exception {
        Fixture fixture = fixture(true, ADMIN);
        fixture.runtime.enabled = false;
        HttpServletRequest disabled = Mockito.mock(HttpServletRequest.class);
        ResponseEntity<?> disabledResult = (ResponseEntity<?>)
                fixture.action.validate(disabled);
        Assertions.assertEquals(HttpStatus.NOT_FOUND, disabledResult.getStatusCode());
        Mockito.verifyNoInteractions(disabled);

        fixture.runtime.enabled = true;
        HttpServletRequest plain = Mockito.mock(HttpServletRequest.class);
        ResponseEntity<?> plainResult = (ResponseEntity<?>) fixture.action.validate(plain);
        Assertions.assertEquals(HttpStatus.UPGRADE_REQUIRED, plainResult.getStatusCode());
        Mockito.verify(plain, Mockito.never()).getInputStream();

        HttpServletRequest noCertificate = Mockito.mock(HttpServletRequest.class);
        Mockito.when(noCertificate.isSecure()).thenReturn(true);
        ResponseEntity<?> unauthorized = (ResponseEntity<?>)
                fixture.action.validate(noCertificate);
        Assertions.assertEquals(HttpStatus.UNAUTHORIZED, unauthorized.getStatusCode());
        Mockito.verify(noCertificate, Mockito.never()).getInputStream();

        fixture.controllerPrincipal = VIEW;
        HttpServletRequest viewImport = authenticatedRequest(new byte[] {1}, null);
        ResponseEntity<?> forbidden = (ResponseEntity<?>)
                fixture.action.importLicense(viewImport);
        Assertions.assertEquals(HttpStatus.FORBIDDEN, forbidden.getStatusCode());
        Mockito.verify(viewImport, Mockito.never()).getInputStream();

        fixture.controllerPrincipal = ADMIN;
        fixture.runtime.readyForWrite = false;
        HttpServletRequest followerImport = authenticatedRequest(new byte[] {1}, null);
        ResponseEntity<?> notLeader = (ResponseEntity<?>)
                fixture.action.importLicense(followerImport);
        Assertions.assertEquals(HttpStatus.SERVICE_UNAVAILABLE,
                notLeader.getStatusCode());
        Mockito.verify(followerImport, Mockito.never()).getInputStream();

        fixture.runtime.readyForWrite = true;
        fixture.controllerPrincipal = VIEW;
        HttpServletRequest forbiddenUpgrade = authenticatedRequest(new byte[] {1}, null);
        ResponseEntity<?> forbiddenUpgradeResult = (ResponseEntity<?>)
                fixture.action.observeUpgradeValidate(forbiddenUpgrade);
        Assertions.assertEquals(HttpStatus.FORBIDDEN,
                forbiddenUpgradeResult.getStatusCode());
        Mockito.verify(forbiddenUpgrade, Mockito.never()).getInputStream();

        fixture.controllerPrincipal = ADMIN;
        fixture.runtime.readyForWrite = false;
        HttpServletRequest followerUpgrade = authenticatedRequest(new byte[] {1}, null);
        ResponseEntity<?> followerUpgradeResult = (ResponseEntity<?>)
                fixture.action.observeUpgradeApply(followerUpgrade);
        Assertions.assertEquals(HttpStatus.SERVICE_UNAVAILABLE,
                followerUpgradeResult.getStatusCode());
        Mockito.verify(followerUpgrade, Mockito.never()).getInputStream();
    }

    @Test
    void capabilityWorksBeforeBootstrapButStatusFailsClosed() {
        Fixture fixture = fixture(false, VIEW);
        ResponseEntity<?> capability = (ResponseEntity<?>)
                fixture.action.capability(authenticatedRequest(null, null));
        Assertions.assertEquals(HttpStatus.OK, capability.getStatusCode());
        MassDbLicenseReadApiCore.Capability body =
                (MassDbLicenseReadApiCore.Capability) capability.getBody();
        Assertions.assertEquals("UNINITIALIZED", body.enforcementMode);
        Assertions.assertNull(body.licenseControlDeploymentUuid);

        ResponseEntity<?> status = (ResponseEntity<?>)
                fixture.action.status(authenticatedRequest(null, null));
        Assertions.assertEquals(HttpStatus.CONFLICT, status.getStatusCode());
        Assertions.assertEquals("MASSDB_LICENSE_BOOTSTRAP_REQUIRED",
                ((MassDbLicenseAction.ErrorBody) status.getBody()).code);
    }

    @Test
    void diagnosticEventsAreViewReadableBoundedAndAvailableWithoutActiveLicense() {
        Fixture fixture = fixture(true, VIEW);
        fixture.runtime.manager.transition(state -> state.appendDiagnosticEvent(
                new MassDbLicenseState.DiagnosticEventInput(
                        "CRITICAL", "CONTROL_PLANE_STALE",
                        "MASSDB_LICENSE_CONTROL_PLANE_STALE",
                        "00000000-0000-4000-8000-000000000041", "", "fe-1",
                        "", "ENFORCING", "IN_SERVICE", true), NOW));
        fixture.runtime.manager.transition(state -> state.appendDiagnosticEvent(
                new MassDbLicenseState.DiagnosticEventInput(
                        "ERROR", "OPERATION_FAILED",
                        "MASSDB_LICENSE_INGRESS_UNAVAILABLE", "", "operation-1",
                        "operation-1", "", "", "", false), NOW + 1));

        HttpServletRequest firstRequest = authenticatedRequest(null, null);
        Mockito.when(firstRequest.getParameter("pageSize")).thenReturn("1");
        ResponseEntity<?> first = (ResponseEntity<?>)
                fixture.action.diagnosticEvents(firstRequest);
        Assertions.assertEquals(HttpStatus.OK, first.getStatusCode());
        MassDbLicenseState.DiagnosticEventPage firstPage =
                (MassDbLicenseState.DiagnosticEventPage) first.getBody();
        Assertions.assertEquals(1, firstPage.items.size());
        Assertions.assertTrue(firstPage.hasMore);

        HttpServletRequest secondRequest = authenticatedRequest(null, null);
        Mockito.when(secondRequest.getParameter("pageSize")).thenReturn("1");
        Mockito.when(secondRequest.getParameter("afterSequence"))
                .thenReturn(Long.toString(firstPage.nextSequence));
        MassDbLicenseState.DiagnosticEventPage secondPage =
                (MassDbLicenseState.DiagnosticEventPage) ((ResponseEntity<?>)
                        fixture.action.diagnosticEvents(secondRequest)).getBody();
        Assertions.assertEquals(1, secondPage.items.size());
        Assertions.assertFalse(secondPage.hasMore);

        HttpServletRequest invalidRequest = authenticatedRequest(null, null);
        Mockito.when(invalidRequest.getParameter("pageSize")).thenReturn("201");
        ResponseEntity<?> invalid = (ResponseEntity<?>)
                fixture.action.diagnosticEvents(invalidRequest);
        Assertions.assertEquals(HttpStatus.UNPROCESSABLE_ENTITY,
                invalid.getStatusCode());
        Assertions.assertEquals("MASSDB_LICENSE_DIAGNOSTIC_PAGE_INVALID",
                ((MassDbLicenseAction.ErrorBody) invalid.getBody()).code);
    }

    @Test
    void authenticatedManagementRequestWritesHashChainedRequestAndResultAudit()
            throws Exception {
        Fixture fixture = fixture(true, VIEW);
        fixture.runtime.localAudit = MassDbLicenseLocalAudit.open(temporaryDirectory);
        HttpServletRequest request = authenticatedRequest(null, null);
        Mockito.when(request.getMethod()).thenReturn("GET");
        Mockito.when(request.getRequestURI()).thenReturn(
                MassDbLicenseAction.BASE_PATH + "/status");

        ResponseEntity<?> response = (ResponseEntity<?>) fixture.action.status(request);

        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
        Path auditFile = temporaryDirectory.resolve("massdb-license-audit")
                .resolve("management-audit-v1.jsonl");
        java.util.List<String> records = Files.readAllLines(
                auditFile, StandardCharsets.UTF_8);
        Assertions.assertEquals(2, records.size());
        Assertions.assertTrue(records.get(0).contains("\"phase\":\"REQUEST\""));
        Assertions.assertTrue(records.get(1).contains("\"phase\":\"RESULT\""));
        Assertions.assertFalse(records.get(0).contains("?"));
    }

    @Test
    void validatesImportsFindsAndExplicitlyAbortsNormalOperation() {
        Fixture fixture = fixture(true, ADMIN);
        byte[] artifact = MassDbLicenseProtocolV1Test.validLicenseBytes();
        HttpServletRequest validateRequest = authenticatedRequest(artifact,
                Collections.singletonMap("Content-SHA256", LICENSE_SHA));
        ResponseEntity<?> validated = (ResponseEntity<?>)
                fixture.action.validate(validateRequest);
        Assertions.assertEquals(HttpStatus.OK, validated.getStatusCode());
        MassDbLicenseReadApiCore.ValidateResult validation =
                (MassDbLicenseReadApiCore.ValidateResult) validated.getBody();
        Assertions.assertTrue(validation.readyForImport);
        Assertions.assertEquals("\"" + validation.preconditionToken + "\"",
                validated.getHeaders().getETag());

        Map<String, String> importHeaders = new java.util.LinkedHashMap<>();
        importHeaders.put("Content-SHA256", LICENSE_SHA);
        importHeaders.put("Idempotency-Key", "license-api-test");
        importHeaders.put(HttpHeaders.IF_MATCH, validated.getHeaders().getETag());
        ResponseEntity<?> imported = (ResponseEntity<?>) fixture.action.importLicense(
                authenticatedRequest(artifact, importHeaders));
        Assertions.assertEquals(HttpStatus.ACCEPTED, imported.getStatusCode());
        MassDbLicenseState.OperationView operation =
                (MassDbLicenseState.OperationView) imported.getBody();
        Assertions.assertEquals("AWAITING_ACK", operation.apiState);
        Assertions.assertEquals(MassDbLicenseAction.BASE_PATH + "/operations/"
                + operation.operationId, imported.getHeaders().getLocation().toString());

        ResponseEntity<?> found = (ResponseEntity<?>) fixture.action.operation(
                authenticatedRequest(null, null), operation.operationId);
        Assertions.assertEquals(HttpStatus.OK, found.getStatusCode());
        ResponseEntity<?> foundByKey = (ResponseEntity<?>)
                fixture.action.operationByIdempotencyKey(
                        authenticatedRequest(null, null), "license-api-test");
        Assertions.assertEquals(operation.operationId,
                ((MassDbLicenseState.OperationView) foundByKey.getBody()).operationId);

        ResponseEntity<?> aborted = (ResponseEntity<?>) fixture.action.abort(
                authenticatedRequest(null, null), operation.operationId);
        Assertions.assertEquals(HttpStatus.OK, aborted.getStatusCode());
        Assertions.assertEquals("ABORTED",
                ((MassDbLicenseState.OperationView) aborted.getBody()).apiState);
        Assertions.assertEquals("no-store",
                aborted.getHeaders().getFirst(HttpHeaders.CACHE_CONTROL));
    }

    @Test
    void rejectsForgedDigestBeforeIdempotencyLookup() {
        Fixture fixture = fixture(true, ADMIN);
        byte[] artifact = MassDbLicenseProtocolV1Test.validLicenseBytes();
        Map<String, String> headers = new java.util.LinkedHashMap<>();
        headers.put("Content-SHA256", repeat('0'));
        headers.put("Idempotency-Key", "license-api-test");
        headers.put(HttpHeaders.IF_MATCH, "ignored");
        ResponseEntity<?> rejected = (ResponseEntity<?>) fixture.action.importLicense(
                authenticatedRequest(artifact, headers));
        Assertions.assertEquals(HttpStatus.UNPROCESSABLE_ENTITY,
                rejected.getStatusCode());
        Assertions.assertEquals("MASSDB_LICENSE_CONTENT_SHA256_MISMATCH",
                ((MassDbLicenseAction.ErrorBody) rejected.getBody()).code);
        Assertions.assertNull(fixture.runtime.manager.snapshot()
                .findOperationByIdempotencyKey("license-api-test"));
    }

    @Test
    void bootstrapApiValidatesAndAtomicallySealsFirstTrustAndIngressState() {
        byte[] plan = bootstrapPlan();
        Fixture fixture = bootstrapFixture(plan);
        ResponseEntity<?> status = (ResponseEntity<?>) fixture.action.bootstrapStatus(
                authenticatedRequest(null, null));
        Assertions.assertEquals(HttpStatus.OK, status.getStatusCode());
        Assertions.assertEquals("OPEN",
                ((MassDbLicenseBootstrapCore.BootstrapStatus) status.getBody()).bootstrapPhase);

        Map<String, String> validateHeaders = Collections.singletonMap(
                "Content-SHA256", sha256(plan));
        ResponseEntity<?> validated = (ResponseEntity<?>) fixture.action.bootstrapValidate(
                authenticatedRequest(plan, validateHeaders));
        Assertions.assertEquals(HttpStatus.OK, validated.getStatusCode());
        MassDbLicenseBootstrapCore.ValidateResult validation =
                (MassDbLicenseBootstrapCore.ValidateResult) validated.getBody();
        Assertions.assertTrue(validation.readyForApply);

        Map<String, String> applyHeaders = new java.util.LinkedHashMap<>();
        applyHeaders.put("Content-SHA256", sha256(plan));
        applyHeaders.put("Idempotency-Key", "bootstrap-api-test");
        applyHeaders.put(HttpHeaders.IF_MATCH, validated.getHeaders().getETag());
        ResponseEntity<?> applied = (ResponseEntity<?>) fixture.action.bootstrapApply(
                authenticatedRequest(plan, applyHeaders));
        Assertions.assertEquals(HttpStatus.OK, applied.getStatusCode());
        MassDbLicenseState.OperationView operation =
                (MassDbLicenseState.OperationView) applied.getBody();
        Assertions.assertEquals("SEALED", operation.apiState);
        Assertions.assertEquals("SEALED",
                fixture.runtime.manager.snapshot().getBootstrapPhase());
        Assertions.assertEquals(1,
                fixture.runtime.manager.snapshot().getBootstrapSealGeneration());

        Map<String, String> replayHeaders = new java.util.LinkedHashMap<>();
        replayHeaders.put("Content-SHA256", sha256(plan));
        replayHeaders.put("Idempotency-Key", "bootstrap-api-replay");
        ResponseEntity<?> replayed = (ResponseEntity<?>) fixture.action.bootstrapApply(
                authenticatedRequest(plan, replayHeaders));
        Assertions.assertEquals(HttpStatus.OK, replayed.getStatusCode());
        Assertions.assertEquals(operation.operationId,
                ((MassDbLicenseState.OperationView) replayed.getBody()).operationId);
        ResponseEntity<?> sealedStatus = (ResponseEntity<?>) fixture.action.bootstrapStatus(
                authenticatedRequest(null, null));
        Assertions.assertEquals("CONSUMED",
                ((MassDbLicenseBootstrapCore.BootstrapStatus)
                        sealedStatus.getBody()).localMarkerStatus);
    }

    private static Fixture fixture(boolean initialized,
            MassDbLicenseManagementIdentity.Principal principal) {
        Map<String, PublicKey> roots = Collections.singletonMap(
                "massdb-test-root-1", MassDbLicenseProtocolV1.parsePublicKeyPem(
                        MassDbLicenseProtocolV1Test.rootPublicBytes()));
        MassDbLicenseState state = MassDbLicenseState.empty();
        if (initialized) {
            byte[] keysetBytes = MassDbLicenseProtocolV1Test.keysetBytes();
            MassDbLicenseProtocolV1.VerifiedKeyset verifiedKeyset =
                    MassDbLicenseProtocolV1.verifyKeyset(keysetBytes, roots, NOW, null);
            state = state.bootstrap(false, repeat('a'))
                    .prepareKeyset("keyset", "keyset-idem", repeat('b'),
                            MassDbLicenseState.MutationKind.ADDITIVE_KEYSET,
                            new MassDbLicenseState.ActiveKeyset(
                                    verifiedKeyset.getPayload().getKeysetVersion(),
                                    verifiedKeyset.getSha256(), keysetBytes), NOW, NOW + 60)
                    .commit("keyset", NOW);
            MassDbLicenseIngressInventory inventory = MassDbLicenseIngressInventory.empty()
                    .upsertConfigured("fe-1", "https://fe-1:8050", true);
            state = state.prepareIngressInventory("ingress", "ingress-idem", repeat('c'),
                    inventory, NOW, NOW + 60).commit("ingress", NOW)
                    .recordIngressHeartbeat("fe-1", true, NOW, NOW + 120)
                    .recordRoutingEvidence("fe-1",
                            MassDbLicenseIngressInventory.RoutingState.IN_SERVICE,
                            MassDbLicenseIngressInventory.EvidenceSource.MACHINE,
                            NOW, NOW + 120);
        }
        FakeRuntime runtime = new FakeRuntime(state,
                new MassDbLicenseReadApiCore("4.0.5", MAX_TERM, roots),
                new MassDbLicenseImportCore(MAX_TERM, roots));
        Fixture fixture = new Fixture(runtime, principal);
        Mockito.when(fixture.controller.isAvailable()).thenReturn(true);
        Mockito.when(fixture.controller.requireAllowedManagementClient(
                Mockito.any(X509Certificate[].class), Mockito.anyLong()))
                .thenAnswer(ignored -> fixture.controllerPrincipal);
        return fixture;
    }

    private static Fixture bootstrapFixture(byte[] plan) {
        Map<String, PublicKey> roots = Collections.singletonMap(
                "massdb-test-root-1", MassDbLicenseProtocolV1.parsePublicKeyPem(
                        MassDbLicenseProtocolV1Test.rootPublicBytes()));
        MassDbLicenseBootstrapCore.PlanSummary summary =
                MassDbLicenseBootstrapCore.summarize(plan);
        MassDbLicenseState state = MassDbLicenseState.empty().openBootstrap(
                BOOTSTRAP_MARKER_ID, BOOTSTRAP_DEPLOYMENT_ID,
                summary.planSha256, NOW - 60);
        MassDbLicenseImportCore importCore = new MassDbLicenseImportCore(MAX_TERM, roots);
        FakeRuntime runtime = new FakeRuntime(state,
                importCore.createReadApiCore("4.0.5"), importCore);
        Fixture fixture = new Fixture(runtime, ADMIN);
        Mockito.when(fixture.controller.isAvailable()).thenReturn(true);
        Mockito.when(fixture.controller.requireAllowedManagementClient(
                Mockito.any(X509Certificate[].class), Mockito.anyLong()))
                .thenReturn(ADMIN);
        Mockito.when(fixture.controller.requireLocalFeIdentity(
                Mockito.eq(BOOTSTRAP_DEPLOYMENT_ID), Mockito.anyLong()))
                .thenReturn(BOOTSTRAP_NODE_ID);
        return fixture;
    }

    private static HttpServletRequest authenticatedRequest(
            byte[] body, Map<String, String> headers) {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.isSecure()).thenReturn(true);
        Mockito.when(request.getAttribute("jakarta.servlet.request.X509Certificate"))
                .thenReturn(new X509Certificate[] {Mockito.mock(X509Certificate.class)});
        if (headers != null) {
            for (Map.Entry<String, String> header : headers.entrySet()) {
                Mockito.when(request.getHeader(header.getKey())).thenReturn(header.getValue());
            }
        }
        if (body != null) {
            Mockito.when(request.getContentLengthLong()).thenReturn((long) body.length);
            try {
                Mockito.when(request.getInputStream()).thenAnswer(
                        ignored -> new ByteArrayServletInputStream(body));
            } catch (IOException impossible) {
                throw new AssertionError(impossible);
            }
        }
        return request;
    }

    private static String repeat(char value) {
        return String.join("", Collections.nCopies(64, String.valueOf(value)));
    }

    private static byte[] bootstrapPlan() {
        String keyset = Base64.getEncoder().encodeToString(
                MassDbLicenseProtocolV1Test.keysetBytes());
        String json = "{\"formatVersion\":1,\"componentType\":\"massdb-sql\","
                + "\"targetPhase\":\"SEALED\",\"keysetArtifactBase64\":\"" + keyset
                + "\",\"ingressNodes\":[{\"nodeUuid\":\"" + BOOTSTRAP_NODE_ID
                + "\",\"endpoint\":\"https://fe-1.example:8050\",\"desired\":true}],"
                + "\"minimumWriteHealth\":\"FE_LEADER_READY\"}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static String sha256(byte[] value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            StringBuilder result = new StringBuilder(64);
            for (byte item : digest) {
                result.append(String.format(java.util.Locale.ROOT, "%02x", item & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static final class Fixture {
        private final FakeRuntime runtime;
        private final MassDbLicenseJettyIdentityController controller =
                Mockito.mock(MassDbLicenseJettyIdentityController.class);
        private final MassDbLicenseAction action;
        private MassDbLicenseManagementIdentity.Principal controllerPrincipal;

        private Fixture(FakeRuntime runtime,
                MassDbLicenseManagementIdentity.Principal principal) {
            this.runtime = runtime;
            this.controllerPrincipal = principal;
            runtime.controller = controller;
            this.action = new MassDbLicenseAction(runtime);
        }
    }

    private static final class FakeRuntime implements MassDbLicenseAction.RuntimeAccess {
        private boolean enabled = true;
        private boolean readyForWrite = true;
        private MassDbLicenseJettyIdentityController controller;
        private final MassDbLicenseManager manager;
        private final MassDbLicenseReadApiCore readCore;
        private final MassDbLicenseImportCore importCore;
        private final MassDbLicenseBootstrapCore bootstrapCore;
        private MassDbLicenseLocalAudit localAudit;

        private FakeRuntime(MassDbLicenseState state, MassDbLicenseReadApiCore readCore,
                MassDbLicenseImportCore importCore) {
            this.manager = new MassDbLicenseManager(state, ignored -> { });
            this.readCore = readCore;
            this.importCore = importCore;
            this.bootstrapCore = new MassDbLicenseBootstrapCore(importCore);
        }

        @Override
        public boolean enabled() {
            return enabled;
        }

        @Override
        public long wallClockEpochSecond() {
            return NOW;
        }

        @Override
        public MassDbLicenseJettyIdentityController identityController() {
            return controller;
        }

        @Override
        public boolean readyForWrite() {
            return readyForWrite;
        }

        @Override
        public MassDbLicenseManager manager() {
            return manager;
        }

        @Override
        public MassDbLicenseReadApiCore readCore() {
            return readCore;
        }

        @Override
        public MassDbLicenseImportCore importCore() {
            return importCore;
        }

        @Override
        public MassDbLicenseBootstrapCore bootstrapCore() {
            return bootstrapCore;
        }

        @Override
        public long operationAckDeadlineSeconds() {
            return 900;
        }

        @Override
        public MassDbLicenseLocalAudit localAudit() {
            return localAudit;
        }
    }

    private static final class ByteArrayServletInputStream extends ServletInputStream {
        private final ByteArrayInputStream input;

        private ByteArrayServletInputStream(byte[] value) {
            this.input = new ByteArrayInputStream(value);
        }

        @Override
        public int read() {
            return input.read();
        }

        @Override
        public int read(byte[] target, int offset, int length) {
            return input.read(target, offset, length);
        }

        @Override
        public boolean isFinished() {
            return input.available() == 0;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener listener) {
        }
    }
}
