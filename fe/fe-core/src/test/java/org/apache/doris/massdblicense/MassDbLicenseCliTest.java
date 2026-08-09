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
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

class MassDbLicenseCliTest {
    @TempDir
    Path directory;

    @Test
    void normalImportAlwaysValidatesActualBytesBeforeDispatch() throws Exception {
        Path license = directory.resolve("candidate.mlic");
        Files.write(license, MassDbLicenseProtocolV1Test.validLicenseBytes());
        RecordingTransport transport = new RecordingTransport();
        transport.responses.add(new MassDbLicenseCli.Response(200,
                "{\"readyForImport\":true,\"preconditionToken\":\"opaque-token\"}"));
        transport.responses.add(new MassDbLicenseCli.Response(202,
                "{\"operationId\":\"operation-1\",\"apiState\":\"AWAITING_ACK\"}"));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ByteArrayOutputStream error = new ByteArrayOutputStream();

        int result = MassDbLicenseCli.run(new String[] {
                "license-import", "--license-file", license.toString(),
                "--idempotency-key", "manager-1:LICENSE_IMPORT:request-1"
        }, new PrintStream(output), new PrintStream(error), transport);

        Assertions.assertEquals(0, result);
        Assertions.assertEquals(2, transport.calls.size());
        Assertions.assertEquals("/validate", transport.calls.get(0).path);
        Assertions.assertEquals("/import", transport.calls.get(1).path);
        Assertions.assertEquals(transport.calls.get(0).headers.get("Content-SHA256"),
                transport.calls.get(1).headers.get("Content-SHA256"));
        Assertions.assertEquals("\"opaque-token\"",
                transport.calls.get(1).headers.get("If-Match"));
        Assertions.assertEquals("manager-1:LICENSE_IMPORT:request-1",
                transport.calls.get(1).headers.get("Idempotency-Key"));
        Assertions.assertArrayEquals(transport.calls.get(0).body,
                transport.calls.get(1).body);
        Assertions.assertTrue(output.toString("UTF-8").contains("operation-1"));
        Assertions.assertEquals("", error.toString("UTF-8"));
    }

    @Test
    void refusesImportWhenValidationHasNoFreshPrecondition() throws Exception {
        Path license = directory.resolve("candidate.mlic");
        Files.write(license, MassDbLicenseProtocolV1Test.validLicenseBytes());
        RecordingTransport transport = new RecordingTransport();
        transport.responses.add(new MassDbLicenseCli.Response(200,
                "{\"readyForImport\":false,\"warnings\":[\"INGRESS_UNAVAILABLE\"]}"));
        ByteArrayOutputStream error = new ByteArrayOutputStream();

        int result = MassDbLicenseCli.run(new String[] {
                "license-import", "--license-file", license.toString(),
                "--idempotency-key", "request-1"
        }, new PrintStream(new ByteArrayOutputStream()), new PrintStream(error), transport);

        Assertions.assertEquals(3, result);
        Assertions.assertEquals(1, transport.calls.size());
        Assertions.assertTrue(error.toString("UTF-8")
                .contains("MASSDB_LICENSE_IMPORT_NOT_READY"));
    }

    @Test
    void printsStableServerErrorAndRejectsUnsafePathBeforeNetwork() throws Exception {
        RecordingTransport rejected = new RecordingTransport();
        rejected.responses.add(new MassDbLicenseCli.Response(403,
                "{\"code\":\"MASSDB_LICENSE_RBAC_FORBIDDEN\"}"));
        ByteArrayOutputStream serverError = new ByteArrayOutputStream();
        int rejectedResult = MassDbLicenseCli.run(
                new String[] {"license-status"},
                new PrintStream(new ByteArrayOutputStream()),
                new PrintStream(serverError), rejected);
        Assertions.assertEquals(3, rejectedResult);
        Assertions.assertTrue(serverError.toString("UTF-8")
                .contains("MASSDB_LICENSE_RBAC_FORBIDDEN"));

        RecordingTransport untouched = new RecordingTransport();
        ByteArrayOutputStream usageError = new ByteArrayOutputStream();
        int unsafe = MassDbLicenseCli.run(new String[] {
                "license-operation", "--operation-id", "../../state"
        }, new PrintStream(new ByteArrayOutputStream()),
                new PrintStream(usageError), untouched);
        Assertions.assertEquals(2, unsafe);
        Assertions.assertTrue(untouched.calls.isEmpty());
        Assertions.assertTrue(usageError.toString("UTF-8")
                .contains("MASSDB_LICENSE_CLI_USAGE"));
    }

    @Test
    void dispatchesMinimalTopologyAndObserveUpgradePreflightWithoutMutationHeaders() {
        RecordingTransport metricsTransport = new RecordingTransport();
        metricsTransport.responses.add(new MassDbLicenseCli.Response(200,
                "massdb_license_state{state=\"ACTIVE\"} 1\n"));
        ByteArrayOutputStream metricsOutput = new ByteArrayOutputStream();
        int metrics = MassDbLicenseCli.run(new String[] {
                "license-metrics"
        }, new PrintStream(metricsOutput), new PrintStream(new ByteArrayOutputStream()),
                metricsTransport);
        Assertions.assertEquals(0, metrics);
        Assertions.assertEquals("GET", metricsTransport.calls.get(0).method);
        Assertions.assertEquals("/metrics", metricsTransport.calls.get(0).path);
        Assertions.assertTrue(new String(metricsOutput.toByteArray(), StandardCharsets.UTF_8)
                .contains("massdb_license_state"));

        RecordingTransport topologyTransport = new RecordingTransport();
        topologyTransport.responses.add(new MassDbLicenseCli.Response(200,
                "{\"schemaVersion\":\"massdb-sql-minimal-topology/v1\"}"));
        int topology = MassDbLicenseCli.run(new String[] {
                "license-topology-minimal"
        }, new PrintStream(new ByteArrayOutputStream()),
                new PrintStream(new ByteArrayOutputStream()), topologyTransport);
        Assertions.assertEquals(0, topology);
        Assertions.assertEquals("GET", topologyTransport.calls.get(0).method);
        Assertions.assertEquals("/topology/minimal", topologyTransport.calls.get(0).path);
        Assertions.assertTrue(topologyTransport.calls.get(0).headers.isEmpty());
        Assertions.assertNull(topologyTransport.calls.get(0).body);

        RecordingTransport preflightTransport = new RecordingTransport();
        preflightTransport.responses.add(new MassDbLicenseCli.Response(200,
                "{\"safeToInitializeObserve\":false}"));
        int preflight = MassDbLicenseCli.run(new String[] {
                "license-upgrade-observe-preflight"
        }, new PrintStream(new ByteArrayOutputStream()),
                new PrintStream(new ByteArrayOutputStream()), preflightTransport);
        Assertions.assertEquals(0, preflight);
        Assertions.assertEquals("GET", preflightTransport.calls.get(0).method);
        Assertions.assertEquals("/upgrade/observe/preflight",
                preflightTransport.calls.get(0).path);
        Assertions.assertTrue(preflightTransport.calls.get(0).headers.isEmpty());
        Assertions.assertNull(preflightTransport.calls.get(0).body);
    }

    @Test
    void createsLocalBootstrapMarkerWithoutNetworkAndDispatchesValidatedPlan() throws Exception {
        Path meta = Files.createDirectory(directory.resolve("meta"));
        Path plan = directory.resolve("bootstrap-plan.json");
        Path marker = meta.resolve("bootstrap-control.marker");
        Files.write(plan, bootstrapPlan());
        RecordingTransport untouched = new RecordingTransport();
        ByteArrayOutputStream nodeOutput = new ByteArrayOutputStream();
        int nodeResult = MassDbLicenseCli.run(new String[] {
                "license-node-uuid-init", "--meta-dir", meta.toString()
        }, new PrintStream(nodeOutput), new PrintStream(new ByteArrayOutputStream()), untouched);
        Assertions.assertEquals(0, nodeResult);
        Assertions.assertTrue(nodeOutput.toString("UTF-8").contains("nodeUuid"));
        ByteArrayOutputStream markerOutput = new ByteArrayOutputStream();
        int markerResult = MassDbLicenseCli.run(new String[] {
                "license-bootstrap-marker-create",
                "--plan-file", plan.toString(),
                "--marker-file", marker.toString(),
                "--meta-dir", meta.toString()
        }, new PrintStream(markerOutput), new PrintStream(new ByteArrayOutputStream()), untouched);
        Assertions.assertEquals(0, markerResult);
        Assertions.assertTrue(Files.isRegularFile(marker));
        Assertions.assertTrue(untouched.calls.isEmpty());
        Assertions.assertTrue(markerOutput.toString("UTF-8").contains("ELIGIBLE"));
        Assertions.assertTrue(markerOutput.toString("UTF-8")
                .contains("\"planFormatVersion\":1"));
        Assertions.assertTrue(markerOutput.toString("UTF-8")
                .contains("\"desiredIngressNodes\":1"));

        RecordingTransport transport = new RecordingTransport();
        transport.responses.add(new MassDbLicenseCli.Response(200,
                "{\"readyForApply\":true,\"preconditionToken\":\"bootstrap-token\"}"));
        transport.responses.add(new MassDbLicenseCli.Response(200,
                "{\"operationId\":\"bootstrap-operation\",\"apiState\":\"SEALED\"}"));
        int applyResult = MassDbLicenseCli.run(new String[] {
                "license-bootstrap-apply",
                "--plan-file", plan.toString(),
                "--idempotency-key", "manager-1:BOOTSTRAP_CONTROL:request-1"
        }, new PrintStream(new ByteArrayOutputStream()),
                new PrintStream(new ByteArrayOutputStream()), transport);
        Assertions.assertEquals(0, applyResult);
        Assertions.assertEquals("/bootstrap/validate", transport.calls.get(0).path);
        Assertions.assertEquals("/bootstrap/apply", transport.calls.get(1).path);
        Assertions.assertEquals("application/json",
                transport.calls.get(1).headers.get("Content-Type"));
        Assertions.assertEquals("\"bootstrap-token\"",
                transport.calls.get(1).headers.get("If-Match"));

        RecordingTransport replay = new RecordingTransport();
        replay.responses.add(new MassDbLicenseCli.Response(409,
                "{\"code\":\"MASSDB_LICENSE_BOOTSTRAP_SEALED\"}"));
        replay.responses.add(new MassDbLicenseCli.Response(200,
                "{\"operationId\":\"bootstrap-operation\",\"apiState\":\"SEALED\"}"));
        int replayResult = MassDbLicenseCli.run(new String[] {
                "license-bootstrap-apply",
                "--plan-file", plan.toString(),
                "--idempotency-key", "manager-1:BOOTSTRAP_CONTROL:request-2"
        }, new PrintStream(new ByteArrayOutputStream()),
                new PrintStream(new ByteArrayOutputStream()), replay);
        Assertions.assertEquals(0, replayResult);
        Assertions.assertEquals("/bootstrap/apply", replay.calls.get(1).path);
        Assertions.assertFalse(replay.calls.get(1).headers.containsKey("If-Match"));
    }

    @Test
    void createsExistingClusterUpgradeMarkerAndDispatchesFreshAttestedApply()
            throws Exception {
        Path meta = Files.createDirectory(directory.resolve("upgrade-meta"));
        Files.createDirectory(meta.resolve("image"));
        String nodeUuid = new MassDbLicenseLocalSnapshotStore(
                meta.resolve("massdb-license")).getNodeUuid();
        MassDbLicenseBuildIdentity build = MassDbLicenseBuildIdentity.current();
        Path plan = directory.resolve("upgrade-plan.json");
        Path marker = meta.resolve("license-upgrade.marker");
        Files.write(plan, upgradePlan(nodeUuid, build));

        RecordingTransport untouched = new RecordingTransport();
        ByteArrayOutputStream identityOutput = new ByteArrayOutputStream();
        int identityResult = MassDbLicenseCli.run(new String[] {
                "license-upgrade-build-identity"
        }, new PrintStream(identityOutput), new PrintStream(new ByteArrayOutputStream()),
                untouched);
        Assertions.assertEquals(0, identityResult);
        Assertions.assertTrue(identityOutput.toString("UTF-8")
                .contains(build.binarySha256));

        ByteArrayOutputStream markerOutput = new ByteArrayOutputStream();
        int markerResult = MassDbLicenseCli.run(new String[] {
                "license-upgrade-marker-create", "--plan-file", plan.toString(),
                "--marker-file", marker.toString(), "--meta-dir", meta.toString()
        }, new PrintStream(markerOutput), new PrintStream(new ByteArrayOutputStream()),
                untouched);
        Assertions.assertEquals(0, markerResult);
        Assertions.assertTrue(markerOutput.toString("UTF-8").contains("\"status\":\"READY\""));
        Assertions.assertTrue(markerOutput.toString("UTF-8")
                .contains("\"requiredFrontends\":1"));
        Assertions.assertTrue(untouched.calls.isEmpty());

        ByteArrayOutputStream retryOutput = new ByteArrayOutputStream();
        Assertions.assertEquals(0, MassDbLicenseCli.run(new String[] {
                "license-upgrade-marker-create", "--plan-file", plan.toString(),
                "--marker-file", marker.toString(), "--meta-dir", meta.toString()
        }, new PrintStream(retryOutput), new PrintStream(new ByteArrayOutputStream()),
                untouched));
        Assertions.assertEquals(markerOutput.toString("UTF-8"), retryOutput.toString("UTF-8"));

        RecordingTransport transport = new RecordingTransport();
        transport.responses.add(new MassDbLicenseCli.Response(200,
                "{\"readyForApply\":true,\"preconditionToken\":\"upgrade-token\"}"));
        transport.responses.add(new MassDbLicenseCli.Response(200,
                "{\"operationId\":\"upgrade-operation\",\"apiState\":\"SEALED\"}"));
        int applied = MassDbLicenseCli.run(new String[] {
                "license-upgrade-observe-apply", "--plan-file", plan.toString(),
                "--idempotency-key", "manager-1:INITIALIZE_OBSERVE:request-1"
        }, new PrintStream(new ByteArrayOutputStream()),
                new PrintStream(new ByteArrayOutputStream()), transport);
        Assertions.assertEquals(0, applied);
        Assertions.assertEquals("/upgrade/observe/validate", transport.calls.get(0).path);
        Assertions.assertEquals("/upgrade/observe/apply", transport.calls.get(1).path);
        Assertions.assertEquals("\"upgrade-token\"",
                transport.calls.get(1).headers.get("If-Match"));
        Assertions.assertEquals("manager-1:INITIALIZE_OBSERVE:request-1",
                transport.calls.get(1).headers.get("Idempotency-Key"));
        Assertions.assertEquals(transport.calls.get(0).headers.get("Content-SHA256"),
                transport.calls.get(1).headers.get("Content-SHA256"));

        RecordingTransport replay = new RecordingTransport();
        replay.responses.add(new MassDbLicenseCli.Response(409,
                "{\"code\":\"MASSDB_LICENSE_UPGRADE_ALREADY_INITIALIZED\"}"));
        replay.responses.add(new MassDbLicenseCli.Response(200,
                "{\"operationId\":\"upgrade-operation\",\"apiState\":\"SEALED\"}"));
        Assertions.assertEquals(0, MassDbLicenseCli.run(new String[] {
                "license-upgrade-observe-apply", "--plan-file", plan.toString(),
                "--idempotency-key", "manager-1:INITIALIZE_OBSERVE:request-1"
        }, new PrintStream(new ByteArrayOutputStream()),
                new PrintStream(new ByteArrayOutputStream()), replay));
        Assertions.assertFalse(replay.calls.get(1).headers.containsKey("If-Match"));
    }

    private static byte[] bootstrapPlan() {
        String keyset = Base64.getEncoder().encodeToString(
                MassDbLicenseProtocolV1Test.keysetBytes());
        String json = "{\"formatVersion\":1,\"componentType\":\"massdb-sql\","
                + "\"targetPhase\":\"SEALED\",\"keysetArtifactBase64\":\"" + keyset
                + "\",\"ingressNodes\":[{\"nodeUuid\":"
                + "\"00000000-0000-4000-8000-000000000061\","
                + "\"endpoint\":\"https://fe-1.example:8050\",\"desired\":true}],"
                + "\"minimumWriteHealth\":\"FE_LEADER_READY\"}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] upgradePlan(String nodeUuid, MassDbLicenseBuildIdentity build) {
        String keyset = Base64.getEncoder().encodeToString(
                MassDbLicenseProtocolV1Test.keysetBytes());
        String json = "{\"formatVersion\":1,\"componentType\":\"massdb-sql\","
                + "\"targetMode\":\"OBSERVE\",\"keysetArtifactBase64\":\""
                + keyset + "\",\"requiredBuild\":{"
                + "\"componentType\":\"massdb-sql\",\"componentVersion\":\""
                + build.componentVersion + "\",\"capabilityVersion\":\""
                + build.capabilityVersion + "\",\"stateFormatVersion\":"
                + build.stateFormatVersion + ",\"journalOperationType\":"
                + build.journalOperationType + ",\"snapshotFormat\":\""
                + build.snapshotFormat + "\",\"binarySha256\":\""
                + build.binarySha256 + "\"},\"frontends\":[{\"nodeUuid\":\""
                + nodeUuid + "\",\"role\":\"VOTER\",\"host\":\"fe-1.example\","
                + "\"editLogPort\":9010,\"httpsEndpoint\":\"https://fe-1.example:8050\"}]}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    private static final class RecordingTransport implements MassDbLicenseCli.Transport {
        private final List<Call> calls = new ArrayList<>();
        private final List<MassDbLicenseCli.Response> responses = new ArrayList<>();

        @Override
        public MassDbLicenseCli.Response request(String method, String path,
                Map<String, String> headers, byte[] body) {
            calls.add(new Call(method, path, new java.util.LinkedHashMap<>(headers),
                    body == null ? null : body.clone()));
            if (responses.isEmpty()) {
                throw new AssertionError("missing fake response");
            }
            return responses.remove(0);
        }
    }

    private static final class Call {
        private final String method;
        private final String path;
        private final Map<String, String> headers;
        private final byte[] body;

        private Call(String method, String path,
                Map<String, String> headers, byte[] body) {
            this.method = method;
            this.path = path;
            this.headers = headers;
            this.body = body;
        }
    }
}
