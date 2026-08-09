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

/** Strict wire objects for the pre-journal existing-cluster FE attestation exchange. */
public final class MassDbLicenseUpgradeProtocol {
    public static final int VERSION = 1;
    public static final String PATH =
            "/api/massdb/license/internal/v1/upgrade/observe/attest";
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT);

    private MassDbLicenseUpgradeProtocol() {
    }

    public static byte[] encode(Object value) throws IOException {
        return MAPPER.writeValueAsBytes(value);
    }

    public static <T> T decode(byte[] value, Class<T> type) throws IOException {
        if (value == null || value.length == 0) {
            throw new IOException("empty MassDB License upgrade attestation payload");
        }
        return MAPPER.readValue(value, type);
    }

    public static final class Request {
        public int protocolVersion;
        public String upgradeSessionId;
        public String deploymentUuid;
        public String planSha256;
        public String membershipSha256;
        public String requesterNodeUuid;
        public String expectedNodeUuid;
        public String challenge;
        public long requestedAt;

        public Request() {
        }

        Request(String upgradeSessionId, String deploymentUuid,
                String planSha256, String membershipSha256,
                String requesterNodeUuid, String expectedNodeUuid,
                String challenge, long requestedAt) {
            this.protocolVersion = VERSION;
            this.upgradeSessionId = upgradeSessionId;
            this.deploymentUuid = deploymentUuid;
            this.planSha256 = planSha256;
            this.membershipSha256 = membershipSha256;
            this.requesterNodeUuid = requesterNodeUuid;
            this.expectedNodeUuid = expectedNodeUuid;
            this.challenge = challenge;
            this.requestedAt = requestedAt;
        }
    }

    public static final class Response {
        public int protocolVersion;
        public String upgradeSessionId;
        public String deploymentUuid;
        public String planSha256;
        public String membershipSha256;
        public String nodeUuid;
        public String challenge;
        public String componentType;
        public String componentVersion;
        public String capabilityVersion;
        public int stateFormatVersion;
        public int journalOperationType;
        public String snapshotFormat;
        public String binarySha256;
        public long observedAt;

        public Response() {
        }

        Response(MassDbLicenseUpgradeMarker.Attestation marker,
                MassDbLicenseBuildIdentity build, String membershipSha256,
                String challenge, long observedAt) {
            this.protocolVersion = VERSION;
            this.upgradeSessionId = marker.upgradeSessionId;
            this.deploymentUuid = marker.licenseControlDeploymentUuid;
            this.planSha256 = marker.upgradePlanSha256;
            this.membershipSha256 = membershipSha256;
            this.nodeUuid = marker.localNodeUuid;
            this.challenge = challenge;
            this.componentType = build.componentType;
            this.componentVersion = build.componentVersion;
            this.capabilityVersion = build.capabilityVersion;
            this.stateFormatVersion = build.stateFormatVersion;
            this.journalOperationType = build.journalOperationType;
            this.snapshotFormat = build.snapshotFormat;
            this.binarySha256 = build.binarySha256;
            this.observedAt = observedAt;
        }
    }
}
