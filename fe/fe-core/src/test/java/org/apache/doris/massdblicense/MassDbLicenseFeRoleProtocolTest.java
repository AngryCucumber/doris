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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

class MassDbLicenseFeRoleProtocolTest {
    @Test
    void decodesSpringJacksonBase64ArtifactWithoutChangingBytes() throws Exception {
        MassDbLicenseFeRoleProtocol.Command command =
                new MassDbLicenseFeRoleProtocol.Command();
        command.type = MassDbLicenseFeRoleProtocol.COMMAND_NORMAL;
        command.operationId = "normal-op";
        command.artifact = new byte[] {0, 1, -1, 127};
        MassDbLicenseFeRoleProtocol.ExchangeResponse response =
                new MassDbLicenseFeRoleProtocol.ExchangeResponse(
                        "00000000-0000-4000-8000-000000000001", 1,
                        Collections.singletonList(command), Collections.emptyList());

        byte[] springWire = new ObjectMapper().writeValueAsBytes(response);
        MassDbLicenseFeRoleProtocol.ExchangeResponse decoded =
                MassDbLicenseFeRoleProtocol.decode(springWire,
                        MassDbLicenseFeRoleProtocol.ExchangeResponse.class);

        Assertions.assertArrayEquals(command.artifact, decoded.commands.get(0).artifact);
        Assertions.assertTrue(new String(springWire, StandardCharsets.UTF_8)
                .contains("\"artifact\":\"AAH/fw==\""));
    }

    @Test
    void rejectsUnknownDuplicateAndTrailingFields() {
        assertInvalid("{\"protocolVersion\":1,\"unknown\":true}");
        assertInvalid("{\"protocolVersion\":1,\"protocolVersion\":1}");
        assertInvalid("{\"protocolVersion\":1} {\"protocolVersion\":1}");
    }

    private static void assertInvalid(String value) {
        Assertions.assertThrows(IOException.class,
                () -> MassDbLicenseFeRoleProtocol.decode(
                        value.getBytes(StandardCharsets.UTF_8),
                        MassDbLicenseFeRoleProtocol.ExchangeRequest.class));
    }
}
