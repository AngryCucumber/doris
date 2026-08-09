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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;

class MassDbLicenseLocalAuditTest {
    @TempDir
    Path directory;

    @Test
    void persistsHashChainAndDetectsTampering() throws IOException {
        MassDbLicenseLocalAudit audit = MassDbLicenseLocalAudit.open(directory);
        MassDbLicenseLocalAudit.Event event = event("REQUEST", "ACCEPTED", 0);
        audit.append(event);
        event = event("RESULT", "OK", 202);
        event.occurredAt++;
        audit.append(event);

        MassDbLicenseLocalAudit.open(directory);
        Path path = directory.resolve(MassDbLicenseLocalAudit.DIRECTORY_NAME)
                .resolve(MassDbLicenseLocalAudit.FILE_NAME);
        Assertions.assertEquals(2,
                Files.readAllLines(path, StandardCharsets.UTF_8).size());

        byte[] value = Files.readAllBytes(path);
        value[value.length / 2] ^= 1;
        Files.write(path, value);
        MassDbLicenseException failure = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseLocalAudit.open(directory));
        Assertions.assertEquals("MASSDB_LICENSE_AUDIT_TAMPERED", failure.getCode());
    }

    @Test
    void rejectsRelativeMetaDirectory() {
        MassDbLicenseException failure = Assertions.assertThrows(
                MassDbLicenseException.class,
                () -> MassDbLicenseLocalAudit.open(Paths.get("relative-meta")));
        Assertions.assertEquals("MASSDB_LICENSE_AUDIT_INVALID", failure.getCode());
    }

    private static MassDbLicenseLocalAudit.Event event(
            String phase, String resultCode, int status) {
        MassDbLicenseLocalAudit.Event event = new MassDbLicenseLocalAudit.Event();
        event.occurredAt = 100;
        event.principalSubjectDigest = String.join("", Collections.nCopies(64, "a"));
        event.principalRole = "ADMIN";
        event.method = "POST";
        event.path = "/api/massdb/license/v1/import";
        event.phase = phase;
        event.resultCode = resultCode;
        event.httpStatus = status;
        return event;
    }
}
