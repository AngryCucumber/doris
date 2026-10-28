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

// Modified for MassDB SQL. See MODIFICATIONS.md for details.

package org.apache.doris.regression.suite

import org.apache.doris.regression.Config
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

import java.nio.file.Files
import java.nio.file.Path

import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertFalse
import static org.junit.jupiter.api.Assertions.assertTrue

class SuiteSshExecTest {
    private final String localUser = System.getProperty("user.name")

    @TempDir
    Path directory

    @Test
    void sshCommandAcceptsNewRegressionHosts() {
        assertEquals(
                "ssh -o StrictHostKeyChecking=no root@172.17.0.1 'mkdir -p /tmp/udf'",
                Suite.buildSshCommand("root", "172.17.0.1", "mkdir -p /tmp/udf"))
    }

    @Test
    void copiesLocalFixturesInBothDirectionsWithoutSsh() {
        def source = Files.writeString(directory.resolve("source.txt"), "local fixture")
        def targetDirectory = Files.createDirectory(directory.resolve("target"))
        Suite.scpFiles(localUser, "127.0.0.1", source.toString(), targetDirectory.toString(), false)
        def copied = targetDirectory.resolve("source.txt")
        assertEquals("local fixture", Files.readString(copied))
        def returned = directory.resolve("returned.txt")
        Suite.scpFiles(localUser, "127.0.0.1", copied.toString(), returned.toString(), true)
        assertEquals("local fixture", Files.readString(returned))
    }

    @Test
    void copiesLocalFixturePathsContainingShellCharacters() {
        def sourceDirectory = Files.createDirectory(directory.resolve("source dir"))
        def source = Files.writeString(sourceDirectory.resolve("it's \$HOME; *.txt"), "quoted fixture")
        def targetDirectory = Files.createDirectory(directory.resolve("target dir"))
        Suite.scpFiles(localUser, "127.0.0.1", source.toString(), targetDirectory.toString(), false)
        assertEquals("quoted fixture", Files.readString(targetDirectory.resolve("it's \$HOME; *.txt")))
        Suite.scpFiles(localUser, "127.0.0.1", sourceDirectory.toString(), targetDirectory.toString(), true)
        assertEquals("quoted fixture", Files.readString(
                targetDirectory.resolve("source dir").resolve("it's \$HOME; *.txt")))
    }

    @Test
    void unresolvableSshHostAliasIsNotTreatedAsLocal() {
        // Such aliases exist only in the SSH client configuration and must still be copied with scp.
        assertFalse(Suite.isLocalHostForUser(localUser, "massdb-ssh-alias.invalid"))
        assertTrue(Suite.isLocalHostForUser(localUser, "127.0.0.1"))
    }

    @Test
    void copyingLocalFixtureToItselfPreservesItsContents() {
        def source = Files.writeString(directory.resolve("source.txt"), "unchanged")
        Suite.scpFiles(localUser, "127.0.0.1", source.toString(), source.toString(), false)
        Suite.scpFiles(localUser, "127.0.0.1", source.toString(), directory.toString(), true)
        assertEquals("unchanged", Files.readString(source))
    }

    private Suite localFixtureSuite() {
        def suiteDirectory = Files.createDirectory(directory.resolve("suites"))
        def suiteFile = Files.createFile(suiteDirectory.resolve("local_udf.groovy")).toFile()
        def config = new Config(suitePath: suiteDirectory.toString(),
                dataPath: directory.resolve("data").toString(),
                realDataPath: directory.resolve("real-data").toString(), defaultDb: "regression_test")
        def scriptContext = new ScriptContext(suiteFile, null, null, config, [], { true })
        def cluster = new SuiteCluster("shared-local-udf", config)
        def context = new SuiteContext(suiteFile, "shared-local-udf", "p0", scriptContext,
                cluster, null, null, config)
        return new Suite("shared-local-udf", "p0", context, cluster)
    }

    @Test
    void preparesOneSharedUdfFileForMultipleLocalBackends() {
        def source = Files.writeString(directory.resolve("udf.jar"), "shared UDF fixture")
        def backends = ["1": "127.0.0.1", "2": "127.0.0.1", "3": "127.0.0.1"]
        Map observedHosts
        Suite.metaClass.getBackendIpHttpPort = { Map hosts, Map ports ->
            hosts.putAll(backends)
            observedHosts = hosts
        }
        Suite.metaClass.sshExec = { String user, String host, String command, boolean alert ->
            throw new AssertionError("Local UDF preparation must not require SSH")
        }
        try {
            def suite = localFixtureSuite()
            suite.scp_udf_file_to_all_be(source.toString())
            assertEquals(backends, observedHosts)
            assertEquals("shared UDF fixture", Files.readString(source))
        } finally {
            GroovySystem.metaClassRegistry.removeMetaClass(Suite)
        }
    }

    @Test
    void createsAndCleansSharedLocalExportDirectoryWithoutSsh() {
        Suite.metaClass.getBackendIpHeartbeatPort = { Map hosts, Map ports ->
            hosts.putAll(["1": "127.0.0.1", "2": "127.0.0.1", "3": "127.0.0.1"])
        }
        try {
            def suite = localFixtureSuite()
            def target = directory.resolve("export with spaces")
            suite.mkdirRemotePathOnAllBE(localUser, target.toString())
            assertTrue(Files.isDirectory(target))
            Files.writeString(target.resolve("result.csv"), "1,2")
            suite.deleteRemotePathOnAllBE(localUser, target.toString())
            assertFalse(Files.exists(target))
            assertTrue(Files.isDirectory(directory))
        } finally {
            GroovySystem.metaClassRegistry.removeMetaClass(Suite)
        }
    }
}
