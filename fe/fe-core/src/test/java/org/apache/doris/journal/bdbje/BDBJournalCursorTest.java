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

package org.apache.doris.journal.bdbje;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.common.Pair;
import org.apache.doris.common.io.Text;
import org.apache.doris.journal.JournalEntity;
import org.apache.doris.persist.OperationType;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.sleepycat.bind.tuple.TupleBinding;
import com.sleepycat.je.Database;
import com.sleepycat.je.DatabaseEntry;
import com.sleepycat.je.Environment;
import com.sleepycat.je.LockMode;
import com.sleepycat.je.OperationStatus;
import com.sleepycat.je.Transaction;
import com.sleepycat.je.TransactionConfig;
import com.sleepycat.je.rep.NoConsistencyRequiredPolicy;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class BDBJournalCursorTest {
    private static final Logger LOG = LogManager.getLogger(BDBEnvironmentTest.class);
    private static List<String> tmpDirs = new ArrayList<>();

    public static String createTmpDir() throws Exception {
        String dorisHome = System.getenv("DORIS_HOME");
        if (Strings.isNullOrEmpty(dorisHome)) {
            dorisHome = Files.createTempDirectory("DORIS_HOME").toAbsolutePath().toString();
        }
        Preconditions.checkArgument(!Strings.isNullOrEmpty(dorisHome));
        Path mockDir = Paths.get(dorisHome, "fe", "mocked");
        if (!Files.exists(mockDir)) {
            Files.createDirectories(mockDir);
        }
        UUID uuid = UUID.randomUUID();
        File dir = Files.createDirectories(Paths.get(dorisHome, "fe", "mocked", "BDBEnvironmentTest-" + uuid.toString())).toFile();
        if (LOG.isDebugEnabled()) {
            LOG.debug("createTmpDir path {}", dir.getAbsolutePath());
        }
        tmpDirs.add(dir.getAbsolutePath());
        return dir.getAbsolutePath();
    }

    @AfterAll
    public static void cleanUp() throws Exception {
        for (String dir : tmpDirs) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("deleteTmpDir path {}", dir);
            }
            FileUtils.deleteDirectory(new File(dir));
        }
    }

    private int findValidPort() {
        int port = 0;
        for (int i = 0; i < 65535; i++) {
            try (ServerSocket socket = new ServerSocket(0)) {
                socket.setReuseAddress(true);
                port = socket.getLocalPort();
                try (DatagramSocket datagramSocket = new DatagramSocket(port)) {
                    datagramSocket.setReuseAddress(true);
                    break;
                } catch (SocketException e) {
                    LOG.info("The port {} is invalid and try another port", port);
                }
            } catch (IOException e) {
                throw new IllegalStateException("Could not find a free TCP/IP port");
            }
        }
        Preconditions.checkArgument(((port > 0) && (port < 65536)));
        return port;
    }

    @RepeatedTest(1)
    public void testNormal() throws Exception {
        Assertions.assertTrue(BDBJournalCursor.getJournalCursor(null, -1, 20) == null);
        Assertions.assertTrue(BDBJournalCursor.getJournalCursor(null, 21, 20) == null);

        int port = findValidPort();
        String selfNodeName = Env.genFeNodeName("127.0.0.1", port, false);
        String selfNodeHostPort = "127.0.0.1:" + port;
        if (LOG.isDebugEnabled()) {
            LOG.debug("selfNodeName:{}, selfNodeHostPort:{}", selfNodeName, selfNodeHostPort);
        }

        BDBEnvironment bdbEnvironment = new BDBEnvironment(true, false);
        bdbEnvironment.setup(new File(createTmpDir()), selfNodeName, selfNodeHostPort, selfNodeHostPort);

        Database db = bdbEnvironment.openDatabase("1");
        db.close();

        BDBJournalCursor bdbJournalCursor = BDBJournalCursor.getJournalCursor(bdbEnvironment, 1, 10);
        Assertions.assertTrue(bdbJournalCursor != null);
        Assertions.assertTrue(bdbJournalCursor.next() == null);

        bdbEnvironment.close();

        bdbJournalCursor = BDBJournalCursor.getJournalCursor(bdbEnvironment, 1, 10);
        Assertions.assertTrue(bdbJournalCursor == null);
    }

    @Test
    void forceSkipDoesNotReadTheSkippedRecordWithoutExplicitProbeOptIn() {
        try (SkipFixture fixture = new SkipFixture(Arrays.asList("1", "2"), false)) {
            Database second = fixture.addSecondDatabase();
            BDBJournalCursor cursor = fixture.cursor(2);
            Mockito.clearInvocations(fixture.environment, fixture.first, second, fixture.storage, fixture.transaction);
            for (long id = 1; id <= 2; id++) {
                Pair<Long, JournalEntity> entry = cursor.next();
                Assertions.assertEquals(id, entry.first.longValue());
                Assertions.assertNull(entry.second);
                Assertions.assertNull(cursor.getSkippedOperation(id));
            }
            Mockito.verifyNoInteractions(fixture.environment, fixture.first, second,
                    fixture.storage, fixture.transaction);
        }
    }

    @Test
    void optedInForceSkipReadsOnlyTheHeaderAndKeepsOrdinaryReadFailuresSkippable() {
        try (SkipFixture fixture = new SkipFixture(Arrays.asList("1", "2", "3", "4", "5", "6"))) {
            Mockito.when(fixture.first.get(Mockito.eq(fixture.transaction), Mockito.any(), Mockito.any(),
                    Mockito.eq(LockMode.READ_COMMITTED))).thenAnswer(call -> {
                        DatabaseEntry key = call.getArgument(1);
                        DatabaseEntry header = call.getArgument(2);
                        Assertions.assertTrue(header.getPartial());
                        Assertions.assertEquals(0, header.getPartialOffset());
                        Assertions.assertEquals(Short.BYTES, header.getPartialLength());
                        long id = TupleBinding.getPrimitiveBinding(Long.class).entryToObject(key);
                        if (id == 5) {
                            return OperationStatus.NOTFOUND;
                        }
                        if (id == 6) {
                            throw new IllegalStateException("Unreadable journal");
                        }
                        short opcode = id == 1 ? OperationType.OP_TIMESTAMP
                                : id == 2 ? OperationType.OP_MASSDB_LICENSE_WATERMARK : Short.MAX_VALUE;
                        // Preserve a nonzero offset, as DatabaseEntry permits shared buffers.
                        header.setData(new byte[] {99, (byte) (opcode >>> 8), (byte) opcode, 99}, 1, id == 4 ? 1 : 2);
                        return OperationStatus.SUCCESS;
                    });
            BDBJournalCursor cursor = fixture.cursor(6);
            Short[] expected = {OperationType.OP_TIMESTAMP, OperationType.OP_MASSDB_LICENSE_WATERMARK,
                    Short.MAX_VALUE, null, null, null};
            for (long id = 1; id <= expected.length; id++) {
                Pair<Long, JournalEntity> entry = cursor.next();
                Assertions.assertEquals(id, entry.first.longValue());
                Assertions.assertNull(entry.second);
                Assertions.assertEquals(expected[(int) id - 1], cursor.getSkippedOperation(id));
                Assertions.assertNull(cursor.getSkippedOperation(id - 1));
            }
            Assertions.assertNull(cursor.next());
            Assertions.assertNull(cursor.getSkippedOperation(6));
            Mockito.verify(fixture.transaction, Mockito.times(6)).abort();
            Mockito.verify(fixture.first, Mockito.times(6)).get(Mockito.eq(fixture.transaction), Mockito.any(),
                    Mockito.any(), Mockito.eq(LockMode.READ_COMMITTED));
        }
    }

    @Test
    void forceSkippingTheFirstRecordOfANewDatabaseDoesNotStrandTheNextRecord() throws Exception {
        try (SkipFixture fixture = new SkipFixture(Arrays.asList("1", "2"))) {
            Database second = fixture.addSecondDatabase();
            header(fixture.first, fixture.transaction, OperationType.OP_TIMESTAMP);
            header(second, fixture.transaction, OperationType.OP_MASSDB_LICENSE_WATERMARK);
            normal(second, 3);
            BDBJournalCursor cursor = fixture.cursor(3);
            cursor.next();
            Assertions.assertEquals(Short.valueOf(OperationType.OP_TIMESTAMP), cursor.getSkippedOperation(1));
            cursor.next();
            Assertions.assertEquals(Short.valueOf(OperationType.OP_MASSDB_LICENSE_WATERMARK),
                    cursor.getSkippedOperation(2));
            Pair<Long, JournalEntity> normal = cursor.next();
            Assertions.assertEquals(3, normal.first.longValue());
            Assertions.assertEquals(OperationType.OP_SAVE_NEXTID, normal.second.getOpCode());
            Assertions.assertEquals("17", normal.second.getData().toString());
            Assertions.assertNull(cursor.getSkippedOperation(2));
        }
    }

    @Test
    void failedHeaderProbeAtDatabaseBoundaryStillSkipsAndNextReadCanRecover() throws Exception {
        try (SkipFixture fixture = new SkipFixture(Arrays.asList("1", "2"))) {
            Database second = fixture.addSecondDatabase();
            Mockito.when(fixture.environment.openDatabase("2")).thenReturn(null, second);
            header(fixture.first, fixture.transaction, OperationType.OP_TIMESTAMP);
            normal(second, 3);
            BDBJournalCursor cursor = fixture.cursor(3);
            cursor.next();
            Assertions.assertNull(cursor.next().second);
            Assertions.assertNull(cursor.getSkippedOperation(2));
            Assertions.assertEquals(3, cursor.next().first.longValue());
        }
    }

    private static void header(Database database, Transaction transaction, short opcode) {
        Mockito.when(database.get(Mockito.eq(transaction), Mockito.any(), Mockito.any(),
                Mockito.eq(LockMode.READ_COMMITTED))).thenAnswer(call -> {
                    DatabaseEntry header = call.getArgument(2);
                    header.setData(new byte[] {(byte) (opcode >>> 8), (byte) opcode});
                    return OperationStatus.SUCCESS;
                });
    }

    private static void normal(Database database, long id) throws IOException {
        JournalEntity entity = new JournalEntity();
        entity.setOpCode(OperationType.OP_SAVE_NEXTID);
        entity.setData(new Text("17"));
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        entity.write(new DataOutputStream(bytes));
        Mockito.when(database.get(Mockito.isNull(), Mockito.any(), Mockito.any(),
                Mockito.eq(LockMode.READ_COMMITTED))).thenAnswer(call -> {
                    Assertions.assertEquals(id, TupleBinding.getPrimitiveBinding(Long.class)
                            .entryToObject((DatabaseEntry) call.getArgument(1)).longValue());
                    DatabaseEntry data = call.getArgument(2);
                    Assertions.assertFalse(data.getPartial());
                    data.setData(bytes.toByteArray());
                    return OperationStatus.SUCCESS;
                });
    }

    private static final class SkipFixture implements AutoCloseable {
        private final BDBEnvironment environment = Mockito.mock(BDBEnvironment.class);
        private final Database first = Mockito.mock(Database.class);
        private final Environment storage = Mockito.mock(Environment.class);
        private final Transaction transaction = Mockito.mock(Transaction.class);
        private final MockedStatic<Env> current;
        private final boolean previousProbe = Config.massdb_license_probe_skipped_journal_header;

        private SkipFixture(List<String> skipped) {
            this(skipped, true);
        }

        private SkipFixture(List<String> skipped, boolean probe) {
            Env env = Mockito.mock(Env.class);
            Mockito.when(env.getForceSkipJournalIds()).thenReturn(skipped);
            current = Mockito.mockStatic(Env.class);
            current.when(Env::getCurrentEnv).thenReturn(env);
            Mockito.when(environment.getDatabaseNames()).thenReturn(Collections.singletonList(1L));
            Mockito.when(environment.openDatabase("1")).thenReturn(first);
            Mockito.when(first.getEnvironment()).thenReturn(storage);
            Mockito.when(storage.beginTransaction(Mockito.isNull(), Mockito.any())).thenAnswer(call -> {
                TransactionConfig config = call.getArgument(1);
                Assertions.assertTrue(config.getNoWait());
                Assertions.assertTrue(config.getReadOnly());
                Assertions.assertTrue(config.getConsistencyPolicy() instanceof NoConsistencyRequiredPolicy);
                return transaction;
            });
            Config.massdb_license_probe_skipped_journal_header = probe;
        }

        private Database addSecondDatabase() {
            Database second = Mockito.mock(Database.class);
            Mockito.when(environment.getDatabaseNames()).thenReturn(Arrays.asList(1L, 2L));
            Mockito.when(environment.openDatabase("2")).thenReturn(second);
            Mockito.when(second.getEnvironment()).thenReturn(storage);
            return second;
        }

        private BDBJournalCursor cursor(long lastId) {
            BDBJournalCursor cursor = BDBJournalCursor.getJournalCursor(environment, 1, lastId, false);
            Assertions.assertNotNull(cursor);
            return cursor;
        }

        @Override
        public void close() {
            try {
                current.close();
            } finally {
                Config.massdb_license_probe_skipped_journal_header = previousProbe;
            }
        }
    }
}
