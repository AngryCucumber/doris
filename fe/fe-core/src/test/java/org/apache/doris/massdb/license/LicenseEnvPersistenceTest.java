// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.common.FeConstants;
import org.apache.doris.common.FeMetaVersion;
import org.apache.doris.common.Pair;
import org.apache.doris.common.io.CountingDataOutputStream;
import org.apache.doris.common.io.Text;
import org.apache.doris.common.jmockit.Deencapsulation;
import org.apache.doris.journal.JournalCursor;
import org.apache.doris.journal.JournalEntity;
import org.apache.doris.meta.MetaContext;
import org.apache.doris.persist.EditLog;
import org.apache.doris.persist.OperationType;
import org.apache.doris.persist.meta.MetaFooter;
import org.apache.doris.persist.meta.MetaHeader;
import org.apache.doris.persist.meta.MetaIndex;
import org.apache.doris.persist.meta.MetaPersistMethod;
import org.apache.doris.persist.meta.MetaReader;
import org.apache.doris.persist.meta.MetaWriter;
import org.apache.doris.persist.meta.PersistMetaModules;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.CRC32;

class LicenseEnvPersistenceTest {
    @TempDir
    Path temporary;

    @BeforeEach
    void metaContext() {
        new MetaContext().setThreadLocalInfo();
    }

    @Test
    void journalRoundTripDispatchesToTheSpecifiedEnv() throws Exception {
        LicensePersistRecord record = initial();
        JournalEntity original = new JournalEntity();
        original.setOpCode(OperationType.OP_MASSDB_LICENSE_INITIALIZE);
        original.setData(record);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        original.write(new DataOutputStream(bytes));
        JournalEntity recovered = new JournalEntity();
        recovered.readFields(new DataInputStream(new ByteArrayInputStream(bytes.toByteArray())));
        Env checkpoint = new Env(true);
        EditLog.loadJournal(checkpoint, 1L, recovered);
        Assertions.assertEquals(1, checkpoint.getLicenseManager().getAppliedVersion());
        Assertions.assertArrayEquals(imageModule(record), module(checkpoint));
        Assertions.assertNotSame(checkpoint.getLicenseManager(), new Env(true).getLicenseManager());
    }

    @Test
    void journalOpcodeMustMatchTheAtomicEnvelope() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeShort(OperationType.OP_MASSDB_LICENSE_CLOCK_REPAIR);
        initial().write(output);
        Assertions.assertThrows(IOException.class, () -> new JournalEntity().readFields(
                new DataInputStream(new ByteArrayInputStream(bytes.toByteArray()))));
    }

    @Test
    void imageModuleIsRegisteredAndRoundTripsHistoricalBytes() throws Exception {
        MetaPersistMethod method = PersistMetaModules.MODULES_MAP.get("massdbLicenseV1");
        Assertions.assertNotNull(method);
        Assertions.assertEquals("loadMassdbLicenseV1", method.readMethod.getName());
        Assertions.assertEquals("saveMassdbLicenseV1", method.writeMethod.getName());
        LicensePersistRecord record = initial();
        Env recovered = new Env(true);
        MetaReader.read(image(FeMetaVersion.VERSION_MASSDB_LICENSE_V1, imageModule(record), true), recovered);
        Assertions.assertEquals(1, recovered.getLicenseManager().getAppliedVersion());
        Assertions.assertArrayEquals(imageModule(record), module(recovered));
    }

    @Test
    void emptyUpgradeImageDoesNotIntroduceAFormatGateOrLicenseFact() throws Exception {
        Env uninitialized = new Env(true);
        Assertions.assertEquals(0, module(uninitialized).length);
        Assertions.assertEquals(FeConstants.meta_version, imageVersion(uninitialized));
        uninitialized.getLicenseManager().onReplayComplete();
        Assertions.assertEquals(0, uninitialized.getLicenseManager().getAppliedVersion());
    }

    @Test
    void missingRequiredModuleCannotBecomeAFreeNewClusterOrLowerTheImageGate() throws Exception {
        Env recovered = new Env(true);
        MetaReader.read(image(FeMetaVersion.VERSION_MASSDB_LICENSE_V1, null, false), recovered);
        recovered.getLicenseManager().onReplayComplete();
        Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY,
                recovered.getLicenseManager().getSnapshot().queryStatus(System.currentTimeMillis() / 1000));
        Assertions.assertEquals(FeMetaVersion.VERSION_MASSDB_LICENSE_V1, imageVersion(recovered));
    }

    @Test
    void unknownHigherImageVersionKeepsTheExistingRecoveryError() throws Exception {
        File file = image(FeMetaVersion.VERSION_MASSDB_LICENSE_V1 + 1, null, false);
        Assertions.assertThrows(IOException.class, () -> MetaReader.read(file, new Env(true)));
    }

    @Test
    void actualModuleLengthAndTrailingBytesAreRejected() throws Exception {
        byte[] original = imageModule(initial());
        byte[] trailing = new byte[original.length + 1];
        System.arraycopy(original, 0, trailing, 0, original.length);
        File trailingImage = image(FeMetaVersion.VERSION_MASSDB_LICENSE_V1, trailing, true);
        Assertions.assertThrows(IOException.class, () -> MetaReader.read(trailingImage, new Env(true)));
        File oversizedImage = image(FeMetaVersion.VERSION_MASSDB_LICENSE_V1,
                new byte[LicensePersistRecord.MAX_BYTES + 1], true);
        Assertions.assertThrows(IOException.class, () -> MetaReader.read(oversizedImage, new Env(true)));
    }

    @Test
    void recoveryIncompleteSurvivesCheckpointAndImageReload() throws Exception {
        Env incomplete = new Env(true);
        incomplete.getLicenseManager().replay(initial());
        incomplete.markLicenseRecoveryIncomplete();
        byte[] saved = module(incomplete);
        Assertions.assertTrue(saved[0] != 0);
        Env recovered = new Env(true);
        MetaReader.read(image(FeMetaVersion.VERSION_MASSDB_LICENSE_V1, saved, true), recovered);
        recovered.getLicenseManager().onReplayComplete();
        Assertions.assertEquals(LicenseQueryStatus.LICENSE_NOT_READY,
                recovered.getLicenseManager().getSnapshot().queryStatus(System.currentTimeMillis() / 1000));
        Assertions.assertTrue(module(recovered)[0] != 0);
    }

    @Test
    void knownOrdinaryForceSkipDoesNotInvalidateLicenseRecovery() throws Exception {
        for (short opcode : new short[] {OperationType.OP_SAVE_NEXTID, OperationType.OP_TIMESTAMP,
                OperationType.OP_CREATE_TABLE}) {
            Env recovered = skipping(opcode);
            recovered.replayJournal(1);
            Assertions.assertEquals(0, module(recovered)[0]);
            Assertions.assertEquals(1, recovered.getLicenseManager().getAppliedVersion());
        }
    }

    @Test
    void unknownLicenseAndMembershipForceSkipsStillInvalidateLicenseRecovery() throws Exception {
        for (Short opcode : new Short[] {null, OperationType.OP_LOCAL_EOF, Short.MAX_VALUE,
                OperationType.OP_MASSDB_LICENSE_INITIALIZE, OperationType.OP_MASSDB_LICENSE_ACCEPT,
                OperationType.OP_MASSDB_LICENSE_BASE_CAPACITY, OperationType.OP_MASSDB_LICENSE_WATERMARK,
                OperationType.OP_MASSDB_LICENSE_CLOCK_REPAIR, OperationType.OP_MASSDB_LICENSE_INTEGRITY,
                OperationType.OP_ADD_BACKEND, OperationType.OP_DROP_BACKEND, OperationType.OP_MODIFY_BACKEND,
                OperationType.OP_BACKEND_STATE_CHANGE, OperationType.OP_ADD_FRONTEND,
                OperationType.OP_ADD_FIRST_FRONTEND, OperationType.OP_MODIFY_FRONTEND,
                OperationType.OP_REMOVE_FRONTEND}) {
            Env recovered = skipping(opcode);
            recovered.replayJournal(1);
            Assertions.assertTrue(module(recovered)[0] != 0, String.valueOf(opcode));
        }
    }

    @Test
    void explicitlySkippedMembershipReplayErrorsStillInvalidateLicenseRecovery() throws Exception {
        short[] previous = Config.skip_operation_types_on_replay_exception;
        short[] members = {OperationType.OP_ADD_BACKEND, OperationType.OP_DROP_BACKEND,
                OperationType.OP_MODIFY_BACKEND, OperationType.OP_BACKEND_STATE_CHANGE,
                OperationType.OP_ADD_FRONTEND, OperationType.OP_ADD_FIRST_FRONTEND,
                OperationType.OP_MODIFY_FRONTEND, OperationType.OP_REMOVE_FRONTEND};
        try {
            Config.skip_operation_types_on_replay_exception = members;
            for (short opcode : members) {
                Env recovered = new Env(true);
                recovered.getLicenseManager().replay(initial());
                JournalEntity malformed = new JournalEntity();
                malformed.setOpCode(opcode);
                malformed.setData(new Text("Invalid member payload"));
                EditLog.loadJournal(recovered, 1L, malformed);
                Assertions.assertTrue(module(recovered)[0] != 0, String.valueOf(opcode));
            }
            Config.skip_operation_types_on_replay_exception = new short[] {OperationType.OP_SAVE_NEXTID};
            Env ordinary = new Env(true);
            ordinary.getLicenseManager().replay(initial());
            JournalEntity malformed = new JournalEntity();
            malformed.setOpCode(OperationType.OP_SAVE_NEXTID);
            malformed.setData(new Text("Invalid numeric ID"));
            EditLog.loadJournal(ordinary, 1L, malformed);
            Assertions.assertEquals(0, module(ordinary)[0]);
        } finally {
            Config.skip_operation_types_on_replay_exception = previous;
        }
    }

    @Test
    void ordinaryForceSkipCannotClearAnEarlierIncompleteRecovery() throws Exception {
        Env recovered = skipping(OperationType.OP_TIMESTAMP);
        recovered.markLicenseRecoveryIncomplete();
        recovered.replayJournal(1);
        Assertions.assertTrue(module(recovered)[0] != 0);
        Assertions.assertNull(new JournalCursor() {
            @Override
            public Pair<Long, JournalEntity> next() {
                return null;
            }

            @Override
            public void close() {
            }
        }.getSkippedOperation(1));
    }

    @Test
    void promotionRetriesAnUnavailableCursorWithoutChangingTheFrozenTarget() throws Exception {
        Env recovered = new Env(true);
        recovered.getLicenseManager().replay(initial());
        EditLog log = Mockito.mock(EditLog.class);
        JournalCursor cursor = ordinaryCursor(1);
        Mockito.when(log.getMaxJournalId()).thenReturn(1L, 2L);
        Mockito.when(log.read(1, 1)).thenReturn(null, cursor);
        Deencapsulation.setField(recovered, "editLog", log);

        Assertions.assertFalse(Deencapsulation.<Boolean>invoke(recovered, "replayJournalsBeforeMaster"));
        Assertions.assertEquals(1, recovered.getReplayedJournalId());
        Assertions.assertEquals(0, module(recovered)[0]);
        Mockito.verify(log, Mockito.times(1)).getMaxJournalId();
        Mockito.verify(log, Mockito.times(2)).read(1, 1);
        Mockito.verify(log, Mockito.never()).read(1, 2);
    }

    @Test
    void promotionContinuesAfterAShortCursorFromTheLastAppliedJournal() throws Exception {
        Env recovered = new Env(true);
        recovered.getLicenseManager().replay(initial());
        EditLog log = Mockito.mock(EditLog.class);
        JournalCursor first = ordinaryCursor(1);
        JournalCursor second = ordinaryCursor(2);
        Mockito.when(log.getMaxJournalId()).thenReturn(2L);
        Mockito.when(log.read(1, 2)).thenReturn(first);
        Mockito.when(log.read(2, 2)).thenReturn(second);
        Deencapsulation.setField(recovered, "editLog", log);

        Assertions.assertFalse(Deencapsulation.<Boolean>invoke(recovered, "replayJournalsBeforeMaster"));
        Assertions.assertEquals(2, recovered.getReplayedJournalId());
        Assertions.assertEquals(0, module(recovered)[0]);
        Mockito.verify(log).read(1, 2);
        Mockito.verify(log).read(2, 2);
    }

    @Test
    void promotionFailsAfterBoundedShortReplayWithoutPersistingIncompleteRecovery() throws Exception {
        Env recovered = new Env(true);
        recovered.getLicenseManager().replay(initial());
        EditLog log = Mockito.mock(EditLog.class);
        JournalCursor cursor = Mockito.mock(JournalCursor.class);
        Mockito.when(log.getMaxJournalId()).thenReturn(1L);
        Mockito.when(log.read(1, 1)).thenReturn(cursor);
        Deencapsulation.setField(recovered, "editLog", log);

        Assertions.assertThrows(IOException.class,
                () -> Deencapsulation.invoke(recovered, "replayJournalsBeforeMaster"));
        Assertions.assertEquals(0, recovered.getReplayedJournalId());
        Assertions.assertEquals(0, module(recovered)[0]);
        Mockito.verify(log, Mockito.times(3)).read(1, 1);
    }

    @Test
    void promotionRejectsUnknownOrRegressedJournalBoundariesWithoutPersistingIncompleteRecovery() throws Exception {
        for (long target : new long[] {-1, 0}) {
            Env recovered = new Env(true);
            recovered.getLicenseManager().replay(initial());
            Deencapsulation.setField(recovered, "replayedJournalId", new AtomicLong(1));
            EditLog log = Mockito.mock(EditLog.class);
            Mockito.when(log.getMaxJournalId()).thenReturn(target);
            Deencapsulation.setField(recovered, "editLog", log);

            Assertions.assertThrows(IOException.class,
                    () -> Deencapsulation.invoke(recovered, "replayJournalsBeforeMaster"));
            Assertions.assertEquals(0, module(recovered)[0]);
            Mockito.verify(log, Mockito.never()).read(Mockito.anyLong(), Mockito.anyLong());
        }
    }

    @Test
    void completedPromotionReplayRetainsActualSkippedLicenseDamage() throws Exception {
        Env recovered = skipping(OperationType.OP_MASSDB_LICENSE_WATERMARK);
        Mockito.when(recovered.getEditLog().getMaxJournalId()).thenReturn(1L);

        Assertions.assertFalse(Deencapsulation.<Boolean>invoke(recovered, "replayJournalsBeforeMaster"));
        Assertions.assertEquals(1, recovered.getReplayedJournalId());
        Assertions.assertTrue(module(recovered)[0] != 0);
    }

    @Test
    void pristineBootstrapRequiresAConfirmedEmptyJournalBoundary() throws Exception {
        Env recovered = new Env(true);
        Deencapsulation.setField(recovered, "isFirstTimeStartUp", true);
        EditLog log = Mockito.mock(EditLog.class);
        Mockito.when(log.getMaxJournalId()).thenReturn(0L);
        Deencapsulation.setField(recovered, "editLog", log);

        Assertions.assertTrue(Deencapsulation.<Boolean>invoke(recovered, "replayJournalsBeforeMaster"));
        Mockito.verify(log, Mockito.never()).read(Mockito.anyLong(), Mockito.anyLong());
        Assertions.assertEquals(0, module(recovered).length);
    }

    private static JournalCursor ordinaryCursor(long journalId) {
        JournalEntity entity = new JournalEntity();
        entity.setOpCode(OperationType.OP_SAVE_NEXTID);
        entity.setData(new Text("100"));
        JournalCursor cursor = Mockito.mock(JournalCursor.class);
        Mockito.when(cursor.next()).thenReturn(Pair.of(journalId, entity)).thenReturn(null);
        return cursor;
    }

    private static Env skipping(Short opcode) throws IOException {
        Env recovered = new Env(true);
        recovered.getLicenseManager().replay(initial());
        EditLog log = Mockito.mock(EditLog.class);
        JournalCursor cursor = Mockito.mock(JournalCursor.class);
        Mockito.when(cursor.next()).thenReturn(Pair.of(1L, null)).thenReturn(null);
        Mockito.when(cursor.getSkippedOperation(1)).thenReturn(opcode);
        Mockito.when(log.read(1, 1)).thenReturn(cursor);
        Deencapsulation.setField(recovered, "editLog", log);
        Deencapsulation.setField(recovered, "forceSkipJournalIds", Collections.singletonList("1"));
        return recovered;
    }

    @Test
    void imageChecksumCoversTheCompletenessPrefix() throws Exception {
        byte[] original = imageModule(initial());
        File file = image(FeMetaVersion.VERSION_MASSDB_LICENSE_V1, original, true);
        long moduleOffset = MetaFooter.read(file).metaIndices.get(1).offset;
        try (java.io.RandomAccessFile bytes = new java.io.RandomAccessFile(file, "rw")) {
            bytes.seek(moduleOffset);
            bytes.writeBoolean(true);
        }
        Assertions.assertThrows(IllegalStateException.class, () -> MetaReader.read(file, new Env(true)));
    }

    @Test
    void checkpointKeepsItsHistoricalCutWhenAnotherEnvAdvances() throws Exception {
        Env historical = new Env(true);
        Env other = new Env(true);
        LicensePersistRecord first = initial();
        LicensePersistRecord second = LicensePersistRecord.initial(UUID.randomUUID(), false, 123_456L);
        historical.getLicenseManager().replay(first);
        other.getLicenseManager().replay(second);
        Assertions.assertArrayEquals(imageModule(first), module(historical));
        Assertions.assertArrayEquals(imageModule(second), module(other));
        Assertions.assertEquals(FeMetaVersion.VERSION_MASSDB_LICENSE_V1, imageVersion(historical));
    }

    @Test
    void imageWriterUsesTheFrozenBoundaryAndKeepsConcurrentModuleIndicesIndependent() throws Exception {
        File first = temporary.resolve("image.41").toFile();
        File second = temporary.resolve("image.42").toFile();
        CountDownLatch firstHeader = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        Env firstEnv = imageWriterEnv(firstHeader, releaseFirst);
        Env secondEnv = imageWriterEnv(null, null);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<?> writingFirst = executor.submit(() -> {
                MetaWriter.write(first, firstEnv, 41);
                return null;
            });
            Assertions.assertTrue(firstHeader.await(10, TimeUnit.SECONDS));
            MetaWriter.write(second, secondEnv, 42);
            releaseFirst.countDown();
            writingFirst.get(10, TimeUnit.SECONDS);
            assertImageWriterBoundaries(first, 41);
            assertImageWriterBoundaries(second, 42);

            File legacy = temporary.resolve("image.77").toFile();
            MetaWriter.write(legacy, secondEnv);
            assertImageWriterBoundaries(legacy, 77);
        } finally {
            releaseFirst.countDown();
            executor.shutdownNow();
            Assertions.assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));
        }
    }

    @Test
    void servingDumpEntersTheLicenseBarrierBeforeEnvLocksAndUsesTheAppliedRoleBoundary() throws Exception {
        String previousMetaDir = Config.meta_dir;
        boolean previousCompatibility = Config.enable_check_compatibility_mode;
        try {
            Config.meta_dir = temporary.toString();
            Config.enable_check_compatibility_mode = false;
            for (boolean leader : new boolean[] {false, true}) {
                Env env = Mockito.spy(new Env(true));
                LicenseManager manager = Mockito.mock(LicenseManager.class);
                Deencapsulation.setField(env, "licenseManager", manager);
                Deencapsulation.setField(env, "licenseLeadership", leader);
                Deencapsulation.setField(env, "replayedJournalId", new AtomicLong(7));
                Mockito.doReturn(19L).when(env).getMaxJournalId();
                Mockito.when(manager.runImageSnapshot(Mockito.any())).thenAnswer(call -> {
                    Assertions.assertFalse(Thread.holdsLock(env));
                    Callable<String> work = call.getArgument(0);
                    return work.call();
                });
                Mockito.doAnswer(call -> {
                    Assertions.assertTrue(Thread.holdsLock(env));
                    File file = call.getArgument(0);
                    long cut = call.getArgument(1);
                    Assertions.assertEquals(leader ? 19L : 7L, cut);
                    Assertions.assertEquals("image." + cut, file.getName());
                    return null;
                }).when(env).saveImage(Mockito.any(File.class), Mockito.anyLong());

                Assertions.assertEquals(temporary.resolve("image." + (leader ? 19 : 7)).toString(), env.dumpImage());
                Mockito.verify(manager).runImageSnapshot(Mockito.any());
                Mockito.verify(env, Mockito.times(leader ? 1 : 0)).getMaxJournalId();
            }
        } finally {
            Config.meta_dir = previousMetaDir;
            Config.enable_check_compatibility_mode = previousCompatibility;
        }
    }

    @Test
    void servingDumpDoesNotWriteAnUnknownMasterBoundary() throws Exception {
        Env env = Mockito.spy(new Env(true));
        LicenseManager manager = Mockito.mock(LicenseManager.class);
        Deencapsulation.setField(env, "licenseManager", manager);
        Deencapsulation.setField(env, "licenseLeadership", true);
        Mockito.doReturn(-1L).when(env).getMaxJournalId();
        Mockito.when(manager.runImageSnapshot(Mockito.any())).thenAnswer(call -> {
            Callable<String> work = call.getArgument(0);
            return work.call();
        });

        Assertions.assertNull(env.dumpImage());
        Mockito.verify(env, Mockito.never()).saveImage(Mockito.any(File.class), Mockito.anyLong());
    }

    private static Env imageWriterEnv(CountDownLatch entered, CountDownLatch release) {
        return Mockito.mock(Env.class, call -> {
            String name = call.getMethod().getName();
            if (name.equals("getReplayedJournalId")) {
                return 77L;
            }
            if (name.equals("saveHeader")) {
                if (entered != null) {
                    entered.countDown();
                    Assertions.assertTrue(release.await(10, TimeUnit.SECONDS));
                }
                CountingDataOutputStream output = call.getArgument(0);
                long cut = call.getArgument(1);
                output.writeInt(FeConstants.meta_version);
                output.writeLong(cut);
                return 0L;
            }
            if (name.startsWith("save") && call.getArguments().length == 2
                    && call.getArgument(0) instanceof CountingDataOutputStream) {
                CountingDataOutputStream output = call.getArgument(0);
                output.writeInt(name.hashCode());
                return 0L;
            }
            return Mockito.RETURNS_DEFAULTS.answer(call);
        });
    }

    private static void assertImageWriterBoundaries(File file, long cut) throws IOException {
        List<MetaIndex> indices = MetaFooter.read(file).metaIndices;
        Assertions.assertEquals(PersistMetaModules.MODULES_IN_ORDER.size() + 1, indices.size());
        try (RandomAccessFile input = new RandomAccessFile(file, "r")) {
            long start = MetaHeader.read(file).getEnd();
            Assertions.assertEquals("header", indices.get(0).name);
            Assertions.assertEquals(start, indices.get(0).offset);
            input.seek(start);
            Assertions.assertEquals(FeConstants.meta_version, input.readInt());
            Assertions.assertEquals(cut, input.readLong());
            for (int i = 0; i < PersistMetaModules.MODULES_IN_ORDER.size(); i++) {
                MetaPersistMethod module = PersistMetaModules.MODULES_IN_ORDER.get(i);
                MetaIndex index = indices.get(i + 1);
                Assertions.assertEquals(module.name, index.name);
                Assertions.assertEquals(start + Integer.BYTES + Long.BYTES + (long) i * Integer.BYTES, index.offset);
                input.seek(index.offset);
                Assertions.assertEquals(module.writeMethod.getName().hashCode(), input.readInt());
            }
        }
    }

    private File image(int version, byte[] module, boolean indexModule) throws IOException {
        File file = temporary.resolve(UUID.randomUUID() + ".image").toFile();
        long start = MetaHeader.write(file);
        List<MetaIndex> indices = new ArrayList<>();
        indices.add(new MetaIndex("header", start));
        try (CountingDataOutputStream output = new CountingDataOutputStream(new FileOutputStream(file, true), start)) {
            output.writeInt(version);
            output.writeLong(0L);
            output.writeLong(100L);
            output.writeBoolean(true);
            if (indexModule) {
                indices.add(new MetaIndex("massdbLicenseV1", output.getCount()));
            }
            if (module != null) {
                output.write(module);
            }
        }
        CRC32 moduleChecksum = new CRC32();
        if (module != null) {
            moduleChecksum.update(module);
        }
        MetaFooter.write(file, indices, version ^ 100L ^ moduleChecksum.getValue());
        return file;
    }

    private static LicensePersistRecord initial() throws IOException {
        return LicensePersistRecord.initial(UUID.fromString("11111111-2222-3333-4444-555555555555"), true, 123_456L);
    }

    private static byte[] imageModule(LicensePersistRecord record) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeBoolean(false);
        output.writeBoolean(true);
        record.write(output);
        return bytes.toByteArray();
    }

    private static byte[] module(Env env) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        env.saveMassdbLicenseV1(new CountingDataOutputStream(bytes), 0);
        return bytes.toByteArray();
    }

    private static int imageVersion(Env env) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        env.saveHeader(new CountingDataOutputStream(bytes), 0, 0);
        return new DataInputStream(new ByteArrayInputStream(bytes.toByteArray())).readInt();
    }
}
