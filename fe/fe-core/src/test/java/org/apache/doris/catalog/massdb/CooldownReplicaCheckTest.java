// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.catalog.massdb;

import org.apache.doris.catalog.Database;
import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.LocalTabletInvertedIndex;
import org.apache.doris.catalog.MaterializedIndex;
import org.apache.doris.catalog.OlapTable;
import org.apache.doris.catalog.Partition;
import org.apache.doris.catalog.Replica;
import org.apache.doris.catalog.Table;
import org.apache.doris.catalog.Tablet;
import org.apache.doris.catalog.TabletMeta;
import org.apache.doris.common.Pair;
import org.apache.doris.cooldown.CooldownConf;
import org.apache.doris.datasource.InternalCatalog;
import org.apache.doris.thrift.TStorageMedium;
import org.apache.doris.thrift.TTabletInfo;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

public class CooldownReplicaCheckTest {
    private static final long DB_ID = 1L;
    private static final long TABLE_ID = 2L;
    private static final long PARTITION_ID = 3L;
    private static final long INDEX_ID = 4L;
    private static final long TABLET_ID = 5L;
    private static final long COOLDOWN_TERM = 7L;

    // tabletReport checks cooldown replicas after releasing the index lock, while another report worker
    // may delete a replica of the same tablet. The deletion here happens in the middle of that iteration.
    @Test
    public void replicaDeletedDuringCooldownCheckDoesNotAbortReport() throws Exception {
        LocalTabletInvertedIndex index = new LocalTabletInvertedIndex();
        index.addTablet(TABLET_ID, new TabletMeta(DB_ID, TABLE_ID, PARTITION_ID, INDEX_ID, 0, TStorageMedium.HDD));
        // addReplica reads the replica id under the index write lock, so arm the deletion afterwards.
        AtomicBoolean armed = new AtomicBoolean();
        AtomicBoolean deleted = new AtomicBoolean();
        for (long backendId = 1; backendId <= 3; backendId++) {
            Replica replica = Mockito.mock(Replica.class);
            long replicaId = 100 + backendId;
            Mockito.when(replica.getBackendIdWithoutException()).thenReturn(backendId);
            Mockito.when(replica.getId()).thenAnswer(invocation -> {
                if (armed.get() && deleted.compareAndSet(false, true)) {
                    long other = replicaId == 101 ? 2 : 1;
                    index.deleteReplica(TABLET_ID, other);
                }
                return replicaId;
            });
            index.addReplica(TABLET_ID, replica);
        }

        Tablet tablet = Mockito.mock(Tablet.class);
        // The cooldown replica is not among the reported ones, so every replica is visited.
        Mockito.when(tablet.getCooldownConf()).thenReturn(Pair.of(999L, COOLDOWN_TERM));
        MaterializedIndex materializedIndex = Mockito.mock(MaterializedIndex.class);
        Mockito.when(materializedIndex.getTablet(TABLET_ID)).thenReturn(tablet);
        Partition partition = Mockito.mock(Partition.class);
        Mockito.when(partition.getIndex(INDEX_ID)).thenReturn(materializedIndex);
        OlapTable table = Mockito.mock(OlapTable.class);
        Mockito.when(table.getPartition(PARTITION_ID)).thenReturn(partition);
        Database database = Mockito.mock(Database.class);
        Mockito.when(database.getTable(TABLE_ID)).thenReturn(Optional.of((Table) table));
        InternalCatalog catalog = Mockito.mock(InternalCatalog.class);
        Mockito.when(catalog.getDbNullable(DB_ID)).thenReturn(database);

        TTabletInfo reported = new TTabletInfo();
        reported.setTabletId(TABLET_ID);
        reported.setCooldownTerm(COOLDOWN_TERM);
        List<CooldownConf> toPush = new ArrayList<>();
        List<CooldownConf> toUpdate = new ArrayList<>();
        Method handleCooldownConf = LocalTabletInvertedIndex.class.getDeclaredMethod("handleCooldownConf",
                TabletMeta.class, TTabletInfo.class, List.class, List.class);
        handleCooldownConf.setAccessible(true);
        try (MockedStatic<Env> env = Mockito.mockStatic(Env.class)) {
            env.when(Env::getCurrentInternalCatalog).thenReturn(catalog);
            armed.set(true);
            handleCooldownConf.invoke(index, index.getTabletMeta(TABLET_ID), reported, toPush, toUpdate);
        }

        Assert.assertTrue(deleted.get());
        Assert.assertEquals(2, index.getReplicasByTabletId(TABLET_ID).size());
        Assert.assertTrue(toPush.isEmpty());
        Assert.assertEquals(1, toUpdate.size());
        Assert.assertEquals(TABLET_ID, toUpdate.get(0).getTabletId());
    }

    private static Replica replica(long backendId) {
        Replica replica = Mockito.mock(Replica.class, Mockito.withSettings().stubOnly());
        Mockito.when(replica.getBackendIdWithoutException()).thenReturn(backendId);
        Mockito.when(replica.getId()).thenReturn(100 + backendId);
        return replica;
    }

    private static InternalCatalog catalogWithTablet() {
        Tablet tablet = Mockito.mock(Tablet.class);
        Mockito.when(tablet.getCooldownConf()).thenReturn(Pair.of(999L, COOLDOWN_TERM));
        MaterializedIndex materializedIndex = Mockito.mock(MaterializedIndex.class);
        Mockito.when(materializedIndex.getTablet(TABLET_ID)).thenReturn(tablet);
        Partition partition = Mockito.mock(Partition.class);
        Mockito.when(partition.getIndex(INDEX_ID)).thenReturn(materializedIndex);
        OlapTable table = Mockito.mock(OlapTable.class);
        Mockito.when(table.getPartition(PARTITION_ID)).thenReturn(partition);
        Database database = Mockito.mock(Database.class);
        Mockito.when(database.getTable(TABLE_ID)).thenReturn(Optional.of((Table) table));
        InternalCatalog catalog = Mockito.mock(InternalCatalog.class);
        Mockito.when(catalog.getDbNullable(DB_ID)).thenReturn(database);
        return catalog;
    }

    // Runs handleCooldownConf on this thread; MockedStatic only applies to the thread that created it.
    private static void checkCooldown(LocalTabletInvertedIndex index, int times, Consumer<List<CooldownConf>> verify)
            throws Exception {
        TTabletInfo reported = new TTabletInfo();
        reported.setTabletId(TABLET_ID);
        reported.setCooldownTerm(COOLDOWN_TERM);
        Method handleCooldownConf = LocalTabletInvertedIndex.class.getDeclaredMethod("handleCooldownConf",
                TabletMeta.class, TTabletInfo.class, List.class, List.class);
        handleCooldownConf.setAccessible(true);
        InternalCatalog catalog = catalogWithTablet();
        try (MockedStatic<Env> env = Mockito.mockStatic(Env.class)) {
            env.when(Env::getCurrentInternalCatalog).thenReturn(catalog);
            for (int i = 0; i < times; i++) {
                List<CooldownConf> toPush = new ArrayList<>();
                List<CooldownConf> toUpdate = new ArrayList<>();
                handleCooldownConf.invoke(index, index.getTabletMeta(TABLET_ID), reported, toPush, toUpdate);
                Assert.assertTrue(toPush.isEmpty());
                verify.accept(toUpdate);
            }
        }
    }

    @Test
    public void replicaAddedDuringCooldownCheckDoesNotAbortReport() throws Exception {
        LocalTabletInvertedIndex index = new LocalTabletInvertedIndex();
        index.addTablet(TABLET_ID, new TabletMeta(DB_ID, TABLE_ID, PARTITION_ID, INDEX_ID, 0, TStorageMedium.HDD));
        AtomicBoolean armed = new AtomicBoolean();
        AtomicBoolean added = new AtomicBoolean();
        for (long backendId = 1; backendId <= 3; backendId++) {
            Replica replica = Mockito.mock(Replica.class);
            long replicaId = 100 + backendId;
            Mockito.when(replica.getBackendIdWithoutException()).thenReturn(backendId);
            Mockito.when(replica.getId()).thenAnswer(invocation -> {
                if (armed.get() && added.compareAndSet(false, true)) {
                    index.addReplica(TABLET_ID, replica(4));
                }
                return replicaId;
            });
            index.addReplica(TABLET_ID, replica);
        }
        armed.set(true);
        checkCooldown(index, 1, toUpdate -> Assert.assertEquals(1, toUpdate.size()));
        Assert.assertTrue(added.get());
        Assert.assertEquals(4, index.getReplicasByTabletId(TABLET_ID).size());
    }

    @Test
    public void tabletWithoutReplicasIsSkipped() throws Exception {
        LocalTabletInvertedIndex index = new LocalTabletInvertedIndex();
        index.addTablet(TABLET_ID, new TabletMeta(DB_ID, TABLE_ID, PARTITION_ID, INDEX_ID, 0, TStorageMedium.HDD));
        index.addReplica(TABLET_ID, replica(1));
        index.deleteReplica(TABLET_ID, 1);
        checkCooldown(index, 1, toUpdate -> Assert.assertTrue(toUpdate.isEmpty()));
    }

    // One thread keeps running the cooldown check while another replaces replicas of the same tablet, as two
    // report workers handling different backends do.
    @Test
    public void concurrentReplicaChangesDuringCooldownChecks() throws Exception {
        LocalTabletInvertedIndex index = new LocalTabletInvertedIndex();
        index.addTablet(TABLET_ID, new TabletMeta(DB_ID, TABLE_ID, PARTITION_ID, INDEX_ID, 0, TStorageMedium.HDD));
        int backends = 64;
        Replica[] replicas = new Replica[backends + 1];
        for (int backendId = 1; backendId <= backends; backendId++) {
            replicas[backendId] = replica(backendId);
            index.addReplica(TABLET_ID, replicas[backendId]);
        }
        AtomicBoolean stop = new AtomicBoolean();
        AtomicInteger changes = new AtomicInteger();
        ExecutorService mutator = Executors.newSingleThreadExecutor();
        try {
            Future<?> changing = mutator.submit(() -> {
                for (int i = 0; !stop.get(); i++) {
                    int backendId = 1 + i % backends;
                    index.deleteReplica(TABLET_ID, backendId);
                    index.addReplica(TABLET_ID, replicas[backendId]);
                    changes.incrementAndGet();
                }
            });
            long deadline = System.currentTimeMillis() + 2000;
            int checks = 0;
            while (System.currentTimeMillis() < deadline) {
                checkCooldown(index, 200, toUpdate -> Assert.assertEquals(1, toUpdate.size()));
                checks += 200;
            }
            stop.set(true);
            changing.get(10, TimeUnit.SECONDS);
            Assert.assertTrue(checks > 0 && changes.get() > 0);
        } finally {
            stop.set(true);
            mutator.shutdownNow();
        }
        Assert.assertEquals(backends, index.getReplicasByTabletId(TABLET_ID).size());
    }
}
