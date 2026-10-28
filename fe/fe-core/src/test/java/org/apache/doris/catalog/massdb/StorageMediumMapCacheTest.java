// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.catalog.massdb;

import org.apache.doris.catalog.DataProperty;
import org.apache.doris.catalog.Database;
import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.OlapTable;
import org.apache.doris.catalog.Partition;
import org.apache.doris.catalog.PartitionInfo;
import org.apache.doris.catalog.ReplicaAllocation;
import org.apache.doris.common.Config;
import org.apache.doris.datasource.InternalCatalog;
import org.apache.doris.persist.EditLog;
import org.apache.doris.thrift.TStorageMedium;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class StorageMediumMapCacheTest {
    private static final long PARTITION_ID = 9L;
    private int previousCacheSeconds;
    private int previousRetrySeconds;
    private Env env;
    private InternalCatalog catalog;
    private OlapTable table;
    private PartitionInfo partitionInfo;

    @Before
    public void setUp() {
        previousCacheSeconds = Config.storage_medium_map_cache_second;
        previousRetrySeconds = Config.storage_medium_map_retry_second;
        Config.storage_medium_map_cache_second = 60;
        Config.storage_medium_map_retry_second = 1;
        env = Mockito.spy(new Env(false));
        env.setEditLog(Mockito.mock(EditLog.class));
        catalog = Mockito.mock(InternalCatalog.class);
        Database database = Mockito.mock(Database.class);
        table = Mockito.mock(OlapTable.class);
        Partition partition = Mockito.mock(Partition.class);
        partitionInfo = new PartitionInfo();
        partitionInfo.addPartition(PARTITION_ID, new DataProperty(TStorageMedium.SSD),
                ReplicaAllocation.DEFAULT_ALLOCATION, false, true);
        Mockito.doReturn(catalog).when(env).getInternalCatalog();
        Mockito.when(catalog.getDbIds()).thenReturn(Collections.singletonList(5L));
        Mockito.when(catalog.getDbNullable(5L)).thenReturn(database);
        Mockito.when(database.getId()).thenReturn(5L);
        Mockito.when(database.getTables()).thenReturn(Collections.singletonList(table));
        Mockito.when(database.getTableNullable(7L)).thenReturn(table);
        Mockito.when(table.isManagedTable()).thenReturn(true);
        Mockito.when(table.getId()).thenReturn(7L);
        Mockito.when(table.getName()).thenReturn("cache_test");
        Mockito.when(table.getPartitionInfo()).thenReturn(partitionInfo);
        Mockito.when(table.getAllPartitions()).thenReturn(Collections.singletonList(partition));
        Mockito.when(table.getPartition(PARTITION_ID)).thenReturn(partition);
        Mockito.when(table.tryReadLock(Mockito.anyLong(), Mockito.any())).thenReturn(true);
        Mockito.when(table.tryWriteLockIfExist(Mockito.anyLong(), Mockito.any())).thenReturn(true);
        Mockito.when(table.isWriteLockHeldByCurrentThread()).thenReturn(true);
        Mockito.when(partition.getId()).thenReturn(PARTITION_ID);
        Mockito.when(partition.getName()).thenReturn("p1");
    }

    @After
    public void tearDown() {
        Config.storage_medium_map_cache_second = previousCacheSeconds;
        Config.storage_medium_map_retry_second = previousRetrySeconds;
    }

    @Test
    public void reflectsChangedStorageMediumImmediately() {
        Assert.assertEquals(TStorageMedium.SSD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
        partitionInfo.setDataProperty(PARTITION_ID, new DataProperty(TStorageMedium.HDD));
        Assert.assertEquals(TStorageMedium.HDD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
    }

    @Test
    public void reflectsInPlaceStorageMediumChanges() {
        env.getPartitionIdToStorageMediumMap();
        partitionInfo.getDataProperty(PARTITION_ID).setStorageMedium(TStorageMedium.HDD);
        Assert.assertEquals(TStorageMedium.HDD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
    }

    @Test
    public void reflectsTableRegistrationAndRemoval() {
        Database database = new Database(5L, "cache_database");
        Mockito.when(catalog.getDbNullable(5L)).thenReturn(database);
        database.registerTable(table);
        OlapTable anotherTable = Mockito.mock(OlapTable.class);
        Partition anotherPartition = Mockito.mock(Partition.class);
        PartitionInfo anotherInfo = new PartitionInfo();
        anotherInfo.addPartition(19L, new DataProperty(TStorageMedium.HDD),
                ReplicaAllocation.DEFAULT_ALLOCATION, false, true);
        Mockito.when(anotherTable.isManagedTable()).thenReturn(true);
        Mockito.when(anotherTable.tryReadLock(Mockito.anyLong(), Mockito.any())).thenReturn(true);
        Mockito.when(anotherTable.getId()).thenReturn(17L);
        Mockito.when(anotherTable.getName()).thenReturn("another_table");
        Mockito.when(anotherTable.getPartitionInfo()).thenReturn(anotherInfo);
        Mockito.when(anotherTable.getAllPartitions()).thenReturn(Collections.singletonList(anotherPartition));
        Mockito.when(anotherPartition.getId()).thenReturn(19L);
        Mockito.when(anotherPartition.getName()).thenReturn("another_partition");

        Assert.assertFalse(env.getPartitionIdToStorageMediumMap().containsKey(19L));
        database.registerTable(anotherTable);
        Assert.assertEquals(TStorageMedium.HDD, env.getPartitionIdToStorageMediumMap().get(19L));
        database.unregisterTable(17L);
        Assert.assertFalse(env.getPartitionIdToStorageMediumMap().containsKey(19L));
    }

    @Test
    public void zeroTtlDisablesReuse() {
        Config.storage_medium_map_cache_second = 0;
        Assert.assertEquals(TStorageMedium.SSD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
        Assert.assertEquals(TStorageMedium.SSD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
        Mockito.verify(catalog, Mockito.times(2)).getDbIds();
    }

    @Test
    public void expiresAtStorageCooldownDeadline() throws Exception {
        long cooldown = System.currentTimeMillis() + 2000;
        partitionInfo.setDataProperty(PARTITION_ID, new DataProperty(TStorageMedium.SSD, cooldown, ""));
        Assert.assertEquals(TStorageMedium.SSD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
        TimeUnit.MILLISECONDS.sleep(Math.max(0, cooldown - System.currentTimeMillis() + 1));
        Assert.assertEquals(TStorageMedium.HDD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
        Assert.assertEquals(TStorageMedium.HDD, partitionInfo.getDataProperty(PARTITION_ID).getStorageMedium());
    }

    @Test
    public void retriesCooldownAfterLockTimeoutWithoutRebuildingOnEveryReport() throws Exception {
        partitionInfo.setDataProperty(PARTITION_ID,
                new DataProperty(TStorageMedium.SSD, System.currentTimeMillis() - 1000, ""));
        Mockito.when(table.tryWriteLockIfExist(Mockito.anyLong(), Mockito.any())).thenReturn(false);
        for (int i = 0; i < 3; i++) {
            Assert.assertFalse(env.getPartitionIdToStorageMediumMap().containsKey(PARTITION_ID));
        }
        Mockito.verify(catalog, Mockito.times(1)).getDbIds();

        Mockito.when(table.tryWriteLockIfExist(Mockito.anyLong(), Mockito.any())).thenReturn(true);
        TimeUnit.MILLISECONDS.sleep(Config.storage_medium_map_retry_second * 1000L + 100);
        Assert.assertEquals(TStorageMedium.HDD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
        Assert.assertEquals(TStorageMedium.HDD, partitionInfo.getDataProperty(PARTITION_ID).getStorageMedium());
        Mockito.verify(catalog, Mockito.times(2)).getDbIds();
        // The cooldown itself changes metadata, so exactly one more scan follows and is then reused.
        Assert.assertEquals(TStorageMedium.HDD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
        Assert.assertEquals(TStorageMedium.HDD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
        Mockito.verify(catalog, Mockito.times(3)).getDbIds();
    }

    @Test
    public void busyTableDoesNotBlockReportWorkersAndIsAddedAfterRetry() throws Exception {
        ReentrantReadWriteLock tableLock = new ReentrantReadWriteLock();
        Mockito.when(table.tryReadLock(Mockito.anyLong(), Mockito.any())).thenAnswer(invocation ->
                tableLock.readLock().tryLock(invocation.getArgument(0), invocation.getArgument(1)));
        Mockito.doAnswer(invocation -> {
            tableLock.readLock().unlock();
            return null;
        }).when(table).readUnlock();

        ExecutorService workers = Executors.newFixedThreadPool(5);
        CountDownLatch writeLocked = new CountDownLatch(1);
        CountDownLatch releaseWriteLock = new CountDownLatch(1);
        try {
            // Another thread holds the table write lock, as a long DDL or a stuck writer would.
            Future<?> writer = workers.submit(() -> {
                tableLock.writeLock().lock();
                try {
                    writeLocked.countDown();
                    releaseWriteLock.await();
                } finally {
                    tableLock.writeLock().unlock();
                }
                return null;
            });
            Assert.assertTrue(writeLocked.await(10, TimeUnit.SECONDS));
            CountDownLatch start = new CountDownLatch(1);
            List<Future<HashMap<Long, TStorageMedium>>> results = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                results.add(workers.submit(() -> {
                    start.await();
                    return env.getPartitionIdToStorageMediumMap();
                }));
            }
            start.countDown();
            for (Future<HashMap<Long, TStorageMedium>> result : results) {
                Assert.assertFalse(result.get(5, TimeUnit.SECONDS).containsKey(PARTITION_ID));
            }
            Mockito.verify(catalog, Mockito.times(1)).getDbIds();

            releaseWriteLock.countDown();
            writer.get(10, TimeUnit.SECONDS);
            // The incomplete map is reused only within the retry interval.
            Assert.assertFalse(env.getPartitionIdToStorageMediumMap().containsKey(PARTITION_ID));
            Mockito.verify(catalog, Mockito.times(1)).getDbIds();
            TimeUnit.MILLISECONDS.sleep(Config.storage_medium_map_retry_second * 1000L + 100);
            Assert.assertEquals(TStorageMedium.SSD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
            Mockito.verify(catalog, Mockito.times(2)).getDbIds();
            // A complete map is reused for the normal cache period again.
            Assert.assertEquals(TStorageMedium.SSD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
            Mockito.verify(catalog, Mockito.times(2)).getDbIds();
        } finally {
            releaseWriteLock.countDown();
            workers.shutdownNow();
        }
    }

    @Test
    public void zeroRetryRebuildsIncompleteMapOnNextReport() {
        Config.storage_medium_map_retry_second = 0;
        Mockito.when(table.tryReadLock(Mockito.anyLong(), Mockito.any())).thenReturn(false, true);
        Assert.assertFalse(env.getPartitionIdToStorageMediumMap().containsKey(PARTITION_ID));
        Assert.assertEquals(TStorageMedium.SSD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
        Mockito.verify(catalog, Mockito.times(2)).getDbIds();
    }

    @Test
    public void doesNotCacheSnapshotBuiltAcrossMetadataChange() {
        AtomicBoolean changed = new AtomicBoolean();
        Mockito.doAnswer(invocation -> {
            if (changed.compareAndSet(false, true)) {
                partitionInfo.setDataProperty(PARTITION_ID, new DataProperty(TStorageMedium.HDD));
            }
            return null;
        }).when(table).readUnlock();
        env.getPartitionIdToStorageMediumMap();
        Assert.assertEquals(TStorageMedium.HDD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
    }

    @Test
    public void concurrentReportsShareOneCatalogScan() throws Exception {
        ExecutorService workers = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<HashMap<Long, TStorageMedium>>> results = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                results.add(workers.submit(() -> {
                    start.await();
                    return env.getPartitionIdToStorageMediumMap();
                }));
            }
            start.countDown();
            HashMap<Long, TStorageMedium> first = results.get(0).get(10, TimeUnit.SECONDS);
            for (Future<HashMap<Long, TStorageMedium>> result : results) {
                Assert.assertSame(first, result.get(10, TimeUnit.SECONDS));
            }
            Mockito.verify(catalog, Mockito.times(1)).getDbIds();
        } finally {
            workers.shutdownNow();
        }
    }
}
