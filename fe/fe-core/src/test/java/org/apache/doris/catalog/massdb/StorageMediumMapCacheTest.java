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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class StorageMediumMapCacheTest {
    private static final long PARTITION_ID = 9L;
    private int previousCacheSeconds;
    private int previousRetrySeconds;
    private Env env;
    private InternalCatalog catalog;
    private Database database;
    private EditLog editLog;
    private OlapTable table;
    private PartitionInfo partitionInfo;

    @Before
    public void setUp() {
        previousCacheSeconds = Config.storage_medium_map_cache_second;
        previousRetrySeconds = Config.storage_medium_map_retry_second;
        Config.storage_medium_map_cache_second = 60;
        Config.storage_medium_map_retry_second = 1;
        env = Mockito.spy(new Env(false));
        editLog = Mockito.mock(EditLog.class);
        env.setEditLog(editLog);
        catalog = Mockito.mock(InternalCatalog.class);
        database = Mockito.mock(Database.class);
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
            tableLock.readLock().lock();
            return null;
        }).when(table).readLock();
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

    private OlapTable addHddTable(long tableId, long partitionId) {
        OlapTable other = Mockito.mock(OlapTable.class);
        Partition otherPartition = Mockito.mock(Partition.class);
        PartitionInfo otherInfo = new PartitionInfo();
        otherInfo.addPartition(partitionId, new DataProperty(TStorageMedium.HDD),
                ReplicaAllocation.DEFAULT_ALLOCATION, false, true);
        Mockito.when(other.isManagedTable()).thenReturn(true);
        Mockito.when(other.getId()).thenReturn(tableId);
        Mockito.when(other.getName()).thenReturn("table_" + tableId);
        Mockito.when(other.getPartitionInfo()).thenReturn(otherInfo);
        Mockito.when(other.getAllPartitions()).thenReturn(Collections.singletonList(otherPartition));
        Mockito.when(other.tryReadLock(Mockito.anyLong(), Mockito.any())).thenReturn(true);
        Mockito.when(otherPartition.getId()).thenReturn(partitionId);
        Mockito.when(database.getTables()).thenReturn(Arrays.asList(table, other));
        return other;
    }

    @Test
    public void busyTableIsSkippedWhileOtherTablesAreServed() throws Exception {
        addHddTable(17L, 19L);
        Mockito.when(table.tryReadLock(Mockito.anyLong(), Mockito.any())).thenReturn(false, true);
        HashMap<Long, TStorageMedium> map = env.getPartitionIdToStorageMediumMap();
        Assert.assertFalse(map.containsKey(PARTITION_ID));
        Assert.assertEquals(TStorageMedium.HDD, map.get(19L));
        TimeUnit.MILLISECONDS.sleep(Config.storage_medium_map_retry_second * 1000L + 100);
        map = env.getPartitionIdToStorageMediumMap();
        Assert.assertEquals(TStorageMedium.SSD, map.get(PARTITION_ID));
        Assert.assertEquals(TStorageMedium.HDD, map.get(19L));
    }

    @Test
    public void incompleteMapIsStillRebuiltOnMetadataChange() {
        Config.storage_medium_map_retry_second = 60;
        Mockito.when(table.tryReadLock(Mockito.anyLong(), Mockito.any())).thenReturn(false, true);
        Assert.assertFalse(env.getPartitionIdToStorageMediumMap().containsKey(PARTITION_ID));
        partitionInfo.setDataProperty(PARTITION_ID, new DataProperty(TStorageMedium.HDD));
        Assert.assertEquals(TStorageMedium.HDD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
        Mockito.verify(catalog, Mockito.times(2)).getDbIds();
    }

    @Test
    public void retryIntervalIsCappedByCacheTtl() throws Exception {
        Config.storage_medium_map_cache_second = 1;
        Config.storage_medium_map_retry_second = 30;
        Mockito.when(table.tryReadLock(Mockito.anyLong(), Mockito.any())).thenReturn(false, true);
        Assert.assertFalse(env.getPartitionIdToStorageMediumMap().containsKey(PARTITION_ID));
        Assert.assertFalse(env.getPartitionIdToStorageMediumMap().containsKey(PARTITION_ID));
        Mockito.verify(catalog, Mockito.times(1)).getDbIds();
        TimeUnit.MILLISECONDS.sleep(1100);
        Assert.assertEquals(TStorageMedium.SSD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
        Mockito.verify(catalog, Mockito.times(2)).getDbIds();
    }

    @Test
    public void partitionAlteredBeforeCooldownIsNotMovedToHdd() {
        long future = System.currentTimeMillis() + TimeUnit.HOURS.toMillis(1);
        partitionInfo.setDataProperty(PARTITION_ID,
                new DataProperty(TStorageMedium.SSD, System.currentTimeMillis() - 1000, ""));
        // Another thread changes the cooldown time after the scan, before the write lock is taken.
        Mockito.when(table.tryWriteLockIfExist(Mockito.anyLong(), Mockito.any())).thenAnswer(invocation -> {
            partitionInfo.setDataProperty(PARTITION_ID, new DataProperty(TStorageMedium.SSD, future, ""));
            return true;
        });
        Assert.assertFalse(env.getPartitionIdToStorageMediumMap().containsKey(PARTITION_ID));
        Assert.assertEquals(TStorageMedium.SSD, partitionInfo.getDataProperty(PARTITION_ID).getStorageMedium());
        Assert.assertEquals(future, partitionInfo.getDataProperty(PARTITION_ID).getCooldownTimeMs());
        Mockito.verify(editLog, Mockito.never()).logModifyPartition(Mockito.any());
        // The change bumped the metadata version, so the next report rebuilds with the new property.
        Assert.assertEquals(TStorageMedium.SSD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
        Mockito.verify(catalog, Mockito.times(2)).getDbIds();
    }

    @Test
    public void tableDroppedBeforeCooldownIsIgnored() {
        partitionInfo.setDataProperty(PARTITION_ID,
                new DataProperty(TStorageMedium.SSD, System.currentTimeMillis() - 1000, ""));
        Mockito.when(database.getTableNullable(7L)).thenReturn(null);
        Assert.assertFalse(env.getPartitionIdToStorageMediumMap().containsKey(PARTITION_ID));
        Assert.assertEquals(TStorageMedium.SSD, partitionInfo.getDataProperty(PARTITION_ID).getStorageMedium());
        Mockito.verify(editLog, Mockito.never()).logModifyPartition(Mockito.any());
        Mockito.verify(table, Mockito.never()).tryWriteLockIfExist(Mockito.anyLong(), Mockito.any());
    }

    // Report workers rebuild the map while a writer changes the table under its real lock, sometimes holding it
    // longer than the try-lock timeout and sometimes leaving an expired SSD partition for the workers to cool down.
    @Test
    public void concurrentReportsAndTableChangesStayConsistent() throws Exception {
        Config.storage_medium_map_retry_second = 0;
        addHddTable(17L, 19L);
        ReentrantReadWriteLock tableLock = new ReentrantReadWriteLock();
        Mockito.when(table.tryReadLock(Mockito.anyLong(), Mockito.any())).thenAnswer(invocation ->
                tableLock.readLock().tryLock(invocation.getArgument(0), invocation.getArgument(1)));
        Mockito.doAnswer(invocation -> {
            tableLock.readLock().lock();
            return null;
        }).when(table).readLock();
        Mockito.doAnswer(invocation -> {
            tableLock.readLock().unlock();
            return null;
        }).when(table).readUnlock();
        Mockito.when(table.tryWriteLockIfExist(Mockito.anyLong(), Mockito.any())).thenAnswer(invocation ->
                tableLock.writeLock().tryLock(invocation.getArgument(0), invocation.getArgument(1)));
        Mockito.doAnswer(invocation -> {
            tableLock.writeLock().unlock();
            return null;
        }).when(table).writeUnlock();
        Mockito.when(table.isWriteLockHeldByCurrentThread()).thenAnswer(invocation ->
                tableLock.isWriteLockedByCurrentThread());

        long deadline = System.currentTimeMillis() + 2000;
        ConcurrentLinkedQueue<Throwable> failures = new ConcurrentLinkedQueue<>();
        AtomicInteger withPartition = new AtomicInteger();
        AtomicInteger withoutPartition = new AtomicInteger();
        AtomicInteger longHolds = new AtomicInteger();
        ExecutorService threads = Executors.newFixedThreadPool(7);
        try {
            List<Future<?>> futures = new ArrayList<>();
            futures.add(threads.submit(() -> {
                for (int i = 0; System.currentTimeMillis() < deadline; i++) {
                    tableLock.writeLock().lock();
                    try {
                        DataProperty next = i % 3 == 0 ? new DataProperty(TStorageMedium.HDD)
                                : i % 3 == 1 ? new DataProperty(TStorageMedium.SSD)
                                : new DataProperty(TStorageMedium.SSD, System.currentTimeMillis() - 1, "");
                        partitionInfo.setDataProperty(PARTITION_ID, next);
                        if (i % 10 == 0) {
                            longHolds.incrementAndGet();
                            TimeUnit.MILLISECONDS.sleep(150);
                        }
                    } finally {
                        tableLock.writeLock().unlock();
                    }
                    TimeUnit.MILLISECONDS.sleep(1);
                }
                tableLock.writeLock().lock();
                try {
                    partitionInfo.setDataProperty(PARTITION_ID, new DataProperty(TStorageMedium.HDD));
                } finally {
                    tableLock.writeLock().unlock();
                }
                return null;
            }));
            for (int worker = 0; worker < 6; worker++) {
                futures.add(threads.submit(() -> {
                    while (System.currentTimeMillis() < deadline) {
                        try {
                            HashMap<Long, TStorageMedium> map = env.getPartitionIdToStorageMediumMap();
                            Assert.assertEquals(TStorageMedium.HDD, map.get(19L));
                            if (map.containsKey(PARTITION_ID)) {
                                Assert.assertNotNull(map.get(PARTITION_ID));
                                withPartition.incrementAndGet();
                            } else {
                                withoutPartition.incrementAndGet();
                            }
                        } catch (Throwable t) {
                            failures.add(t);
                            return null;
                        }
                    }
                    return null;
                }));
            }
            for (Future<?> future : futures) {
                future.get(30, TimeUnit.SECONDS);
            }
        } finally {
            threads.shutdownNow();
        }
        Assert.assertTrue(String.valueOf(failures), failures.isEmpty());
        Assert.assertTrue("lock held past the try-lock timeout", longHolds.get() > 0);
        Assert.assertTrue("some reports saw the busy table skipped", withoutPartition.get() > 0);
        Assert.assertTrue("some reports saw the table", withPartition.get() > 0);
        Assert.assertFalse(tableLock.isWriteLocked());
        Assert.assertEquals(0, tableLock.getReadLockCount());
        Assert.assertEquals(TStorageMedium.HDD, env.getPartitionIdToStorageMediumMap().get(PARTITION_ID));
    }
}
