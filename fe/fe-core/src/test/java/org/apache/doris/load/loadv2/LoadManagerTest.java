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

package org.apache.doris.load.loadv2;

import org.apache.doris.analysis.UserIdentity;
import org.apache.doris.catalog.Database;
import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.Table;
import org.apache.doris.common.Config;
import org.apache.doris.common.FeMetaVersion;
import org.apache.doris.common.MetaNotFoundException;
import org.apache.doris.common.Pair;
import org.apache.doris.common.jmockit.Deencapsulation;
import org.apache.doris.datasource.CatalogMgr;
import org.apache.doris.datasource.InternalCatalog;
import org.apache.doris.load.EtlJobType;
import org.apache.doris.meta.MetaContext;
import org.apache.doris.mysql.privilege.AccessControllerManager;
import org.apache.doris.mysql.privilege.PrivPredicate;
import org.apache.doris.persist.EditLog;
import org.apache.doris.qe.ConnectContext;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import mockit.Expectations;
import mockit.Injectable;
import mockit.Mocked;
import mockit.Verifications;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class LoadManagerTest {
    private LoadManager loadManager;
    private final String fieldName = "idToLoadJob";
    private UserIdentity userInfo = UserIdentity.createAnalyzedUserIdentWithIp("root", "localhost");
    private int oldStreamingLabelKeepMaxSecond;
    private int oldLabelNumThreshold;

    @Before
    public void setUp() throws Exception {
        oldStreamingLabelKeepMaxSecond = Config.streaming_label_keep_max_second;
        oldLabelNumThreshold = Config.label_num_threshold;
    }

    @After
    public void tearDown() throws Exception {
        Config.streaming_label_keep_max_second = oldStreamingLabelKeepMaxSecond;
        Config.label_num_threshold = oldLabelNumThreshold;
        File file = new File("./loadManagerTest");
        if (file.exists()) {
            file.delete();
        }
    }

    @Test
    public void testSerializationNormal(@Mocked Env env, @Mocked InternalCatalog catalog, @Injectable Database database,
            @Injectable Table table) throws Exception {
        new Expectations() {
            {
                env.getInternalCatalog();
                minTimes = 0;
                result = catalog;
                catalog.getDbNullable(anyLong);
                minTimes = 0;
                result = database;
                database.getTableNullable(anyLong);
                minTimes = 0;
                result = table;
                table.getName();
                minTimes = 0;
                result = "tablename";
                Env.getCurrentEnvJournalVersion();
                minTimes = 0;
                result = FeMetaVersion.VERSION_CURRENT;
            }
        };

        loadManager = new LoadManager(new LoadJobScheduler());
        LoadJob job1 = new InsertLoadJob("job1", 1L, 1L, 1L, System.currentTimeMillis(), "", "", "", userInfo);
        Deencapsulation.invoke(loadManager, "addLoadJob", job1);

        File file = serializeToFile(loadManager);

        // make it deserialized
        LoadManager newLoadManager = deserializeFromFile(file);

        Map<Long, LoadJob> loadJobs = Deencapsulation.getField(loadManager, fieldName);
        Map<Long, LoadJob> newLoadJobs = Deencapsulation.getField(newLoadManager, fieldName);
        Assert.assertEquals(loadJobs, newLoadJobs);
    }

    @Test
    public void testSerializationWithJobRemoved(@Mocked MetaContext metaContext, @Mocked Env env,
            @Mocked InternalCatalog catalog, @Injectable Database database, @Injectable Table table) throws Exception {
        new Expectations() {
            {
                env.getInternalCatalog();
                minTimes = 0;
                result = catalog;
                catalog.getDbNullable(anyLong);
                minTimes = 0;
                result = database;
                database.getTableNullable(anyLong);
                minTimes = 0;
                result = table;
                table.getName();
                minTimes = 0;
                result = "tablename";
                Env.getCurrentEnvJournalVersion();
                minTimes = 0;
                result = FeMetaVersion.VERSION_CURRENT;
            }
        };

        loadManager = new LoadManager(new LoadJobScheduler());
        LoadJob job1 = new InsertLoadJob("job1", 1L, 1L, 1L, System.currentTimeMillis(), "", "", "", userInfo);
        Deencapsulation.invoke(loadManager, "addLoadJob", job1);

        // make job1 don't serialize
        Config.streaming_label_keep_max_second = 1;
        Thread.sleep(2000);

        File file = serializeToFile(loadManager);

        LoadManager newLoadManager = deserializeFromFile(file);
        Map<Long, LoadJob> newLoadJobs = Deencapsulation.getField(newLoadManager, fieldName);

        Assert.assertEquals(0, newLoadJobs.size());
    }

    @Test
    public void testCleanOverLimitJobs(@Mocked Env env,
            @Mocked InternalCatalog catalog, @Injectable Database database, @Injectable Table table) throws Exception {
        new Expectations() {
            {
                env.getNextId();
                returns(1L, 2L);
                env.getInternalCatalog();
                minTimes = 0;
                result = catalog;
                catalog.getDbNullable(anyLong);
                minTimes = 0;
                result = database;
                database.getTableNullable(anyLong);
                minTimes = 0;
                result = table;
                table.getName();
                minTimes = 0;
                result = "tablename";
                Env.getCurrentEnvJournalVersion();
                minTimes = 0;
                result = FeMetaVersion.VERSION_CURRENT;
            }
        };

        loadManager = new LoadManager(new LoadJobScheduler());
        LoadJob job1 = new InsertLoadJob("job1", 1L, 1L, 1L, System.currentTimeMillis(), "", "", "", userInfo);
        Thread.sleep(100);
        LoadJob job2 = new InsertLoadJob("job2", 1L, 1L, 1L, System.currentTimeMillis(), "", "", "", userInfo);
        Deencapsulation.invoke(loadManager, "addLoadJob", job2);
        Deencapsulation.invoke(loadManager, "addLoadJob", job1);
        Config.label_num_threshold = 1;
        loadManager.removeOverLimitLoadJob();
        Map<Long, LoadJob> idToJobs = Deencapsulation.getField(loadManager, fieldName);
        Map<Long, Map<String, List<LoadJob>>> dbIdToLabelToLoadJobs = Deencapsulation.getField(loadManager,
                "dbIdToLabelToLoadJobs");
        Assert.assertEquals(1, idToJobs.size());
        Assert.assertEquals(1, dbIdToLabelToLoadJobs.size());
        LoadJob loadJob = idToJobs.get(job2.getId());
        Assert.assertEquals("job2", loadJob.getLabel());
        Assert.assertNotNull(dbIdToLabelToLoadJobs.get(1L).get("job2"));
    }

    @Test
    public void testRemoveAbandonedPendingInsertJob(@Mocked Env env, @Mocked InternalCatalog catalog,
            @Injectable Database database, @Injectable Table table) throws Exception {
        mockCatalog(env, catalog, database, table);
        int oldLabelKeepMaxSecond = Config.label_keep_max_second;
        int oldStreamingLabelKeepMaxSecond = Config.streaming_label_keep_max_second;
        Config.label_keep_max_second = 3600;
        Config.streaming_label_keep_max_second = 3600;
        try {
            long now = System.currentTimeMillis();
            long beforeKeepTime = now - (Config.label_keep_max_second + 60) * 1000L;
            loadManager = new LoadManager(new LoadJobScheduler());

            // registered when planned, never finished, older than label_keep_max_second
            LoadJob abandoned = new InsertLoadJob(1L, "abandoned", 10L);
            Deencapsulation.setField(abandoned, "createTimestamp", beforeKeepTime);
            // registered when planned and still running
            LoadJob running = new InsertLoadJob(1L, "running", 11L);
            // finished recently, although created long ago
            LoadJob finished = new InsertLoadJob("finished", 1L, 1L, 1L, beforeKeepTime, "", "", "", userInfo, 12L);
            // other job types are not touched even if they stay PENDING
            LoadJob broker = new BrokerLoadJob();
            Deencapsulation.setField(broker, "id", 13L);
            Deencapsulation.setField(broker, "dbId", 1L);
            Deencapsulation.setField(broker, "label", "broker");
            Deencapsulation.setField(broker, "createTimestamp", beforeKeepTime);
            for (LoadJob job : new LoadJob[] {abandoned, running, finished, broker}) {
                loadManager.addLoadJob(job);
            }

            loadManager.removeOldLoadJob();

            Map<Long, LoadJob> idToJobs = Deencapsulation.getField(loadManager, fieldName);
            Map<Long, Map<String, List<LoadJob>>> dbIdToLabelToLoadJobs = Deencapsulation.getField(loadManager,
                    "dbIdToLabelToLoadJobs");
            Assert.assertNull(idToJobs.get(10L));
            Assert.assertNull(dbIdToLabelToLoadJobs.get(1L).get("abandoned"));
            Assert.assertEquals(3, idToJobs.size());
            Assert.assertNotNull(idToJobs.get(11L));
            Assert.assertNotNull(idToJobs.get(12L));
            Assert.assertNotNull(idToJobs.get(13L));
        } finally {
            Config.label_keep_max_second = oldLabelKeepMaxSecond;
            Config.streaming_label_keep_max_second = oldStreamingLabelKeepMaxSecond;
        }
    }

    @Test
    public void testGetLoadJobNum(@Mocked Env env, @Mocked InternalCatalog catalog,
            @Injectable Database database, @Injectable Table table) throws Exception {
        mockCatalog(env, catalog, database, table);
        loadManager = new LoadManager(new LoadJobScheduler());
        Assert.assertTrue(loadManager.getLoadJobNum().isEmpty());

        loadManager.addLoadJob(new InsertLoadJob(1L, "pending1", 1L));
        loadManager.addLoadJob(new InsertLoadJob(1L, "pending2", 2L));
        loadManager.addLoadJob(new InsertLoadJob("finished", 1L, 1L, 1L, System.currentTimeMillis(), "", "", "",
                userInfo, 3L));
        loadManager.addLoadJob(new InsertLoadJob("cancelled", 1L, 1L, 1L, System.currentTimeMillis(), "failed",
                "", "", userInfo, 4L));
        LoadJob broker = new BrokerLoadJob();
        Deencapsulation.setField(broker, "id", 5L);
        Deencapsulation.setField(broker, "label", "broker");
        loadManager.addLoadJob(broker);

        Map<Pair<EtlJobType, JobState>, Long> expected = Maps.newHashMap();
        expected.put(Pair.of(EtlJobType.INSERT, JobState.PENDING), 2L);
        expected.put(Pair.of(EtlJobType.INSERT, JobState.FINISHED), 1L);
        expected.put(Pair.of(EtlJobType.INSERT, JobState.CANCELLED), 1L);
        expected.put(Pair.of(EtlJobType.BROKER, JobState.PENDING), 1L);
        Assert.assertEquals(expected, loadManager.getLoadJobNum());
    }

    @Test
    public void testCleanerWaitsForFinishingInsertJob(@Mocked Env env, @Mocked InternalCatalog catalog,
            @Injectable Database database, @Injectable Table table, @Mocked EditLog editLog) throws Exception {
        mockRecordFinished(env, catalog, database, table, editLog);
        loadManager = new LoadManager(new LoadJobScheduler());
        long createTimestamp = System.currentTimeMillis() - 3600 * 1000L;
        CountDownLatch finishing = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        // an insert that ran longer than label_keep_max_second and is being finished when the cleaner runs
        InsertLoadJob job = new InsertLoadJob(1L, "long_insert", 101L) {
            @Override
            public void setJobProperties(long transactionId, long tableId, long createTimestamp, String failMsg,
                    String trackingUrl, String firstErrorMsg, UserIdentity userInfo) throws MetaNotFoundException {
                finishing.countDown();
                try {
                    release.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                super.setJobProperties(transactionId, tableId, createTimestamp, failMsg, trackingUrl, firstErrorMsg,
                        userInfo);
            }
        };
        Deencapsulation.setField(job, "createTimestamp", createTimestamp);
        loadManager.addLoadJob(job);
        int oldLabelKeepMaxSecond = Config.label_keep_max_second;
        Config.label_keep_max_second = 60;
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<?> finish = pool.submit(() -> {
                loadManager.recordFinishedLoadJob("long_insert", 99L, "db", 1L, EtlJobType.INSERT, createTimestamp,
                        "", "", "", userInfo, 101L);
                return null;
            });
            Assert.assertTrue(finishing.await(5, TimeUnit.SECONDS));
            // the cleaner must not drop the job between its lookup and its update
            Future<?> clean = pool.submit(() -> loadManager.removeOldLoadJob());
            Thread.sleep(300);
            Assert.assertFalse(clean.isDone());
            release.countDown();
            finish.get(5, TimeUnit.SECONDS);
            clean.get(5, TimeUnit.SECONDS);
        } finally {
            release.countDown();
            pool.shutdownNow();
            Config.label_keep_max_second = oldLabelKeepMaxSecond;
        }
        Assert.assertEquals(JobState.FINISHED, job.getState());
        Assert.assertSame(job, loadManager.getLoadJob(101L));
        new Verifications() {
            {
                editLog.logCreateLoadJob(job);
                times = 1;
            }
        };
    }

    @Test
    public void testInsertJobDroppedByCleanerIsRecordedAgain(@Mocked Env env, @Mocked InternalCatalog catalog,
            @Injectable Database database, @Injectable Table table, @Mocked EditLog editLog) throws Exception {
        mockRecordFinished(env, catalog, database, table, editLog);
        loadManager = new LoadManager(new LoadJobScheduler());
        long createTimestamp = System.currentTimeMillis() - 3600 * 1000L;
        InsertLoadJob job = new InsertLoadJob(1L, "long_insert", 102L);
        Deencapsulation.setField(job, "createTimestamp", createTimestamp);
        loadManager.addLoadJob(job);
        int oldLabelKeepMaxSecond = Config.label_keep_max_second;
        Config.label_keep_max_second = 60;
        try {
            loadManager.removeOldLoadJob();
        } finally {
            Config.label_keep_max_second = oldLabelKeepMaxSecond;
        }
        Assert.assertNull(loadManager.getLoadJob(102L));

        // the insert finishes after the cleaner dropped its job: the job is created again and journaled
        loadManager.recordFinishedLoadJob("long_insert", 99L, "db", 1L, EtlJobType.INSERT, createTimestamp,
                "", "", "", userInfo, 102L);
        LoadJob recorded = loadManager.getLoadJob(1000L);
        Assert.assertNotNull(recorded);
        Assert.assertEquals(JobState.FINISHED, recorded.getState());
        Map<Long, Map<String, List<LoadJob>>> dbIdToLabelToLoadJobs = Deencapsulation.getField(loadManager,
                "dbIdToLabelToLoadJobs");
        Assert.assertEquals(1, dbIdToLabelToLoadJobs.get(1L).get("long_insert").size());
        Assert.assertEquals(1, loadManager.queryLoadJobsByJobIds(Lists.newArrayList(102L, 1000L)).size());
        new Verifications() {
            {
                editLog.logCreateLoadJob(recorded);
                times = 1;
            }
        };
    }

    // run the tasks on the pool threads at the same instant, return when all are done
    private static void runTogether(ExecutorService pool, List<Runnable> tasks) throws Exception {
        CountDownLatch ready = new CountDownLatch(tasks.size());
        AtomicBoolean go = new AtomicBoolean();
        List<Future<?>> futures = Lists.newArrayList();
        for (Runnable task : tasks) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                while (!go.get()) {
                    // spin, so that the tasks start together
                }
                task.run();
            }));
        }
        ready.await(5, TimeUnit.SECONDS);
        go.set(true);
        for (Future<?> future : futures) {
            future.get(5, TimeUnit.SECONDS);
        }
    }

    @Test
    public void testJobsAddedTogetherAreAllInTheLabelIndex() throws Exception {
        // the first insert jobs of a database registered at the same time by 8 sessions, which do not hold the
        // LoadManager lock: none of them may be lost from the label index (SHOW LOAD reads it)
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            for (int round = 0; round < 300; round++) {
                LoadManager manager = new LoadManager(new LoadJobScheduler());
                List<Runnable> tasks = Lists.newArrayList();
                for (int i = 0; i < threads; i++) {
                    InsertLoadJob job = new InsertLoadJob(1L, "label_" + i, round * threads + i);
                    tasks.add(() -> manager.addLoadJob(job));
                }
                runTogether(pool, tasks);
                Map<Long, Map<String, List<LoadJob>>> dbIdToLabelToLoadJobs = Deencapsulation.getField(manager,
                        "dbIdToLabelToLoadJobs");
                Assert.assertEquals("round " + round, threads, dbIdToLabelToLoadJobs.get(1L).size());
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    public void testJobAddedWhileCleanerEmptiesTheDatabase() throws Exception {
        // the cleaner drops the last job of a database, and with it the label map of the database, while a new
        // insert job of the database is registered: the new job must stay in the label index
        int oldLabelKeepMaxSecond = Config.label_keep_max_second;
        Config.label_keep_max_second = 60;
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            for (int round = 0; round < 300; round++) {
                LoadManager manager = new LoadManager(new LoadJobScheduler());
                InsertLoadJob abandoned = new InsertLoadJob(1L, "abandoned", 2L * round);
                Deencapsulation.setField(abandoned, "createTimestamp", System.currentTimeMillis() - 3600 * 1000L);
                manager.addLoadJob(abandoned);
                InsertLoadJob added = new InsertLoadJob(1L, "added", 2L * round + 1);
                runTogether(pool, Lists.newArrayList(manager::removeOldLoadJob, () -> manager.addLoadJob(added)));
                Map<Long, Map<String, List<LoadJob>>> dbIdToLabelToLoadJobs = Deencapsulation.getField(manager,
                        "dbIdToLabelToLoadJobs");
                Assert.assertNotNull("round " + round, dbIdToLabelToLoadJobs.get(1L));
                Assert.assertEquals("round " + round, Lists.newArrayList(added),
                        dbIdToLabelToLoadJobs.get(1L).get("added"));
                Assert.assertNull(dbIdToLabelToLoadJobs.get(1L).get("abandoned"));
            }
        } finally {
            pool.shutdownNow();
            Config.label_keep_max_second = oldLabelKeepMaxSecond;
        }
    }

    @Test
    public void testReadersWhileJobsAreAdded() throws Exception {
        // SHOW LOAD and the procs iterate the label lists holding only the read lock, while insert jobs are added
        // without any lock; many jobs under few labels make the lists long
        LoadManager manager = new LoadManager(new LoadJobScheduler());
        int writers = 4;
        int jobsPerWriter = 3000;
        AtomicBoolean done = new AtomicBoolean();
        List<Throwable> errors = Collections.synchronizedList(Lists.newArrayList());
        ExecutorService pool = Executors.newFixedThreadPool(writers + 4);
        try {
            List<Future<?>> readers = Lists.newArrayList();
            for (int i = 0; i < 4; i++) {
                readers.add(pool.submit(() -> {
                    while (!done.get()) {
                        try {
                            manager.getLoadJobNum(JobState.PENDING, 1L);
                        } catch (Throwable t) {
                            errors.add(t);
                            return;
                        }
                    }
                }));
            }
            List<Future<?>> adders = Lists.newArrayList();
            for (int w = 0; w < writers; w++) {
                int firstId = w * jobsPerWriter;
                adders.add(pool.submit(() -> {
                    for (int i = 0; i < jobsPerWriter; i++) {
                        manager.addLoadJob(new InsertLoadJob(1L, "label_" + (i % 5), firstId + i));
                    }
                }));
            }
            for (Future<?> adder : adders) {
                adder.get(60, TimeUnit.SECONDS);
            }
            done.set(true);
            for (Future<?> reader : readers) {
                reader.get(60, TimeUnit.SECONDS);
            }
        } finally {
            done.set(true);
            pool.shutdownNow();
        }
        Assert.assertTrue("readers failed: " + errors, errors.isEmpty());
        Assert.assertEquals(writers * jobsPerWriter, manager.getLoadJobNum(JobState.PENDING, 1L));
    }

    @Test
    public void testCleanLabelWhileJobIsAdded(@Mocked Env env, @Mocked InternalCatalog catalog,
            @Injectable Database database, @Mocked EditLog editLog) throws Exception {
        new Expectations() {
            {
                Env.getCurrentEnv();
                minTimes = 0;
                result = env;
                Env.getCurrentInternalCatalog();
                minTimes = 0;
                result = catalog;
                env.getEditLog();
                minTimes = 0;
                result = editLog;
                catalog.getDbOrDdlException(anyString);
                minTimes = 0;
                result = database;
                database.getId();
                minTimes = 0;
                result = 1L;
            }
        };
        // CLEAN LABEL drops the finished job of a label while a new job with the label is added: the new job
        // must stay in the label index
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            for (int round = 0; round < 300; round++) {
                LoadManager manager = new LoadManager(new LoadJobScheduler());
                InsertLoadJob finished = new InsertLoadJob(1L, "label", 2L * round);
                Deencapsulation.setField(finished, "state", JobState.FINISHED);
                manager.addLoadJob(finished);
                InsertLoadJob added = new InsertLoadJob(1L, "label", 2L * round + 1);
                runTogether(pool, Lists.newArrayList(() -> {
                    try {
                        manager.cleanLabel("db", "label");
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, () -> manager.addLoadJob(added)));
                Map<Long, Map<String, List<LoadJob>>> dbIdToLabelToLoadJobs = Deencapsulation.getField(manager,
                        "dbIdToLabelToLoadJobs");
                Assert.assertNotNull("round " + round, dbIdToLabelToLoadJobs.get(1L));
                Assert.assertEquals("round " + round, Lists.newArrayList(added),
                        dbIdToLabelToLoadJobs.get(1L).get("label"));
                Assert.assertNull(manager.getLoadJob(2L * round));
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    public void testProcCountsJobsOfAllDatabases(@Mocked Env env, @Mocked CatalogMgr catalogMgr,
            @Mocked AccessControllerManager accessManager, @Injectable Database db1, @Injectable Database db2)
            throws Exception {
        new Expectations() {
            {
                Env.getCurrentEnv();
                minTimes = 0;
                result = env;
                env.getCatalogMgr();
                minTimes = 0;
                result = catalogMgr;
                env.getAccessManager();
                minTimes = 0;
                result = accessManager;
                catalogMgr.getDbNullable(1L);
                minTimes = 0;
                result = db1;
                catalogMgr.getDbNullable(2L);
                minTimes = 0;
                result = db2;
                catalogMgr.getDbNullable(3L);
                minTimes = 0;
                result = null;
                db1.getFullName();
                minTimes = 0;
                result = "db1";
                db2.getFullName();
                minTimes = 0;
                result = "db2";
                accessManager.checkDbPriv((ConnectContext) any, anyString, anyString, (PrivPredicate) any);
                minTimes = 0;
                result = true;
            }
        };
        LoadManager manager = new LoadManager(new LoadJobScheduler());
        // the same label in two databases, and jobs of a database that was dropped meanwhile
        manager.addLoadJob(new InsertLoadJob(1L, "same", 1L));
        manager.addLoadJob(new InsertLoadJob(2L, "same", 2L));
        manager.addLoadJob(new InsertLoadJob(3L, "other", 3L));
        Assert.assertEquals(2, manager.getLoadJobNum(JobState.PENDING));
    }

    private void mockRecordFinished(Env env, InternalCatalog catalog, Database database, Table table,
            EditLog editLog) throws Exception {
        new Expectations() {
            {
                Env.getCurrentEnv();
                minTimes = 0;
                result = env;
                Env.getCurrentInternalCatalog();
                minTimes = 0;
                result = catalog;
                env.getEditLog();
                minTimes = 0;
                result = editLog;
                env.getNextId();
                minTimes = 0;
                result = 1000L;
                catalog.getDbOrMetaException(anyString);
                minTimes = 0;
                result = database;
                catalog.getDbOrMetaException(anyLong);
                minTimes = 0;
                result = database;
                database.getId();
                minTimes = 0;
                result = 1L;
                database.getFullName();
                minTimes = 0;
                result = "db";
                database.getTableOrMetaException(anyLong);
                minTimes = 0;
                result = table;
                table.getName();
                minTimes = 0;
                result = "tbl";
            }
        };
    }

    private void mockCatalog(Env env, InternalCatalog catalog, Database database, Table table) {
        new Expectations() {
            {
                env.getInternalCatalog();
                minTimes = 0;
                result = catalog;
                catalog.getDbNullable(anyLong);
                minTimes = 0;
                result = database;
                database.getTableNullable(anyLong);
                minTimes = 0;
                result = table;
                table.getName();
                minTimes = 0;
                result = "tablename";
            }
        };
    }

    private File serializeToFile(LoadManager loadManager) throws Exception {
        File file = new File("./loadManagerTest");
        file.createNewFile();
        DataOutputStream dos = new DataOutputStream(new FileOutputStream(file));
        loadManager.write(dos);
        dos.flush();
        dos.close();
        return file;
    }

    private LoadManager deserializeFromFile(File file) throws Exception {
        DataInputStream dis = new DataInputStream(new FileInputStream(file));
        LoadManager loadManager = new LoadManager(new LoadJobScheduler());
        loadManager.readFields(dis);
        return loadManager;
    }
}
