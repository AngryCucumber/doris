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
import org.apache.doris.common.jmockit.Deencapsulation;
import org.apache.doris.datasource.InternalCatalog;
import org.apache.doris.meta.MetaContext;

import mockit.Expectations;
import mockit.Injectable;
import mockit.Mocked;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.List;
import java.util.Map;

public class LoadManagerTest {
    private LoadManager loadManager;
    private final String fieldName = "idToLoadJob";
    private UserIdentity userInfo = UserIdentity.createAnalyzedUserIdentWithIp("root", "localhost");

    @Before
    public void setUp() throws Exception {

    }

    @After
    public void tearDown() throws Exception {
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
