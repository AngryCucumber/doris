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

package org.apache.doris.cloud.load;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.common.jmockit.Deencapsulation;
import org.apache.doris.load.loadv2.JobState;
import org.apache.doris.load.loadv2.LoadJob;
import org.apache.doris.load.loadv2.LoadJobScheduler;

import com.google.common.collect.Sets;
import mockit.Mocked;
import org.junit.Assert;
import org.junit.Test;

import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

public class CloudLoadManagerTest {

    private static CopyJob finishedCopyJob(long id, String label, long finishTimestamp) {
        CopyJob job = new CopyJob();
        Deencapsulation.setField(job, "id", id);
        Deencapsulation.setField(job, "dbId", 1L);
        Deencapsulation.setField(job, "label", label);
        Deencapsulation.setField(job, "state", JobState.FINISHED);
        Deencapsulation.setField(job, "finishTimestamp", finishTimestamp);
        Map<String, String> properties = Deencapsulation.getField(job, "properties");
        properties.put("TableName", "t1");
        return job;
    }

    @Test
    public void testRemoveCopyJobsKeepsTheNewest(@Mocked Env env) {
        int oldMaxCopyJobPerTable = Config.cloud_max_copy_job_per_table;
        Config.cloud_max_copy_job_per_table = 2;
        try {
            // the clean copy job scheduler is a thread and not used by the removal
            CloudLoadManager manager = new CloudLoadManager(new LoadJobScheduler(), null);
            long now = System.currentTimeMillis();
            for (int i = 0; i < 4; i++) {
                manager.addLoadJob(finishedCopyJob(i, "copy_" + i, now - (4 - i) * 1000L));
            }
            // removes the completed copy jobs of the table beyond the newest 2; the label lists are copy-on-write
            manager.removeOldLoadJob();
            Map<Long, Map<String, ConcurrentLinkedQueue<LoadJob>>> dbIdToLabelToLoadJobs =
                    Deencapsulation.getField(manager, "dbIdToLabelToLoadJobs");
            Assert.assertEquals(Sets.newHashSet("copy_2", "copy_3"), dbIdToLabelToLoadJobs.get(1L).keySet());
            Assert.assertNull(manager.getLoadJob(0L));
            Assert.assertNull(manager.getLoadJob(1L));
            Assert.assertNotNull(manager.getLoadJob(2L));
            Assert.assertNotNull(manager.getLoadJob(3L));
        } finally {
            Config.cloud_max_copy_job_per_table = oldMaxCopyJobPerTable;
        }
    }
}
