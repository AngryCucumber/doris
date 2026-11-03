// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.cloud.load.massdb;

import org.apache.doris.catalog.Env;
import org.apache.doris.cloud.load.CloudLoadManager;
import org.apache.doris.cloud.load.CopyJob;
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
            // removes the completed copy jobs of the table beyond the newest 2; the label lists are concurrent queues
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
