// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.master.massdb;

import org.apache.doris.catalog.Env;
import org.apache.doris.master.MasterImpl;
import org.apache.doris.master.ReportHandler;
import org.apache.doris.mysql.authenticate.TestLogAppender;
import org.apache.doris.system.Backend;
import org.apache.doris.system.SystemInfoService;
import org.apache.doris.task.AgentTaskQueue;
import org.apache.doris.thrift.TBackend;
import org.apache.doris.thrift.TFinishTaskRequest;
import org.apache.doris.thrift.TMasterResult;
import org.apache.doris.thrift.TStatus;
import org.apache.doris.thrift.TStatusCode;
import org.apache.doris.thrift.TTaskType;

import mockit.Mock;
import mockit.MockUp;
import org.apache.logging.log4j.Level;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class MasterImplClearTransactionTaskTest {
    private static final long BACKEND_ID = 10000L;
    private static final String HOST = "127.0.0.1";
    private static final int HEARTBEAT_PORT = 9050;
    private static final int BE_PORT = 9060;
    private static final String NULL_TASK_WARNING = "Finish task rpc got null task";

    private MasterImpl masterImpl;

    @Before
    public void setUp() {
        AgentTaskQueue.clearAllTasks();

        SystemInfoService systemInfoService = new SystemInfoService();
        Backend backend = new Backend(BACKEND_ID, HOST, HEARTBEAT_PORT);
        backend.setBePort(BE_PORT);
        systemInfoService.addBackend(backend);

        new MockUp<Env>() {
            @Mock
            public SystemInfoService getCurrentSystemInfo() {
                return systemInfoService;
            }
        };

        new MockUp<ReportHandler>() {
            @Mock
            public void start() {
            }
        };

        masterImpl = new MasterImpl();
    }

    @After
    public void tearDown() {
        AgentTaskQueue.clearAllTasks();
    }

    @Test
    public void testClearTransactionReportIsNotAWarning() {
        // every aborted txn sends a clear transaction task to each backend without queueing it
        try (TestLogAppender appender = TestLogAppender.attach(MasterImpl.class, Level.DEBUG)) {
            TMasterResult result = masterImpl.finishTask(newFinishTaskRequest(TTaskType.CLEAR_TRANSACTION_TASK));

            Assert.assertEquals(TStatusCode.OK, result.getStatus().getStatusCode());
            Assert.assertFalse(appender.contains(Level.WARN, NULL_TASK_WARNING));
            Assert.assertTrue(appender.contains(Level.DEBUG, "Finish task rpc for request="));
        }
    }

    @Test
    public void testOtherUnqueuedReportsKeepTheirLevel() {
        try (TestLogAppender appender = TestLogAppender.attach(MasterImpl.class, Level.DEBUG)) {
            TMasterResult release = masterImpl.finishTask(newFinishTaskRequest(TTaskType.RELEASE_SNAPSHOT));
            TMasterResult drop = masterImpl.finishTask(newFinishTaskRequest(TTaskType.DROP));

            Assert.assertEquals(TStatusCode.OK, release.getStatus().getStatusCode());
            Assert.assertEquals(TStatusCode.OK, drop.getStatus().getStatusCode());
            Assert.assertTrue(appender.contains(Level.WARN, NULL_TASK_WARNING));
            Assert.assertTrue(appender.contains(Level.INFO, "Finish task rpc for request="));
        }
    }

    @Test
    public void testUnknownQueuedTypeIsStillCancelled() {
        try (TestLogAppender appender = TestLogAppender.attach(MasterImpl.class, Level.DEBUG)) {
            TMasterResult result = masterImpl.finishTask(newFinishTaskRequest(TTaskType.CREATE));

            Assert.assertEquals(TStatusCode.CANCELLED, result.getStatus().getStatusCode());
            Assert.assertTrue(appender.contains(Level.WARN, "cannot find task"));
        }
    }

    private TFinishTaskRequest newFinishTaskRequest(TTaskType taskType) {
        TBackend tBackend = new TBackend(HOST, BE_PORT, 0);
        TFinishTaskRequest request = new TFinishTaskRequest(tBackend, taskType, 1L, new TStatus(TStatusCode.OK));
        request.setReportVersion(1L);
        return request;
    }
}
