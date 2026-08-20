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

package org.apache.doris.master;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.common.jmockit.Deencapsulation;
import org.apache.doris.system.Backend;
import org.apache.doris.system.SystemInfoService;
import org.apache.doris.thrift.TBackend;
import org.apache.doris.thrift.TMasterResult;
import org.apache.doris.thrift.TReportRequest;
import org.apache.doris.thrift.TStatusCode;
import org.apache.doris.thrift.TTaskType;

import com.google.common.collect.Maps;
import mockit.Mock;
import mockit.MockUp;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;

public class ReportHandlerTest {
    private SystemInfoService systemInfoService;

    @Before
    public void setUp() {
        systemInfoService = new SystemInfoService();
        new MockUp<Env>() {
            @Mock
            public SystemInfoService getCurrentSystemInfo() {
                return systemInfoService;
            }
        };
    }

    private Backend addBackend(long beId) {
        Backend backend = new Backend(beId, "192.168.7." + (beId % 250), 9050);
        backend.setBePort(9060);
        systemInfoService.addBackend(backend);
        return backend;
    }

    private TReportRequest buildTaskReport(Backend backend) {
        TReportRequest request = new TReportRequest();
        request.setBackend(new TBackend(backend.getHost(), backend.getBePort(), backend.getHttpPort()));
        Map<TTaskType, Set<Long>> tasks = Maps.newHashMap();
        request.setTasks(tasks);
        return request;
    }

    @Test
    public void testPutToQueueDedup() throws Exception {
        ReportHandler handler = new ReportHandler();
        Backend backend = addBackend(10001L);

        TMasterResult result1 = handler.handleReport(buildTaskReport(backend));
        Assert.assertEquals(TStatusCode.OK, result1.getStatus().getStatusCode());
        TMasterResult result2 = handler.handleReport(buildTaskReport(backend));
        Assert.assertEquals(TStatusCode.OK, result2.getStatus().getStatusCode());

        // a report of the same (backend, type) replaces the pending payload instead of
        // enqueueing a duplicated key
        int totalQueueSize = Deencapsulation.invoke(handler, "getTotalQueueSize");
        Assert.assertEquals(1, totalQueueSize);
        Map<?, ?> reportTasks = Deencapsulation.getField(handler, "reportTasks");
        Assert.assertEquals(1, reportTasks.size());
    }

    @Test
    public void testShardRoutingByBackendId() throws Exception {
        ReportHandler handler = new ReportHandler();
        List<BlockingQueue<?>> queues = Deencapsulation.getField(handler, "reportQueues");
        int workerNum = queues.size();
        Assert.assertEquals(Math.max(1, Config.report_handler_worker_num), workerNum);

        long beId1 = 20000L;
        long beId2 = 20001L;
        handler.handleReport(buildTaskReport(addBackend(beId1)));
        handler.handleReport(buildTaskReport(addBackend(beId2)));

        int shard1 = (int) (beId1 % workerNum);
        int shard2 = (int) (beId2 % workerNum);
        if (shard1 == shard2) {
            Assert.assertEquals(2, queues.get(shard1).size());
        } else {
            Assert.assertEquals(1, queues.get(shard1).size());
            Assert.assertEquals(1, queues.get(shard2).size());
        }

        int totalQueueSize = Deencapsulation.invoke(handler, "getTotalQueueSize");
        Assert.assertEquals(2, totalQueueSize);
    }
}
