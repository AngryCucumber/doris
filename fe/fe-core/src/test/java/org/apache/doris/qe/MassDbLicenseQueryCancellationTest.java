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

package org.apache.doris.qe;

import org.apache.doris.catalog.Env;
import org.apache.doris.datasource.hive.HiveTransactionMgr;
import org.apache.doris.qe.QeProcessorImpl.QueryInfo;
import org.apache.doris.thrift.TQueryOptions;
import org.apache.doris.thrift.TUniqueId;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class MassDbLicenseQueryCancellationTest {
    @Test
    void runningQueryCancellationUsesItsTrustedExecutorClassification() throws Exception {
        ConnectContext context = Mockito.mock(ConnectContext.class);
        StmtExecutor executor = Mockito.mock(StmtExecutor.class);
        Coordinator coordinator = Mockito.mock(Coordinator.class);
        TQueryOptions options = new TQueryOptions();
        TUniqueId queryId = new TUniqueId(91, 92);
        Mockito.when(context.getExecutor()).thenReturn(executor);
        Mockito.when(coordinator.getQueryOptions()).thenReturn(options);
        Mockito.when(executor.cancelMassDbLicenseProtectedRead(
                "MASSDB_LICENSE_EXPIRED")).thenReturn(true);

        QeProcessorImpl.INSTANCE.registerQuery(queryId,
                new QueryInfo(context, "SELECT * FROM sales.orders", coordinator));
        try {
            Assertions.assertEquals(1,
                    QeProcessorImpl.INSTANCE.cancelMassDbLicenseProtectedReads(
                            "MASSDB_LICENSE_EXPIRED"));
            Mockito.verify(executor).cancelMassDbLicenseProtectedRead(
                    "MASSDB_LICENSE_EXPIRED");
        } finally {
            HiveTransactionMgr transactions = Mockito.mock(HiveTransactionMgr.class);
            try (MockedStatic<Env> env = Mockito.mockStatic(Env.class)) {
                env.when(Env::getCurrentHiveTransactionMgr).thenReturn(transactions);
                QeProcessorImpl.INSTANCE.unregisterQuery(queryId);
            }
        }
    }
}
