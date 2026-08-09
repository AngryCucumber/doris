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

package org.apache.doris.massdblicense;

import org.apache.doris.catalog.Env;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.service.arrowflight.DorisFlightSqlProducer;
import org.apache.doris.service.arrowflight.results.FlightSqlChannel;
import org.apache.doris.service.arrowflight.results.FlightSqlResultCacheEntry;
import org.apache.doris.service.arrowflight.sessions.FlightSessionsManager;

import com.google.protobuf.ByteString;
import org.apache.arrow.flight.FlightRuntimeException;
import org.apache.arrow.flight.Location;
import org.apache.arrow.flight.sql.impl.FlightSql.TicketStatementQuery;
import org.apache.arrow.vector.VectorSchemaRoot;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.ArrayList;

class MassDbLicenseArrowFlightGuardTest {
    @Test
    void catalogMetadataReturnsStableLicenseDenialBeforeReadingSessionState() throws Exception {
        Env env = Mockito.mock(Env.class);
        Mockito.when(env.evaluateMassDbLicenseLocalQuery()).thenReturn(
                MassDbLicenseLocalSnapshotStore.QueryDecision.deny("MASSDB_LICENSE_EXPIRED"));
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            DorisFlightSqlProducer producer = new DorisFlightSqlProducer(
                    Mockito.mock(Location.class), Mockito.mock(FlightSessionsManager.class));
            try {
                FlightRuntimeException error = Assertions.assertThrows(
                        FlightRuntimeException.class,
                        () -> producer.getFlightInfoCatalogs(null, null, null));
                Assertions.assertTrue(error.getMessage().contains("MASSDB_LICENSE_EXPIRED"));
            } finally {
                producer.close();
            }
        }
    }

    @Test
    void metadataStreamPreservesStableArrowDenialInsteadOfWrappingInternalError()
            throws Exception {
        Env env = Mockito.mock(Env.class);
        Mockito.when(env.evaluateMassDbLicenseLocalQuery()).thenReturn(
                MassDbLicenseLocalSnapshotStore.QueryDecision.deny("MASSDB_LICENSE_EXPIRED"));
        org.apache.arrow.flight.FlightProducer.ServerStreamListener listener =
                Mockito.mock(org.apache.arrow.flight.FlightProducer.ServerStreamListener.class);
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            DorisFlightSqlProducer producer = new DorisFlightSqlProducer(
                    Mockito.mock(Location.class), Mockito.mock(FlightSessionsManager.class));
            try {
                FlightRuntimeException error = Assertions.assertThrows(
                        FlightRuntimeException.class,
                        () -> producer.getStreamCatalogs(null, listener));
                Assertions.assertTrue(error.getMessage().contains("MASSDB_LICENSE_EXPIRED"));
                Mockito.verify(listener).error(error);
            } finally {
                producer.close();
            }
        }
    }

    @Test
    void protectedCachedResultIsRecheckedBeforeArrowStreamStarts() throws Exception {
        Env env = Mockito.mock(Env.class);
        Mockito.when(env.evaluateMassDbLicenseLocalQuery()).thenReturn(
                MassDbLicenseLocalSnapshotStore.QueryDecision.deny("MASSDB_LICENSE_EXPIRED"));
        FlightSessionsManager sessions = Mockito.mock(FlightSessionsManager.class);
        ConnectContext context = Mockito.mock(ConnectContext.class);
        FlightSqlChannel channel = Mockito.mock(FlightSqlChannel.class);
        org.apache.arrow.flight.FlightProducer.ServerStreamListener listener =
                Mockito.mock(org.apache.arrow.flight.FlightProducer.ServerStreamListener.class);
        VectorSchemaRoot root = new VectorSchemaRoot(new ArrayList<>(), new ArrayList<>());
        FlightSqlResultCacheEntry entry = new FlightSqlResultCacheEntry(
                root, "SHOW TABLES", true);
        Mockito.when(sessions.getConnectContext("peer")).thenReturn(context);
        Mockito.when(context.getFlightSqlChannel()).thenReturn(channel);
        Mockito.when(channel.getResult("query-id")).thenReturn(entry);
        TicketStatementQuery ticket = TicketStatementQuery.newBuilder()
                .setStatementHandle(ByteString.copyFromUtf8("peer:query-id"))
                .build();
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            DorisFlightSqlProducer producer = new DorisFlightSqlProducer(
                    Mockito.mock(Location.class), sessions);
            try {
                FlightRuntimeException error = Assertions.assertThrows(
                        FlightRuntimeException.class,
                        () -> producer.getStreamStatement(ticket, null, listener));
                Assertions.assertTrue(error.getMessage().contains("MASSDB_LICENSE_EXPIRED"));
                Mockito.verify(listener, Mockito.never()).start(Mockito.any());
                Mockito.verify(listener, Mockito.never()).completed();
                Mockito.verify(channel).invalidate("query-id");
            } finally {
                producer.close();
            }
        } finally {
            root.close();
        }
    }
}
