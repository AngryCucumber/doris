// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.nereids.trees.plans.commands;

import org.apache.doris.catalog.Env;
import org.apache.doris.massdb.license.LicenseSqlException;
import org.apache.doris.nereids.StatementContext;
import org.apache.doris.nereids.exceptions.AnalysisException;
import org.apache.doris.nereids.trees.plans.Plan;
import org.apache.doris.nereids.trees.plans.commands.info.CreateTableInfo;
import org.apache.doris.nereids.trees.plans.logical.LogicalPlan;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.qe.StmtExecutor;

import com.google.common.collect.ImmutableMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.Optional;

class LicenseCtasAdmissionTest {
    @AfterEach
    void clearContext() {
        ConnectContext.remove();
    }

    @Test
    void externalCtasCannotCreateATableBeforeSourceAdmission() throws Exception {
        Fixture fixture = new Fixture(true);
        LicenseSqlException denied = new LicenseSqlException(6200,
                ImmutableMap.of("reason", "LICENSE_EXPIRED", "message", "LICENSE_EXPIRED"));
        Mockito.doThrow(denied).when(fixture.executor).checkLicenseExternalWrite(
                fixture.context.getStatementContext(), fixture.finalPlan);
        try (MockedStatic<Env> environment = Mockito.mockStatic(Env.class)) {
            environment.when(Env::getCurrentEnv).thenReturn(fixture.env);
            Assertions.assertSame(denied, Assertions.assertThrows(LicenseSqlException.class,
                    () -> fixture.command.run(fixture.context, fixture.executor)));
            Mockito.verify(fixture.env, Mockito.never()).createTable(Mockito.any(CreateTableInfo.class));
            Mockito.verify(fixture.command, Mockito.never()).handleFallbackFailedCtas(Mockito.any());
        }
    }

    @Test
    void externalCtasChecksTheBoundSourceBeforeCreating() throws Exception {
        Fixture fixture = new Fixture(true);
        // Existing IF NOT EXISTS result avoids executing an unrelated insert in this boundary test.
        Mockito.when(fixture.env.createTable(fixture.info)).thenReturn(true);
        try (MockedStatic<Env> environment = Mockito.mockStatic(Env.class)) {
            environment.when(Env::getCurrentEnv).thenReturn(fixture.env);
            fixture.command.run(fixture.context, fixture.executor);
            InOrder order = Mockito.inOrder(fixture.command, fixture.executor, fixture.env);
            order.verify(fixture.command).validateCreateTableAsSelect(fixture.context, fixture.query);
            order.verify(fixture.executor).checkLicenseExternalWrite(
                    fixture.context.getStatementContext(), fixture.finalPlan);
            order.verify(fixture.env).createTable(fixture.info);
        }
    }

    @Test
    void internalCtasIsNotMisclassifiedByItsSourceResultSink() throws Exception {
        Fixture fixture = new Fixture(false);
        Mockito.when(fixture.env.createTable(fixture.info)).thenReturn(true);
        try (MockedStatic<Env> environment = Mockito.mockStatic(Env.class)) {
            environment.when(Env::getCurrentEnv).thenReturn(fixture.env);
            fixture.command.run(fixture.context, fixture.executor);
            Mockito.verifyNoInteractions(fixture.executor);
            Mockito.verify(fixture.env).createTable(fixture.info);
        }
    }

    @Test
    void invalidCtasKeepsItsOriginalValidationError() {
        Fixture fixture = new Fixture(true);
        AnalysisException invalid = new AnalysisException("invalid original schema");
        Mockito.doThrow(invalid).when(fixture.command).validateCreateTableAsSelect(fixture.context, fixture.query);
        Assertions.assertSame(invalid, Assertions.assertThrows(AnalysisException.class,
                () -> fixture.command.run(fixture.context, fixture.executor)));
        Mockito.verifyNoInteractions(fixture.executor, fixture.env);
    }

    private static final class Fixture {
        private final ConnectContext context = new ConnectContext();
        private final Env env = Mockito.mock(Env.class);
        private final CreateTableInfo info = Mockito.mock(CreateTableInfo.class);
        private final LogicalPlan query = Mockito.mock(LogicalPlan.class);
        private final Plan finalPlan = Mockito.mock(Plan.class);
        private final StmtExecutor executor = Mockito.mock(StmtExecutor.class);
        private final CreateTableCommand command = Mockito.spy(new CreateTableCommand(Optional.of(query), info));

        private Fixture(boolean external) {
            context.setStatementContext(new StatementContext(context, null));
            Mockito.when(info.isExternal()).thenReturn(external);
            Mockito.doReturn(finalPlan).when(command).validateCreateTableAsSelect(context, query);
        }
    }
}
