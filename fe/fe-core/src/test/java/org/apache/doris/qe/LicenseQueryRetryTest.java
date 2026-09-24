// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.qe;

import org.apache.doris.analysis.StatementBase;
import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.EnvFactory;
import org.apache.doris.common.Config;
import org.apache.doris.common.QueryTimeoutException;
import org.apache.doris.common.Status;
import org.apache.doris.common.UserException;
import org.apache.doris.common.profile.ExecutionProfile;
import org.apache.doris.datasource.hive.HiveTransactionMgr;
import org.apache.doris.massdb.license.LicenseManager;
import org.apache.doris.massdb.license.LicenseQueryStatus;
import org.apache.doris.mysql.MysqlChannel;
import org.apache.doris.mysql.MysqlSerializer;
import org.apache.doris.nereids.StatementContext;
import org.apache.doris.nereids.glue.LogicalPlanAdapter;
import org.apache.doris.nereids.trees.plans.commands.EmptyCommand;
import org.apache.doris.planner.OlapScanNode;
import org.apache.doris.planner.Planner;
import org.apache.doris.qe.runtime.PipelineExecutionTask;
import org.apache.doris.qe.runtime.PipelineExecutionTaskBuilder;
import org.apache.doris.qe.runtime.ThriftPlansBuilder;
import org.apache.doris.resource.workloadgroup.QueryQueue;
import org.apache.doris.resource.workloadgroup.QueueToken;
import org.apache.doris.rpc.RpcException;
import org.apache.doris.system.SystemInfoService;
import org.apache.doris.thrift.TQueryOptions;
import org.apache.doris.thrift.TStatusCode;
import org.apache.doris.thrift.TUniqueId;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Controlled Q19 tests of both product retry loops, with the real coordinator dispatch boundary.
 * Parsing/planning and the remote pipeline task are doubles; no test grants admission by calling markStarted.
 */
class LicenseQueryRetryTest {
    private final AtomicReference<LicenseQueryStatus> status = new AtomicReference<>(LicenseQueryStatus.VALID);
    private final List<Attempt> attempts = new ArrayList<>();
    private final List<TUniqueId> commandQueryIds = new ArrayList<>();
    private MockedStatic<Env> currentEnv;
    private MockedStatic<EnvFactory> factories;
    private MockedStatic<ThriftPlansBuilder> thrift;
    private MockedStatic<PipelineExecutionTaskBuilder> tasks;
    private ConnectContext context;
    private MysqlChannel channel;
    private Planner planner;
    private LogicalPlanAdapter query;
    private StmtExecutor executor;
    private Failure failure = Failure.RPC;
    private boolean beforeDispatch;
    private boolean failEveryAttempt;
    private boolean sentResult;
    private int dispatches;
    private int previousRetryTime;
    private String previousDeployMode;
    private String previousCloudId;

    @BeforeEach
    void setUp() throws Exception {
        previousRetryTime = Config.max_query_retry_time;
        previousDeployMode = Config.deploy_mode;
        previousCloudId = Config.cloud_unique_id;
        Config.max_query_retry_time = 1;
        Config.deploy_mode = "local";
        Config.cloud_unique_id = "";

        Env env = Mockito.mock(Env.class);
        LicenseManager manager = Mockito.mock(LicenseManager.class);
        Mockito.when(manager.queryStatus()).thenAnswer(call -> status.get());
        Mockito.when(env.getLicenseManager()).thenReturn(manager);
        Mockito.when(env.isMaster()).thenReturn(true);
        currentEnv = Mockito.mockStatic(Env.class);
        currentEnv.when(Env::getCurrentEnv).thenReturn(env);
        currentEnv.when(Env::getCurrentHiveTransactionMgr).thenReturn(Mockito.mock(HiveTransactionMgr.class));
        context = Mockito.spy(new ConnectContext());
        context.env = env;
        context.getSessionVariable().setEnableSqlCache(false);
        context.getSessionVariable().enableProfile = false;
        Mockito.doReturn(false).when(context).supportHandleByFe();
        channel = Mockito.mock(MysqlChannel.class);
        Mockito.when(channel.getSerializer()).thenReturn(MysqlSerializer.newInstance());
        Mockito.when(channel.isSend()).thenAnswer(call -> sentResult);
        Mockito.doReturn(channel).when(context).getMysqlChannel();

        planner = Mockito.mock(Planner.class);
        query = Mockito.mock(LogicalPlanAdapter.class);
        Mockito.when(query.getOrigStmt()).thenReturn(new OriginStatement("select v from protected_table", 0));
        executor = newExecutor();
        EnvFactory factory = Mockito.mock(EnvFactory.class);
        factories = Mockito.mockStatic(EnvFactory.class);
        factories.when(EnvFactory::getInstance).thenReturn(factory);
        Mockito.when(factory.createCoordinator(Mockito.same(context), Mockito.same(planner), Mockito.any()))
                .thenAnswer(call -> newAttempt().coordinator);
        thrift = Mockito.mockStatic(ThriftPlansBuilder.class);
        thrift.when(() -> ThriftPlansBuilder.plansToThrift(Mockito.any())).thenAnswer(call -> {
            Attempt attempt = attempts.get(attempts.size() - 1);
            Assertions.assertSame(attempt.data, call.getArgument(0));
            if (beforeDispatch && shouldFail()) {
                expireAndFail(attempt);
            }
            return Collections.emptyMap();
        });
        tasks = Mockito.mockStatic(PipelineExecutionTaskBuilder.class);
        tasks.when(() -> PipelineExecutionTaskBuilder.build(Mockito.any(), Mockito.anyMap())).thenAnswer(call -> {
            Attempt attempt = attempts.get(attempts.size() - 1);
            Assertions.assertSame(attempt.data, call.getArgument(0));
            return attempt.task;
        });
    }

    @AfterEach
    void tearDown() {
        // This is a defensive cleanup after assertions; each test independently checks product cleanup first.
        try {
            for (Attempt attempt : attempts) {
                QeProcessorImpl.INSTANCE.unregisterQuery(attempt.queryId);
            }
        } finally {
            if (tasks != null) {
                tasks.close();
            }
            if (thrift != null) {
                thrift.close();
            }
            if (factories != null) {
                factories.close();
            }
            if (currentEnv != null) {
                currentEnv.close();
            }
            Config.max_query_retry_time = previousRetryTime;
            Config.deploy_mode = previousDeployMode;
            Config.cloud_unique_id = previousCloudId;
            ConnectContext.remove();
        }
    }

    @Test
    void startedRpcRetryCrossesExpiryButNewExecuteOnSameExecutorDoesNot() throws Exception {
        executor.execute(new TUniqueId(719, 1));

        Assertions.assertEquals(QueryState.MysqlStateType.EOF, context.getState().getStateType());
        assertAttempts(2, 2);
        Assertions.assertEquals(1, commandQueryIds.size(), "RPC retry must use the inner product loop");
        Assertions.assertNotEquals(attempts.get(0).queryId, attempts.get(1).queryId);
        Mockito.verify(attempts.get(0).coordinator).cancel(Mockito.any(Status.class));
        Mockito.verify(attempts.get(1).coordinator, Mockito.never()).cancel(Mockito.any(Status.class));
        assertCleaned();
        assertNewExecutionDenied(executor, new TUniqueId(719, 2));
        assertNewExecutionDenied(newExecutor(), new TUniqueId(719, 3));
        assertAttempts(2, 2);
    }

    @Test
    void rpcRetryBeforeFirstDispatchDoesNotAcquireStartedAdmission() throws Exception {
        beforeDispatch = true;
        executor.execute(new TUniqueId(719, 4));

        assertLicenseDenied();
        assertAttempts(1, 0);
        Assertions.assertNotEquals(attempts.get(0).queryId, context.queryId(),
                "The actual inner retry must change queryId before its admission check rejects it");
        Assertions.assertEquals(1, commandQueryIds.size());
        assertCleaned();
        assertNewExecutionDenied(executor, new TUniqueId(719, 5));
        assertAttempts(1, 0);
    }

    @Test
    void startedReplanRetryKeepsAdmissionAcrossBothProductLoops() throws Exception {
        failure = Failure.REPLAN;
        Config.cloud_unique_id = "license-controlled-replan";
        executor.queryRetry(new TUniqueId(719, 6));

        Assertions.assertEquals(QueryState.MysqlStateType.EOF, context.getState().getStateType());
        assertAttempts(2, 2);
        Assertions.assertEquals(2, commandQueryIds.size(), "The outer product loop must execute a new attempt");
        Assertions.assertNotEquals(commandQueryIds.get(0), commandQueryIds.get(1));
        Assertions.assertEquals(commandQueryIds.get(1), attempts.get(1).queryId);
        assertCleaned();
        context.getState().reset();
        executor.queryRetry(new TUniqueId(719, 7));
        assertLicenseDenied();
        assertAttempts(2, 2);
        assertCleaned();
    }

    @Test
    void replanBeforeFirstDispatchDoesNotAcquireStartedAdmission() throws Exception {
        failure = Failure.REPLAN;
        beforeDispatch = true;
        Config.cloud_unique_id = "license-controlled-replan";
        executor.queryRetry(new TUniqueId(719, 8));

        assertLicenseDenied();
        assertAttempts(1, 0);
        Assertions.assertEquals(2, commandQueryIds.size());
        Assertions.assertNotEquals(commandQueryIds.get(0), commandQueryIds.get(1));
        assertCleaned();
    }

    @Test
    void startedExecutionStillHonorsCancellationAndClearsAdmission() throws Exception {
        failure = Failure.CANCEL;
        executor.execute(new TUniqueId(719, 9));

        assertOriginalFailure("controlled cancellation");
        assertAttempts(1, 1);
        Assertions.assertTrue(attempts.get(0).coordinator.isQueryCancelled());
        Mockito.verify(attempts.get(0).token, Mockito.atLeastOnce()).cancel();
        Mockito.verify(attempts.get(0).job, Mockito.atLeastOnce()).cancel(Mockito.any(Status.class));
        assertCleaned();
        assertNewExecutionDenied(executor, new TUniqueId(719, 10));
        assertAttempts(1, 1);
    }

    @Test
    void startedExecutionStillHonorsTimeoutAndClearsAdmission() throws Exception {
        failure = Failure.TIMEOUT;
        executor.execute(new TUniqueId(719, 11));

        assertOriginalFailure("query timeout");
        assertAttempts(1, 1);
        Assertions.assertTrue(attempts.get(0).coordinator.isTimeout());
        Mockito.verify(attempts.get(0).coordinator).cancel(Mockito.argThat(
                reason -> reason.getErrorCode() == TStatusCode.TIMEOUT));
        assertCleaned();
        assertNewExecutionDenied(executor, new TUniqueId(719, 12));
        assertAttempts(1, 1);
    }

    @Test
    void exhaustedRetryBudgetCleansEveryAttemptAndItsAdmission() throws Exception {
        failEveryAttempt = true;
        executor.execute(new TUniqueId(719, 13));

        assertOriginalFailure("controlled RPC failure");
        assertAttempts(2, 2);
        Assertions.assertEquals(1, commandQueryIds.size());
        assertCleaned();
        assertNewExecutionDenied(executor, new TUniqueId(719, 14));
        assertAttempts(2, 2);
    }

    @Test
    void sentResultsStillPreventRetryAfterExpiryAndAdmissionIsCleaned() throws Exception {
        sentResult = true;
        executor.execute(new TUniqueId(719, 15));

        assertOriginalFailure("controlled RPC failure");
        assertAttempts(1, 1);
        assertCleaned();
        sentResult = false;
        assertNewExecutionDenied(executor, new TUniqueId(719, 16));
        assertAttempts(1, 1);
    }

    private StmtExecutor newExecutor() {
        // The command substitutes only parsing/planning, then enters the private product retry loop.
        // Both queryRetry/execute wrappers and every handleQueryStmt/dispatch/finally path remain real.
        EmptyCommand command = new EmptyCommand() {
            @Override
            public void run(ConnectContext ctx, StmtExecutor running) throws Exception {
                commandQueryIds.add(ctx.queryId().deepCopy());
                StatementBase original = running.getParsedStmt();
                running.setParsedStmt(query);
                running.setPlanner(planner);
                try {
                    invokeQueryRetry(running, ctx.queryId());
                } finally {
                    running.setParsedStmt(original);
                }
            }
        };
        LogicalPlanAdapter commandStatement = new LogicalPlanAdapter(command, new StatementContext());
        commandStatement.setOrigStmt(new OriginStatement("select v from protected_table", 0));
        return new StmtExecutor(context, commandStatement);
    }

    private Attempt newAttempt() throws Exception {
        Attempt attempt = new Attempt(context.queryId().deepCopy());
        attempts.add(attempt);
        Mockito.doAnswer(call -> {
            dispatches++;
            Assertions.assertTrue((Boolean) field(executor, StmtExecutor.class, "licenseQueryStarted"),
                    "Only the real coordinator must establish admission immediately before this task");
            if (shouldFail()) {
                expireAndFail(attempt);
            } else {
                Assertions.assertEquals(LicenseQueryStatus.EXPIRED, status.get());
            }
            return null;
        }).when(attempt.task).execute();
        return attempt;
    }

    private boolean shouldFail() {
        return failEveryAttempt || attempts.size() == 1;
    }

    private void expireAndFail(Attempt attempt) throws Exception {
        status.set(LicenseQueryStatus.EXPIRED);
        switch (failure) {
            case RPC:
                throw new RpcException("controlled-backend", "controlled RPC failure");
            case REPLAN:
                throw new UserException(SystemInfoService.ERROR_E230 + ": controlled replan failure");
            case CANCEL:
                executor.cancel(new Status(TStatusCode.CANCELLED, "controlled cancellation"));
                throw new UserException("controlled cancellation");
            case TIMEOUT:
                setField(attempt.data, CoordinatorContext.class, "timeoutDeadline", (Supplier<Long>) () -> 0L);
                throw new QueryTimeoutException();
            default:
                throw new AssertionError(failure);
        }
    }

    private void assertAttempts(int expectedAttempts, int expectedDispatches) throws Exception {
        Assertions.assertEquals(expectedAttempts, attempts.size());
        Assertions.assertEquals(expectedDispatches, dispatches);
        for (Attempt attempt : attempts) {
            Mockito.verify(attempt.coordinator).exec();
            Mockito.verify(attempt.coordinator).close();
            Mockito.verify(attempt.task, Mockito.times(beforeDispatch ? 0 : 1)).execute();
            Mockito.verify(attempt.queue).releaseAndNotify(attempt.token);
            Mockito.verify(attempt.scan, Mockito.atLeastOnce()).stop();
        }
    }

    private void assertCleaned() throws Exception {
        for (Attempt attempt : attempts) {
            Assertions.assertNull(QeProcessorImpl.INSTANCE.getCoordinator(attempt.queryId),
                    "The product finally must unregister every attempt, including changed query IDs");
        }
        for (String flag : new String[] {"licenseReadOutput", "licenseExternalWrite", "licensePreparedPointQuery",
                "licenseQueryStarted"}) {
            Assertions.assertFalse((Boolean) field(executor, StmtExecutor.class, flag), flag);
        }
        for (String reference : new String[] {"licenseQueryPlan", "licenseQueryStatement", "licenseQueryFinalPlan"}) {
            Assertions.assertNull(field(executor, StmtExecutor.class, reference), reference);
        }
    }

    private void assertNewExecutionDenied(StmtExecutor next, TUniqueId queryId) throws Exception {
        context.getState().reset();
        next.execute(queryId);
        assertLicenseDenied();
        assertCleaned();
        Assertions.assertFalse((Boolean) field(next, StmtExecutor.class, "licenseQueryStarted"));
    }

    private void assertLicenseDenied() {
        Assertions.assertEquals(QueryState.MysqlStateType.ERR, context.getState().getStateType());
        Assertions.assertEquals(6200, context.getState().getErrorCode().getCode());
        Assertions.assertTrue(context.getState().getErrorMessage().contains("LICENSE_EXPIRED"));
    }

    private void assertOriginalFailure(String message) {
        Assertions.assertEquals(QueryState.MysqlStateType.ERR, context.getState().getStateType());
        Assertions.assertTrue(context.getState().getErrorMessage().contains(message));
        Assertions.assertFalse(context.getState().getErrorMessage().contains("LICENSE_EXPIRED"));
    }

    private static void invokeQueryRetry(StmtExecutor running, TUniqueId queryId) throws Exception {
        Method method = StmtExecutor.class.getDeclaredMethod("handleQueryWithRetry", TUniqueId.class);
        method.setAccessible(true);
        try {
            method.invoke(running, queryId);
        } catch (InvocationTargetException wrapped) {
            Throwable cause = wrapped.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw (Error) cause;
        }
    }

    private static Object field(Object target, Class<?> owner, String name) throws Exception {
        Field field = owner.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }

    private static void setField(Object target, Class<?> owner, String name, Object value) throws Exception {
        Field field = owner.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private enum Failure {
        RPC, REPLAN, CANCEL, TIMEOUT
    }

    private class Attempt {
        private final TUniqueId queryId;
        private final NereidsCoordinator coordinator =
                Mockito.mock(NereidsCoordinator.class, Mockito.CALLS_REAL_METHODS);
        private final CoordinatorContext data = Mockito.mock(CoordinatorContext.class, Mockito.CALLS_REAL_METHODS);
        private final PipelineExecutionTask task = Mockito.mock(PipelineExecutionTask.class);
        private final QueryQueue queue = Mockito.mock(QueryQueue.class);
        private final QueueToken token = Mockito.mock(QueueToken.class);
        private final OlapScanNode scan = Mockito.mock(OlapScanNode.class);
        private final JobProcessor job = Mockito.mock(JobProcessor.class);

        private Attempt(TUniqueId queryId) throws Exception {
            this.queryId = queryId;
            setField(data, CoordinatorContext.class, "connectContext", context);
            setField(data, CoordinatorContext.class, "coordinator", coordinator);
            setField(data, CoordinatorContext.class, "queryId", queryId);
            setField(data, CoordinatorContext.class, "scanNodes", Collections.singletonList(scan));
            setField(data, CoordinatorContext.class, "queryOptions", new TQueryOptions().setExecutionTimeout(30));
            setField(data, CoordinatorContext.class, "instanceNum", (Supplier<Integer>) () -> 1);
            setField(data, CoordinatorContext.class, "timeoutDeadline", (Supplier<Long>) () -> Long.MAX_VALUE);
            setField(data, CoordinatorContext.class, "executionProfile", Mockito.mock(ExecutionProfile.class));
            setField(data, CoordinatorContext.class, "status", new Status());
            data.setQueueInfo(queue, token);
            data.setJobProcessor(job);
            setField(coordinator, NereidsCoordinator.class, "coordinatorContext", data);
            // Queue mechanics are separately tested; leave the real close() release path active here.
            setField(coordinator, NereidsCoordinator.class, "needEnqueue", false);
            Mockito.doReturn(0L).when(coordinator).getJobId();
            Mockito.doNothing().when(coordinator).processTopSink(Mockito.any(), Mockito.any());
            Mockito.doReturn(new RowBatch()).when(coordinator).getNext();
        }
    }
}
