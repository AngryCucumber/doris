// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.qe;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.common.UserException;
import org.apache.doris.datasource.hive.HiveTransactionMgr;
import org.apache.doris.massdb.license.LicenseManager;
import org.apache.doris.massdb.license.LicenseQueryStatus;
import org.apache.doris.massdb.license.LicenseSqlException;
import org.apache.doris.nereids.StatementContext;
import org.apache.doris.nereids.glue.LogicalPlanAdapter;
import org.apache.doris.nereids.trees.plans.commands.EmptyCommand;
import org.apache.doris.planner.OlapScanNode;
import org.apache.doris.planner.Planner;
import org.apache.doris.planner.ScanNode;
import org.apache.doris.qe.QeProcessorImpl.QueryInfo;
import org.apache.doris.qe.runtime.PipelineExecutionTask;
import org.apache.doris.qe.runtime.PipelineExecutionTaskBuilder;
import org.apache.doris.qe.runtime.ThriftPlansBuilder;
import org.apache.doris.resource.workloadgroup.QueryQueue;
import org.apache.doris.resource.workloadgroup.QueueToken;
import org.apache.doris.resource.workloadgroup.WorkloadGroup;
import org.apache.doris.resource.workloadgroup.WorkloadGroupMgr;
import org.apache.doris.rpc.BackendServiceProxy;
import org.apache.doris.system.Backend;
import org.apache.doris.thrift.TPipelineWorkloadGroup;
import org.apache.doris.thrift.TQueryOptions;
import org.apache.doris.thrift.TUniqueId;

import com.google.protobuf.ByteString;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Supplier;

class LicenseQueryExecutionTest {
    private final AtomicReference<LicenseQueryStatus> status = new AtomicReference<>(LicenseQueryStatus.VALID);
    private MockedStatic<Env> currentEnv;
    private Env env;
    private ConnectContext context;

    @BeforeEach
    void setUp() {
        env = Mockito.mock(Env.class);
        LicenseManager manager = Mockito.mock(LicenseManager.class);
        Mockito.when(manager.queryStatus()).thenAnswer(invocation -> status.get());
        Mockito.when(env.getLicenseManager()).thenReturn(manager);
        Mockito.when(env.isMaster()).thenReturn(true);
        currentEnv = Mockito.mockStatic(Env.class);
        currentEnv.when(Env::getCurrentEnv).thenReturn(env);
        context = new ConnectContext();
        context.env = env;
        context.setQueryId(new TUniqueId(1, 1));
    }

    @AfterEach
    void tearDown() {
        ConnectContext.remove();
        currentEnv.close();
    }

    @Test
    void onlyStartedExecutionMayRetryAfterExpiry() throws Exception {
        StmtExecutor executor = new StmtExecutor(context, "select v from t where k=1");
        executor.checkLicensePreparedPointQuery();
        executor.markLicenseQueryStarted();
        status.set(LicenseQueryStatus.EXPIRED);
        executor.checkLicenseBeforeDispatch();
        executor.markLicenseQueryStarted();

        StmtExecutor next = new StmtExecutor(context, "select v from t where k=1");
        LicenseSqlException denied = Assertions.assertThrows(LicenseSqlException.class,
                next::checkLicensePreparedPointQuery);
        Assertions.assertEquals(6200, denied.getMysqlErrorCode().getCode());
        Assertions.assertTrue(denied.getMessage().contains("LICENSE_EXPIRED"));
    }

    @Test
    void earlyAdmissionAndFailedDispatchDoNotBecomePermanentPermission() throws Exception {
        StmtExecutor executor = new StmtExecutor(context, "select v from t where k=1");
        executor.checkLicensePreparedPointQuery();
        status.set(LicenseQueryStatus.EXPIRED);
        Assertions.assertThrows(LicenseSqlException.class, executor::markLicenseQueryStarted);
        Assertions.assertThrows(LicenseSqlException.class, executor::checkLicenseBeforeDispatch);
        status.set(LicenseQueryStatus.VALID);
        executor.markLicenseQueryStarted();
    }

    @Test
    void failedPointQueryPreparationDoesNotGrantRetryAfterExpiry() throws Exception {
        StmtExecutor executor = new StmtExecutor(context, "select v from t where k=1");
        executor.checkLicensePreparedPointQuery();
        PointQueryExecutor point = Mockito.mock(PointQueryExecutor.class, Mockito.CALLS_REAL_METHODS);
        point.setLicenseQueryExecutor(executor);
        Mockito.doThrow(new UserException("preparation failed")).when(point).setScanRangeLocations();
        Assertions.assertThrows(UserException.class, point::getNext);
        status.set(LicenseQueryStatus.EXPIRED);
        Assertions.assertThrows(LicenseSqlException.class, executor::checkLicenseBeforeDispatch);
    }

    @Test
    void pointQueryRechecksAfterRequestPreparationBeforeRpc() throws Exception {
        context.setThreadLocalInfo();
        StmtExecutor executor = new StmtExecutor(context, "select v from t where k=1");
        executor.checkLicensePreparedPointQuery();
        PointQueryExecutor point = Mockito.mock(PointQueryExecutor.class, Mockito.CALLS_REAL_METHODS);
        point.setLicenseQueryExecutor(executor);
        Mockito.doNothing().when(point).setScanRangeLocations();
        ShortCircuitQueryContext cached = Mockito.mock(ShortCircuitQueryContext.class);
        for (String field : new String[] {"serializedDescTable", "serializedOutputExpr", "serializedQueryOptions"}) {
            setField(cached, ShortCircuitQueryContext.class, field, ByteString.EMPTY);
        }
        setField(point, PointQueryExecutor.class, "shortCircuitQueryContext", cached);
        setField(point, PointQueryExecutor.class, "candidateBackends",
                Collections.singletonList(Mockito.mock(Backend.class)));
        Mockito.doAnswer(invocation -> {
            status.set(LicenseQueryStatus.EXPIRED);
            return null;
        }).when(point).addKeyTuples(Mockito.any());
        try (MockedStatic<BackendServiceProxy> proxy = Mockito.mockStatic(BackendServiceProxy.class)) {
            Assertions.assertThrows(LicenseSqlException.class, point::getNext);
            proxy.verifyNoInteractions();
        }
        Assertions.assertThrows(LicenseSqlException.class, executor::checkLicenseBeforeDispatch);
    }

    @Test
    void procedureAndInternalSessionFlagsDoNotExemptClientReads() {
        context.setRunProcedure(true);
        context.getState().setInternal(true);
        status.set(LicenseQueryStatus.MISSING);
        StmtExecutor executor = new StmtExecutor(context, "select v from t");
        Assertions.assertThrows(LicenseSqlException.class, executor::checkLicensePreparedPointQuery);
    }

    @Test
    void queryGuardRunsBeforeFrontendOrCacheResultAccess() throws Exception {
        StmtExecutor executor = new StmtExecutor(context, "select * from t");
        LogicalPlanAdapter statement = Mockito.mock(LogicalPlanAdapter.class);
        executor.setParsedStmt(statement);
        Planner planner = Mockito.mock(Planner.class);
        executor.setPlanner(planner);
        status.set(LicenseQueryStatus.EXPIRED);
        Method handle = StmtExecutor.class.getDeclaredMethod("handleQueryStmt");
        handle.setAccessible(true);
        InvocationTargetException failure = Assertions.assertThrows(InvocationTargetException.class,
                () -> handle.invoke(executor));
        Assertions.assertInstanceOf(LicenseSqlException.class, failure.getCause());
        Mockito.verify(planner, Mockito.never()).handleQueryInFe(Mockito.any());
        Mockito.verify(statement, Mockito.never()).getLogicalPlan();
    }

    @Test
    void publicExecutionEntryClearsAdmissionAndPreservesSqlErrorCode() throws Exception {
        EmptyCommand command = new EmptyCommand() {
            @Override
            public void run(ConnectContext ctx, StmtExecutor executor) throws Exception {
                executor.checkLicensePreparedPointQuery();
                executor.markLicenseQueryStarted();
            }
        };
        LogicalPlanAdapter statement = new LogicalPlanAdapter(command, new StatementContext());
        statement.setOrigStmt(new OriginStatement("", 0));
        StmtExecutor executor = new StmtExecutor(context, statement);
        executor.execute(new TUniqueId(1, 2));
        Assertions.assertNotEquals(QueryState.MysqlStateType.ERR, context.getState().getStateType());
        status.set(LicenseQueryStatus.EXPIRED);
        context.getState().reset();
        executor.execute(new TUniqueId(1, 3));
        Assertions.assertEquals(QueryState.MysqlStateType.ERR, context.getState().getStateType());
        Assertions.assertEquals(6200, context.getState().getErrorCode().getCode());
        Assertions.assertTrue(context.getState().getErrorMessage().contains("LICENSE_EXPIRED"));
        executor.checkLicenseBeforeDispatch();
    }

    @Test
    void legacyCoordinatorRechecksAfterQueueAndReleasesOnDenial() throws Exception {
        checkQueuedCoordinator(false);
    }

    @Test
    void nereidsCoordinatorRechecksBeforeSinkAndReleasesOnDenial() throws Exception {
        checkQueuedCoordinator(true);
    }

    @Test
    void nereidsFirstDispatchWaitsForMonitorThenRechecksExpiry() throws Exception {
        boolean workloadEnabled = Config.enable_workload_group;
        boolean queueEnabled = Config.enable_query_queue;
        Config.enable_workload_group = true;
        Config.enable_query_queue = true;
        context.setQueryId(new TUniqueId(771, 991));
        StmtExecutor executor = new StmtExecutor(context, "select * from t");
        executor.checkLicensePreparedPointQuery();
        QueryQueue queue = Mockito.mock(QueryQueue.class);
        QueueToken token = Mockito.mock(QueueToken.class);
        Mockito.when(queue.getToken(Mockito.anyInt())).thenReturn(token);
        WorkloadGroup group = Mockito.mock(WorkloadGroup.class);
        Mockito.when(group.getQueryQueue()).thenReturn(queue);
        Mockito.when(group.toThrift()).thenReturn(new TPipelineWorkloadGroup());
        WorkloadGroupMgr groups = Mockito.mock(WorkloadGroupMgr.class);
        Mockito.when(groups.getWorkloadGroup(context)).thenReturn(Collections.singletonList(group));
        Mockito.when(env.getWorkloadGroupMgr()).thenReturn(groups);
        currentEnv.when(Env::getCurrentHiveTransactionMgr).thenReturn(Mockito.mock(HiveTransactionMgr.class));

        NereidsCoordinator coordinator = Mockito.mock(NereidsCoordinator.class, Mockito.CALLS_REAL_METHODS);
        CoordinatorContext data = Mockito.mock(CoordinatorContext.class, Mockito.CALLS_REAL_METHODS);
        ScanNode scan = Mockito.mock(OlapScanNode.class);
        setField(data, CoordinatorContext.class, "connectContext", context);
        setField(data, CoordinatorContext.class, "scanNodes", Collections.singletonList(scan));
        setField(data, CoordinatorContext.class, "queryId", context.queryId());
        setField(data, CoordinatorContext.class, "queryOptions", new TQueryOptions().setExecutionTimeout(30));
        setField(data, CoordinatorContext.class, "instanceNum", (Supplier<Integer>) () -> 1);
        setField(coordinator, NereidsCoordinator.class, "coordinatorContext", data);
        setField(coordinator, NereidsCoordinator.class, "needEnqueue", true);
        Mockito.doReturn(false).when(coordinator).isQueryCancelled();
        Mockito.doReturn(0L).when(coordinator).getJobId();
        Mockito.doNothing().when(coordinator).processTopSink(Mockito.any(), Mockito.any());
        coordinator.setLicenseQueryExecutor(executor);
        PipelineExecutionTask task = Mockito.mock(PipelineExecutionTask.class);
        CountDownLatch held = new CountDownLatch(1);
        CountDownLatch built = new CountDownLatch(1);
        AtomicReference<Throwable> holderFailure = new AtomicReference<>();
        Thread executingThread = Thread.currentThread();
        Thread holder = new Thread(() -> {
            try {
                synchronized (data) {
                    held.countDown();
                    Assertions.assertTrue(built.await(5, TimeUnit.SECONDS));
                    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
                    boolean blockedHere = false;
                    while (System.nanoTime() < deadline) {
                        ThreadInfo info = ManagementFactory.getThreadMXBean().getThreadInfo(executingThread.getId());
                        if (info != null && info.getThreadState() == Thread.State.BLOCKED
                                && info.getLockInfo() != null
                                && info.getLockInfo().getIdentityHashCode() == System.identityHashCode(data)) {
                            blockedHere = true;
                            break;
                        }
                        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
                    }
                    Assertions.assertTrue(blockedHere, "The real coordinator must wait on this context monitor");
                    status.set(LicenseQueryStatus.EXPIRED);
                }
            } catch (Throwable failure) {
                holderFailure.set(failure);
            }
        }, "license-dispatch-monitor-holder");
        try (MockedStatic<ThriftPlansBuilder> thrift = Mockito.mockStatic(ThriftPlansBuilder.class);
                MockedStatic<PipelineExecutionTaskBuilder> tasks =
                        Mockito.mockStatic(PipelineExecutionTaskBuilder.class)) {
            thrift.when(() -> ThriftPlansBuilder.plansToThrift(data)).thenReturn(Collections.emptyMap());
            tasks.when(() -> PipelineExecutionTaskBuilder.build(data, Collections.emptyMap())).thenAnswer(call -> {
                built.countDown();
                return task;
            });
            QeProcessorImpl.INSTANCE.registerQuery(context.queryId(), new QueryInfo(null, "test", coordinator));
            holder.start();
            Assertions.assertTrue(held.await(5, TimeUnit.SECONDS));
            Assertions.assertThrows(LicenseSqlException.class, coordinator::exec);
            Assertions.assertThrows(LicenseSqlException.class, executor::checkLicenseBeforeDispatch);
            Mockito.verify(task, Mockito.never()).execute();
            Mockito.verify(token).get(Mockito.anyString(), Mockito.anyInt());
        } finally {
            built.countDown();
            holder.join(6000);
            coordinator.close();
            QeProcessorImpl.INSTANCE.unregisterQuery(context.queryId());
            Config.enable_workload_group = workloadEnabled;
            Config.enable_query_queue = queueEnabled;
        }
        Assertions.assertFalse(holder.isAlive());
        Assertions.assertNull(holderFailure.get());
        Mockito.verify(queue).releaseAndNotify(token);
        Mockito.verify(scan).stop();
    }

    private void checkQueuedCoordinator(boolean nereids) throws Exception {
        boolean workloadEnabled = Config.enable_workload_group;
        boolean queueEnabled = Config.enable_query_queue;
        Config.enable_workload_group = true;
        Config.enable_query_queue = true;
        try {
            StmtExecutor executor = new StmtExecutor(context, "insert into external.t select * from t");
            executor.checkLicenseExternalWrite((Planner) null);
            QueryQueue queue = Mockito.mock(QueryQueue.class);
            QueueToken token = Mockito.mock(QueueToken.class);
            Mockito.when(queue.getToken(Mockito.anyInt())).thenReturn(token);
            Mockito.doAnswer(invocation -> {
                // Model a successful queue wait that crossed the certificate boundary.
                status.set(LicenseQueryStatus.EXPIRED);
                return null;
            }).when(token).get(Mockito.anyString(), Mockito.anyInt());
            WorkloadGroup group = Mockito.mock(WorkloadGroup.class);
            Mockito.when(group.getQueryQueue()).thenReturn(queue);
            Mockito.when(group.toThrift()).thenReturn(new TPipelineWorkloadGroup());
            WorkloadGroupMgr groups = Mockito.mock(WorkloadGroupMgr.class);
            Mockito.when(groups.getWorkloadGroup(context)).thenReturn(Collections.singletonList(group));
            Mockito.when(env.getWorkloadGroupMgr()).thenReturn(groups);
            List<ScanNode> scans = Collections.singletonList(Mockito.mock(OlapScanNode.class));
            Coordinator coordinator;
            if (nereids) {
                NereidsCoordinator actual = Mockito.mock(NereidsCoordinator.class, Mockito.CALLS_REAL_METHODS);
                CoordinatorContext data = Mockito.mock(CoordinatorContext.class);
                setField(data, CoordinatorContext.class, "connectContext", context);
                setField(data, CoordinatorContext.class, "scanNodes", scans);
                setField(data, CoordinatorContext.class, "queryId", context.queryId());
                setField(data, CoordinatorContext.class, "queryOptions", new TQueryOptions().setExecutionTimeout(30));
                Mockito.when(data.getQueryQueue()).thenReturn(Optional.of(queue));
                Mockito.when(data.getQueueToken()).thenReturn(Optional.of(token));
                setField(actual, NereidsCoordinator.class, "coordinatorContext", data);
                setField(actual, NereidsCoordinator.class, "needEnqueue", true);
                coordinator = actual;
            } else {
                coordinator = Mockito.mock(Coordinator.class, Mockito.CALLS_REAL_METHODS);
                setField(coordinator, Coordinator.class, "context", context);
                setField(coordinator, Coordinator.class, "scanNodes", scans);
                setField(coordinator, Coordinator.class, "queryId", context.queryId());
                setField(coordinator, Coordinator.class, "queryOptions", new TQueryOptions().setExecutionTimeout(30));
            }
            Mockito.doReturn(false).when(coordinator).isQueryCancelled();
            coordinator.setLicenseQueryExecutor(executor);
            try {
                Assertions.assertThrows(LicenseSqlException.class, coordinator::exec);
                Mockito.verify(token).get(Mockito.anyString(), Mockito.anyInt());
                if (!nereids) {
                    Mockito.verify(coordinator, Mockito.never()).execInternal();
                }
            } finally {
                coordinator.close();
            }
            Mockito.verify(queue).releaseAndNotify(token);
            Mockito.verify(scans.get(0)).stop();
        } finally {
            Config.enable_workload_group = workloadEnabled;
            Config.enable_query_queue = queueEnabled;
        }
    }

    private static void setField(Object target, Class<?> owner, String name, Object value) throws Exception {
        Field field = owner.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }
}
