// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.load;

import org.apache.doris.analysis.StatementBase;
import org.apache.doris.analysis.UserIdentity;
import org.apache.doris.catalog.Env;
import org.apache.doris.common.UserException;
import org.apache.doris.common.util.BrokerUtil;
import org.apache.doris.datasource.InternalCatalog;
import org.apache.doris.massdb.license.LicenseQueryGuard;
import org.apache.doris.massdb.license.LicenseSqlException;
import org.apache.doris.mysql.privilege.AccessControllerManager;
import org.apache.doris.nereids.trees.plans.commands.ExportCommand;
import org.apache.doris.persist.EditLog;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.scheduler.exception.JobException;
import org.apache.doris.scheduler.manager.TransientTaskManager;

import com.google.common.collect.ImmutableMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

class LicenseExportAdmissionTest {
    @AfterEach
    void clearContext() {
        ConnectContext.remove();
    }

    @Test
    void deniedSubmissionCannotRegisterJournalDeleteOrSchedule() throws Exception {
        ExportMgr manager = new ExportMgr();
        ExportJob job = job();
        Env env = Mockito.mock(Env.class);
        EditLog editLog = Mockito.mock(EditLog.class);
        TransientTaskManager tasks = Mockito.mock(TransientTaskManager.class);
        Mockito.when(env.getEditLog()).thenReturn(editLog);
        Mockito.when(env.getTransientTaskManager()).thenReturn(tasks);
        LicenseSqlException denied = denied();
        try (MockedStatic<Env> environment = Mockito.mockStatic(Env.class);
                MockedStatic<LicenseQueryGuard> guard = Mockito.mockStatic(LicenseQueryGuard.class);
                MockedStatic<BrokerUtil> broker = Mockito.mockStatic(BrokerUtil.class)) {
            environment.when(Env::getCurrentEnv).thenReturn(env);
            guard.when(LicenseQueryGuard::checkProtectedRead).thenThrow(denied);
            Assertions.assertSame(denied, Assertions.assertThrows(LicenseSqlException.class,
                    () -> manager.addExportJobAndRegisterTask(job)));
            Assertions.assertTrue(manager.getJobs().isEmpty());
            Mockito.verifyNoInteractions(editLog, tasks);
            broker.verifyNoInteractions();
            Mockito.verify(job, Mockito.never()).updateExportJobState(Mockito.any(), Mockito.anyLong(),
                    Mockito.any(), Mockito.any(), Mockito.any());
        }
    }

    @Test
    void acceptedSubmissionDoesNotAuthorizeAnExpiredQueuedTask() throws Exception {
        ExportMgr manager = new ExportMgr();
        ExportJob job = job();
        ExportTaskExecutor task = new ExportTaskExecutor(Optional.of(Mockito.mock(StatementBase.class)), job);
        Mockito.doReturn(Collections.singletonList(task)).when(job).getCopiedTaskExecutors();
        Env env = Mockito.mock(Env.class);
        EditLog editLog = Mockito.mock(EditLog.class);
        TransientTaskManager tasks = Mockito.mock(TransientTaskManager.class);
        Mockito.when(env.getEditLog()).thenReturn(editLog);
        Mockito.when(env.getTransientTaskManager()).thenReturn(tasks);
        AtomicBoolean valid = new AtomicBoolean(true);
        LicenseSqlException denied = denied();
        try (MockedStatic<Env> environment = Mockito.mockStatic(Env.class);
                MockedStatic<LicenseQueryGuard> guard = Mockito.mockStatic(LicenseQueryGuard.class);
                MockedStatic<BrokerUtil> broker = Mockito.mockStatic(BrokerUtil.class)) {
            environment.when(Env::getCurrentEnv).thenReturn(env);
            guard.when(LicenseQueryGuard::checkProtectedRead).thenAnswer(call -> {
                if (!valid.get()) {
                    throw denied;
                }
                return null;
            });
            manager.addExportJobAndRegisterTask(job);
            Assertions.assertEquals(1, manager.getJobs().size());
            Mockito.verify(editLog).logExportCreate(job);
            Mockito.verify(tasks).addMemoryTask(task);
            broker.verify(() -> BrokerUtil.deleteDirectoryWithFileSystem("s3://owned/export/", null));

            valid.set(false);
            JobException failure = Assertions.assertThrows(JobException.class, task::execute);
            Assertions.assertSame(denied, LicenseSqlException.find(failure));
            Mockito.verify(job).updateExportJobState(ExportJobState.CANCELLED, task.getId(), null,
                    ExportFailMsg.CancelType.RUN_FAIL, denied.getMessage());
            Mockito.verify(job, Mockito.never()).updateExportJobState(ExportJobState.EXPORTING, task.getId(),
                    null, null, null);
            Mockito.verify(job, Mockito.never()).getExportTable();
            // The successful submission's directory deletion is deliberately not rolled back.
            broker.verify(() -> BrokerUtil.deleteDirectoryWithFileSystem("s3://owned/export/", null), Mockito.times(1));
        }
    }

    @Test
    void cancelledTaskKeepsItsExistingCancellationBeforeAdmission() throws Exception {
        ExportJob job = job();
        ExportTaskExecutor task = new ExportTaskExecutor(Optional.empty(), job);
        task.cancel();
        try (MockedStatic<LicenseQueryGuard> guard = Mockito.mockStatic(LicenseQueryGuard.class)) {
            Assertions.assertThrows(JobException.class, task::execute);
            guard.verifyNoInteractions();
            Mockito.verifyNoInteractions(job);
        }
    }

    @Test
    void exportPermissionFailurePrecedesLicenseCheck() {
        Env env = Mockito.mock(Env.class);
        AccessControllerManager access = Mockito.mock(AccessControllerManager.class);
        Mockito.when(env.getAccessManager()).thenReturn(access);
        ConnectContext context = new ConnectContext();
        InternalCatalog catalog =
                Mockito.mock(InternalCatalog.class);
        Mockito.when(catalog.getName()).thenReturn("internal");
        Mockito.when(env.getInternalCatalog()).thenReturn(catalog);
        context.setEnv(env);
        context.setCurrentUserIdentity(UserIdentity.createAnalyzedUserIdentWithIp("reader", "%"));
        context.setThreadLocalInfo();
        ExportCommand command = new ExportCommand(Arrays.asList("internal", "db", "t"),
                Collections.emptyList(), Optional.empty(), "s3://owned/export/",
                Collections.emptyMap(), Optional.empty());
        try (MockedStatic<Env> environment = Mockito.mockStatic(Env.class);
                MockedStatic<LicenseQueryGuard> guard = Mockito.mockStatic(LicenseQueryGuard.class)) {
            environment.when(Env::getCurrentEnv).thenReturn(env);
            Throwable failure = Assertions.assertThrows(UserException.class, () -> command.run(context, null));
            Assertions.assertNull(LicenseSqlException.find(failure));
            guard.verifyNoInteractions();
            Mockito.verify(env, Mockito.never()).getExportMgr();
        }
    }

    private static ExportJob job() {
        ExportJob job = Mockito.mock(ExportJob.class);
        Mockito.when(job.getId()).thenReturn(11L);
        Mockito.when(job.getDbId()).thenReturn(7L);
        Mockito.when(job.getLabel()).thenReturn("owned_export");
        Mockito.when(job.getDeleteExistingFiles()).thenReturn("true");
        Mockito.when(job.getExportPath()).thenReturn("s3://owned/export/part");
        Mockito.when(job.getState()).thenReturn(ExportJobState.PENDING);
        return job;
    }

    private static LicenseSqlException denied() {
        return new LicenseSqlException(6200,
                ImmutableMap.of("reason", "LICENSE_EXPIRED", "message", "LICENSE_EXPIRED"));
    }
}
