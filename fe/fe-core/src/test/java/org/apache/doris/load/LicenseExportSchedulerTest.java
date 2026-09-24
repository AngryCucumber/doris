// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.load;

import org.apache.doris.analysis.StatementBase;
import org.apache.doris.catalog.Env;
import org.apache.doris.common.CustomThreadFactory;
import org.apache.doris.common.util.BrokerUtil;
import org.apache.doris.massdb.license.LicenseManager;
import org.apache.doris.massdb.license.LicenseQueryStatus;
import org.apache.doris.persist.EditLog;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.scheduler.disruptor.TaskDisruptor;
import org.apache.doris.scheduler.exception.JobException;
import org.apache.doris.scheduler.executor.TransientTaskExecutor;
import org.apache.doris.scheduler.manager.TransientTaskManager;

import com.lmax.disruptor.dsl.Disruptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

/** Real queue, task handler and export state transitions; no RPC or filesystem operation is performed. */
class LicenseExportSchedulerTest {
    @Test
    void submittedExportWaitsInRealSchedulerAndExpiresBeforeItsFirstExecution() throws Exception {
        AtomicReference<LicenseQueryStatus> status = new AtomicReference<>(LicenseQueryStatus.VALID);
        AtomicReference<Throwable> workerFailure = new AtomicReference<>();
        List<Thread> workers = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch release = new CountDownLatch(1);
        TransientTaskManager tasks = new TransientTaskManager();
        TaskDisruptor scheduler = (TaskDisruptor) field(tasks, TransientTaskManager.class, "disruptor");
        // These product settings are captured in static final fields. Never mutate them or assume test ordering.
        int consumers = (Integer) field(null, TaskDisruptor.class, "consumerThreadCount");
        int capacity = (Integer) field(null, TaskDisruptor.class, "DEFAULT_RING_BUFFER_SIZE");
        Assertions.assertTrue(consumers > 0 && consumers <= 128, "Bound the test's owned worker count");
        Assertions.assertTrue(capacity > consumers + 2, "Queue must hold blockers and the export event");
        CountDownLatch occupied = new CountDownLatch(consumers);
        Env env = Mockito.mock(Env.class);
        LicenseManager license = Mockito.mock(LicenseManager.class);
        EditLog journal = Mockito.mock(EditLog.class);
        Mockito.when(env.getLicenseManager()).thenReturn(license);
        Mockito.when(license.queryStatus()).thenAnswer(call -> status.get());
        Mockito.when(env.getTransientTaskManager()).thenReturn(tasks);
        Mockito.when(env.getEditLog()).thenReturn(journal);

        ExportMgr exports = new ExportMgr();
        ExportJob job = new ExportJob(2601L);
        setField(job, ExportJob.class, "dbId", 2602L);
        setField(job, ExportJob.class, "label", "owned_license_export_queue");
        setField(job, ExportJob.class, "exportPath", "s3://owned-license-export/part");
        setField(job, ExportJob.class, "deleteExistingFiles", "true");
        StatementBase statement = Mockito.mock(StatementBase.class);
        ExportTaskExecutor task = Mockito.spy(new ExportTaskExecutor(Optional.of(statement), job));
        CountDownLatch completed = new CountDownLatch(1);
        Mockito.doAnswer(call -> {
            try {
                return call.callRealMethod();
            } finally {
                completed.countDown();
            }
        }).when(task).execute();
        setField(job, ExportJob.class, "jobExecutorList", new ArrayList<>(Collections.singletonList(task)));
        List<TransientTaskExecutor> blockers = new ArrayList<>();

        try (MockedStatic<Env> current = environment(env);
                MockedStatic<BrokerUtil> broker = Mockito.mockStatic(BrokerUtil.class);
                MockedConstruction<CustomThreadFactory> factory = Mockito.mockConstruction(CustomThreadFactory.class,
                        (mock, context) -> Mockito.when(mock.newThread(Mockito.any())).thenAnswer(call -> {
                            Runnable consumer = call.getArgument(0);
                            Thread thread = new Thread(() -> {
                                // Mockito static scopes are thread local: each actual worker gets the same test env.
                                try (MockedStatic<Env> workerEnv = environment(env)) {
                                    consumer.run();
                                } catch (Throwable failure) {
                                    workerFailure.compareAndSet(null, failure);
                                } finally {
                                    ConnectContext.remove();
                                }
                            }, "license-export-queue-worker-" + workers.size());
                            thread.setDaemon(false);
                            workers.add(thread);
                            return thread;
                        }))) {
            try {
                tasks.start();
                Assertions.assertEquals(consumers, workers.size());
                for (int i = 0; i < consumers; i++) {
                    TransientTaskExecutor blocker = blocker(2700L + i, occupied, release);
                    blockers.add(blocker);
                    tasks.addMemoryTask(blocker);
                }
                Assertions.assertTrue(occupied.await(8, TimeUnit.SECONDS), "Every real worker must be occupied");
                Assertions.assertNull(workerFailure.get());

                exports.addExportJobAndRegisterTask(job);
                Assertions.assertEquals(Collections.singletonList(job), exports.getJobs());
                Assertions.assertEquals(ExportJobState.PENDING, job.getState());
                Assertions.assertSame(task, tasks.getMemoryTaskExecutor(task.getId()));
                Mockito.verify(journal).logExportCreate(job);
                Mockito.verify(task, Mockito.never()).execute();
                Mockito.verifyNoInteractions(statement);
                broker.verify(() -> BrokerUtil.deleteDirectoryWithFileSystem("s3://owned-license-export/", null));
                // Submission and its deletion are already real product control-flow side effects.
                // They are not rolled back or misrepresented as an expiry rejection before submission.
                status.set(LicenseQueryStatus.EXPIRED);
                release.countDown();
                Assertions.assertTrue(completed.await(5, TimeUnit.SECONDS), "Queued export must actually execute");
                awaitRemoved(tasks, task.getId(), 5000);
                for (TransientTaskExecutor blocker : blockers) {
                    awaitRemoved(tasks, blocker.getId(), 5000);
                }
                Assertions.assertEquals(ExportJobState.CANCELLED, job.getState());
                Assertions.assertEquals(ExportFailMsg.CancelType.RUN_FAIL, job.getFailMsg().getCancelType());
                Assertions.assertTrue(job.getFailMsg().getMsg().contains("LICENSE_EXPIRED"));
                Assertions.assertTrue(job.getCopiedTaskExecutors().isEmpty());
                Mockito.verify(task).execute();
                Mockito.verify(task).cancel();
                Mockito.verifyNoInteractions(statement);
                Mockito.verify(license, Mockito.times(2)).queryStatus();
                broker.verify(() -> BrokerUtil.deleteDirectoryWithFileSystem("s3://owned-license-export/", null),
                        Mockito.times(1));
                Assertions.assertNull(workerFailure.get());
            } finally {
                release.countDown();
                scheduler.close();
                // close() logs a timeout without halting. Always halt this test-owned ring and join its workers.
                Disruptor<?> ring = (Disruptor<?>) field(scheduler, TaskDisruptor.class, "disruptor");
                if (ring != null) {
                    ring.halt();
                }
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
                for (Thread worker : workers) {
                    long remaining = deadline - System.nanoTime();
                    if (remaining > 0) {
                        worker.join(Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining)));
                    }
                }
                Assertions.assertTrue(workers.stream().noneMatch(Thread::isAlive),
                        "Every owned non-daemon scheduler worker must terminate");
                Assertions.assertNull(workerFailure.get());
            }
        }
    }

    private static TransientTaskExecutor blocker(long id, CountDownLatch occupied, CountDownLatch release) {
        return new TransientTaskExecutor() {
            @Override
            public void execute() throws JobException {
                occupied.countDown();
                try {
                    if (!release.await(15, TimeUnit.SECONDS)) {
                        throw new JobException("Owned queue blocker timed out");
                    }
                } catch (InterruptedException failure) {
                    Thread.currentThread().interrupt();
                    throw new JobException(failure);
                }
            }

            @Override
            public void cancel() {
                release.countDown();
            }

            @Override
            public Long getId() {
                return id;
            }
        };
    }

    private static void awaitRemoved(TransientTaskManager tasks, long id, long timeoutMillis) {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        while (tasks.getMemoryTaskExecutor(id) != null && System.nanoTime() < deadline) {
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
        }
        Assertions.assertNull(tasks.getMemoryTaskExecutor(id), "Real task handler must remove its completed event");
    }

    private static MockedStatic<Env> environment(Env env) {
        MockedStatic<Env> scope = Mockito.mockStatic(Env.class);
        scope.when(Env::getCurrentEnv).thenReturn(env);
        return scope;
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
}
