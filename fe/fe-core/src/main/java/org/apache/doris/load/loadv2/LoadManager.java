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

package org.apache.doris.load.loadv2;

import org.apache.doris.analysis.UserIdentity;
import org.apache.doris.catalog.Database;
import org.apache.doris.catalog.DatabaseIf;
import org.apache.doris.catalog.Env;
import org.apache.doris.common.AnalysisException;
import org.apache.doris.common.CaseSensibility;
import org.apache.doris.common.Config;
import org.apache.doris.common.DdlException;
import org.apache.doris.common.LabelAlreadyUsedException;
import org.apache.doris.common.MetaNotFoundException;
import org.apache.doris.common.Pair;
import org.apache.doris.common.PatternMatcher;
import org.apache.doris.common.PatternMatcherWrapper;
import org.apache.doris.common.io.Writable;
import org.apache.doris.common.util.LogBuilder;
import org.apache.doris.common.util.LogKey;
import org.apache.doris.datasource.InternalCatalog;
import org.apache.doris.load.EtlJobType;
import org.apache.doris.load.FailMsg;
import org.apache.doris.mysql.privilege.PrivPredicate;
import org.apache.doris.nereids.trees.expressions.And;
import org.apache.doris.nereids.trees.expressions.Expression;
import org.apache.doris.nereids.trees.plans.commands.LoadCommand;
import org.apache.doris.persist.CleanLabelOperationLog;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.qe.OriginStatement;
import org.apache.doris.qe.StmtExecutor;
import org.apache.doris.thrift.TPipelineWorkloadGroup;
import org.apache.doris.thrift.TUniqueId;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.StopWatch;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Deque;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * The broker and mini load jobs(v2) are included in this class.
 * The lock sequence:
 * Database.lock
 * LoadManager.lock
 * LoadJob.lock
 */
public class LoadManager implements Writable {
    private static final Logger LOG = LogManager.getLogger(LoadManager.class);

    protected Map<Long, LoadJob> idToLoadJob = Maps.newConcurrentMap();
    protected Map<Long, Map<String, List<LoadJob>>> dbIdToLabelToLoadJobs = Maps.newConcurrentMap();
    protected LoadJobScheduler loadJobScheduler;

    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private MysqlLoadManager mysqlLoadManager;

    public LoadManager(LoadJobScheduler loadJobScheduler) {
        this.loadJobScheduler = loadJobScheduler;
        this.mysqlLoadManager = new MysqlLoadManager();
    }

    public void start() {
        mysqlLoadManager.start();
    }

    public long createLoadJobFromCommand(LoadCommand command, StmtExecutor executor, ConnectContext ctx)
            throws Exception {
        List<TPipelineWorkloadGroup> twgList = null;
        if (Config.enable_workload_group) {
            try {
                twgList = Env.getCurrentEnv().getWorkloadGroupMgr().getWorkloadGroup(ConnectContext.get())
                        .stream()
                        .map(e -> e.toThrift())
                        .collect(Collectors.toList());
            } catch (Throwable t) {
                LOG.info("Get workload group failed when create load job,", t);
                throw t;
            }
        }

        Database database = checkDb(command.getLabel().getDbName());
        long dbId = database.getId();
        LoadJob loadJob;
        writeLock();
        try {
            checkLabelUsed(dbId, command.getLabel().getLabelName());
            if (command.getBrokerDesc() == null && command.getResourceDesc() == null) {
                throw new DdlException("LoadManager only support the broker and spark load.");
            }
            if (unprotectedGetUnfinishedJobNum() >= Config.desired_max_waiting_jobs) {
                throw new DdlException(
                    "There are more than " + Config.desired_max_waiting_jobs
                        + " unfinished load jobs, please retry later. "
                        + "You can use `SHOW LOAD` to view submitted jobs");
            }

            loadJob = BulkLoadJob.fromLoadCommand(command, executor, ctx);

            if (twgList != null) {
                loadJob.settWorkloadGroups(twgList);
            }

            createLoadJob(loadJob);
        } finally {
            writeUnlock();
        }

        Env.getCurrentEnv().getEditLog().logCreateLoadJob(loadJob);

        // The job must be submitted after edit log.
        // It guarantees that load job has not been changed before edit log.
        loadJobScheduler.submitJob(loadJob);
        return loadJob.getId();
    }

    private long unprotectedGetUnfinishedJobNum() {
        return idToLoadJob.values().stream()
                .filter(j -> (j.getJobType() != EtlJobType.INSERT
                                && j.getState() != JobState.FINISHED
                                && j.getState() != JobState.CANCELLED)).count();
    }

    public MysqlLoadManager getMysqlLoadManager() {
        return mysqlLoadManager;
    }

    public void replayCreateLoadJob(LoadJob loadJob) {
        createLoadJob(loadJob);
        LOG.info(new LogBuilder(LogKey.LOAD_JOB, loadJob.getId()).add("msg", "replay create load job").build());
    }

    // add load job and also add to callback factory
    protected void createLoadJob(LoadJob loadJob) {
        if (loadJob.isExpired(System.currentTimeMillis())) {
            // This can happen in replay logic.
            return;
        }
        addLoadJob(loadJob);
        // add callback before txn if load job is uncompleted,
        // because callback will be performed on replay without txn begin
        // register txn state listener
        if (!loadJob.isCompleted()) {
            Env.getCurrentGlobalTransactionMgr().getCallbackFactory().addCallback(loadJob);
        }
    }

    public void addLoadJob(LoadJob loadJob) {
        // Insert label may be null in txn mode, we add txn insert job after success.
        if (loadJob.getLabel() != null) {
            idToLoadJob.put(loadJob.getId(), loadJob);
            // Insert jobs are added without the LoadManager lock. compute() runs atomically per database, so two jobs
            // cannot each create the label map of a database (one of them would be lost from the label index and from
            // SHOW LOAD), and a job is not added to a map that jobRemovedTrigger is dropping. The lists are
            // copy-on-write: readers holding only the read lock iterate them while jobs are added.
            dbIdToLabelToLoadJobs.compute(loadJob.getDbId(), (dbId, labelToLoadJobs) -> {
                if (labelToLoadJobs == null) {
                    labelToLoadJobs = new ConcurrentHashMap<>();
                }
                labelToLoadJobs.computeIfAbsent(loadJob.getLabel(), label -> new CopyOnWriteArrayList<>())
                        .add(loadJob);
                return labelToLoadJobs;
            });
        }
    }

    /**
     * Record finished load job by editLog.
     **/
    public void recordFinishedLoadJob(String label, long transactionId, String dbName, long tableId, EtlJobType jobType,
                                      long createTimestamp, String failMsg, String trackingUrl, String firstErrorMsg,
                                      UserIdentity userInfo, long jobId) throws MetaNotFoundException {

        // get db id
        Database db = Env.getCurrentInternalCatalog().getDbOrMetaException(dbName);

        LoadJob loadJob;
        // The label cleaner drops insert jobs that stayed PENDING too long while holding the write lock, so find and
        // finish the job under the same lock: either the cleaner has dropped it already and it is created again
        // below, or it is no longer PENDING when the cleaner looks at it.
        writeLock();
        try {
            loadJob = idToLoadJob.get(jobId);
            if (loadJob != null && LOG.isDebugEnabled()) {
                LOG.debug("recordFinishedLoadJob: reuse existing load job, jobId={}, label={}, dbId={}, jobType={}",
                        jobId, label, db.getId(), jobType);
            }
            if (loadJob instanceof InsertLoadJob) {
                ((InsertLoadJob) loadJob).setJobProperties(transactionId, tableId, createTimestamp,
                        failMsg, trackingUrl, firstErrorMsg, userInfo);
            }
        } finally {
            writeUnlock();
        }
        if (loadJob == null) {
            // The jobId received here does not exist in idToLoadJob. This means the InsertLoadJob
            // that was registered during executor construction (and that accumulated BE-reported
            // load statistics via updateJobProgress) is NOT the one we are about to snapshot here.
            // A brand-new InsertLoadJob will be created below with an empty LoadStatistic, so
            // SHOW LOAD's JobDetails (ScannedRows / LoadBytes / All backends) will be all zero.
            // Logging this at WARN so CI failures of the form
            // "test_insert_statistic: expected:<N> but was:<0>" can be diagnosed directly.
            LOG.warn("recordFinishedLoadJob: jobId={} not found in idToLoadJob, creating a new "
                            + "{} load job for label={}, dbId={}. JobDetails statistics will be empty.",
                    jobId, jobType, label, db.getId());
            switch (jobType) {
                case INSERT:
                    // a new job gets a new id, which may write the edit log, so create it outside the lock
                    loadJob = new InsertLoadJob(label, transactionId, db.getId(), tableId, createTimestamp, failMsg,
                            trackingUrl, firstErrorMsg, userInfo);
                    break;
                default:
                    return;
            }
            writeLock();
            try {
                addLoadJob(loadJob);
            } finally {
                writeUnlock();
            }
        }
        // persistent
        Env.getCurrentEnv().getEditLog().logCreateLoadJob(loadJob);
    }

    /**
     * Match need cancel loadJob by stmt.
     **/
    @VisibleForTesting
    public static void addNeedCancelLoadJob(String label, String state, Expression operator,
                                            List<LoadJob> loadJobs, List<LoadJob> matchLoadJobs)
            throws AnalysisException {
        PatternMatcher matcher = PatternMatcherWrapper.createMysqlPattern(label,
                CaseSensibility.LABEL.getCaseSensibility());
        matchLoadJobs.addAll(
                loadJobs.stream()
                        .filter(job -> job.getState() != JobState.CANCELLED)
                        .filter(job -> {
                            if (operator != null) {
                                // compound
                                boolean labelFilter =
                                        label.contains("%") ? matcher.match(job.getLabel())
                                                : job.getLabel().equalsIgnoreCase(label);
                                boolean stateFilter = job.getState().name().equalsIgnoreCase(state);
                                return operator instanceof And ? labelFilter && stateFilter :
                                        labelFilter || stateFilter;
                            }
                            if (StringUtils.isNotEmpty(label)) {
                                return label.contains("%") ? matcher.match(job.getLabel())
                                        : job.getLabel().equalsIgnoreCase(label);
                            }
                            if (StringUtils.isNotEmpty(state)) {
                                return job.getState().name().equalsIgnoreCase(state);
                            }
                            return false;
                        }).collect(Collectors.toList())
        );
    }

    /**
     * Cancel load job by stmt.
     **/
    public void cancelLoadJob(String dbName, String label, String state, Expression operator)
            throws DdlException, AnalysisException {
        Database db = Env.getCurrentInternalCatalog().getDbOrDdlException(dbName);
        // List of load jobs waiting to be cancelled
        List<LoadJob> unfinishedLoadJob;
        readLock();
        try {
            Map<String, List<LoadJob>> labelToLoadJobs = dbIdToLabelToLoadJobs.get(db.getId());
            if (labelToLoadJobs == null) {
                throw new DdlException("Load job does not exist");
            }
            List<LoadJob> matchLoadJobs = Lists.newArrayList();
            addNeedCancelLoadJob(label, state, operator,
                    labelToLoadJobs.values().stream().flatMap(Collection::stream).collect(Collectors.toList()),
                    matchLoadJobs);
            if (matchLoadJobs.isEmpty()) {
                throw new DdlException("Load job does not exist");
            }
            // check state here
            unfinishedLoadJob =
                    matchLoadJobs.stream().filter(entity -> !entity.isTxnDone()).collect(Collectors.toList());
            if (unfinishedLoadJob.isEmpty()) {
                throw new DdlException("There is no uncompleted job");
            }
        } finally {
            readUnlock();
        }
        for (LoadJob loadJob : unfinishedLoadJob) {
            try {
                loadJob.cancelJob(new FailMsg(FailMsg.CancelType.USER_CANCEL, "user cancel"));
            } catch (DdlException e) {
                throw new DdlException(
                        "Cancel load job [" + loadJob.getId() + "] fail, " + "label=[" + loadJob.getLabel()
                                +
                                "] failed msg=" + e.getMessage());
            }
        }
    }

    /**
     * Replay end load job.
     **/
    public void replayEndLoadJob(LoadJobFinalOperation operation) {
        LoadJob job = idToLoadJob.get(operation.getId());
        if (job == null) {
            // This should not happen.
            // Last time I found that when user submit a job with already used label, an END_LOAD_JOB edit log
            // will be wrote but the job is not added to 'idToLoadJob', so this job here we got will be null.
            // And this bug has been fixed.
            // Just add a log here to observe.
            LOG.warn("job does not exist when replaying end load job edit log: {}", operation);
            return;
        }
        job.unprotectReadEndOperation(operation);
        LOG.info(new LogBuilder(LogKey.LOAD_JOB, operation.getId()).add("operation", operation)
                .add("msg", "replay end load job").build());

        Env.getCurrentGlobalTransactionMgr().getCallbackFactory().removeCallback(operation.getId());
        // When idToLoadJob size increase 10000 roughly, we run removeOldLoadJob to reduce mem used
        if ((idToLoadJob.size() > 0) && (idToLoadJob.size() % 10000 == 0)) {
            removeOldLoadJob();
        }
    }

    /**
     * Replay update load job.
     **/
    public void replayUpdateLoadJobStateInfo(LoadJob.LoadJobStateUpdateInfo info) {
        long jobId = info.getJobId();
        LoadJob job = idToLoadJob.get(jobId);
        if (job == null) {
            LOG.warn("replay update load job state failed. error: job not found, id: {}", jobId);
            return;
        }

        job.replayUpdateStateInfo(info);
    }

    /**
     * Get load job num, used by proc.
     **/
    public int getLoadJobNum(JobState jobState, long dbId) {
        readLock();
        try {
            Map<String, List<LoadJob>> labelToLoadJobs = dbIdToLabelToLoadJobs.get(dbId);
            if (labelToLoadJobs == null) {
                return 0;
            }
            List<LoadJob> loadJobList =
                    labelToLoadJobs.values().stream().flatMap(entity -> entity.stream()).collect(Collectors.toList());
            return (int) loadJobList.stream().filter(entity -> entity.getState() == jobState).count();
        } finally {
            readUnlock();
        }
    }

    /**
     * Get load job num, used by proc.
     **/
    public int getLoadJobNum(JobState jobState) {
        readLock();
        try {
            return (int) getLoadJobsOfVisibleDbs().stream().filter(entity -> entity.getState() == jobState).count();
        } finally {
            readUnlock();
        }
    }

    /**
     * Get load job num, used by metric.
     **/
    public Map<Pair<EtlJobType, JobState>, Long> getLoadJobNum() {
        // count into an array instead of grouping by a Pair per job, this runs over all jobs on every metric request
        EtlJobType[] jobTypes = EtlJobType.values();
        JobState[] jobStates = JobState.values();
        long[][] counts = new long[jobTypes.length][jobStates.length];
        for (LoadJob loadJob : idToLoadJob.values()) {
            EtlJobType jobType = loadJob.getJobType();
            JobState jobState = loadJob.getState();
            if (jobType != null && jobState != null) {
                counts[jobType.ordinal()][jobState.ordinal()]++;
            }
        }
        Map<Pair<EtlJobType, JobState>, Long> loadJobNum = new HashMap<>();
        for (int i = 0; i < jobTypes.length; i++) {
            for (int j = 0; j < jobStates.length; j++) {
                if (counts[i][j] > 0) {
                    loadJobNum.put(Pair.of(jobTypes[i], jobStates[j]), counts[i][j]);
                }
            }
        }
        return loadJobNum;
    }

    /**
     * Remove old load job.
     **/
    public void removeOldLoadJob() {
        long currentTimeMs = System.currentTimeMillis();
        AtomicLong abandonedInsertJobNum = new AtomicLong();
        removeLoadJobIf(job -> {
            if (job.isExpired(currentTimeMs)) {
                return true;
            }
            if (isAbandonedInsertJob(job, currentTimeMs)) {
                abandonedInsertJobNum.incrementAndGet();
                return true;
            }
            return false;
        });
        if (abandonedInsertJobNum.get() > 0) {
            LOG.warn("removed {} insert load jobs that stayed PENDING for more than {} seconds",
                    abandonedInsertJobNum.get(), Config.label_keep_max_second);
        }
    }

    /**
     * An insert load job is registered in PENDING state when the insert is planned, and only the executor that
     * planned it moves it to FINISHED or CANCELLED. If that executor never finishes the job (for example the
     * insert is empty, or beginning the transaction fails), the job stays PENDING forever: it is never expired
     * and never journaled. Drop such jobs once they are older than label_keep_max_second.
     */
    private static boolean isAbandonedInsertJob(LoadJob job, long currentTimeMs) {
        return job instanceof InsertLoadJob
                && job.getState() == JobState.PENDING
                && (currentTimeMs - job.getCreateTimestamp()) / 1000 > Config.label_keep_max_second;
    }

    /**
     * Remove completed jobs if total job num exceed Config.label_num_threshold
     */
    public void removeOverLimitLoadJob() {
        if (Config.label_num_threshold < 0 || idToLoadJob.size() <= Config.label_num_threshold) {
            return;
        }
        writeLock();
        try {
            Deque<LoadJob> finishedJobs = idToLoadJob
                    .values()
                    .stream()
                    .filter(LoadJob::isCompleted)
                    .sorted(Comparator.comparingLong(o -> o.finishTimestamp))
                    .collect(Collectors.toCollection(ArrayDeque::new));
            while (!finishedJobs.isEmpty()
                    && idToLoadJob.size() > Config.label_num_threshold) {
                LoadJob loadJob = finishedJobs.pollFirst();
                idToLoadJob.remove(loadJob.getId());
                jobRemovedTrigger(loadJob);
            }
        } finally {
            writeUnlock();
        }
    }

    private void jobRemovedTrigger(LoadJob job) {
        if (job instanceof BulkLoadJob) {
            ((BulkLoadJob) job).recycleProgress();
        }
        // atomically per database, see addLoadJob
        dbIdToLabelToLoadJobs.computeIfPresent(job.getDbId(), (dbId, labelToLoadJobs) -> {
            List<LoadJob> jobs = labelToLoadJobs.get(job.getLabel());
            if (jobs != null) {
                jobs.remove(job);
                if (jobs.isEmpty()) {
                    labelToLoadJobs.remove(job.getLabel());
                }
            }
            return labelToLoadJobs.isEmpty() ? null : labelToLoadJobs;
        });
    }

    private void removeLoadJobIf(Predicate<LoadJob> pred) {
        long removeJobNum = 0;
        StopWatch stopWatch = StopWatch.createStarted();
        writeLock();
        try {
            Iterator<Map.Entry<Long, LoadJob>> iter = idToLoadJob.entrySet().iterator();
            while (iter.hasNext()) {
                LoadJob job = iter.next().getValue();
                if (pred.test(job)) {
                    iter.remove();
                    jobRemovedTrigger(job);
                    removeJobNum++;
                }
            }
        } finally {
            writeUnlock();
            stopWatch.stop();
            LOG.info("end to removeOldLoadJob, removeJobNum:{} cost:{} ms",
                    removeJobNum, stopWatch.getTime());
        }
    }

    public List<Pair<Long, String>> getCreateLoadStmt(long dbId, String label) throws DdlException {
        List<Pair<Long, String>> result = new ArrayList<>();
        readLock();
        try {
            if (dbIdToLabelToLoadJobs.containsKey(dbId)) {
                Map<String, List<LoadJob>> labelToLoadJobs = dbIdToLabelToLoadJobs.get(dbId);
                if (labelToLoadJobs.containsKey(label)) {
                    List<LoadJob> labelLoadJobs = labelToLoadJobs.get(label);
                    for (LoadJob job : labelLoadJobs) {
                        try {
                            Method getOriginStmt = job.getClass().getMethod("getOriginStmt");
                            if (getOriginStmt != null) {
                                result.add(
                                        Pair.of(job.getId(), ((OriginStatement) getOriginStmt.invoke(job)).originStmt));
                            } else {
                                throw new DdlException("Not support load job type: " + job.getClass().getName());
                            }
                        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
                            throw new DdlException("Not support load job type: " + job.getClass().getName());
                        }
                    }
                } else {
                    throw new DdlException("Label does not exist: " + label);
                }
            } else {
                // If dbId is not found in dbIdToLabelToLoadJobs,
                // it means the database has no label records,
                // so throw a "Label does not exist" error.
                throw new DdlException("Label does not exist: " + label);
            }
            return result;
        } finally {
            readUnlock();
        }
    }

    /**
     * This method will return the jobs info which can meet the condition of input param.
     *
     * @param dbId          used to filter jobs which belong to this db
     * @param labelValue    used to filter jobs which's label is or like labelValue.
     * @param accurateMatch true: filter jobs which's label is labelValue. false: filter jobs which's label like itself.
     * @param statesValue   used to filter jobs which's state within the statesValue set.
     * @return The result is the list of jobInfo.
     * JobInfo is a list which includes the comparable object: jobId, label, state etc.
     * The result is unordered.
     */
    public List<List<Comparable>> getLoadJobInfosByDb(long dbId, String labelValue, boolean accurateMatch,
                                                      Set<String> statesValue) throws AnalysisException {
        LinkedList<List<Comparable>> loadJobInfos = new LinkedList<List<Comparable>>();
        if (!dbIdToLabelToLoadJobs.containsKey(dbId)) {
            return loadJobInfos;
        }

        Set<JobState> states = Sets.newHashSet();
        if (statesValue == null || statesValue.size() == 0) {
            states.addAll(EnumSet.allOf(JobState.class));
        } else {
            for (String stateValue : statesValue) {
                try {
                    states.add(JobState.valueOf(stateValue));
                } catch (IllegalArgumentException e) {
                    // ignore this state
                }
            }
        }

        readLock();
        try {
            Map<String, List<LoadJob>> labelToLoadJobs = dbIdToLabelToLoadJobs.get(dbId);
            if (labelToLoadJobs == null) {
                // the cleaner removed the last jobs of the database after the check above
                return loadJobInfos;
            }
            List<LoadJob> loadJobList = Lists.newArrayList();
            if (Strings.isNullOrEmpty(labelValue)) {
                loadJobList.addAll(
                        labelToLoadJobs.values().stream().flatMap(Collection::stream).collect(Collectors.toList()));
            } else {
                // check label value
                if (accurateMatch) {
                    if (!labelToLoadJobs.containsKey(labelValue)) {
                        return loadJobInfos;
                    }
                    loadJobList.addAll(labelToLoadJobs.get(labelValue));
                } else {
                    // non-accurate match
                    PatternMatcher matcher =
                            PatternMatcherWrapper.createMysqlPattern(labelValue,
                                    CaseSensibility.LABEL.getCaseSensibility());
                    for (Map.Entry<String, List<LoadJob>> entry : labelToLoadJobs.entrySet()) {
                        if (matcher.match(entry.getKey())) {
                            loadJobList.addAll(entry.getValue());
                        }
                    }
                }
            }

            // check state
            for (LoadJob loadJob : loadJobList) {
                try {
                    if (!states.contains(loadJob.getState())) {
                        continue;
                    }
                    // check auth
                    try {
                        loadJob.checkAuth("show load");
                    } catch (DdlException e) {
                        continue;
                    }
                    // add load job info
                    loadJobInfos.add(loadJob.getShowInfo());
                } catch (RuntimeException | DdlException e) {
                    // ignore this load job
                    LOG.warn("get load job info failed. job id: {}", loadJob.getId(), e);
                }
            }
            return loadJobInfos;
        } finally {
            readUnlock();
        }
    }

    public List<List<Comparable>> getAllLoadJobInfos() {
        LinkedList<List<Comparable>> loadJobInfos = new LinkedList<List<Comparable>>();

        readLock();
        try {
            List<LoadJob> loadJobList = getLoadJobsOfVisibleDbs();

            // check state
            for (LoadJob loadJob : loadJobList) {
                try {
                    // add load job info
                    loadJobInfos.add(loadJob.getShowInfo());
                } catch (DdlException e) {
                    continue;
                }
            }
            return loadJobInfos;
        } finally {
            readUnlock();
        }
    }

    public LoadJob getLoadJob(long jobId) {
        return idToLoadJob.get(jobId);
    }

    public List<LoadJob> queryLoadJobsByJobIds(List<Long> jobIds) {
        if (CollectionUtils.isEmpty(jobIds)) {
            return new ArrayList<>();
        }
        List<LoadJob> jobs = new ArrayList<>();
        jobIds.forEach(id -> {
            // look up once, the label cleaner may remove the job in between
            LoadJob job = idToLoadJob.get(id);
            if (job != null) {
                jobs.add(job);
            }
        });
        return jobs;
    }

    public void prepareJobs() {
        analyzeLoadJobs();
        submitJobs();
    }

    private void submitJobs() {
        loadJobScheduler.submitJob(idToLoadJob.values().stream().filter(loadJob -> loadJob.state == JobState.PENDING)
                .collect(Collectors.toList()));
    }

    private void analyzeLoadJobs() {
        for (LoadJob loadJob : idToLoadJob.values()) {
            if (loadJob.getState() == JobState.PENDING) {
                loadJob.analyze();
            }
        }
    }

    protected Database checkDb(String dbName) throws DdlException {
        return Env.getCurrentInternalCatalog().getDbOrDdlException(dbName);
    }

    /**
     * step1: if label has been used in load jobs.
     * step2: if label has been user in load jobs, the create_timestamp will be checked.
     *
     * @throws LabelAlreadyUsedException throw exception when label has been used by an unfinished job.
     */
    private void checkLabelUsed(long dbId, String label) throws DdlException {
        if (dbIdToLabelToLoadJobs.containsKey(dbId)) {
            Map<String, List<LoadJob>> labelToLoadJobs = dbIdToLabelToLoadJobs.get(dbId);
            if (labelToLoadJobs.containsKey(label)) {
                List<LoadJob> labelLoadJobs = labelToLoadJobs.get(label);
                Optional<LoadJob> loadJobOptional = labelLoadJobs.stream()
                        .filter(entity -> entity.getState() != JobState.CANCELLED).findFirst();
                if (loadJobOptional.isPresent()) {
                    LOG.warn("Failed to add load job when label {} has been used.", label);
                    throw new LabelAlreadyUsedException(label);
                }
            }
        }
    }

    public void cleanLabel(String dbName, String label) throws DdlException {
        Database db = Env.getCurrentInternalCatalog().getDbOrDdlException(dbName);
        cleanLabelInternal(db.getId(), label, false);
    }

    public void replayCleanLabel(CleanLabelOperationLog log) {
        cleanLabelInternal(log.getDbId(), log.getLabel(), true);
    }

    /**
     * Clean the label with given database and label
     * It will only remove the load jobs which are already done.
     * 1. Remove from LoadManager
     * 2. Remove from DatabaseTransactionMgr
     *
     * @param dbId
     * @param label
     * @param isReplay
     */
    private void cleanLabelInternal(long dbId, String label, boolean isReplay) {
        // 1. Remove from LoadManager
        AtomicLong counter = new AtomicLong();
        writeLock();
        try {
            // atomically per database, see addLoadJob
            dbIdToLabelToLoadJobs.computeIfPresent(dbId, (id, labelToJob) -> {
                if (Strings.isNullOrEmpty(label)) {
                    // clean all labels in this db
                    for (List<LoadJob> jobs : labelToJob.values()) {
                        counter.addAndGet(removeCompletedJobs(jobs));
                    }
                    labelToJob.values().removeIf(List::isEmpty);
                } else {
                    List<LoadJob> jobs = labelToJob.get(label);
                    if (jobs != null) {
                        // stream load labelToJob is null
                        counter.addAndGet(removeCompletedJobs(jobs));
                        if (jobs.isEmpty()) {
                            labelToJob.remove(label);
                        }
                    }
                }
                return labelToJob;
            });
        } finally {
            writeUnlock();
        }
        // 2. Remove from DatabaseTransactionMgr
        try {
            Env.getCurrentGlobalTransactionMgr().cleanLabel(dbId, label, isReplay);
        } catch (Exception e) {
            // just ignore, because we don't want to throw any exception here.
            LOG.warn("Exception:", e);
        }

        LOG.info("finished to clean {} labels on db {} with label '{}' in load mgr. is replay: {}",
                counter.get(), dbId, label, isReplay);
    }

    // remove the completed jobs of one label from the label index and idToLoadJob, return how many
    private int removeCompletedJobs(List<LoadJob> jobs) {
        int removed = 0;
        // a snapshot, the list is copy-on-write
        for (LoadJob job : jobs) {
            if (!job.isCompleted()) {
                continue;
            }
            if (job instanceof BulkLoadJob) {
                ((BulkLoadJob) job).recycleProgress();
            }
            jobs.remove(job);
            idToLoadJob.remove(job.getId());
            ++removed;
        }
        return removed;
    }

    // jobs of all databases the current user may see, for the procs that show all of them; a database dropped while
    // its jobs are still kept is skipped
    private List<LoadJob> getLoadJobsOfVisibleDbs() {
        List<LoadJob> loadJobs = Lists.newArrayList();
        for (Map.Entry<Long, Map<String, List<LoadJob>>> entry : dbIdToLabelToLoadJobs.entrySet()) {
            DatabaseIf db = Env.getCurrentEnv().getCatalogMgr().getDbNullable(entry.getKey());
            if (db == null || !Env.getCurrentEnv().getAccessManager().checkDbPriv(ConnectContext.get(),
                    InternalCatalog.INTERNAL_CATALOG_NAME, db.getFullName(), PrivPredicate.LOAD)) {
                continue;
            }
            // not merged by label: the same label can be used in several databases
            entry.getValue().values().forEach(loadJobs::addAll);
        }
        return loadJobs;
    }

    protected void readLock() {
        lock.readLock().lock();
    }

    protected void readUnlock() {
        lock.readLock().unlock();
    }

    protected void writeLock() {
        lock.writeLock().lock();
    }

    protected void writeUnlock() {
        lock.writeLock().unlock();
    }

    /**
     * Init.
     **/
    public void initJobProgress(Long jobId, TUniqueId loadId, Set<TUniqueId> fragmentIds,
                                List<Long> relatedBackendIds) {
        LoadJob job = idToLoadJob.get(jobId);
        if (job != null) {
            job.initLoadProgress(loadId, fragmentIds, relatedBackendIds);
        }
    }

    /**
     * Update.
     **/
    public void updateJobProgress(Long jobId, Long beId, TUniqueId loadId, TUniqueId fragmentId, long scannedRows,
                                  long scannedBytes, boolean isDone) {
        LoadJob job = idToLoadJob.get(jobId);
        if (LOG.isDebugEnabled()) {
            LOG.debug("updateJobProgress: jobId={}, beId={}, scannedRows={}, scannedBytes={}, isDone={}, "
                            + "found={}, jobIdMatched={}",
                    jobId, beId, scannedRows, scannedBytes, isDone,
                    idToLoadJob.containsKey(jobId), job == null ? -1L : job.getId());
        }
        if (job != null) {
            job.updateProgress(beId, loadId, fragmentId, scannedRows, scannedBytes, isDone);
        }
    }

    @Override
    public void write(DataOutput out) throws IOException {
        long currentTimeMs = System.currentTimeMillis();
        List<LoadJob> loadJobs =
                idToLoadJob.values().stream().filter(t -> !t.isExpired(currentTimeMs))
                        .collect(Collectors.toList());

        LOG.info("write load job size: {}", loadJobs.size());
        out.writeInt(loadJobs.size());
        for (LoadJob loadJob : loadJobs) {
            LOG.info("write load job: {}", loadJob.getId());
            loadJob.write(out);
        }
    }

    /**
     * Read from file.
     **/
    public void readFields(DataInput in) throws IOException {
        long currentTimeMs = System.currentTimeMillis();
        int size = in.readInt();
        LOG.info("load job num {} ", size);
        for (int i = 0; i < size; i++) {
            LoadJob loadJob = LoadJob.read(in);
            if (loadJob.isExpired(currentTimeMs)) {
                continue;
            }
            idToLoadJob.put(loadJob.getId(), loadJob);
            Map<String, List<LoadJob>> map = dbIdToLabelToLoadJobs.get(loadJob.getDbId());
            if (map == null) {
                map = Maps.newConcurrentMap();
                dbIdToLabelToLoadJobs.put(loadJob.getDbId(), map);
            }

            List<LoadJob> jobs = map.get(loadJob.getLabel());
            if (jobs == null) {
                // copy-on-write like the lists created by addLoadJob
                jobs = new CopyOnWriteArrayList<>();
                map.put(loadJob.getLabel(), jobs);
            }
            jobs.add(loadJob);
            // The callback of load job which is replayed by image need to be registered in callback factory.
            // The commit and visible txn will callback the unfinished load job.
            // Otherwise, the load job always does not be completed while the txn is visible.
            if (!loadJob.isCompleted()) {
                Env.getCurrentGlobalTransactionMgr().getCallbackFactory().addCallback(loadJob);
            }
        }
    }
}
