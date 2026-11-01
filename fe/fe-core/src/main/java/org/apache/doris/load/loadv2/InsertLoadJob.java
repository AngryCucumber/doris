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
import org.apache.doris.catalog.AuthorizationInfo;
import org.apache.doris.catalog.Database;
import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.Table;
import org.apache.doris.catalog.TableIf;
import org.apache.doris.common.Config;
import org.apache.doris.common.MetaNotFoundException;
import org.apache.doris.load.EtlJobType;
import org.apache.doris.load.FailMsg;
import org.apache.doris.load.FailMsg.CancelType;

import com.google.common.base.Strings;
import com.google.common.collect.Sets;
import com.google.gson.annotations.SerializedName;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Set;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;

/**
 * The class is performed to record the finished info of insert load job.
 * It is created after txn is visible which belongs to insert load job.
 * The state of insert load job is always finished, so it will never be scheduled by JobScheduler.
 */
public class InsertLoadJob extends LoadJob {

    private static final Logger LOG = LogManager.getLogger(InsertLoadJob.class);

    @SerializedName("tid")
    private long tableId;

    private static final AtomicIntegerFieldUpdater<InsertLoadJob> ENDED_BY =
            AtomicIntegerFieldUpdater.newUpdater(InsertLoadJob.class, "endedBy");
    private static final int NOT_ENDED = 0;
    private static final int FINISHED_BY_EXECUTOR = 1;
    private static final int DROPPED_BY_CLEANER = 2;

    // Whether the executor finished the job or the label cleaner dropped it while it was still PENDING: whichever
    // sets it first wins, see dropIfAbandoned() and finishUnlessDropped(). Not persisted.
    private volatile int endedBy;

    // only for log replay
    public InsertLoadJob() {
        super(EtlJobType.INSERT);
    }

    public InsertLoadJob(long dbId, String label, long jobId) {
        super(EtlJobType.INSERT, dbId, label, jobId);
    }

    public InsertLoadJob(String label, long transactionId, long dbId, long tableId,
            long createTimestamp, String failMsg, String trackingUrl, String firstErrorMsg,
            UserIdentity userInfo) throws MetaNotFoundException {
        super(EtlJobType.INSERT, dbId, label);
        setJobProperties(transactionId, tableId, createTimestamp, failMsg, trackingUrl, firstErrorMsg, userInfo);
    }

    public InsertLoadJob(String label, long transactionId, long dbId, long tableId,
                         long createTimestamp, String failMsg, String trackingUrl, String firstErrorMsg,
                         UserIdentity userInfo, Long jobId) throws MetaNotFoundException {
        super(EtlJobType.INSERT, dbId, label, jobId);
        setJobProperties(transactionId, tableId, createTimestamp, failMsg, trackingUrl, firstErrorMsg, userInfo);
    }

    /**
     * Mark the job dropped if it stayed PENDING for more than label_keep_max_second: the executor that planned it
     * never finished it (for example the insert was empty, or beginning the transaction failed). Called by the label
     * cleaner, which then removes the job. An executor finishing the job at the same time either finishes it first,
     * and the job is kept, or finds it dropped and records a new job, see LoadManager.recordFinishedLoadJob().
     */
    public boolean dropIfAbandoned(long currentTimeMs) {
        // no lock: the cleaner never waits for a job, a job only ever leaves PENDING; asking again for a dropped job
        // still says dropped
        return isAbandoned(currentTimeMs) && (ENDED_BY.compareAndSet(this, NOT_ENDED, DROPPED_BY_CLEANER)
                || endedBy == DROPPED_BY_CLEANER);
    }

    private boolean isAbandoned(long currentTimeMs) {
        return state == JobState.PENDING && (currentTimeMs - createTimestamp) / 1000 > Config.label_keep_max_second;
    }

    /**
     * Finish the job with these properties, unless the label cleaner dropped it, see dropIfAbandoned().
     *
     * @return false if the job was dropped and not changed
     */
    public boolean finishUnlessDropped(long transactionId, long tableId, long createTimestamp, String failMsg,
            String trackingUrl, String firstErrorMsg, UserIdentity userInfo) throws MetaNotFoundException {
        if (!ENDED_BY.compareAndSet(this, NOT_ENDED, FINISHED_BY_EXECUTOR) && endedBy == DROPPED_BY_CLEANER) {
            return false;
        }
        // under the job's lock, so that SHOW LOAD sees the properties of the finished job together
        writeLock();
        try {
            setJobProperties(transactionId, tableId, createTimestamp, failMsg, trackingUrl, firstErrorMsg, userInfo);
        } finally {
            writeUnlock();
        }
        return true;
    }

    public void setJobProperties(long transactionId, long tableId, long createTimestamp,
                                        String failMsg, String trackingUrl, String firstErrorMsg,
                                        UserIdentity userInfo) throws MetaNotFoundException {
        this.tableId = tableId;
        this.transactionId = transactionId;
        this.createTimestamp = createTimestamp;
        this.loadStartTimestamp = createTimestamp;
        this.finishTimestamp = System.currentTimeMillis();
        if (Strings.isNullOrEmpty(failMsg)) {
            this.state = JobState.FINISHED;
            this.progress = 100;
        } else {
            this.state = JobState.CANCELLED;
            this.failMsg = new FailMsg(CancelType.LOAD_RUN_FAIL, failMsg);
            this.progress = 0;
        }
        this.authorizationInfo = gatherAuthInfo();
        this.loadingStatus.setTrackingUrl(trackingUrl);
        this.loadingStatus.setFirstErrorMsg(firstErrorMsg);
        this.userInfo = userInfo;
    }

    public AuthorizationInfo gatherAuthInfo() throws MetaNotFoundException {
        Database database = Env.getCurrentInternalCatalog().getDbOrMetaException(dbId);
        return new AuthorizationInfo(database.getFullName(), getTableNames());
    }

    @Override
    public Set<String> getTableNamesForShow() {
        String name = Env.getCurrentInternalCatalog().getDb(dbId).flatMap(db -> db.getTable(tableId))
                .map(TableIf::getName).orElse(String.valueOf(tableId));
        return Sets.newHashSet(name);
    }

    @Override
    public Set<String> getTableNames() throws MetaNotFoundException {
        try {
            Database database = Env.getCurrentInternalCatalog().getDbOrMetaException(dbId);
            Table table = database.getTableOrMetaException(tableId);
            return Sets.newHashSet(table.getName());
        } catch (Exception e) {
            LOG.warn(e);
            throw e;
        }
    }
}
