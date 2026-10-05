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

// Modified for MassDB SQL. See MODIFICATIONS.md for details.

package org.apache.doris.journal.bdbje;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.common.Pair;
import org.apache.doris.journal.JournalCursor;
import org.apache.doris.journal.JournalEntity;

import com.sleepycat.bind.tuple.TupleBinding;
import com.sleepycat.je.Database;
import com.sleepycat.je.DatabaseEntry;
import com.sleepycat.je.LockMode;
import com.sleepycat.je.OperationStatus;
import com.sleepycat.je.Transaction;
import com.sleepycat.je.TransactionConfig;
import com.sleepycat.je.rep.NoConsistencyRequiredPolicy;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.util.List;

public class BDBJournalCursor implements JournalCursor {
    private static final Logger LOG = LogManager.getLogger(BDBJournalCursor.class);

    private long toKey;
    private long currentKey;
    private BDBEnvironment environment;
    private List<Long> dbNames;
    private Database database;
    private int nextDbPositionIndex;
    private final int maxTryTime = 3;
    private long skippedJournalId = -1;
    private Short skippedOperation;

    public static BDBJournalCursor getJournalCursor(BDBEnvironment env, long fromKey, long toKey) {
        return getJournalCursor(env, fromKey, toKey, true);
    }

    public static BDBJournalCursor getJournalCursor(BDBEnvironment env, long fromKey, long toKey,
            boolean exitIfNotFound) {
        if (toKey < fromKey || fromKey < 0) {
            LOG.warn("Invalid key range! fromKey:{} toKey:{}", fromKey, toKey);
            return null;
        }
        BDBJournalCursor cursor = null;
        try {
            cursor = new BDBJournalCursor(env, fromKey, toKey, exitIfNotFound);
        } catch (Exception e) {
            LOG.error("new BDBJournalCursor error.", e);
        }
        return cursor;
    }

    private BDBJournalCursor(BDBEnvironment env, long fromKey, long toKey, boolean exitIfNotFound) throws Exception {
        this.environment = env;
        this.toKey = toKey;
        this.currentKey = fromKey;
        this.dbNames = env.getDatabaseNames();
        if (dbNames == null) {
            throw new NullPointerException("dbNames is null.");
        }
        this.nextDbPositionIndex = 0;

        // find the db which may contain the fromKey
        String dbName = null;
        for (long db : dbNames) {
            if (fromKey >= db) {
                dbName = Long.toString(db);
                nextDbPositionIndex++;
            } else {
                break;
            }
        }

        if (dbName == null) {
            if (exitIfNotFound) {
                LOG.error("Can not find the key:{}, fail to get journal cursor. will exit.", fromKey);
                System.exit(-1);
            } else {
                throw new Exception("Can not find the key:" + fromKey + ", fail to get journal cursor.");
            }
        }
        this.database = env.openDatabase(dbName);
    }

    @Override
    public Pair<Long, JournalEntity> next() {
        skippedJournalId = -1;
        skippedOperation = null;
        if (currentKey > toKey) {
            return null;
        }

        if (Env.getCurrentEnv().getForceSkipJournalIds().contains(String.valueOf(currentKey))) {
            skippedJournalId = currentKey;
            // Preserve the no-read emergency path for physically damaged records by default.
            if (Config.massdb_license_probe_skipped_journal_header) {
                skippedOperation = probeSkippedOperation();
            }
            return Pair.of(currentKey++, null);
        }
        Long key = currentKey;
        DatabaseEntry theKey = new DatabaseEntry();
        TupleBinding<Long> myBinding = TupleBinding.getPrimitiveBinding(Long.class);
        myBinding.objectToEntry(key, theKey);

        DatabaseEntry theData = new DatabaseEntry();
        // if current db does not contain any more data, then we go to search the next db
        try {
            // null means perform the operation without transaction protection.
            // READ_COMMITTED guarantees no dirty read.
            int tryTimes = 0;
            while (true) {
                advanceDatabase();
                OperationStatus operationStatus = database.get(null, theKey, theData, LockMode.READ_COMMITTED);
                if (operationStatus == OperationStatus.SUCCESS) {
                    // Recreate the data String.
                    byte[] retData = theData.getData();
                    DataInputStream in = new DataInputStream(new ByteArrayInputStream(retData));
                    JournalEntity entity = new JournalEntity();
                    try {
                        entity.readFields(in);
                        entity.setDataSize(retData.length);
                    } catch (Exception e) {
                        LOG.error("fail to read journal entity key={}, will exit", currentKey, e);
                        System.exit(-1);
                    }
                    currentKey++;
                    return Pair.of(key, entity);
                } else if (tryTimes < maxTryTime) {
                    tryTimes++;
                    LOG.warn("fail to get journal {}, will try again. status: {}", currentKey, operationStatus);
                    Thread.sleep(3000);
                } else if (operationStatus == OperationStatus.NOTFOUND) {
                    // In the case:
                    // On non-master FE, the replayer will first get the max journal id,
                    // than try to replay logs from current replayed id to the max journal id. But when
                    // master FE try to write a log to bdbje, but crashed before this log is committed,
                    // the non-master FE may still get this incomplete log's id as max journal id,
                    // and try to replay it. We will first get LockTimeoutException (because the transaction
                    // is hanging and waiting to be aborted after timeout). and after this log abort,
                    // we will get NOTFOUND.
                    // So we simply throw a exception and let the replayer get the max id again.
                    throw new Exception(
                            "Failed to find key " + currentKey + " in database " + database.getDatabaseName());
                } else {
                    LOG.error("fail to get journal {}, status: {}, will exit", currentKey, operationStatus);
                    System.exit(-1);
                }
            }
        } catch (Exception e) {
            LOG.warn("Catch an exception when get next JournalEntity. key:{}", currentKey, e);
            return null;
        }
    }

    @Override
    public Short getSkippedOperation(long journalId) {
        return journalId == skippedJournalId ? skippedOperation : null;
    }

    private void advanceDatabase() {
        // A force-skipped record can be the first key in a new database.
        while (nextDbPositionIndex < dbNames.size() && currentKey >= dbNames.get(nextDbPositionIndex)) {
            Database nextDatabase = environment.openDatabase(dbNames.get(nextDbPositionIndex).toString());
            if (nextDatabase == null) {
                throw new IllegalStateException("Journal database unavailable");
            }
            database = nextDatabase;
            nextDbPositionIndex++;
        }
    }

    private Short probeSkippedOperation() {
        try {
            advanceDatabase();
            DatabaseEntry key = new DatabaseEntry();
            TupleBinding.getPrimitiveBinding(Long.class).objectToEntry(currentKey, key);
            DatabaseEntry header = new DatabaseEntry();
            header.setPartial(0, Short.BYTES, true);
            Transaction transaction = database.getEnvironment().beginTransaction(null, new TransactionConfig()
                    .setReadOnly(true).setNoWait(true).setConsistencyPolicy(new NoConsistencyRequiredPolicy()));
            try {
                // One committed header read, without business decoding, lock waits or retry sleeps.
                if (database.get(transaction, key, header, LockMode.READ_COMMITTED) != OperationStatus.SUCCESS
                        || header.getSize() != Short.BYTES) {
                    return null;
                }
                byte[] bytes = header.getData();
                int offset = header.getOffset();
                return (short) ((bytes[offset] & 0xff) << 8 | bytes[offset + 1] & 0xff);
            } finally {
                transaction.abort();
            }
        } catch (RuntimeException e) {
            // Ordinary read failures remain unknown. Physical JE corruption can invalidate the environment;
            // the opt-in probe is not a physical-corruption recovery mechanism.
            LOG.warn("Unable to classify force-skipped journal {}", currentKey);
            return null;
        }
    }

    @Override
    public void close() {

    }
}
