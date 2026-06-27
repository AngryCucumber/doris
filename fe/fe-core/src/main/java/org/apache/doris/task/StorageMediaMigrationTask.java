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

package org.apache.doris.task;

import org.apache.doris.thrift.TStorageMedium;
import org.apache.doris.thrift.TStorageMediumMigrateReq;
import org.apache.doris.thrift.TTaskType;

import com.google.common.base.Strings;

public class StorageMediaMigrationTask extends AgentTask {

    private int schemaHash;
    private TStorageMedium toStorageMedium;
    // if dataDir is specified, the toStorageMedium is meaning less
    private String dataDir;

    // Tablet tiering (B route) fields. Set only for TIER_MIGRATION tasks; legacy
    // (partition-cooldown) migration leaves them unset so its thrift is unchanged.
    private long srcPathHash = -1;
    private long destPathHash = -1;
    private long policyEffectiveRevision = -1;
    private long tabletTierStateVersion = -1;
    private long migrationAttemptId = -1;
    private boolean strictCheck = false;
    private String reasonCode;

    public StorageMediaMigrationTask(long backendId, long tabletId, int schemaHash,
                                     TStorageMedium toStorageMedium) {
        super(null, backendId, TTaskType.STORAGE_MEDIUM_MIGRATE, -1L, -1L, -1L, -1L, tabletId);

        this.schemaHash = schemaHash;
        this.toStorageMedium = toStorageMedium;
    }

    public TStorageMediumMigrateReq toThrift() {
        TStorageMediumMigrateReq request = new TStorageMediumMigrateReq(tabletId, schemaHash, toStorageMedium);
        if (!Strings.isNullOrEmpty(dataDir)) {
            request.setDataDir(dataDir);
        }
        // TIER_MIGRATION tasks pass dest_path_hash (NOT data_dir); BE strictly
        // matches it. Only emit tiering fields when actually set.
        if (srcPathHash != -1) {
            request.setSrcPathHash(srcPathHash);
        }
        if (destPathHash != -1) {
            request.setDestPathHash(destPathHash);
        }
        if (policyEffectiveRevision != -1) {
            request.setPolicyEffectiveRevision(policyEffectiveRevision);
        }
        if (tabletTierStateVersion != -1) {
            request.setTabletTierStateVersion(tabletTierStateVersion);
        }
        if (migrationAttemptId != -1) {
            request.setMigrationAttemptId(migrationAttemptId);
        }
        if (strictCheck) {
            request.setStrictCheck(true);
        }
        if (!Strings.isNullOrEmpty(reasonCode)) {
            request.setReasonCode(reasonCode);
        }
        return request;
    }

    public void setTieringFields(long srcPathHash, long destPathHash, long policyEffectiveRevision,
            long tabletTierStateVersion, long migrationAttemptId, boolean strictCheck,
            String reasonCode) {
        this.srcPathHash = srcPathHash;
        this.destPathHash = destPathHash;
        this.policyEffectiveRevision = policyEffectiveRevision;
        this.tabletTierStateVersion = tabletTierStateVersion;
        this.migrationAttemptId = migrationAttemptId;
        this.strictCheck = strictCheck;
        this.reasonCode = reasonCode;
    }

    public long getMigrationAttemptId() {
        return migrationAttemptId;
    }

    public long getDestPathHash() {
        return destPathHash;
    }

    public String getDataDir() {
        return dataDir;
    }

    public void setDataDir(String dataDir) {
        this.dataDir = dataDir;
    }

    public int getSchemaHash() {
        return schemaHash;
    }

    public TStorageMedium getToStorageMedium() {
        return toStorageMedium;
    }
}
