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

package org.apache.doris.nereids.trees.plans.commands;

import org.apache.doris.catalog.DatabaseIf;
import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.common.DdlException;
import org.apache.doris.common.ErrorCode;
import org.apache.doris.common.ErrorReport;
import org.apache.doris.common.UserException;
import org.apache.doris.common.util.InternalDatabaseUtil;
import org.apache.doris.common.util.PropertyAnalyzer;
import org.apache.doris.mysql.privilege.PrivPredicate;
import org.apache.doris.nereids.trees.plans.PlanType;
import org.apache.doris.nereids.trees.plans.visitor.PlanVisitor;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.qe.StmtExecutor;
import org.apache.doris.tiering.TabletTieringMgr;
import org.apache.doris.tiering.TieringPolicy;
import org.apache.doris.tiering.TieringScopeType;

import com.google.common.base.Strings;

import java.util.HashMap;
import java.util.Map;

/**
 * Command for ALTER DATABASE ... SET PROPERTIES in Nereids.
 */
public class AlterDatabasePropertiesCommand extends AlterCommand {

    private final String dbName;
    private final Map<String, String> properties;

    public AlterDatabasePropertiesCommand(String databaseName, Map<String, String> properties) {
        super(PlanType.ALTER_DATABASE_PROPERTIES_COMMAND);
        this.dbName = databaseName;
        this.properties = properties;
    }

    private void validate(ConnectContext ctx) throws UserException {
        InternalDatabaseUtil.checkDatabase(dbName, ConnectContext.get());
        if (!Env.getCurrentEnv().getAccessManager().checkGlobalPriv(ConnectContext.get(), PrivPredicate.ADMIN)) {
            ErrorReport.reportAnalysisException(ErrorCode.ERR_DBACCESS_DENIED_ERROR,
                    ctx.getQualifiedUser(), dbName);
        }

        if (Strings.isNullOrEmpty(dbName)) {
            ErrorReport.reportAnalysisException(ErrorCode.ERR_NO_DB_ERROR);
        }

        if (properties == null || properties.isEmpty()) {
            throw new UserException("Properties is null or empty");
        }

        // clone properties for analyse
        Map<String, String> analysisProperties = new HashMap<String, String>(properties);
        PropertyAnalyzer.analyzeBinlogConfig(analysisProperties);
    }

    @Override
    public void doRun(ConnectContext ctx, StmtExecutor executor) throws Exception {
        validate(ctx);

        // Tablet tiering (B route): a TENANT-scope policy is keyed by the database
        // id (database = tenant). ALTER DATABASE <db> SET PROPERTIES('tablet_tiering.*')
        // is intercepted here and routed to the tiering manager rather than stored
        // as a plain database property. Priority is table < partition < tenant.
        if (handleTenantTieringProperties()) {
            return;
        }

        Env.getCurrentEnv().alterDatabaseProperty(dbName, properties);
    }

    private boolean handleTenantTieringProperties() throws UserException {
        boolean anyTiering = false;
        boolean allTiering = true;
        for (String key : properties.keySet()) {
            if (key.startsWith(PropertyAnalyzer.PROPERTIES_TABLET_TIERING_PREFIX)) {
                anyTiering = true;
            } else {
                allTiering = false;
            }
        }
        if (!anyTiering) {
            return false;
        }
        if (!allTiering) {
            throw new DdlException("tablet_tiering.* database properties cannot be mixed with "
                    + "other properties in one ALTER DATABASE statement");
        }
        if (Config.isCloudMode()) {
            throw new DdlException("tablet_tiering is not supported in cloud mode");
        }
        DatabaseIf db = Env.getCurrentEnv().getInternalCatalog().getDbOrDdlException(dbName);
        long dbId = db.getId();
        TabletTieringMgr mgr = Env.getCurrentEnv().getTabletTieringMgr();
        if (mgr == null) {
            throw new DdlException("tablet tiering manager is not available");
        }
        TieringPolicy existing = mgr.getPolicyManager().getPolicy(TieringScopeType.TENANT, dbId);
        mgr.modifyTieringPolicy(PropertyAnalyzer.analyzeTabletTieringPolicy(
                properties, TieringScopeType.TENANT, dbId, existing));
        return true;
    }

    public String getDbName() {
        return dbName;
    }

    public Map<String, String> getProperties() {
        return properties;
    }

    @Override
    public <R, C> R accept(PlanVisitor<R, C> visitor, C context) {
        return visitor.visitAlterDatabasePropertiesCommand(this, context);
    }

}

