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

package org.apache.doris.massdblicense;

import org.apache.doris.catalog.Env;
import org.apache.doris.datasource.tvf.source.TVFScanNode;
import org.apache.doris.nereids.analyzer.UnboundRelation;
import org.apache.doris.nereids.analyzer.UnboundTVFRelation;
import org.apache.doris.nereids.trees.expressions.Expression;
import org.apache.doris.nereids.trees.expressions.SubqueryExpr;
import org.apache.doris.nereids.trees.plans.Plan;
import org.apache.doris.nereids.trees.plans.commands.AlterRoutineLoadCommand;
import org.apache.doris.nereids.trees.plans.commands.CancelLoadCommand;
import org.apache.doris.nereids.trees.plans.commands.Command;
import org.apache.doris.nereids.trees.plans.commands.CopyIntoCommand;
import org.apache.doris.nereids.trees.plans.commands.EmptyCommand;
import org.apache.doris.nereids.trees.plans.commands.ExecuteCommand;
import org.apache.doris.nereids.trees.plans.commands.ExplainCommand;
import org.apache.doris.nereids.trees.plans.commands.KillCommand;
import org.apache.doris.nereids.trees.plans.commands.LoadCommand;
import org.apache.doris.nereids.trees.plans.commands.PrepareCommand;
import org.apache.doris.nereids.trees.plans.commands.SetOptionsCommand;
import org.apache.doris.nereids.trees.plans.commands.SetTransactionCommand;
import org.apache.doris.nereids.trees.plans.commands.SyncCommand;
import org.apache.doris.nereids.trees.plans.commands.TransactionCommand;
import org.apache.doris.nereids.trees.plans.commands.clean.CleanLabelCommand;
import org.apache.doris.nereids.trees.plans.commands.insert.BatchInsertIntoTableCommand;
import org.apache.doris.nereids.trees.plans.commands.insert.InsertIntoTableCommand;
import org.apache.doris.nereids.trees.plans.commands.load.CreateRoutineLoadCommand;
import org.apache.doris.nereids.trees.plans.commands.load.MysqlLoadCommand;
import org.apache.doris.nereids.trees.plans.commands.load.PauseRoutineLoadCommand;
import org.apache.doris.nereids.trees.plans.commands.load.ResumeRoutineLoadCommand;
import org.apache.doris.nereids.trees.plans.commands.load.StopRoutineLoadCommand;
import org.apache.doris.nereids.trees.plans.commands.use.UseCloudClusterCommand;
import org.apache.doris.nereids.trees.plans.commands.use.UseCommand;
import org.apache.doris.nereids.trees.plans.logical.LogicalCatalogRelation;
import org.apache.doris.nereids.trees.plans.logical.LogicalPlan;
import org.apache.doris.nereids.trees.plans.physical.PhysicalCatalogRelation;
import org.apache.doris.planner.GroupCommitScanNode;
import org.apache.doris.planner.ScanNode;
import org.apache.doris.tablefunction.HttpStreamTableValuedFunction;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

/**
 * Component-native query gate. Query origin is assigned by trusted FE constructors and is never
 * derived from a session variable, HTTP header, user name, or source address.
 */
public final class MassDbLicenseQueryGuard {
    public enum QueryOrigin {
        EXTERNAL_MYSQL,
        EXTERNAL_HTTP_LOAD,
        EXTERNAL_ARROW,
        FORWARDED_EXTERNAL,
        INTERNAL
    }

    private MassDbLicenseQueryGuard() {
    }

    /** Parsed/unbound preflight used before forwarding or invoking a command. */
    public static boolean isProtectedParsedPlan(QueryOrigin origin, LogicalPlan logicalPlan) {
        if (origin == QueryOrigin.INTERNAL) {
            return false;
        }
        LogicalPlan plan = unwrap(logicalPlan);
        if (plan instanceof InsertIntoTableCommand) {
            return hasProtectedRelation(origin, ((InsertIntoTableCommand) plan).getLogicalQuery());
        }
        if (plan instanceof BatchInsertIntoTableCommand) {
            return hasProtectedRelation(origin, ((BatchInsertIntoTableCommand) plan).getLogicalQuery());
        }
        if (isAlwaysAvailableCommand(plan)) {
            return false;
        }
        if (plan instanceof Command) {
            return true;
        }
        return hasProtectedRelation(origin, plan);
    }

    /** Analyzed preflight immediately before an executor or transaction is created. */
    public static boolean isProtectedAnalyzedPlan(QueryOrigin origin,
            List<ScanNode> scanNodes, boolean ingestionPlan) {
        if (origin == QueryOrigin.INTERNAL) {
            return false;
        }
        for (ScanNode scanNode : scanNodes) {
            if (ingestionPlan && scanNode instanceof GroupCommitScanNode) {
                continue;
            }
            if (ingestionPlan && origin == QueryOrigin.EXTERNAL_HTTP_LOAD
                    && scanNode instanceof TVFScanNode) {
                continue;
            }
            return true;
        }
        return false;
    }

    public static void enforceParsedPlan(QueryOrigin origin, LogicalPlan logicalPlan)
            throws MassDbLicenseQueryException {
        if (isProtectedParsedPlan(origin, logicalPlan)) {
            enforceCurrentDecision(origin);
        }
    }

    public static void enforceAnalyzedPlan(QueryOrigin origin,
            List<ScanNode> scanNodes, boolean ingestionPlan)
            throws MassDbLicenseQueryException {
        if (isProtectedAnalyzedPlan(origin, scanNodes, ingestionPlan)) {
            enforceCurrentDecision(origin);
        }
    }

    public static void enforceMetadataRead(QueryOrigin origin)
            throws MassDbLicenseQueryException {
        enforceCurrentDecision(origin);
    }

    /** Re-evaluates the local snapshot only; old/unconfigured components return null and stay compatible. */
    public static String currentDenialCode(QueryOrigin origin) {
        if (origin == QueryOrigin.INTERNAL) {
            return null;
        }
        MassDbLicenseLocalSnapshotStore.QueryDecision decision =
                Env.getCurrentEnv().evaluateMassDbLicenseLocalQuery();
        if (decision == null || decision.allowed) {
            return null;
        }
        return decision.errorCode == null ? "MASSDB_LICENSE_INVALID" : decision.errorCode;
    }

    public static void enforceCurrentDecision(QueryOrigin origin)
            throws MassDbLicenseQueryException {
        String code = currentDenialCode(origin);
        if (code != null) {
            throw new MassDbLicenseQueryException(code);
        }
    }

    private static LogicalPlan unwrap(LogicalPlan plan) {
        LogicalPlan current = plan;
        while (true) {
            if (current instanceof PrepareCommand) {
                current = ((PrepareCommand) current).getLogicalPlan();
            } else if (current instanceof ExecuteCommand) {
                current = ((ExecuteCommand) current).getLogicalPlan();
            } else if (current instanceof ExplainCommand) {
                current = ((ExplainCommand) current).getLogicalPlan();
            } else {
                return current;
            }
        }
    }

    private static boolean isAlwaysAvailableCommand(LogicalPlan plan) {
        return plan instanceof LoadCommand
                || plan instanceof MysqlLoadCommand
                || plan instanceof CopyIntoCommand
                || plan instanceof CreateRoutineLoadCommand
                || plan instanceof AlterRoutineLoadCommand
                || plan instanceof PauseRoutineLoadCommand
                || plan instanceof ResumeRoutineLoadCommand
                || plan instanceof StopRoutineLoadCommand
                || plan instanceof CancelLoadCommand
                || plan instanceof CleanLabelCommand
                || plan instanceof TransactionCommand
                || plan instanceof SetOptionsCommand
                || plan instanceof SetTransactionCommand
                || plan instanceof UseCommand
                || plan instanceof UseCloudClusterCommand
                || plan instanceof KillCommand
                || plan instanceof EmptyCommand
                || plan instanceof SyncCommand;
    }

    private static boolean hasProtectedRelation(QueryOrigin origin, Plan root) {
        Set<Plan> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        Set<Expression> visitedExpressions =
                Collections.newSetFromMap(new IdentityHashMap<>());
        return hasProtectedRelation(origin, root, visited, visitedExpressions);
    }

    private static boolean hasProtectedRelation(QueryOrigin origin, Plan plan,
            Set<Plan> visited, Set<Expression> visitedExpressions) {
        if (plan == null || !visited.add(plan)) {
            return false;
        }
        if (plan instanceof UnboundTVFRelation) {
            String functionName = ((UnboundTVFRelation) plan).getFunctionName();
            return origin != QueryOrigin.EXTERNAL_HTTP_LOAD
                    || !HttpStreamTableValuedFunction.NAME.equalsIgnoreCase(functionName);
        }
        if (plan instanceof UnboundRelation
                || plan instanceof LogicalCatalogRelation
                || plan instanceof PhysicalCatalogRelation) {
            return true;
        }
        for (Expression expression : plan.getExpressions()) {
            if (hasProtectedSubquery(origin, expression, visited, visitedExpressions)) {
                return true;
            }
        }
        for (Plan child : plan.children()) {
            if (hasProtectedRelation(origin, child, visited, visitedExpressions)) {
                return true;
            }
        }
        for (Plan extraPlan : plan.extraPlans()) {
            if (hasProtectedRelation(origin, extraPlan, visited, visitedExpressions)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasProtectedSubquery(QueryOrigin origin, Expression expression,
            Set<Plan> visited, Set<Expression> visitedExpressions) {
        if (expression == null || !visitedExpressions.add(expression)) {
            return false;
        }
        if (expression instanceof SubqueryExpr
                && hasProtectedRelation(origin, ((SubqueryExpr) expression).getQueryPlan(),
                        visited, visitedExpressions)) {
            return true;
        }
        for (Expression child : expression.children()) {
            if (hasProtectedSubquery(origin, child, visited, visitedExpressions)) {
                return true;
            }
        }
        return false;
    }
}
