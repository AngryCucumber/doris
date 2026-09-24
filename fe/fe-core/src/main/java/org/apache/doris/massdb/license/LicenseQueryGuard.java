// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.TableIf;
import org.apache.doris.nereids.NereidsPlanner;
import org.apache.doris.nereids.StatementContext;
import org.apache.doris.nereids.analyzer.UnboundAlias;
import org.apache.doris.nereids.analyzer.UnboundRelation;
import org.apache.doris.nereids.analyzer.UnboundResultSink;
import org.apache.doris.nereids.trees.expressions.Alias;
import org.apache.doris.nereids.trees.expressions.Expression;
import org.apache.doris.nereids.trees.expressions.functions.scalar.DictGet;
import org.apache.doris.nereids.trees.expressions.functions.scalar.DictGetMany;
import org.apache.doris.nereids.trees.expressions.functions.table.TableValuedFunction;
import org.apache.doris.nereids.trees.expressions.literal.IntegerLikeLiteral;
import org.apache.doris.nereids.trees.plans.Plan;
import org.apache.doris.nereids.trees.plans.logical.LogicalCheckPolicy;
import org.apache.doris.nereids.trees.plans.logical.LogicalLimit;
import org.apache.doris.nereids.trees.plans.logical.LogicalProject;
import org.apache.doris.nereids.trees.plans.logical.LogicalSubQueryAlias;
import org.apache.doris.nereids.trees.plans.physical.AbstractPhysicalSort;
import org.apache.doris.nereids.trees.plans.physical.PhysicalDistribute;
import org.apache.doris.nereids.trees.plans.physical.PhysicalEmptyRelation;
import org.apache.doris.nereids.trees.plans.physical.PhysicalFilter;
import org.apache.doris.nereids.trees.plans.physical.PhysicalHashAggregate;
import org.apache.doris.nereids.trees.plans.physical.PhysicalLimit;
import org.apache.doris.nereids.trees.plans.physical.PhysicalProject;
import org.apache.doris.nereids.trees.plans.physical.PhysicalSink;
import org.apache.doris.nereids.trees.plans.physical.PhysicalUnion;
import org.apache.doris.nereids.trees.plans.physical.PhysicalWindow;
import org.apache.doris.planner.Planner;
import org.apache.doris.tablefunction.MetadataTableValuedFunction;
import org.apache.doris.tablefunction.NumbersTableValuedFunction;
import org.apache.doris.tablefunction.TableValuedFunctionIf;

import java.util.LinkedHashMap;
import java.util.Map;

/** Shared FE read admission. Caller owns execution lifetime and trusted top-level write purpose. */
public final class LicenseQueryGuard {
    private LicenseQueryGuard() {
    }

    public static void check(Planner planner) throws LicenseSqlException {
        check(planner, false);
    }

    public static void checkExternalWrite(Planner planner) throws LicenseSqlException {
        check(planner, true);
    }

    private static void check(Planner planner, boolean externalWrite) throws LicenseSqlException {
        LicenseQueryStatus status = Env.getCurrentEnv().getLicenseManager().queryStatus();
        if (status.permitsNewQuery()) {
            return;
        }
        Classification classification = null;
        if (planner instanceof NereidsPlanner) {
            NereidsPlanner nereids = (NereidsPlanner) planner;
            classification = classification(nereids.getStatementContext(), nereids.getPhysicalPlan());
        }
        check(status, classification, externalWrite);
    }

    public static void check(StatementContext context, Plan finalPlan) throws LicenseSqlException {
        LicenseQueryStatus status = Env.getCurrentEnv().getLicenseManager().queryStatus();
        if (!status.permitsNewQuery()) {
            check(status, classification(context, finalPlan), false);
        }
    }

    public static void checkExternalWrite(StatementContext context, Plan finalPlan) throws LicenseSqlException {
        LicenseQueryStatus status = Env.getCurrentEnv().getLicenseManager().queryStatus();
        if (!status.permitsNewQuery()) {
            check(status, classification(context, finalPlan), true);
        }
    }

    public static void checkProtectedRead() throws LicenseSqlException {
        check(Env.getCurrentEnv().getLicenseManager().queryStatus(), null, false);
    }

    /** Null or old cache classification is deliberately unknown, never a metadata exemption. */
    public static void check(LicenseQueryStatus status, Classification classification, boolean externalWrite)
            throws LicenseSqlException {
        if (status.permitsNewQuery() || (classification != null && !classification.requiresLicense(externalWrite))) {
            return;
        }
        String reason = reason(status);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("reason", reason);
        body.put("message", reason);
        body.put("retryable", status == LicenseQueryStatus.LICENSE_NOT_READY);
        throw new LicenseSqlException(6200, body);
    }

    public static String reason(LicenseQueryStatus status) {
        return status == LicenseQueryStatus.LICENSE_NOT_READY ? status.name() : "LICENSE_" + status.name();
    }

    public static boolean requiresLicense(StatementContext context, Plan finalPlan) {
        Classification classification = classification(context, finalPlan);
        return classification == null || classification.requiresLicense(false);
    }

    private static Classification classification(StatementContext context, Plan finalPlan) {
        if (context == null) {
            return null;
        }
        Classification saved = context.getLicenseQueryClassification();
        return saved != null ? saved : context.getLicenseQueryFacts().finish(finalPlan);
    }

    /** Small immutable cache fact; invalidated together with the cache's existing table/schema dependencies. */
    public static final class Classification {
        private final boolean protectedSource;
        private final boolean emptyWithoutRead;
        private final boolean tableProbe;

        private Classification(boolean protectedSource, boolean emptyWithoutRead, boolean tableProbe) {
            this.protectedSource = protectedSource;
            this.emptyWithoutRead = emptyWithoutRead;
            this.tableProbe = tableProbe;
        }

        public boolean requiresLicense(boolean externalWrite) {
            return protectedSource && !emptyWithoutRead && (externalWrite || !tableProbe);
        }

        public boolean isEmptyWithoutRead() {
            return emptyWithoutRead;
        }

        public boolean isTableProbe() {
            return tableProbe;
        }
    }

    /** Fed by existing binding visits, before rewriting can erase a table or fold a dictionary call. */
    public static final class Facts {
        private boolean originalSeen;
        private boolean analyzed;
        private boolean originalProbe;
        private boolean protectedSource;
        private boolean view;
        private boolean tvf;
        private boolean dictionary;
        private boolean realTable;
        private TableIf probeTable;
        private boolean multipleTables;

        public void begin(Plan original) {
            if (!originalSeen) {
                originalSeen = true;
                originalProbe = isOriginalTableProbe(original);
            }
        }

        public void analyzed() {
            analyzed = true;
        }

        public void table(TableIf table, boolean isView) {
            view |= isView;
            if (!isView && table.getType() != TableIf.TableType.SCHEMA) {
                protectedSource = true;
                realTable = true;
                if (probeTable == null) {
                    probeTable = table;
                } else if (probeTable != table) {
                    multipleTables = true;
                }
            }
        }

        public void function(Expression expression) {
            if (expression instanceof DictGet || expression instanceof DictGetMany) {
                dictionary = true;
                protectedSource = true;
            }
        }

        public void tableFunction(TableValuedFunction function) {
            tableFunction(function.getCatalogFunction());
        }

        public void tableFunction(TableValuedFunctionIf function) {
            tvf = true;
            if (!(function instanceof MetadataTableValuedFunction)
                    && !(function instanceof NumbersTableValuedFunction)) {
                protectedSource = true;
            }
        }

        public Classification finish(Plan finalPlan) {
            if (!originalSeen || !analyzed || finalPlan == null) {
                return null;
            }
            return new Classification(protectedSource, emptyWithoutRead(finalPlan),
                    originalProbe && realTable && !multipleTables && !view && !tvf && !dictionary);
        }
    }

    /** Match only the unoptimized SELECT 1 shape. Removed WHERE/ORDER/CAST must not become probes. */
    public static boolean isOriginalTableProbe(Plan plan) {
        if (plan instanceof UnboundResultSink) {
            plan = plan.child(0);
        }
        if (!(plan instanceof LogicalLimit)) {
            return false;
        }
        LogicalLimit<?> limit = (LogicalLimit<?>) plan;
        if (limit.getLimit() != 1 || limit.getOffset() != 0 || !(limit.child() instanceof LogicalProject)) {
            return false;
        }
        LogicalProject<?> project = (LogicalProject<?>) limit.child();
        if (project.isDistinct() || project.getProjects().size() != 1) {
            return false;
        }
        Expression expression = project.getProjects().get(0);
        if (expression instanceof Alias || expression instanceof UnboundAlias) {
            expression = expression.child(0);
        }
        if (!(expression instanceof IntegerLikeLiteral) || ((IntegerLikeLiteral) expression).getLongValue() != 1) {
            return false;
        }
        plan = project.child();
        if (plan instanceof LogicalSubQueryAlias) {
            plan = plan.child(0);
        }
        if (plan instanceof LogicalCheckPolicy) {
            plan = plan.child(0);
        }
        if (!(plan instanceof UnboundRelation)) {
            return false;
        }
        UnboundRelation relation = (UnboundRelation) plan;
        return !relation.getTableSample().isPresent() && relation.getScanParams() == null
                && !relation.getTableSnapshot().isPresent() && !relation.getIndexName().isPresent()
                && relation.getPartNames().isEmpty() && relation.getTabletIds().isEmpty();
    }

    /** Structural proof only: every executable input is empty, and the complete result emits zero rows. */
    public static boolean emptyWithoutRead(Plan plan) {
        if (plan instanceof PhysicalEmptyRelation) {
            return true;
        }
        if (plan instanceof PhysicalUnion) {
            PhysicalUnion union = (PhysicalUnion) plan;
            if (!union.getConstantExprsList().isEmpty()) {
                return false;
            }
            for (Plan child : union.children()) {
                if (!emptyWithoutRead(child)) {
                    return false;
                }
            }
            return true;
        }
        if (plan instanceof PhysicalHashAggregate
                && ((PhysicalHashAggregate<?>) plan).getGroupByExpressions().isEmpty()) {
            return false;
        }
        if (plan instanceof PhysicalSink || plan instanceof PhysicalProject || plan instanceof PhysicalFilter
                || plan instanceof PhysicalDistribute || plan instanceof PhysicalLimit
                || plan instanceof AbstractPhysicalSort || plan instanceof PhysicalWindow
                || plan instanceof PhysicalHashAggregate) {
            return plan.arity() == 1 && emptyWithoutRead(plan.child(0));
        }
        return false;
    }
}
