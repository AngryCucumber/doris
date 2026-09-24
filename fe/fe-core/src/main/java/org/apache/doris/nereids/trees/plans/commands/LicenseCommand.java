// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.nereids.trees.plans.commands;

import org.apache.doris.analysis.RedirectStatus;
import org.apache.doris.catalog.Column;
import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.ScalarType;
import org.apache.doris.common.ErrorCode;
import org.apache.doris.common.ErrorReport;
import org.apache.doris.common.UserException;
import org.apache.doris.massdb.license.LicenseConfirmationIds;
import org.apache.doris.massdb.license.LicenseException;
import org.apache.doris.massdb.license.LicenseManagementException;
import org.apache.doris.massdb.license.LicenseManagementResult;
import org.apache.doris.massdb.license.LicenseManager.Action;
import org.apache.doris.massdb.license.LicenseSqlException;
import org.apache.doris.massdb.license.LicenseSqlRedactor;
import org.apache.doris.massdb.license.LicenseVerifier;
import org.apache.doris.mysql.privilege.PrivPredicate;
import org.apache.doris.nereids.trees.plans.PlanType;
import org.apache.doris.nereids.trees.plans.visitor.PlanVisitor;
import org.apache.doris.persist.gson.GsonUtils;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.qe.ShowResultSet;
import org.apache.doris.qe.ShowResultSetMetaData;
import org.apache.doris.qe.StmtExecutor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** SQL adapter for the shared license management service. No certificate bytes enter result metadata. */
public final class LicenseCommand extends ShowCommand implements NeedAuditEncryption {
    private static final ShowResultSetMetaData META = ShowResultSetMetaData.builder()
            .addColumn(new Column("Key", ScalarType.createVarchar(128)))
            .addColumn(new Column("Value", ScalarType.createVarchar(65535)))
            .build();

    private final Action action;
    private final String payload;

    public LicenseCommand(Action action, String payload) {
        super(PlanType.LICENSE_COMMAND);
        this.action = action;
        this.payload = payload;
    }

    public Action getAction() {
        return action;
    }

    /** Also executed on the accepting FE, before forwarding; the Master repeats this check. */
    public void checkPermission(ConnectContext ctx) throws UserException {
        if (action != Action.STATUS && !isAdministrator(ctx)) {
            ErrorReport.reportAnalysisException(ErrorCode.ERR_SPECIFIC_ACCESS_DENIED_ERROR, "ADMIN");
        }
    }

    private boolean isAdministrator(ConnectContext ctx) {
        return Env.getCurrentEnv().getAccessManager().checkGlobalPriv(ctx, PrivPredicate.ADMIN);
    }

    @Override
    public ShowResultSet doRun(ConnectContext ctx, StmtExecutor executor) throws Exception {
        checkPermission(ctx);
        try {
            LicenseManagementResult result = Env.getCurrentEnv().getLicenseManager().execute(action, payload,
                    ctx.getCurrentUserIdentity().toString(), isAdministrator(ctx));
            return resultSet(result.getBody());
        } catch (LicenseManagementException exception) {
            throw new LicenseSqlException(exception);
        }
    }

    @Override
    public ShowResultSetMetaData getMetaData() {
        return META;
    }

    @Override
    public RedirectStatus toRedirectStatus() {
        return action == Action.STATUS ? RedirectStatus.NO_FORWARD : RedirectStatus.FORWARD_NO_SYNC;
    }

    @Override
    public boolean needAuditEncryption() {
        return action == Action.IMPORT || action == Action.VALIDATE || action == Action.CLOCK_REPAIR;
    }

    @Override
    public String geneEncryptionSQL(String sql) {
        return LicenseSqlRedactor.redact(sql);
    }

    @Override
    public <R, C> R accept(PlanVisitor<R, C> visitor, C context) {
        return visitor.visitCommand(this, context);
    }

    @Override
    public String toString() {
        return "LicenseCommand(" + action + ")";
    }

    public static ShowResultSet resultSet(Map<String, Object> body) {
        List<List<String>> rows = new ArrayList<>();
        body.forEach((key, value) -> rows.add(new ArrayList<>(Arrays.asList(key, render(value)))));
        return new ShowResultSet(META, rows);
    }

    private static String render(Object value) {
        return value instanceof String ? (String) value : GsonUtils.GSON.toJson(value);
    }

    /**
     * A Master receipt proves a commit, not application on the accepting Follower. The result rows
     * share the forwarded Thrift result and are updated before any client packet is sent.
     */
    public static void awaitLocalApplication(ConnectContext ctx, ShowResultSet result) {
        if (result == null) {
            return;
        }
        String submission = value(result, "submission_status");
        if (!"APPLIED".equals(submission) && !"COMMITTED".equals(submission)) {
            return;
        }
        long committed;
        try {
            committed = Long.parseLong(value(result, "committed_version"));
        } catch (NumberFormatException exception) {
            return;
        }
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        long applied = ctx.getEnv().getLicenseManager().getAppliedVersion();
        while (applied < committed && System.nanoTime() < deadline) {
            try {
                Thread.sleep(20);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                break;
            }
            applied = ctx.getEnv().getLicenseManager().getAppliedVersion();
        }
        setValue(result, "applied_version", Long.toString(applied));
        setValue(result, "submission_status", applied >= committed ? "APPLIED" : "COMMITTED");
        setValue(result, "reason", applied >= committed ? "LICENSE_APPLIED" : "LICENSE_COMMITTED_PENDING_APPLY");
        setValue(result, "retryable", Boolean.toString(applied < committed));
        if (applied < committed) {
            setValue(result, "message", "Committed on Master; this FE has not applied the version yet");
        } else {
            setValue(result, "message", "LICENSE_APPLIED");
        }
    }

    private static String value(ShowResultSet result, String key) {
        for (List<String> row : result.getResultRows()) {
            if (row.size() == 2 && key.equals(row.get(0))) {
                return row.get(1);
            }
        }
        return null;
    }

    private static void setValue(ShowResultSet result, String key, String value) {
        for (List<String> row : result.getResultRows()) {
            if (row.size() == 2 && key.equals(row.get(0))) {
                row.set(1, value);
                return;
            }
        }
        result.getResultRows().add(new ArrayList<>(Arrays.asList(key, value)));
    }

    /** No automatic resubmission after a forwarding failure with an unknown commit outcome. */
    public LicenseSqlException forwardingUnknown() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("reason", "LICENSE_SUBMISSION_UNKNOWN");
        body.put("message", "Master response unavailable; query the receipt before resubmitting");
        body.put("retryable", true);
        body.put("submission_status", "UNKNOWN");
        if (action == Action.IMPORT || action == Action.VALIDATE) {
            try {
                body.put("fingerprint", LicenseVerifier.fingerprint(payload));
            } catch (LicenseException exception) {
                // An invalid or oversized candidate has no trustworthy confirmation identifier.
            }
        } else if (action == Action.IMPORT_RECEIPT && payload != null && payload.matches("[0-9a-f]{64}")) {
            body.put("fingerprint", payload);
        } else if (action == Action.CLOCK_REPAIR) {
            String repairId = LicenseConfirmationIds.repairIdHint(payload);
            if (repairId != null) {
                body.put("repair_id", repairId);
            }
        } else if (action == Action.CLOCK_REPAIR_RECEIPT && payload != null
                && payload.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) {
            body.put("repair_id", payload);
        }
        body.put("committed_version", null);
        body.put("applied_version", Env.getCurrentEnv().getLicenseManager().getAppliedVersion());
        return new LicenseSqlException(6203, body);
    }
}
