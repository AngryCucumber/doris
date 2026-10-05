// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.analysis.RedirectStatus;
import org.apache.doris.analysis.UserIdentity;
import org.apache.doris.catalog.Env;
import org.apache.doris.common.NereidsException;
import org.apache.doris.common.UserException;
import org.apache.doris.massdb.license.LicenseManager.Action;
import org.apache.doris.mysql.privilege.AccessControllerManager;
import org.apache.doris.mysql.privilege.PrivPredicate;
import org.apache.doris.nereids.trees.plans.commands.LicenseCommand;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.qe.ShowResultSet;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

class LicenseSqlCommandTest {
    @Test
    void unknownOutcomeKeepsMandatoryNullVersionInSqlJson() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("reason", "LICENSE_SUBMISSION_UNKNOWN");
        body.put("submission_status", "UNKNOWN");
        body.put("committed_version", null);
        body.put("applied_version", 7);
        LicenseSqlException error = new LicenseSqlException(6203, body);
        Assertions.assertTrue(JsonParser.parseString(error.getMessage()).getAsJsonObject()
                .get("committed_version").isJsonNull());
        Assertions.assertEquals(6203, error.getMysqlErrorCode().getCode());
    }

    @Test
    void forwardingFailureCarriesOnlyConfirmationHintsAndNeverClaimsSubmission() throws Exception {
        Env env = Mockito.mock(Env.class);
        LicenseManager manager = Mockito.mock(LicenseManager.class);
        Mockito.when(env.getLicenseManager()).thenReturn(manager);
        Mockito.when(manager.getAppliedVersion()).thenReturn(7L);
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            LicenseSqlException error = new LicenseCommand(Action.IMPORT, "a.b.c").forwardingUnknown();
            com.google.gson.JsonObject body = JsonParser.parseString(error.getMessage()).getAsJsonObject();
            Assertions.assertEquals(6203, error.getMysqlErrorCode().getCode());
            Assertions.assertEquals("HY000", new String(error.getMysqlErrorCode().getSqlState(),
                    StandardCharsets.US_ASCII));
            Assertions.assertEquals("UNKNOWN", body.get("submission_status").getAsString());
            Assertions.assertEquals(LicenseVerifier.fingerprint("a.b.c"), body.get("fingerprint").getAsString());
            Assertions.assertTrue(body.get("committed_version").isJsonNull());
            Assertions.assertEquals(7, body.get("applied_version").getAsLong());
            Assertions.assertFalse(error.getMessage().contains("a.b.c"));

            String repairId = "12345678-1234-1234-1234-123456789abc";
            String ticket = "a." + Base64.getUrlEncoder().withoutPadding().encodeToString(
                    ("{\"repair_id\":\"" + repairId + "\"}").getBytes(StandardCharsets.UTF_8)) + ".c";
            error = new LicenseCommand(Action.CLOCK_REPAIR, ticket).forwardingUnknown();
            body = JsonParser.parseString(error.getMessage()).getAsJsonObject();
            Assertions.assertEquals(repairId, body.get("repair_id").getAsString());
            Assertions.assertEquals("UNKNOWN", body.get("submission_status").getAsString());
            Assertions.assertFalse(error.getMessage().contains(ticket));
            error = new LicenseCommand(Action.IMPORT_RECEIPT, "private.payload.signature").forwardingUnknown();
            Assertions.assertFalse(error.getMessage().contains("private.payload.signature"));
        }
    }

    @Test
    void onlyStatusIsLocalAndNonAdministrative() throws Exception {
        Env env = Mockito.mock(Env.class);
        ConnectContext context = Mockito.mock(ConnectContext.class);
        AccessControllerManager access = Mockito.mock(AccessControllerManager.class);
        Mockito.when(env.getAccessManager()).thenReturn(access);
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            for (Action action : Action.values()) {
                LicenseCommand command = new LicenseCommand(action, "a.b.c");
                if (action == Action.STATUS) {
                    command.checkPermission(context);
                    Assertions.assertEquals(RedirectStatus.NO_FORWARD, command.toRedirectStatus());
                } else {
                    UserException exception = Assertions.assertThrows(UserException.class,
                            () -> command.checkPermission(context));
                    Assertions.assertEquals(1227, exception.getMysqlErrorCode().getCode());
                    Assertions.assertEquals(RedirectStatus.FORWARD_NO_SYNC, command.toRedirectStatus());
                }
            }
        }
    }

    @Test
    void acceptingIdentityAndAdminDecisionReachSharedManager() throws Exception {
        Env env = Mockito.mock(Env.class);
        ConnectContext context = Mockito.mock(ConnectContext.class);
        AccessControllerManager access = Mockito.mock(AccessControllerManager.class);
        LicenseManager manager = Mockito.mock(LicenseManager.class);
        UserIdentity identity = UserIdentity.createAnalyzedUserIdentWithIp("license_user", "127.0.0.1");
        Mockito.when(env.getAccessManager()).thenReturn(access);
        Mockito.when(env.getLicenseManager()).thenReturn(manager);
        Mockito.when(context.getCurrentUserIdentity()).thenReturn(identity);
        Mockito.when(access.checkGlobalPriv(context, PrivPredicate.ADMIN)).thenReturn(true);
        Map<String, Object> body = receipt(7, 7);
        Mockito.when(manager.execute(Action.IMPORT, "a.b.c", identity.toString(), true))
                .thenReturn(new LicenseManagementResult(200, body));
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            ShowResultSet result = new LicenseCommand(Action.IMPORT, "a.b.c").doRun(context, null);
            Assertions.assertEquals("7", value(result, "committed_version"));
            Mockito.verify(manager).execute(Action.IMPORT, "a.b.c", identity.toString(), true);
        }
    }

    @Test
    void statusDoesNotElevateOrdinaryUserAndManagerErrorKeepsReasonAndSqlState() throws Exception {
        Env env = Mockito.mock(Env.class);
        ConnectContext context = Mockito.mock(ConnectContext.class);
        AccessControllerManager access = Mockito.mock(AccessControllerManager.class);
        LicenseManager manager = Mockito.mock(LicenseManager.class);
        UserIdentity identity = UserIdentity.createAnalyzedUserIdentWithIp("reader", "%");
        Mockito.when(env.getAccessManager()).thenReturn(access);
        Mockito.when(env.getLicenseManager()).thenReturn(manager);
        Mockito.when(context.getCurrentUserIdentity()).thenReturn(identity);
        Mockito.when(manager.execute(Action.STATUS, null, identity.toString(), false))
                .thenReturn(new LicenseManagementResult(200, receipt(0, 0)));
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            new LicenseCommand(Action.STATUS, null).doRun(context, null);
            Mockito.verify(manager).execute(Action.STATUS, null, identity.toString(), false);
            Mockito.when(access.checkGlobalPriv(context, PrivPredicate.ADMIN)).thenReturn(true);
            Mockito.when(manager.execute(Action.IMPORT, "a.b.c", identity.toString(), true))
                    .thenThrow(new LicenseManagementException("LICENSE_VERSION_CONFLICT", 409,
                            "NOT_SUBMITTED", "fingerprint", 0, 7));
            LicenseSqlException error = Assertions.assertThrows(LicenseSqlException.class,
                    () -> new LicenseCommand(Action.IMPORT, "a.b.c").doRun(context, null));
            Assertions.assertEquals(6202, error.getMysqlErrorCode().getCode());
            Assertions.assertEquals("45000", new String(error.getMysqlErrorCode().getSqlState(),
                    StandardCharsets.US_ASCII));
            Assertions.assertTrue(error.getMessage().contains("LICENSE_VERSION_CONFLICT"));
            Assertions.assertSame(error, LicenseSqlException.find(new NereidsException(error)));
        }
    }

    @Test
    void retryAdviceDistinguishesTransientRejectionFromConflictsAndUnknownSubmissions() {
        for (String reason : new String[] {"LICENSE_IMPORT_CONFLICT", "LICENSE_REPAIR_CONFLICT",
                "LICENSE_BE_LIMIT_EXCEEDED", "LICENSE_FE_LIMIT_EXCEEDED"}) {
            LicenseManagementException failure = new LicenseManagementException(reason, 409,
                    "NOT_SUBMITTED", "fingerprint", 0, 7);
            Assertions.assertEquals(false, failure.getBody().get("retryable"), reason);
            Assertions.assertEquals("45000", failure.getSqlState());
            Assertions.assertEquals("45000", new String(
                    new LicenseSqlException(failure).getMysqlErrorCode().getSqlState(), StandardCharsets.US_ASCII));
        }
        for (String reason : new String[] {"LICENSE_FE_UPGRADE_REQUIRED", "LICENSE_CLOCK_REPAIR_REQUIRED",
                "LICENSE_IMPORT_HISTORY_UNAVAILABLE", "LICENSE_REPAIR_HISTORY_UNAVAILABLE",
                "LICENSE_VERIFICATION_UNAVAILABLE"}) {
            LicenseManagementException failure = new LicenseManagementException(reason, 503,
                    "NOT_SUBMITTED", "fingerprint", 0, 7);
            Assertions.assertEquals(false, failure.getBody().get("retryable"), reason);
        }
        for (String reason : new String[] {"LICENSE_NOT_READY", "LICENSE_NOT_LEADER",
                "LICENSE_COMMIT_UNCERTAIN", "LICENSE_MANAGEMENT_UNAVAILABLE"}) {
            LicenseManagementException failure = new LicenseManagementException(reason, 503,
                    "UNKNOWN", "fingerprint", 0, 7);
            Assertions.assertEquals(false, failure.getBody().get("retryable"), reason);
            Assertions.assertEquals("UNKNOWN", failure.getBody().get("submission_status"));
            Assertions.assertEquals("fingerprint", failure.getBody().get("fingerprint"));
        }
        for (String reason : new String[] {"LICENSE_NOT_READY", "LICENSE_NOT_LEADER",
                "LICENSE_IMPORT_NOT_READY", "LICENSE_METADATA_UNAVAILABLE", "LICENSE_STORE_UNAVAILABLE"}) {
            LicenseManagementException failure = new LicenseManagementException(reason, 503,
                    "NOT_SUBMITTED", "fingerprint", 0, 7);
            Assertions.assertEquals(true, failure.getBody().get("retryable"), reason);
        }
        LicenseManagementException stale = new LicenseManagementException("LICENSE_STALE_IMPORT_DECISION", 409,
                "NOT_SUBMITTED", "fingerprint", 0, 7);
        Assertions.assertEquals(true, stale.getBody().get("retryable"));
        Assertions.assertEquals("45000", stale.getSqlState());
        for (String reason : new String[] {"LICENSE_RATE_LIMITED", "LICENSE_MANAGEMENT_BUSY"}) {
            LicenseManagementException failure = new LicenseManagementException(reason, 429,
                    "NOT_SUBMITTED", "fingerprint", 0, 7);
            Assertions.assertEquals(true, failure.getBody().get("retryable"), reason);
            Assertions.assertEquals(6, failure.getRetryAfterSeconds());
        }
        LicenseManagementException committed = new LicenseManagementException("LICENSE_COMMITTED_PENDING_APPLY", 202,
                "COMMITTED", "fingerprint", 8, 7);
        Assertions.assertEquals(true, committed.getBody().get("retryable"));
        Assertions.assertEquals("COMMITTED", committed.getBody().get("submission_status"));
        Assertions.assertEquals(8L, committed.getBody().get("committed_version"));
        Assertions.assertEquals(7L, committed.getBody().get("applied_version"));
    }

    @Test
    void followerWaitObservesLicenseVersionWithoutChangingCommittedFact() {
        ConnectContext context = Mockito.mock(ConnectContext.class);
        Env env = Mockito.mock(Env.class);
        LicenseManager manager = Mockito.mock(LicenseManager.class);
        Mockito.when(context.getEnv()).thenReturn(env);
        Mockito.when(env.getLicenseManager()).thenReturn(manager);
        Mockito.when(manager.getAppliedVersion()).thenReturn(6L, 7L);
        ShowResultSet result = LicenseCommand.resultSet(receipt(7, 7));
        LicenseCommand.awaitLocalApplication(context, result);
        Assertions.assertEquals("APPLIED", value(result, "submission_status"));
        Assertions.assertEquals("7", value(result, "committed_version"));
        Assertions.assertEquals("7", value(result, "applied_version"));
    }

    @Test
    void followerTimeoutReturnsCommittedPendingApplyAndRetainsConfirmationId() {
        ConnectContext context = Mockito.mock(ConnectContext.class);
        Env env = Mockito.mock(Env.class);
        LicenseManager manager = Mockito.mock(LicenseManager.class);
        Mockito.when(context.getEnv()).thenReturn(env);
        Mockito.when(env.getLicenseManager()).thenReturn(manager);
        Mockito.when(manager.getAppliedVersion()).thenReturn(6L);
        ShowResultSet result = LicenseCommand.resultSet(receipt(7, 7));
        long start = System.nanoTime();
        LicenseCommand.awaitLocalApplication(context, result);
        Assertions.assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(6));
        Assertions.assertEquals("COMMITTED", value(result, "submission_status"));
        Assertions.assertEquals("LICENSE_COMMITTED_PENDING_APPLY", value(result, "reason"));
        Assertions.assertEquals("7", value(result, "committed_version"));
        Assertions.assertEquals("6", value(result, "applied_version"));
        Assertions.assertEquals("fingerprint", value(result, "fingerprint"));
    }

    private static Map<String, Object> receipt(long committed, long applied) {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("reason", "LICENSE_APPLIED");
        values.put("submission_status", "APPLIED");
        values.put("committed_version", committed);
        values.put("applied_version", applied);
        values.put("fingerprint", "fingerprint");
        return values;
    }

    private static String value(ShowResultSet result, String key) {
        for (List<String> row : result.getResultRows()) {
            if (key.equals(row.get(0))) {
                return row.get(1);
            }
        }
        return null;
    }
}
