// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/** Socket-free checks; synthetic JDBC proxies are never original FE or performance evidence. */
public final class LicenseComplexPlanningFixtureTest {
    private static int assertions;

    private LicenseComplexPlanningFixtureTest() {
    }

    private static void check(boolean condition, String description) {
        assertions++;
        if (!condition) {
            throw new AssertionError(description);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, handler);
    }

    static final class JdbcTranscript {
        final List<String> calls = new ArrayList<>();
        int targetRows = 1;
        boolean targetFailure;
        boolean targetClosed;
        String queryId = "123456789abcdef-8123456789abcdef";

        ResultSet rows(boolean identity) {
            int[] row = {-1};
            ResultSetMetaData metadata = proxy(ResultSetMetaData.class, (value, method, arguments) -> {
                switch (method.getName()) {
                    case "getColumnCount": return identity ? 1 : 33;
                    case "getColumnLabel":
                        int column = (int) arguments[0];
                        return column == 1 ? "matched_rows"
                                : String.format(java.util.Locale.ROOT, "sum_expr_%02d", column - 1);
                    case "getColumnTypeName": return "BIGINT";
                    default: throw new AssertionError("Unexpected metadata operation: " + method.getName());
                }
            });
            return proxy(ResultSet.class, (value, method, arguments) -> {
                switch (method.getName()) {
                    case "getMetaData": return metadata;
                    case "next": return ++row[0] < (identity ? 1 : targetRows);
                    case "getString":
                        if (identity) {
                            return queryId;
                        }
                        int column = (int) arguments[0];
                        // Above 2^53: loss through double conversion must be observable.
                        return column == 1 ? "1024" : "9007199254740993";
                    case "close":
                        calls.add(identity ? "identity_result_closed" : "target_result_closed");
                        if (!identity) {
                            targetClosed = true;
                        }
                        return null;
                    default: throw new AssertionError("Unexpected result operation: " + method.getName());
                }
            });
        }

        Statement target(boolean prepared) {
            InvocationHandler handler = (value, method, arguments) -> {
                switch (method.getName()) {
                    case "execute":
                        calls.add(prepared ? "prepared_target" : "text_target");
                        check(prepared ? arguments == null : arguments.length == 1, "Wrong execute overload");
                        if (targetFailure) {
                            throw new SQLException("synthetic private failure", "HY000", 1234);
                        }
                        return true;
                    case "getResultSet": return rows(false);
                    default: throw new AssertionError("Unexpected target operation: " + method.getName());
                }
            };
            return prepared ? proxy(PreparedStatement.class, handler) : proxy(Statement.class, handler);
        }

        Connection connection() {
            Statement lookup = proxy(Statement.class, (value, method, arguments) -> {
                switch (method.getName()) {
                    case "setQueryTimeout": return null;
                    case "executeQuery":
                        check(targetClosed, "Target must be fully fetched and closed before query-ID lookup");
                        check(LicenseComplexPlanningFixture.LAST_ID.equals(arguments[0]),
                                "Must use last_query_id, never query_id or an intervening SQL statement");
                        calls.add("same_connection_last_query_id");
                        return rows(true);
                    case "close": calls.add("identity_statement_closed"); return null;
                    default: throw new AssertionError("Unexpected identity operation: " + method.getName());
                }
            });
            return proxy(Connection.class, (value, method, arguments) -> {
                check(method.getName().equals("createStatement"), "Unexpected connection operation");
                calls.add("create_identity_statement");
                return lookup;
            });
        }
    }

    private static Map<String, Object> capture(JdbcTranscript jdbc, boolean prepared) throws Exception {
        Map<String, Object> receipt = new LinkedHashMap<>();
        LicenseComplexPlanningFixture.executeAndIdentify(jdbc.connection(), jdbc.target(prepared),
                "synthetic_statement_never_sent_to_a_server", prepared, 1, receipt);
        return receipt;
    }

    private static void rejectedOffsets(String json, int seconds) throws Exception {
        try {
            LicenseComplexPlanningFixture.offsets(LicenseComplexPlanningFixture.JSON.readTree(json), seconds);
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Invalid arrival sequence was accepted: " + json);
    }

    public static void main(String[] args) throws Exception {
        check(args.length == 1, "Supply one existing empty owned .build-records directory");
        Path output = LicenseComplexPlanningFixture.directory(args[0]);
        try (Stream<Path> children = Files.list(output)) {
            check(children.findAny().isEmpty(), "Selfcheck output must be empty");
        }
        JsonNode fixture = LicenseComplexPlanningFixture.JSON.readTree(Files.readAllBytes(
                Path.of("/data/project/massdb-sql/docs/license-p0-contract-20260922.json")))
                .path("complex_planning_fixture");
        ObjectNode definition = LicenseComplexPlanningFixture.JSON.createObjectNode();
        definition.put("query_sql", fixture.path("query_sql").asText());
        definition.put("query_sha256_utf8", fixture.path("query_sha256_utf8").asText());
        definition.put("event_offset_seconds", 180);
        definition.putArray("columns").add("matched_rows");
        for (int index = 1; index <= 32; index++) {
            ((com.fasterxml.jackson.databind.node.ArrayNode) definition.path("columns"))
                    .add(String.format(java.util.Locale.ROOT, "sum_expr_%02d", index));
        }
        LicenseComplexPlanningFixture.validateDefinition(definition);
        ObjectNode changed = definition.deepCopy();
        changed.put("query_sql", changed.path("query_sql").asText() + " ");
        try {
            LicenseComplexPlanningFixture.validateDefinition(changed);
            throw new AssertionError("Changed frozen query was accepted");
        } catch (IllegalArgumentException expected) {
            // The fixed digest is an independent constant, not trusted from supplied JSON.
        }
        for (String input : List.of("[-1]", "[0,0]", "[2,1]", "[1000000000]", "[true]", "[0.5]")) {
            rejectedOffsets(input, 1);
        }
        check(LicenseComplexPlanningFixture.offsets(LicenseComplexPlanningFixture.JSON.readTree("[]"), 0).length == 0,
                "Zero warmup must retain an empty schedule");
        long[] sequence = LicenseComplexPlanningFixture.offsets(
                LicenseComplexPlanningFixture.JSON.readTree("[0,1,999999999]"), 1);
        check(Arrays.equals(sequence, new long[] {0, 1, 999999999}), "Arrival integers changed");
        for (boolean prepared : List.of(false, true)) {
            JdbcTranscript jdbc = new JdbcTranscript();
            Map<String, Object> receipt = capture(jdbc, prepared);
            JsonNode result = LicenseComplexPlanningFixture.JSON.valueToTree(receipt);
            check(result.path("columns").size() == 33 && result.path("rows").size() == 1
                    && result.path("rows").get(0).size() == 33, "Lost result metadata or values");
            check(result.path("rows").get(0).get(32).asText().equals("9007199254740993"),
                    "Exact JDBC string passed through a floating-point conversion");
            check(jdbc.calls.equals(List.of(prepared ? "prepared_target" : "text_target", "target_result_closed",
                    "create_identity_statement", "same_connection_last_query_id", "identity_result_closed",
                    "identity_statement_closed")), "Target/query-ID association order changed");
            check(result.path("started_ns").asLong() <= result.path("finished_ns").asLong()
                    && result.path("query_id_lookup_ns").asLong() >= 0, "Clock boundaries invalid");
        }
        for (String fault : List.of("target_sql_failure", "duplicate_row", "wrong_query_id")) {
            JdbcTranscript jdbc = new JdbcTranscript();
            jdbc.targetFailure = fault.equals("target_sql_failure");
            jdbc.targetRows = fault.equals("duplicate_row") ? 2 : 1;
            jdbc.queryId = fault.equals("wrong_query_id") ? "not-a-query-id" : jdbc.queryId;
            Map<String, Object> receipt = new LinkedHashMap<>();
            try {
                LicenseComplexPlanningFixture.executeAndIdentify(jdbc.connection(), jdbc.target(false),
                        "synthetic_statement_never_sent_to_a_server", false, 1, receipt);
                throw new AssertionError("Fault was accepted: " + fault);
            } catch (SQLException | IllegalArgumentException expected) {
                check(receipt.containsKey("started_ns") && receipt.containsKey("finished_ns"),
                        "Failed target lost its execution clock boundaries");
                check(!receipt.containsKey("query_id"), "A failed association invented a target query ID");
            }
        }
        Map<String, Object> safeError = LicenseComplexPlanningFixture.error(
                new SQLException("password=synthetic-do-not-log", "28000", 123));
        check(!LicenseComplexPlanningFixture.JSON.writeValueAsString(safeError).contains("synthetic-do-not-log"),
                "Connection error leaked credentials");
        ExecutorService cleanup = LicenseComplexPlanningFixture.pool(1, "selfcheck-no-tasks");
        try {
            check(!LicenseComplexPlanningFixture.awaitUntil(cleanup, System.nanoTime() - 1),
                    "Expired deadline must not turn a live pool into confirmed termination");
            cleanup.shutdown();
            check(LicenseComplexPlanningFixture.awaitUntil(cleanup,
                    System.nanoTime() + TimeUnit.SECONDS.toNanos(1)), "Stopped pool was not confirmed");
            check(LicenseComplexPlanningFixture.awaitUntil(cleanup, System.nanoTime() - 1),
                    "Already stopped pool must retain confirmed termination");
        } finally {
            cleanup.shutdownNow();
        }
        check(!LicenseComplexPlanningFixture.overlapsEvent(1, 2, null, null), "No event means no overlap");
        check(!LicenseComplexPlanningFixture.overlapsEvent(1, 9, 10L, null), "Pre-event completion is not overlap");
        check(LicenseComplexPlanningFixture.overlapsEvent(1, 10, 10L, null),
                "Equality at DDL start must be sampled conservatively");
        check(LicenseComplexPlanningFixture.overlapsEvent(11, 12, 10L, null),
                "Completion before the ACK is published must be sampled");
        check(LicenseComplexPlanningFixture.overlapsEvent(20, 21, 10L, 20L),
                "Equality at ACK must be sampled conservatively");
        check(!LicenseComplexPlanningFixture.overlapsEvent(21, 22, 10L, 20L),
                "New request strictly after ACK belongs to the post-event sampling rule");
        ObjectNode bounds = LicenseComplexPlanningFixture.JSON.createObjectNode().put("profile_overlap_limit", 64);
        check(LicenseComplexPlanningFixture.integer(bounds, "profile_overlap_limit", 64, 64) == 64,
                "Fixed overlap sample cap changed");
        for (int value : List.of(63, 65)) {
            bounds.put("profile_overlap_limit", value);
            try {
                LicenseComplexPlanningFixture.integer(bounds, "profile_overlap_limit", 64, 64);
                throw new AssertionError("Nonfixed overlap sample cap accepted");
            } catch (IllegalArgumentException expected) {
                // A changed cap must be a new reviewed protocol, not a silently different run.
            }
        }
        LicenseComplexPlanningFixture.writeNew(output.resolve("self-check.json"),
                Map.of("status", "unit_checks_passed", "network_connections_opened", 0,
                        "scenario_count", 28, "assertion_count", assertions,
                        "original_fe_tested", false, "ddl_tested", false, "performance_pass", false));
    }
}
