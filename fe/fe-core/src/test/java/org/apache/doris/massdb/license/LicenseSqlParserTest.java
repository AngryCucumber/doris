// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.analysis.StatementBase;
import org.apache.doris.catalog.Env;
import org.apache.doris.common.ErrorCode;
import org.apache.doris.common.Pair;
import org.apache.doris.common.UserException;
import org.apache.doris.common.profile.Profile;
import org.apache.doris.common.util.SqlUtils;
import org.apache.doris.massdb.license.LicenseManager.Action;
import org.apache.doris.nereids.DorisLexer;
import org.apache.doris.nereids.DorisParser;
import org.apache.doris.nereids.exceptions.SyntaxParseException;
import org.apache.doris.nereids.parser.Dialect;
import org.apache.doris.nereids.parser.NereidsParser;
import org.apache.doris.nereids.parser.SqlDialectHelper;
import org.apache.doris.nereids.trees.plans.commands.LicenseCommand;
import org.apache.doris.nereids.trees.plans.commands.info.BaseViewInfo;
import org.apache.doris.plugin.DialectConverterPlugin;
import org.apache.doris.plugin.PluginMgr;
import org.apache.doris.proto.Data;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.qe.ConnectProcessor;
import org.apache.doris.qe.OriginStatement;
import org.apache.doris.qe.QueryState;
import org.apache.doris.qe.SessionVariable;
import org.apache.doris.qe.SqlModeHelper;
import org.apache.doris.qe.StmtExecutor;
import org.apache.doris.thrift.TMasterOpRequest;
import org.apache.doris.thrift.TMasterOpResult;

import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.ConsoleErrorListener;
import org.antlr.v4.runtime.ParserRuleContext;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

class LicenseSqlParserTest {
    @Test
    void ordinaryLicenseIdentifiersStillUseConfiguredDialectPlugin() {
        SessionVariable session = new SessionVariable();
        session.setSqlDialect("presto");
        Env env = Mockito.mock(Env.class);
        PluginMgr plugins = Mockito.mock(PluginMgr.class);
        DialectConverterPlugin plugin = Mockito.mock(DialectConverterPlugin.class);
        StatementBase converted = Mockito.mock(StatementBase.class);
        Mockito.when(env.getPluginMgr()).thenReturn(plugins);
        Mockito.when(plugins.getActiveDialectPluginList(Dialect.PRESTO)).thenReturn(Collections.singletonList(plugin));
        String ordinary = "SELECT transform(ARRAY[1,2], x -> x + 1), 'license admin'";
        Mockito.when(plugin.parseSqlWithDialect(ordinary, session)).thenReturn(Collections.singletonList(converted));
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            Assertions.assertSame(converted, new NereidsParser().parseSQL(ordinary, session).get(0));
            Assertions.assertEquals(1, new NereidsParser().parseSQL("SHOW LICENSE", session).size());
            Mockito.verify(plugin).parseSqlWithDialect(ordinary, session);
            Mockito.verifyNoMoreInteractions(plugin);
        }
    }

    @Test
    void converterFailuresDoNotLogSensitiveInputOrExceptionDetails() throws Exception {
        String sql = "SELECT 'ADMIN IMPORT LICENSE private.payload.signature'";
        SessionVariable session = new SessionVariable();
        session.setSqlDialect("presto");
        Env env = Mockito.mock(Env.class);
        PluginMgr plugins = Mockito.mock(PluginMgr.class);
        DialectConverterPlugin plugin = Mockito.mock(DialectConverterPlugin.class);
        Mockito.when(env.getPluginMgr()).thenReturn(plugins);
        Mockito.when(plugins.getActiveDialectPluginList(Dialect.PRESTO)).thenReturn(Collections.singletonList(plugin));
        Mockito.when(plugin.convertSql(sql, session)).thenThrow(new IllegalArgumentException(sql));
        List<LogEvent> events = new CopyOnWriteArrayList<>();
        CountDownLatch logged = new CountDownLatch(1);
        AbstractAppender capture = new AbstractAppender("license-converter-errors", null, null, false,
                Property.EMPTY_ARRAY) {
            @Override
            public void append(LogEvent event) {
                events.add(event.toImmutable());
                logged.countDown();
            }
        };
        Logger logger = (Logger) LogManager.getLogger(SqlDialectHelper.class);
        Level original = logger.getLevel();
        capture.start();
        logger.addAppender(capture);
        logger.setLevel(Level.WARN);
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            Assertions.assertEquals(sql, SqlDialectHelper.convertSqlByDialect(sql, session));
            Assertions.assertTrue(logged.await(2, TimeUnit.SECONDS));
            for (LogEvent event : events) {
                Assertions.assertFalse(event.getMessage().getFormattedMessage().contains("private.payload.signature"));
                Assertions.assertNull(event.getThrown());
            }
        } finally {
            logger.removeAppender(capture);
            logger.setLevel(original);
            capture.stop();
        }
    }

    @Test
    void allEightFrozenCommandsReachTheirSharedAction() {
        Map<String, Action> commands = new LinkedHashMap<>();
        commands.put("SHOW LICENSE", Action.STATUS);
        commands.put("SHOW LICENSE DEPLOYMENT", Action.DEPLOYMENT);
        commands.put("ADMIN IMPORT LICENSE 'a.b.c'", Action.IMPORT);
        commands.put("ADMIN VALIDATE LICENSE 'a.b.c'", Action.VALIDATE);
        commands.put("SHOW LICENSE IMPORT 'fingerprint'", Action.IMPORT_RECEIPT);
        commands.put("ADMIN LICENSE CLOCK CHALLENGE", Action.CLOCK_CHALLENGE);
        commands.put("ADMIN REPAIR LICENSE CLOCK 'a.b.c'", Action.CLOCK_REPAIR);
        commands.put("SHOW LICENSE CLOCK REPAIR 'repair-id'", Action.CLOCK_REPAIR_RECEIPT);
        commands.forEach((sql, action) -> {
            LicenseCommand command = (LicenseCommand) new NereidsParser().parseSingle(sql);
            Assertions.assertEquals(action, command.getAction());
            Assertions.assertFalse(command.toString().contains("a.b.c"));
        });
    }

    @Test
    void newWordsRemainUsableAsUnquotedIdentifiers() {
        Assertions.assertNotNull(new NereidsParser().parseSingle(
                "SELECT license, import, validate, deployment, clock, challenge FROM license"));
    }

    @Test
    void multiStatementAndCommentSyntaxAreAccepted() {
        Assertions.assertEquals(3, new NereidsParser().parseMultiple(
                "SELECT 1; ADMIN /* c */ IMPORT LICENSE 'a.b.c'; SHOW LICENSE").size());
    }

    @Test
    void hintSensitivityIsCheckedOnceAndOnlyWhenHintsExist() {
        String noHint = "SELECT 1 /* ordinary comment */";
        try (MockedStatic<LicenseSqlRedactor> redactor = Mockito.mockStatic(
                LicenseSqlRedactor.class, Mockito.CALLS_REAL_METHODS)) {
            Assertions.assertTrue(NereidsParser.getHintMap(noHint, tokens(noHint), DorisParser::selectHint).isEmpty());
            redactor.verifyNoInteractions();
        }
        String hints = "SELECT /*+ SET_VAR(query_timeout=10) */ 1 UNION ALL "
                + "SELECT /*+ SET_VAR(query_timeout=20) */ 2";
        for (boolean sensitive : new boolean[] {false, true}) {
            String sql = hints + (sensitive ? "; ADMIN IMPORT LICENSE 'private.payload.signature'" : "");
            try (MockedStatic<LicenseSqlRedactor> redactor = Mockito.mockStatic(
                    LicenseSqlRedactor.class, Mockito.CALLS_REAL_METHODS)) {
                Map<Integer, ParserRuleContext> parsed = NereidsParser.getHintMap(sql, tokens(sql), parser -> {
                    if (sensitive) {
                        Assertions.assertTrue(parser.getErrorListeners().stream()
                                .noneMatch(ConsoleErrorListener.class::isInstance));
                        DorisLexer lexer = (DorisLexer) parser.getInputStream().getTokenSource();
                        Assertions.assertTrue(lexer.getErrorListeners().stream()
                                .noneMatch(ConsoleErrorListener.class::isInstance));
                    }
                    return parser.selectHint();
                });
                Assertions.assertEquals(2, parsed.size());
                Assertions.assertTrue(parsed.containsKey(sql.indexOf("/*+")));
                Assertions.assertTrue(parsed.containsKey(sql.lastIndexOf("/*+")));
                redactor.verify(() -> LicenseSqlRedactor.isSensitive(sql), Mockito.times(1));
            }
        }
    }

    @Test
    void invalidHintsKeepUpstreamRecoveryWithoutPrintingCertificateText() throws Exception {
        String sql = "SELECT /*+ SET_VAR(query_timeout=10 */ 1; "
                + "ADMIN /*+ SET_VAR(secret='private.payload.signature' */ IMPORT LICENSE 'a.b.c'";
        ByteArrayOutputStream diagnostics = new ByteArrayOutputStream();
        PrintStream original = System.err;
        ConnectContext previous = ConnectContext.get();
        try (PrintStream capture = new PrintStream(diagnostics, true, StandardCharsets.UTF_8.name())) {
            // SET_VAR applies during plan construction and requires a real connection context.
            new ConnectContext().setThreadLocalInfo();
            System.setErr(capture);
            Map<Integer, ParserRuleContext> hints = NereidsParser.getHintMap(sql, tokens(sql), parser -> {
                ParserRuleContext result = parser.selectHint();
                Assertions.assertTrue(parser.getNumberOfSyntaxErrors() > 0);
                return result;
            });
            Assertions.assertEquals(2, hints.size());
            Assertions.assertEquals(2, new NereidsParser().parseMultiple(sql).size());
        } finally {
            System.setErr(original);
            if (previous == null) {
                ConnectContext.remove();
            } else {
                previous.setThreadLocalInfo();
            }
        }
        Assertions.assertEquals("", diagnostics.toString(StandardCharsets.UTF_8.name()));
    }

    @Test
    void ordinaryLicenseMetadataRetainsDetailedSyntaxErrors() {
        for (String sql : new String[] {"SHOW CREATE TABLE license", "SHOW FULL COLUMNS FROM license",
                "SELECT * FROM license WHERE creator='admin'"}) {
            Assertions.assertNotNull(new NereidsParser().parseSingle(sql));
        }
        SyntaxParseException error = Assertions.assertThrows(SyntaxParseException.class,
                () -> new NereidsParser().parseSingle("SHOW CREATE TABLE license unexpected_token"));
        Assertions.assertFalse(error.getMessage().contains("certificate text redacted"));
        Assertions.assertTrue(error.getMessage().contains("unexpected_token"));
    }

    @Test
    void sensitiveBatchesKeepCompleteOriginsAndStatementIndexesThroughExecution() throws Exception {
        SessionVariable session = new SessionVariable();
        session.setEnableSqlCache(false);
        ConnectContext context = context(session);
        Env env = Mockito.mock(Env.class, Mockito.RETURNS_DEEP_STUBS);
        Mockito.when(env.isMaster()).thenReturn(true);
        String ambiguous = "SELECT 1; ADMIN IMPORT LICENSE /* outer /* inner */ ; */ "
                + "'private.payload.signature'; SELECT '\\'; SELECT 'two'";
        List<String> unsafeFragments = SqlUtils.splitMultiStmts(ambiguous);
        Assertions.assertEquals(4, unsafeFragments.size());
        Assertions.assertTrue(unsafeFragments.stream().anyMatch(fragment ->
                fragment.contains("private.payload.signature") && !LicenseSqlRedactor.isSensitive(fragment)));
        try (MockedStatic<Env> currentEnv = Mockito.mockStatic(Env.class);
                MockedStatic<ConnectContext> current = Mockito.mockStatic(ConnectContext.class);
                MockedStatic<SqlUtils> separator = Mockito.mockStatic(SqlUtils.class, Mockito.CALLS_REAL_METHODS)) {
            currentEnv.when(Env::getCurrentEnv).thenReturn(env);
            current.when(ConnectContext::get).thenReturn(context);
            for (long mode : new long[] {0, SqlModeHelper.MODE_NO_BACKSLASH_ESCAPES}) {
                session.setSqlMode(mode);
                List<String> packets = new ArrayList<>();
                for (String before : new String[] {"SELECT 1", "SELECT 'quote'';inside'", "SELECT `quote\\`",
                        "SELECT 1 /* outer /* inner */ ; hidden separator */",
                        "SELECT 1 -- continued\\\n ; hidden separator\n"}) {
                    packets.add(before + "; ADMIN IMPORT LICENSE 'private.payload.signature'; SELECT 2");
                }
                if (mode == SqlModeHelper.MODE_NO_BACKSLASH_ESCAPES) {
                    packets.add(ambiguous);
                }
                for (String sql : packets) {
                    int statementCount = new NereidsParser().parseMultiple(sql).size();
                    Assertions.assertEquals(sql.equals(ambiguous) ? 4 : 3, statementCount);
                    RecordingProcessor processor = new RecordingProcessor(context);
                    try (MockedConstruction<StmtExecutor> executors = Mockito.mockConstruction(StmtExecutor.class,
                            (executor, construction) -> {
                                StatementBase statement = (StatementBase) construction.arguments().get(1);
                                Mockito.when(executor.getParsedStmt()).thenReturn(statement);
                                Mockito.when(executor.getProfile()).thenReturn(new Profile(false, 1, 0));
                            })) {
                        processor.executeQuery(sql);
                        Assertions.assertEquals(statementCount, executors.constructed().size(), sql);
                        Assertions.assertEquals(statementCount, processor.origins.size(), sql);
                        for (int i = 0; i < processor.origins.size(); i++) {
                            OriginStatement origin = processor.origins.get(i);
                            Assertions.assertEquals(sql, origin.originStmt);
                            Assertions.assertEquals(i, origin.idx);
                            Assertions.assertEquals(LicenseSqlRedactor.REDACTED, origin.getSafeSql());
                            Assertions.assertEquals(LicenseSqlRedactor.REDACTED, processor.auditSql.get(i));
                        }
                    }
                }
            }
            separator.verifyNoInteractions();
        }
    }

    @Test
    void forwardedOrdinaryErrorsKeepUpstreamMappingWhileLicenseReasonsSurvive() throws Exception {
        SessionVariable session = new SessionVariable();
        ConnectContext context = context(session);
        Env env = Mockito.mock(Env.class, Mockito.RETURNS_DEEP_STUBS);
        UserException ordinary = new UserException("ordinary access failure");
        ordinary.setMysqlErrorCode(ErrorCode.ERR_SPECIFIC_ACCESS_DENIED_ERROR);
        LicenseSqlException license = new LicenseSqlException(6200,
                Collections.singletonMap("reason", "LICENSE_EXPIRED"));
        try (MockedStatic<Env> current = Mockito.mockStatic(Env.class)) {
            current.when(Env::getCurrentEnv).thenReturn(env);
            for (Exception failure : new Exception[] {ordinary, new IllegalStateException("ordinary failure"),
                    new IllegalStateException("wrapper", license)}) {
                try (MockedConstruction<StmtExecutor> executors = Mockito.mockConstruction(StmtExecutor.class,
                        (executor, construction) -> Mockito.doThrow(failure).when(executor)
                                .queryRetry(Mockito.any()))) {
                    TMasterOpRequest request = new TMasterOpRequest();
                    request.setSql("SELECT 1");
                    request.setUser("root");
                    TMasterOpResult result = new RecordingProcessor(context).proxyExecute(request);
                    Assertions.assertEquals(1, executors.constructed().size());
                    if (failure.getCause() == license) {
                        Assertions.assertEquals(6200, result.getStatusCode());
                        Assertions.assertEquals(license.getMessage(), result.getErrMessage());
                    } else {
                        Assertions.assertEquals(1105, result.getStatusCode());
                        Assertions.assertEquals("Unexpected exception: " + failure.getMessage(),
                                result.getErrMessage());
                    }
                }
            }
        }
    }

    private static ConnectContext context(SessionVariable session) {
        ConnectContext context = Mockito.mock(ConnectContext.class, Mockito.RETURNS_DEEP_STUBS);
        Mockito.when(context.getSessionVariable()).thenReturn(session);
        Mockito.when(context.getState()).thenReturn(new QueryState());
        return context;
    }

    private static class RecordingProcessor extends ConnectProcessor {
        private final List<OriginStatement> origins = new ArrayList<>();
        private final List<String> auditSql = new ArrayList<>();

        private RecordingProcessor(ConnectContext context) {
            super(context);
            connectType = ConnectType.MYSQL;
        }

        @Override
        protected void auditAfterExec(String sql, StatementBase statement, Data.PQueryStatistics statistics,
                boolean printFuzzyVariables) {
            origins.add(statement.getOrigStmt());
            auditSql.add(LicenseSqlRedactor.redact(sql));
        }

        @Override
        protected ByteBuffer getResultPacket() {
            return ByteBuffer.allocate(0);
        }
    }

    private static CommonTokenStream tokens(String sql) {
        CommonTokenStream stream = new CommonTokenStream(NereidsParser.scan(sql));
        stream.fill();
        return stream;
    }

    @Test
    void removedPlannerFlagsCannotRouteManagementIntoLegacyParsing() throws Exception {
        SessionVariable session = new SessionVariable();
        Field oldPlanner = SessionVariable.class.getDeclaredField("enableNereidsPlanner");
        oldPlanner.setAccessible(true);
        oldPlanner.setBoolean(session, false);
        session.enableFallbackToOriginalPlanner = true;
        Assertions.assertEquals(1, new NereidsParser().parseSQL("SHOW LICENSE", session).size());
        Assertions.assertEquals(1, new NereidsParser().parseSQL("ADMIN IMPORT LICENSE 'a.b.c'", session).size());
        SyntaxParseException error = Assertions.assertThrows(SyntaxParseException.class,
                () -> new NereidsParser().parseSQL(
                        "ADMIN IMPORT LICENSE 'private.payload.signature' invalid", session));
        Assertions.assertFalse(error.getMessage().contains("private.payload.signature"));
    }

    @Test
    void syntaxFailuresNeverRetainRawCertificateOrUnderlyingTokenErrors() {
        for (String sql : new String[] {
                "ADMIN IMPORT LICENSE 'private.payload.signature' extra",
                "ADMIN VALIDATE LICENSE 'private.payload.signature",
                "ADMIN REPAIR LICENSE CLOCK private.payload.signature",
                "SELECT 1; ADMIN IMPORT LICENSE 'private.payload.signature' invalid",
                "SELECT /*+ SET_VAR(query_timeout=10) */ 1; "
                        + "ADMIN /*+ SET_VAR(secret='private.payload.signature' */ IMPORT LICENSE 'a.b.c'",
                "PREPARE x FROM 'ADMIN IMPORT LICENSE private.payload.signature'",
                "ADMIN IMPORT LICENSE ?"}) {
            SyntaxParseException error = Assertions.assertThrows(SyntaxParseException.class,
                    () -> new NereidsParser().parseSingle(sql));
            Assertions.assertFalse(error.getMessage().contains("private.payload.signature"));
            Assertions.assertNull(error.getCause());
        }
    }

    @Test
    void encryptionBuilderCoversBothCertificateKinds() {
        for (String sql : new String[] {"ADMIN IMPORT LICENSE 'private.payload.signature'",
                "ADMIN VALIDATE LICENSE 'private.payload.signature'",
                "ADMIN REPAIR LICENSE CLOCK 'private.payload.signature'"}) {
            TreeMap<Pair<Integer, Integer>, String> replacements = new TreeMap<>(new Pair.PairComparator<>());
            new NereidsParser().parseForEncryption(sql, replacements);
            Assertions.assertEquals(1, replacements.size());
            Assertions.assertFalse(BaseViewInfo.rewriteSql(replacements, sql).contains("private.payload.signature"));
        }
    }
}
