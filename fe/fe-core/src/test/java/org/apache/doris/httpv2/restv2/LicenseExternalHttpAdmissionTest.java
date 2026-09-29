// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.httpv2.restv2;

import org.apache.doris.analysis.BrokerDesc;
import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;
import org.apache.doris.common.parquet.ParquetReader;
import org.apache.doris.common.util.BrokerUtil;
import org.apache.doris.datasource.CatalogMgr;
import org.apache.doris.datasource.es.EsExternalCatalog;
import org.apache.doris.datasource.es.EsRestClient;
import org.apache.doris.httpv2.entity.ResponseBody;
import org.apache.doris.httpv2.exception.UnauthorizedException;
import org.apache.doris.httpv2.rest.RestApiStatusCode;
import org.apache.doris.massdb.license.LicenseManager;
import org.apache.doris.massdb.license.LicenseQueryStatus;
import org.apache.doris.thrift.TBrokerFileStatus;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.http.ResponseEntity;

import java.io.BufferedReader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

class LicenseExternalHttpAdmissionTest {
    private static final String SEARCH_BODY = "{\"query\":{\"match_all\":{}}}";
    private static final String SEARCH_RESULT = "{\"hits\":{\"hits\":[{\"_source\":{\"value\":\"sample\"}}]}}";
    private static final String FILE_PATH = "hdfs://preview.invalid/sample";
    private static final List<List<String>> SAMPLE = Collections.singletonList(Arrays.asList("1", "sample"));
    private boolean originalHttpAuth;

    @BeforeEach
    void saveHttpAuth() {
        originalHttpAuth = Config.enable_all_http_auth;
        Config.enable_all_http_auth = false;
    }

    @AfterEach
    void restoreHttpAuth() {
        Config.enable_all_http_auth = originalHttpAuth;
    }

    @Test
    void searchRejectsEveryDeniedStateBeforeAnyEsAccessWithEitherAuthSetting() throws Exception {
        for (boolean authenticate : new boolean[] {false, true}) {
            Config.enable_all_http_auth = authenticate;
            try (Fixture fixture = new Fixture()) {
                int requests = 0;
                for (LicenseQueryStatus status : LicenseQueryStatus.values()) {
                    if (status.permitsNewQuery()) {
                        continue;
                    }
                    Mockito.when(fixture.manager.queryStatus()).thenReturn(status);
                    assertDenied(fixture.esAction.search(fixture.request, fixture.response), status);
                    requests++;
                }
                Assertions.assertEquals(authenticate ? requests : 0, fixture.esAction.authCalls);
                Mockito.verify(fixture.manager, Mockito.times(requests)).queryStatus();
                Mockito.verify(fixture.catalog, Mockito.never()).makeSureInitialized();
                Mockito.verifyNoInteractions(fixture.esClient);
            }
        }
    }

    @Test
    void validAndExpiringSearchPreserveTheExternalResult() throws Exception {
        Config.enable_all_http_auth = true;
        try (Fixture fixture = new Fixture()) {
            for (LicenseQueryStatus status : new LicenseQueryStatus[] {
                    LicenseQueryStatus.VALID, LicenseQueryStatus.EXPIRING}) {
                Mockito.when(fixture.manager.queryStatus()).thenReturn(status);
                assertSearchResult(fixture.esAction.search(fixture.request, fixture.response));
            }
            Assertions.assertEquals(2, fixture.esAction.authCalls);
            Mockito.verify(fixture.catalog, Mockito.times(2)).makeSureInitialized();
            Mockito.verify(fixture.esClient, Mockito.times(2)).searchIndex("index", SEARCH_BODY);
        }
    }

    @Test
    void mappingRemainsAvailableInEveryLicenseState() throws Exception {
        try (Fixture fixture = new Fixture()) {
            for (LicenseQueryStatus status : LicenseQueryStatus.values()) {
                Mockito.when(fixture.manager.queryStatus()).thenReturn(status);
                Map<?, ?> data = (Map<?, ?>) successData(
                        fixture.esAction.getMapping(fixture.request, fixture.response));
                JsonNode mapping = (JsonNode) data.get("result");
                Assertions.assertEquals("keyword", mapping.path("properties").path("value").path("type").asText());
            }
            Mockito.verify(fixture.manager, Mockito.never()).queryStatus();
            Mockito.verify(fixture.esClient, Mockito.times(LicenseQueryStatus.values().length)).getMapping("index");
            Mockito.verify(fixture.esClient, Mockito.never()).searchIndex(Mockito.anyString(), Mockito.anyString());
        }
    }

    @Test
    void mappingRejectsUrlSelectorsBeforeCatalogOrExternalAccess() throws Exception {
        try (Fixture fixture = new Fixture()) {
            // Servlet query parameters are already decoded: %23 arrives here as '#'.
            for (String selector : new String[] {null, "", "_search#", "_search?preference=",
                    "../_search#", "index/_search", "index\\_search", "_search%23", "index%2F_search",
                    " index", "index ", "a\tb", "a\nb", "a\rb", "a\u0000b", "a\u007fb", "a\u00a0b", "a\u2003b"}) {
                Mockito.when(fixture.request.getParameter("table")).thenReturn(selector);
                ResponseEntity<?> response = (ResponseEntity<?>) fixture.esAction.getMapping(
                        fixture.request, fixture.response);
                Assertions.assertEquals(200, response.getStatusCode().value());
                ResponseBody<?> body = (ResponseBody<?>) response.getBody();
                Assertions.assertEquals(RestApiStatusCode.BAD_REQUEST.code, body.getCode(), String.valueOf(selector));
                Assertions.assertEquals("invalid ES index selector", body.getData());
            }
            Mockito.verify(fixture.env, Mockito.never()).getCatalogMgr();
            Mockito.verify(fixture.manager, Mockito.never()).queryStatus();
            Mockito.verifyNoInteractions(fixture.catalog, fixture.esClient);
        }
    }

    @Test
    void mappingAllowsNamesAliasesMultipleIndicesAndPatternsWhenExpired() throws Exception {
        try (Fixture fixture = new Fixture()) {
            Mockito.when(fixture.esClient.getMapping(Mockito.anyString()))
                    .thenReturn("{\"properties\":{\"value\":{\"type\":\"keyword\"}}}");
            for (String selector : new String[] {"index", "read_alias", "logs-2026.09", "logs-a,logs-b",
                    "logs-*", "*", "logs-*,read_alias"}) {
                Mockito.when(fixture.request.getParameter("table")).thenReturn(selector);
                Map<?, ?> data = (Map<?, ?>) successData(
                        fixture.esAction.getMapping(fixture.request, fixture.response));
                Assertions.assertEquals(selector, data.get("table"));
                JsonNode mapping = (JsonNode) data.get("result");
                Assertions.assertEquals("keyword", mapping.path("properties").path("value").path("type").asText());
                Mockito.verify(fixture.esClient).getMapping(selector);
            }
            Mockito.verify(fixture.manager, Mockito.never()).queryStatus();
            Mockito.verify(fixture.esClient, Mockito.never()).searchIndex(Mockito.anyString(), Mockito.anyString());
        }
    }

    @Test
    void sameSearchControllerObservesExpiryAndRenewalOnTheNextRequest() throws Exception {
        try (Fixture fixture = new Fixture()) {
            Mockito.when(fixture.manager.queryStatus()).thenReturn(
                    LicenseQueryStatus.VALID, LicenseQueryStatus.EXPIRED, LicenseQueryStatus.VALID);
            assertSearchResult(fixture.esAction.search(fixture.request, fixture.response));
            assertDenied(fixture.esAction.search(fixture.request, fixture.response), LicenseQueryStatus.EXPIRED);
            assertSearchResult(fixture.esAction.search(fixture.request, fixture.response));
            Mockito.verify(fixture.manager, Mockito.times(3)).queryStatus();
            Mockito.verify(fixture.catalog, Mockito.times(2)).makeSureInitialized();
            Mockito.verify(fixture.esClient, Mockito.times(2)).searchIndex("index", SEARCH_BODY);
        }
    }

    @Test
    void fileReviewRejectsBeforeListingReadingOrOpeningParquetWithEitherAuthSetting() throws Exception {
        for (boolean authenticate : new boolean[] {false, true}) {
            Config.enable_all_http_auth = authenticate;
            try (Fixture fixture = new Fixture();
                    MockedStatic<BrokerUtil> broker = Mockito.mockStatic(BrokerUtil.class);
                    MockedStatic<ParquetReader> parquet = Mockito.mockStatic(ParquetReader.class)) {
                int requests = 0;
                for (LicenseQueryStatus status : LicenseQueryStatus.values()) {
                    if (status.permitsNewQuery()) {
                        continue;
                    }
                    Mockito.when(fixture.manager.queryStatus()).thenReturn(status);
                    for (String format : new String[] {"CSV", "PARQUET"}) {
                        assertDenied(fixture.importAction.fileReview(fileRequest(format),
                                fixture.request, fixture.response), status);
                        requests++;
                    }
                }
                Assertions.assertEquals(authenticate ? requests : 0, fixture.importAction.authCalls);
                Mockito.verify(fixture.manager, Mockito.times(requests)).queryStatus();
                broker.verifyNoInteractions();
                parquet.verifyNoInteractions();
            }
        }
    }

    @Test
    void validAndExpiringCsvPreviewKeepSampleData() throws Exception {
        Config.enable_all_http_auth = true;
        try (Fixture fixture = new Fixture();
                MockedStatic<BrokerUtil> broker = Mockito.mockStatic(BrokerUtil.class);
                MockedStatic<ParquetReader> parquet = Mockito.mockStatic(ParquetReader.class)) {
            prepareCsv(broker);
            for (LicenseQueryStatus status : new LicenseQueryStatus[] {
                    LicenseQueryStatus.VALID, LicenseQueryStatus.EXPIRING}) {
                Mockito.when(fixture.manager.queryStatus()).thenReturn(status);
                assertFileSample(fixture.importAction.fileReview(fileRequest("CSV"),
                        fixture.request, fixture.response));
            }
            Assertions.assertEquals(2, fixture.importAction.authCalls);
            broker.verify(() -> BrokerUtil.parseFile(Mockito.eq(FILE_PATH),
                    Mockito.any(BrokerDesc.class), Mockito.anyList()), Mockito.times(2));
            broker.verify(() -> BrokerUtil.readFile(Mockito.eq(FILE_PATH),
                    Mockito.any(BrokerDesc.class), Mockito.eq(1024L * 1024)), Mockito.times(2));
            parquet.verifyNoInteractions();
        }
    }

    @Test
    void validAndExpiringParquetPreviewKeepSchemaAndRows() throws Exception {
        try (Fixture fixture = new Fixture();
                MockedStatic<BrokerUtil> broker = Mockito.mockStatic(BrokerUtil.class);
                MockedStatic<ParquetReader> parquet = Mockito.mockStatic(ParquetReader.class)) {
            prepareListing(broker);
            ParquetReader reader = Mockito.mock(ParquetReader.class);
            Mockito.when(reader.getSchema(false)).thenReturn(Arrays.asList("id", "value"));
            Mockito.when(reader.getLines(50)).thenReturn(SAMPLE);
            parquet.when(() -> ParquetReader.create(Mockito.eq(FILE_PATH), Mockito.any(BrokerDesc.class)))
                    .thenReturn(reader);
            for (LicenseQueryStatus status : new LicenseQueryStatus[] {
                    LicenseQueryStatus.VALID, LicenseQueryStatus.EXPIRING}) {
                Mockito.when(fixture.manager.queryStatus()).thenReturn(status);
                ImportAction.FileReviewResponseVo data = assertFileSample(fixture.importAction.fileReview(
                        fileRequest("PARQUET"), fixture.request, fixture.response));
                Assertions.assertEquals(Arrays.asList("id", "value"), data.getFileSample().getColNames());
            }
            parquet.verify(() -> ParquetReader.create(Mockito.eq(FILE_PATH), Mockito.any(BrokerDesc.class)),
                    Mockito.times(2));
            Mockito.verify(reader, Mockito.times(2)).getLines(50);
            broker.verify(() -> BrokerUtil.readFile(Mockito.anyString(), Mockito.any(BrokerDesc.class),
                    Mockito.anyLong()), Mockito.never());
        }
    }

    @Test
    void sameFileReviewControllerObservesExpiryAndRenewal() throws Exception {
        try (Fixture fixture = new Fixture();
                MockedStatic<BrokerUtil> broker = Mockito.mockStatic(BrokerUtil.class);
                MockedStatic<ParquetReader> parquet = Mockito.mockStatic(ParquetReader.class)) {
            prepareCsv(broker);
            Mockito.when(fixture.manager.queryStatus()).thenReturn(
                    LicenseQueryStatus.VALID, LicenseQueryStatus.EXPIRED, LicenseQueryStatus.VALID);
            assertFileSample(fixture.importAction.fileReview(fileRequest("CSV"), fixture.request, fixture.response));
            assertDenied(fixture.importAction.fileReview(fileRequest("CSV"), fixture.request, fixture.response),
                    LicenseQueryStatus.EXPIRED);
            assertFileSample(fixture.importAction.fileReview(fileRequest("CSV"), fixture.request, fixture.response));
            Mockito.verify(fixture.manager, Mockito.times(3)).queryStatus();
            broker.verify(() -> BrokerUtil.parseFile(Mockito.eq(FILE_PATH), Mockito.any(BrokerDesc.class),
                    Mockito.anyList()), Mockito.times(2));
            broker.verify(() -> BrokerUtil.readFile(Mockito.eq(FILE_PATH), Mockito.any(BrokerDesc.class),
                    Mockito.anyLong()), Mockito.times(2));
            parquet.verifyNoInteractions();
        }
    }

    @Test
    void enabledAuthenticationRejectsBeforeLicenseOrExternalAccess() throws Exception {
        Config.enable_all_http_auth = true;
        try (Fixture fixture = new Fixture();
                MockedStatic<BrokerUtil> broker = Mockito.mockStatic(BrokerUtil.class);
                MockedStatic<ParquetReader> parquet = Mockito.mockStatic(ParquetReader.class)) {
            fixture.esAction.rejectAuth = true;
            fixture.importAction.rejectAuth = true;
            Assertions.assertThrows(UnauthorizedException.class,
                    () -> fixture.esAction.search(fixture.request, fixture.response));
            Assertions.assertThrows(UnauthorizedException.class, () -> fixture.importAction.fileReview(
                    fileRequest("CSV"), fixture.request, fixture.response));
            Assertions.assertEquals(1, fixture.esAction.authCalls);
            Assertions.assertEquals(1, fixture.importAction.authCalls);
            Mockito.verify(fixture.manager, Mockito.never()).queryStatus();
            Mockito.verify(fixture.catalog, Mockito.never()).makeSureInitialized();
            Mockito.verifyNoInteractions(fixture.esClient);
            broker.verifyNoInteractions();
            parquet.verifyNoInteractions();
        }
    }

    @Test
    void redirectsKeepEachControllersOriginalAuthenticationOrder() throws Exception {
        Config.enable_all_http_auth = true;
        try (Fixture fixture = new Fixture();
                MockedStatic<BrokerUtil> broker = Mockito.mockStatic(BrokerUtil.class);
                MockedStatic<ParquetReader> parquet = Mockito.mockStatic(ParquetReader.class)) {
            fixture.esAction.redirect = true;
            fixture.importAction.redirect = true;
            Assertions.assertSame(fixture.esAction.redirectResponse,
                    fixture.esAction.search(fixture.request, fixture.response));
            Assertions.assertSame(fixture.importAction.redirectResponse, fixture.importAction.fileReview(
                    fileRequest("CSV"), fixture.request, fixture.response));
            Assertions.assertEquals(1, fixture.esAction.authCalls);
            Assertions.assertEquals(0, fixture.importAction.authCalls);
            Mockito.verify(fixture.manager, Mockito.never()).queryStatus();
            Mockito.verify(fixture.catalog, Mockito.never()).makeSureInitialized();
            Mockito.verifyNoInteractions(fixture.esClient);
            broker.verifyNoInteractions();
            parquet.verifyNoInteractions();
        }
    }

    private static void assertDenied(Object result, LicenseQueryStatus status) {
        ResponseEntity<?> response = (ResponseEntity<?>) result;
        Assertions.assertEquals(403, response.getStatusCode().value());
        Map<?, ?> body = (Map<?, ?>) response.getBody();
        String reason = status == LicenseQueryStatus.LICENSE_NOT_READY ? status.name() : "LICENSE_" + status.name();
        Assertions.assertEquals(reason, body.get("reason"));
        Assertions.assertEquals(reason, body.get("message"));
        Assertions.assertEquals(status == LicenseQueryStatus.LICENSE_NOT_READY, body.get("retryable"));
        Assertions.assertFalse(body.containsKey("result"));
        Assertions.assertFalse(body.containsKey("fileSample"));
    }

    private static Object successData(Object result) {
        ResponseEntity<?> response = (ResponseEntity<?>) result;
        Assertions.assertEquals(200, response.getStatusCode().value());
        ResponseBody<?> body = (ResponseBody<?>) response.getBody();
        Assertions.assertEquals(RestApiStatusCode.OK.code, body.getCode());
        return body.getData();
    }

    private static void assertSearchResult(Object result) {
        Map<?, ?> data = (Map<?, ?>) successData(result);
        Assertions.assertEquals("es", data.get("catalog"));
        Assertions.assertEquals("index", data.get("table"));
        JsonNode json = (JsonNode) data.get("result");
        Assertions.assertEquals("sample", json.path("hits").path("hits").get(0).path("_source").path("value").asText());
    }

    private static ImportAction.FileReviewResponseVo assertFileSample(Object result) {
        ImportAction.FileReviewResponseVo data = (ImportAction.FileReviewResponseVo) successData(result);
        Assertions.assertEquals(1, data.getReviewStatistic().getFileNumber());
        Assertions.assertEquals(9L, data.getReviewStatistic().getFileSize());
        Assertions.assertEquals(FILE_PATH, data.getFileSample().getSampleFileName());
        Assertions.assertEquals(1, data.getFileSample().getFileLineNumber());
        Assertions.assertEquals(2, data.getFileSample().getMaxColumnSize());
        Assertions.assertEquals(SAMPLE, data.getFileSample().getSampleFileLines());
        return data;
    }

    private static ImportAction.FileReviewRequestVo fileRequest(String format) {
        ImportAction.FileInfo file = new ImportAction.FileInfo();
        file.setFileUrl(FILE_PATH);
        file.setFormat(format);
        file.setColumnSeparator(",");
        ImportAction.ConnectInfo connection = new ImportAction.ConnectInfo();
        connection.setBrokerName("preview_broker");
        connection.setBrokerProps(Collections.emptyMap());
        ImportAction.FileReviewRequestVo request = new ImportAction.FileReviewRequestVo();
        request.setFileInfo(file);
        request.setConnectInfo(connection);
        return request;
    }

    private static void prepareListing(MockedStatic<BrokerUtil> broker) {
        broker.when(() -> BrokerUtil.parseFile(Mockito.eq(FILE_PATH), Mockito.any(BrokerDesc.class),
                Mockito.anyList())).thenAnswer(invocation -> {
                    List<TBrokerFileStatus> files = invocation.getArgument(2);
                    TBrokerFileStatus file = new TBrokerFileStatus();
                    file.path = FILE_PATH;
                    file.size = 9L;
                    file.isDir = false;
                    files.add(file);
                    return null;
                });
    }

    private static void prepareCsv(MockedStatic<BrokerUtil> broker) {
        prepareListing(broker);
        broker.when(() -> BrokerUtil.readFile(Mockito.eq(FILE_PATH), Mockito.any(BrokerDesc.class),
                Mockito.anyLong())).thenReturn("1,sample\n".getBytes(StandardCharsets.UTF_8));
    }

    private static final class Fixture implements AutoCloseable {
        private final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        private final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        private final Env env = Mockito.mock(Env.class);
        private final LicenseManager manager = Mockito.mock(LicenseManager.class);
        private final EsExternalCatalog catalog = Mockito.mock(EsExternalCatalog.class);
        private final EsRestClient esClient = Mockito.mock(EsRestClient.class);
        private final TestEsAction esAction = new TestEsAction();
        private final TestImportAction importAction = new TestImportAction();
        private final MockedStatic<Env> environment;

        private Fixture() throws Exception {
            CatalogMgr catalogs = Mockito.mock(CatalogMgr.class);
            Mockito.when(env.getLicenseManager()).thenReturn(manager);
            Mockito.when(env.getCatalogMgr()).thenReturn(catalogs);
            Mockito.when(catalogs.getCatalog("es")).thenReturn(catalog);
            Mockito.when(catalog.getEsRestClient()).thenReturn(esClient);
            Mockito.when(esClient.searchIndex("index", SEARCH_BODY)).thenReturn(SEARCH_RESULT);
            Mockito.when(esClient.getMapping("index"))
                    .thenReturn("{\"properties\":{\"value\":{\"type\":\"keyword\"}}}");
            Mockito.when(request.getParameter("catalog")).thenReturn("es");
            Mockito.when(request.getParameter("table")).thenReturn("index");
            Mockito.when(request.getScheme()).thenReturn("http");
            Mockito.when(request.getReader()).thenAnswer(ignored -> new BufferedReader(new StringReader(SEARCH_BODY)));
            Mockito.when(manager.queryStatus()).thenReturn(LicenseQueryStatus.EXPIRED);
            environment = Mockito.mockStatic(Env.class);
            environment.when(Env::getCurrentEnv).thenReturn(env);
        }

        @Override
        public void close() {
            environment.close();
        }
    }

    private static final class TestEsAction extends ESCatalogAction {
        private int authCalls;
        private boolean rejectAuth;
        private boolean redirect;
        private final Object redirectResponse = new Object();

        @Override
        public ActionAuthorizationInfo executeCheckPassword(HttpServletRequest request, HttpServletResponse response) {
            authCalls++;
            if (rejectAuth) {
                throw new UnauthorizedException("original authentication failure");
            }
            return null;
        }

        @Override
        public boolean needRedirect(String scheme) {
            return redirect;
        }

        @Override
        public Object redirectToHttps(HttpServletRequest request) {
            return redirectResponse;
        }
    }

    private static final class TestImportAction extends ImportAction {
        private int authCalls;
        private boolean rejectAuth;
        private boolean redirect;
        private final Object redirectResponse = new Object();

        @Override
        public ActionAuthorizationInfo executeCheckPassword(HttpServletRequest request, HttpServletResponse response) {
            authCalls++;
            if (rejectAuth) {
                throw new UnauthorizedException("original authentication failure");
            }
            return null;
        }

        @Override
        public boolean needRedirect(String scheme) {
            return redirect;
        }

        @Override
        public Object redirectToHttps(HttpServletRequest request) {
            return redirectResponse;
        }
    }
}
