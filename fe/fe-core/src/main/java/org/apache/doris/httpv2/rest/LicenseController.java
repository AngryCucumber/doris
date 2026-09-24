// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.httpv2.rest;

import org.apache.doris.analysis.UserIdentity;
import org.apache.doris.catalog.Env;
import org.apache.doris.cluster.ClusterNamespace;
import org.apache.doris.common.Config;
import org.apache.doris.httpv2.exception.UnauthorizedException;
import org.apache.doris.massdb.license.LicenseConfirmationIds;
import org.apache.doris.massdb.license.LicenseFeCompatibility;
import org.apache.doris.massdb.license.LicenseManagementException;
import org.apache.doris.massdb.license.LicenseManagementResult;
import org.apache.doris.massdb.license.LicenseManager.Action;
import org.apache.doris.massdb.license.LicenseVerifier;
import org.apache.doris.mysql.privilege.PrivPredicate;
import org.apache.doris.qe.ConnectContext;
import org.apache.doris.system.Frontend;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.Header;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.impl.conn.DefaultManagedHttpClientConnection;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** Bounded management adapter. Certificate bodies and credentials are never included in diagnostic messages. */
@RestController
@RequestMapping("/api/license")
public class LicenseController extends RestBaseController {
    public static final String CLUSTER_TOKEN = "X-MassDB-License-Cluster-Token";
    static final String FORWARDED_FOR = "X-MassDB-License-Forwarded-For";
    static final String FORWARDED_IDENTITY = "X-MassDB-License-Forwarded-Identity";
    static final String CSRF_HEADER = "X-MassDB-License-CSRF";
    static final int MAX_BODY_BYTES = 96 * 1024;
    private static final int MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(16)
                    .maxDocumentLength(MAX_RESPONSE_BYTES).maxStringLength(MAX_BODY_BYTES)
                    .maxNumberLength(20).maxNameLength(128).build()).build());

    @GetMapping
    public ResponseEntity<?> status(HttpServletRequest request, HttpServletResponse response) {
        return handle(Action.STATUS, null, request, response);
    }

    @GetMapping("/deployment")
    public ResponseEntity<?> deployment(HttpServletRequest request, HttpServletResponse response) {
        return handle(Action.DEPLOYMENT, null, request, response);
    }

    @PostMapping("/validate")
    public ResponseEntity<?> validate(HttpServletRequest request, HttpServletResponse response) {
        return handle(Action.VALIDATE, null, request, response);
    }

    @PostMapping("/import")
    public ResponseEntity<?> importCertificate(HttpServletRequest request, HttpServletResponse response) {
        return handle(Action.IMPORT, null, request, response);
    }

    @GetMapping("/imports/{fingerprint}")
    public ResponseEntity<?> importReceipt(@PathVariable("fingerprint") String fingerprint,
            HttpServletRequest request, HttpServletResponse response) {
        return handle(Action.IMPORT_RECEIPT, fingerprint, request, response);
    }

    @PostMapping("/clock/challenge")
    public ResponseEntity<?> challenge(HttpServletRequest request, HttpServletResponse response) {
        return handle(Action.CLOCK_CHALLENGE, null, request, response);
    }

    @PostMapping("/clock/repair")
    public ResponseEntity<?> repair(HttpServletRequest request, HttpServletResponse response) {
        return handle(Action.CLOCK_REPAIR, null, request, response);
    }

    @GetMapping("/clock/repairs/{repairId}")
    public ResponseEntity<?> repairReceipt(@PathVariable("repairId") String repairId,
            HttpServletRequest request, HttpServletResponse response) {
        return handle(Action.CLOCK_REPAIR_RECEIPT, repairId, request, response);
    }

    /** Read-only upgrade probe; the existing cluster token does not grant license mutation privileges. */
    @GetMapping("/capability")
    public ResponseEntity<?> capability(HttpServletRequest request, HttpServletResponse response) {
        ConnectContext previous = ConnectContext.get();
        try {
            if (request.getHeader(CLUSTER_TOKEN) != null) {
                checkForwardingPeer(request);
            } else {
                authenticate(request, response);
                if (!isAdministrator()) {
                    return failure(403, "ACCESS_DENIED", "ADMIN privilege is required", false, false);
                }
            }
            return response(200, environment().getLicenseManager().capability(), null);
        } catch (UnauthorizedException e) {
            return failure(401, "UNAUTHENTICATED", "Authentication failed", false, false);
        } catch (RuntimeException e) {
            return failure(503, "LICENSE_NOT_READY", "License capability is unavailable", true, false);
        } finally {
            restoreContext(previous);
        }
    }

    private ResponseEntity<?> handle(Action action, String identifier,
            HttpServletRequest request, HttpServletResponse response) {
        ConnectContext previous = ConnectContext.get();
        try {
            if (request.getContentLengthLong() > MAX_BODY_BYTES) {
                throw new BadLicenseRequest("LICENSE_BODY_TOO_LARGE");
            }
            ActionAuthorizationInfo credentials = authenticate(request, response);
            boolean admin = isAdministrator();
            if (action != Action.STATUS && !admin) {
                return failure(403, "ACCESS_DENIED", "ADMIN privilege is required", false, false);
            }
            boolean write = "POST".equals(request.getMethod());
            if (write && !isForwarded(request)) {
                checkWriteOrigin(request);
            }
            String payload = identifier;
            byte[] body = new byte[0];
            if (write) {
                body = readBounded(request.getInputStream(), MAX_BODY_BYTES);
                payload = parsePayload(action, body);
            } else if (identifier != null && !validIdentifier(action, identifier)) {
                throw new BadLicenseRequest("LICENSE_INVALID_IDENTIFIER");
            }
            if (action != Action.STATUS && !environment().isMaster()) {
                if (isForwarded(request)) {
                    return failure(503, "LICENSE_NOT_READY", "Master changed; query the receipt", true, false);
                }
                return forward(action, payload, body, credentials, request);
            }
            LicenseManagementResult result = execute(action, payload,
                    ConnectContext.get().getCurrentUserIdentity().toString(), admin);
            return response(result.getHttpStatus(), result.getBody(), null);
        } catch (BadLicenseRequest e) {
            return failure(400, e.reason, "Invalid license request", false, false);
        } catch (UnauthorizedException e) {
            return failure(401, "UNAUTHENTICATED", "Authentication failed", false, false);
        } catch (CsrfFailure e) {
            return failure(403, "CSRF_REJECTED", "Same-origin license request is required", false, false);
        } catch (LicenseManagementException e) {
            return response(e.getHttpStatus(), e.getBody(),
                    e.getRetryAfterSeconds() > 0 ? Integer.toString(e.getRetryAfterSeconds()) : null);
        } catch (IOException e) {
            return failure(400, "LICENSE_INVALID_REQUEST", "License request could not be read", false, false);
        } catch (RuntimeException e) {
            return failure(503, "LICENSE_NOT_READY", "License management is unavailable", true, false);
        } finally {
            restoreContext(previous);
        }
    }

    protected Env environment() {
        return Env.getCurrentEnv();
    }

    protected LicenseManagementResult execute(Action action, String payload, String principal, boolean administrator)
            throws LicenseManagementException {
        return environment().getLicenseManager().execute(action, payload, principal, administrator);
    }

    protected boolean isAdministrator() {
        return environment().getAccessManager().checkGlobalPriv(
                ConnectContext.get().getCurrentUserIdentity(), PrivPredicate.ADMIN);
    }

    protected ActionAuthorizationInfo authenticate(HttpServletRequest request, HttpServletResponse response) {
        boolean forwarded = isForwarded(request);
        if (forwarded) {
            checkForwardingPeer(request);
        }
        ActionAuthorizationInfo credentials;
        if (request.getHeader("Authorization") != null) {
            credentials = getAuthorizationInfo(request);
            if (forwarded) {
                String originalIp = request.getHeader(FORWARDED_FOR);
                if (originalIp == null || originalIp.length() > 64 || !originalIp.matches("[0-9A-Fa-f:.]+")) {
                    throw new UnauthorizedException("Invalid original source");
                }
                credentials.remoteIp = originalIp;
            }
            UserIdentity identity = checkPassword(credentials);
            if (forwarded && !encodeIdentity(identity).equals(request.getHeader(FORWARDED_IDENTITY))) {
                throw new UnauthorizedException("Original identity changed");
            }
            ConnectContext context = new ConnectContext();
            context.setEnv(environment());
            context.setRemoteIP(credentials.remoteIp);
            context.setCurrentUserIdentity(identity);
            context.setThreadLocalInfo();
        } else {
            if (forwarded) {
                throw new UnauthorizedException("Forwarded credentials are required");
            }
            credentials = checkWithCookie(request, response, false);
            // A cookie authenticates the existing Web session. The Master still rechecks its password on forwarding.
            credentials.remoteIp = request.getRemoteAddr();
        }
        return credentials;
    }

    /** BaseController's malformed-header diagnostic contains the header; never use it for this adapter. */
    @Override
    public ActionAuthorizationInfo getAuthorizationInfo(HttpServletRequest request) {
        try {
            String header = request.getHeader("Authorization");
            if (header == null || header.length() > 16 * 1024 || !header.regionMatches(true, 0, "Basic ", 0, 6)) {
                throw new IllegalArgumentException();
            }
            String decoded = decodeUtf8(Base64.getDecoder().decode(header.substring(6)));
            int separator = decoded.indexOf(':');
            if (separator < 1 || decoded.indexOf('\0') >= 0) {
                throw new IllegalArgumentException();
            }
            ActionAuthorizationInfo auth = new ActionAuthorizationInfo();
            String fullName = decoded.substring(0, separator);
            int clusterSeparator = fullName.indexOf('@');
            auth.fullUserName = ClusterNamespace.getNameFromFullName(
                    clusterSeparator < 0 ? fullName : fullName.substring(0, clusterSeparator));
            auth.password = decoded.substring(separator + 1);
            auth.remoteIp = request.getRemoteAddr();
            return auth;
        } catch (IOException | RuntimeException e) {
            throw new UnauthorizedException("Invalid authentication information");
        }
    }

    protected void checkForwardingPeer(HttpServletRequest request) {
        String expected = environment().getToken();
        String actual = request.getHeader(CLUSTER_TOKEN);
        if (expected == null || expected.isEmpty() || actual == null || actual.length() > 4096
                || !MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                        actual.getBytes(StandardCharsets.UTF_8))) {
            throw new UnauthorizedException("Invalid FE authentication");
        }
        final InetAddress peer;
        try {
            peer = InetAddress.getByName(request.getRemoteAddr());
        } catch (IOException e) {
            throw new UnauthorizedException("Invalid FE source");
        }
        for (Frontend frontend : environment().getFrontends(null)) {
            try {
                for (InetAddress address : InetAddress.getAllByName(frontend.getHost())) {
                    if (address.equals(peer)) {
                        return;
                    }
                }
            } catch (IOException ignored) {
                // An unresolved registration cannot authenticate a caller.
            }
        }
        throw new UnauthorizedException("Unregistered FE source");
    }

    private static boolean isForwarded(HttpServletRequest request) {
        return request.getHeader(CLUSTER_TOKEN) != null || request.getHeader(FORWARDED_FOR) != null
                || request.getHeader(FORWARDED_IDENTITY) != null;
    }

    static void checkWriteOrigin(HttpServletRequest request) {
        boolean cookie = request.getHeader("Authorization") == null;
        String origin = request.getHeader("Origin");
        if (origin != null || cookie) {
            try {
                URI uri = new URI(origin == null ? "" : origin);
                int port = uri.getPort() == -1 ? ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80) : uri.getPort();
                if (uri.getHost() == null || uri.getUserInfo() != null || uri.getQuery() != null
                        || uri.getFragment() != null || (uri.getPath() != null && !uri.getPath().isEmpty())
                        || !request.getScheme().equalsIgnoreCase(uri.getScheme())
                        || !request.getServerName().equalsIgnoreCase(uri.getHost())
                        || request.getServerPort() != port) {
                    throw new CsrfFailure();
                }
            } catch (java.net.URISyntaxException e) {
                throw new CsrfFailure();
            }
        }
        if (cookie && !"1".equals(request.getHeader(CSRF_HEADER))) {
            throw new CsrfFailure();
        }
    }

    static String parsePayload(Action action, byte[] body) throws BadLicenseRequest {
        try {
            if (action == Action.CLOCK_CHALLENGE && body.length == 0) {
                return null;
            }
            try (JsonParser parser = JSON.createParser(decodeUtf8(body))) {
                JsonNode object = JSON.readTree(parser);
                if (object == null || !object.isObject() || parser.nextToken() != null) {
                    throw new BadLicenseRequest("LICENSE_INVALID_REQUEST");
                }
                if (action == Action.CLOCK_CHALLENGE) {
                    if (!object.isEmpty()) {
                        throw new BadLicenseRequest("LICENSE_INVALID_REQUEST");
                    }
                    return null;
                }
                String field = action == Action.CLOCK_REPAIR ? "repair_certificate" : "certificate";
                JsonNode certificate = object.get(field);
                if (object.size() != 1 || certificate == null || !certificate.isTextual()
                        || certificate.textValue().isEmpty()) {
                    throw new BadLicenseRequest("LICENSE_INVALID_REQUEST");
                }
                if (certificate.textValue().getBytes(StandardCharsets.UTF_8).length
                        > LicenseVerifier.MAX_COMPACT_LENGTH) {
                    throw new BadLicenseRequest("LICENSE_CERTIFICATE_TOO_LARGE");
                }
                return certificate.textValue();
            }
        } catch (IOException e) {
            throw new BadLicenseRequest("LICENSE_INVALID_REQUEST");
        }
    }

    static byte[] readBounded(InputStream input, int maximum) throws IOException, BadLicenseRequest {
        ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(maximum, 8192));
        byte[] buffer = new byte[8192];
        int size;
        while ((size = input.read(buffer, 0, Math.min(buffer.length, maximum - output.size() + 1))) != -1) {
            if (size > maximum - output.size()) {
                throw new BadLicenseRequest("LICENSE_BODY_TOO_LARGE");
            }
            output.write(buffer, 0, size);
        }
        return output.toByteArray();
    }

    static boolean validIdentifier(Action action, String identifier) {
        return action == Action.IMPORT_RECEIPT ? identifier.matches("[0-9a-f]{64}")
                : identifier.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    }

    protected ResponseEntity<?> forward(Action action, String payload, byte[] body,
            ActionAuthorizationInfo credentials, HttpServletRequest request) {
        try {
            Env env = environment();
            if (!env.isReady() || env.getMasterHttpPort() <= 0 || env.getToken() == null || env.getToken().isEmpty()) {
                return failure(503, "LICENSE_NOT_READY", "Master is unavailable", true, false);
            }
            URI uri = new URI(Config.enable_https ? "https" : "http", null, env.getMasterHost(),
                    masterManagementPort(env), actionPath(action, payload), null, null);
            RequestBuilder outgoing = RequestBuilder.create(request.getMethod()).setUri(uri)
                    .setHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                            (credentials.fullUserName + ":" + credentials.password).getBytes(StandardCharsets.UTF_8)))
                    .setHeader(CLUSTER_TOKEN, env.getToken())
                    .setHeader(FORWARDED_FOR, credentials.remoteIp)
                    .setHeader(FORWARDED_IDENTITY, encodeIdentity(ConnectContext.get().getCurrentUserIdentity()));
            if ("POST".equals(request.getMethod())) {
                outgoing.setEntity(new ByteArrayEntity(body))
                        .setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE);
            }
            RequestConfig config = RequestConfig.custom().setConnectTimeout(3000).setSocketTimeout(15000)
                    .setConnectionRequestTimeout(3000).setAuthenticationEnabled(false).build();
            // The request is already bounded. Disable retries/authentication negotiation so a 401 body is preserved
            // and a dropped response cannot silently submit a management operation a second time.
            // The ordinary HttpClient factory also enables wire/header dumps at DEBUG. Use its non-logging connection
            // implementation here so certificate bodies and authentication headers never reach those loggers.
            BasicHttpClientConnectionManager connections = new BasicHttpClientConnectionManager(
                    RegistryBuilder.<ConnectionSocketFactory>create()
                            .register("http", PlainConnectionSocketFactory.getSocketFactory())
                            .register("https", SSLConnectionSocketFactory.getSystemSocketFactory()).build(),
                    (route, configuration) -> new DefaultManagedHttpClientConnection("license-management", 8192));
            try (CloseableHttpClient client = HttpClients.custom().disableAutomaticRetries().disableRedirectHandling()
                    .disableCookieManagement().disableAuthCaching().setDefaultRequestConfig(config)
                    .setConnectionManager(connections).build()) {
                HttpRequestBase call = (HttpRequestBase) outgoing.build();
                try (CloseableHttpResponse forwarded = client.execute(call)) {
                    try {
                        int status = forwarded.getStatusLine().getStatusCode();
                        if (status < 200 || (status >= 300 && status < 400) || forwarded.getEntity() == null
                                || forwarded.getEntity().getContentLength() > MAX_RESPONSE_BYTES) {
                            return submissionUnknown(action, payload);
                        }
                        Map<String, Object> responseBody = JSON.readValue(
                                readBounded(forwarded.getEntity().getContent(), MAX_RESPONSE_BYTES),
                                new TypeReference<Map<String, Object>>() { });
                        Header retryAfter = forwarded.getFirstHeader("Retry-After");
                        return forwardedResponse(status, responseBody,
                                retryAfter == null ? null : retryAfter.getValue(), env);
                    } finally {
                        // Close the socket before closing an oversized/malformed entity; do not drain unbounded input.
                        call.abort();
                    }
                } finally {
                    call.abort();
                }
            }
        } catch (Exception e) {
            return submissionUnknown(action, payload);
        }
    }

    static int masterManagementPort(Env env) throws IOException {
        if (!Config.enable_https) {
            // This address is published by the current Master; do not replace it with this FE's HTTP configuration.
            return env.getMasterHttpPort();
        }
        Frontend candidate = null;
        boolean ambiguous = false;
        for (Frontend frontend : env.getFrontends(null)) {
            if (frontend.getHost().equals(env.getMasterHost())) {
                if (frontend.getRpcPort() == env.getMasterRpcPort() && frontend.getRpcPort() > 0) {
                    return LicenseFeCompatibility.managementPort(frontend, Config.https_port);
                }
                ambiguous |= candidate != null;
                candidate = frontend;
            }
        }
        if (candidate != null && !ambiguous) {
            return LicenseFeCompatibility.managementPort(candidate, Config.https_port);
        }
        throw new IOException("Master management identity is unavailable");
    }

    private static ResponseEntity<?> forwardedResponse(int status, Map<String, Object> body,
            String retryAfter, Env env) {
        if ((status == 200 || status == 202) && body.get("committed_version") instanceof Number
                && ((Number) body.get("committed_version")).longValue() > 0) {
            long version = ((Number) body.get("committed_version")).longValue();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (env.getLicenseManager().getAppliedVersion() < version && System.nanoTime() < deadline) {
                try {
                    TimeUnit.MILLISECONDS.sleep(10);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    // We already have the Master's commit acknowledgement; cancellation cannot erase that fact.
                    break;
                }
            }
            LicenseManagementResult result = new LicenseManagementResult(status, body)
                    .withLocalAppliedVersion(env.getLicenseManager().getAppliedVersion());
            return response(result.getHttpStatus(), result.getBody(), retryAfter);
        }
        return response(status, body, retryAfter);
    }

    private static String actionPath(Action action, String payload) {
        switch (action) {
            case DEPLOYMENT:
                return "/api/license/deployment";
            case VALIDATE:
                return "/api/license/validate";
            case IMPORT:
                return "/api/license/import";
            case IMPORT_RECEIPT:
                return "/api/license/imports/" + payload;
            case CLOCK_CHALLENGE:
                return "/api/license/clock/challenge";
            case CLOCK_REPAIR:
                return "/api/license/clock/repair";
            case CLOCK_REPAIR_RECEIPT:
                return "/api/license/clock/repairs/" + payload;
            default:
                throw new IllegalArgumentException("Action is local");
        }
    }

    private static ResponseEntity<?> submissionUnknown(Action action, String payload) {
        Map<String, Object> body = errorBody("LICENSE_SUBMISSION_UNKNOWN",
                "Query the receipt before retrying", true, true);
        try {
            if (action == Action.IMPORT) {
                body.put("fingerprint", LicenseVerifier.fingerprint(payload));
            } else if (action == Action.IMPORT_RECEIPT) {
                body.put("fingerprint", payload);
            } else if (action == Action.CLOCK_REPAIR_RECEIPT) {
                body.put("repair_id", payload);
            } else if (action == Action.CLOCK_REPAIR) {
                String repairId = LicenseConfirmationIds.repairIdHint(payload);
                if (repairId != null) {
                    body.put("repair_id", repairId);
                }
            }
        } catch (Exception ignored) {
            // An invalid candidate may not provide a usable receipt identifier.
        }
        return response(503, body, null);
    }

    private static String decodeUtf8(byte[] bytes) throws IOException {
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
    }

    private static String encodeIdentity(UserIdentity identity) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(identity.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static ResponseEntity<?> failure(int status, String reason, String message,
            boolean retryable, boolean unknown) {
        return response(status, errorBody(reason, message, retryable, unknown), null);
    }

    private static Map<String, Object> errorBody(String reason, String message, boolean retryable, boolean unknown) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("reason", reason);
        body.put("message", message);
        body.put("retryable", retryable);
        body.put("submission_status", unknown ? "UNKNOWN" : "NOT_SUBMITTED");
        body.put("committed_version", null);
        body.put("applied_version", null);
        return body;
    }

    private static ResponseEntity<?> response(int status, Map<String, Object> body, String retryAfter) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setCacheControl("no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        if (retryAfter != null && retryAfter.matches("[0-9]{1,6}")) {
            headers.set("Retry-After", retryAfter);
        }
        return ResponseEntity.status(status).headers(headers).body(body);
    }

    private static void restoreContext(ConnectContext previous) {
        if (previous == null) {
            ConnectContext.remove();
        } else {
            previous.setThreadLocalInfo();
        }
    }

    static final class BadLicenseRequest extends IOException {
        final String reason;

        BadLicenseRequest(String reason) {
            super("Invalid license request");
            this.reason = reason;
        }
    }

    static final class CsrfFailure extends RuntimeException {
    }
}
