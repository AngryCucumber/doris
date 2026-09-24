// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Structured safe error. Never attach a parser/provider exception containing request input. */
public final class LicenseManagementException extends Exception {
    private final String reason;
    private final int httpStatus;
    private final int sqlErrorCode;
    private final String sqlState;
    private final int retryAfterSeconds;
    private final Map<String, Object> body;

    public LicenseManagementException(String reason, int httpStatus, String submissionStatus,
            String fingerprint, long committedVersion, long appliedVersion) {
        this(reason, httpStatus, submissionStatus, fingerprint, null, committedVersion, appliedVersion);
    }

    public LicenseManagementException(String reason, int httpStatus, String submissionStatus,
            String fingerprint, String repairId, long committedVersion, long appliedVersion) {
        super(reason);
        if (reason == null || !reason.matches("LICENSE_[A-Z0-9_]+")) {
            throw new IllegalArgumentException("Invalid public license reason");
        }
        this.reason = reason;
        this.httpStatus = httpStatus;
        boolean history = reason.endsWith("HISTORY_UNAVAILABLE");
        sqlErrorCode = history ? 6204 : httpStatus == 409 ? 6202
                : httpStatus == 429 || httpStatus == 503 ? 6203 : 6201;
        sqlState = sqlErrorCode == 6202 ? "40001" : sqlErrorCode >= 6203 ? "HY000" : "45000";
        retryAfterSeconds = httpStatus == 429 ? 6 : 0;
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("reason", reason);
        values.put("message", reason);
        values.put("retryable", httpStatus == 409 || httpStatus == 429 || httpStatus == 503
                || (httpStatus == 202 && "COMMITTED".equals(submissionStatus)));
        values.put("submission_status", submissionStatus);
        values.put("fingerprint", fingerprint);
        if (repairId != null) {
            values.put("repair_id", repairId);
        }
        values.put("committed_version", committedVersion);
        values.put("applied_version", appliedVersion);
        body = Collections.unmodifiableMap(values);
    }

    public String getReason() {
        return reason;
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public int getSqlErrorCode() {
        return sqlErrorCode;
    }

    public String getSqlState() {
        return sqlState;
    }

    public int getRetryAfterSeconds() {
        return retryAfterSeconds;
    }

    public Map<String, Object> getBody() {
        return body;
    }
}
