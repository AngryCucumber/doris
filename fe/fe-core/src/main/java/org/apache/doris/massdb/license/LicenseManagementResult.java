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

/** Transport-neutral, payload-free management response shared by SQL and HTTP. */
public final class LicenseManagementResult {
    private final int httpStatus;
    private final Map<String, Object> body;

    public LicenseManagementResult(int httpStatus, Map<String, Object> body) {
        this.httpStatus = httpStatus;
        this.body = Collections.unmodifiableMap(new LinkedHashMap<>(body));
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public Map<String, Object> getBody() {
        return body;
    }

    /** A Master's acknowledgement does not prove that the receiving Follower applied it. */
    public LicenseManagementResult withLocalAppliedVersion(long version) {
        Object committed = body.get("committed_version");
        Object submission = body.get("submission_status");
        if (!(committed instanceof Number) || httpStatus < 200 || httpStatus >= 300
                || !("COMMITTED".equals(submission) || "APPLIED".equals(submission))) {
            return this;
        }
        boolean applied = version >= ((Number) committed).longValue();
        Map<String, Object> local = new LinkedHashMap<>(body);
        local.put("applied_version", version);
        local.put("submission_status", applied ? "APPLIED" : "COMMITTED");
        local.put("reason", applied ? "LICENSE_APPLIED" : "LICENSE_COMMITTED_PENDING_APPLY");
        local.put("retryable", !applied);
        return new LicenseManagementResult(applied ? 200 : 202, local);
    }
}
