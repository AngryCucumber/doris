// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

/** Bounded public failure codes; never includes signed payloads, keys or parser input. */
public final class LicenseRepairException extends Exception {
    public enum Code {
        INVALID_TICKET,
        UNTRUSTED_REPAIR_KEY,
        VERIFICATION_UNAVAILABLE,
        NOT_LEADER,
        CHALLENGE_REQUIRED,
        CHALLENGE_EXPIRED,
        CHALLENGE_MISMATCH,
        LOCAL_TIME_OUTSIDE_REPAIR_WINDOW,
        REPAIR_ALREADY_CONSUMED,
        STALE_PREPARATION,
        COMMIT_UNCERTAIN,
        STORE_UNAVAILABLE,
        VERSION_EXHAUSTED
    }

    private final Code code;

    public LicenseRepairException(Code code) {
        super(code.name());
        this.code = code;
    }

    public Code getCode() {
        return code;
    }
}
