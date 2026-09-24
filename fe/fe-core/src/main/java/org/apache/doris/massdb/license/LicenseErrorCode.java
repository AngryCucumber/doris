// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

/** Stable, non-sensitive reasons for rejecting a certificate. */
public enum LicenseErrorCode {
    INPUT_TOO_LARGE,
    INVALID_COMPACT,
    INVALID_BASE64URL,
    INVALID_JSON,
    INVALID_HEADER,
    UNTRUSTED_KEY,
    INVALID_SIGNATURE,
    UNSUPPORTED_SCHEMA,
    UNSUPPORTED_POLICY,
    INVALID_CLAIMS,
    VERIFICATION_UNAVAILABLE,
    INVALID_TRUST_STORE,
    KEY_STILL_REQUIRED,
    DEPLOYMENT_MISMATCH,
    IMPORT_NOT_READY,
    CLOCK_SUSPECT,
    ISSUED_IN_FUTURE,
    CERTIFICATE_EXPIRED,
    FEATURE_NOT_LICENSED,
    NODE_LIMIT_TOO_SMALL,
    RENEWAL_REDUCTION,
    IMPORT_CONFLICT,
    IMPORT_HISTORY_UNAVAILABLE,
    STALE_IMPORT_DECISION
}
