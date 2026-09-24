// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

/** Query entitlement only; these states do not grant database privileges or prohibit writes. */
public enum LicenseQueryStatus {
    VALID,
    EXPIRING,
    MISSING,
    NOT_YET_VALID,
    EXPIRED,
    INVALID,
    FEATURE_NOT_LICENSED,
    LICENSE_NOT_READY,
    CLOCK_SUSPECT,
    LIMIT_EXCEEDED;

    public boolean permitsNewQuery() {
        return this == VALID || this == EXPIRING;
    }
}
