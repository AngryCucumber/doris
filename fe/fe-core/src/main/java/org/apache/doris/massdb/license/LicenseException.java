// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import java.util.Objects;

/** Does not retain parser/provider exceptions, which may contain certificate data. */
public final class LicenseException extends Exception {
    private final LicenseErrorCode errorCode;

    public LicenseException(LicenseErrorCode errorCode) {
        super("License certificate rejected: " + Objects.requireNonNull(errorCode).name());
        this.errorCode = errorCode;
    }

    public LicenseErrorCode getErrorCode() {
        return errorCode;
    }
}
