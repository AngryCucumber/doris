// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package org.apache.doris.massdblicense;

import org.apache.doris.common.ErrorCode;
import org.apache.doris.common.UserException;

/** Stable component-public error returned when the local License decision denies a read. */
public final class MassDbLicenseQueryException extends UserException {
    private final String licenseErrorCode;

    public MassDbLicenseQueryException(String licenseErrorCode) {
        super(message(licenseErrorCode));
        this.licenseErrorCode = licenseErrorCode;
        setMysqlErrorCode(ErrorCode.ERR_MASSDB_LICENSE_QUERY_DENIED);
    }

    public String getLicenseErrorCode() {
        return licenseErrorCode;
    }

    public static String message(String code) {
        String detail;
        if ("MASSDB_LICENSE_EXPIRED".equals(code)) {
            detail = "MassDB License has expired; business queries are unavailable";
        } else if ("MASSDB_LICENSE_MISSING".equals(code)
                || "MASSDB_LICENSE_REQUIRED".equals(code)) {
            detail = "MassDB License has not been imported; business queries are unavailable";
        } else if ("MASSDB_LICENSE_CLOCK_ROLLBACK".equals(code)) {
            detail = "MassDB License clock rollback protection is active; business queries are unavailable";
        } else if ("MASSDB_LICENSE_CONTROL_PLANE_STALE".equals(code)) {
            detail = "MassDB License control-plane state is stale; business queries are unavailable";
        } else {
            detail = "MassDB License is invalid; business queries are unavailable";
        }
        return code + ": " + detail;
    }
}
