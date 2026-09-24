// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.common.ErrorCode;
import org.apache.doris.common.NereidsException;
import org.apache.doris.common.UserException;
import org.apache.doris.persist.gson.GsonUtils;

import com.google.gson.Gson;

import java.util.Map;

/** Typed SQL transport adapter: preserve the structured reason through planner wrappers. */
public final class LicenseSqlException extends UserException {
    private static final Gson JSON = GsonUtils.GSON.newBuilder().serializeNulls().create();
    private final String safeMessage;

    public LicenseSqlException(LicenseManagementException exception) {
        this(exception.getSqlErrorCode(), exception.getBody());
    }

    public LicenseSqlException(int code, Map<String, Object> body) {
        super(JSON.toJson(body));
        safeMessage = JSON.toJson(body);
        switch (code) {
            case 6200:
                setMysqlErrorCode(ErrorCode.ERR_LICENSE_QUERY_DENIED);
                break;
            case 6201:
                setMysqlErrorCode(ErrorCode.ERR_LICENSE_CANDIDATE_INVALID);
                break;
            case 6202:
                setMysqlErrorCode(ErrorCode.ERR_LICENSE_CONFLICT);
                break;
            case 6204:
                setMysqlErrorCode(ErrorCode.ERR_LICENSE_HISTORY_UNKNOWN);
                break;
            default:
                setMysqlErrorCode(ErrorCode.ERR_LICENSE_NOT_READY);
        }
    }

    @Override
    public String getMessage() {
        return safeMessage;
    }

    @Override
    public String getDetailMessage() {
        return safeMessage;
    }

    public static LicenseSqlException find(Throwable error) {
        for (int depth = 0; error != null && depth < 16; depth++) {
            if (error instanceof LicenseSqlException) {
                return (LicenseSqlException) error;
            }
            error = error instanceof NereidsException ? ((NereidsException) error).getException() : error.getCause();
        }
        return null;
    }
}
