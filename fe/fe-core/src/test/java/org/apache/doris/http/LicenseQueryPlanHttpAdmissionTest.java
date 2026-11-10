// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.http;

import org.apache.doris.massdb.license.LicenseManager;
import org.apache.doris.massdb.license.LicenseQueryStatus;

import mockit.Mock;
import mockit.MockUp;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

/**
 * Review L14: the `_query_plan` admission test stubs LicenseQueryGuard. This one goes through the real HTTP
 * stack, planner and guard; only the license status is forced.
 */
public class LicenseQueryPlanHttpAdmissionTest extends DorisHttpTestCase {
    /** Forces the status itself. */
    @Override
    protected boolean validLicenseFixture() {
        return false;
    }

    @Test
    public void expiredLicenseDeniesTheQueryPlanWithTheTransportStatus() throws IOException {
        forceStatus(LicenseQueryStatus.EXPIRED);
        try (Response response = queryPlan()) {
            Assert.assertEquals(403, response.code());
            JSONObject body = (JSONObject) JSONValue.parse(response.body().string());
            Assert.assertEquals("LICENSE_EXPIRED", body.get("reason"));
        }
    }

    @Test
    public void validLicenseServesTheQueryPlan() throws IOException {
        forceStatus(LicenseQueryStatus.VALID);
        try (Response response = queryPlan()) {
            Assert.assertEquals(200, response.code());
            JSONObject body = (JSONObject) JSONValue.parse(response.body().string());
            Assert.assertEquals(200L, ((JSONObject) body.get("data")).get("status"));
        }
    }

    private static void forceStatus(LicenseQueryStatus status) {
        new MockUp<LicenseManager>() {
            @Mock
            public LicenseQueryStatus queryStatus() {
                return status;
            }
        };
    }

    private Response queryPlan() throws IOException {
        RequestBody body = RequestBody.create(
                "{ \"sql\" :  \" select k1,k2 from " + DB_NAME + "." + TABLE_NAME + " \" }", JSON);
        Request request = new Request.Builder()
                .post(body)
                .addHeader("Authorization", rootAuth)
                .url(URI + "/_query_plan")
                .build();
        return networkClient.newCall(request).execute();
    }
}
