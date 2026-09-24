// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/** Offline known-envelope and malformed-input checks; never connects to a database. */
public final class LicenseGroupCommitReceiptTest {
    private LicenseGroupCommitReceiptTest() {
    }

    private static JsonNode parse(Method method, String input) throws Exception {
        return (JsonNode) method.invoke(null, input, new ObjectMapper().createObjectNode());
    }

    private static void reject(Method method, String input) throws Exception {
        try {
            parse(method, input);
        } catch (InvocationTargetException error) {
            if (error.getCause() instanceof IllegalStateException
                    || error.getCause() instanceof com.fasterxml.jackson.core.JsonProcessingException) {
                return;
            }
            throw error;
        }
        throw new AssertionError("Malformed server-info envelope was accepted");
    }

    public static void main(String[] args) throws Exception {
        Method method = LicenseGroupCommitFixture.class.getDeclaredMethod("serverReceipt", String.class, ObjectNode.class);
        method.setAccessible(true);
        String shortInfo = "{'label':'group_commit_example','status':'PREPARE','txnId':'1'}";
        StringBuilder longInfo = new StringBuilder(shortInfo.substring(0, shortInfo.length() - 1)).append(", 'query_id':'");
        for (int index = 0; index < 80; index++) {
            longInfo.append('a');
        }
        longInfo.append("'}");
        if (!parse(method, shortInfo).path("status").asText().equals("PREPARE")
                || !parse(method, ((char) shortInfo.length()) + shortInfo).path("txnId").asText().equals("1")
                || !parse(method, "\ufffd" + longInfo).has("query_id")) {
            throw new AssertionError("Known server-info envelope was not decoded");
        }
        reject(method, null);
        reject(method, "xx" + shortInfo);
        reject(method, "X" + shortInfo);
        reject(method, "\ufffd" + shortInfo);
        reject(method, shortInfo + " 0");
        System.out.println("8 server-info envelope checks passed; database_requests=0");
    }
}
