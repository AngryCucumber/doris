// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import org.apache.doris.massdb.license.LicenseDocument;
import org.apache.doris.massdb.license.LicenseException;
import org.apache.doris.massdb.license.LicenseSnapshot;
import org.apache.doris.massdb.license.LicenseVerifier;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Offline fixture oracle using actual P1 bytecode; no services or performance measurements. */
public final class LicensePayloadFixtureProbe {
    public static void main(String[] args) throws Exception {
        PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(
                new X509EncodedKeySpec(Files.readAllBytes(Paths.get(args[0]))));
        LicenseVerifier verifier = new LicenseVerifier(Collections.singletonMap("a", key));
        long at = Long.parseLong(args[1]);
        Map<String, Object> results = new LinkedHashMap<>();
        for (int i = 2; i < args.length; i++) {
            Map<String, Object> result = new LinkedHashMap<>();
            try {
                String compact = new String(Files.readAllBytes(Paths.get(args[i])), StandardCharsets.US_ASCII);
                LicenseDocument document = verifier.verify(compact);
                LicenseSnapshot snapshot = new LicenseSnapshot(document.getDeploymentId(), document, null,
                        document, 1, 1, true, false, false, 1, 1);
                result.put("verified", true);
                result.put("query_status", snapshot.queryStatus(at).name());
                result.put("feature_count", document.getFeatures().size());
            } catch (LicenseException failure) {
                result.put("verified", false);
                result.put("error_code", failure.getErrorCode().name());
            }
            results.put(Paths.get(args[i]).getFileName().toString(), result);
        }
        System.out.println(new ObjectMapper().writeValueAsString(results));
    }
}
