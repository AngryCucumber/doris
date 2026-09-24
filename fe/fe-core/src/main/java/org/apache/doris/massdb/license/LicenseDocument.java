// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/** Signed claims only; successful verification does not establish current entitlement. */
public final class LicenseDocument {
    private final UUID deploymentId;
    private final String licenseId;
    private final String issuer;
    private final String customerId;
    private final String edition;
    private final String keyId;
    private final String fingerprint;
    private final long issuedAt;
    private final long notBefore;
    private final long expiresAt;
    private final long sequence;
    private final int maxFeNodes;
    private final int maxBeNodes;
    private final Set<String> features;

    LicenseDocument(UUID deploymentId, String licenseId, String issuer, String customerId,
            String edition, String keyId, String fingerprint, long issuedAt, long notBefore,
            long expiresAt, long sequence, int maxFeNodes, int maxBeNodes, Set<String> features) {
        this.deploymentId = deploymentId;
        this.licenseId = licenseId;
        this.issuer = issuer;
        this.customerId = customerId;
        this.edition = edition;
        this.keyId = keyId;
        this.fingerprint = fingerprint;
        this.issuedAt = issuedAt;
        this.notBefore = notBefore;
        this.expiresAt = expiresAt;
        this.sequence = sequence;
        this.maxFeNodes = maxFeNodes;
        this.maxBeNodes = maxBeNodes;
        this.features = Collections.unmodifiableSet(new LinkedHashSet<>(features));
    }

    public UUID getDeploymentId() {
        return deploymentId;
    }

    public String getLicenseId() {
        return licenseId;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getCustomerId() {
        return customerId;
    }

    public String getEdition() {
        return edition;
    }

    public String getKeyId() {
        return keyId;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public long getNotBefore() {
        return notBefore;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public long getSequence() {
        return sequence;
    }

    public int getMaxFeNodes() {
        return maxFeNodes;
    }

    public int getMaxBeNodes() {
        return maxBeNodes;
    }

    public Set<String> getFeatures() {
        return features;
    }

    public boolean hasFeature(String feature) {
        return features.contains(feature);
    }
}
