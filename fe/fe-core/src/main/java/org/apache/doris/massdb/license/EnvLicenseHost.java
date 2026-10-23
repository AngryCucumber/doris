// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.


package org.apache.doris.massdb.license;

import org.apache.doris.catalog.Env;
import org.apache.doris.common.Config;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/** Binds the serving {@link Env} to the license manager; kept outside Env to limit upstream changes. */
public final class EnvLicenseHost implements LicenseManager.Host {
    private final Env env;
    private final boolean checkpointCatalog;

    public EnvLicenseHost(Env env, boolean checkpointCatalog) {
        this.env = env;
        this.checkpointCatalog = checkpointCatalog;
    }

    @Override
    public boolean isMaster() {
        return env.isLicenseLeadership();
    }

    @Override
    public LicenseManager.Membership membership() {
        return LicenseFeCompatibility.membership(env);
    }

    @Override
    public long frontendVersion() {
        return LicenseFeCompatibility.frontendVersion(env);
    }

    @Override
    public void commit(short operation, LicensePersistRecord record) throws IOException {
        if (!env.isLicenseLeadership() || checkpointCatalog) {
            throw new IOException("License commits require the current serving master");
        }
        env.getEditLog().logLicense(operation, record);
    }

    @Override
    public boolean activationReady() {
        return LicenseFeCompatibility.checkAll(env, env.getLicenseManager().capability());
    }

    @Override
    public String trustStorePath() {
        return Config.massdb_license_trust_store_file;
    }

    @Override
    public String signedTrustManifestPath() {
        return Config.massdb_license_trust_manifest_signed;
    }

    @Override
    public Map<String, Object> localCapability(String trustDigest) {
        return LicenseFeCompatibility.localCapability(env, trustDigest);
    }

    @Override
    public LicenseClock.PeerVerdict peerClockVerdict(long selfWallMillis, long toleranceMillis) {
        return LicenseFeCompatibility.peerClockVerdict(env, selfWallMillis, toleranceMillis);
    }

    @Override
    public List<String> trustDigestMismatches(String localDigest) {
        return LicenseFeCompatibility.trustDigestMismatches(env, localDigest);
    }
}
