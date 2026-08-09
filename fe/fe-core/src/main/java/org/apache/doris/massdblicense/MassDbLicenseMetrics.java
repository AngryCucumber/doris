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

import java.util.Map;
import java.util.TreeMap;

/** Renders one authoritative status snapshot as the frozen component-native Prometheus gauges. */
public final class MassDbLicenseMetrics {
    private MassDbLicenseMetrics() {
    }

    public static String render(MassDbLicenseReadApiCore.Status status,
            MassDbLicenseState state) {
        StringBuilder output = new StringBuilder(2048);
        help(output, "massdb_license_expiry_timestamp_seconds",
                "Unix expiry time of the active MassDB License");
        gauge(output, "massdb_license_expiry_timestamp_seconds",
                status.licenseExpiresAt == null ? 0 : status.licenseExpiresAt);
        help(output, "massdb_license_state", "Current MassDB License state");
        output.append("massdb_license_state{state=\"")
                .append(label(status.state)).append("\"} 1\n");
        help(output, "massdb_license_enforcement_enabled",
                "Whether query enforcement is enabled");
        gauge(output, "massdb_license_enforcement_enabled",
                MassDbLicenseState.EnforcementMode.ENFORCING.name()
                        .equals(status.enforcementMode) ? 1 : 0);
        boolean guardReady = status.expectedIngressNodes > 0;
        Map<String, MassDbLicenseIngressInventory.IngressNode> nodes =
                new TreeMap<>(state.getIngressInventory().getNodes());
        for (MassDbLicenseIngressInventory.IngressNode node : nodes.values()) {
            if (node.isDesired() && node.isLive(status.effectiveNow)
                    && !node.isGuardReady()) {
                guardReady = false;
            }
        }
        help(output, "massdb_license_guard_ready",
                "Whether every desired live ingress has installed the License query guard");
        gauge(output, "massdb_license_guard_ready", guardReady ? 1 : 0);
        help(output, "massdb_license_info", "Non-sensitive active License identity");
        if (status.licenseId != null && status.issuerKeyId != null
                && status.contentSha256 != null) {
            output.append("massdb_license_info{issuer_key_id=\"")
                    .append(label(status.issuerKeyId)).append("\",license_id=\"")
                    .append(label(status.licenseId)).append("\",sha256_prefix=\"")
                    .append(label(status.contentSha256.substring(
                            0, Math.min(12, status.contentSha256.length()))))
                    .append("\"} 1\n");
        }
        help(output, "massdb_license_ingress_expected", "Desired License ingress count");
        gauge(output, "massdb_license_ingress_expected", status.expectedIngressNodes);
        help(output, "massdb_license_ingress_live", "Live desired License ingress count");
        gauge(output, "massdb_license_ingress_live", status.liveIngressNodes);
        help(output, "massdb_license_ingress_covered", "Covered desired License ingress count");
        gauge(output, "massdb_license_ingress_covered", status.coveredIngressNodes);
        help(output, "massdb_license_coverage_freshness",
                "Aggregate License ingress coverage freshness");
        output.append("massdb_license_coverage_freshness{state=\"")
                .append(label(status.coverageFreshness)).append("\"} 1\n");
        help(output, "massdb_license_control_plane_freshness",
                "Per-ingress License control-plane freshness");
        help(output, "massdb_license_control_plane_staleness_remaining_seconds",
                "Seconds before the ingress control-plane snapshot becomes expired");
        for (Map.Entry<String, MassDbLicenseIngressInventory.IngressNode> entry
                : nodes.entrySet()) {
            MassDbLicenseIngressInventory.IngressNode node = entry.getValue();
            if (!node.isDesired()) {
                continue;
            }
            String freshness = node.getReportedControlPlaneFreshness();
            if (freshness == null || freshness.isEmpty() || "MISSING".equals(freshness)) {
                freshness = node.isLive(status.effectiveNow) ? "FRESH" : "STALE";
            }
            output.append("massdb_license_control_plane_freshness{node_uuid=\"")
                    .append(label(entry.getKey())).append("\",state=\"")
                    .append(label(freshness)).append("\"} 1\n");
            Long remaining = node.getReportedControlPlaneStalenessRemainingSeconds();
            output.append("massdb_license_control_plane_staleness_remaining_seconds")
                    .append("{node_uuid=\"").append(label(entry.getKey()))
                    .append("\"} ").append(remaining == null ? 0 : remaining).append('\n');
        }
        return output.toString();
    }

    private static void help(StringBuilder output, String name, String description) {
        output.append("# HELP ").append(name).append(' ').append(description).append('\n')
                .append("# TYPE ").append(name).append(" gauge\n");
    }

    private static void gauge(StringBuilder output, String name, long value) {
        output.append(name).append(' ').append(value).append('\n');
    }

    private static String label(String value) {
        return value.replace("\\", "\\\\")
                .replace("\n", "\\n")
                .replace("\"", "\\\"");
    }
}
