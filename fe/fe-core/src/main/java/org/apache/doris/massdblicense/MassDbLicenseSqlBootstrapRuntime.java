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

import org.apache.doris.analysis.UserIdentity;
import org.apache.doris.catalog.Env;
import org.apache.doris.catalog.InfoSchemaDb;
import org.apache.doris.catalog.MysqlDb;
import org.apache.doris.common.Config;
import org.apache.doris.common.DdlException;
import org.apache.doris.common.FeConstants;
import org.apache.doris.common.UserException;
import org.apache.doris.common.Version;
import org.apache.doris.ha.FrontendNodeType;
import org.apache.doris.massdblicense.MassDbLicenseBootstrapCore.BackendMember;
import org.apache.doris.massdblicense.MassDbLicenseBootstrapCore.FrontendMember;
import org.apache.doris.massdblicense.MassDbLicenseBootstrapCore.IngestAccount;
import org.apache.doris.massdblicense.MassDbLicenseBootstrapCore.IngestRoute;
import org.apache.doris.massdblicense.MassDbLicenseBootstrapCore.InstallationHealth;
import org.apache.doris.massdblicense.MassDbLicenseBootstrapCore.InstallationPlan;
import org.apache.doris.mysql.privilege.Auth;
import org.apache.doris.system.Backend;
import org.apache.doris.system.Frontend;
import org.apache.doris.system.SystemInfoService;
import org.apache.doris.system.SystemInfoService.HostInfo;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** Idempotent reconciliation of the frozen MassDB SQL first-install plan. */
public final class MassDbLicenseSqlBootstrapRuntime {
    interface ComponentControl {
        boolean isClassicMode();

        boolean isReadyMaster();

        String selfHost();

        int selfEditLogPort();

        int localQueryPort();

        int localHttpsPort();

        String localBuildVersion();

        Set<String> databaseNames();

        List<FrontendStatus> frontends();

        List<BackendStatus> backends();

        boolean canEnsureIngestAccount(IngestAccount account);

        boolean isIngestAccountExact(IngestAccount account);

        void addFrontend(FrontendMember frontend);

        void addBackend(BackendMember backend);

        void ensureIngestAccount(IngestAccount account);
    }

    static final class FrontendStatus {
        final String role;
        final String host;
        final int editLogPort;
        final int queryPort;
        final boolean alive;
        final String buildVersion;

        FrontendStatus(String role, String host, int editLogPort,
                int queryPort, boolean alive) {
            this(role, host, editLogPort, queryPort, alive, null);
        }

        FrontendStatus(String role, String host, int editLogPort,
                int queryPort, boolean alive, String buildVersion) {
            this.role = role;
            this.host = host;
            this.editLogPort = editLogPort;
            this.queryPort = queryPort;
            this.alive = alive;
            this.buildVersion = buildVersion;
        }
    }

    static final class BackendStatus {
        final String host;
        final int heartbeatPort;
        final int bePort;
        final int httpPort;
        final int brpcPort;
        final boolean loadAvailable;

        BackendStatus(String host, int heartbeatPort, int bePort,
                int httpPort, int brpcPort, boolean loadAvailable) {
            this.host = host;
            this.heartbeatPort = heartbeatPort;
            this.bePort = bePort;
            this.httpPort = httpPort;
            this.brpcPort = brpcPort;
            this.loadAvailable = loadAvailable;
        }
    }

    private final ComponentControl control;

    public MassDbLicenseSqlBootstrapRuntime() {
        this(new ProductionControl(Env.getServingEnv()));
    }

    MassDbLicenseSqlBootstrapRuntime(ComponentControl control) {
        if (control == null) {
            throw new IllegalArgumentException("component control不能为空");
        }
        this.control = control;
    }

    public void requireCompatible(InstallationPlan plan, long now) {
        requirePlan(plan);
        if (!control.isClassicMode()) {
            fail("MASSDB_LICENSE_BOOTSTRAP_MODE_UNSUPPORTED",
                    "首版完整bootstrap只支持classic MassDB SQL集群");
        }
        if (!control.isReadyMaster()) {
            fail("MASSDB_LICENSE_NOT_LEADER", "完整bootstrap只能由就绪MASTER执行");
        }
        requireSystemDatabasesOnly(control.databaseNames());
        FrontendMember master = plannedMaster(plan);
        if (!master.host.equals(control.selfHost())
                || master.editLogPort != control.selfEditLogPort()
                || master.queryPort != control.localQueryPort()
                || master.httpsPort != control.localHttpsPort()) {
            fail("MASSDB_LICENSE_BOOTSTRAP_TOPOLOGY_CONFLICT",
                    "plan中的MASTER地址或端口与当前FE不一致");
        }
        requireActualTopologyIsPlanSubset(plan, control.frontends(), control.backends());
        if (!control.canEnsureIngestAccount(plan.getIngestAccount())) {
            fail("MASSDB_LICENSE_BOOTSTRAP_ACCOUNT_CONFLICT",
                    "同名纯写账号已存在但密码或权限不符合冻结计划");
        }
        requireMasterRoute(plan, master);
    }

    public InstallationHealth reconcileAndRequireHealthy(InstallationPlan plan, long now) {
        requireCompatible(plan, now);
        Map<String, FrontendStatus> actualFrontends = indexFrontends(control.frontends());
        for (FrontendMember frontend : plan.getFrontends()) {
            String key = endpointKey(frontend.host, frontend.editLogPort);
            if (!actualFrontends.containsKey(key)) {
                if ("MASTER".equals(frontend.role)) {
                    fail("MASSDB_LICENSE_BOOTSTRAP_TOPOLOGY_CONFLICT",
                            "当前MASTER不在组件权威成员关系中");
                }
                control.addFrontend(frontend);
            }
        }
        Map<String, BackendStatus> actualBackends = indexBackends(control.backends());
        for (BackendMember backend : plan.getBackends()) {
            String key = endpointKey(backend.host, backend.heartbeatPort);
            if (!actualBackends.containsKey(key)) {
                control.addBackend(backend);
            }
        }
        control.ensureIngestAccount(plan.getIngestAccount());

        List<FrontendStatus> refreshedFrontends = control.frontends();
        List<BackendStatus> refreshedBackends = control.backends();
        requireActualTopologyIsPlanSubset(plan, refreshedFrontends, refreshedBackends);
        int aliveFrontends = countAliveFrontends(plan, refreshedFrontends);
        int aliveBackends = countAliveBackends(plan, refreshedBackends);
        int readyRoutes = readyRoutes(plan, refreshedFrontends);
        boolean accountReady = control.isIngestAccountExact(plan.getIngestAccount());
        return new InstallationHealth(plan.getFrontends().size(), aliveFrontends,
                plan.getBackends().size(), aliveBackends, readyRoutes, accountReady);
    }

    /** Returns only the topology and identity health needed by License operations. */
    public MinimalTopology minimalTopology(MassDbLicenseState state, long now) {
        requireSealedState(state);
        if (now < 0) {
            fail("MASSDB_LICENSE_CLOCK_INVALID", "最小拓扑检查时间不能为负数");
        }

        List<MinimalFrontend> frontends = new ArrayList<>();
        int aliveFrontends = 0;
        for (FrontendStatus status : safeFrontends(control.frontends())) {
            frontends.add(new MinimalFrontend(status.role, status.host,
                    status.editLogPort, status.queryPort, status.alive));
            if (status.alive) {
                aliveFrontends++;
            }
        }
        frontends.sort(Comparator.comparing((MinimalFrontend value) -> value.host)
                .thenComparingInt(value -> value.editLogPort));

        List<MinimalBackend> backends = new ArrayList<>();
        int loadAvailableBackends = 0;
        for (BackendStatus status : safeBackends(control.backends())) {
            backends.add(new MinimalBackend(status.host, status.heartbeatPort,
                    status.bePort, status.httpPort, status.brpcPort,
                    status.loadAvailable));
            if (status.loadAvailable) {
                loadAvailableBackends++;
            }
        }
        backends.sort(Comparator.comparing((MinimalBackend value) -> value.host)
                .thenComparingInt(value -> value.heartbeatPort));

        List<MinimalIngress> ingressNodes = new ArrayList<>();
        int desiredIngressNodes = 0;
        int liveDesiredIngressNodes = 0;
        int guardReadyDesiredIngressNodes = 0;
        for (MassDbLicenseIngressInventory.IngressNode node
                : new TreeMap<>(state.getIngressInventory().getNodes()).values()) {
            boolean live = node.isLive(now);
            String identityStatus = identityStatus(node, live);
            ingressNodes.add(new MinimalIngress(node.getNodeUuid(), node.getEndpoint(),
                    node.isDesired(), live, node.isGuardReady(), identityStatus,
                    node.getLastRoleStatusObservedAt(),
                    node.getReportedVerificationState().name(),
                    node.getReportedControlPlaneFreshness(),
                    node.getRoutingState().name(),
                    node.hasFreshRoutingEvidence(now),
                    node.isReportedLicenseQueryAllowed(),
                    node.getReportedLocalStateErrorCode()));
            if (node.isDesired()) {
                desiredIngressNodes++;
                if (live) {
                    liveDesiredIngressNodes++;
                }
                if (node.isGuardReady()) {
                    guardReadyDesiredIngressNodes++;
                }
            }
        }

        TopologySummary summary = new TopologySummary(frontends.size(), aliveFrontends,
                backends.size(), loadAvailableBackends, desiredIngressNodes,
                liveDesiredIngressNodes, guardReadyDesiredIngressNodes);
        return new MinimalTopology(state, now, control.isReadyMaster(), summary,
                frontends, backends, ingressNodes);
    }

    /**
     * Gives operators a compatibility hint for an existing cluster without creating License
     * state. Ordinary component heartbeats are deliberately not trusted as upgrade authority.
     */
    public ObserveUpgradePreflight observeUpgradePreflight(
            MassDbLicenseState state, long now) {
        if (state == null || state.isInitialized()
                || !"UNINITIALIZED".equals(state.getBootstrapPhase())) {
            fail("MASSDB_LICENSE_UPGRADE_ALREADY_INITIALIZED",
                    "License一致性状态已初始化，不能执行存量OBSERVE预检");
        }
        if (!control.isClassicMode()) {
            fail("MASSDB_LICENSE_UPGRADE_MODE_UNSUPPORTED",
                    "首版存量OBSERVE升级只支持classic MassDB SQL集群");
        }
        if (!control.isReadyMaster()) {
            fail("MASSDB_LICENSE_NOT_LEADER", "存量OBSERVE预检只能由就绪MASTER执行");
        }
        if (now < 0) {
            fail("MASSDB_LICENSE_CLOCK_INVALID", "升级预检时间不能为负数");
        }
        Set<String> businessDatabases = businessDatabaseNames(control.databaseNames());
        if (businessDatabases.isEmpty()) {
            fail("MASSDB_LICENSE_UPGRADE_NOT_EXISTING_CLUSTER",
                    "未发现既有业务元数据，不能走存量OBSERVE升级路径");
        }

        String expectedBuildVersion = control.localBuildVersion();
        if (expectedBuildVersion == null || expectedBuildVersion.trim().isEmpty()) {
            fail("MASSDB_LICENSE_UPGRADE_BUILD_ID_UNAVAILABLE",
                    "当前FE无法提供精确构建标识");
        }
        List<UpgradeFrontend> frontends = new ArrayList<>();
        Set<String> blockers = new LinkedHashSet<>();
        List<FrontendStatus> actualFrontends = safeFrontends(control.frontends());
        if (actualFrontends.isEmpty()) {
            blockers.add("MASSDB_LICENSE_UPGRADE_FE_MEMBERSHIP_EMPTY");
        }
        boolean allOnline = !actualFrontends.isEmpty();
        boolean allBuildsMatch = !actualFrontends.isEmpty();
        for (FrontendStatus status : actualFrontends) {
            boolean buildMissing = status.buildVersion == null
                    || status.buildVersion.trim().isEmpty();
            boolean buildMatches = !buildMissing
                    && expectedBuildVersion.equals(status.buildVersion);
            frontends.add(new UpgradeFrontend(status.role, status.host,
                    status.editLogPort, status.alive, status.buildVersion,
                    buildMatches));
            String endpoint = displayEndpoint(status.host, status.editLogPort);
            if (!status.alive) {
                allOnline = false;
                blockers.add("MASSDB_LICENSE_UPGRADE_FE_OFFLINE:" + endpoint);
            }
            if (!buildMatches) {
                allBuildsMatch = false;
                blockers.add((buildMissing
                        ? "MASSDB_LICENSE_UPGRADE_BUILD_ID_MISSING:"
                        : "MASSDB_LICENSE_UPGRADE_BUILD_ID_MISMATCH:") + endpoint);
            }
        }
        frontends.sort(Comparator.comparing((UpgradeFrontend value) -> value.host)
                .thenComparingInt(value -> value.editLogPort));
        boolean compatibilityHintReady = allOnline && allBuildsMatch;
        blockers.add("MASSDB_LICENSE_UPGRADE_TRUSTED_ATTESTATION_REQUIRED");
        return new ObserveUpgradePreflight(now, businessDatabases.size(),
                expectedBuildVersion, allOnline, allBuildsMatch,
                compatibilityHintReady, frontends, new ArrayList<>(blockers));
    }

    private static void requireSealedState(MassDbLicenseState state) {
        if (state == null || !state.isInitialized()) {
            fail("MASSDB_LICENSE_BOOTSTRAP_REQUIRED", "License一致性状态尚未bootstrap");
        }
        if (!"SEALED".equals(state.getBootstrapPhase())
                || state.getBootstrapSealGeneration() != 1) {
            fail("MASSDB_LICENSE_BOOTSTRAP_NOT_SEALED",
                    "最小拓扑仅在bootstrap永久SEALED后可读取");
        }
    }

    private static String identityStatus(
            MassDbLicenseIngressInventory.IngressNode node, boolean live) {
        if (node.isIdentityConflicted()) {
            return "CONFLICT";
        }
        if (node.getLastRoleStatusObservedAt() <= 0) {
            return "UNSEEN";
        }
        return live ? "AUTHENTICATED" : "STALE";
    }

    private static Set<String> businessDatabaseNames(Set<String> databaseNames) {
        Set<String> business = new HashSet<>(databaseNames == null
                ? Collections.emptySet() : databaseNames);
        business.remove(InfoSchemaDb.DATABASE_NAME);
        business.remove(MysqlDb.DATABASE_NAME);
        business.remove(FeConstants.INTERNAL_DB_NAME);
        return business;
    }

    private static List<FrontendStatus> safeFrontends(List<FrontendStatus> values) {
        return values == null ? Collections.emptyList() : values;
    }

    private static List<BackendStatus> safeBackends(List<BackendStatus> values) {
        return values == null ? Collections.emptyList() : values;
    }

    public static final class MinimalTopology {
        public final String schemaVersion = "massdb-sql-minimal-topology/v1";
        public final String componentType = "massdb-sql";
        public final String licenseControlDeploymentUuid;
        public final String bootstrapPhase;
        public final long bootstrapSealGeneration;
        public final String enforcementMode;
        public final long enforcementEpoch;
        public final long topologyRevision;
        public final long checkedAt;
        public final boolean leaderReady;
        public final TopologySummary summary;
        public final List<MinimalFrontend> frontends;
        public final List<MinimalBackend> backends;
        public final List<MinimalIngress> ingressNodes;

        private MinimalTopology(MassDbLicenseState state, long checkedAt,
                boolean leaderReady, TopologySummary summary,
                List<MinimalFrontend> frontends, List<MinimalBackend> backends,
                List<MinimalIngress> ingressNodes) {
            this.licenseControlDeploymentUuid = state.getLicenseControlDeploymentUuid();
            this.bootstrapPhase = state.getBootstrapPhase();
            this.bootstrapSealGeneration = state.getBootstrapSealGeneration();
            this.enforcementMode = state.getEnforcementMode().name();
            this.enforcementEpoch = state.getEnforcementEpoch();
            this.topologyRevision = state.getTopologyRevision();
            this.checkedAt = checkedAt;
            this.leaderReady = leaderReady;
            this.summary = summary;
            this.frontends = immutableCopy(frontends);
            this.backends = immutableCopy(backends);
            this.ingressNodes = immutableCopy(ingressNodes);
        }
    }

    public static final class TopologySummary {
        public final int actualFrontendCount;
        public final int aliveFrontendCount;
        public final int actualBackendCount;
        public final int loadAvailableBackendCount;
        public final int desiredIngressCount;
        public final int liveDesiredIngressCount;
        public final int guardReadyDesiredIngressCount;

        private TopologySummary(int actualFrontendCount, int aliveFrontendCount,
                int actualBackendCount, int loadAvailableBackendCount,
                int desiredIngressCount, int liveDesiredIngressCount,
                int guardReadyDesiredIngressCount) {
            this.actualFrontendCount = actualFrontendCount;
            this.aliveFrontendCount = aliveFrontendCount;
            this.actualBackendCount = actualBackendCount;
            this.loadAvailableBackendCount = loadAvailableBackendCount;
            this.desiredIngressCount = desiredIngressCount;
            this.liveDesiredIngressCount = liveDesiredIngressCount;
            this.guardReadyDesiredIngressCount = guardReadyDesiredIngressCount;
        }
    }

    public static final class MinimalFrontend {
        public final String role;
        public final String host;
        public final int editLogPort;
        public final int queryPort;
        public final boolean alive;

        private MinimalFrontend(String role, String host, int editLogPort,
                int queryPort, boolean alive) {
            this.role = role;
            this.host = host;
            this.editLogPort = editLogPort;
            this.queryPort = queryPort;
            this.alive = alive;
        }
    }

    public static final class MinimalBackend {
        public final String host;
        public final int heartbeatPort;
        public final int bePort;
        public final int httpPort;
        public final int brpcPort;
        public final boolean loadAvailable;

        private MinimalBackend(String host, int heartbeatPort, int bePort,
                int httpPort, int brpcPort, boolean loadAvailable) {
            this.host = host;
            this.heartbeatPort = heartbeatPort;
            this.bePort = bePort;
            this.httpPort = httpPort;
            this.brpcPort = brpcPort;
            this.loadAvailable = loadAvailable;
        }
    }

    public static final class MinimalIngress {
        public final String nodeUuid;
        public final String endpoint;
        public final boolean desired;
        public final boolean live;
        public final boolean guardReady;
        public final String identityStatus;
        public final long lastAuthenticatedRoleStatusAt;
        public final String verificationState;
        public final String controlPlaneFreshness;
        public final String routingState;
        public final boolean routingEvidenceFresh;
        public final boolean licenseQueryAllowed;
        public final String localStateErrorCode;

        private MinimalIngress(String nodeUuid, String endpoint, boolean desired,
                boolean live, boolean guardReady, String identityStatus,
                long lastAuthenticatedRoleStatusAt, String verificationState,
                String controlPlaneFreshness, String routingState,
                boolean routingEvidenceFresh, boolean licenseQueryAllowed,
                String localStateErrorCode) {
            this.nodeUuid = nodeUuid;
            this.endpoint = endpoint;
            this.desired = desired;
            this.live = live;
            this.guardReady = guardReady;
            this.identityStatus = identityStatus;
            this.lastAuthenticatedRoleStatusAt = lastAuthenticatedRoleStatusAt;
            this.verificationState = verificationState;
            this.controlPlaneFreshness = controlPlaneFreshness;
            this.routingState = routingState;
            this.routingEvidenceFresh = routingEvidenceFresh;
            this.licenseQueryAllowed = licenseQueryAllowed;
            this.localStateErrorCode = localStateErrorCode;
        }
    }

    public static final class ObserveUpgradePreflight {
        public final String schemaVersion = "massdb-sql-observe-upgrade-preflight/v1";
        public final String componentType = "massdb-sql";
        public final String currentEnforcementMode = "UNINITIALIZED";
        public final String evidenceClass = "COMPATIBILITY_HINT_ONLY";
        public final long checkedAt;
        public final int businessDatabaseCount;
        public final String expectedBuildVersion;
        public final boolean allPersistedFrontendsOnline;
        public final boolean allReportedBuildsMatch;
        public final boolean compatibilityHintReady;
        public final boolean trustedNodeAttestationReady = false;
        public final boolean safeToInitializeObserve = false;
        public final List<UpgradeFrontend> frontends;
        public final List<String> blockers;

        private ObserveUpgradePreflight(long checkedAt, int businessDatabaseCount,
                String expectedBuildVersion, boolean allPersistedFrontendsOnline,
                boolean allReportedBuildsMatch, boolean compatibilityHintReady,
                List<UpgradeFrontend> frontends, List<String> blockers) {
            this.checkedAt = checkedAt;
            this.businessDatabaseCount = businessDatabaseCount;
            this.expectedBuildVersion = expectedBuildVersion;
            this.allPersistedFrontendsOnline = allPersistedFrontendsOnline;
            this.allReportedBuildsMatch = allReportedBuildsMatch;
            this.compatibilityHintReady = compatibilityHintReady;
            this.frontends = immutableCopy(frontends);
            this.blockers = immutableCopy(blockers);
        }
    }

    public static final class UpgradeFrontend {
        public final String role;
        public final String host;
        public final int editLogPort;
        public final boolean alive;
        public final String reportedBuildVersion;
        public final boolean exactBuildMatch;

        private UpgradeFrontend(String role, String host, int editLogPort,
                boolean alive, String reportedBuildVersion, boolean exactBuildMatch) {
            this.role = role;
            this.host = host;
            this.editLogPort = editLogPort;
            this.alive = alive;
            this.reportedBuildVersion = reportedBuildVersion;
            this.exactBuildMatch = exactBuildMatch;
        }
    }

    private static <T> List<T> immutableCopy(List<T> values) {
        return Collections.unmodifiableList(new ArrayList<>(values));
    }

    private static void requirePlan(InstallationPlan plan) {
        if (plan == null || plan.getFrontends().isEmpty() || plan.getBackends().isEmpty()
                || plan.getIngestAccount() == null || plan.getIngestRoutes().isEmpty()) {
            fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "完整安装计划为空");
        }
    }

    private static FrontendMember plannedMaster(InstallationPlan plan) {
        for (FrontendMember frontend : plan.getFrontends()) {
            if ("MASTER".equals(frontend.role)) {
                return frontend;
            }
        }
        fail("MASSDB_LICENSE_BOOTSTRAP_PLAN_INVALID", "完整安装计划缺少MASTER");
        return null;
    }

    private static void requireMasterRoute(InstallationPlan plan, FrontendMember master) {
        if (plan.getIngestRoutes().size() != 1) {
            fail("MASSDB_LICENSE_BOOTSTRAP_ROUTE_CONFLICT", "首启必须只有一条MASTER入库路由");
        }
        IngestRoute route = plan.getIngestRoutes().get(0);
        String expected = "https://" + (master.host.indexOf(':') >= 0
                ? "[" + master.host + "]" : master.host) + ":" + master.httpsPort;
        if (!"STREAM_LOAD_HTTPS".equals(route.kind)
                || !master.nodeUuid.equals(route.feNodeUuid)
                || !expected.equals(route.endpoint)) {
            fail("MASSDB_LICENSE_BOOTSTRAP_ROUTE_CONFLICT",
                    "入库路由没有精确绑定当前MASTER HTTPS入口");
        }
    }

    private static void requireSystemDatabasesOnly(Set<String> databaseNames) {
        Set<String> unexpected = new HashSet<>(databaseNames == null
                ? Collections.emptySet() : databaseNames);
        unexpected.remove(InfoSchemaDb.DATABASE_NAME);
        unexpected.remove(MysqlDb.DATABASE_NAME);
        unexpected.remove(FeConstants.INTERNAL_DB_NAME);
        if (!unexpected.isEmpty()) {
            fail("MASSDB_LICENSE_BOOTSTRAP_NOT_FRESH",
                    "检测到非系统数据库，拒绝执行首次安装bootstrap");
        }
    }

    private static void requireActualTopologyIsPlanSubset(InstallationPlan plan,
            List<FrontendStatus> frontends, List<BackendStatus> backends) {
        Map<String, FrontendMember> plannedFrontends = new HashMap<>();
        for (FrontendMember frontend : plan.getFrontends()) {
            plannedFrontends.put(endpointKey(frontend.host, frontend.editLogPort), frontend);
        }
        for (FrontendStatus actual : frontends) {
            FrontendMember planned = plannedFrontends.get(
                    endpointKey(actual.host, actual.editLogPort));
            if (planned == null || !planned.role.equals(actual.role)) {
                fail("MASSDB_LICENSE_BOOTSTRAP_TOPOLOGY_CONFLICT",
                        "存在未纳入冻结plan或role不一致的FE成员");
            }
        }
        Map<String, BackendMember> plannedBackends = new HashMap<>();
        for (BackendMember backend : plan.getBackends()) {
            plannedBackends.put(endpointKey(backend.host, backend.heartbeatPort), backend);
        }
        for (BackendStatus actual : backends) {
            if (!plannedBackends.containsKey(endpointKey(actual.host, actual.heartbeatPort))) {
                fail("MASSDB_LICENSE_BOOTSTRAP_TOPOLOGY_CONFLICT",
                        "存在未纳入冻结plan的BE成员");
            }
        }
    }

    private static int countAliveFrontends(InstallationPlan plan,
            List<FrontendStatus> actualValues) {
        Map<String, FrontendStatus> actual = indexFrontends(actualValues);
        int alive = 0;
        for (FrontendMember planned : plan.getFrontends()) {
            FrontendStatus status = actual.get(endpointKey(planned.host, planned.editLogPort));
            if (status != null && status.alive && status.queryPort == planned.queryPort) {
                alive++;
            }
        }
        return alive;
    }

    private static int countAliveBackends(InstallationPlan plan,
            List<BackendStatus> actualValues) {
        Map<String, BackendStatus> actual = indexBackends(actualValues);
        int alive = 0;
        for (BackendMember planned : plan.getBackends()) {
            BackendStatus status = actual.get(endpointKey(planned.host, planned.heartbeatPort));
            if (status != null && status.loadAvailable
                    && status.bePort == planned.bePort && status.httpPort == planned.httpPort
                    && status.brpcPort == planned.brpcPort) {
                alive++;
            }
        }
        return alive;
    }

    private static int readyRoutes(InstallationPlan plan, List<FrontendStatus> frontends) {
        FrontendMember master = plannedMaster(plan);
        FrontendStatus status = indexFrontends(frontends).get(
                endpointKey(master.host, master.editLogPort));
        return status != null && status.alive && controlRouteMatchesLocal(plan, master) ? 1 : 0;
    }

    private static boolean controlRouteMatchesLocal(InstallationPlan plan,
            FrontendMember master) {
        IngestRoute route = plan.getIngestRoutes().get(0);
        return master.nodeUuid.equals(route.feNodeUuid);
    }

    private static Map<String, FrontendStatus> indexFrontends(List<FrontendStatus> values) {
        Map<String, FrontendStatus> result = new HashMap<>();
        for (FrontendStatus value : values) {
            result.put(endpointKey(value.host, value.editLogPort), value);
        }
        return result;
    }

    private static Map<String, BackendStatus> indexBackends(List<BackendStatus> values) {
        Map<String, BackendStatus> result = new HashMap<>();
        for (BackendStatus value : values) {
            result.put(endpointKey(value.host, value.heartbeatPort), value);
        }
        return result;
    }

    private static String endpointKey(String host, int port) {
        return host + "\t" + port;
    }

    private static String displayEndpoint(String host, int port) {
        return (host.indexOf(':') >= 0 ? "[" + host + "]" : host) + ":" + port;
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    private static final class ProductionControl implements ComponentControl {
        private final Env env;
        private final SystemInfoService systemInfo;
        private final Auth auth;

        private ProductionControl(Env env) {
            this.env = env;
            this.systemInfo = env.getClusterInfo();
            this.auth = env.getAuth();
        }

        @Override
        public boolean isClassicMode() {
            return Config.isNotCloudMode();
        }

        @Override
        public boolean isReadyMaster() {
            return env.isReady() && env.isMaster();
        }

        @Override
        public String selfHost() {
            return env.getSelfNode().getHost();
        }

        @Override
        public int selfEditLogPort() {
            return env.getSelfNode().getPort();
        }

        @Override
        public int localQueryPort() {
            return Config.query_port;
        }

        @Override
        public int localHttpsPort() {
            return Config.https_port;
        }

        @Override
        public String localBuildVersion() {
            return Version.DORIS_BUILD_VERSION + "-" + Version.DORIS_BUILD_SHORT_HASH;
        }

        @Override
        public Set<String> databaseNames() {
            return new HashSet<>(env.getInternalCatalog().getDbNames());
        }

        @Override
        public List<FrontendStatus> frontends() {
            List<FrontendStatus> result = new ArrayList<>();
            InetSocketAddress leader = currentLeader();
            for (Frontend frontend : env.getFrontends(null)) {
                boolean self = frontend.getHost().equals(selfHost())
                        && frontend.getEditLogPort() == selfEditLogPort();
                boolean master = (self && env.isMaster()) || (leader != null
                        && leader.getHostString().equals(frontend.getHost())
                        && leader.getPort() == frontend.getEditLogPort());
                String role = master ? "MASTER"
                        : frontend.getRole() == FrontendNodeType.OBSERVER
                        ? "OBSERVER" : "FOLLOWER";
                result.add(new FrontendStatus(role, frontend.getHost(),
                        frontend.getEditLogPort(), self ? Config.query_port
                                : frontend.getQueryPort(), self ? env.isReady()
                                : frontend.isAlive(), self ? localBuildVersion()
                                : frontend.getVersion()));
            }
            return result;
        }

        private InetSocketAddress currentLeader() {
            try {
                return env.getHaProtocol() == null ? null : env.getHaProtocol().getLeader();
            } catch (RuntimeException unavailable) {
                return null;
            }
        }

        @Override
        public List<BackendStatus> backends() {
            List<BackendStatus> result = new ArrayList<>();
            for (Backend backend : systemInfo.getAllClusterBackends(false)) {
                result.add(new BackendStatus(backend.getHost(), backend.getHeartbeatPort(),
                        backend.getBePort(), backend.getHttpPort(), backend.getBrpcPort(),
                        backend.isLoadAvailable()));
            }
            return result;
        }

        @Override
        public boolean canEnsureIngestAccount(IngestAccount account) {
            return auth.canEnsureMassDbBootstrapIngestAccount(
                    user(account), account.getPasswordHash());
        }

        @Override
        public boolean isIngestAccountExact(IngestAccount account) {
            return auth.isMassDbBootstrapIngestAccountExact(
                    user(account), account.getPasswordHash());
        }

        @Override
        public void addFrontend(FrontendMember frontend) {
            try {
                FrontendNodeType type = "OBSERVER".equals(frontend.role)
                        ? FrontendNodeType.OBSERVER : FrontendNodeType.FOLLOWER;
                env.addFrontend(type, frontend.host, frontend.editLogPort);
            } catch (DdlException failure) {
                throw componentFailure("MASSDB_LICENSE_BOOTSTRAP_FE_ADD_FAILED", failure);
            }
        }

        @Override
        public void addBackend(BackendMember backend) {
            try {
                systemInfo.addBackends(Collections.singletonList(
                        new HostInfo(backend.host, backend.heartbeatPort)), false);
            } catch (UserException failure) {
                throw componentFailure("MASSDB_LICENSE_BOOTSTRAP_BE_ADD_FAILED", failure);
            }
        }

        @Override
        public void ensureIngestAccount(IngestAccount account) {
            try {
                auth.ensureMassDbBootstrapIngestAccount(
                        user(account), account.getPasswordHash());
            } catch (DdlException failure) {
                throw componentFailure("MASSDB_LICENSE_BOOTSTRAP_ACCOUNT_FAILED", failure);
            }
        }

        private static UserIdentity user(IngestAccount account) {
            return UserIdentity.createAnalyzedUserIdentWithIp(
                    account.username, account.hostPattern);
        }

        private static MassDbLicenseException componentFailure(
                String code, Exception failure) {
            return new MassDbLicenseException(code,
                    "组件bootstrap动作失败: " + failure.getClass().getSimpleName());
        }
    }
}
