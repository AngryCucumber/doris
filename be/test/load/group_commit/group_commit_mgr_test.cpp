// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

#include "load/group_commit/group_commit_mgr.h"

#include <gtest/gtest.h>

#include <chrono>
#include <limits>
#include <memory>
#include <thread>

#include "agent/be_exec_version_manager.h"
#include "common/config.h"
#include "exec/pipeline/dependency.h"
#include "runtime/exec_env.h"
#include "util/debug_points.h"
#include "util/defer_op.h"

namespace doris {

TEST(GroupCommitCreatePlanRetryTest, IntervalDoublesUpToOneSecond) {
    EXPECT_EQ(group_commit_create_plan_retry_interval_ms(0), 0);
    EXPECT_EQ(group_commit_create_plan_retry_interval_ms(1), 50);
    EXPECT_EQ(group_commit_create_plan_retry_interval_ms(2), 100);
    EXPECT_EQ(group_commit_create_plan_retry_interval_ms(5), 800);
    EXPECT_EQ(group_commit_create_plan_retry_interval_ms(6), 1000);
    EXPECT_EQ(group_commit_create_plan_retry_interval_ms(std::numeric_limits<int32_t>::max()),
              1000);
}

// While plan creation fails (e.g. the FE rejects new transactions), the BE used to retry at once and
// sent the FE about 1,900 plan requests a second until group_commit_create_plan_timeout_ms. With the
// back-off it tries a handful of times, and the timeout still releases the waiting load.
TEST(GroupCommitCreatePlanRetryTest, FailedPlanCreationIsRetriedWithBackOff) {
    const auto original_debug_points = config::enable_debug_points;
    const auto original_timeout = config::group_commit_create_plan_timeout_ms;
    Defer restore {[&] {
        DebugPoints::instance()->remove("GroupCommitTable._create_group_commit_load.error");
        config::enable_debug_points = original_debug_points;
        config::group_commit_create_plan_timeout_ms = original_timeout;
    }};
    config::enable_debug_points = true;
    DebugPoints::instance()->add("GroupCommitTable._create_group_commit_load.error");
    config::group_commit_create_plan_timeout_ms = 3500;

    GroupCommitMgr mgr(ExecEnv::GetInstance());
    constexpr int64_t table_id = 2;
    auto create_plan_dep = std::make_shared<Dependency>(0, 0, "CreateGroupCommitPlan", true);
    auto put_block_dep = std::make_shared<Dependency>(0, 0, "GroupCommitPutBlock", true);
    std::shared_ptr<LoadBlockQueue> queue;
    // the plan is created in the background; the load waits on create_plan_dep
    EXPECT_FALSE(mgr.get_first_block_load_queue(1, table_id, 0, 1, UniqueId::gen_uid(), queue,
                                                BeExecVersionManager::get_newest_version(),
                                                TGroupCommitMode::SYNC_MODE, create_plan_dep,
                                                put_block_dep)
                         .ok());
    EXPECT_FALSE(create_plan_dep->ready());

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!create_plan_dep->ready() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    ASSERT_TRUE(create_plan_dep->ready());

    const auto table = mgr._table_map.at(table_id);
    std::unique_lock l(table->_lock);
    // attempts at about 0, 50, 150, 350, 750, 1550 and 2550 ms, and the timeout at 3500 ms; without
    // the back-off thousands
    EXPECT_GE(table->_create_plan_failures, 5);
    EXPECT_LE(table->_create_plan_failures, 10);
    EXPECT_NE(table->_create_plan_failed_reason.find("timeout"), std::string::npos)
            << table->_create_plan_failed_reason;
    EXPECT_NE(table->_create_plan_failed_reason.find("injected"), std::string::npos)
            << table->_create_plan_failed_reason;
    EXPECT_TRUE(table->_create_plan_deps.empty());
}

namespace {

struct PlanRetryTestEnv {
    PlanRetryTestEnv(int64_t timeout_ms) {
        config::enable_debug_points = true;
        DebugPoints::instance()->add("GroupCommitTable._create_group_commit_load.error");
        config::group_commit_create_plan_timeout_ms = timeout_ms;
    }
    ~PlanRetryTestEnv() {
        DebugPoints::instance()->remove("GroupCommitTable._create_group_commit_load.error");
        config::enable_debug_points = original_debug_points;
        config::group_commit_create_plan_timeout_ms = original_timeout;
    }
    const bool original_debug_points = config::enable_debug_points;
    const int64_t original_timeout = config::group_commit_create_plan_timeout_ms;
};

// Starts a load on the table; it waits for a plan on the returned dependency.
std::shared_ptr<Dependency> start_load(GroupCommitMgr& mgr, int64_t table_id) {
    auto create_plan_dep = std::make_shared<Dependency>(0, 0, "CreateGroupCommitPlan", true);
    auto put_block_dep = std::make_shared<Dependency>(0, 0, "GroupCommitPutBlock", true);
    std::shared_ptr<LoadBlockQueue> queue;
    EXPECT_FALSE(mgr.get_first_block_load_queue(1, table_id, 0, 1, UniqueId::gen_uid(), queue,
                                                BeExecVersionManager::get_newest_version(),
                                                TGroupCommitMode::SYNC_MODE, create_plan_dep,
                                                put_block_dep)
                         .ok());
    return create_plan_dep;
}

// Milliseconds until the dependency is ready, or -1 after 10 s.
int64_t wait_ready(const std::shared_ptr<Dependency>& dep,
                   std::chrono::steady_clock::time_point since) {
    const auto deadline = since + std::chrono::seconds(10);
    while (!dep->ready() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!dep->ready()) {
        return -1;
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                                 since)
            .count();
}

} // namespace

// The back-off must not hold waiting loads past their timeout: with a timeout of 784 ms the
// attempts at 750 and 1550 ms used to release the load at 1550 ms.
TEST(GroupCommitCreatePlanRetryTest, TimeoutIsNotDelayedByTheBackOff) {
    for (int64_t timeout_ms : {97, 784, 1634}) {
        SCOPED_TRACE(timeout_ms);
        PlanRetryTestEnv env(timeout_ms);
        GroupCommitMgr mgr(ExecEnv::GetInstance());
        const auto start = std::chrono::steady_clock::now();
        const auto waited_ms = wait_ready(start_load(mgr, 3), start);
        EXPECT_GE(waited_ms, timeout_ms);
        EXPECT_LE(waited_ms, timeout_ms + 150);
    }
}

// A load that arrives after earlier loads timed out tries at once. It used to wait for the back-off
// of the earlier loads, up to 1 s, and failed without an attempt if its own timeout was shorter.
TEST(GroupCommitCreatePlanRetryTest, LoadsAfterATimeoutTryAtOnce) {
    PlanRetryTestEnv env(1700);
    GroupCommitMgr mgr(ExecEnv::GetInstance());
    constexpr int64_t table_id = 4;
    // attempts at about 0, 50, 150, 350, 750 and 1550 ms; the next one would be at 2550 ms
    ASSERT_GT(wait_ready(start_load(mgr, table_id), std::chrono::steady_clock::now()), 0);
    const auto table = mgr._table_map.at(table_id);
    {
        std::unique_lock l(table->_lock);
        ASSERT_GE(table->_create_plan_failures, 5);
        ASSERT_TRUE(table->_create_plan_deps.empty());
    }

    const auto start = std::chrono::steady_clock::now();
    auto dep = start_load(mgr, table_id);
    // the first attempt of the new load fails at once with the injected error
    int32_t failures = 0;
    while (std::chrono::steady_clock::now() < start + std::chrono::milliseconds(300)) {
        {
            std::unique_lock l(table->_lock);
            failures = table->_create_plan_failures;
            if (failures == 1) {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_EQ(failures, 1);
    EXPECT_GT(wait_ready(dep, start), 0);
}

} // namespace doris
