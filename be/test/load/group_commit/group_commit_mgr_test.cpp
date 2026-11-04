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
    // attempts at about 0, 50, 150, 350, 750, 1550, 2550 and 3550 ms (the last one finds the
    // timeout); without the back-off thousands
    EXPECT_GE(table->_create_plan_failures, 5);
    EXPECT_LE(table->_create_plan_failures, 10);
    EXPECT_NE(table->_create_plan_failed_reason.find("timeout"), std::string::npos)
            << table->_create_plan_failed_reason;
    EXPECT_NE(table->_create_plan_failed_reason.find("injected"), std::string::npos)
            << table->_create_plan_failed_reason;
    EXPECT_TRUE(table->_create_plan_deps.empty());
}

} // namespace doris
