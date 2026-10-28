// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.planner.massdb;

import org.apache.doris.common.Config;
import org.apache.doris.planner.GroupCommitPlanner;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class GroupCommitInsertRpcTimeoutTest {
    private int previousMargin;
    private int previousMultiplier;

    @Before
    public void setUp() {
        previousMargin = Config.group_commit_insert_rpc_timeout_second;
        previousMultiplier = Config.group_commit_timeout_multipler;
        Config.group_commit_insert_rpc_timeout_second = 300;
        Config.group_commit_timeout_multipler = 10;
    }

    @After
    public void tearDown() {
        Config.group_commit_insert_rpc_timeout_second = previousMargin;
        Config.group_commit_timeout_multipler = previousMultiplier;
    }

    @Test
    public void defaultInsertTimeoutNoLongerBoundsTheRpc() {
        // insert_timeout defaults to 4 hours; the internal load of a 10 s interval times out after 600 s.
        Assert.assertEquals(900, GroupCommitPlanner.getGroupCommitInsertRpcTimeoutSec(14400, 10000));
    }

    @Test
    public void longGroupCommitIntervalsExtendTheRpcTimeout() {
        Assert.assertEquals(1800 + 300, GroupCommitPlanner.getGroupCommitInsertRpcTimeoutSec(14400, 180000));
        Assert.assertEquals(605 + 300, GroupCommitPlanner.getGroupCommitInsertRpcTimeoutSec(14400, 60500));
    }

    @Test
    public void shorterInsertTimeoutStillWins() {
        Assert.assertEquals(60, GroupCommitPlanner.getGroupCommitInsertRpcTimeoutSec(60, 10000));
        Assert.assertEquals(1, GroupCommitPlanner.getGroupCommitInsertRpcTimeoutSec(0, 10000));
    }

    @Test
    public void zeroMarginOrMultiplierKeepsTheInsertTimeout() {
        Config.group_commit_insert_rpc_timeout_second = 0;
        Assert.assertEquals(14400, GroupCommitPlanner.getGroupCommitInsertRpcTimeoutSec(14400, 10000));
        Config.group_commit_insert_rpc_timeout_second = 300;
        Config.group_commit_timeout_multipler = 0;
        Assert.assertEquals(14400, GroupCommitPlanner.getGroupCommitInsertRpcTimeoutSec(14400, 10000));
    }
}
