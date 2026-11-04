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
// Modified for MassDB SQL. See MODIFICATIONS.md for details.

#include "service/http/action/stream_load.h"

#include <gen_cpp/PaloInternalService_types.h>
#include <gen_cpp/PlanNodes_types.h>
#include <gtest/gtest.h>

#include <memory>

#include "common/config.h"
#include "event2/buffer.h"
#include "event2/event.h"
#include "event2/http.h"
#include "event2/http_struct.h"
#include "evhttp.h"
#include "load/group_commit/wal/wal_manager.h"
#include "load/stream_load/stream_load_context.h"
#include "runtime/exec_env.h"
#include "service/http/action/http_stream.h"
#include "service/http/ev_http_server.h"
#include "service/http/http_channel.h"
#include "service/http/http_common.h"
#include "service/http/http_handler.h"
#include "service/http/http_handler_with_auth.h"
#include "service/http/http_headers.h"
#include "service/http/http_request.h"
#include "service/http/utils.h"
#include "util/defer_op.h"

namespace doris {

class StreamLoadTest : public testing::Test {
public:
    StreamLoadTest() = default;
    virtual ~StreamLoadTest() = default;
    void SetUp() override {}
    void TearDown() override { ExecEnv::GetInstance()->clear_wal_mgr(); }
};

void http_request_done_cb(struct evhttp_request* req, void* arg) {
    event_base_loopbreak((struct event_base*)arg);
}

TEST_F(StreamLoadTest, TestHeader) {
    // 1G
    auto wal_mgr = WalManager::create_unique(ExecEnv::GetInstance(), config::group_commit_wal_path);
    static_cast<void>(wal_mgr->_wal_dirs_info->add("test_path_1", 1000, 0, 0));
    static_cast<void>(wal_mgr->_wal_dirs_info->add("test_path_2", 10000, 0, 0));
    static_cast<void>(wal_mgr->_wal_dirs_info->add("test_path_3", 100000, 0, 0));
    ExecEnv::GetInstance()->set_wal_mgr(std::move(wal_mgr));
    // 1. empty info
    {
        auto* evhttp_req = evhttp_request_new(nullptr, nullptr);
        HttpRequest req(evhttp_req);
        EXPECT_EQ(req.header(HttpHeaders::CONTENT_LENGTH).empty(), true);
        evhttp_request_free(evhttp_req);
    }

    // 2. chunked stream load whih group commit
    {
        //struct event_base* base = nullptr;
        char uri[] = "Http://127.0.0.1/test.txt";
        auto evhttp_req = evhttp_request_new(nullptr, nullptr);
        evhttp_req->type = EVHTTP_REQ_GET;
        evhttp_req->uri = uri;
        evhttp_req->uri_elems = evhttp_uri_parse(uri);
        evhttp_add_header(evhttp_req->input_headers, HTTP_GROUP_COMMIT.c_str(), "true");
        HttpRequest req(evhttp_req);
        req.init_from_evhttp();
        EXPECT_EQ(req.header(HttpHeaders::CONTENT_LENGTH).empty(), true);
        evhttp_uri_free(evhttp_req->uri_elems);
        evhttp_req->uri = nullptr;
        evhttp_req->uri_elems = nullptr;
        evhttp_request_free(evhttp_req);
    }

    // 3. small stream load whih group commit
    {
        char uri[] = "Http://127.0.0.1/test.txt";
        auto evhttp_req = evhttp_request_new(nullptr, nullptr);
        evhttp_req->type = EVHTTP_REQ_GET;
        evhttp_req->uri = uri;
        evhttp_req->uri_elems = evhttp_uri_parse(uri);
        evhttp_add_header(evhttp_req->input_headers, HTTP_GROUP_COMMIT.c_str(), "true");
        evhttp_add_header(evhttp_req->input_headers, HttpHeaders::CONTENT_LENGTH, "20000");
        HttpRequest req(evhttp_req);
        req.init_from_evhttp();
        EXPECT_EQ(req.header(HttpHeaders::CONTENT_LENGTH), "20000");
        EXPECT_EQ(load_size_smaller_than_wal_limit(20000), true);
        evhttp_uri_free(evhttp_req->uri_elems);
        evhttp_req->uri = nullptr;
        evhttp_req->uri_elems = nullptr;
        evhttp_request_free(evhttp_req);
    }

    // 4. large stream load whih group commit
    {
        char uri[] = "Http://127.0.0.1/test.txt";
        auto evhttp_req = evhttp_request_new(nullptr, nullptr);
        evhttp_req->type = EVHTTP_REQ_GET;
        evhttp_req->uri = uri;
        evhttp_req->uri_elems = evhttp_uri_parse(uri);
        evhttp_add_header(evhttp_req->input_headers, HTTP_GROUP_COMMIT.c_str(), "true");
        evhttp_add_header(evhttp_req->input_headers, HttpHeaders::CONTENT_LENGTH, "1073741824");
        HttpRequest req(evhttp_req);
        req.init_from_evhttp();
        EXPECT_EQ(req.header(HttpHeaders::CONTENT_LENGTH), "1073741824");
        EXPECT_EQ(load_size_smaller_than_wal_limit(1073741824), false);
        evhttp_uri_free(evhttp_req->uri_elems);
        evhttp_req->uri = nullptr;
        evhttp_req->uri_elems = nullptr;
        evhttp_request_free(evhttp_req);
    }
}

TEST_F(StreamLoadTest, JsonBodySizeLimitPlusOneErrorIncludesExactBytes) {
    const auto original_json_max_mb = config::streaming_load_json_max_mb;
    Defer restore_json_max_mb {
            [original_json_max_mb] { config::streaming_load_json_max_mb = original_json_max_mb; }};
    config::streaming_load_json_max_mb = 100;

    auto* evhttp_req = evhttp_request_new(nullptr, nullptr);
    HttpRequest req(evhttp_req);
    req.set_header(HttpHeaders::AUTHORIZATION, "Basic cm9vdDo=");
    req.set_header(HTTP_FORMAT_KEY, "json");
    req.set_header(HttpHeaders::CONTENT_LENGTH, "104857601");

    StreamLoadAction action(nullptr);
    auto ctx = std::make_shared<StreamLoadContext>(nullptr);
    auto status = action._on_header(&req, ctx);

    EXPECT_TRUE(status.is<ErrorCode::EXCEEDED_LIMIT>());
    EXPECT_EQ(status.to_string_no_stack(),
              "[E-217]json body size 104857601 bytes (100.00 MiB) exceeds the limit of 104857600 "
              "bytes (100 MiB) set by BE's conf streaming_load_json_max_mb. Increase it if you "
              "are sure this load is reasonable");
    evhttp_request_free(evhttp_req);
}

TEST_F(StreamLoadTest, CsvBodySizeLimitPlusOneErrorIncludesExactBytes) {
    const auto original_max_mb = config::streaming_load_max_mb;
    Defer restore_max_mb {[original_max_mb] { config::streaming_load_max_mb = original_max_mb; }};
    config::streaming_load_max_mb = 100;

    auto* evhttp_req = evhttp_request_new(nullptr, nullptr);
    HttpRequest req(evhttp_req);
    req.set_header(HttpHeaders::AUTHORIZATION, "Basic cm9vdDo=");
    req.set_header(HTTP_FORMAT_KEY, "csv");
    req.set_header(HttpHeaders::CONTENT_LENGTH, "104857601");

    StreamLoadAction action(nullptr);
    auto ctx = std::make_shared<StreamLoadContext>(nullptr);
    auto status = action._on_header(&req, ctx);

    EXPECT_TRUE(status.is<ErrorCode::EXCEEDED_LIMIT>());
    EXPECT_EQ(status.to_string_no_stack(),
              "[E-217]body size 104857601 bytes (100.00 MiB) exceeds the limit of 104857600 bytes "
              "(100 MiB) set by BE's conf streaming_load_max_mb. Increase it if you are sure this "
              "load is reasonable");
    evhttp_request_free(evhttp_req);
}

TEST_F(StreamLoadTest, HttpStreamBodySizeLimitPlusOneErrorIncludesExactBytes) {
    const auto original_max_mb = config::streaming_load_max_mb;
    Defer restore_max_mb {[original_max_mb] { config::streaming_load_max_mb = original_max_mb; }};
    config::streaming_load_max_mb = 100;

    auto* evhttp_req = evhttp_request_new(nullptr, nullptr);
    HttpRequest req(evhttp_req);
    req.set_header(HttpHeaders::AUTHORIZATION, "Basic cm9vdDo=");
    req.set_header(HttpHeaders::CONTENT_LENGTH, "104857601");

    HttpStreamAction action(nullptr);
    auto ctx = std::make_shared<StreamLoadContext>(nullptr);
    auto status = action._on_header(&req, ctx);

    EXPECT_TRUE(status.is<ErrorCode::EXCEEDED_LIMIT>());
    EXPECT_EQ(status.to_string_no_stack(),
              "[E-217]body size 104857601 bytes (100.00 MiB) exceeds the limit of 104857600 bytes "
              "(100 MiB) set by BE config `streaming_load_max_mb`. Increase it if you are sure "
              "this load is reasonable");
    evhttp_request_free(evhttp_req);
}

namespace {

// A chunked load with a label, as Flink sends one, through _handle_group_commit.
struct LabeledChunkedLoad {
    evhttp_request* evhttp_req = evhttp_request_new(nullptr, nullptr);
    HttpRequest req {evhttp_req};
    std::shared_ptr<StreamLoadContext> ctx = std::make_shared<StreamLoadContext>(nullptr);

    LabeledChunkedLoad(const std::string& group_commit, bool two_phase_commit,
                       const std::string& transfer_encoding = "chunked") {
        if (!transfer_encoding.empty()) {
            req.set_header(HttpHeaders::TRANSFER_ENCODING, transfer_encoding);
        } else {
            req.set_header(HttpHeaders::CONTENT_LENGTH, "19");
        }
        if (!group_commit.empty()) {
            req.set_header(HTTP_GROUP_COMMIT, group_commit);
        }
        ctx->label = "flink_label_1";
        ctx->two_phase_commit = two_phase_commit;
    }
    ~LabeledChunkedLoad() { evhttp_request_free(evhttp_req); }
};

} // namespace

// A chunked load drops its label only when it asks for group commit by its group_commit header and
// can take it. Dropping it for a load without that header (a normal load unless the table's
// group_commit_mode says otherwise) or for a two-phase commit made a retry with the same label load
// the data twice.
TEST_F(StreamLoadTest, ChunkedLoadKeepsItsLabelUnlessItGoesThroughGroupCommit) {
    const auto original_wait = config::wait_internal_group_commit_finish;
    Defer restore {[original_wait] { config::wait_internal_group_commit_finish = original_wait; }};
    config::wait_internal_group_commit_finish = false;
    StreamLoadAction action(nullptr);
    {
        LabeledChunkedLoad load("", false);
        ASSERT_TRUE(action._handle_group_commit(&load.req, load.ctx).ok());
        EXPECT_EQ(load.ctx->label, "flink_label_1");
        EXPECT_FALSE(load.ctx->group_commit);
        EXPECT_EQ(load.ctx->group_commit_mode, ""); // the table's group_commit_mode decides
    }
    {
        LabeledChunkedLoad load("", true);
        ASSERT_TRUE(action._handle_group_commit(&load.req, load.ctx).ok());
        EXPECT_EQ(load.ctx->label, "flink_label_1");
        EXPECT_FALSE(load.ctx->group_commit);
    }
    {
        LabeledChunkedLoad load("off_mode", false);
        ASSERT_TRUE(action._handle_group_commit(&load.req, load.ctx).ok());
        EXPECT_EQ(load.ctx->label, "flink_label_1");
        EXPECT_FALSE(load.ctx->group_commit);
    }
    {
        LabeledChunkedLoad load("sync_mode", true);
        ASSERT_TRUE(action._handle_group_commit(&load.req, load.ctx).ok());
        EXPECT_EQ(load.ctx->label, "flink_label_1");
        EXPECT_FALSE(load.ctx->group_commit);
    }
    {
        // Flink with group commit, as before
        LabeledChunkedLoad load("sync_mode", false);
        ASSERT_TRUE(action._handle_group_commit(&load.req, load.ctx).ok());
        EXPECT_EQ(load.ctx->label, "");
        EXPECT_TRUE(load.ctx->group_commit);
        EXPECT_EQ(load.ctx->group_commit_mode, "sync_mode");
    }
    {
        // a load of known length still may not set both
        LabeledChunkedLoad load("sync_mode", false, "");
        auto st = action._handle_group_commit(&load.req, load.ctx);
        EXPECT_TRUE(st.is<ErrorCode::INVALID_ARGUMENT>()) << st;
        EXPECT_EQ(load.ctx->label, "flink_label_1");
    }
}

TEST_F(StreamLoadTest, ChunkedHttpStreamKeepsItsLabelUnlessItGoesThroughGroupCommit) {
    const auto original_wait = config::wait_internal_group_commit_finish;
    Defer restore {[original_wait] { config::wait_internal_group_commit_finish = original_wait; }};
    config::wait_internal_group_commit_finish = false;
    HttpStreamAction action(nullptr);
    {
        LabeledChunkedLoad load("sync_mode", true);
        ASSERT_TRUE(action._handle_group_commit(&load.req, load.ctx).ok());
        EXPECT_EQ(load.ctx->label, "flink_label_1");
        EXPECT_FALSE(load.ctx->group_commit);
    }
    {
        LabeledChunkedLoad load("sync_mode", false);
        ASSERT_TRUE(action._handle_group_commit(&load.req, load.ctx).ok());
        EXPECT_EQ(load.ctx->label, "");
        EXPECT_TRUE(load.ctx->group_commit);
    }
}

// The plan of a Parquet or ORC load is made before the body arrives, with the file size from
// Content-Length. A chunked request has none: the scan was given a size of 0 and read nothing, and
// the load succeeded with no rows. The size of the received file replaces it before the plan runs.
TEST_F(StreamLoadTest, ChunkedLocalFileLoadScansTheReceivedFile) {
    auto ctx = std::make_shared<StreamLoadContext>(nullptr);
    ctx->data_saved_path = "/storage/stream_load/db/t.20261104.1";
    ctx->receive_bytes = 123457;
    auto make_range = [](const std::string& path) {
        TFileRangeDesc range;
        range.__set_path(path);
        range.__set_start_offset(0);
        range.__set_size(0);
        range.__set_file_size(0);
        return range;
    };
    TScanRangeParams scan_range;
    scan_range.scan_range.ext_scan_range.file_scan_range.__set_ranges(
            {make_range(ctx->data_saved_path), make_range("/another/file")});
    TPipelineInstanceParams instance;
    instance.per_node_scan_ranges[0] = {scan_range};
    ctx->put_result.pipeline_params.__set_local_params({instance});

    StreamLoadAction::_set_saved_file_size(ctx.get());

    const auto& ranges = ctx->put_result.pipeline_params.local_params[0]
                                 .per_node_scan_ranges[0][0]
                                 .scan_range.ext_scan_range.file_scan_range.ranges;
    EXPECT_EQ(ranges[0].size, 123457);
    EXPECT_EQ(ranges[0].file_size, 123457);
    EXPECT_EQ(ranges[0].start_offset, 0);
    EXPECT_EQ(ranges[1].size, 0);
    EXPECT_EQ(ranges[1].file_size, 0);
}
} // namespace doris
