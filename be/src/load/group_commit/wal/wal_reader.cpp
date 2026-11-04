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

#include "wal_reader.h"

#include <absl/strings/str_split.h>

#include <cstring>

#include "agent/be_exec_version_manager.h"
#include "common/logging.h"
#include "core/block/block.h"
#include "core/column/column_nullable.h"
#include "core/data_type/data_type_nullable.h"
#include "cpp/sync_point.h"
#include "exprs/function/simple_function_factory.h"
#include "exprs/function_context.h"
#include "load/group_commit/wal/wal_manager.h"
#include "runtime/runtime_state.h"

namespace doris {
#include "common/compile_check_begin.h"
bool wal_column_type_matches(const DataTypePtr& block_type, const DataTypePtr& expected) {
    if (block_type->equals(*expected)) {
        return true;
    }
    const auto block_nested = remove_nullable(block_type);
    const auto expected_nested = remove_nullable(expected);
    return block_nested->equals(*expected_nested) ||
           (block_nested->get_primitive_type() == TYPE_VARIANT &&
            expected_nested->get_primitive_type() == TYPE_VARIANT);
}

bool wal_column_is_nested(const DataTypePtr& type) {
    switch (remove_nullable(type)->get_primitive_type()) {
    case TYPE_ARRAY:
    case TYPE_MAP:
    case TYPE_STRUCT:
    case TYPE_VARIANT:
        return true;
    default:
        return false;
    }
}

bool wal_column_is_all_null(const IColumn& column) {
    const auto full_column = column.convert_to_full_column_if_const();
    const auto* nullable = check_and_get_column<ColumnNullable>(full_column.get());
    return nullable != nullptr &&
           std::memchr(nullable->get_null_map_data().data(), 0, full_column->size()) == nullptr;
}

Status convert_wal_column(RuntimeState* state, const ColumnWithTypeAndName& column,
                          const DataTypePtr& target_type, const DataTypePtr& table_type,
                          ColumnPtr* result) {
    DORIS_CHECK(state != nullptr);
    DORIS_CHECK(result != nullptr);
    const auto result_type =
            column.type->is_nullable() ? make_nullable(target_type) : remove_nullable(target_type);
    const auto full_column = column.column->convert_to_full_column_if_const();
    const auto rows = full_column->size();
    if (wal_column_is_all_null(*full_column)) {
        // also the only way for a type that no CAST accepts, e.g. an IPV6 column planned for an INT
        // column, whose values were lost to NULL when it was written
        auto nulls = result_type->create_column();
        nulls->insert_many_defaults(rows);
        *result = std::move(nulls);
        return Status::OK();
    }
    if (wal_column_is_nested(table_type)) {
        return Status::InternalError(
                "{} is not converted to {}: the table column is {}, to which only all-NULL blocks "
                "are converted",
                column.type->get_name(), result_type->get_name(), table_type->get_name());
    }
    ColumnsWithTypeAndName arguments {{full_column, column.type, column.name}};
    // as format::Cast and VExprContext set up the cast of a file column to its table type
    auto function = SimpleFunctionFactory::instance().get_function(
            "CAST", arguments, result_type,
            {.new_version_unix_timestamp = state->query_options().new_version_unix_timestamp},
            state->be_exec_version());
    if (function == nullptr) {
        return Status::InternalError("no CAST from {} to {}", column.type->get_name(),
                                     result_type->get_name());
    }
    Block cast_block {arguments};
    cast_block.insert({nullptr, result_type, column.name});
    auto context = FunctionContext::create_context(state, result_type, {column.type});
    context->set_enable_strict_mode(state->enable_strict_mode());
    RETURN_IF_ERROR(function->execute(context.get(), cast_block, {0}, 1, rows));
    *result = cast_block.get_by_position(1).column->convert_to_full_column_if_const();
    if ((*result)->size() != rows) {
        return Status::InternalError("CAST from {} to {} returned {} rows for {}",
                                     column.type->get_name(), result_type->get_name(),
                                     (*result)->size(), rows);
    }
    return Status::OK();
}

WalReader::WalReader(RuntimeState* state) : _state(state) {
    _wal_id = state->wal_id();
}

Status WalReader::init_reader(const TupleDescriptor* tuple_descriptor) {
    _tuple_descriptor = tuple_descriptor;
    RETURN_IF_ERROR(_state->exec_env()->wal_mgr()->get_wal_path(_wal_id, _wal_path));
    _wal_reader = std::make_shared<doris::WalFileReader>(_wal_path);
    RETURN_IF_ERROR(_wal_reader->init());
    return Status::OK();
}

Status WalReader::get_next_block(Block* block, size_t* read_rows, bool* eof) {
    //read src block
    PBlock pblock;
    auto st = _wal_reader->read_block(pblock);
    if (st.is<ErrorCode::END_OF_FILE>()) {
        LOG(INFO) << "read eof on wal:" << _wal_path;
        *read_rows = 0;
        *eof = true;
        return Status::OK();
    }
    if (!st.ok()) {
        LOG(WARNING) << "Failed to read wal on path = " << _wal_path;
        return st;
    }
    const int64_t block_index = _block_index++;
    int be_exec_version = pblock.has_be_exec_version() ? pblock.be_exec_version() : 0;
    if (!BeExecVersionManager::check_be_exec_version(be_exec_version)) {
        return Status::DataQualityError("check be exec version fail when reading wal file {}",
                                        _wal_path);
    }
    Block src_block;
    size_t uncompressed_size = 0;
    int64_t uncompressed_time = 0;
    RETURN_IF_ERROR(src_block.deserialize(pblock, &uncompressed_size, &uncompressed_time));
    //convert to dst block
    Block dst_block;
    int index = 0;
    auto output_block_columns = block->get_columns_with_type_and_name();
    size_t output_block_column_size = output_block_columns.size();
    TEST_SYNC_POINT_CALLBACK("WalReader::set_column_id_count", &_column_id_count);
    TEST_SYNC_POINT_CALLBACK("WalReader::set_out_block_column_size", &output_block_column_size);
    if (_column_id_count != src_block.columns() ||
        output_block_column_size != _tuple_descriptor->slots().size()) {
        return Status::InternalError(
                "not equal wal _column_id_count={} vs wal block columns size={}, "
                "output block columns size={} vs tuple_descriptor size={}",
                std::to_string(_column_id_count), std::to_string(src_block.columns()),
                std::to_string(output_block_column_size),
                std::to_string(_tuple_descriptor->slots().size()));
    }
    for (auto* slot_desc : _tuple_descriptor->slots()) {
        auto pos = _column_pos_map[slot_desc->col_unique_id()];
        if (pos >= src_block.columns()) {
            return Status::InternalError("read wal {} fail, pos {}, columns size {}", _wal_path,
                                         pos, src_block.columns());
        }
        const auto& source = src_block.get_by_position(pos);
        ColumnPtr column_ptr = source.column;
        if (!column_ptr && slot_desc->is_nullable()) {
            column_ptr = make_nullable(column_ptr);
        }
        const auto& target_type = output_block_columns[index].type;
        if (!wal_column_type_matches(source.type, target_type)) {
            auto convert_st =
                    convert_wal_column(_state, source, target_type, target_type, &column_ptr);
            if (!convert_st.ok()) {
                // not DATA_QUALITY_ERROR: WalTable deletes a WAL that fails with it, and the other
                // blocks hold rows that can be loaded; the WAL is kept and retried
                return Status::InternalError(
                        "WAL {} block {} column {} (unique id {}) has type {}, the table column is "
                        "{}: {}",
                        _wal_path, block_index, slot_desc->col_name(), slot_desc->col_unique_id(),
                        source.type->get_name(), target_type->get_name(),
                        convert_st.to_string_no_stack());
            }
        }
        dst_block.insert(index, ColumnWithTypeAndName(std::move(column_ptr),
                                                      output_block_columns[index].type,
                                                      output_block_columns[index].name));
        index++;
    }
    block->swap(dst_block);
    *read_rows = block->rows();
    VLOG_DEBUG << "read block rows:" << *read_rows;
    return Status::OK();
}

Status WalReader::get_columns(std::unordered_map<std::string, DataTypePtr>* name_to_type,
                              std::unordered_set<std::string>* missing_cols) {
    std::string col_ids;
    RETURN_IF_ERROR(_wal_reader->read_header(_version, col_ids));
    std::vector<std::string> column_id_vector =
            absl::StrSplit(col_ids, ",", absl::SkipWhitespace());
    _column_id_count = column_id_vector.size();
    try {
        int64_t pos = 0;
        for (auto col_id_str : column_id_vector) {
            auto col_id = std::strtoll(col_id_str.c_str(), nullptr, 10);
            _column_pos_map.emplace(col_id, pos);
            pos++;
        }
    } catch (const std::invalid_argument& e) {
        return Status::InvalidArgument("Invalid format, {}", e.what());
    }
    return Status::OK();
}

#include "common/compile_check_end.h"
} // namespace doris