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

#pragma once
#include "format/generic_reader.h"
#include "load/group_commit/wal/wal_file_reader.h"
#include "runtime/descriptors.h"

namespace doris {
#include "common/compile_check_begin.h"
struct ScannerCounter;

// Whether a WAL block column of type `block_type` can be handed on as `expected` without conversion:
// the same type up to nullability. VARIANT columns are always handed on as they are.
bool wal_column_type_matches(const DataTypePtr& block_type, const DataTypePtr& expected);

// ARRAY, MAP, STRUCT and VARIANT: a WAL block is converted to such a type only when it is all NULL.
bool wal_column_is_nested(const DataTypePtr& type);

// Converts a WAL block column to the type the reader hands on. The blocks of one WAL can disagree on a
// column's type (seen in WALs from 4.1.0: a VARCHAR block before DOUBLE blocks, an all-NULL IPV6 block
// before INT blocks), and a reader that hands one block's column on under another block's type
// crashes or fails on every replay. An all-NULL column becomes NULLs of the target type. Any other
// column is cast the way the file scan casts a file column to its table type, if the target type is
// scalar (callers pass the table column's type, so nothing is cast twice). Nothing else is converted to
// a nested type: the file scan maps no scalar to a nested type, and maps nested types element by element,
// which a CAST need not match. A failed or refused cast is an error, never NULLs in place of values.
// The result keeps the column's nullability. Callers fail the replay with an error other than
// DATA_QUALITY_ERROR, which would make WalTable delete the WAL.
Status convert_wal_column(RuntimeState* state, const ColumnWithTypeAndName& column,
                          const DataTypePtr& target_type, ColumnPtr* result);

class WalReader : public GenericReader {
    ENABLE_FACTORY_CREATOR(WalReader);

public:
    WalReader(RuntimeState* state);
    ~WalReader() override = default;
    Status init_reader(const TupleDescriptor* tuple_descriptor);
    Status get_next_block(Block* block, size_t* read_rows, bool* eof) override;
    Status get_columns(std::unordered_map<std::string, DataTypePtr>* name_to_type,
                       std::unordered_set<std::string>* missing_cols) override;

    Status close() override {
        if (_wal_reader) {
            return _wal_reader->finalize();
        }
        return Status::OK();
    }

private:
    RuntimeState* _state = nullptr;
    int64_t _wal_id;
    std::string _wal_path;
    std::shared_ptr<doris::WalFileReader> _wal_reader = nullptr;
    const TupleDescriptor* _tuple_descriptor = nullptr;
    // column_id, column_pos
    std::map<int64_t, int64_t> _column_pos_map;
    int64_t _column_id_count;
    uint32_t _version = 0;
    // ordinal of the next block, for error messages
    int64_t _block_index = 0;
};
#include "common/compile_check_end.h"
} // namespace doris
