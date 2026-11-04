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

#include "format_v2/wal/wal_reader.h"

#include <absl/strings/numbers.h>
#include <absl/strings/str_split.h>

#include <ranges>
#include <unordered_set>
#include <utility>

#include "agent/be_exec_version_manager.h"
#include "common/cast_set.h"
#include "core/block/block.h"
#include "core/data_type/data_type_factory.hpp"
#include "core/data_type/data_type_nullable.h"
#include "format_v2/column_mapper.h"
#include "format_v2/materialized_reader_util.h"
#include "load/group_commit/wal/wal_file_reader.h"
#include "load/group_commit/wal/wal_manager.h"
#include "load/group_commit/wal/wal_reader.h"
#include "runtime/exec_env.h"
#include "runtime/runtime_state.h"

namespace doris::format::wal {
namespace {

class WalColumnMapper final : public TableColumnMapper {
public:
    using TableColumnMapper::TableColumnMapper;

    Status create_mapping(const std::vector<ColumnDefinition>& projected_columns,
                          const std::map<std::string, Field>& partition_values,
                          const std::vector<ColumnDefinition>& file_schema) override {
        for (const auto& projected : projected_columns) {
            if (!projected.has_identifier_field_id()) {
                return Status::InternalError("WAL projected column {} has no unique id",
                                             projected.name);
            }
            const auto found = std::ranges::find_if(file_schema, [&](const auto& file_column) {
                return file_column.has_identifier_field_id() &&
                       file_column.get_identifier_field_id() == projected.get_identifier_field_id();
            });
            if (found == file_schema.end()) {
                return Status::InternalError("WAL does not contain column unique id {} ({})",
                                             projected.get_identifier_field_id(), projected.name);
            }
        }
        return TableColumnMapper::create_mapping(projected_columns, partition_values, file_schema);
    }

protected:
    bool enable_lazy_materialization() const override { return false; }
    bool force_full_complex_scan_projection() const override { return true; }
};

ColumnDefinition build_wal_column_definition(const PColumnMeta& meta, int32_t local_id) {
    ColumnDefinition field;
    field.local_id = local_id;
    field.name = meta.name();
    field.type = make_nullable(DataTypeFactory::instance().create_data_type(meta));
    field.children.reserve(meta.children_size());
    for (int child_idx = 0; child_idx < meta.children_size(); ++child_idx) {
        field.children.push_back(build_wal_column_definition(meta.children(child_idx), child_idx));
        // The mapper matches WAL columns by field id (WalTableReader), down to STRUCT children, and
        // the table column's children carry their positions as field ids (AccessPathParser numbers
        // them so without an external schema). A child without one matched nothing and every STRUCT
        // value was replayed as NULLs.
        field.children.back().identifier = Field::create_field<TYPE_INT>(child_idx);
    }
    return field;
}

} // namespace

Status parse_wal_column_ids(const std::string& encoded, std::vector<int32_t>* column_ids) {
    DORIS_CHECK(column_ids != nullptr);
    column_ids->clear();
    if (encoded.empty()) {
        return Status::Corruption("WAL header contains no column ids");
    }

    std::unordered_set<int32_t> seen;
    for (const absl::string_view token : absl::StrSplit(encoded, ',')) {
        int32_t column_id = 0;
        if (token.empty() || !absl::SimpleAtoi(token, &column_id)) {
            return Status::Corruption("invalid WAL column id '{}'", std::string(token));
        }
        if (!seen.emplace(column_id).second) {
            return Status::Corruption("duplicate WAL column id {}", column_id);
        }
        column_ids->push_back(column_id);
    }
    return Status::OK();
}

WalReader::WalReader(std::shared_ptr<io::FileSystemProperties>& system_properties,
                     std::unique_ptr<io::FileDescription>& file_description,
                     std::shared_ptr<io::IOContext> io_ctx, RuntimeProfile* profile,
                     const std::vector<ColumnDefinition>& projected_columns)
        : FileReader(system_properties, file_description, std::move(io_ctx), profile),
          _projected_columns(projected_columns) {}

WalReader::~WalReader() {
    static_cast<void>(close());
}

Status WalReader::init(RuntimeState* state) {
    if (state == nullptr || state->exec_env() == nullptr ||
        state->exec_env()->wal_mgr() == nullptr) {
        return Status::InvalidArgument("WAL v2 reader requires a runtime WAL manager");
    }
    _state = state;
    RETURN_IF_ERROR(state->exec_env()->wal_mgr()->get_wal_path(state->wal_id(), _wal_path));
    _wal_reader = std::make_shared<doris::WalFileReader>(_wal_path);
    RETURN_IF_ERROR(_wal_reader->init());

    std::string encoded_column_ids;
    RETURN_IF_ERROR(_wal_reader->read_header(_version, encoded_column_ids));
    RETURN_IF_ERROR(parse_wal_column_ids(encoded_column_ids, &_column_ids));
    _reader_eof = false;
    _eof = false;
    return Status::OK();
}

Status WalReader::get_schema(std::vector<ColumnDefinition>* file_schema) const {
    if (file_schema == nullptr) {
        return Status::InvalidArgument("WAL v2 file_schema is null");
    }
    RETURN_IF_ERROR(_ensure_schema_loaded());
    *file_schema = _file_schema;
    return Status::OK();
}

std::unique_ptr<TableColumnMapper> WalReader::create_column_mapper(
        TableColumnMapperOptions options) const {
    return std::make_unique<WalColumnMapper>(std::move(options));
}

Status WalReader::open(std::shared_ptr<FileScanRequest> request) {
    RETURN_IF_ERROR(FileReader::open(std::move(request)));
    _first_block_consumed = false;
    _eof = false;
    _block_index = 0;
    return Status::OK();
}

Status WalReader::get_block(Block* file_block, size_t* rows, bool* eof) {
    DORIS_CHECK(file_block != nullptr);
    DORIS_CHECK(rows != nullptr);
    DORIS_CHECK(eof != nullptr);
    if (_request == nullptr) {
        return Status::InternalError("WAL v2 reader is not open");
    }

    *rows = 0;
    *eof = false;
    if (_reader_eof) {
        *eof = true;
        _eof = true;
        return Status::OK();
    }

    PBlock pblock;
    if (_first_block_loaded && !_first_block_consumed) {
        // Schema discovery owns the first payload temporarily; transfer it into the read path so
        // the reader neither retains a second PBlock nor forces protobuf to clone its buffers.
        pblock.Swap(&_first_block);
        _first_block_consumed = true;
        _first_block_loaded = false;
    } else {
        auto status = _wal_reader->read_block(pblock);
        if (status.is<ErrorCode::END_OF_FILE>()) {
            _reader_eof = true;
            *eof = true;
            _eof = true;
            return Status::OK();
        }
        RETURN_IF_ERROR(status);
    }
    RETURN_IF_ERROR(_validate_block_version(pblock));
    const int64_t block_index = _block_index++;

    Block source_block;
    size_t uncompressed_size = 0;
    int64_t decompress_time = 0;
    RETURN_IF_ERROR(source_block.deserialize(pblock, &uncompressed_size, &decompress_time));
    if (source_block.columns() != _column_ids.size()) {
        return Status::Corruption("WAL block has {} columns but header declares {}",
                                  source_block.columns(), _column_ids.size());
    }
    RETURN_IF_ERROR(_materialize_requested_columns(&source_block, file_block, block_index));
    *rows = file_block->rows();
    _record_scan_rows(cast_set<int64_t>(*rows));
    RETURN_IF_ERROR(
            apply_materialized_reader_filters(_request.get(), _io_ctx.get(), file_block, rows));
    return Status::OK();
}

Status WalReader::close() {
    _request.reset();
    _reader_eof = true;
    _eof = true;
    if (_wal_reader == nullptr) {
        return Status::OK();
    }
    auto status = _wal_reader->finalize();
    if (status.ok()) {
        _wal_reader.reset();
    }
    return status;
}

Status WalReader::_ensure_schema_loaded() const {
    if (_schema_inited) {
        return Status::OK();
    }

    auto status = _wal_reader->read_block(_first_block);
    if (status.is<ErrorCode::END_OF_FILE>()) {
        // An empty WAL still has a complete unique-id header. Use only matching projected types;
        // there is no data block from which unprojected physical types could be inferred.
        return _init_schema_from_block(nullptr);
    }
    RETURN_IF_ERROR(status);
    RETURN_IF_ERROR(_validate_block_version(_first_block));
    _first_block_loaded = true;
    return _init_schema_from_block(&_first_block);
}

Status WalReader::_validate_block_version(const PBlock& pblock) const {
    const int version = pblock.has_be_exec_version() ? pblock.be_exec_version() : 0;
    if (!BeExecVersionManager::check_be_exec_version(version)) {
        return Status::DataQualityError("unsupported BE execution version {} in WAL", version);
    }
    return Status::OK();
}

Status WalReader::_init_schema_from_block(const PBlock* pblock) const {
    if (pblock != nullptr && cast_set<size_t>(pblock->column_metas_size()) != _column_ids.size()) {
        return Status::Corruption("WAL block schema has {} columns but header declares {}",
                                  pblock->column_metas_size(), _column_ids.size());
    }

    _file_schema.clear();
    _table_types.assign(_column_ids.size(), nullptr);
    // deserialized only to see whether a first block column is all NULL
    std::unique_ptr<Block> first_block;
    // nested table columns whose first block is all NULL and of another type
    std::vector<size_t> all_null_first;
    for (size_t idx = 0; idx < _column_ids.size(); ++idx) {
        ColumnDefinition field;
        field.identifier = Field::create_field<TYPE_INT>(_column_ids[idx]);
        field.local_id = cast_set<int32_t>(idx);
        const auto projected = std::ranges::find_if(_projected_columns, [&](const auto& candidate) {
            return candidate.has_identifier_field_id() &&
                   candidate.get_identifier_field_id() == _column_ids[idx];
        });
        if (projected != _projected_columns.end()) {
            _table_types[idx] = projected->type;
        }
        if (pblock != nullptr) {
            const auto& meta = pblock->column_metas(cast_set<int>(idx));
            // WAL metadata is the file-local schema; preserve its complete nested shape so the
            // mapper can validate ARRAY/MAP/STRUCT projections instead of seeing an empty shell.
            field = build_wal_column_definition(meta, cast_set<int32_t>(idx));
            field.identifier = Field::create_field<TYPE_INT>(_column_ids[idx]);
            // The blocks of one WAL can disagree on a column's type, so the first block does not
            // describe the file. When it differs from the table column the WAL's column id names:
            // - a scalar table column takes the table type, so that every block is converted to the
            //   table type itself (_materialize_requested_columns) and never twice;
            // - an ARRAY, MAP, STRUCT or VARIANT one, to which nothing but all-NULL blocks is
            //   converted, keeps the type of the first block that holds a value, which the mapper
            //   maps as it maps a WAL of that type only; an all-NULL first block tells nothing
            //   (_describe_all_null_first_columns).
            if (projected != _projected_columns.end() &&
                !wal_column_type_matches(field.type, projected->type)) {
                if (!wal_column_is_nested(projected->type)) {
                    field.type = make_nullable(projected->type);
                    field.children.clear();
                } else {
                    if (first_block == nullptr) {
                        first_block = Block::create_unique();
                        size_t uncompressed_size = 0;
                        int64_t decompress_time = 0;
                        RETURN_IF_ERROR(first_block->deserialize(*pblock, &uncompressed_size,
                                                                 &decompress_time));
                    }
                    if (idx < first_block->columns() &&
                        wal_column_is_all_null(*first_block->get_by_position(idx).column)) {
                        all_null_first.push_back(idx);
                    }
                }
            }
        } else {
            if (projected == _projected_columns.end()) {
                continue;
            }
            field.name = projected->name;
            field.type = projected->type;
        }
        _file_schema.push_back(std::move(field));
    }
    if (!all_null_first.empty()) {
        _describe_all_null_first_columns(std::move(all_null_first));
    }
    _schema_inited = true;
    return Status::OK();
}

void WalReader::_describe_all_null_first_columns(std::vector<size_t> columns) const {
    // Reads the WAL a second time, one block at a time, until each column holds a value. Only WALs
    // whose blocks disagree on a nested column's type get here. A block that cannot be read ends
    // the search: the read of the WAL itself reports it.
    WalFileReader reader(_wal_path);
    uint32_t version = 0;
    std::string encoded_column_ids;
    auto status = reader.init();
    if (status.ok()) {
        status = reader.read_header(version, encoded_column_ids);
    }
    while (status.ok() && !columns.empty()) {
        PBlock pblock;
        status = reader.read_block(pblock);
        if (!status.ok() || !_validate_block_version(pblock).ok() ||
            cast_set<size_t>(pblock.column_metas_size()) != _column_ids.size()) {
            break;
        }
        Block block;
        size_t uncompressed_size = 0;
        int64_t decompress_time = 0;
        if (!block.deserialize(pblock, &uncompressed_size, &decompress_time).ok() ||
            block.columns() != _column_ids.size()) {
            break;
        }
        std::erase_if(columns, [&](size_t idx) {
            if (wal_column_is_all_null(*block.get_by_position(idx).column)) {
                return false;
            }
            auto field = build_wal_column_definition(pblock.column_metas(cast_set<int>(idx)),
                                                     cast_set<int32_t>(idx));
            field.identifier = _file_schema[idx].identifier;
            _file_schema[idx] = std::move(field);
            return true;
        });
    }
    static_cast<void>(reader.finalize());
    // NULL in every block: NULLs of the table type, with its children for the mapper
    for (const auto idx : columns) {
        auto& field = _file_schema[idx];
        field.type = make_nullable(_table_types[idx]);
        PColumnMeta table_meta;
        field.type->to_pb_column_meta(&table_meta);
        field.children = build_wal_column_definition(table_meta, field.local_id).children;
    }
}

Status WalReader::_materialize_requested_columns(Block* source_block, Block* file_block,
                                                 int64_t block_index) const {
    DORIS_CHECK(source_block != nullptr);
    for (const auto& [file_column_id, block_position] : _request->local_positions) {
        const auto source_idx = file_column_id.value();
        if (source_idx < 0 || cast_set<size_t>(source_idx) >= source_block->columns()) {
            return Status::Corruption("WAL request refers to invalid local column {}", source_idx);
        }
        if (block_position.value() >= file_block->columns()) {
            return Status::InternalError("WAL request has invalid block position {}",
                                         block_position.value());
        }
        const auto& target = file_block->get_by_position(block_position.value());
        auto& source = source_block->get_by_position(source_idx);
        // Deserialized WAL columns have a single owner. Move that ownership into the output block
        // before mutate() so wide payloads do not trigger copy-on-write deep clones.
        auto column = std::move(source.column);
        if (!wal_column_type_matches(source.type, target.type)) {
            // A block whose column type differs from the file schema: the mapper's cast for the
            // file schema type must not read it (a string cast reading a DOUBLE column crashes)
            ColumnPtr converted;
            const auto& table_type = cast_set<size_t>(source_idx) < _table_types.size() &&
                                                     _table_types[source_idx] != nullptr
                                             ? _table_types[source_idx]
                                             : target.type;
            auto st = convert_wal_column(_state, {std::move(column), source.type, source.name},
                                         target.type, table_type, &converted);
            if (!st.ok()) {
                // not DATA_QUALITY_ERROR: WalTable deletes a WAL that fails with it, and the other
                // blocks hold rows that can be loaded; the WAL is kept and retried
                return Status::InternalError(
                        "WAL {} block {} column {} (unique id {}) has type {}, the file schema "
                        "type is {}: {}",
                        _wal_path, block_index, source.name, _column_ids[source_idx],
                        source.type->get_name(), target.type->get_name(), st.to_string_no_stack());
            }
            column = std::move(converted);
        }
        column = make_column_nullable_if_needed(std::move(column), target.type);
        file_block->replace_by_position(block_position.value(), IColumn::mutate(std::move(column)));
    }
    return Status::OK();
}

} // namespace doris::format::wal
