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

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <memory>

#include "agent/be_exec_version_manager.h"
#include "core/block/block.h"
#include "core/column/column_string.h"
#include "core/data_type/data_type_array.h"
#include "core/data_type/data_type_ipv6.h"
#include "core/data_type/data_type_map.h"
#include "core/data_type/data_type_nullable.h"
#include "core/data_type/data_type_number.h"
#include "core/data_type/data_type_string.h"
#include "core/data_type/data_type_struct.h"
#include "io/fs/local_file_system.h"
#include "load/group_commit/wal/wal_file_reader.h"
#include "load/group_commit/wal/wal_reader.h"
#include "load/group_commit/wal/wal_writer.h"
#include "runtime/runtime_state.h"

namespace doris::format::wal {
namespace {

std::string temporary_wal_path() {
    const auto root = std::filesystem::temp_directory_path() /
                      ("doris-wal-v2-" +
                       std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    const auto path = root / "1" / "2" / "1_1_1_test";
    std::filesystem::create_directories(path.parent_path());
    return path.string();
}

PBlock serialize_block(const Block& block) {
    PBlock pblock;
    size_t uncompressed_bytes = 0;
    size_t compressed_bytes = 0;
    int64_t compress_time = 0;
    EXPECT_TRUE(block.serialize(BeExecVersionManager::get_newest_version(), &pblock,
                                &uncompressed_bytes, &compressed_bytes, &compress_time,
                                segment_v2::CompressionTypePB::SNAPPY)
                        .ok());
    return pblock;
}

// A WAL of one column (unique id 7) whose blocks carry the given columns, and a reader over it whose
// projected (table) column 7 has `table_type`, as WalTableReader builds it.
struct MixedWal {
    std::string path;
    RuntimeState state;
    std::unique_ptr<WalReader> reader;

    MixedWal(const std::vector<ColumnWithTypeAndName>& blocks, const DataTypePtr& table_type) {
        path = temporary_wal_path();
        WalWriter writer(path);
        EXPECT_TRUE(writer.init(io::global_local_filesystem()).ok());
        EXPECT_TRUE(writer.append_header("7").ok());
        for (const auto& column : blocks) {
            auto pblock = serialize_block(Block({column}));
            EXPECT_TRUE(writer.append_blocks({&pblock}).ok());
        }
        EXPECT_TRUE(writer.finalize().ok());

        ColumnDefinition projected;
        projected.name = "c";
        projected.type = table_type;
        projected.identifier = Field::create_field<TYPE_INT>(7);
        std::shared_ptr<io::FileSystemProperties> properties;
        std::unique_ptr<io::FileDescription> description;
        reader = std::make_unique<WalReader>(properties, description, nullptr, nullptr,
                                             std::vector<ColumnDefinition> {projected});
        reader->_state = &state;
        reader->_wal_path = path;
        reader->_wal_reader = std::make_shared<WalFileReader>(path);
        EXPECT_TRUE(reader->_wal_reader->init().ok());
        std::string encoded_ids;
        EXPECT_TRUE(reader->_wal_reader->read_header(reader->_version, encoded_ids).ok());
        EXPECT_TRUE(parse_wal_column_ids(encoded_ids, &reader->_column_ids).ok());
    }

    ~MixedWal() {
        static_cast<void>(reader->close());
        std::filesystem::remove_all(
                std::filesystem::path(path).parent_path().parent_path().parent_path());
    }

    // The file schema type of column 7, then the reader opened for it.
    DataTypePtr open() {
        std::vector<ColumnDefinition> schema;
        EXPECT_TRUE(reader->get_schema(&schema).ok());
        EXPECT_EQ(schema.size(), 1);
        auto request = std::make_shared<FileScanRequest>();
        request->local_positions.emplace(LocalColumnId(0), LocalIndex(0));
        EXPECT_TRUE(reader->open(std::move(request)).ok());
        return schema[0].type;
    }

    // Reads the next block into a block of `file_type`.
    Status next(const DataTypePtr& file_type, ColumnPtr* column, bool* eof) {
        Block output({{file_type->create_column(), file_type, "c"}});
        size_t rows = 0;
        RETURN_IF_ERROR(reader->get_block(&output, &rows, eof));
        *column = output.get_by_position(0).column;
        return Status::OK();
    }
};

ColumnWithTypeAndName nullable_strings(const std::vector<std::string>& values) {
    const auto type = make_nullable(std::make_shared<DataTypeString>());
    auto column = type->create_column();
    for (const auto& value : values) {
        column->insert_data(value.data(), value.size());
    }
    return {std::move(column), type, "c"};
}

template <PrimitiveType T, typename DataType>
ColumnWithTypeAndName nullable_numbers(
        const std::vector<typename PrimitiveTypeTraits<T>::CppType>& values) {
    const auto type = make_nullable(std::make_shared<DataType>());
    auto column = type->create_column();
    for (const auto& value : values) {
        column->insert(Field::create_field<T>(value));
    }
    return {std::move(column), type, "c"};
}

ColumnWithTypeAndName all_null(const DataTypePtr& nested, size_t rows) {
    const auto type = make_nullable(nested);
    auto column = type->create_column();
    column->insert_many_defaults(rows);
    return {std::move(column), type, "c"};
}

} // namespace

TEST(WalReaderV2Test, ParseColumnIdsPreservesHeaderOrder) {
    std::vector<int32_t> column_ids;
    ASSERT_TRUE(parse_wal_column_ids("17,4,99", &column_ids).ok());
    EXPECT_EQ(column_ids, (std::vector<int32_t> {17, 4, 99}));
}

TEST(WalReaderV2Test, ParseColumnIdsRejectsMalformedOrAmbiguousHeaders) {
    std::vector<int32_t> column_ids;
    EXPECT_FALSE(parse_wal_column_ids("", &column_ids).ok());
    EXPECT_FALSE(parse_wal_column_ids("17,,99", &column_ids).ok());
    EXPECT_FALSE(parse_wal_column_ids("17,nope,99", &column_ids).ok());
    EXPECT_FALSE(parse_wal_column_ids("17,4,17", &column_ids).ok());
}

TEST(WalReaderV2Test, WriterBackedReaderPreservesNestedSchemaAndMovesFirstPayload) {
    const auto wal_path = temporary_wal_path();
    const auto int_type = make_nullable(std::make_shared<DataTypeInt32>());
    const auto array_type = make_nullable(std::make_shared<DataTypeArray>(int_type));
    const auto string_type = make_nullable(std::make_shared<DataTypeString>());
    const auto map_type = make_nullable(std::make_shared<DataTypeMap>(string_type, int_type));
    const auto struct_type = make_nullable(std::make_shared<DataTypeStruct>(
            DataTypes {int_type, array_type}, Strings {"id", "nested_items"}));

    Block source;
    auto array_column = array_type->create_column();
    array_column->insert_default();
    source.insert({std::move(array_column), array_type, "items"});
    auto string_column = string_type->create_column();
    string_column->insert_data("value", 5);
    source.insert({std::move(string_column), string_type, "renamed_later"});
    auto map_column = map_type->create_column();
    map_column->insert_default();
    source.insert({std::move(map_column), map_type, "properties"});
    auto struct_column = struct_type->create_column();
    struct_column->insert_default();
    source.insert({std::move(struct_column), struct_type, "record"});
    auto pblock = serialize_block(source);

    WalWriter writer(wal_path);
    ASSERT_TRUE(writer.init(io::global_local_filesystem()).ok());
    ASSERT_TRUE(writer.append_header("17,4,88,99").ok());
    ASSERT_TRUE(writer.append_blocks({&pblock}).ok());
    ASSERT_TRUE(writer.finalize().ok());

    std::shared_ptr<io::FileSystemProperties> properties;
    std::unique_ptr<io::FileDescription> description;
    WalReader reader(properties, description, nullptr, nullptr, {});
    reader._wal_reader = std::make_shared<WalFileReader>(wal_path);
    ASSERT_TRUE(reader._wal_reader->init().ok());
    std::string encoded_ids;
    ASSERT_TRUE(reader._wal_reader->read_header(reader._version, encoded_ids).ok());
    ASSERT_TRUE(parse_wal_column_ids(encoded_ids, &reader._column_ids).ok());

    std::vector<ColumnDefinition> schema;
    ASSERT_TRUE(reader.get_schema(&schema).ok());
    ASSERT_EQ(schema.size(), 4);
    ASSERT_EQ(schema[0].children.size(), 1);
    EXPECT_TRUE(schema[0].children[0].type->is_nullable());
    ASSERT_EQ(schema[2].children.size(), 2);
    EXPECT_TRUE(schema[2].children[0].type->is_nullable());
    EXPECT_TRUE(schema[2].children[1].type->is_nullable());
    ASSERT_EQ(schema[3].children.size(), 2);
    EXPECT_EQ(schema[3].children[0].name, "id");
    EXPECT_EQ(schema[3].children[1].name, "nested_items");
    ASSERT_EQ(schema[3].children[1].children.size(), 1);

    auto request = std::make_shared<FileScanRequest>();
    request->local_positions.emplace(LocalColumnId(1), LocalIndex(0));
    request->local_positions.emplace(LocalColumnId(0), LocalIndex(1));
    ASSERT_TRUE(reader.open(std::move(request)).ok());
    Block output({
            {string_type->create_column(), string_type, "renamed"},
            {array_type->create_column(), array_type, "items"},
    });
    size_t rows = 0;
    bool eof = false;
    ASSERT_TRUE(reader.get_block(&output, &rows, &eof).ok());
    EXPECT_EQ(rows, 1);
    EXPECT_FALSE(eof);
    EXPECT_EQ(reader._first_block.ByteSizeLong(), 0);
    EXPECT_EQ(output.get_by_position(0).column->get_data_at(0).to_string(), "value");

    ASSERT_TRUE(reader.close().ok());
    std::filesystem::remove_all(
            std::filesystem::path(wal_path).parent_path().parent_path().parent_path());
}

TEST(WalReaderV2Test, MaterializationTransfersColumnOwnership) {
    std::shared_ptr<io::FileSystemProperties> properties;
    std::unique_ptr<io::FileDescription> description;
    WalReader reader(properties, description, nullptr, nullptr, {});
    reader._request = std::make_shared<FileScanRequest>();
    reader._request->local_positions.emplace(LocalColumnId(0), LocalIndex(0));

    const auto type = std::make_shared<DataTypeString>();
    auto source_column = ColumnString::create();
    source_column->insert_data("payload", 7);
    const auto* original = source_column.get();
    Block source({{std::move(source_column), type, "value"}});
    Block output({{type->create_column(), type, "value"}});

    ASSERT_TRUE(reader._materialize_requested_columns(&source, &output, 0).ok());
    EXPECT_FALSE(static_cast<bool>(source.get_by_position(0).column));
    EXPECT_EQ(output.get_by_position(0).column.get(), original);
}

// The 4.1.0 WAL of table 1769744610596: a VARCHAR block before DOUBLE blocks. The file schema used to
// come from the first block, so the second block went through a string -> double cast and the BE died.
TEST(WalReaderV2Test, StringBlockBeforeDoubleBlocksIsCastToTheTableType) {
    const auto double_type = make_nullable(std::make_shared<DataTypeFloat64>());
    MixedWal wal({nullable_strings({"1.5", "not a number", "104.06230831375629"}),
                  nullable_numbers<TYPE_DOUBLE, DataTypeFloat64>({2.5, 3.25})},
                 double_type);
    const auto file_type = wal.open();
    EXPECT_TRUE(file_type->equals(*double_type)) << file_type->get_name();

    ColumnPtr column;
    bool eof = false;
    ASSERT_TRUE(wal.next(file_type, &column, &eof).ok());
    ASSERT_EQ(column->size(), 3);
    EXPECT_EQ((*column)[0].get<TYPE_DOUBLE>(), 1.5);
    EXPECT_TRUE((*column)[1].is_null()); // not strict: as a load casts an invalid value
    EXPECT_EQ((*column)[2].get<TYPE_DOUBLE>(), 104.06230831375629);
    ASSERT_TRUE(wal.next(file_type, &column, &eof).ok());
    ASSERT_EQ(column->size(), 2);
    EXPECT_EQ((*column)[0].get<TYPE_DOUBLE>(), 2.5);
    EXPECT_EQ((*column)[1].get<TYPE_DOUBLE>(), 3.25);
    ASSERT_TRUE(wal.next(file_type, &column, &eof).ok());
    EXPECT_TRUE(eof);
}

// The 4.1.0 WAL of WA_BASIC_0023: an all-NULL IPV6 block before INT blocks. No CAST turns IPV6 into
// INT, so the all-NULL block has to become INT NULLs.
TEST(WalReaderV2Test, AllNullBlockOfAnotherTypeBecomesNulls) {
    const auto int_type = make_nullable(std::make_shared<DataTypeInt32>());
    MixedWal wal({all_null(std::make_shared<DataTypeIPv6>(), 4),
                  nullable_numbers<TYPE_INT, DataTypeInt32>({41, 42})},
                 int_type);
    const auto file_type = wal.open();
    EXPECT_TRUE(file_type->equals(*int_type)) << file_type->get_name();

    ColumnPtr column;
    bool eof = false;
    ASSERT_TRUE(wal.next(file_type, &column, &eof).ok());
    ASSERT_EQ(column->size(), 4);
    for (size_t row = 0; row < 4; ++row) {
        EXPECT_TRUE((*column)[row].is_null());
    }
    ASSERT_TRUE(wal.next(file_type, &column, &eof).ok());
    ASSERT_EQ(column->size(), 2);
    EXPECT_EQ((*column)[0].get<TYPE_INT>(), 41);
    EXPECT_EQ((*column)[1].get<TYPE_INT>(), 42);
}

// A later block whose type differs from the first one's (and the table's) is cast as well.
TEST(WalReaderV2Test, LaterBlockOfAnotherTypeIsCast) {
    const auto bigint_type = make_nullable(std::make_shared<DataTypeInt64>());
    MixedWal wal({nullable_numbers<TYPE_BIGINT, DataTypeInt64>({5000000000}),
                  nullable_numbers<TYPE_INT, DataTypeInt32>({7, -8})},
                 bigint_type);
    const auto file_type = wal.open();
    ColumnPtr column;
    bool eof = false;
    ASSERT_TRUE(wal.next(file_type, &column, &eof).ok());
    EXPECT_EQ((*column)[0].get<TYPE_BIGINT>(), 5000000000);
    ASSERT_TRUE(wal.next(file_type, &column, &eof).ok());
    ASSERT_EQ(column->size(), 2);
    EXPECT_EQ((*column)[0].get<TYPE_BIGINT>(), 7);
    EXPECT_EQ((*column)[1].get<TYPE_BIGINT>(), -8);
}

// A block that no CAST can convert fails with the block and the types named, instead of reaching a
// cast that reads it as another column type, and without an error that would get the WAL deleted.
TEST(WalReaderV2Test, UnconvertibleBlockFailsWithAClearError) {
    const auto int_type = make_nullable(std::make_shared<DataTypeInt32>());
    MixedWal wal({nullable_numbers<TYPE_INT, DataTypeInt32>({1}),
                  nullable_numbers<TYPE_IPV6, DataTypeIPv6>({IPv6(7)})},
                 int_type);
    const auto file_type = wal.open();
    ColumnPtr column;
    bool eof = false;
    ASSERT_TRUE(wal.next(file_type, &column, &eof).ok());
    auto st = wal.next(file_type, &column, &eof);
    ASSERT_FALSE(st.ok());
    // WalTable deletes a WAL whose replay fails with DATA_QUALITY_ERROR; this one must be kept
    EXPECT_TRUE(st.is<ErrorCode::INTERNAL_ERROR>()) << st;
    EXPECT_NE(st.to_string().find("block 1 column c (unique id 7) has type Nullable(IPv6)"),
              std::string::npos)
            << st;
}

// Blocks that agree with the table keep the first block's schema and are handed on without a copy.
TEST(WalReaderV2Test, MatchingBlocksAreHandedOnUnchanged) {
    const auto varchar_type = make_nullable(std::make_shared<DataTypeString>(20, TYPE_VARCHAR));
    MixedWal wal({nullable_strings({"a", "b"})}, varchar_type);
    const auto file_type = wal.open();
    EXPECT_EQ(file_type->get_name(), make_nullable(std::make_shared<DataTypeString>())->get_name());

    auto request = std::make_shared<FileScanRequest>();
    request->local_positions.emplace(LocalColumnId(0), LocalIndex(0));
    wal.reader->_request = request;
    auto source = nullable_strings({"x"});
    const auto* original = source.column.get();
    Block source_block({source});
    source.column = nullptr;
    Block output({{file_type->create_column(), file_type, "c"}});
    ASSERT_TRUE(wal.reader->_materialize_requested_columns(&source_block, &output, 0).ok());
    EXPECT_EQ(output.get_by_position(0).column.get(), original);
}

TEST(WalColumnConversionTest, TypeMatchIgnoresNullabilityAndStringLength) {
    const auto string_type = std::make_shared<DataTypeString>();
    EXPECT_TRUE(wal_column_type_matches(make_nullable(string_type),
                                        std::make_shared<DataTypeString>(20, TYPE_VARCHAR)));
    EXPECT_TRUE(wal_column_type_matches(std::make_shared<DataTypeInt32>(),
                                        make_nullable(std::make_shared<DataTypeInt32>())));
    EXPECT_FALSE(wal_column_type_matches(std::make_shared<DataTypeInt32>(),
                                         std::make_shared<DataTypeInt64>()));
    EXPECT_FALSE(wal_column_type_matches(make_nullable(string_type),
                                         make_nullable(std::make_shared<DataTypeFloat64>())));
}

// The legacy reader (enable_file_scanner_v2 = false) shares the conversion; strict casts fail.
TEST(WalColumnConversionTest, StrictCastFailsInsteadOfWritingNulls) {
    RuntimeState state;
    TQueryOptions options;
    options.__set_enable_strict_cast(true);
    state.set_query_options(options);
    ColumnPtr result;
    auto st = convert_wal_column(&state, nullable_strings({"1.5", "not a number"}),
                                 std::make_shared<DataTypeFloat64>(), &result);
    EXPECT_FALSE(st.ok());

    RuntimeState non_strict;
    ASSERT_TRUE(convert_wal_column(&non_strict, nullable_strings({"1.5", "not a number"}),
                                   std::make_shared<DataTypeFloat64>(), &result)
                        .ok());
    ASSERT_EQ(result->size(), 2);
    EXPECT_TRUE(result->is_nullable()); // keeps the WAL column's nullability
    EXPECT_EQ((*result)[0].get<TYPE_DOUBLE>(), 1.5);
    EXPECT_TRUE((*result)[1].is_null());
}

} // namespace doris::format::wal
