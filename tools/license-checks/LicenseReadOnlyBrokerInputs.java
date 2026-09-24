// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import org.apache.avro.Schema;
import org.apache.avro.generic.GenericData;
import org.apache.avro.generic.GenericRecord;
import org.apache.hadoop.conf.Configuration;
import org.apache.parquet.avro.AvroParquetWriter;
import org.apache.parquet.column.page.PageReadStore;
import org.apache.parquet.example.data.Group;
import org.apache.parquet.example.data.simple.convert.GroupRecordConverter;
import org.apache.parquet.hadoop.ParquetFileReader;
import org.apache.parquet.hadoop.ParquetWriter;
import org.apache.parquet.hadoop.metadata.CompressionCodecName;
import org.apache.parquet.io.ColumnIOFactory;
import org.apache.parquet.io.LocalInputFile;
import org.apache.parquet.io.LocalOutputFile;
import org.apache.parquet.io.MessageColumnIO;
import org.apache.parquet.io.RecordReader;
import org.apache.parquet.schema.LogicalTypeAnnotation;
import org.apache.parquet.schema.MessageType;
import org.apache.parquet.schema.PrimitiveType.PrimitiveTypeName;
import org.apache.parquet.schema.Type.Repetition;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/** Creates LP026's two local input files; independently reads every Parquet row before manifest publication. */
public final class LicenseReadOnlyBrokerInputs {
    private LicenseReadOnlyBrokerInputs() {
    }

    private static void require(boolean value, String message) {
        LicenseReadOnlyBrokerFixture.require(value, message);
    }

    private static void writeParquet(Path path) throws Exception {
        Schema schema = new Schema.Parser().parse("{\"type\":\"record\",\"name\":\"lp026_row\","
                + "\"fields\":[{\"name\":\"id\",\"type\":\"int\"},"
                + "{\"name\":\"payload\",\"type\":\"string\"}]}");
        try (ParquetWriter<GenericRecord> writer = AvroParquetWriter.<GenericRecord>builder(new LocalOutputFile(path))
                .withConf(new Configuration(false)).withSchema(schema)
                .withCompressionCodec(CompressionCodecName.UNCOMPRESSED).withDictionaryEncoding(false)
                .withRowGroupSize(65536).withPageSize(4096).build()) {
            for (int id = 1; id <= 2; id++) {
                GenericRecord row = new GenericData.Record(schema);
                row.put("id", id);
                row.put("payload", id == 1 ? "lp026-a" : "lp026-b");
                writer.write(row);
            }
        }
    }

    static Map<String, Object> independentlyReadParquet(Path path) throws Exception {
        List<Map<String, Object>> rows = new ArrayList<>();
        String schemaText;
        try (ParquetFileReader reader = ParquetFileReader.open(new LocalInputFile(path))) {
            MessageType schema = reader.getFooter().getFileMetaData().getSchema();
            schemaText = schema.toString();
            require(schema.getFieldCount() == 2 && schema.getFieldName(0).equals("id")
                    && schema.getFieldName(1).equals("payload"), "PARQUET_COLUMN_MISMATCH");
            require(schema.getType(0).isRepetition(Repetition.REQUIRED)
                    && schema.getType(1).isRepetition(Repetition.REQUIRED), "PARQUET_NULLABILITY_MISMATCH");
            require(schema.getType(0).asPrimitiveType().getPrimitiveTypeName() == PrimitiveTypeName.INT32
                    && schema.getType(1).asPrimitiveType().getPrimitiveTypeName() == PrimitiveTypeName.BINARY
                    && schema.getType(1).getLogicalTypeAnnotation()
                    instanceof LogicalTypeAnnotation.StringLogicalTypeAnnotation, "PARQUET_TYPE_MISMATCH");
            require(reader.getFooter().getBlocks().stream().mapToLong(block -> block.getRowCount()).sum() == 2,
                    "PARQUET_FOOTER_ROW_COUNT");
            MessageColumnIO columnIO = new ColumnIOFactory().getColumnIO(schema);
            PageReadStore pages;
            while ((pages = reader.readNextRowGroup()) != null) {
                RecordReader<Group> records = columnIO.getRecordReader(pages, new GroupRecordConverter(schema));
                for (long index = 0; index < pages.getRowCount(); index++) {
                    require(rows.size() < 2, "PARQUET_EXTRA_ROW");
                    Group row = records.read();
                    require(row.getFieldRepetitionCount(0) == 1 && row.getFieldRepetitionCount(1) == 1,
                            "PARQUET_NONSCALAR_ROW");
                    rows.add(Map.of("id", row.getInteger(0, 0), "payload", row.getBinary(1, 0).toStringUsingUTF8()));
                }
            }
        }
        // The low-level Group reader does not reuse the Avro writer schema or writer's records.
        List<Map<String, Object>> expected = List.of(Map.of("id", 1, "payload", "lp026-a"),
                Map.of("id", 2, "payload", "lp026-b"));
        require(rows.equals(expected), "PARQUET_COMPLETE_ROW_MODEL_MISMATCH");
        return Map.of("schema_valid", true, "parquet_rows", rows, "parquet_schema", schemaText);
    }

    public static void main(String[] args) throws Exception {
        require(args.length == 1, "EXPECTED_ONE_EXISTING_EMPTY_OWNED_DIRECTORY");
        Path directory = LicenseReadOnlyBrokerFixture.ownedDirectory(args[0]);
        try (Stream<Path> children = Files.list(directory)) {
            require(children.findAny().isEmpty(), "INPUT_DIRECTORY_NOT_EMPTY");
        }
        Path csv = directory.resolve("rows.csv");
        Path parquet = directory.resolve("rows.parquet");
        Files.writeString(csv, "1,lp026-a\n2,lp026-b\n", StandardCharsets.US_ASCII,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        writeParquet(parquet);
        byte[] csvBytes = LicenseReadOnlyBrokerFixture.boundedRead(csv, 1024);
        List<Map<String, Object>> csvRows = new ArrayList<>();
        for (String line : new String(csvBytes, StandardCharsets.US_ASCII).split("\n")) {
            String[] fields = line.split(",", -1);
            require(fields.length == 2, "CSV_COLUMN_COUNT");
            csvRows.add(Map.of("id", Integer.parseInt(fields[0]), "payload", fields[1]));
        }
        require(csvRows.equals(List.of(Map.of("id", 1, "payload", "lp026-a"),
                Map.of("id", 2, "payload", "lp026-b"))), "CSV_COMPLETE_ROW_MODEL_MISMATCH");
        Map<String, Object> validation = new LinkedHashMap<>(independentlyReadParquet(parquet));
        byte[] parquetBytes = LicenseReadOnlyBrokerFixture.boundedRead(parquet,
                LicenseReadOnlyBrokerFixture.MAX_FILE_BYTES);
        String csvSha = LicenseReadOnlyBrokerFixture.sha256(csvBytes);
        String parquetSha = LicenseReadOnlyBrokerFixture.sha256(parquetBytes);
        validation.put("schema_version", 1);
        validation.put("independent_reader", "ParquetFileReader+GroupRecordConverter");
        validation.put("csv_rows", csvRows);
        validation.put("csv_sha256", csvSha);
        validation.put("parquet_sha256", parquetSha);
        validation.put("parquet_size", parquetBytes.length);
        validation.put("rows_match_model", true);
        Map<String, Object> origins = new LinkedHashMap<>();
        for (Class<?> type : List.of(AvroParquetWriter.class, ParquetFileReader.class, GroupRecordConverter.class,
                Schema.class, Configuration.class, org.apache.parquet.format.PageHeader.class)) {
            origins.put(type.getName(), type.getProtectionDomain().getCodeSource().getLocation().toString());
        }
        validation.put("loaded_origins", origins);
        LicenseReadOnlyBrokerFixture.writeNewJson(directory.resolve("input-validation.json"), validation);
        List<Map<String, Object>> files = List.of(
                Map.of("uri", LicenseReadOnlyBrokerFixture.CSV_URI, "path", csv.toString(), "format", "CSV",
                        "size", csvBytes.length, "sha256", csvSha, "rows", 2),
                Map.of("uri", LicenseReadOnlyBrokerFixture.PARQUET_URI, "path", parquet.toString(), "format", "PARQUET",
                        "size", parquetBytes.length, "sha256", parquetSha, "rows", 2));
        LicenseReadOnlyBrokerFixture.writeNewJson(directory.resolve("input-manifest.json"),
                Map.of("schema_version", 1, "files", files, "rows", 2,
                        "columns", List.of(Map.of("name", "id", "type", "INT32"),
                                Map.of("name", "payload", "type", "UTF8"))));
    }
}
