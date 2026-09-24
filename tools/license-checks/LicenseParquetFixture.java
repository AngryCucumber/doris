// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
import org.apache.parquet.hadoop.metadata.BlockMetaData;
import org.apache.parquet.hadoop.metadata.ColumnChunkMetaData;
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
import java.security.MessageDigest;
import java.util.Locale;

/** Local-only LP008 writer and independent low-level reader; no SQL, HTTP or filesystem service. */
public final class LicenseParquetFixture {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Schema SCHEMA = new Schema.Parser().parse("{\"type\":\"record\","
            + "\"name\":\"lp008_row\",\"fields\":[{\"name\":\"id\",\"type\":\"long\"},"
            + "{\"name\":\"grp\",\"type\":\"int\"},{\"name\":\"v\",\"type\":\"long\"},"
            + "{\"name\":\"payload\",\"type\":\"string\"}]}");

    private LicenseParquetFixture() {
    }

    private static String hex(byte[] bytes) {
        char[] alphabet = "0123456789abcdef".toCharArray();
        char[] result = new char[bytes.length * 2];
        for (int index = 0; index < bytes.length; index++) {
            result[index * 2] = alphabet[(bytes[index] & 255) >>> 4];
            result[index * 2 + 1] = alphabet[bytes[index] & 15];
        }
        return new String(result);
    }

    private static Path file(Path directory, int index) {
        return directory.resolve(String.format(Locale.ROOT, "part-%05d.parquet", index));
    }

    private static void generate(Path directory, int files, int rows) throws Exception {
        Files.createDirectory(directory);
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        for (int index = 0; index < files; index++) {
            try (ParquetWriter<GenericRecord> writer = AvroParquetWriter.<GenericRecord>builder(
                    new LocalOutputFile(file(directory, index)))
                    .withConf(new Configuration(false)).withSchema(SCHEMA)
                    .withCompressionCodec(CompressionCodecName.UNCOMPRESSED)
                    .withDictionaryEncoding(false).withRowGroupSize(8L * 1024 * 1024)
                    .withPageSize(64 * 1024).build()) {
                for (int offset = 0; offset < rows; offset++) {
                    long id = (long) index * rows + offset;
                    GenericRecord record = new GenericData.Record(SCHEMA);
                    record.put("id", id);
                    record.put("grp", (int) (id % 1024));
                    record.put("v", id % 100000);
                    record.put("payload", hex(md5.digest(Long.toString(id).getBytes(StandardCharsets.US_ASCII))));
                    writer.write(record);
                }
            }
        }
    }

    private static void checkSchema(MessageType schema) {
        String[] names = {"id", "grp", "v", "payload"};
        PrimitiveTypeName[] types = {PrimitiveTypeName.INT64, PrimitiveTypeName.INT32,
                PrimitiveTypeName.INT64, PrimitiveTypeName.BINARY};
        if (schema.getFieldCount() != names.length) {
            throw new IllegalStateException("Unexpected column count: " + schema);
        }
        for (int index = 0; index < names.length; index++) {
            if (!schema.getFieldName(index).equals(names[index])
                    || !schema.getType(index).isRepetition(Repetition.REQUIRED)
                    || schema.getType(index).asPrimitiveType().getPrimitiveTypeName() != types[index]) {
                throw new IllegalStateException("Unexpected column: " + schema.getType(index));
            }
        }
        if (!(schema.getType(3).getLogicalTypeAnnotation()
                instanceof LogicalTypeAnnotation.StringLogicalTypeAnnotation)) {
            throw new IllegalStateException("Payload must carry the UTF-8 string annotation");
        }
    }

    private static ObjectNode read(Path path) throws Exception {
        ObjectNode result = JSON.createObjectNode().put("name", path.getFileName().toString());
        MessageDigest allRows = MessageDigest.getInstance("SHA-256");
        MessageDigest payloads = MessageDigest.getInstance("SHA-256");
        long count = 0;
        long[] sums = new long[3];
        long[] minima = {Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE};
        long[] maxima = {Long.MIN_VALUE, Long.MIN_VALUE, Long.MIN_VALUE};
        int minPayload = Integer.MAX_VALUE;
        int maxPayload = 0;
        try (ParquetFileReader reader = ParquetFileReader.open(new LocalInputFile(path))) {
            MessageType schema = reader.getFooter().getFileMetaData().getSchema();
            checkSchema(schema);
            result.put("schema", schema.toString());
            result.put("created_by", reader.getFooter().getFileMetaData().getCreatedBy());
            long footerRows = 0;
            for (BlockMetaData block : reader.getFooter().getBlocks()) {
                footerRows += block.getRowCount();
                for (ColumnChunkMetaData column : block.getColumns()) {
                    if (column.getCodec() != CompressionCodecName.UNCOMPRESSED) {
                        throw new IllegalStateException("Unexpected codec: " + column.getCodec());
                    }
                }
            }
            result.put("footer_rows", footerRows);
            result.put("row_groups", reader.getFooter().getBlocks().size());
            MessageColumnIO columnIO = new ColumnIOFactory().getColumnIO(schema);
            PageReadStore pages;
            while ((pages = reader.readNextRowGroup()) != null) {
                RecordReader<Group> records = columnIO.getRecordReader(pages, new GroupRecordConverter(schema));
                for (long offset = 0; offset < pages.getRowCount(); offset++) {
                    Group row = records.read();
                    for (int column = 0; column < 4; column++) {
                        if (row.getFieldRepetitionCount(column) != 1) {
                            throw new IllegalStateException("Missing or repeated scalar at row " + count);
                        }
                    }
                    long[] values = {row.getLong(0, 0), row.getInteger(1, 0), row.getLong(2, 0)};
                    String payload = row.getBinary(3, 0).toStringUsingUTF8();
                    byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
                    minPayload = Math.min(minPayload, payloadBytes.length);
                    maxPayload = Math.max(maxPayload, payloadBytes.length);
                    for (int column = 0; column < 3; column++) {
                        sums[column] = Math.addExact(sums[column], values[column]);
                        minima[column] = Math.min(minima[column], values[column]);
                        maxima[column] = Math.max(maxima[column], values[column]);
                    }
                    // Read values only: expected data is calculated separately by the Python model.
                    allRows.update((values[0] + "\t" + values[1] + "\t" + values[2] + "\t" + payload + "\n")
                            .getBytes(StandardCharsets.UTF_8));
                    payloads.update(payloadBytes);
                    payloads.update((byte) '\n');
                    count++;
                }
            }
            if (footerRows != count) {
                throw new IllegalStateException("Footer/read row count mismatch");
            }
        }
        result.put("rows", count).put("rows_sha256", hex(allRows.digest()))
                .put("payloads_sha256", hex(payloads.digest()))
                .put("min_payload_bytes", minPayload).put("max_payload_bytes", maxPayload);
        String[] names = {"id", "grp", "v"};
        for (int column = 0; column < 3; column++) {
            result.put("sum_" + names[column], sums[column]);
            result.put("min_" + names[column], minima[column]);
            result.put("max_" + names[column], maxima[column]);
        }
        return result;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            throw new IllegalArgumentException("generate|read directory files rows_per_file report.json");
        }
        Path directory = Path.of(args[1]).toAbsolutePath();
        int files = Integer.parseInt(args[2]);
        int rows = Integer.parseInt(args[3]);
        if (files < 1 || files > 100 || rows != 10000) {
            throw new IllegalArgumentException("Bounded fixture requires 1..100 files and 10000 rows/file");
        }
        ObjectNode report = JSON.createObjectNode().put("mode", args[0])
                .put("java_version", System.getProperty("java.version"))
                .put("java_runtime_version", System.getProperty("java.runtime.version"))
                .put("java_vendor", System.getProperty("java.vendor"));
        long started = System.nanoTime();
        if (args[0].equals("generate")) {
            generate(directory, files, rows);
            report.put("files", files).put("rows_per_file", rows);
        } else if (args[0].equals("read")) {
            ArrayNode results = report.putArray("files");
            for (int index = 0; index < files; index++) {
                results.add(read(file(directory, index)));
            }
        } else {
            throw new IllegalArgumentException("Unknown local operation: " + args[0]);
        }
        report.put("elapsed_nanos", System.nanoTime() - started);
        ObjectNode origins = report.putObject("loaded_origins");
        for (Class<?> type : new Class<?>[] {AvroParquetWriter.class, ParquetFileReader.class,
                GroupRecordConverter.class, Schema.class, Configuration.class, ObjectMapper.class}) {
            origins.put(type.getName(), type.getProtectionDomain().getCodeSource().getLocation().toString());
        }
        Files.writeString(Path.of(args[4]), JSON.writerWithDefaultPrettyPrinter().writeValueAsString(report) + "\n");
    }
}
