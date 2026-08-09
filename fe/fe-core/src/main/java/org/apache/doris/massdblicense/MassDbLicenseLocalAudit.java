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

package org.apache.doris.massdblicense;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.regex.Pattern;

/** Append-only, hash-chained local audit for component-native License management calls. */
public final class MassDbLicenseLocalAudit {
    static final String DIRECTORY_NAME = "massdb-license-audit";
    static final String FILE_NAME = "management-audit-v1.jsonl";
    private static final long MAX_FILE_BYTES = 128L << 20;
    private static final int MAX_RECORD_BYTES = 16 << 10;
    private static final String ZERO_HASH = String.join("", Collections.nCopies(64, "0"));
    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");
    private static final Set<PosixFilePermission> DIRECTORY_PERMISSIONS =
            Collections.unmodifiableSet(EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE));
    private static final Set<PosixFilePermission> FILE_PERMISSIONS =
            Collections.unmodifiableSet(EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));
    private static final ObjectMapper STRICT_JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY);

    private final Path path;
    private long sequence;
    private String headHash = ZERO_HASH;

    private MassDbLicenseLocalAudit(Path path) {
        this.path = path;
    }

    public static MassDbLicenseLocalAudit open(Path metaDirectory) {
        if (metaDirectory == null || !metaDirectory.isAbsolute()) {
            fail("MASSDB_LICENSE_AUDIT_INVALID", "本地审计目录必须基于绝对meta目录");
        }
        Path directory = metaDirectory.normalize().resolve(DIRECTORY_NAME);
        try {
            FileAttribute<Set<PosixFilePermission>> directoryMode =
                    PosixFilePermissions.asFileAttribute(DIRECTORY_PERMISSIONS);
            Files.createDirectories(directory, directoryMode);
            Files.setPosixFilePermissions(directory, DIRECTORY_PERMISSIONS);
            requireDirectory(directory);
            Path path = directory.resolve(FILE_NAME);
            if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                FileAttribute<Set<PosixFilePermission>> fileMode =
                        PosixFilePermissions.asFileAttribute(FILE_PERMISSIONS);
                try (FileChannel ignored = FileChannel.open(path,
                        EnumSet.of(StandardOpenOption.CREATE_NEW,
                                StandardOpenOption.WRITE), fileMode)) {
                    ignored.force(true);
                }
                syncDirectory(directory);
            }
            MassDbLicenseLocalAudit audit = new MassDbLicenseLocalAudit(path);
            audit.restoreAndVerify();
            return audit;
        } catch (MassDbLicenseException failure) {
            throw failure;
        } catch (IOException | UnsupportedOperationException failure) {
            fail("MASSDB_LICENSE_AUDIT_IO", "无法创建或读取License本地审计文件");
            return null;
        }
    }

    public synchronized void append(Event event) {
        requireEvent(event);
        if (sequence == Long.MAX_VALUE) {
            fail("MASSDB_LICENSE_AUDIT_FULL", "License审计序列已耗尽");
        }
        Record record = new Record();
        record.sequence = sequence + 1;
        record.previousHash = headHash;
        record.occurredAt = event.occurredAt;
        record.principalSubjectDigest = event.principalSubjectDigest;
        record.principalRole = event.principalRole;
        record.method = event.method;
        record.path = event.path;
        record.idempotencyKeyDigest = event.idempotencyKeyDigest;
        record.phase = event.phase;
        record.resultCode = event.resultCode;
        record.httpStatus = event.httpStatus;
        record.hash = hash(record);
        byte[] encoded;
        try {
            encoded = STRICT_JSON.writeValueAsBytes(record);
        } catch (IOException failure) {
            fail("MASSDB_LICENSE_AUDIT_INVALID", "License审计记录无法编码");
            return;
        }
        if (encoded.length == 0 || encoded.length > MAX_RECORD_BYTES) {
            fail("MASSDB_LICENSE_AUDIT_INVALID", "License审计记录超过16KiB上限");
        }
        byte[] line = Arrays.copyOf(encoded, encoded.length + 1);
        line[line.length - 1] = '\n';
        requireFile(path);
        OpenOption[] options = new OpenOption[] {
                StandardOpenOption.WRITE,
                StandardOpenOption.APPEND,
                LinkOption.NOFOLLOW_LINKS
        };
        try (FileChannel channel = FileChannel.open(path, options)) {
            if (channel.size() + line.length > MAX_FILE_BYTES) {
                fail("MASSDB_LICENSE_AUDIT_FULL",
                        "License审计文件达到128MiB上限，必须按运维流程归档");
            }
            ByteBuffer buffer = ByteBuffer.wrap(line);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        } catch (MassDbLicenseException failure) {
            throw failure;
        } catch (IOException failure) {
            fail("MASSDB_LICENSE_AUDIT_IO", "License审计记录无法持久化");
        }
        requireFile(path);
        sequence = record.sequence;
        headHash = record.hash;
    }

    private void restoreAndVerify() {
        requireFile(path);
        long nextSequence = 0;
        String previous = ZERO_HASH;
        try (InputStream input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            ByteArrayOutputStream line = new ByteArrayOutputStream(1024);
            int value;
            while ((value = input.read()) >= 0) {
                if (value != '\n') {
                    if (line.size() >= MAX_RECORD_BYTES) {
                        fail("MASSDB_LICENSE_AUDIT_TAMPERED",
                                "License审计文件包含超长或截断记录");
                    }
                    line.write(value);
                    continue;
                }
                if (line.size() == 0) {
                    fail("MASSDB_LICENSE_AUDIT_TAMPERED", "License审计链包含空记录");
                }
                Record record = STRICT_JSON.readValue(line.toByteArray(), Record.class);
                requireRecord(record, nextSequence + 1, previous);
                nextSequence = record.sequence;
                previous = record.hash;
                line.reset();
            }
            if (line.size() != 0) {
                fail("MASSDB_LICENSE_AUDIT_TAMPERED", "License审计文件末尾记录被截断");
            }
        } catch (MassDbLicenseException failure) {
            throw failure;
        } catch (IOException failure) {
            fail("MASSDB_LICENSE_AUDIT_TAMPERED", "License审计文件无法严格解析");
        }
        requireFile(path);
        sequence = nextSequence;
        headHash = previous;
    }

    private static void requireRecord(Record record, long expectedSequence,
            String expectedPrevious) {
        if (record == null || record.sequence != expectedSequence
                || !expectedPrevious.equals(record.previousHash)
                || !SHA256.matcher(nullToEmpty(record.hash)).matches()) {
            fail("MASSDB_LICENSE_AUDIT_TAMPERED", "License审计链格式或序列损坏");
        }
        Event event = record.toEvent();
        requireEvent(event);
        if (!hash(record).equals(record.hash)) {
            fail("MASSDB_LICENSE_AUDIT_TAMPERED", "License审计链摘要不匹配");
        }
    }

    private static void requireEvent(Event event) {
        if (event == null || event.occurredAt <= 0
                || !SHA256.matcher(nullToEmpty(event.principalSubjectDigest)).matches()
                || empty(event.principalRole) || empty(event.method) || empty(event.path)
                || (!"REQUEST".equals(event.phase) && !"RESULT".equals(event.phase))
                || empty(event.resultCode)
                || (!empty(event.idempotencyKeyDigest)
                        && !SHA256.matcher(event.idempotencyKeyDigest).matches())
                || event.httpStatus < 0 || event.httpStatus > 599
                || event.principalRole.length() > 64 || event.method.length() > 16
                || event.path.length() > 4096 || event.resultCode.length() > 256) {
            fail("MASSDB_LICENSE_AUDIT_INVALID", "License审计事件字段非法");
        }
    }

    private static String hash(Record record) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            update(digest, Long.toString(record.sequence));
            update(digest, record.previousHash);
            update(digest, Long.toString(record.occurredAt));
            update(digest, record.principalSubjectDigest);
            update(digest, record.principalRole);
            update(digest, record.method);
            update(digest, record.path);
            update(digest, record.idempotencyKeyDigest);
            update(digest, record.phase);
            update(digest, record.resultCode);
            update(digest, Integer.toString(record.httpStatus));
            return hex(digest.digest());
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static void update(MessageDigest digest, String value) {
        byte[] bytes = nullToEmpty(value).getBytes(StandardCharsets.UTF_8);
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
        digest.update(bytes);
    }

    private static void requireDirectory(Path directory) {
        try {
            PosixFileAttributes attributes = Files.readAttributes(
                    directory, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isDirectory() || attributes.isSymbolicLink()
                    || !attributes.permissions().equals(DIRECTORY_PERMISSIONS)) {
                fail("MASSDB_LICENSE_AUDIT_INVALID", "License审计目录不安全");
            }
        } catch (IOException | UnsupportedOperationException failure) {
            fail("MASSDB_LICENSE_AUDIT_INVALID", "License审计目录不安全");
        }
    }

    private static void requireFile(Path path) {
        try {
            PosixFileAttributes attributes = Files.readAttributes(
                    path, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isRegularFile() || attributes.isSymbolicLink()
                    || !attributes.permissions().equals(FILE_PERMISSIONS)
                    || attributes.size() > MAX_FILE_BYTES) {
                fail("MASSDB_LICENSE_AUDIT_INVALID", "License审计文件不安全或过大");
            }
        } catch (IOException | UnsupportedOperationException failure) {
            fail("MASSDB_LICENSE_AUDIT_INVALID", "License审计文件不安全或不存在");
        }
    }

    private static void syncDirectory(Path directory) throws IOException {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        }
    }

    private static String hex(byte[] value) {
        StringBuilder output = new StringBuilder(value.length * 2);
        char[] alphabet = "0123456789abcdef".toCharArray();
        for (byte item : value) {
            int unsigned = item & 0xff;
            output.append(alphabet[unsigned >>> 4]).append(alphabet[unsigned & 0x0f]);
        }
        return output.toString();
    }

    private static boolean empty(String value) {
        return value == null || value.isEmpty();
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static void fail(String code, String message) {
        throw new MassDbLicenseException(code, message);
    }

    public static class Event {
        public long occurredAt;
        public String principalSubjectDigest;
        public String principalRole;
        public String method;
        public String path;
        public String idempotencyKeyDigest = "";
        public String phase;
        public String resultCode;
        public int httpStatus;
    }

    public static final class Record extends Event {
        public long sequence;
        public String previousHash;
        public String hash;

        private Event toEvent() {
            Event event = new Event();
            event.occurredAt = occurredAt;
            event.principalSubjectDigest = principalSubjectDigest;
            event.principalRole = principalRole;
            event.method = method;
            event.path = path;
            event.idempotencyKeyDigest = idempotencyKeyDigest;
            event.phase = phase;
            event.resultCode = resultCode;
            event.httpStatus = httpStatus;
            return event;
        }
    }
}
