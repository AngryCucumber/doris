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

import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Component-native, offline-capable CLI for FE role identity provisioning. */
public final class MassDbLicenseIdentityCli {
    private static final String COMPONENT = "massdb-sql";
    private static final String ROLE = "fe";
    private static final int EXIT_USAGE = 2;
    private static final int EXIT_REJECTED = 3;
    private static final int EXIT_INTERNAL = 4;
    private static final Set<PosixFilePermission> PRIVATE_FILE_PERMISSIONS =
            Collections.unmodifiableSet(EnumSet.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));

    private MassDbLicenseIdentityCli() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err, Instant.now().getEpochSecond()));
    }

    static int run(String[] args, PrintStream output, PrintStream error,
            long nowEpochSecond) {
        Objects.requireNonNull(args, "args");
        Objects.requireNonNull(output, "output");
        Objects.requireNonNull(error, "error");
        try {
            if (args.length == 0) {
                throw new UsageException("缺少命令");
            }
            Options options = Options.parse(args);
            switch (options.command) {
                case "identity-csr":
                    identityCsr(options, output, nowEpochSecond);
                    return 0;
                case "identity-import":
                    identityImport(options, output, nowEpochSecond);
                    return 0;
                case "identity-status":
                    identityStatus(options, output, nowEpochSecond);
                    return 0;
                case "identity-cleanup":
                    identityCleanup(options, output, nowEpochSecond);
                    return 0;
                default:
                    throw new UsageException("未知命令: " + options.command);
            }
        } catch (UsageException failure) {
            error.println(errorJson("MASSDB_LICENSE_CLI_USAGE", failure.getMessage()));
            return EXIT_USAGE;
        } catch (MassDbLicenseException failure) {
            error.println(errorJson(failure.getCode(), failure.getMessage()));
            return EXIT_REJECTED;
        } catch (RuntimeException failure) {
            error.println(errorJson("MASSDB_LICENSE_CLI_INTERNAL",
                    "组件身份命令执行失败，请检查组件日志和本地文件权限"));
            return EXIT_INTERNAL;
        }
    }

    private static void identityCsr(Options options, PrintStream output,
            long nowEpochSecond) {
        options.requireOnly("store-dir", "artifact-root-dir", "secret-file",
                "meta-dir", "deployment-uuid", "csr-out", "dns-san", "ip-san");
        Path metaDirectory = absolutePath(options.requiredOne("meta-dir"), "meta-dir");
        Path csrOutput = absolutePath(options.requiredOne("csr-out"), "csr-out");
        String deploymentUuid = options.requiredOne("deployment-uuid");
        List<String> dnsValues = options.values("dns-san");
        List<String> ipValues = options.values("ip-san");
        boolean replayWithoutAddressSans = dnsValues.isEmpty() && ipValues.isEmpty();
        MassDbLicenseIdentityAddressSans.AddressSans addressSans =
                MassDbLicenseIdentityAddressSans.normalize(
                        dnsValues, ipValues, !replayWithoutAddressSans);
        String nodeUuid = new MassDbLicenseLocalSnapshotStore(
                metaDirectory.resolve("massdb-license")).getNodeUuid();
        try (StoreContext context = openStore(options)) {
            MassDbLicenseIdentityStore.Enrollment enrollment =
                    replayWithoutAddressSans
                            ? context.store.replayPendingLegacyEnrollment(
                                    COMPONENT, deploymentUuid, ROLE, nodeUuid, nowEpochSecond)
                            : context.store.beginEnrollment(
                                    COMPONENT, deploymentUuid, ROLE, nodeUuid,
                                    addressSans.dnsNames(), addressSans.ipAddresses(),
                                    nowEpochSecond);
            writePrivateOutput(csrOutput,
                    enrollment.getCsrPem().getBytes(StandardCharsets.US_ASCII));
            output.println("{\"ok\":true,\"state\":\"ENROLLMENT_PENDING\""
                    + ",\"generation\":" + enrollment.getGeneration()
                    + ",\"component\":\"" + json(enrollment.getComponent()) + "\""
                    + ",\"deploymentUuid\":\""
                    + json(enrollment.getDeploymentUuid()) + "\""
                    + ",\"role\":\"" + json(enrollment.getRole()) + "\""
                    + ",\"nodeUuid\":\"" + json(enrollment.getNodeUuid()) + "\""
                    + ",\"csrSha256\":\"" + enrollment.getCsrSha256() + "\""
                    + ",\"csrFile\":\"" + json(csrOutput.toString()) + "\"}");
        }
    }

    private static void identityImport(Options options, PrintStream output,
            long nowEpochSecond) {
        options.requireOnly("store-dir", "artifact-root-dir", "secret-file",
                "identity-file");
        Path identityFile = absolutePath(
                options.requiredOne("identity-file"), "identity-file");
        byte[] artifact = readBounded(identityFile, MassDbLicenseProtocolV1.MAX_ARTIFACT_BYTES,
                "身份包");
        try (StoreContext context = openStore(options)) {
            context.store.importAndActivate(artifact, nowEpochSecond);
            printStatus(output, context.store.status(nowEpochSecond));
        } finally {
            Arrays.fill(artifact, (byte) 0);
        }
    }

    private static void identityStatus(Options options, PrintStream output,
            long nowEpochSecond) {
        options.requireOnly("store-dir", "artifact-root-dir", "secret-file");
        try (StoreContext context = openStore(options)) {
            printStatus(output, context.store.status(nowEpochSecond));
        }
    }

    private static void identityCleanup(Options options, PrintStream output,
            long nowEpochSecond) {
        options.requireOnly("store-dir", "artifact-root-dir", "secret-file");
        try (StoreContext context = openStore(options)) {
            MassDbLicenseIdentityStore.CleanupResult result =
                    context.store.cleanupRetired(nowEpochSecond);
            output.println("{\"ok\":true,\"markedGenerations\":"
                    + result.getMarkedGenerations() + ",\"removedGenerations\":"
                    + result.getRemovedGenerations() + ",\"removedFiles\":"
                    + result.getRemovedFiles() + "}");
        }
    }

    private static StoreContext openStore(Options options) {
        Path storeDirectory = absolutePath(
                options.requiredOne("store-dir"), "store-dir");
        Path rootDirectory = absolutePath(
                options.requiredOne("artifact-root-dir"), "artifact-root-dir");
        Path secretFile = absolutePath(
                options.requiredOne("secret-file"), "secret-file");
        Map<String, PublicKey> roots = MassDbLicenseRootTrustLoader.loadRootKeys(rootDirectory);
        char[] secret = MassDbLicenseIdentityRuntime.readSecret(secretFile);
        try {
            return new StoreContext(
                    new MassDbLicenseIdentityStore(storeDirectory, secret, roots), secret);
        } catch (RuntimeException failure) {
            Arrays.fill(secret, '\0');
            throw failure;
        }
    }

    private static void printStatus(PrintStream output,
            MassDbLicenseIdentityStore.IdentityStatus status) {
        output.println("{\"ok\":true,\"state\":\"" + status.getState().name() + "\""
                + ",\"generation\":" + status.getGeneration()
                + ",\"component\":\"" + json(status.getComponent()) + "\""
                + ",\"deploymentUuid\":\"" + json(status.getDeploymentUuid()) + "\""
                + ",\"role\":\"" + json(status.getRole()) + "\""
                + ",\"nodeUuid\":\"" + json(status.getNodeUuid()) + "\""
                + ",\"notBefore\":" + status.getNotBefore()
                + ",\"notAfter\":" + status.getNotAfter()
                + ",\"artifactSha256\":\"" + status.getArtifactSha256() + "\"}");
    }

    private static Path absolutePath(String value, String label) {
        try {
            Path path = Paths.get(value);
            if (!path.isAbsolute()) {
                throw new UsageException("--" + label + " 必须是绝对路径");
            }
            return path.normalize();
        } catch (InvalidPathException failure) {
            throw new UsageException("--" + label + " 路径无效");
        }
    }

    private static byte[] readBounded(Path path, int maximum, String label) {
        byte[] result = null;
        try {
            BasicFileAttributes before = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (Files.isSymbolicLink(path) || !before.isRegularFile()
                    || before.size() <= 0 || before.size() > maximum) {
                throw new MassDbLicenseException("MASSDB_LICENSE_FILE_INVALID",
                        label + "必须是非符号链接普通文件且大小不超过协议上限");
            }
            result = new byte[(int) before.size()];
            try (SeekableByteChannel input = Files.newByteChannel(path,
                    StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                ByteBuffer target = ByteBuffer.wrap(result);
                while (target.hasRemaining()) {
                    if (input.read(target) < 0) {
                        throw new MassDbLicenseException("MASSDB_LICENSE_FILE_INVALID",
                                label + "在读取期间被截断");
                    }
                }
                if (input.read(ByteBuffer.allocate(1)) != -1) {
                    throw new MassDbLicenseException("MASSDB_LICENSE_FILE_INVALID",
                            label + "在读取期间增长");
                }
            }
            BasicFileAttributes after = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!after.isRegularFile() || before.size() != after.size()
                    || !before.lastModifiedTime().equals(after.lastModifiedTime())
                    || !Objects.equals(before.fileKey(), after.fileKey())) {
                throw new MassDbLicenseException("MASSDB_LICENSE_FILE_INVALID",
                        label + "在读取期间发生变化");
            }
            byte[] complete = result;
            result = null;
            return complete;
        } catch (MassDbLicenseException failure) {
            throw failure;
        } catch (IOException | SecurityException failure) {
            throw new MassDbLicenseException("MASSDB_LICENSE_FILE_INVALID",
                    "无法安全读取" + label);
        } finally {
            if (result != null) {
                Arrays.fill(result, (byte) 0);
            }
        }
    }

    private static void writePrivateOutput(Path target, byte[] content) {
        Path parent = target.getParent();
        if (parent == null || Files.isSymbolicLink(parent)
                || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(target)) {
            throw new MassDbLicenseException("MASSDB_LICENSE_CLI_OUTPUT_INVALID",
                    "CSR输出目录必须存在且目标不能是符号链接");
        }
        Path temporary = parent.resolve("." + target.getFileName()
                + ".tmp-" + UUID.randomUUID());
        try {
            Files.write(temporary, content, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE);
            setPrivatePermissions(temporary);
            try (FileChannel file = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                file.force(true);
            }
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException failure) {
                throw new MassDbLicenseException("MASSDB_LICENSE_CLI_OUTPUT_INVALID",
                        "CSR输出文件系统不支持原子替换");
            }
            try (FileChannel directory = FileChannel.open(parent, StandardOpenOption.READ)) {
                directory.force(true);
            }
        } catch (MassDbLicenseException failure) {
            throw failure;
        } catch (IOException | SecurityException failure) {
            throw new MassDbLicenseException("MASSDB_LICENSE_CLI_OUTPUT_INVALID",
                    "无法安全写入CSR输出文件");
        } finally {
            try {
                Files.deleteIfExists(temporary);
            } catch (IOException ignored) {
                // Unreferenced same-directory temporary file is safe to retry later.
            }
        }
    }

    private static void setPrivatePermissions(Path path) throws IOException {
        try {
            Files.setPosixFilePermissions(path, PRIVATE_FILE_PERMISSIONS);
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX packages retain the no-symlink and atomic-write guarantees.
        }
    }

    private static String errorJson(String code, String message) {
        return "{\"ok\":false,\"code\":\"" + json(code)
                + "\",\"message\":\"" + json(message) + "\"}";
    }

    private static String json(String value) {
        StringBuilder result = new StringBuilder(value.length() + 16);
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            switch (item) {
                case '\\':
                    result.append("\\\\");
                    break;
                case '"':
                    result.append("\\\"");
                    break;
                case '\b':
                    result.append("\\b");
                    break;
                case '\f':
                    result.append("\\f");
                    break;
                case '\n':
                    result.append("\\n");
                    break;
                case '\r':
                    result.append("\\r");
                    break;
                case '\t':
                    result.append("\\t");
                    break;
                default:
                    if (item < 0x20) {
                        result.append(String.format(Locale.ROOT, "\\u%04x", (int) item));
                    } else {
                        result.append(item);
                    }
            }
        }
        return result.toString();
    }

    private static final class StoreContext implements AutoCloseable {
        private final MassDbLicenseIdentityStore store;
        private final char[] secret;

        private StoreContext(MassDbLicenseIdentityStore store, char[] secret) {
            this.store = store;
            this.secret = secret;
        }

        @Override
        public void close() {
            store.close();
            Arrays.fill(secret, '\0');
        }
    }

    private static final class Options {
        private final String command;
        private final Map<String, List<String>> values;

        private Options(String command, Map<String, List<String>> values) {
            this.command = command;
            this.values = values;
        }

        private static Options parse(String[] args) {
            String command = args[0];
            Map<String, List<String>> values = new LinkedHashMap<>();
            for (int index = 1; index < args.length; index += 2) {
                String option = args[index];
                if (!option.startsWith("--") || option.length() == 2
                        || index + 1 >= args.length) {
                    throw new UsageException("参数必须使用 --name value 形式");
                }
                String name = option.substring(2);
                String value = args[index + 1];
                if (value.isEmpty()) {
                    throw new UsageException(option + " 不能为空");
                }
                List<String> existing = values.computeIfAbsent(
                        name, ignored -> new ArrayList<>());
                if (!"dns-san".equals(name) && !"ip-san".equals(name)
                        && !existing.isEmpty()) {
                    throw new UsageException(option + " 不能重复");
                }
                existing.add(value);
            }
            return new Options(command, values);
        }

        private void requireOnly(String... allowed) {
            Set<String> accepted = new java.util.HashSet<>(Arrays.asList(allowed));
            for (String name : values.keySet()) {
                if (!accepted.contains(name)) {
                    throw new UsageException("命令不支持参数 --" + name);
                }
            }
            requiredOne("store-dir");
            requiredOne("artifact-root-dir");
            requiredOne("secret-file");
        }

        private String requiredOne(String name) {
            List<String> found = values.get(name);
            if (found == null || found.size() != 1) {
                throw new UsageException("缺少参数 --" + name);
            }
            return found.get(0);
        }

        private List<String> values(String name) {
            List<String> found = values.get(name);
            return found == null ? Collections.emptyList()
                    : Collections.unmodifiableList(found);
        }
    }

    private static final class UsageException extends RuntimeException {
        private UsageException(String message) {
            super(message);
        }
    }
}
