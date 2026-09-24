// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

import org.apache.doris.massdb.license.LicenseClockRepairVerifier;
import org.apache.doris.massdb.license.LicenseException;
import org.apache.doris.massdb.license.LicenseRepairException;
import org.apache.doris.massdb.license.LicenseText;
import org.apache.doris.massdb.license.LicenseTrustStore;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** Isolated release probe. Generates ephemeral test keys only; never ships a trust default. */
public final class LicenseReleaseProbe {
    private static final ObjectMapper JSON = new ObjectMapper();

    private LicenseReleaseProbe() {
    }

    public static void main(String[] args) throws Exception {
        try {
            Map<String, Object> result;
            switch (args[0]) {
                case "info":
                    result = info();
                    break;
                case "text-digest":
                    result = textDigest();
                    break;
                case "keygen":
                    keygen(Paths.get(args[1]), Paths.get(args[2]));
                    result = status("KEY_PAIR_CREATED");
                    break;
                case "sign":
                    sign(Paths.get(args[1]), Paths.get(args[2]), args[3], args[4], Paths.get(args[5]));
                    result = status("SIGNED");
                    break;
                case "verify":
                    LicenseTrustStore trust = LicenseTrustStore.parse(Files.readAllBytes(Paths.get(args[2])));
                    String compact = new String(Files.readAllBytes(Paths.get(args[3])), StandardCharsets.US_ASCII);
                    if ("license".equals(args[1])) {
                        trust.newLicenseVerifier().verify(compact);
                    } else if ("time_repair".equals(args[1])) {
                        new LicenseClockRepairVerifier(trust.getKeys(LicenseTrustStore.Purpose.TIME_REPAIR))
                                .verify(compact);
                    } else {
                        throw new IllegalArgumentException("Unsupported purpose");
                    }
                    result = status("VERIFIED");
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported probe command");
            }
            System.out.println(JSON.writeValueAsString(result));
        } catch (LicenseException e) {
            rejected(e.getErrorCode().name());
        } catch (LicenseRepairException e) {
            rejected(e.getCode().name());
        } catch (Exception e) {
            System.err.println("PROBE_ERROR: " + e.getClass().getSimpleName());
            System.exit(3);
        }
    }

    private static void rejected(String code) throws Exception {
        Map<String, Object> result = status("REJECTED");
        result.put("error_code", code);
        System.out.println(JSON.writeValueAsString(result));
        System.exit(2);
    }

    private static Map<String, Object> status(String status) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", status);
        return result;
    }

    private static Map<String, Object> info() throws Exception {
        Map<String, Object> result = status("AVAILABLE");
        for (String property : new String[] {"java.version", "java.runtime.version", "java.vendor", "java.home",
                "os.name", "os.version", "os.arch"}) {
            result.put(property, System.getProperty(property));
        }
        result.put("ed25519_provider", Signature.getInstance("Ed25519").getProvider().toString());
        Map<String, Object> classes = new LinkedHashMap<>();
        for (String name : new String[] {"LicenseText", "LicenseVerifier", "LicenseTrustStore",
                "LicenseClockRepairVerifier"}) {
            String resource = "org/apache/doris/massdb/license/" + name + ".class";
            byte[] bytes;
            try (InputStream input = LicenseReleaseProbe.class.getClassLoader().getResourceAsStream(resource)) {
                if (input == null) {
                    throw new IllegalStateException("Probe target class missing");
                }
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int count;
                while ((count = input.read(buffer)) >= 0) {
                    output.write(buffer, 0, count);
                }
                bytes = output.toByteArray();
            }
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("major", ((bytes[6] & 255) << 8) | (bytes[7] & 255));
            data.put("sha256", hex(MessageDigest.getInstance("SHA-256").digest(bytes)));
            data.put("location", LicenseReleaseProbe.class.getClassLoader().getResource(resource).toString());
            classes.put(name, data);
        }
        result.put("loaded_classes", classes);
        return result;
    }

    private static Map<String, Object> textDigest() throws Exception {
        MessageDigest identifier = MessageDigest.getInstance("SHA-256");
        MessageDigest bare = MessageDigest.getInstance("SHA-256");
        MessageDigest wrapped = MessageDigest.getInstance("SHA-256");
        int identifiers = 0;
        int displays = 0;
        int internal = 0;
        for (int point = 0; point <= 0x10ffff; point++) {
            String text = new String(Character.toChars(point));
            boolean id = LicenseText.matches(text, 8, true);
            boolean display = LicenseText.matches(text, 8, false);
            boolean inside = LicenseText.matches("a" + text + "z", 8, false);
            identifier.update((byte) (id ? 1 : 0));
            bare.update((byte) (display ? 1 : 0));
            wrapped.update((byte) (inside ? 1 : 0));
            identifiers += id ? 1 : 0;
            displays += display ? 1 : 0;
            internal += inside ? 1 : 0;
        }
        Map<String, Object> result = status("CALCULATED");
        result.put("domain", "U+000000..U+10FFFF inclusive; surrogate code points are rejection cases");
        result.put("code_points", 0x110000);
        result.put("unicode_scalars", 0x110000 - 0x800);
        result.put("identifier_sha256", hex(identifier.digest()));
        result.put("display_bare_sha256", hex(bare.digest()));
        result.put("display_wrapped_sha256", hex(wrapped.digest()));
        result.put("identifier_accepted", identifiers);
        result.put("display_bare_accepted", displays);
        result.put("display_wrapped_accepted", internal);
        return result;
    }

    private static void keygen(Path privatePath, Path publicPath) throws Exception {
        KeyPair keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        writePem(privatePath, "PRIVATE KEY", keys.getPrivate().getEncoded());
        writePem(publicPath, "PUBLIC KEY", keys.getPublic().getEncoded());
    }

    private static void writePem(Path path, String label, byte[] bytes) throws Exception {
        String pem = "-----BEGIN " + label + "-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(bytes)
                + "\n-----END " + label + "-----\n";
        Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.write(path, pem.getBytes(StandardCharsets.US_ASCII));
    }

    private static void sign(Path privatePath, Path claimsPath, String type, String kid, Path output) throws Exception {
        String pem = new String(Files.readAllBytes(privatePath), StandardCharsets.US_ASCII);
        String material = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        PrivateKey key = KeyFactory.getInstance("Ed25519").generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(material)));
        Map<String, String> header = new LinkedHashMap<>();
        header.put("typ", type);
        header.put("alg", "Ed25519");
        header.put("kid", kid);
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String signed = encoder.encodeToString(JSON.writeValueAsBytes(header)) + "."
                + encoder.encodeToString(Files.readAllBytes(claimsPath));
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(key);
        signature.update(signed.getBytes(StandardCharsets.US_ASCII));
        Files.write(output, (signed + "." + encoder.encodeToString(signature.sign()))
                .getBytes(StandardCharsets.US_ASCII));
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format("%02x", value & 255));
        }
        return result.toString();
    }
}
