// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import org.apache.doris.common.io.Writable;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Bounded atomic FE metadata envelope. Raw slots are retained even when their signatures are invalid. */
public final class LicensePersistRecord implements Writable {
    public static final int MAX_BYTES = 2 * 1024 * 1024;
    public static final short INITIALIZE = 6200;
    public static final short ACCEPT = 6201;
    public static final short BASE = 6202;
    public static final short WATERMARK = 6203;
    public static final short REPAIR = 6204;
    public static final short INTEGRITY = 6205;
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxDocumentLength(MAX_BYTES)
                    .maxStringLength(LicenseVerifier.MAX_COMPACT_LENGTH).maxNestingDepth(8)
                    .maxNumberLength(20).maxNameLength(128).build()).build());

    private final ObjectNode data;
    private final byte[] encoded;
    // State, facts and receipts are immutable. Keep only this record's fully validated clock view.
    private final LicenseClockRepair.State clockState;

    private LicensePersistRecord(ObjectNode data) throws IOException {
        this.data = data.deepCopy();
        clockState = validateEnvelope();
        encoded = JSON.writeValueAsBytes(this.data);
        if (encoded.length > MAX_BYTES - 38) {
            throw invalid();
        }
    }

    public static LicensePersistRecord initial(UUID deployment, boolean bootstrap, long wallMillis)
            throws IOException {
        ObjectNode root = JSON.createObjectNode();
        root.put("format_version", 1);
        root.put("operation", INITIALIZE);
        root.put("record_version", 1);
        root.put("deployment_id", deployment.toString());
        root.put("bootstrap", bootstrap);
        root.put("activated", false);
        root.put("complete", true);
        root.put("clock_suspect", false);
        root.set("rollout", NullNode.getInstance());
        writeImports(root, LicenseImportState.empty(deployment));
        writeClock(root, new LicenseClockRepair.State(deployment,
                new LicenseClock.Facts(0, 0, wallMillis, 0), Collections.emptyMap()));
        root.set("submission_versions", JSON.createObjectNode());
        return new LicensePersistRecord(root);
    }

    public LicensePersistRecord withImports(short operation, LicenseImportState state, boolean activate)
            throws IOException {
        ObjectNode replacement = next(operation);
        writeImports(replacement, state);
        replacement.put("activated", isActivated() || activate);
        ObjectNode versions = JSON.createObjectNode();
        for (LicenseImportState.Receipt receipt : state.getReceipts()) {
            retainVersion(versions, receipt.getFingerprint(), getVersion() + 1);
        }
        for (LicenseImportState.Slot slot : new LicenseImportState.Slot[] {
                state.getActive(), state.getPending(), state.getEffectiveBase()}) {
            if (slot != null) {
                retainVersion(versions, slot.getDocument().getFingerprint(), getVersion() + 1);
            }
        }
        for (LicenseClockRepair.Receipt receipt : clockState().getReceipts().values()) {
            retainVersion(versions, receipt.getFingerprint(), getVersion() + 1);
        }
        replacement.set("submission_versions", versions);
        return new LicensePersistRecord(replacement);
    }

    public LicensePersistRecord withClock(short operation, LicenseClockRepair.State state) throws IOException {
        ObjectNode replacement = next(operation);
        if (state.getFacts().getClockEpoch() > clockState().getFacts().getClockEpoch()) {
            replacement.put("clock_suspect", false);
        }
        writeClock(replacement, state);
        ObjectNode versions = JSON.createObjectNode();
        // License receipts and occupied slots outlive repair-history eviction.
        for (JsonNode receipt : data.get("receipts")) {
            retainVersion(versions, receipt.get("fingerprint").textValue(), getVersion() + 1);
        }
        for (String name : new String[] {"active", "pending", "base"}) {
            JsonNode slot = data.get(name);
            if (!slot.isNull()) {
                try {
                    retainVersion(versions, LicenseVerifier.fingerprint(slot.get("compact").textValue()),
                            getVersion() + 1);
                } catch (LicenseException ignored) {
                    // A corrupt isolated slot cannot become a successful receipt.
                }
            }
        }
        for (LicenseClockRepair.Receipt receipt : state.getReceipts().values()) {
            retainVersion(versions, receipt.getFingerprint(), getVersion() + 1);
        }
        replacement.set("submission_versions", versions);
        return new LicensePersistRecord(replacement);
    }

    public LicensePersistRecord withClockSuspect() throws IOException {
        ObjectNode replacement = next(INTEGRITY);
        replacement.put("clock_suspect", true);
        return new LicensePersistRecord(replacement);
    }

    /** Attach the successful live FE proof to the same atomic first-import/renewal record. */
    public LicensePersistRecord withRollout(String packageDigest, String trustDigest, long frontendVersion)
            throws IOException {
        ObjectNode replacement = data.deepCopy();
        ObjectNode rollout = replacement.putObject("rollout");
        rollout.put("package_sha256", packageDigest);
        rollout.put("trust_sha256", trustDigest);
        rollout.put("frontend_version", frontendVersion);
        return new LicensePersistRecord(replacement);
    }

    public boolean matchesRollout(String packageDigest, String trustDigest, long frontendVersion) {
        JsonNode rollout = data.get("rollout");
        return !rollout.isNull() && packageDigest != null && trustDigest != null
                && packageDigest.equals(rollout.get("package_sha256").textValue())
                && trustDigest.equals(rollout.get("trust_sha256").textValue())
                && frontendVersion == rollout.get("frontend_version").longValue();
    }

    private ObjectNode next(short operation) throws IOException {
        if (getVersion() == Long.MAX_VALUE) {
            throw invalid();
        }
        ObjectNode replacement = data.deepCopy();
        replacement.put("operation", operation);
        replacement.put("record_version", getVersion() + 1);
        return replacement;
    }

    private void retainVersion(ObjectNode versions, String fingerprint, long fallback) {
        long previous = submissionVersion(fingerprint);
        versions.put(fingerprint, previous == 0 ? fallback : previous);
    }

    private static void writeImports(ObjectNode root, LicenseImportState state) {
        root.set("active", rawSlot(state.getActive()));
        root.set("pending", rawSlot(state.getPending()));
        root.set("base", rawSlot(state.getEffectiveBase()));
        root.put("highest_sequence", state.getHighestSequence());
        root.put("license_version", state.getLicenseVersion());
        ArrayNode receipts = root.putArray("receipts");
        for (LicenseImportState.Receipt receipt : state.getReceipts()) {
            ObjectNode value = receipts.addObject();
            value.put("fingerprint", receipt.getFingerprint());
            value.put("license_id", receipt.getLicenseId());
            value.put("sequence", receipt.getSequence());
            value.put("committed_version", receipt.getCommittedVersion());
        }
    }

    private static JsonNode rawSlot(LicenseImportState.Slot slot) {
        if (slot == null) {
            return NullNode.getInstance();
        }
        ObjectNode value = JSON.createObjectNode();
        value.put("compact", slot.getCompact());
        value.put("committed_version", slot.getCommittedVersion());
        return value;
    }

    private static void writeClock(ObjectNode root, LicenseClockRepair.State state) {
        LicenseClock.Facts facts = state.getFacts();
        ObjectNode clock = root.putObject("clock");
        clock.put("version", facts.getVersion());
        clock.put("epoch", facts.getClockEpoch());
        clock.put("high_water_millis", facts.getHighWaterMillis());
        clock.put("authorization_version", facts.getRepairAuthorizationVersion());
        ArrayNode receipts = clock.putArray("receipts");
        for (LicenseClockRepair.Receipt receipt : state.getReceipts().values()) {
            ObjectNode value = receipts.addObject();
            value.put("repair_id", receipt.getRepairId().toString());
            value.put("committed_version", receipt.getCommittedVersion());
            value.put("clock_epoch", receipt.getClockEpoch());
            value.put("corrected_millis", receipt.getCorrectedMillis());
            value.put("key_id", receipt.getKeyId());
            value.put("fingerprint", receipt.getFingerprint());
        }
    }

    private LicenseClockRepair.State validateEnvelope() throws IOException {
        try {
            fields(data, "format_version", "operation", "record_version", "deployment_id", "bootstrap",
                    "activated", "complete", "active", "pending", "base", "highest_sequence", "license_version",
                    "receipts", "clock", "submission_versions", "clock_suspect", "rollout");
            if (number(data, "format_version") != 1 || number(data, "record_version") < 1
                    || number(data, "operation") < INITIALIZE || number(data, "operation") > INTEGRITY) {
                throw invalid();
            }
            uuid(text(data, "deployment_id", 36));
            bool(data, "bootstrap");
            bool(data, "activated");
            bool(data, "complete");
            bool(data, "clock_suspect");
            JsonNode rollout = data.get("rollout");
            if (!rollout.isNull()) {
                fields(rollout, "package_sha256", "trust_sha256", "frontend_version");
                if (!text(rollout, "package_sha256", 64).matches("[0-9a-f]{64}")
                        || !text(rollout, "trust_sha256", 64).matches("[0-9a-f]{64}")) {
                    throw invalid();
                }
                number(rollout, "frontend_version");
            }
            number(data, "highest_sequence");
            number(data, "license_version");
            for (String name : new String[] {"active", "pending", "base"}) {
                JsonNode slot = data.get(name);
                if (!slot.isNull()) {
                    fields(slot, "compact", "committed_version");
                    text(slot, "compact", LicenseVerifier.MAX_COMPACT_LENGTH);
                    if (number(slot, "committed_version") < 1) {
                        throw invalid();
                    }
                }
            }
            importReceipts();
            LicenseClockRepair.State parsedClock = parseClockState();
            JsonNode versions = data.get("submission_versions");
            if (!versions.isObject() || versions.size() > 2 * LicenseImportState.MAX_RECEIPTS + 3) {
                throw invalid();
            }
            Iterator<String> names = versions.fieldNames();
            while (names.hasNext()) {
                String name = names.next();
                long version = number(versions, name);
                if (!name.matches("[0-9a-f]{64}") || version < 1 || version > getVersion()) {
                    throw invalid();
                }
            }
            return parsedClock;
        } catch (IllegalArgumentException e) {
            throw invalid();
        }
    }

    private List<LicenseImportState.Receipt> importReceipts() throws IOException {
        JsonNode array = data.get("receipts");
        array(array, LicenseImportState.MAX_RECEIPTS);
        List<LicenseImportState.Receipt> receipts = new ArrayList<>();
        for (JsonNode value : array) {
            fields(value, "fingerprint", "license_id", "sequence", "committed_version");
            receipts.add(new LicenseImportState.Receipt(text(value, "fingerprint", 64),
                    text(value, "license_id", 256), number(value, "sequence"), number(value, "committed_version")));
        }
        return receipts;
    }

    LicenseClockRepair.State clockState() throws IOException {
        return clockState;
    }

    private LicenseClockRepair.State parseClockState() throws IOException {
        JsonNode value = data.get("clock");
        fields(value, "version", "epoch", "high_water_millis", "authorization_version", "receipts");
        LicenseClock.Facts facts = new LicenseClock.Facts(number(value, "version"), number(value, "epoch"),
                number(value, "high_water_millis"), number(value, "authorization_version"));
        array(value.get("receipts"), LicenseClockRepair.MAX_RECEIPTS);
        Map<UUID, LicenseClockRepair.Receipt> receipts = new LinkedHashMap<>();
        for (JsonNode receipt : value.get("receipts")) {
            fields(receipt, "repair_id", "committed_version", "clock_epoch", "corrected_millis", "key_id",
                    "fingerprint");
            UUID id = uuid(text(receipt, "repair_id", 36));
            LicenseClockRepair.Receipt parsed = new LicenseClockRepair.Receipt(id,
                    number(receipt, "committed_version"), number(receipt, "clock_epoch"),
                    number(receipt, "corrected_millis"), text(receipt, "key_id", 128),
                    text(receipt, "fingerprint", 64));
            if (receipts.put(id, parsed) != null) {
                throw invalid();
            }
        }
        return new LicenseClockRepair.State(getDeploymentId(), facts, receipts);
    }

    /** Signature/business damage is isolated per slot; envelope corruption remains an IOException. */
    Restored restore(LicenseVerifier verifier) throws IOException {
        return restore(verifier, null);
    }

    /** Reuse only exact slots verified by the same immutable verifier in the preceding state. */
    Restored restore(LicenseVerifier verifier, Restored previous) throws IOException {
        boolean invalidSlot = false;
        LicenseImportState.Slot[] slots = new LicenseImportState.Slot[3];
        String[] names = {"active", "pending", "base"};
        for (int i = 0; i < names.length; i++) {
            JsonNode value = data.get(names[i]);
            if (!value.isNull()) {
                try {
                    String compact = value.get("compact").textValue();
                    long version = value.get("committed_version").longValue();
                    LicenseImportState.Slot slot = matchingSlot(slots, compact, version);
                    if (slot == null && previous != null && previous.verifier == verifier) {
                        slot = matchingSlot(previous.verifiedSlots, compact, version);
                    }
                    if (slot == null) {
                        slot = LicenseImportState.Slot.verify(compact, version, verifier);
                    }
                    if (!getDeploymentId().equals(slot.getDocument().getDeploymentId())
                            || slot.getDocument().getSequence() > data.get("highest_sequence").longValue()
                            || slot.getCommittedVersion() > data.get("license_version").longValue()) {
                        invalidSlot = true;
                    } else {
                        slots[i] = slot;
                    }
                } catch (LicenseException | IllegalArgumentException e) {
                    invalidSlot = true;
                }
            }
        }
        try {
            return new Restored(LicenseImportState.restore(getDeploymentId(), slots[0], slots[1], slots[2],
                    data.get("highest_sequence").longValue(), data.get("license_version").longValue(),
                    importReceipts()), invalidSlot, verifier);
        } catch (IllegalArgumentException e) {
            throw invalid();
        }
    }

    private static LicenseImportState.Slot matchingSlot(LicenseImportState.Slot[] slots,
            String compact, long committedVersion) {
        for (LicenseImportState.Slot slot : slots) {
            if (slot != null && slot.getCommittedVersion() == committedVersion && slot.getCompact().equals(compact)) {
                return slot;
            }
        }
        return null;
    }

    static final class Restored {
        final LicenseImportState imports;
        final boolean invalidSlots;
        private final LicenseVerifier verifier;
        private final LicenseImportState.Slot[] verifiedSlots;

        private Restored(LicenseImportState imports, boolean invalidSlots, LicenseVerifier verifier) {
            this.imports = imports;
            this.invalidSlots = invalidSlots;
            this.verifier = verifier;
            this.verifiedSlots = new LicenseImportState.Slot[] {
                    imports.getActive(), imports.getPending(), imports.getEffectiveBase()};
        }
    }

    public short getOperation() {
        return (short) data.get("operation").intValue();
    }

    public long getVersion() {
        return data.get("record_version").longValue();
    }

    public UUID getDeploymentId() {
        return UUID.fromString(data.get("deployment_id").textValue());
    }

    public boolean isActivated() {
        return data.get("activated").booleanValue();
    }

    public boolean isBootstrap() {
        return data.get("bootstrap").booleanValue();
    }

    public boolean isComplete() {
        return data.get("complete").booleanValue();
    }

    public boolean isClockSuspect() {
        return data.get("clock_suspect").booleanValue();
    }

    public long submissionVersion(String fingerprint) {
        JsonNode value = data.get("submission_versions").get(fingerprint);
        return value == null ? 0 : value.longValue();
    }

    boolean sameAs(LicensePersistRecord other) {
        // Factories write long nodes; recovery may decode the same validated integer as an int node.
        // Compare integral values exactly while retaining object fields, array order and scalar types.
        return other != null && data.equals((left, right) ->
                left.isIntegralNumber() && right.isIntegralNumber()
                        ? Long.compare(left.longValue(), right.longValue())
                        : left.equals(right) ? 0 : 1, other.data);
    }

    @Override
    public void write(DataOutput output) throws IOException {
        output.writeInt(encoded.length);
        output.write(encoded);
        output.write(checksum(encoded));
    }

    public static LicensePersistRecord read(DataInput input) throws IOException {
        int length = input.readInt();
        if (length < 1 || length > MAX_BYTES - 38) {
            throw invalid();
        }
        byte[] bytes = new byte[length];
        input.readFully(bytes);
        byte[] expected = new byte[32];
        input.readFully(expected);
        if (!MessageDigest.isEqual(expected, checksum(bytes))) {
            throw invalid();
        }
        try (JsonParser parser = JSON.createParser(bytes)) {
            JsonNode value = JSON.readTree(parser);
            if (!(value instanceof ObjectNode) || parser.nextToken() != null) {
                throw invalid();
            }
            return new LicensePersistRecord((ObjectNode) value);
        } catch (IOException | IllegalArgumentException e) {
            throw invalid();
        }
    }

    private static void fields(JsonNode value, String... names) throws IOException {
        if (value == null || !value.isObject() || value.size() != names.length) {
            throw invalid();
        }
        for (String name : names) {
            if (!value.has(name)) {
                throw invalid();
            }
        }
    }

    private static long number(JsonNode object, String name) throws IOException {
        JsonNode value = object.get(name);
        if (value == null || !value.isIntegralNumber() || !value.canConvertToLong() || value.longValue() < 0) {
            throw invalid();
        }
        return value.longValue();
    }

    private static String text(JsonNode object, String name, int max) throws IOException {
        JsonNode value = object.get(name);
        if (value == null || !value.isTextual() || value.textValue().isEmpty() || value.textValue().length() > max) {
            throw invalid();
        }
        return value.textValue();
    }

    private static void bool(JsonNode object, String name) throws IOException {
        if (!object.get(name).isBoolean()) {
            throw invalid();
        }
    }

    private static void array(JsonNode value, int max) throws IOException {
        if (value == null || !value.isArray() || value.size() > max) {
            throw invalid();
        }
    }

    private static UUID uuid(String value) throws IOException {
        UUID parsed = UUID.fromString(value);
        if (!parsed.toString().equals(value)) {
            throw invalid();
        }
        return parsed;
    }

    private static IOException invalid() {
        return new IOException("Invalid MassDB license metadata envelope");
    }

    private static byte[] checksum(byte[] bytes) throws IOException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw invalid();
        }
    }
}
