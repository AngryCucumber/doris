// Copyright (c) 2026
// 厦门市美亚柏科信息安全研究所有限公司
// Xiamen Meiya Pico Information Security Research Institute Co., Ltd.
// SPDX-License-Identifier: LicenseRef-MassDB-Commercial
// Use is governed by LICENSE-MASSDB.txt and a separate agreement with the company.
// Upstream and third-party components retain their respective licenses.

package org.apache.doris.massdb.license;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

class LicensePersistRecordTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final UUID DEPLOYMENT = UUID.fromString("12345678-1234-1234-1234-123456789abc");
    private static final String KEY_ID = "repair-issuer";
    private static final long WALL = 1_000_000;

    @Test
    void fullHistoryIsValidatedOncePerRecordAndRepeatedClockReadsDoNotRebuildIt() throws Exception {
        byte[] wire = encode(history(LicenseClockRepair.MAX_RECEIPTS));
        try (MockedStatic<LicenseText> validation = Mockito.mockStatic(
                LicenseText.class, Mockito.CALLS_REAL_METHODS)) {
            LicensePersistRecord record = decode(wire);
            // Every receipt still goes through the real constructor and its key validation on recovery.
            validation.verify(() -> LicenseText.matches(KEY_ID, 128, true),
                    Mockito.times(LicenseClockRepair.MAX_RECEIPTS));
            LicenseClockRepair.State state = record.clockState();
            Assertions.assertEquals(LicenseClockRepair.MAX_RECEIPTS, state.getReceipts().size());
            for (int i = 0; i < 10_000; i++) {
                LicenseClockRepair.State reading = record.clockState();
                Assertions.assertSame(state, reading);
                Assertions.assertEquals(LicenseClockRepair.MAX_RECEIPTS, reading.getFacts().getVersion());
                UUID id = new UUID(0, i % LicenseClockRepair.MAX_RECEIPTS + 1);
                Assertions.assertNotNull(reading.getReceipts().get(id));
            }
            validation.verify(() -> LicenseText.matches(KEY_ID, 128, true),
                    Mockito.times(LicenseClockRepair.MAX_RECEIPTS));
            Assertions.assertArrayEquals(wire, encode(record));

            // A new image/journal envelope must validate independently, even for identical bytes.
            LicensePersistRecord another = decode(wire);
            validation.verify(() -> LicenseText.matches(KEY_ID, 128, true),
                    Mockito.times(2 * LicenseClockRepair.MAX_RECEIPTS));
            Assertions.assertNotSame(state, another.clockState());
            Assertions.assertTrue(record.sameAs(another));
        }
    }

    @Test
    void malformedNewEnvelopesNeverReuseThePreviouslyValidClockHistory() throws Exception {
        LicensePersistRecord valid = history(2);
        byte[] original = encode(valid);
        ObjectNode envelope = envelope(original);
        List<Consumer<ObjectNode>> corruptions = Arrays.asList(
                root -> clock(root).put("unknown", true),
                root -> clock(root).remove("authorization_version"),
                root -> clock(root).put("version", "2"),
                root -> clock(root).put("version", 2.0),
                root -> clock(root).put("version", true),
                root -> root.put("record_version", BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE)),
                root -> clock(root).put("high_water_millis", LicenseClock.MAX_MILLIS + 1),
                root -> receipts(root).add(receipts(root).get(0).deepCopy()),
                root -> ((ObjectNode) receipts(root).get(1)).put("committed_version", 3),
                root -> ((ObjectNode) receipts(root).get(1)).put("clock_epoch", 1),
                root -> ((ObjectNode) receipts(root).get(0)).put("key_id", "private.payload.signature\n"),
                root -> ((ObjectNode) receipts(root).get(0)).put("fingerprint", "not-a-fingerprint"),
                root -> ((ObjectNode) receipts(root).get(0)).put("repair_id", "not-a-uuid"),
                root -> {
                    ArrayNode values = receipts(root);
                    while (values.size() <= LicenseClockRepair.MAX_RECEIPTS) {
                        values.add(values.get(0).deepCopy());
                    }
                },
                // This field is checked after the clock history; a partial validation cannot escape.
                root -> root.putObject("submission_versions").put("invalid-fingerprint", 1));
        LicenseClockRepair.State cached = valid.clockState();
        for (Consumer<ObjectNode> corruption : corruptions) {
            ObjectNode damaged = envelope.deepCopy();
            corruption.accept(damaged);
            byte[] wire = frame(JSON.writeValueAsBytes(damaged));
            IOException error = Assertions.assertThrows(IOException.class, () -> decode(wire));
            Assertions.assertEquals("Invalid MassDB license metadata envelope", error.getMessage());
            Assertions.assertNull(error.getCause());
            Assertions.assertSame(cached, valid.clockState());
            Assertions.assertEquals(2, valid.clockState().getReceipts().size());
            Assertions.assertArrayEquals(original, encode(valid));
        }
    }

    @Test
    void clockViewsCannotBeMutatedAndReplacementRecordsRetainTheirOwnFacts() throws Exception {
        LicensePersistRecord original = history(2);
        byte[] originalWire = encode(original);
        LicenseClockRepair.State before = original.clockState();
        Assertions.assertThrows(UnsupportedOperationException.class, () -> before.getReceipts().clear());
        Map.Entry<UUID, LicenseClockRepair.Receipt> entry = before.getReceipts().entrySet().iterator().next();
        Assertions.assertThrows(UnsupportedOperationException.class, () -> entry.setValue(entry.getValue()));

        Map<UUID, LicenseClockRepair.Receipt> receipts = new LinkedHashMap<>(before.getReceipts());
        LicenseClockRepair.Receipt added = receipt(3);
        receipts.put(added.getRepairId(), added);
        LicenseClockRepair.State next = new LicenseClockRepair.State(DEPLOYMENT,
                new LicenseClock.Facts(3, 3, WALL + 60_000, 3), receipts);
        LicensePersistRecord replacement = original.withClock(LicensePersistRecord.REPAIR, next);
        receipts.clear();
        Assertions.assertNotSame(before, replacement.clockState());
        Assertions.assertEquals(3, replacement.clockState().getReceipts().size());
        Assertions.assertEquals(WALL + 60_000, replacement.clockState().getFacts().getHighWaterMillis());
        Assertions.assertEquals(2, before.getReceipts().size());
        Assertions.assertEquals(WALL, before.getFacts().getHighWaterMillis());
        Assertions.assertArrayEquals(originalWire, encode(original));
        LicensePersistRecord recovered = decode(encode(replacement));
        Assertions.assertTrue(recovered.sameAs(replacement));
        Assertions.assertTrue(recovered.clockState().getFacts().sameAs(replacement.clockState().getFacts()));
        Assertions.assertEquals(added.getFingerprint(),
                recovered.clockState().getReceipts().get(added.getRepairId()).getFingerprint());
    }

    @Test
    void coldReplayMatchesFactoryRecordsAcrossInitializationWatermarksAndRepairs() throws Exception {
        LicensePersistRecord initial = LicensePersistRecord.initial(DEPLOYMENT, false, WALL);
        LicensePersistRecord source = history(2);
        LicenseClockRepair.State previous = source.clockState();
        LicensePersistRecord watermark = source.withClock(LicensePersistRecord.WATERMARK,
                new LicenseClockRepair.State(DEPLOYMENT, new LicenseClock.Facts(3, 2, WALL + 60_000, 2),
                        previous.getReceipts()));
        Map<UUID, LicenseClockRepair.Receipt> receipts = new LinkedHashMap<>(previous.getReceipts());
        LicenseClockRepair.Receipt added = receipt(3);
        receipts.put(added.getRepairId(), added);
        LicensePersistRecord repair = source.withClock(LicensePersistRecord.REPAIR,
                new LicenseClockRepair.State(DEPLOYMENT, new LicenseClock.Facts(3, 3, WALL, 3), receipts));
        LicensePersistRecord rollout = repair.withRollout(String.format("%064x", 10),
                String.format("%064x", 11), 1);
        for (LicensePersistRecord pendingCommit : new LicensePersistRecord[] {initial, watermark, repair, rollout}) {
            byte[] written = encode(pendingCommit);
            LicensePersistRecord replayed = decode(written);
            Assertions.assertArrayEquals(written, encode(replayed));
            // A durable journal read must match the in-memory record after an uncertain write/apply result.
            Assertions.assertTrue(pendingCommit.sameAs(replayed));
            Assertions.assertTrue(replayed.sameAs(pendingCommit));
            Assertions.assertTrue(pendingCommit.clockState().getFacts().sameAs(replayed.clockState().getFacts()));
            JsonNode reorderedFields = reverseObjectFields(envelope(written));
            LicensePersistRecord reordered = decode(frame(JSON.writeValueAsBytes(reorderedFields)));
            Assertions.assertTrue(pendingCommit.sameAs(reordered));
        }
    }

    @Test
    void replayMatchingStillRejectsDifferentFactsScalarValuesAndArrayOrder() throws Exception {
        LicensePersistRecord record = history(2);
        ObjectNode original = envelope(encode(record));
        List<Consumer<ObjectNode>> differences = Arrays.asList(
                root -> root.put("record_version", record.getVersion() + 1),
                root -> clock(root).put("high_water_millis", WALL + 1),
                root -> root.put("bootstrap", true),
                root -> root.put("complete", false),
                root -> root.put("clock_suspect", true),
                root -> root.put("deployment_id", "12345678-1234-1234-1234-123456789abd"),
                root -> root.put("operation", LicensePersistRecord.INTEGRITY),
                root -> ((ObjectNode) receipts(root).get(0)).put("key_id", "different-issuer"),
                root -> {
                    ArrayNode receipts = receipts(root);
                    JsonNode first = receipts.get(0);
                    receipts.set(0, receipts.get(1));
                    receipts.set(1, first);
                });
        for (Consumer<ObjectNode> difference : differences) {
            ObjectNode changed = original.deepCopy();
            difference.accept(changed);
            LicensePersistRecord replayed = decode(frame(JSON.writeValueAsBytes(changed)));
            Assertions.assertFalse(record.sameAs(replayed));
            Assertions.assertFalse(replayed.sameAs(record));
        }
        // Adjacent integers beyond floating-point precision must never compare equal.
        ObjectNode largeVersion = original.deepCopy();
        largeVersion.put("record_version", Long.MAX_VALUE);
        LicensePersistRecord last = decode(frame(JSON.writeValueAsBytes(largeVersion)));
        largeVersion.put("record_version", Long.MAX_VALUE - 1);
        LicensePersistRecord preceding = decode(frame(JSON.writeValueAsBytes(largeVersion)));
        Assertions.assertFalse(last.sameAs(preceding));
        Assertions.assertFalse(record.sameAs(null));
    }

    @Test
    void cachedClockViewDoesNotBypassChecksumsJsonUniquenessOrFrameBounds() throws Exception {
        byte[] valid = encode(history(2));
        byte[] checksumDamage = valid.clone();
        checksumDamage[checksumDamage.length - 1] ^= 1;
        byte[] truncated = Arrays.copyOf(valid, valid.length - 1);
        String json = JSON.writeValueAsString(envelope(valid));
        byte[] duplicate = frame((json.substring(0, json.length() - 1) + ",\"clock\":{}}")
                .getBytes(StandardCharsets.UTF_8));
        byte[] trailing = frame((json + "{}").getBytes(StandardCharsets.UTF_8));
        for (byte[] invalid : new byte[][] {checksumDamage, truncated, duplicate, trailing}) {
            Assertions.assertThrows(IOException.class, () -> decode(invalid));
        }
        for (int length : new int[] {-1, 0, LicensePersistRecord.MAX_BYTES}) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            new DataOutputStream(bytes).writeInt(length);
            Assertions.assertThrows(IOException.class, () -> decode(bytes.toByteArray()));
        }
        Assertions.assertArrayEquals(valid, encode(decode(valid)));
    }

    private static LicensePersistRecord history(int count) throws Exception {
        Map<UUID, LicenseClockRepair.Receipt> receipts = new LinkedHashMap<>();
        for (int i = 1; i <= count; i++) {
            LicenseClockRepair.Receipt receipt = receipt(i);
            receipts.put(receipt.getRepairId(), receipt);
        }
        LicensePersistRecord record = LicensePersistRecord.initial(DEPLOYMENT, false, WALL)
                .withClock(LicensePersistRecord.REPAIR, new LicenseClockRepair.State(DEPLOYMENT,
                        new LicenseClock.Facts(count, count, WALL, count), receipts));
        // Model a retained history accumulated over count repairs, not count live signature operations.
        ObjectNode root = envelope(encode(record));
        root.put("record_version", count + 1);
        return decode(frame(JSON.writeValueAsBytes(root)));
    }

    private static LicenseClockRepair.Receipt receipt(int sequence) {
        return new LicenseClockRepair.Receipt(new UUID(0, sequence), sequence, sequence, WALL,
                KEY_ID, String.format("%064x", sequence));
    }

    private static JsonNode reverseObjectFields(JsonNode value) {
        if (value.isObject()) {
            ObjectNode reversed = JSON.createObjectNode();
            List<String> names = new ArrayList<>();
            value.fieldNames().forEachRemaining(names::add);
            Collections.reverse(names);
            for (String name : names) {
                reversed.set(name, reverseObjectFields(value.get(name)));
            }
            return reversed;
        }
        if (value.isArray()) {
            ArrayNode array = JSON.createArrayNode();
            for (JsonNode element : value) {
                array.add(reverseObjectFields(element));
            }
            return array;
        }
        return value;
    }

    private static ObjectNode clock(ObjectNode root) {
        return (ObjectNode) root.get("clock");
    }

    private static ArrayNode receipts(ObjectNode root) {
        return (ArrayNode) clock(root).get("receipts");
    }

    private static ObjectNode envelope(byte[] wire) throws Exception {
        DataInputStream input = new DataInputStream(new ByteArrayInputStream(wire));
        byte[] bytes = new byte[input.readInt()];
        input.readFully(bytes);
        return (ObjectNode) JSON.readTree(bytes);
    }

    private static byte[] encode(LicensePersistRecord record) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        record.write(new DataOutputStream(bytes));
        return bytes.toByteArray();
    }

    private static byte[] frame(byte[] json) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeInt(json.length);
        output.write(json);
        output.write(MessageDigest.getInstance("SHA-256").digest(json));
        return bytes.toByteArray();
    }

    private static LicensePersistRecord decode(byte[] wire) throws IOException {
        return LicensePersistRecord.read(new DataInputStream(new ByteArrayInputStream(wire)));
    }
}
