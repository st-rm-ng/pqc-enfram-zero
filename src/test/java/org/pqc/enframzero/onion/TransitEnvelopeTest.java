package org.pqc.enframzero.onion;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class TransitEnvelopeTest {

    @Test
    void serialiseDeserialise_roundTrip() {
        byte[] key = "det-key-abc".getBytes(StandardCharsets.UTF_8);
        byte[] value = new byte[]{1, 2, 3, 4, 5};
        byte[] payload = TransitEnvelope.serialisePayload(key, value);
        byte[][] parts = TransitEnvelope.deserialisePayload(payload);
        assertArrayEquals(key, parts[0]);
        assertArrayEquals(value, parts[1]);
    }

    @Test
    void serialiseDeserialise_emptyValue() {
        byte[] key = "k".getBytes(StandardCharsets.UTF_8);
        byte[] value = new byte[0];
        byte[] payload = TransitEnvelope.serialisePayload(key, value);
        byte[][] parts = TransitEnvelope.deserialisePayload(payload);
        assertArrayEquals(key, parts[0]);
        assertArrayEquals(value, parts[1]);
    }

    @Test
    void signInput_concatenatesKemAndPayload() {
        byte[] kem = new byte[]{1, 2, 3};
        byte[] payload = new byte[]{4, 5, 6};
        byte[] sig = new byte[]{0};
        TransitEnvelope envelope = new TransitEnvelope(kem, payload, sig);
        byte[] combined = envelope.signInput();
        assertEquals(6, combined.length);
        assertEquals(1, combined[0]);
        assertEquals(4, combined[3]);
    }
}
