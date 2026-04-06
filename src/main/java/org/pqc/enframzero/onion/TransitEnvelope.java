package org.pqc.enframzero.onion;

/**
 * Wire format for a single DynamoDB item.
 * All fields are opaque byte arrays stored as DynamoDB Binary (B) attributes.
 *
 * <ul>
 *   <li>{@code kemEncapsulation} — ML-KEM ciphertext encapsulating the ephemeral transit key</li>
 *   <li>{@code encryptedPayload} — AES-GCM(transitKey, serialise(deterministicKey, encryptedValue))</li>
 *   <li>{@code dsaSignature}     — ML-DSA signature over (kemEncapsulation || encryptedPayload)</li>
 * </ul>
 *
 * The {@code encryptedPayload} itself contains the AES-GCM encrypted value (at-rest layer)
 * nested inside the ML-KEM transit layer, realising the two-layer onion encryption.
 */
public record TransitEnvelope(
        byte[] kemEncapsulation,
        byte[] encryptedPayload,
        byte[] dsaSignature
) {

    /**
     * Serialises the deterministic key and encrypted value into a compact binary payload.
     * Format: 4-byte big-endian key length | key bytes | encrypted value bytes.
     */
    public static byte[] serialisePayload(byte[] deterministicKeyBytes, byte[] encryptedValue) {
        byte[] result = new byte[4 + deterministicKeyBytes.length + encryptedValue.length];
        int keyLen = deterministicKeyBytes.length;
        result[0] = (byte) (keyLen >>> 24);
        result[1] = (byte) (keyLen >>> 16);
        result[2] = (byte) (keyLen >>> 8);
        result[3] = (byte) keyLen;
        System.arraycopy(deterministicKeyBytes, 0, result, 4, keyLen);
        System.arraycopy(encryptedValue, 0, result, 4 + keyLen, encryptedValue.length);
        return result;
    }

    /**
     * Deserialises a payload produced by {@link #serialisePayload}.
     * Returns a two-element array: [deterministicKeyBytes, encryptedValue].
     */
    public static byte[][] deserialisePayload(byte[] payload) {
        int keyLen = ((payload[0] & 0xFF) << 24)
                | ((payload[1] & 0xFF) << 16)
                | ((payload[2] & 0xFF) << 8)
                | (payload[3] & 0xFF);
        byte[] keyBytes = new byte[keyLen];
        byte[] valueBytes = new byte[payload.length - 4 - keyLen];
        System.arraycopy(payload, 4, keyBytes, 0, keyLen);
        System.arraycopy(payload, 4 + keyLen, valueBytes, 0, valueBytes.length);
        return new byte[][]{keyBytes, valueBytes};
    }

    /**
     * Concatenates kemEncapsulation and encryptedPayload for signing/verification.
     */
    public byte[] signInput() {
        byte[] combined = new byte[kemEncapsulation.length + encryptedPayload.length];
        System.arraycopy(kemEncapsulation, 0, combined, 0, kemEncapsulation.length);
        System.arraycopy(encryptedPayload, 0, combined, kemEncapsulation.length, encryptedPayload.length);
        return combined;
    }
}
