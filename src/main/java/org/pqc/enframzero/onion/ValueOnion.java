package org.pqc.enframzero.onion;

import org.pqc.enframzero.crypto.AesGcmService;

/**
 * Encrypts and decrypts value bytes using the data encryption key (at-rest layer).
 * Uses AES-256-GCM with a random IV per encryption, producing ciphertext that is
 * fully opaque and unlinkable across multiple writes of the same value.
 */
public class ValueOnion {

    private final AesGcmService aesGcm;

    public ValueOnion(AesGcmService aesGcm) {
        this.aesGcm = aesGcm;
    }

    /**
     * Encrypts a plaintext value with the data encryption key.
     * Returns {@code IV (12 bytes) || ciphertext || GCM tag (16 bytes)}.
     */
    public byte[] encrypt(byte[] plainValue, byte[] dataKey) {
        return aesGcm.encrypt(plainValue, dataKey);
    }

    /**
     * Decrypts a value previously encrypted by {@link #encrypt}.
     */
    public byte[] decrypt(byte[] encryptedValue, byte[] dataKey) {
        return aesGcm.decrypt(encryptedValue, dataKey);
    }
}
