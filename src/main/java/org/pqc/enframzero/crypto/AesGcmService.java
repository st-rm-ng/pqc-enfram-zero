package org.pqc.enframzero.crypto;

/**
 * Symmetric authenticated encryption using AES-256-GCM.
 */
public interface AesGcmService {

    /**
     * Encrypts plaintext with the given 256-bit key.
     * Returns a self-contained byte array: {@code IV (12 bytes) || ciphertext || GCM tag (16 bytes)}.
     */
    byte[] encrypt(byte[] plaintext, byte[] key);

    /**
     * Decrypts the combined byte array produced by {@link #encrypt}.
     * Throws if the GCM authentication tag does not match (tampered ciphertext).
     */
    byte[] decrypt(byte[] ivAndCiphertext, byte[] key);
}
