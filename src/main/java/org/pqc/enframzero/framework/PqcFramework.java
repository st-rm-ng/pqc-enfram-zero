package org.pqc.enframzero.framework;

import java.util.Optional;

/**
 * Public API for the PQC client-side encryption framework.
 *
 * <p>All values are transparently encrypted before storage and decrypted on retrieval.
 * Plaintext exists only within this client process.
 */
public interface PqcFramework {

    /**
     * Stores a value under the given key, applying both at-rest (AES-256-GCM)
     * and in-transit (ML-KEM) encryption layers.
     */
    void put(String key, byte[] value);

    /**
     * Retrieves and decrypts the value for the given key.
     * Returns empty if no entry exists. Throws if integrity verification fails.
     */
    Optional<byte[]> get(String key);

    /**
     * Deletes the encrypted entry for the given key.
     */
    void delete(String key);

    /** Convenience overload for String values (UTF-8 encoding). */
    default void putString(String key, String value) {
        put(key, value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /** Convenience overload returning a String (UTF-8 decoding). */
    default Optional<String> getString(String key) {
        return get(key).map(b -> new String(b, java.nio.charset.StandardCharsets.UTF_8));
    }
}
