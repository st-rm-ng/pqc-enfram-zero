package org.pqc.enframzero.framework;

import org.pqc.enframzero.keys.KeyBundleRegistry;

import java.util.Optional;

/**
 * Public API for the PQC client-side encryption framework.
 *
 * <p>All values are transparently encrypted before storage and decrypted on retrieval.
 * Plaintext exists only within this client process.
 *
 * <p>Each operation has a no-arg form that uses the master key bundle and an overload
 * that accepts a {@code bundleId} to use (or auto-create) a named bundle. The bundle id
 * is stored alongside the ciphertext in DynamoDB so the correct bundle can be selected
 * on retrieval.
 */
public interface PqcFramework {

    // ── master-bundle operations (backward-compatible) ──────────────────────

    /** Encrypts and stores {@code value} using the master key bundle. */
    default void put(String key, byte[] value) {
        put(key, value, KeyBundleRegistry.MASTER);
    }

    /** Retrieves and decrypts the value using the master key bundle. */
    default Optional<byte[]> get(String key) {
        return get(key, KeyBundleRegistry.MASTER);
    }

    /** Deletes the entry encrypted with the master key bundle. */
    default void delete(String key) {
        delete(key, KeyBundleRegistry.MASTER);
    }

    // ── named-bundle operations ──────────────────────────────────────────────

    /**
     * Encrypts and stores {@code value} using the bundle identified by {@code bundleId}.
     * If the bundle does not exist yet it is auto-generated and registered.
     */
    void put(String key, byte[] value, String bundleId);

    /**
     * Retrieves and decrypts the value using the bundle identified by {@code bundleId}.
     * Returns empty if no entry exists. Throws {@link IllegalArgumentException} if the
     * bundle has not been registered. Throws {@link IntegrityException} if verification fails.
     */
    Optional<byte[]> get(String key, String bundleId);

    /**
     * Deletes the entry that was encrypted with the bundle identified by {@code bundleId}.
     * Throws {@link IllegalArgumentException} if the bundle has not been registered.
     */
    void delete(String key, String bundleId);

    // ── string convenience helpers ───────────────────────────────────────────

    /** Convenience overload for String values (UTF-8 encoding), master bundle. */
    default void putString(String key, String value) {
        put(key, value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /** Convenience overload for String values (UTF-8 encoding), named bundle. */
    default void putString(String key, String value, String bundleId) {
        put(key, value.getBytes(java.nio.charset.StandardCharsets.UTF_8), bundleId);
    }

    /** Convenience overload returning a String (UTF-8 decoding), master bundle. */
    default Optional<String> getString(String key) {
        return get(key).map(b -> new String(b, java.nio.charset.StandardCharsets.UTF_8));
    }

    /** Convenience overload returning a String (UTF-8 decoding), named bundle. */
    default Optional<String> getString(String key, String bundleId) {
        return get(key, bundleId).map(b -> new String(b, java.nio.charset.StandardCharsets.UTF_8));
    }
}
