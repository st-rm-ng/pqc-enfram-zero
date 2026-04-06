package org.pqc.enframzero.keys;

/**
 * Generates client-side PQC key bundles.
 */
public interface PqcKeyManager {

    /**
     * Generates a fresh {@link PqcKeyBundle} containing:
     * <ul>
     *   <li>ML-KEM-1024 key pair (for transit encryption)</li>
     *   <li>ML-DSA-65 key pair (for integrity signatures)</li>
     *   <li>256-bit AES data encryption key (for at-rest encryption)</li>
     * </ul>
     */
    PqcKeyBundle generateKeys();
}
