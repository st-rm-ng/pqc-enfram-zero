package org.pqc.enframzero.store;

import org.pqc.enframzero.onion.TransitEnvelope;

import java.util.Optional;

/**
 * Persistence layer for encrypted envelopes.
 * Receives and returns only opaque {@link TransitEnvelope} objects — no plaintext crosses this boundary.
 */
public interface EncryptedStore {

    /**
     * Stores the envelope under the given deterministic key.
     * Overwrites any existing entry for the same key.
     */
    void put(String deterministicKey, TransitEnvelope envelope);

    /**
     * Retrieves the envelope for the given deterministic key, if present.
     */
    Optional<TransitEnvelope> get(String deterministicKey);

    /**
     * Deletes the entry for the given deterministic key.
     * No-op if the key does not exist.
     */
    void delete(String deterministicKey);
}
