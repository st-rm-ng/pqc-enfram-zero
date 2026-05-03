package org.pqc.enframzero.benchmark;

import org.pqc.enframzero.onion.TransitEnvelope;
import org.pqc.enframzero.store.EncryptedStore;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory EncryptedStore used by benchmarks to isolate cryptographic
 * overhead from DynamoDB network latency.
 */
public class InMemoryEncryptedStore implements EncryptedStore {

    private final Map<String, TransitEnvelope> data = new ConcurrentHashMap<>();

    @Override
    public void put(String deterministicKey, TransitEnvelope envelope) {
        data.put(deterministicKey, envelope);
    }

    @Override
    public Optional<TransitEnvelope> get(String deterministicKey) {
        return Optional.ofNullable(data.get(deterministicKey));
    }

    @Override
    public void delete(String deterministicKey) {
        data.remove(deterministicKey);
    }

    /**
     * Computes the total raw bytes of a stored envelope
     * (deterministic key + all binary fields), matching the actual bytes
     * written to DynamoDB as Binary and String attributes.
     */
    public int storedBytes(String plainKey, String deterministicKey) {
        TransitEnvelope e = data.get(deterministicKey);
        if (e == null) throw new IllegalArgumentException("Key not found: " + plainKey);
        return deterministicKey.length()          // pk attribute (Base64URL string)
             + e.keyId().length()                 // kid attribute (bundle id string)
             + e.kemEncapsulation().length         // kem attribute (binary)
             + e.encryptedPayload().length         // payload attribute (binary)
             + e.dsaSignature().length;            // sig attribute (binary)
    }
}
