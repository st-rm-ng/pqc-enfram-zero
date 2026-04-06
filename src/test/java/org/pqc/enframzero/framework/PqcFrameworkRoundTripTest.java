package org.pqc.enframzero.framework;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pqc.enframzero.crypto.AesGcmServiceImpl;
import org.pqc.enframzero.crypto.MlDsaServiceImpl;
import org.pqc.enframzero.crypto.MlKemServiceImpl;
import org.pqc.enframzero.keys.InMemoryKeyManager;
import org.pqc.enframzero.keys.PqcKeyBundle;
import org.pqc.enframzero.onion.KeyOnion;
import org.pqc.enframzero.onion.TransitEnvelope;
import org.pqc.enframzero.onion.ValueOnion;
import org.pqc.enframzero.store.EncryptedStore;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class PqcFrameworkRoundTripTest {

    private PqcFramework framework;

    @BeforeEach
    void setUp() {
        var aesGcm = new AesGcmServiceImpl();
        PqcKeyBundle bundle = new InMemoryKeyManager().generateKeys();
        framework = new PqcFrameworkImpl(
                bundle,
                new MlKemServiceImpl(),
                new MlDsaServiceImpl(),
                aesGcm,
                new KeyOnion(aesGcm),
                new ValueOnion(aesGcm),
                new InMemoryEncryptedStore()
        );
    }

    @Test
    void putAndGetString_roundTrip() {
        framework.putString("user:1", "Alice");
        Optional<String> result = framework.getString("user:1");
        assertTrue(result.isPresent());
        assertEquals("Alice", result.get());
    }

    @Test
    void putAndGetBytes_roundTrip() {
        byte[] value = new byte[]{10, 20, 30, 40};
        framework.put("binary-key", value);
        Optional<byte[]> result = framework.get("binary-key");
        assertTrue(result.isPresent());
        assertArrayEquals(value, result.get());
    }

    @Test
    void get_missingKey_returnsEmpty() {
        assertTrue(framework.get("nonexistent").isEmpty());
    }

    @Test
    void delete_removesEntry() {
        framework.putString("temp", "value");
        framework.delete("temp");
        assertTrue(framework.getString("temp").isEmpty());
    }

    @Test
    void put_overwritesPreviousValue() {
        framework.putString("key", "first");
        framework.putString("key", "second");
        assertEquals("second", framework.getString("key").orElseThrow());
    }

    @Test
    void put_multipleKeysAreIndependent() {
        framework.putString("k1", "v1");
        framework.putString("k2", "v2");
        assertEquals("v1", framework.getString("k1").orElseThrow());
        assertEquals("v2", framework.getString("k2").orElseThrow());
    }

    @Test
    void get_tamperedEnvelope_throwsIntegrityException() {
        var aesGcm = new AesGcmServiceImpl();
        PqcKeyBundle bundle = new InMemoryKeyManager().generateKeys();
        InMemoryEncryptedStore store = new InMemoryEncryptedStore();
        PqcFramework fw = new PqcFrameworkImpl(
                bundle,
                new MlKemServiceImpl(),
                new MlDsaServiceImpl(),
                aesGcm,
                new KeyOnion(aesGcm),
                new ValueOnion(aesGcm),
                store
        );

        fw.putString("secret", "value");
        // Tamper with the stored envelope's signature
        store.tamperSignature("secret");

        assertThrows(IntegrityException.class, () -> fw.getString("secret"));
    }

    /** Simple in-memory store for testing, backed by a HashMap. */
    static class InMemoryEncryptedStore implements EncryptedStore {
        private final Map<String, TransitEnvelope> data = new HashMap<>();

        @Override
        public void put(String key, TransitEnvelope envelope) {
            data.put(key, envelope);
        }

        @Override
        public Optional<TransitEnvelope> get(String key) {
            return Optional.ofNullable(data.get(key));
        }

        @Override
        public void delete(String key) {
            data.remove(key);
        }

        /** Flips a byte in the signature of every stored envelope matching the logical key prefix. */
        public void tamperSignature(String logicalKeyPrefix) {
            for (Map.Entry<String, TransitEnvelope> entry : data.entrySet()) {
                TransitEnvelope e = entry.getValue();
                byte[] tampered = e.dsaSignature().clone();
                tampered[tampered.length / 2] ^= 0xFF;
                data.put(entry.getKey(), new TransitEnvelope(e.kemEncapsulation(), e.encryptedPayload(), tampered));
            }
        }
    }
}
