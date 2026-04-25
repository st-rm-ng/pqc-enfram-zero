package org.pqc.enframzero.framework;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pqc.enframzero.crypto.AesGcmServiceImpl;
import org.pqc.enframzero.crypto.MlDsaServiceImpl;
import org.pqc.enframzero.crypto.MlKemServiceImpl;
import org.pqc.enframzero.keys.InMemoryKeyManager;
import org.pqc.enframzero.keys.KeyBundleRegistry;
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
    private InMemoryEncryptedStore store;

    @BeforeEach
    void setUp() {
        var aesGcm = new AesGcmServiceImpl();
        var keyManager = new InMemoryKeyManager();
        KeyBundleRegistry registry = new KeyBundleRegistry(keyManager.generateKeys(), keyManager);
        store = new InMemoryEncryptedStore();
        framework = new PqcFrameworkImpl(
                registry,
                new MlKemServiceImpl(),
                new MlDsaServiceImpl(),
                aesGcm,
                new KeyOnion(aesGcm),
                new ValueOnion(aesGcm),
                store
        );
    }

    // ── master-bundle tests (backward-compatible) ────────────────────────────

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
        var keyManager = new InMemoryKeyManager();
        KeyBundleRegistry registry = new KeyBundleRegistry(keyManager.generateKeys(), keyManager);
        InMemoryEncryptedStore tamperedStore = new InMemoryEncryptedStore();
        PqcFramework fw = new PqcFrameworkImpl(
                registry,
                new MlKemServiceImpl(),
                new MlDsaServiceImpl(),
                aesGcm,
                new KeyOnion(aesGcm),
                new ValueOnion(aesGcm),
                tamperedStore
        );

        fw.putString("secret", "value");
        tamperedStore.tamperSignature("secret");

        assertThrows(IntegrityException.class, () -> fw.getString("secret"));
    }

    // ── multi-bundle tests ───────────────────────────────────────────────────

    @Test
    void put_namedBundle_roundTrip() {
        framework.putString("session:xyz", "data", "bundle-b");
        Optional<String> result = framework.getString("session:xyz", "bundle-b");
        assertTrue(result.isPresent());
        assertEquals("data", result.get());
    }

    @Test
    void put_namedBundle_autoCreaesBundle() {
        // "bundle-c" does not exist yet — should be auto-created
        assertDoesNotThrow(() -> framework.putString("new-key", "hello", "bundle-c"));
        assertEquals("hello", framework.getString("new-key", "bundle-c").orElseThrow());
    }

    @Test
    void put_masterAndNamedBundle_storedUnderDifferentPartitionKeys() {
        // Same logical key written with two different bundles must produce two separate rows
        framework.putString("shared-key", "master-value");
        framework.putString("shared-key", "bundle-b-value", "bundle-b");

        assertEquals("master-value", framework.getString("shared-key").orElseThrow());
        assertEquals("bundle-b-value", framework.getString("shared-key", "bundle-b").orElseThrow());
        assertEquals(2, store.size());
    }

    @Test
    void get_namedBundle_wrongBundleCannotDecrypt() {
        // Register "bundle-b" by writing a different key with it, then write "key" with master.
        // Reading "key" with "bundle-b" must miss because the HMAC(bundleBDEK, "key") ≠ HMAC(masterDEK, "key").
        framework.put("warmup", new byte[]{0}, "bundle-b");
        framework.putString("key", "secret");
        Optional<String> result = framework.getString("key", "bundle-b");
        assertTrue(result.isEmpty(), "Different bundle derives a different partition key → miss");
    }

    @Test
    void get_unregisteredBundle_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> framework.getString("any-key", "bundle-never-registered"));
    }

    @Test
    void delete_namedBundle_removesOnlyThatEntry() {
        framework.putString("key", "master-value");
        framework.putString("key", "bundle-b-value", "bundle-b");

        framework.delete("key", "bundle-b");

        assertEquals("master-value", framework.getString("key").orElseThrow());
        assertTrue(framework.getString("key", "bundle-b").isEmpty());
    }

    @Test
    void storedEnvelope_hasCorrectKid() {
        framework.putString("k", "v", "bundle-b");
        // All stored envelopes should carry kid = "bundle-b"
        store.allEnvelopes().forEach(e -> assertEquals("bundle-b", e.keyId()));
    }

    // ── helper store ─────────────────────────────────────────────────────────

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

        public int size() {
            return data.size();
        }

        public java.util.Collection<TransitEnvelope> allEnvelopes() {
            return data.values();
        }

        /** Flips a byte in the signature of every stored envelope. */
        public void tamperSignature(String ignored) {
            for (Map.Entry<String, TransitEnvelope> entry : data.entrySet()) {
                TransitEnvelope e = entry.getValue();
                byte[] tampered = e.dsaSignature().clone();
                tampered[tampered.length / 2] ^= 0xFF;
                data.put(entry.getKey(), new TransitEnvelope(e.keyId(), e.kemEncapsulation(), e.encryptedPayload(), tampered));
            }
        }
    }
}
