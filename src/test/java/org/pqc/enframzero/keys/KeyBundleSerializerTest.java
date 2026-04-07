package org.pqc.enframzero.keys;

import org.junit.jupiter.api.Test;
import org.pqc.enframzero.crypto.AesGcmServiceImpl;
import org.pqc.enframzero.framework.PqcFrameworkImpl;
import org.pqc.enframzero.framework.PqcFramework;
import org.pqc.enframzero.onion.KeyOnion;
import org.pqc.enframzero.onion.TransitEnvelope;
import org.pqc.enframzero.onion.ValueOnion;
import org.pqc.enframzero.store.EncryptedStore;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class KeyBundleSerializerTest {

    private static PqcKeyBundle freshBundle() {
        return new InMemoryKeyManager().generateKeys();
    }

    @Test
    void roundTrip_preservesAllKeyComponents() {
        PqcKeyBundle original = freshBundle();

        byte[] kemPubBefore  = original.kemPublicKey().getEncoded();
        byte[] kemPrivBefore = original.kemPrivateKey().getEncoded();
        byte[] dsaPubBefore  = original.dsaPublicKey().getEncoded();
        byte[] dsaPrivBefore = original.dsaPrivateKey().getEncoded();
        byte[] dekBefore     = original.dataEncryptionKey();

        byte[] serialised = KeyBundleSerializer.serialize(original);
        PqcKeyBundle restored = KeyBundleSerializer.deserialize(serialised);

        assertArrayEquals(kemPubBefore,  restored.kemPublicKey().getEncoded(),  "ML-KEM public key mismatch");
        assertArrayEquals(kemPrivBefore, restored.kemPrivateKey().getEncoded(), "ML-KEM private key mismatch");
        assertArrayEquals(dsaPubBefore,  restored.dsaPublicKey().getEncoded(),  "ML-DSA public key mismatch");
        assertArrayEquals(dsaPrivBefore, restored.dsaPrivateKey().getEncoded(), "ML-DSA private key mismatch");
        assertArrayEquals(dekBefore,     restored.dataEncryptionKey(),          "AES DEK mismatch");
    }

    @Test
    void serialisedSize_isWithinExpectedBounds() {
        byte[] bytes = KeyBundleSerializer.serialize(freshBundle());
        // ML-KEM-1024: pub=1568, priv=3168; ML-DSA-65: pub=1952, priv=4032; DEK=32; framing=5*4=20
        int expectedMin = 1568 + 3168 + 1952 + 4032 + 32 + 20;
        int expectedMax = expectedMin + 256; // small slack for any padding
        assertTrue(bytes.length >= expectedMin && bytes.length <= expectedMax,
                "Unexpected serialised size: " + bytes.length);
    }

    @Test
    void differentBundles_produceDifferentSerialisedBytes() {
        byte[] a = KeyBundleSerializer.serialize(freshBundle());
        byte[] b = KeyBundleSerializer.serialize(freshBundle());
        assertFalse(java.util.Arrays.equals(a, b));
    }

    @Test
    void deserialisedBundle_worksWithFramework() {
        var aesGcm = new AesGcmServiceImpl();
        PqcKeyBundle original = freshBundle();

        // Serialise and restore the bundle
        PqcKeyBundle restored = KeyBundleSerializer.deserialize(KeyBundleSerializer.serialize(original));

        // Build two framework instances sharing the same in-memory store
        InMemoryStore store = new InMemoryStore();
        PqcFramework fwWrite = buildFramework(original, store, aesGcm);
        PqcFramework fwRead  = buildFramework(restored, store, aesGcm);

        fwWrite.putString("hello", "quantum-safe");
        assertEquals("quantum-safe", fwRead.getString("hello").orElseThrow());
    }

    private static PqcFramework buildFramework(PqcKeyBundle bundle, EncryptedStore store,
                                                org.pqc.enframzero.crypto.AesGcmService aesGcm) {
        return new PqcFrameworkImpl(
                bundle,
                new org.pqc.enframzero.crypto.MlKemServiceImpl(),
                new org.pqc.enframzero.crypto.MlDsaServiceImpl(),
                aesGcm,
                new KeyOnion(aesGcm),
                new ValueOnion(aesGcm),
                store
        );
    }

    static class InMemoryStore implements EncryptedStore {
        private final Map<String, TransitEnvelope> data = new HashMap<>();
        @Override public void put(String k, TransitEnvelope e) { data.put(k, e); }
        @Override public Optional<TransitEnvelope> get(String k) { return Optional.ofNullable(data.get(k)); }
        @Override public void delete(String k) { data.remove(k); }
    }
}
