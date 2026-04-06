package org.pqc.enframzero.onion;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pqc.enframzero.crypto.AesGcmServiceImpl;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class KeyOnionTest {

    private KeyOnion keyOnion;
    private byte[] dataKey;

    @BeforeEach
    void setUp() {
        keyOnion = new KeyOnion(new AesGcmServiceImpl());
        dataKey = new byte[32];
        new SecureRandom().nextBytes(dataKey);
    }

    @Test
    void detLayer_sameInputProducesSameOutput() {
        String key = "user:123";
        String out1 = keyOnion.apply(key, dataKey, OnionLayer.DET);
        String out2 = keyOnion.apply(key, dataKey, OnionLayer.DET);
        assertEquals(out1, out2, "DET layer must be deterministic");
    }

    @Test
    void detLayer_differentKeyProducesDifferentOutput() {
        String out1 = keyOnion.apply("user:1", dataKey, OnionLayer.DET);
        String out2 = keyOnion.apply("user:2", dataKey, OnionLayer.DET);
        assertNotEquals(out1, out2);
    }

    @Test
    void detLayer_differentDekProducesDifferentOutput() {
        String key = "user:123";
        byte[] otherDek = new byte[32];
        new SecureRandom().nextBytes(otherDek);
        String out1 = keyOnion.apply(key, dataKey, OnionLayer.DET);
        String out2 = keyOnion.apply(key, otherDek, OnionLayer.DET);
        assertNotEquals(out1, out2);
    }

    @Test
    void plainLayer_returnsInputUnchanged() {
        String key = "my-plain-key";
        assertEquals(key, keyOnion.apply(key, dataKey, OnionLayer.PLAIN));
    }

    @Test
    void rndLayer_sameInputProducesDifferentOutput() {
        String key = "user:123";
        String out1 = keyOnion.apply(key, dataKey, OnionLayer.RND);
        String out2 = keyOnion.apply(key, dataKey, OnionLayer.RND);
        assertNotEquals(out1, out2, "RND layer must produce different ciphertext each call");
    }

    @Test
    void detLayer_outputIsBase64UrlEncoded() {
        String out = keyOnion.apply("test-key", dataKey, OnionLayer.DET);
        // Base64URL alphabet: A-Z, a-z, 0-9, -, _ (no +, /, or =)
        assertTrue(out.matches("[A-Za-z0-9_-]+"), "DET output must be Base64URL without padding");
    }
}
