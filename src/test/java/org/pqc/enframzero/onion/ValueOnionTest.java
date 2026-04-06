package org.pqc.enframzero.onion;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pqc.enframzero.crypto.AesGcmServiceImpl;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class ValueOnionTest {

    private ValueOnion valueOnion;
    private byte[] dataKey;

    @BeforeEach
    void setUp() {
        valueOnion = new ValueOnion(new AesGcmServiceImpl());
        dataKey = new byte[32];
        new SecureRandom().nextBytes(dataKey);
    }

    @Test
    void encryptDecrypt_roundTrip() {
        byte[] value = "sensitive data".getBytes();
        byte[] encrypted = valueOnion.encrypt(value, dataKey);
        byte[] decrypted = valueOnion.decrypt(encrypted, dataKey);
        assertArrayEquals(value, decrypted);
    }

    @Test
    void encrypt_sameValueProducesDifferentCiphertext() {
        byte[] value = "same value".getBytes();
        byte[] enc1 = valueOnion.encrypt(value, dataKey);
        byte[] enc2 = valueOnion.encrypt(value, dataKey);
        assertFalse(Arrays.equals(enc1, enc2));
    }

    @Test
    void encryptedOutputIsLargerThanInput() {
        byte[] value = "hello".getBytes();
        byte[] encrypted = valueOnion.encrypt(value, dataKey);
        assertTrue(encrypted.length > value.length);
    }
}
