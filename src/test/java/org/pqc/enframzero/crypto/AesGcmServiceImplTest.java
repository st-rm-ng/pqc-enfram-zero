package org.pqc.enframzero.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class AesGcmServiceImplTest {

    private AesGcmService service;
    private byte[] key;

    @BeforeEach
    void setUp() {
        service = new AesGcmServiceImpl();
        key = new byte[32];
        new SecureRandom().nextBytes(key);
    }

    @Test
    void encryptDecrypt_roundTrip() {
        byte[] plaintext = "Hello, PQC World!".getBytes();
        byte[] ciphertext = service.encrypt(plaintext, key);
        byte[] decrypted = service.decrypt(ciphertext, key);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void encrypt_sameInputProducesDifferentCiphertext() {
        byte[] plaintext = "same message".getBytes();
        byte[] ct1 = service.encrypt(plaintext, key);
        byte[] ct2 = service.encrypt(plaintext, key);
        assertFalse(Arrays.equals(ct1, ct2), "Random IV must produce different ciphertext each call");
    }

    @Test
    void encrypt_prependsIv_outputLargerThanInput() {
        byte[] plaintext = "test".getBytes();
        byte[] ciphertext = service.encrypt(plaintext, key);
        // IV (12) + plaintext + GCM tag (16)
        assertEquals(CryptoConstants.AES_GCM_IV_BYTES + plaintext.length + 16, ciphertext.length);
    }

    @Test
    void decrypt_tamperedCiphertext_throwsCryptoException() {
        byte[] plaintext = "tamper me".getBytes();
        byte[] ciphertext = service.encrypt(plaintext, key);
        ciphertext[ciphertext.length - 1] ^= 0xFF; // flip last byte (tag)
        assertThrows(CryptoException.class, () -> service.decrypt(ciphertext, key));
    }

    @Test
    void decrypt_wrongKey_throwsCryptoException() {
        byte[] plaintext = "secret".getBytes();
        byte[] ciphertext = service.encrypt(plaintext, key);
        byte[] wrongKey = new byte[32];
        new SecureRandom().nextBytes(wrongKey);
        assertThrows(CryptoException.class, () -> service.decrypt(ciphertext, wrongKey));
    }

    @Test
    void encryptDecrypt_emptyPlaintext() {
        byte[] plaintext = new byte[0];
        byte[] ciphertext = service.encrypt(plaintext, key);
        byte[] decrypted = service.decrypt(ciphertext, key);
        assertArrayEquals(plaintext, decrypted);
    }
}
