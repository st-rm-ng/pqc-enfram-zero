package org.pqc.enframzero.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pqc.enframzero.keys.InMemoryKeyManager;
import org.pqc.enframzero.keys.PqcKeyBundle;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class MlDsaServiceImplTest {

    private MlDsaService service;
    private PqcKeyBundle bundle;

    @BeforeEach
    void setUp() {
        service = new MlDsaServiceImpl();
        bundle = new InMemoryKeyManager().generateKeys();
    }

    @Test
    void signAndVerify_validSignature() {
        byte[] message = "authenticate this".getBytes();
        byte[] signature = service.sign(message, bundle.dsaPrivateKey());
        assertTrue(service.verify(message, signature, bundle.dsaPublicKey()));
    }

    @Test
    void verify_tamperedMessage_returnsFalse() {
        byte[] message = "original message".getBytes();
        byte[] signature = service.sign(message, bundle.dsaPrivateKey());
        message[0] ^= 0xFF;
        assertFalse(service.verify(message, signature, bundle.dsaPublicKey()));
    }

    @Test
    void verify_tamperedSignature_returnsFalse() {
        byte[] message = "signed message".getBytes();
        byte[] signature = service.sign(message, bundle.dsaPrivateKey());
        byte[] tampered = Arrays.copyOf(signature, signature.length);
        tampered[tampered.length / 2] ^= 0xFF;
        assertFalse(service.verify(message, tampered, bundle.dsaPublicKey()));
    }

    @Test
    void verify_wrongPublicKey_returnsFalse() {
        byte[] message = "message".getBytes();
        byte[] signature = service.sign(message, bundle.dsaPrivateKey());
        PqcKeyBundle otherBundle = new InMemoryKeyManager().generateKeys();
        assertFalse(service.verify(message, signature, otherBundle.dsaPublicKey()));
    }

    @Test
    void sign_producesNonEmptySignature() {
        byte[] message = "hello".getBytes();
        byte[] signature = service.sign(message, bundle.dsaPrivateKey());
        assertNotNull(signature);
        assertTrue(signature.length > 0);
    }
}
