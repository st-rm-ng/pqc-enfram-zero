package org.pqc.enframzero.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pqc.enframzero.keys.InMemoryKeyManager;
import org.pqc.enframzero.keys.PqcKeyBundle;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class MlKemServiceImplTest {

    private MlKemService service;
    private PqcKeyBundle bundle;

    @BeforeEach
    void setUp() {
        service = new MlKemServiceImpl();
        bundle = new InMemoryKeyManager().generateKeys();
    }

    @Test
    void encapsulateDecapsulate_recoversSameSharedSecret() {
        MlKemService.KemResult result = service.encapsulate(bundle.kemPublicKey());
        byte[] recovered = service.decapsulate(bundle.kemPrivateKey(), result.encapsulation());
        assertArrayEquals(result.sharedSecret(), recovered,
                "Decapsulated secret must match the encapsulated secret");
    }

    @Test
    void encapsulate_producesNonEmptyOutputs() {
        MlKemService.KemResult result = service.encapsulate(bundle.kemPublicKey());
        assertNotNull(result.sharedSecret());
        assertNotNull(result.encapsulation());
        assertTrue(result.sharedSecret().length > 0);
        assertTrue(result.encapsulation().length > 0);
    }

    @Test
    void encapsulate_differentEncapsulationEachCall() {
        MlKemService.KemResult r1 = service.encapsulate(bundle.kemPublicKey());
        MlKemService.KemResult r2 = service.encapsulate(bundle.kemPublicKey());
        assertFalse(Arrays.equals(r1.encapsulation(), r2.encapsulation()),
                "Each encapsulation must use a fresh ephemeral key");
    }

    @Test
    void sharedSecretIsThirtyTwoBytes() {
        MlKemService.KemResult result = service.encapsulate(bundle.kemPublicKey());
        assertEquals(32, result.sharedSecret().length,
                "ML-KEM-1024 shared secret must be 32 bytes");
    }

    @Test
    void decapsulate_wrongPrivateKey_producesWrongSecret() {
        MlKemService.KemResult result = service.encapsulate(bundle.kemPublicKey());
        PqcKeyBundle otherBundle = new InMemoryKeyManager().generateKeys();
        byte[] wrongSecret = service.decapsulate(otherBundle.kemPrivateKey(), result.encapsulation());
        assertFalse(Arrays.equals(result.sharedSecret(), wrongSecret),
                "Decapsulation with wrong private key must not recover the correct secret");
    }
}
