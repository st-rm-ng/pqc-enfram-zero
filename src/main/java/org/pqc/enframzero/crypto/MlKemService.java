package org.pqc.enframzero.crypto;

import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

/**
 * ML-KEM (CRYSTALS-Kyber) key encapsulation mechanism for data-in-transit security.
 * Each call to {@link #encapsulate} generates a fresh ephemeral shared secret.
 */
public interface MlKemService {

    /**
     * Generates an ephemeral shared secret and its encapsulation for the recipient's public key.
     * The shared secret must be used immediately and never stored.
     */
    KemResult encapsulate(MLKEMPublicKeyParameters recipientPublicKey);

    /**
     * Recovers the shared secret from the encapsulation ciphertext using the private key.
     */
    byte[] decapsulate(MLKEMPrivateKeyParameters privateKey, byte[] encapsulation);

    record KemResult(byte[] sharedSecret, byte[] encapsulation) {}
}
