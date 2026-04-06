package org.pqc.enframzero.crypto;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * ML-DSA (CRYSTALS-Dilithium) digital signature service for integrity protection.
 */
public interface MlDsaService {

    /**
     * Signs the message with the ML-DSA private key.
     */
    byte[] sign(byte[] message, MLDSAPrivateKeyParameters privateKey);

    /**
     * Verifies the signature over the message using the ML-DSA public key.
     */
    boolean verify(byte[] message, byte[] signature, MLDSAPublicKeyParameters publicKey);
}
