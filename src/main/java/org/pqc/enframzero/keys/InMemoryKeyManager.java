package org.pqc.enframzero.keys;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

import java.security.SecureRandom;

/**
 * Generates and holds key material exclusively in JVM heap memory.
 * Keys are never written to disk or transmitted.
 */
public class InMemoryKeyManager implements PqcKeyManager {

    @Override
    public PqcKeyBundle generateKeys() {
        SecureRandom rng = new SecureRandom();

        // ML-KEM-1024: NIST security level 5 (quantum security ≥ AES-256)
        MLKEMKeyPairGenerator kemGen = new MLKEMKeyPairGenerator();
        kemGen.init(new MLKEMKeyGenerationParameters(rng, MLKEMParameters.ml_kem_1024));
        AsymmetricCipherKeyPair kemPair = kemGen.generateKeyPair();

        // ML-DSA-65: NIST security level 3
        MLDSAKeyPairGenerator dsaGen = new MLDSAKeyPairGenerator();
        dsaGen.init(new MLDSAKeyGenerationParameters(rng, MLDSAParameters.ml_dsa_65));
        AsymmetricCipherKeyPair dsaPair = dsaGen.generateKeyPair();

        // 256-bit AES data encryption key for at-rest encryption
        byte[] dataKey = new byte[32];
        rng.nextBytes(dataKey);

        return new PqcKeyBundle(
                (MLKEMPublicKeyParameters) kemPair.getPublic(),
                (MLKEMPrivateKeyParameters) kemPair.getPrivate(),
                (MLDSAPublicKeyParameters) dsaPair.getPublic(),
                (MLDSAPrivateKeyParameters) dsaPair.getPrivate(),
                dataKey
        );
    }
}
