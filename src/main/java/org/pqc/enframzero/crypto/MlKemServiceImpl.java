package org.pqc.enframzero.crypto;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import java.security.SecureRandom;

public class MlKemServiceImpl implements MlKemService {

    private final SecureRandom rng = new SecureRandom();

    @Override
    public KemResult encapsulate(MLKEMPublicKeyParameters recipientPublicKey) {
        try {
            MLKEMGenerator generator = new MLKEMGenerator(rng);
            SecretWithEncapsulation result = generator.generateEncapsulated(recipientPublicKey);
            byte[] sharedSecret = result.getSecret().clone();
            byte[] encapsulation = result.getEncapsulation().clone();
            result.destroy();
            return new KemResult(sharedSecret, encapsulation);
        } catch (Exception e) {
            throw new CryptoException("ML-KEM encapsulation failed", e);
        }
    }

    @Override
    public byte[] decapsulate(MLKEMPrivateKeyParameters privateKey, byte[] encapsulation) {
        try {
            MLKEMExtractor extractor = new MLKEMExtractor(privateKey);
            return extractor.extractSecret(encapsulation);
        } catch (Exception e) {
            throw new CryptoException("ML-KEM decapsulation failed", e);
        }
    }
}
