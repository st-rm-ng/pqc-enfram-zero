package org.pqc.enframzero.crypto;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

public class MlDsaServiceImpl implements MlDsaService {

    @Override
    public byte[] sign(byte[] message, MLDSAPrivateKeyParameters privateKey) {
        try {
            MLDSASigner signer = new MLDSASigner();
            signer.init(true, privateKey);
            signer.update(message, 0, message.length);
            return signer.generateSignature();
        } catch (Exception e) {
            throw new CryptoException("ML-DSA signing failed", e);
        }
    }

    @Override
    public boolean verify(byte[] message, byte[] signature, MLDSAPublicKeyParameters publicKey) {
        try {
            MLDSASigner verifier = new MLDSASigner();
            verifier.init(false, publicKey);
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(signature);
        } catch (Exception e) {
            throw new CryptoException("ML-DSA verification failed", e);
        }
    }
}
