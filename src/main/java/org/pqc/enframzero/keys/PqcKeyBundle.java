package org.pqc.enframzero.keys;

import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

import java.util.Arrays;

/**
 * Immutable container for all client-side key material.
 * Keys exist only in memory and must never be serialised or transmitted.
 * Call {@link #destroy()} when done to zero sensitive key bytes.
 */
public final class PqcKeyBundle implements AutoCloseable {

    private final MLKEMPublicKeyParameters kemPublicKey;
    private final MLKEMPrivateKeyParameters kemPrivateKey;
    private final MLDSAPublicKeyParameters dsaPublicKey;
    private final MLDSAPrivateKeyParameters dsaPrivateKey;
    private final byte[] dataEncryptionKey;

    public PqcKeyBundle(
            MLKEMPublicKeyParameters kemPublicKey,
            MLKEMPrivateKeyParameters kemPrivateKey,
            MLDSAPublicKeyParameters dsaPublicKey,
            MLDSAPrivateKeyParameters dsaPrivateKey,
            byte[] dataEncryptionKey) {
        this.kemPublicKey = kemPublicKey;
        this.kemPrivateKey = kemPrivateKey;
        this.dsaPublicKey = dsaPublicKey;
        this.dsaPrivateKey = dsaPrivateKey;
        this.dataEncryptionKey = dataEncryptionKey.clone();
    }

    public MLKEMPublicKeyParameters kemPublicKey() { return kemPublicKey; }
    public MLKEMPrivateKeyParameters kemPrivateKey() { return kemPrivateKey; }
    public MLDSAPublicKeyParameters dsaPublicKey() { return dsaPublicKey; }
    public MLDSAPrivateKeyParameters dsaPrivateKey() { return dsaPrivateKey; }

    /** Returns a defensive copy of the 32-byte AES-256 data encryption key. */
    public byte[] dataEncryptionKey() { return dataEncryptionKey.clone(); }

    /** Zeros the data encryption key bytes held in this bundle. */
    public void destroy() {
        Arrays.fill(dataEncryptionKey, (byte) 0);
    }

    @Override
    public void close() {
        destroy();
    }
}
