package org.pqc.enframzero.keys;

import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Serialises and deserialises a {@link PqcKeyBundle} to/from a compact binary format.
 *
 * <p>Wire format — five length-prefixed fields in order:
 * <pre>
 *   [4-byte big-endian length][ML-KEM-1024 public key  (~1568 bytes)]
 *   [4-byte big-endian length][ML-KEM-1024 private key (~3168 bytes)]
 *   [4-byte big-endian length][ML-DSA-65   public key  (~1952 bytes)]
 *   [4-byte big-endian length][ML-DSA-65   private key (~4032 bytes)]
 *   [4-byte big-endian length][AES-256 DEK  (32 bytes)]
 * </pre>
 *
 * <p>The raw bytes are only meaningful when wrapped inside a
 * {@link KmsBlobKeyStore} envelope; never write them to disk unprotected.
 */
public final class KeyBundleSerializer {

    private KeyBundleSerializer() {}

    public static byte[] serialize(PqcKeyBundle bundle) {
        byte[] kemPub  = bundle.kemPublicKey().getEncoded();
        byte[] kemPriv = bundle.kemPrivateKey().getEncoded();
        byte[] dsaPub  = bundle.dsaPublicKey().getEncoded();
        byte[] dsaPriv = bundle.dsaPrivateKey().getEncoded();
        byte[] dek     = bundle.dataEncryptionKey();
        try {
            int total = 5 * 4 + kemPub.length + kemPriv.length
                    + dsaPub.length + dsaPriv.length + dek.length;
            ByteBuffer buf = ByteBuffer.allocate(total);
            writeField(buf, kemPub);
            writeField(buf, kemPriv);
            writeField(buf, dsaPub);
            writeField(buf, dsaPriv);
            writeField(buf, dek);
            return buf.array();
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    public static PqcKeyBundle deserialize(byte[] data) {
        ByteBuffer buf = ByteBuffer.wrap(data);
        byte[] kemPubBytes  = readField(buf);
        byte[] kemPrivBytes = readField(buf);
        byte[] dsaPubBytes  = readField(buf);
        byte[] dsaPrivBytes = readField(buf);
        byte[] dek          = readField(buf);
        try {
            return new PqcKeyBundle(
                    new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_1024, kemPubBytes),
                    new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_1024, kemPrivBytes),
                    new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, dsaPubBytes),
                    new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, dsaPrivBytes),
                    dek
            );
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    private static void writeField(ByteBuffer buf, byte[] field) {
        buf.putInt(field.length);
        buf.put(field);
    }

    private static byte[] readField(ByteBuffer buf) {
        int len = buf.getInt();
        byte[] field = new byte[len];
        buf.get(field);
        return field;
    }
}
