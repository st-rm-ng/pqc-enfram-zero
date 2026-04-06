package org.pqc.enframzero.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public class AesGcmServiceImpl implements AesGcmService {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final SecureRandom rng = new SecureRandom();

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] key) {
        try {
            byte[] iv = new byte[CryptoConstants.AES_GCM_IV_BYTES];
            rng.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CryptoConstants.AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(CryptoConstants.AES_GCM_TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] result = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
            return result;
        } catch (Exception e) {
            throw new CryptoException("AES-GCM encryption failed", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] ivAndCiphertext, byte[] key) {
        try {
            byte[] iv = Arrays.copyOfRange(ivAndCiphertext, 0, CryptoConstants.AES_GCM_IV_BYTES);
            byte[] ciphertext = Arrays.copyOfRange(ivAndCiphertext, CryptoConstants.AES_GCM_IV_BYTES, ivAndCiphertext.length);

            Cipher cipher = Cipher.getInstance(CryptoConstants.AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(CryptoConstants.AES_GCM_TAG_BITS, iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CryptoException("AES-GCM decryption failed", e);
        }
    }
}
