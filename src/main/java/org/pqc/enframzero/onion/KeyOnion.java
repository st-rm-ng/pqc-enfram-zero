package org.pqc.enframzero.onion;

import org.pqc.enframzero.crypto.AesGcmService;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Transforms a plaintext DynamoDB key into the form stored on the server.
 *
 * <p>DET layer: HMAC-SHA256(DEK, plainKey) — deterministic, enables exact GetItem lookups.
 * The server learns only that the same logical key was accessed, not its content.
 *
 * <p>RND layer: AES-GCM(DEK, plainKey) — fully opaque, for scan-only access patterns.
 */
public class KeyOnion {

    private final AesGcmService aesGcm;

    public KeyOnion(AesGcmService aesGcm) {
        this.aesGcm = aesGcm;
    }

    /**
     * Applies the given onion layer to transform the plaintext key.
     *
     * @param plainKey  the logical key (plaintext)
     * @param dataKey   the 256-bit AES data encryption key
     * @param layer     the target onion layer
     * @return the transformed key as a Base64URL-encoded string
     */
    public String apply(String plainKey, byte[] dataKey, OnionLayer layer) {
        return switch (layer) {
            case PLAIN -> plainKey;
            case DET -> deterministicHash(plainKey, dataKey);
            case RND -> randomEncrypt(plainKey, dataKey);
        };
    }

    private String deterministicHash(String key, byte[] dataKey) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(dataKey, "HmacSHA256"));
            byte[] hash = mac.doFinal(key.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 key derivation failed", e);
        }
    }

    private String randomEncrypt(String key, byte[] dataKey) {
        byte[] encrypted = aesGcm.encrypt(key.getBytes(StandardCharsets.UTF_8), dataKey);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encrypted);
    }
}
