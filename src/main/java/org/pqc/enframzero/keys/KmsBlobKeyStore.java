package org.pqc.enframzero.keys;

import org.pqc.enframzero.crypto.AesGcmService;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Persists a {@link PqcKeyBundle} as a KMS-encrypted blob on the local filesystem.
 *
 * <h3>Envelope encryption design</h3>
 * <p>The serialised key bundle (~10 KB) exceeds the KMS 4 KB direct-encrypt limit,
 * so we use standard envelope encryption:
 * <ol>
 *   <li>{@code GenerateDataKey} — KMS returns a one-time AES-256 data key (DEK)
 *       in both plaintext and KMS-ciphertext form.</li>
 *   <li>AES-256-GCM encrypt the serialised bundle with the plaintext DEK.</li>
 *   <li>Write blob: {@code [4-byte DEK-ciphertext length][DEK ciphertext][IV||ciphertext||tag]}</li>
 *   <li>Zero the plaintext DEK immediately after use.</li>
 * </ol>
 *
 * <p>On {@link #load}: read the DEK ciphertext, call {@code kms:Decrypt}, then
 * AES-GCM decrypt the bundle ciphertext. The plaintext DEK never touches disk.
 *
 * <h3>Usage</h3>
 * <pre>
 *   KmsBlobKeyStore store = KmsBlobKeyStore.create("eu-central-1");
 *   store.save(bundle, Path.of("keystore.enc"), "alias/pqc-keystore-dev");
 *   PqcKeyBundle loaded = store.load(Path.of("keystore.enc"));
 * </pre>
 */
public class KmsBlobKeyStore {

    private final KmsClient kms;
    private final AesGcmService aesGcm;

    public KmsBlobKeyStore(KmsClient kms, AesGcmService aesGcm) {
        this.kms    = kms;
        this.aesGcm = aesGcm;
    }

    public static KmsBlobKeyStore create(String region, AesGcmService aesGcm) {
        KmsClient kms = KmsClient.builder()
                .region(Region.of(region))
                .build();
        return new KmsBlobKeyStore(kms, aesGcm);
    }

    /**
     * Serialises {@code bundle}, encrypts it with a fresh KMS data key, and writes
     * the resulting blob to {@code blobPath}.
     *
     * @param bundle    key material to persist
     * @param blobPath  destination file (created or overwritten)
     * @param kmsKeyId  KMS key ID or alias (e.g. {@code "alias/pqc-keystore-dev"})
     */
    public void save(PqcKeyBundle bundle, Path blobPath, String kmsKeyId) throws IOException {
        // 1. Ask KMS for a one-time AES-256 data key
        GenerateDataKeyResponse dkResp = kms.generateDataKey(GenerateDataKeyRequest.builder()
                .keyId(kmsKeyId)
                .keySpec(DataKeySpec.AES_256)
                .build());

        byte[] plaintextDek    = dkResp.plaintext().asByteArray();
        byte[] encryptedDek    = dkResp.ciphertextBlob().asByteArray();

        try {
            // 2. AES-GCM encrypt the serialised bundle with the plaintext DEK
            byte[] plainBundle      = KeyBundleSerializer.serialize(bundle);
            byte[] encryptedBundle  = aesGcm.encrypt(plainBundle, plaintextDek);
            Arrays.fill(plainBundle, (byte) 0);

            // 3. Write blob: [4-byte enc-DEK length][enc-DEK][enc-bundle]
            byte[] blob = ByteBuffer.allocate(4 + encryptedDek.length + encryptedBundle.length)
                    .putInt(encryptedDek.length)
                    .put(encryptedDek)
                    .put(encryptedBundle)
                    .array();

            Files.createDirectories(blobPath.getParent() == null ? Path.of(".") : blobPath.getParent());
            Files.write(blobPath, blob);
        } finally {
            Arrays.fill(plaintextDek, (byte) 0);
        }
    }

    /**
     * Reads the blob from {@code blobPath}, decrypts the envelope DEK via KMS,
     * and returns the reconstructed {@link PqcKeyBundle}.
     */
    public PqcKeyBundle load(Path blobPath) throws IOException {
        byte[] blob = Files.readAllBytes(blobPath);
        ByteBuffer buf = ByteBuffer.wrap(blob);

        // 1. Read the KMS-encrypted DEK
        int dekLen = buf.getInt();
        byte[] encryptedDek = new byte[dekLen];
        buf.get(encryptedDek);

        // 2. Read the AES-GCM encrypted bundle
        byte[] encryptedBundle = new byte[buf.remaining()];
        buf.get(encryptedBundle);

        // 3. Decrypt the DEK via KMS
        DecryptResponse decResp = kms.decrypt(DecryptRequest.builder()
                .ciphertextBlob(SdkBytes.fromByteArray(encryptedDek))
                .build());
        byte[] plaintextDek = decResp.plaintext().asByteArray();

        try {
            // 4. AES-GCM decrypt the bundle and deserialise
            byte[] plainBundle = aesGcm.decrypt(encryptedBundle, plaintextDek);
            try {
                return KeyBundleSerializer.deserialize(plainBundle);
            } finally {
                Arrays.fill(plainBundle, (byte) 0);
            }
        } finally {
            Arrays.fill(plaintextDek, (byte) 0);
        }
    }
}
