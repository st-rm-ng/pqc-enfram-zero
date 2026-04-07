package org.pqc.enframzero.keys;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.pqc.enframzero.crypto.AesGcmServiceImpl;
import org.pqc.enframzero.framework.PqcFramework;
import org.pqc.enframzero.framework.PqcFrameworkImpl;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for {@link KmsBlobKeyStore} against live AWS KMS.
 *
 * <p>Requires:
 * <ul>
 *   <li>{@code PQC_TABLE_NAME} — DynamoDB table name (e.g. {@code pqc-items-dev})</li>
 *   <li>{@code PQC_KMS_KEY_ALIAS} — KMS key alias (e.g. {@code alias/pqc-keystore-dev})</li>
 *   <li>AWS credentials configured via the default credential provider chain</li>
 * </ul>
 *
 * <p>Run with:
 * <pre>
 *   PQC_TABLE_NAME=pqc-items-dev PQC_KMS_KEY_ALIAS=alias/pqc-keystore-dev \
 *     mvn test -Dgroups=integration
 * </pre>
 */
@Tag("integration")
class KmsBlobKeyStoreIntegrationTest {

    private static final String REGION = "eu-central-1";

    private static String tableName() {
        String v = System.getenv("PQC_TABLE_NAME");
        assertNotNull(v, "PQC_TABLE_NAME environment variable must be set");
        return v;
    }

    private static String kmsKeyAlias() {
        String v = System.getenv("PQC_KMS_KEY_ALIAS");
        assertNotNull(v, "PQC_KMS_KEY_ALIAS environment variable must be set");
        return v;
    }

    @Test
    void saveAndLoad_roundTrip_preservesAllKeyComponents(@TempDir Path tmpDir) throws Exception {
        KmsBlobKeyStore store = KmsBlobKeyStore.create(REGION, new AesGcmServiceImpl());
        Path blobPath = tmpDir.resolve("keystore.enc");

        PqcKeyBundle original = new InMemoryKeyManager().generateKeys();
        byte[] kemPub  = original.kemPublicKey().getEncoded();
        byte[] kemPriv = original.kemPrivateKey().getEncoded();
        byte[] dsaPub  = original.dsaPublicKey().getEncoded();
        byte[] dsaPriv = original.dsaPrivateKey().getEncoded();
        byte[] dek     = original.dataEncryptionKey();

        store.save(original, blobPath, kmsKeyAlias());
        assertTrue(blobPath.toFile().exists());
        assertTrue(blobPath.toFile().length() > 0);

        PqcKeyBundle restored = store.load(blobPath);

        assertArrayEquals(kemPub,  restored.kemPublicKey().getEncoded(),  "ML-KEM public key mismatch");
        assertArrayEquals(kemPriv, restored.kemPrivateKey().getEncoded(), "ML-KEM private key mismatch");
        assertArrayEquals(dsaPub,  restored.dsaPublicKey().getEncoded(),  "ML-DSA public key mismatch");
        assertArrayEquals(dsaPriv, restored.dsaPrivateKey().getEncoded(), "ML-DSA private key mismatch");
        assertArrayEquals(dek,     restored.dataEncryptionKey(),          "AES DEK mismatch");
    }

    @Test
    void loadedBundle_canReadDataWrittenWithOriginalBundle(@TempDir Path tmpDir) throws Exception {
        KmsBlobKeyStore store = KmsBlobKeyStore.create(REGION, new AesGcmServiceImpl());
        Path blobPath = tmpDir.resolve("keystore.enc");
        String table = tableName();
        String kmsAlias = kmsKeyAlias();

        // Write data using a fresh bundle
        PqcKeyBundle original = new InMemoryKeyManager().generateKeys();
        PqcFramework fwWrite = PqcFrameworkImpl.create(table, REGION, original);

        String key   = "kms-integration-" + System.currentTimeMillis();
        String value = "persisted-across-restart";
        fwWrite.putString(key, value);

        // Save the bundle, then reload it (simulates JVM restart)
        store.save(original, blobPath, kmsAlias);
        original.destroy();

        PqcKeyBundle restored = store.load(blobPath);
        PqcFramework fwRead = PqcFrameworkImpl.create(table, REGION, restored);

        assertEquals(value, fwRead.getString(key).orElseThrow());

        // Cleanup
        fwRead.delete(key);
        assertTrue(fwRead.getString(key).isEmpty());
    }
}
