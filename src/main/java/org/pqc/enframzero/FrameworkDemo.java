package org.pqc.enframzero;

import org.pqc.enframzero.crypto.AesGcmServiceImpl;
import org.pqc.enframzero.crypto.MlDsaServiceImpl;
import org.pqc.enframzero.framework.IntegrityException;
import org.pqc.enframzero.framework.PqcFrameworkImpl;
import org.pqc.enframzero.keys.InMemoryKeyManager;
import org.pqc.enframzero.keys.KmsBlobKeyStore;
import org.pqc.enframzero.keys.PqcKeyBundle;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * End-to-end demonstration of the PQC EnFram Zero framework against a live DynamoDB table,
 * including key persistence via KMS-encrypted blob.
 *
 * <p>Scenarios:
 * <ol>
 *   <li>Bootstrap — ML-KEM-1024 + ML-DSA-65 + AES-256 key generation</li>
 *   <li>put() — two-layer onion encryption (AES-GCM at-rest + ML-KEM in-transit)</li>
 *   <li>Raw scan — DynamoDB holds only opaque ciphertexts, never plaintext</li>
 *   <li>get() — signature verified, both layers decrypted, plaintext recovered</li>
 *   <li>Overwrite — same key, different value, fresh ephemeral ML-KEM keys</li>
 *   <li>Delete — entry removed from DynamoDB</li>
 *   <li>Tamper — corrupted payload triggers IntegrityException on get()</li>
 *   <li>Persistence — key bundle saved as KMS-encrypted blob; reloaded after simulated restart</li>
 * </ol>
 */
public class FrameworkDemo {

    private static final String TABLE         = "pqc-items-dev";
    private static final String REGION        = "eu-central-1";
    private static final String KMS_KEY_ALIAS = "alias/pqc-keystore-dev";
    private static final Path   BLOB_PATH     = Path.of("pqc-keystore.enc");

    public static void main(String[] args) throws Exception {
        banner();

        DynamoDbClient rawClient = DynamoDbClient.builder()
                .region(Region.of(REGION))
                .build();

        KmsBlobKeyStore keyStore = KmsBlobKeyStore.create(REGION, new AesGcmServiceImpl());

        // ── 1. Bootstrap ────────────────────────────────────────────────────
        section("1. Key Generation");

        System.out.println("  Generating PQC key bundle in-memory:");
        System.out.println("    ML-KEM-1024  (NIST Level 5) — ephemeral transit-key encapsulation");
        System.out.println("    ML-DSA-65    (NIST Level 3) — digital signature for integrity");
        System.out.println("    AES-256 DEK                 — at-rest value encryption");

        long t0 = System.currentTimeMillis();
        PqcKeyBundle bundle = new InMemoryKeyManager().generateKeys();
        PqcFrameworkImpl framework = PqcFrameworkImpl.create(TABLE, REGION, bundle);
        System.out.printf("  Key generation: %d ms%n", System.currentTimeMillis() - t0);

        // ── 2. put() ────────────────────────────────────────────────────────
        section("2. Storing Encrypted Entries");

        String key1 = "user:alice";
        String val1 = "{ \"role\": \"admin\", \"clearance\": \"TOP_SECRET\", \"token\": \"abc-123\" }";
        printKv("  Storing", key1, val1);
        t0 = System.currentTimeMillis();
        framework.putString(key1, val1);
        System.out.printf("  put() latency: %d ms%n%n", System.currentTimeMillis() - t0);

        String key2 = "config:db-password";
        String val2 = "s3cur3-p@ssw0rd-2026";
        printKv("  Storing", key2, val2);
        t0 = System.currentTimeMillis();
        framework.putString(key2, val2);
        System.out.printf("  put() latency: %d ms%n", System.currentTimeMillis() - t0);

        // ── 3. Raw DynamoDB scan ─────────────────────────────────────────────
        section("3. Raw DynamoDB Contents");

        ScanResponse scan = rawClient.scan(ScanRequest.builder().tableName(TABLE).build());
        System.out.printf("  Items in table: %d%n%n", scan.count());
        for (Map<String, AttributeValue> item : scan.items()) {
            System.out.printf("  pk      : %s%n", item.get("pk").s());
            System.out.printf("  kem     : %d bytes  (ML-KEM-1024 encapsulation)%n",
                    item.get("kem").b().asByteArray().length);
            System.out.printf("  payload : %d bytes  (AES-GCM, transit layer)%n",
                    item.get("payload").b().asByteArray().length);
            System.out.printf("  sig     : %d bytes  (ML-DSA-65 signature)%n",
                    item.get("sig").b().asByteArray().length);
            System.out.println("  ---");
        }

        // ── 4. get() ────────────────────────────────────────────────────────
        section("4. Retrieving and Decrypting");

        t0 = System.currentTimeMillis();
        Optional<String> got1 = framework.getString(key1);
        System.out.printf("  get(\"%s\")%n", key1);
        System.out.printf("    value   : %s%n", got1.orElse("<empty>"));
        System.out.printf("    correct : %b   (%d ms)%n%n", got1.map(val1::equals).orElse(false), System.currentTimeMillis() - t0);

        t0 = System.currentTimeMillis();
        Optional<String> got2 = framework.getString(key2);
        System.out.printf("  get(\"%s\")%n", key2);
        System.out.printf("    value   : %s%n", got2.orElse("<empty>"));
        System.out.printf("    correct : %b   (%d ms)%n", got2.map(val2::equals).orElse(false), System.currentTimeMillis() - t0);

        // ── 5. Overwrite ─────────────────────────────────────────────────────
        section("5. Overwrite (fresh ephemeral ML-KEM keys per write)");

        String val1v2 = "{ \"role\": \"readonly\", \"clearance\": \"STANDARD\" }";
        System.out.printf("  Overwriting \"%s\"%n  old: %s%n  new: %s%n", key1, val1, val1v2);
        framework.putString(key1, val1v2);
        Optional<String> gotOverwrite = framework.getString(key1);
        System.out.printf("  Decrypted : %s%n", gotOverwrite.orElse("<empty>"));
        System.out.printf("  Correct   : %b%n", gotOverwrite.map(val1v2::equals).orElse(false));
        // DynamoDB pk is unchanged — HMAC is deterministic; only ciphertext replaced

        // ── 6. Delete ─────────────────────────────────────────────────────────
        section("6. Delete");

        System.out.printf("  Deleting \"%s\"%n", key2);
        framework.delete(key2);
        Optional<String> afterDelete = framework.getString(key2);
        System.out.printf("  get() after delete: %s%n", afterDelete.map(s -> "\"" + s + "\"").orElse("<empty>"));

        // ── 7. Tamper detection ───────────────────────────────────────────────
        section("7. Tamper Detection (ML-DSA-65 Integrity)");

        String tamperKey = "tamper:test";

        Set<String> pksBefore = rawClient.scan(ScanRequest.builder().tableName(TABLE).build())
                .items().stream()
                .map(i -> i.get("pk").s())
                .collect(Collectors.toSet());

        framework.putString(tamperKey, "legitimate-data");
        System.out.printf("  Stored \"%s\" = \"legitimate-data\"%n", tamperKey);

        ScanResponse scanAfter = rawClient.scan(ScanRequest.builder().tableName(TABLE).build());
        Map<String, AttributeValue> tamperItem = scanAfter.items().stream()
                .filter(i -> !pksBefore.contains(i.get("pk").s()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Tamper item not found in scan"));

        String tamperPk = tamperItem.get("pk").s();
        byte[] originalPayload = tamperItem.get("payload").b().asByteArray();
        byte[] corrupted = Arrays.copyOf(originalPayload, originalPayload.length);
        corrupted[20] ^= (byte) 0xFF;

        rawClient.putItem(PutItemRequest.builder()
                .tableName(TABLE)
                .item(Map.of(
                        "pk",      AttributeValue.fromS(tamperPk),
                        "kem",     tamperItem.get("kem"),
                        "payload", AttributeValue.fromB(SdkBytes.fromByteArray(corrupted)),
                        "sig",     tamperItem.get("sig")
                ))
                .build());
        System.out.println("  Payload corrupted in DynamoDB (1 byte flipped at offset 20)");

        try {
            framework.getString(tamperKey);
            System.out.println("  ERROR: expected IntegrityException was NOT thrown!");
        } catch (IntegrityException e) {
            System.out.println("  IntegrityException: " + e.getMessage());
            System.out.println("  Tamper detected correctly — ML-DSA signature mismatch.");

            // Original signature — computed during put() over (encapsulation ‖ originalPayload)
            byte[] originalSig = tamperItem.get("sig").b().asByteArray();

            // Re-sign the corrupted payload to produce a "wrong" signature for comparison
            byte[] kem = tamperItem.get("kem").b().asByteArray();
            byte[] signInputCorrupted = new byte[kem.length + corrupted.length];
            System.arraycopy(kem, 0, signInputCorrupted, 0, kem.length);
            System.arraycopy(corrupted, 0, signInputCorrupted, kem.length, corrupted.length);
            byte[] corruptedSig = new MlDsaServiceImpl().sign(signInputCorrupted, bundle.dsaPrivateKey());

            System.out.printf("  Original signature : %s... (%d bytes)%n", toHex(originalSig, 16), originalSig.length);
            System.out.printf("  Corrupted signature: %s... (%d bytes)%n", toHex(corruptedSig, 16), corruptedSig.length);
        }

        // ── 8. Key Persistence ───────────────────────────────────────────────
        section("8. Key Persistence (KMS-encrypted blob)");

        // 8a. Save the key bundle to an encrypted blob
        System.out.printf("  Saving key bundle to: %s%n", BLOB_PATH.toAbsolutePath());
        System.out.printf("  KMS key alias       : %s%n", KMS_KEY_ALIAS);
        t0 = System.currentTimeMillis();
        keyStore.save(bundle, BLOB_PATH, KMS_KEY_ALIAS);
        System.out.printf("  save() latency      : %d ms%n", System.currentTimeMillis() - t0);
        System.out.printf("  Blob size on disk   : %d bytes (encrypted DEK + AES-GCM bundle)%n", BLOB_PATH.toFile().length());

        // 8b. Destroy the in-memory bundle to simulate a JVM restart
        bundle.destroy();
        System.out.println("\n  [simulating JVM restart — in-memory keys destroyed]");

        // 8c. Reload from the blob
        System.out.printf("%n  Loading key bundle from blob via KMS...%n");
        t0 = System.currentTimeMillis();
        PqcKeyBundle restoredBundle = keyStore.load(BLOB_PATH);
        PqcFrameworkImpl restoredFramework = PqcFrameworkImpl.create(TABLE, REGION, restoredBundle);
        System.out.printf("  load() latency : %d ms%n", System.currentTimeMillis() - t0);

        // 8d. Read back data written before the "restart" — proves key round-trip
        Optional<String> afterRestore = restoredFramework.getString(key1);
        System.out.printf("%n  get(\"%s\") with restored keys:%n", key1);
        System.out.printf("    value   : %s%n", afterRestore.orElse("<empty>"));
        System.out.printf("    correct : %b%n", afterRestore.map(val1v2::equals).orElse(false));
        System.out.println("  Data written before the restart is fully readable with the restored bundle.");

        // ── Cleanup ─────────────────────────────────────────────────────────
        section("Cleanup");

        restoredFramework.delete(key1);
        rawClient.deleteItem(DeleteItemRequest.builder()
                .tableName(TABLE)
                .key(Map.of("pk", AttributeValue.fromS(tamperPk)))
                .build());
        BLOB_PATH.toFile().delete();
        ScanResponse finalScan = rawClient.scan(ScanRequest.builder().tableName(TABLE).build());
        System.out.printf("  Table items after cleanup: %d%n", finalScan.count());

        rawClient.close();
        System.out.println("\nDemo complete.");
        System.exit(0);
    }

    private static void banner() {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║   PQC EnFram Zero — Post-Quantum Encryption Framework Demo   ║");
        System.out.println("║   ML-KEM-1024 (transit) · ML-DSA-65 (integrity) · AES-256    ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.printf("  Table  : %s%n", TABLE);
        System.out.printf("  Region : %s%n%n", REGION);
    }

    private static void section(String title) {
        System.out.printf("%n── %s %s%n", title, "─".repeat(Math.max(0, 57 - title.length())));
    }

    private static void printKv(String prefix, String key, String value) {
        System.out.printf("%s key=\"%s\" value=\"%s\"%n", prefix, key, value);
    }

    private static String toHex(byte[] bytes, int len) {
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = 0; i < Math.min(len, bytes.length); i++) {
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }
}
