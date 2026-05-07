package org.pqc.enframzero.benchmark;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.pqc.enframzero.framework.PqcFrameworkImpl;
import org.pqc.enframzero.keys.*;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Map;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Cloud-facing benchmark suite measuring key management overhead, AWS KMS call latency,
 * and real DynamoDB operation latency (network included).
 *
 * Run with:
 *   PQC_TABLE_NAME=<table> PQC_KMS_KEY_ALIAS=<alias> \
 *     mvn test -Dtest.excludedGroups= -Dtest.groups=cloud-benchmark
 */
@Tag("cloud-benchmark")
public class CloudBenchmarkSuite {

    private static final String REGION   = "eu-central-1";
    private static final int    KM_WU   = 5;
    private static final int    KM_N    = 50;
    private static final int    KMS_WU  = 5;
    private static final int    KMS_N   = 20;
    private static final int    DB_WU   = 10;
    private static final int    DB_N    = 50;

    @FunctionalInterface interface Op { void run() throws Exception; }
    record StatsMs(double meanMs, double sdMs) {
        String fmt() { return String.format("%10.2f  %10.2f", meanMs, sdMs); }
    }
    record StatsUs(double meanUs, double sdUs) {
        String fmt() { return String.format("%10.1f  %10.1f", meanUs, sdUs); }
    }

    static StatsMs timeMs(int warmup, int measured, Op op) throws Exception {
        for (int i = 0; i < warmup; i++) op.run();
        long[] ns = new long[measured];
        for (int i = 0; i < measured; i++) {
            long t = System.nanoTime(); op.run(); ns[i] = System.nanoTime() - t;
        }
        double mean = Arrays.stream(ns).average().orElseThrow() / 1_000_000.0;
        double var  = Arrays.stream(ns)
                .mapToDouble(n -> { double d = n / 1_000_000.0 - mean; return d * d; })
                .average().orElseThrow();
        return new StatsMs(mean, Math.sqrt(var));
    }

    static StatsUs timeUs(int warmup, int measured, Op op) throws Exception {
        for (int i = 0; i < warmup; i++) op.run();
        long[] ns = new long[measured];
        for (int i = 0; i < measured; i++) {
            long t = System.nanoTime(); op.run(); ns[i] = System.nanoTime() - t;
        }
        double mean = Arrays.stream(ns).average().orElseThrow() / 1_000.0;
        double var  = Arrays.stream(ns)
                .mapToDouble(n -> { double d = n / 1_000.0 - mean; return d * d; })
                .average().orElseThrow();
        return new StatsUs(mean, Math.sqrt(var));
    }

    @Test
    void runAll() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("\n=== PQC EnFram Zero — Cloud Benchmark Report ===");
        System.out.printf("  Region   : %s%n", REGION);
        System.out.printf("  Platform : %s %s%n",
                System.getProperty("os.name"), System.getProperty("os.arch"));
        System.out.printf("  JVM      : %s%n%n", Runtime.version());

        benchKeyManagement();
        benchKms();
        benchDynamoDB();
    }

    // ── 1. Key management overhead ───────────────────────────────────────────

    void benchKeyManagement() throws Exception {
        System.out.printf("%n--- Key Management Overhead (n=%d, warmup=%d, µs) ---%n", KM_N, KM_WU);
        System.out.printf("  %-48s  %10s  %10s%n", "Operation", "Mean (µs)", "SD (µs)");
        System.out.println("  " + "-".repeat(72));

        System.out.printf("  %-48s  %s%n", "InMemoryKeyManager.generateKeys()",
                timeUs(KM_WU, KM_N, () -> new InMemoryKeyManager().generateKeys()).fmt());

        PqcKeyBundle bundle = new InMemoryKeyManager().generateKeys();

        System.out.printf("  %-48s  %s%n", "KeyBundleSerializer.serialize(~10 KB)",
                timeUs(20, 200, () -> KeyBundleSerializer.serialize(bundle)).fmt());

        byte[] serialized = KeyBundleSerializer.serialize(bundle);
        System.out.printf("  %-48s  %s%n", "KeyBundleSerializer.deserialize(~10 KB)",
                timeUs(20, 200, () -> KeyBundleSerializer.deserialize(serialized)).fmt());
    }

    // ── 2. AWS KMS call latency ──────────────────────────────────────────────

    void benchKms() throws Exception {
        String kmsAlias = System.getenv("PQC_KMS_KEY_ALIAS");
        assumeTrue(kmsAlias != null, "PQC_KMS_KEY_ALIAS not set — skipping KMS benchmarks");

        System.out.printf("%n--- AWS KMS Operations (n=%d, warmup=%d, ms) ---%n", KMS_N, KMS_WU);
        System.out.printf("  %-48s  %10s  %10s%n", "Operation", "Mean (ms)", "SD (ms)");
        System.out.println("  " + "-".repeat(72));

        try (KmsClient kms = KmsClient.builder().region(Region.of(REGION)).build()) {

            System.out.printf("  %-48s  %s%n", "KMS GenerateDataKey (AES-256)",
                    timeMs(KMS_WU, KMS_N, () ->
                            kms.generateDataKey(GenerateDataKeyRequest.builder()
                                    .keyId(kmsAlias)
                                    .keySpec(DataKeySpec.AES_256)
                                    .build())).fmt());

            GenerateDataKeyResponse dkResp = kms.generateDataKey(
                    GenerateDataKeyRequest.builder().keyId(kmsAlias).keySpec(DataKeySpec.AES_256).build());
            SdkBytes encryptedDek = dkResp.ciphertextBlob();

            System.out.printf("  %-48s  %s%n", "KMS Decrypt (recover DEK)",
                    timeMs(KMS_WU, KMS_N, () ->
                            kms.decrypt(DecryptRequest.builder()
                                    .ciphertextBlob(encryptedDek)
                                    .build())).fmt());
        }
    }

    // ── 3. Real DynamoDB operations (with network) ───────────────────────────

    void benchDynamoDB() throws Exception {
        String tableName = System.getenv("PQC_TABLE_NAME");
        assumeTrue(tableName != null, "PQC_TABLE_NAME not set — skipping DynamoDB benchmarks");

        System.out.printf("%n--- Real DynamoDB Operations (n=%d, warmup=%d, ms) ---%n", DB_N, DB_WU);
        System.out.printf("  %-48s  %10s  %10s%n", "Operation", "Mean (ms)", "SD (ms)");
        System.out.println("  " + "-".repeat(72));

        SecureRandom rng = new SecureRandom();

        try (DynamoDbClient dynamo = DynamoDbClient.builder().region(Region.of(REGION)).build()) {

            // ── Unencrypted baseline ──
            String baselineKey = "cloud-bench-baseline";
            Map<String, AttributeValue> baselineItem = Map.of(
                    "pk", AttributeValue.fromS(baselineKey),
                    "v",  AttributeValue.fromS("a".repeat(256))
            );

            System.out.printf("  %-48s  %s%n", "PutItem baseline (unencrypted, 256 B value)",
                    timeMs(DB_WU, DB_N, () ->
                            dynamo.putItem(PutItemRequest.builder()
                                    .tableName(tableName).item(baselineItem).build())).fmt());

            System.out.printf("  %-48s  %s%n", "GetItem baseline (unencrypted)",
                    timeMs(DB_WU, DB_N, () ->
                            dynamo.getItem(GetItemRequest.builder()
                                    .tableName(tableName)
                                    .key(Map.of("pk", AttributeValue.fromS(baselineKey)))
                                    .build())).fmt());

            dynamo.deleteItem(DeleteItemRequest.builder()
                    .tableName(tableName)
                    .key(Map.of("pk", AttributeValue.fromS(baselineKey)))
                    .build());
        }

        // ── Encrypted framework operations ──
        PqcFrameworkImpl fw = PqcFrameworkImpl.create(tableName, REGION);
        byte[] value256 = new byte[256];
        rng.nextBytes(value256);
        String getKey = "cloud-bench-get";

        for (int i = 0; i < DB_WU; i++) {
            fw.put("cloud-bench-wu-" + i, value256);
            fw.get("cloud-bench-wu-" + i);
        }

        System.out.printf("  %-48s  %s%n", "Framework put() 256 B (encrypted, real DynamoDB)",
                timeMs(0, DB_N, () -> fw.put("cloud-bench-" + rng.nextLong(), value256)).fmt());

        fw.put(getKey, value256);
        System.out.printf("  %-48s  %s%n", "Framework get() 256 B (encrypted, real DynamoDB)",
                timeMs(0, DB_N, () -> fw.get(getKey)).fmt());
    }
}
