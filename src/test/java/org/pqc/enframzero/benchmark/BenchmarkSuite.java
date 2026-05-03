package org.pqc.enframzero.benchmark;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.mlkem.*;
import org.bouncycastle.pqc.crypto.mldsa.*;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.pqc.enframzero.crypto.*;
import org.pqc.enframzero.framework.PqcFrameworkImpl;
import org.pqc.enframzero.keys.*;
import org.pqc.enframzero.onion.KeyOnion;
import org.pqc.enframzero.onion.OnionLayer;
import org.pqc.enframzero.onion.ValueOnion;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

/**
 * Benchmark suite measuring: cryptographic primitive latency, classical comparison,
 * full framework operation latency (crypto-only, in-memory store), and storage overhead.
 *
 * Run with:
 *   mvn test -Dtest.excludedGroups= -Dtest.groups=benchmark
 */
@Tag("benchmark")
public class BenchmarkSuite {

    private static final int WARMUP          = 200;
    private static final int MEASURED        = 1000;
    private static final int FW_WARMUP       = 50;
    private static final int FW_MEASURED     = 500;

    // ── timing infrastructure ────────────────────────────────────────────────

    @FunctionalInterface interface Op { void run() throws Exception; }

    record Stats(double meanUs, double sdUs) {
        String fmt() { return String.format("%10.1f  %10.1f", meanUs, sdUs); }
    }

    static Stats time(int warmup, int measured, Op op) throws Exception {
        for (int i = 0; i < warmup; i++) op.run();
        long[] ns = new long[measured];
        for (int i = 0; i < measured; i++) {
            long t = System.nanoTime();
            op.run();
            ns[i] = System.nanoTime() - t;
        }
        double mean = Arrays.stream(ns).average().orElseThrow() / 1_000.0;
        double var  = Arrays.stream(ns)
                .mapToDouble(n -> { double d = n / 1_000.0 - mean; return d * d; })
                .average().orElseThrow();
        return new Stats(mean, Math.sqrt(var));
    }

    static void header(String title) {
        System.out.printf("%n--- %s (n=%d, warmup=%d) ---%n", title, MEASURED, WARMUP);
        System.out.printf("  %-42s  %10s  %10s%n", "Operation", "Mean (µs)", "SD (µs)");
        System.out.println("  " + "-".repeat(66));
    }

    static void row(String label, Stats s) {
        System.out.printf("  %-42s  %s%n", label, s.fmt());
    }

    // ── main test entry point ────────────────────────────────────────────────

    @Test
    void runAll() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("\n=== PQC EnFram Zero — Benchmark Report ===");
        System.out.printf("  Platform : %s %s%n",
                System.getProperty("os.name"), System.getProperty("os.arch"));
        System.out.printf("  JVM      : %s%n", Runtime.version());
        System.out.printf("  n        : %d iterations, %d warmup%n%n", MEASURED, WARMUP);

        benchPrimitives();
        benchClassical();
        benchFramework();
        printStorageOverhead();
    }

    // ── 1. Cryptographic primitives ──────────────────────────────────────────

    void benchPrimitives() throws Exception {
        header("Cryptographic Primitive Latency");
        SecureRandom rng = new SecureRandom();

        // ML-KEM-1024 KeyGen
        row("ML-KEM-1024  KeyGen", time(WARMUP, MEASURED, () -> {
            MLKEMKeyPairGenerator g = new MLKEMKeyPairGenerator();
            g.init(new MLKEMKeyGenerationParameters(rng, MLKEMParameters.ml_kem_1024));
            g.generateKeyPair();
        }));

        // Pre-generate key pair for encaps / decaps
        MLKEMKeyPairGenerator kemGen = new MLKEMKeyPairGenerator();
        kemGen.init(new MLKEMKeyGenerationParameters(rng, MLKEMParameters.ml_kem_1024));
        AsymmetricCipherKeyPair kemPair = kemGen.generateKeyPair();
        MLKEMPublicKeyParameters  kemPub  = (MLKEMPublicKeyParameters)  kemPair.getPublic();
        MLKEMPrivateKeyParameters kemPriv = (MLKEMPrivateKeyParameters) kemPair.getPrivate();

        row("ML-KEM-1024  Encaps", time(WARMUP, MEASURED, () -> {
            SecretWithEncapsulation r = new MLKEMGenerator(rng).generateEncapsulated(kemPub);
            r.destroy();
        }));

        // Pre-compute encapsulation bytes for decaps benchmark
        SecretWithEncapsulation enc = new MLKEMGenerator(rng).generateEncapsulated(kemPub);
        byte[] encapsBytes = enc.getEncapsulation().clone();
        enc.destroy();

        row("ML-KEM-1024  Decaps", time(WARMUP, MEASURED, () ->
                new MLKEMExtractor(kemPriv).extractSecret(encapsBytes)));

        // ML-DSA-65 KeyGen
        row("ML-DSA-65    KeyGen", time(WARMUP, MEASURED, () -> {
            MLDSAKeyPairGenerator g = new MLDSAKeyPairGenerator();
            g.init(new MLDSAKeyGenerationParameters(rng, MLDSAParameters.ml_dsa_65));
            g.generateKeyPair();
        }));

        // Pre-generate DSA key pair
        MLDSAKeyPairGenerator dsaGen = new MLDSAKeyPairGenerator();
        dsaGen.init(new MLDSAKeyGenerationParameters(rng, MLDSAParameters.ml_dsa_65));
        AsymmetricCipherKeyPair dsaPair = dsaGen.generateKeyPair();
        MLDSAPrivateKeyParameters dsaPriv = (MLDSAPrivateKeyParameters) dsaPair.getPrivate();
        MLDSAPublicKeyParameters  dsaPub  = (MLDSAPublicKeyParameters)  dsaPair.getPublic();

        // sign input: encapsulation (1568 B) || encrypted payload (~359 B for 256 B value)
        byte[] signInput = new byte[1568 + 359];
        rng.nextBytes(signInput);

        row("ML-DSA-65    Sign", time(WARMUP, MEASURED, () -> {
            MLDSASigner s = new MLDSASigner();
            s.init(true, dsaPriv);
            s.update(signInput, 0, signInput.length);
            s.generateSignature();
        }));

        // Pre-compute signature for verify benchmark
        MLDSASigner signer = new MLDSASigner();
        signer.init(true, dsaPriv);
        signer.update(signInput, 0, signInput.length);
        byte[] sig = signer.generateSignature();

        row("ML-DSA-65    Verify", time(WARMUP, MEASURED, () -> {
            MLDSASigner v = new MLDSASigner();
            v.init(false, dsaPub);
            v.update(signInput, 0, signInput.length);
            v.verifySignature(sig);
        }));

        // AES-256-GCM encrypt at various payload sizes
        byte[] aesKey = new byte[32];
        rng.nextBytes(aesKey);
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
        byte[] iv = new byte[12];
        rng.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        for (int size : new int[]{64, 256, 1024, 4096, 65536}) {
            byte[] pt = new byte[size];
            rng.nextBytes(pt);
            row(String.format("AES-256-GCM  Encrypt %6d B", size), time(WARMUP, MEASURED, () -> {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                c.doFinal(pt);
            }));
        }

        // HMAC-SHA-256 key derivation (realistic key input: "user:alice")
        byte[] hmacKey = new byte[32];
        rng.nextBytes(hmacKey);
        byte[] hmacInput = "user:alice".getBytes();
        row("HMAC-SHA-256 Key Derivation", time(WARMUP, MEASURED, () -> {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            mac.doFinal(hmacInput);
        }));
    }

    // ── 2. Classical comparison ──────────────────────────────────────────────

    void benchClassical() throws Exception {
        header("Classical Scheme Comparison");
        SecureRandom rng = new SecureRandom();

        // ECDH-P256 key generation
        row("ECDH-P256    KeyGen", time(WARMUP, MEASURED, () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"), rng);
            kpg.generateKeyPair();
        }));

        // Pre-generate two P-256 key pairs for agreement benchmark
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"), rng);
        KeyPair kp1 = kpg.generateKeyPair();
        KeyPair kp2 = kpg.generateKeyPair();

        row("ECDH-P256    Key Agreement", time(WARMUP, MEASURED, () -> {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
            ka.init(kp1.getPrivate());
            ka.doPhase(kp2.getPublic(), true);
            ka.generateSecret();
        }));

        // 256-byte message (typical payload)
        byte[] msg = new byte[256];
        rng.nextBytes(msg);

        row("ECDSA-P256   Sign", time(WARMUP, MEASURED, () -> {
            Signature s = Signature.getInstance("SHA256withECDSA", "BC");
            s.initSign(kp1.getPrivate(), rng);
            s.update(msg);
            s.sign();
        }));

        // Pre-compute signature for verify benchmark
        Signature sigObj = Signature.getInstance("SHA256withECDSA", "BC");
        sigObj.initSign(kp1.getPrivate(), rng);
        sigObj.update(msg);
        byte[] ecdsaSig = sigObj.sign();

        row("ECDSA-P256   Verify", time(WARMUP, MEASURED, () -> {
            Signature v = Signature.getInstance("SHA256withECDSA", "BC");
            v.initVerify(kp1.getPublic());
            v.update(msg);
            v.verify(ecdsaSig);
        }));
    }

    // ── 3. Framework operations (in-memory store) ────────────────────────────

    void benchFramework() throws Exception {
        System.out.printf("%n--- Framework Operations / Crypto Only (n=%d, warmup=%d) ---%n",
                FW_MEASURED, FW_WARMUP);
        System.out.printf("  %-42s  %10s  %10s%n", "Operation", "Mean (µs)", "SD (µs)");
        System.out.println("  " + "-".repeat(66));

        InMemoryKeyManager     km       = new InMemoryKeyManager();
        PqcKeyBundle           bundle   = km.generateKeys();
        KeyBundleRegistry      registry = new KeyBundleRegistry(bundle, km);
        AesGcmService          aesGcm   = new AesGcmServiceImpl();
        MlKemService           mlKem    = new MlKemServiceImpl();
        MlDsaService           mlDsa    = new MlDsaServiceImpl();
        KeyOnion               keyOnion = new KeyOnion(aesGcm);
        ValueOnion             valOnion = new ValueOnion(aesGcm);
        InMemoryEncryptedStore store    = new InMemoryEncryptedStore();

        PqcFrameworkImpl fw = new PqcFrameworkImpl(
                registry, mlKem, mlDsa, aesGcm, keyOnion, valOnion, store);

        SecureRandom rng = new SecureRandom();

        for (int size : new int[]{64, 256, 1024, 4096}) {
            byte[] value = new byte[size];
            rng.nextBytes(value);
            String getKey = "bench:get:" + size;

            // warmup
            for (int i = 0; i < FW_WARMUP; i++) {
                fw.put("bench:wu:" + i + ":" + size, value);
                fw.get("bench:wu:" + i + ":" + size);
            }

            // put: fresh key each call so the store doesn't hit any HM shortcut
            Stats putStats = time(0, FW_MEASURED, () -> {
                fw.put("bench:put:" + rng.nextLong(), value);
            });
            row(String.format("put()  %5d B value", size), putStats);

            // get: always the same pre-loaded key
            fw.put(getKey, value);
            Stats getStats = time(0, FW_MEASURED, () -> fw.get(getKey));
            row(String.format("get()  %5d B value", size), getStats);
        }
    }

    // ── 4. Storage overhead ──────────────────────────────────────────────────

    void printStorageOverhead() throws Exception {
        System.out.println("\n--- Storage Overhead per Encrypted Record ---");
        System.out.printf("  %-10s  %-11s  %-10s  %-13s  %-8s%n",
                "Value (B)", "Stored (B)", "Fixed (B)", "Variable (B)", "Ratio");
        System.out.println("  " + "-".repeat(60));

        // Measure actual stored bytes using the in-memory store
        InMemoryKeyManager     km       = new InMemoryKeyManager();
        PqcKeyBundle           bundle   = km.generateKeys();
        KeyBundleRegistry      registry = new KeyBundleRegistry(bundle, km);
        AesGcmService          aesGcm   = new AesGcmServiceImpl();
        MlKemService           mlKem    = new MlKemServiceImpl();
        MlDsaService           mlDsa    = new MlDsaServiceImpl();
        KeyOnion               keyOnion = new KeyOnion(aesGcm);
        ValueOnion             valOnion = new ValueOnion(aesGcm);
        InMemoryEncryptedStore store    = new InMemoryEncryptedStore();

        PqcFrameworkImpl fw = new PqcFrameworkImpl(
                registry, mlKem, mlDsa, aesGcm, keyOnion, valOnion, store);

        // Fixed overhead: kem (1568) + sig (3309) + pk (43) + kid (6)
        int FIXED = 1568 + 3309 + 43 + 6; // 4926

        SecureRandom rng = new SecureRandom();
        for (int size : new int[]{64, 256, 1024, 4096, 65536}) {
            byte[] value = new byte[size];
            rng.nextBytes(value);
            String plain = "overhead:key:" + size;

            // Derive the deterministic key the same way the framework does
            byte[] dek = bundle.dataEncryptionKey();
            String detKey = keyOnion.apply(plain, dek, OnionLayer.DET);
            Arrays.fill(dek, (byte) 0);

            fw.put(plain, value);
            int stored   = store.storedBytes(plain, detKey);
            int variable = stored - FIXED;
            double ratio = (double) stored / size;

            System.out.printf("  %-10d  %-11d  %-10d  %-13d  %.1fx%n",
                    size, stored, FIXED, variable, ratio);
        }
    }
}
