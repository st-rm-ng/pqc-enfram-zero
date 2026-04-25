package org.pqc.enframzero.framework;

import org.pqc.enframzero.crypto.AesGcmService;
import org.pqc.enframzero.crypto.AesGcmServiceImpl;
import org.pqc.enframzero.crypto.MlDsaService;
import org.pqc.enframzero.crypto.MlDsaServiceImpl;
import org.pqc.enframzero.crypto.MlKemService;
import org.pqc.enframzero.crypto.MlKemServiceImpl;
import org.pqc.enframzero.keys.InMemoryKeyManager;
import org.pqc.enframzero.keys.KeyBundleRegistry;
import org.pqc.enframzero.keys.PqcKeyBundle;
import org.pqc.enframzero.onion.KeyOnion;
import org.pqc.enframzero.onion.OnionLayer;
import org.pqc.enframzero.onion.TransitEnvelope;
import org.pqc.enframzero.onion.ValueOnion;
import org.pqc.enframzero.store.DynamoDbEncryptedStore;
import org.pqc.enframzero.store.EncryptedStore;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

/**
 * Wires all framework components together and implements the two-layer onion encryption flow.
 *
 * <p>put(key, value, bundleId) flow:
 * <ol>
 *   <li>Resolve the key bundle from the registry (auto-create if missing)</li>
 *   <li>AES-GCM encrypt value with DEK (at-rest layer)</li>
 *   <li>Derive deterministic DynamoDB key via HMAC-SHA256(DEK, plainKey)</li>
 *   <li>Serialise (deterministicKey, encryptedValue) into a payload</li>
 *   <li>ML-KEM encapsulate: generate ephemeral transitKey + encapsulation</li>
 *   <li>AES-GCM encrypt payload with transitKey (transit layer)</li>
 *   <li>ML-DSA sign (encapsulation || encryptedPayload)</li>
 *   <li>Store envelope (including bundleId as {@code kid}) in DynamoDB</li>
 * </ol>
 *
 * <p>get(key, bundleId) flow reverses the above, verifying the signature before decryption.
 */
public class PqcFrameworkImpl implements PqcFramework {

    private final KeyBundleRegistry registry;
    private final MlKemService mlKem;
    private final MlDsaService mlDsa;
    private final AesGcmService aesGcm;
    private final KeyOnion keyOnion;
    private final ValueOnion valueOnion;
    private final EncryptedStore store;

    public PqcFrameworkImpl(
            KeyBundleRegistry registry,
            MlKemService mlKem,
            MlDsaService mlDsa,
            AesGcmService aesGcm,
            KeyOnion keyOnion,
            ValueOnion valueOnion,
            EncryptedStore store) {
        this.registry = registry;
        this.mlKem = mlKem;
        this.mlDsa = mlDsa;
        this.aesGcm = aesGcm;
        this.keyOnion = keyOnion;
        this.valueOnion = valueOnion;
        this.store = store;
    }

    /**
     * Convenience factory that wires all implementations with default settings.
     * Generates a fresh master key bundle on each call (keys held in memory only).
     */
    public static PqcFrameworkImpl create(String tableName, String region) {
        InMemoryKeyManager keyManager = new InMemoryKeyManager();
        KeyBundleRegistry registry = new KeyBundleRegistry(keyManager.generateKeys(), keyManager);
        return create(tableName, region, registry);
    }

    /**
     * Convenience factory using the supplied bundle as the master.
     * Backward-compatible replacement for the old single-bundle factory.
     */
    public static PqcFrameworkImpl create(String tableName, String region, PqcKeyBundle masterBundle) {
        InMemoryKeyManager keyManager = new InMemoryKeyManager();
        return create(tableName, region, new KeyBundleRegistry(masterBundle, keyManager));
    }

    /**
     * Convenience factory for callers that manage their own {@link KeyBundleRegistry}.
     */
    public static PqcFrameworkImpl create(String tableName, String region, KeyBundleRegistry registry) {
        AesGcmService aesGcm = new AesGcmServiceImpl();
        MlKemService mlKem = new MlKemServiceImpl();
        MlDsaService mlDsa = new MlDsaServiceImpl();
        KeyOnion keyOnion = new KeyOnion(aesGcm);
        ValueOnion valueOnion = new ValueOnion(aesGcm);
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
                .region(Region.of(region))
                .build();
        EncryptedStore store = new DynamoDbEncryptedStore(dynamoDbClient, tableName);
        return new PqcFrameworkImpl(registry, mlKem, mlDsa, aesGcm, keyOnion, valueOnion, store);
    }

    @Override
    public void put(String key, byte[] value, String bundleId) {
        PqcKeyBundle bundle = registry.getOrCreate(bundleId);
        byte[] dek = bundle.dataEncryptionKey();
        try {
            byte[] encryptedValue = valueOnion.encrypt(value, dek);
            String deterministicKey = keyOnion.apply(key, dek, OnionLayer.DET);
            byte[] deterministicKeyBytes = deterministicKey.getBytes(StandardCharsets.UTF_8);
            byte[] plaintextPayload = TransitEnvelope.serialisePayload(deterministicKeyBytes, encryptedValue);
            MlKemService.KemResult kem = mlKem.encapsulate(bundle.kemPublicKey());
            byte[] encryptedPayload = aesGcm.encrypt(plaintextPayload, kem.sharedSecret());
            byte[] signInput = signInput(kem.encapsulation(), encryptedPayload);
            byte[] signature = mlDsa.sign(signInput, bundle.dsaPrivateKey());
            TransitEnvelope envelope = new TransitEnvelope(bundleId, kem.encapsulation(), encryptedPayload, signature);
            store.put(deterministicKey, envelope);
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    @Override
    public Optional<byte[]> get(String key, String bundleId) {
        PqcKeyBundle bundle = registry.get(bundleId)
                .orElseThrow(() -> new IllegalArgumentException("Key bundle not registered: " + bundleId));
        byte[] dek = bundle.dataEncryptionKey();
        try {
            String deterministicKey = keyOnion.apply(key, dek, OnionLayer.DET);
            Optional<TransitEnvelope> envelopeOpt = store.get(deterministicKey);
            if (envelopeOpt.isEmpty()) {
                return Optional.empty();
            }
            TransitEnvelope envelope = envelopeOpt.get();
            byte[] signInput = signInput(envelope.kemEncapsulation(), envelope.encryptedPayload());
            boolean valid = mlDsa.verify(signInput, envelope.dsaSignature(), bundle.dsaPublicKey());
            if (!valid) {
                throw new IntegrityException("ML-DSA signature verification failed for key: " + key);
            }
            byte[] transitKey = mlKem.decapsulate(bundle.kemPrivateKey(), envelope.kemEncapsulation());
            byte[] plaintextPayload = aesGcm.decrypt(envelope.encryptedPayload(), transitKey);
            byte[][] parts = TransitEnvelope.deserialisePayload(plaintextPayload);
            byte[] encryptedValue = parts[1];
            return Optional.of(valueOnion.decrypt(encryptedValue, dek));
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    @Override
    public void delete(String key, String bundleId) {
        PqcKeyBundle bundle = registry.get(bundleId)
                .orElseThrow(() -> new IllegalArgumentException("Key bundle not registered: " + bundleId));
        byte[] dek = bundle.dataEncryptionKey();
        try {
            String deterministicKey = keyOnion.apply(key, dek, OnionLayer.DET);
            store.delete(deterministicKey);
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    private static byte[] signInput(byte[] kemEncapsulation, byte[] encryptedPayload) {
        byte[] combined = new byte[kemEncapsulation.length + encryptedPayload.length];
        System.arraycopy(kemEncapsulation, 0, combined, 0, kemEncapsulation.length);
        System.arraycopy(encryptedPayload, 0, combined, kemEncapsulation.length, encryptedPayload.length);
        return combined;
    }
}
