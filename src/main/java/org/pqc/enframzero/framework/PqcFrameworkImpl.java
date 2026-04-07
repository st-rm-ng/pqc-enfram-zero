package org.pqc.enframzero.framework;

import org.pqc.enframzero.crypto.AesGcmService;
import org.pqc.enframzero.crypto.AesGcmServiceImpl;
import org.pqc.enframzero.crypto.MlDsaService;
import org.pqc.enframzero.crypto.MlDsaServiceImpl;
import org.pqc.enframzero.crypto.MlKemService;
import org.pqc.enframzero.crypto.MlKemServiceImpl;
import org.pqc.enframzero.keys.InMemoryKeyManager;
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
import java.util.Optional;

/**
 * Wires all framework components together and implements the two-layer onion encryption flow.
 *
 * <p>put(key, value) flow:
 * <ol>
 *   <li>AES-GCM encrypt value with DEK (at-rest layer)</li>
 *   <li>Derive deterministic DynamoDB key via HMAC-SHA256(DEK, plainKey)</li>
 *   <li>Serialise (deterministicKey, encryptedValue) into a payload</li>
 *   <li>ML-KEM encapsulate: generate ephemeral transitKey + encapsulation</li>
 *   <li>AES-GCM encrypt payload with transitKey (transit layer)</li>
 *   <li>ML-DSA sign (encapsulation || encryptedPayload)</li>
 *   <li>Store envelope in DynamoDB</li>
 * </ol>
 *
 * <p>get(key) flow reverses the above, verifying the signature before decryption.
 */
public class PqcFrameworkImpl implements PqcFramework {

    private final PqcKeyBundle keyBundle;
    private final MlKemService mlKem;
    private final MlDsaService mlDsa;
    private final AesGcmService aesGcm;
    private final KeyOnion keyOnion;
    private final ValueOnion valueOnion;
    private final EncryptedStore store;

    public PqcFrameworkImpl(
            PqcKeyBundle keyBundle,
            MlKemService mlKem,
            MlDsaService mlDsa,
            AesGcmService aesGcm,
            KeyOnion keyOnion,
            ValueOnion valueOnion,
            EncryptedStore store) {
        this.keyBundle = keyBundle;
        this.mlKem = mlKem;
        this.mlDsa = mlDsa;
        this.aesGcm = aesGcm;
        this.keyOnion = keyOnion;
        this.valueOnion = valueOnion;
        this.store = store;
    }

    /**
     * Convenience factory that wires all implementations with default settings.
     * Generates a fresh key bundle on each call (keys held in memory only).
     *
     * @param tableName the DynamoDB table name to use
     * @param region    the AWS region (e.g. "eu-central-1")
     */
    public static PqcFrameworkImpl create(String tableName, String region) {
        return create(tableName, region, new InMemoryKeyManager().generateKeys());
    }

    /**
     * Convenience factory that wires all implementations using the supplied key bundle.
     * Use this to restore a previously persisted bundle loaded via {@link org.pqc.enframzero.keys.KmsBlobKeyStore}.
     *
     * @param tableName the DynamoDB table name to use
     * @param region    the AWS region (e.g. "eu-central-1")
     * @param keyBundle existing key material (caller retains ownership; not destroyed here)
     */
    public static PqcFrameworkImpl create(String tableName, String region, PqcKeyBundle keyBundle) {
        AesGcmService aesGcm = new AesGcmServiceImpl();
        MlKemService mlKem = new MlKemServiceImpl();
        MlDsaService mlDsa = new MlDsaServiceImpl();
        KeyOnion keyOnion = new KeyOnion(aesGcm);
        ValueOnion valueOnion = new ValueOnion(aesGcm);
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
                .region(Region.of(region))
                .build();
        EncryptedStore store = new DynamoDbEncryptedStore(dynamoDbClient, tableName);
        return new PqcFrameworkImpl(keyBundle, mlKem, mlDsa, aesGcm, keyOnion, valueOnion, store);
    }

    @Override
    public void put(String key, byte[] value) {
        byte[] dek = keyBundle.dataEncryptionKey();
        try {
            // Step 1: At-rest encryption of the value
            byte[] encryptedValue = valueOnion.encrypt(value, dek);

            // Step 2: Deterministic key for DynamoDB lookup
            String deterministicKey = keyOnion.apply(key, dek, OnionLayer.DET);
            byte[] deterministicKeyBytes = deterministicKey.getBytes(StandardCharsets.UTF_8);

            // Step 3: Assemble inner payload
            byte[] plaintextPayload = TransitEnvelope.serialisePayload(deterministicKeyBytes, encryptedValue);

            // Step 4: ML-KEM encapsulation (fresh ephemeral transit key per operation)
            MlKemService.KemResult kem = mlKem.encapsulate(keyBundle.kemPublicKey());

            // Step 5: Transit-layer encryption of the payload
            byte[] encryptedPayload = aesGcm.encrypt(plaintextPayload, kem.sharedSecret());

            // Step 6: ML-DSA signature for integrity
            byte[] signInput = signInput(kem.encapsulation(), encryptedPayload);
            byte[] signature = mlDsa.sign(signInput, keyBundle.dsaPrivateKey());

            // Step 7: Persist
            TransitEnvelope envelope = new TransitEnvelope(kem.encapsulation(), encryptedPayload, signature);
            store.put(deterministicKey, envelope);
        } finally {
            java.util.Arrays.fill(dek, (byte) 0);
        }
    }

    @Override
    public Optional<byte[]> get(String key) {
        byte[] dek = keyBundle.dataEncryptionKey();
        try {
            // Step 1: Derive the same deterministic key to look up in DynamoDB
            String deterministicKey = keyOnion.apply(key, dek, OnionLayer.DET);

            // Step 2: Fetch envelope
            Optional<TransitEnvelope> envelopeOpt = store.get(deterministicKey);
            if (envelopeOpt.isEmpty()) {
                return Optional.empty();
            }
            TransitEnvelope envelope = envelopeOpt.get();

            // Step 3: Verify ML-DSA signature before decryption
            byte[] signInput = signInput(envelope.kemEncapsulation(), envelope.encryptedPayload());
            boolean valid = mlDsa.verify(signInput, envelope.dsaSignature(), keyBundle.dsaPublicKey());
            if (!valid) {
                throw new IntegrityException("ML-DSA signature verification failed for key: " + key);
            }

            // Step 4: ML-KEM decapsulation to recover ephemeral transit key
            byte[] transitKey = mlKem.decapsulate(keyBundle.kemPrivateKey(), envelope.kemEncapsulation());

            // Step 5: Decrypt transit layer
            byte[] plaintextPayload = aesGcm.decrypt(envelope.encryptedPayload(), transitKey);

            // Step 6: Extract encrypted value from payload
            byte[][] parts = TransitEnvelope.deserialisePayload(plaintextPayload);
            byte[] encryptedValue = parts[1];

            // Step 7: Decrypt at-rest layer
            return Optional.of(valueOnion.decrypt(encryptedValue, dek));
        } finally {
            java.util.Arrays.fill(dek, (byte) 0);
        }
    }

    @Override
    public void delete(String key) {
        byte[] dek = keyBundle.dataEncryptionKey();
        try {
            String deterministicKey = keyOnion.apply(key, dek, OnionLayer.DET);
            store.delete(deterministicKey);
        } finally {
            java.util.Arrays.fill(dek, (byte) 0);
        }
    }

    private static byte[] signInput(byte[] kemEncapsulation, byte[] encryptedPayload) {
        byte[] combined = new byte[kemEncapsulation.length + encryptedPayload.length];
        System.arraycopy(kemEncapsulation, 0, combined, 0, kemEncapsulation.length);
        System.arraycopy(encryptedPayload, 0, combined, kemEncapsulation.length, encryptedPayload.length);
        return combined;
    }
}
