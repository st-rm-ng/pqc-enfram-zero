package org.pqc.enframzero.store;

import org.pqc.enframzero.onion.TransitEnvelope;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;

import java.util.Map;
import java.util.Optional;

/**
 * DynamoDB-backed implementation of {@link EncryptedStore}.
 *
 * <p>Table schema (partition key only, PAY_PER_REQUEST billing):
 * <pre>
 *   pk      (S) — deterministic key (HMAC-SHA256, Base64URL)
 *   kem     (B) — ML-KEM encapsulation ciphertext
 *   payload (B) — AES-GCM encrypted payload (transit layer)
 *   sig     (B) — ML-DSA signature
 * </pre>
 */
public class DynamoDbEncryptedStore implements EncryptedStore {

    private static final String ATTR_PK = "pk";
    private static final String ATTR_KEM = "kem";
    private static final String ATTR_PAYLOAD = "payload";
    private static final String ATTR_SIG = "sig";

    private final DynamoDbClient client;
    private final String tableName;

    public DynamoDbEncryptedStore(DynamoDbClient client, String tableName) {
        this.client = client;
        this.tableName = tableName;
    }

    @Override
    public void put(String deterministicKey, TransitEnvelope envelope) {
        client.putItem(PutItemRequest.builder()
                .tableName(tableName)
                .item(Map.of(
                        ATTR_PK,      AttributeValue.fromS(deterministicKey),
                        ATTR_KEM,     AttributeValue.fromB(SdkBytes.fromByteArray(envelope.kemEncapsulation())),
                        ATTR_PAYLOAD, AttributeValue.fromB(SdkBytes.fromByteArray(envelope.encryptedPayload())),
                        ATTR_SIG,     AttributeValue.fromB(SdkBytes.fromByteArray(envelope.dsaSignature()))
                ))
                .build());
    }

    @Override
    public Optional<TransitEnvelope> get(String deterministicKey) {
        GetItemResponse response = client.getItem(GetItemRequest.builder()
                .tableName(tableName)
                .key(Map.of(ATTR_PK, AttributeValue.fromS(deterministicKey)))
                .build());

        if (!response.hasItem() || response.item().isEmpty()) {
            return Optional.empty();
        }

        Map<String, AttributeValue> item = response.item();
        return Optional.of(new TransitEnvelope(
                item.get(ATTR_KEM).b().asByteArray(),
                item.get(ATTR_PAYLOAD).b().asByteArray(),
                item.get(ATTR_SIG).b().asByteArray()
        ));
    }

    @Override
    public void delete(String deterministicKey) {
        client.deleteItem(DeleteItemRequest.builder()
                .tableName(tableName)
                .key(Map.of(ATTR_PK, AttributeValue.fromS(deterministicKey)))
                .build());
    }
}
