package org.pqc.enframzero.store;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.pqc.enframzero.framework.PqcFramework;
import org.pqc.enframzero.framework.PqcFrameworkImpl;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test against a live DynamoDB table.
 * Requires the environment variable {@code PQC_TABLE_NAME} to be set and
 * AWS credentials to be configured (default credential provider chain).
 *
 * Run with: PQC_TABLE_NAME=pqc-items-dev mvn test -Dgroups=integration
 */
@Tag("integration")
class DynamoDbEncryptedStoreIntegrationTest {

    @Test
    void putGetDelete_roundTrip() {
        String tableName = System.getenv("PQC_TABLE_NAME");
        assertNotNull(tableName, "PQC_TABLE_NAME environment variable must be set for integration tests");

        PqcFramework fw = PqcFrameworkImpl.create(tableName, "eu-central-1");

        String key = "integration-test-key-" + System.currentTimeMillis();
        String value = "integration-test-value";

        fw.putString(key, value);
        assertEquals(value, fw.getString(key).orElseThrow());

        fw.delete(key);
        assertTrue(fw.getString(key).isEmpty());
    }
}
