package org.pqc.enframzero.onion;

/**
 * Encryption layers in the CryptDB-inspired onion model.
 * PLAIN never leaves the client. DET and RND are the forms stored in DynamoDB.
 */
public enum OnionLayer {
    /** Plaintext — exists only on the client, never sent to the server. */
    PLAIN,
    /** Deterministic encryption — same input always produces same output, enabling GetItem lookups. */
    DET,
    /** Random encryption — random IV/nonce, fully opaque, no lookup possible. */
    RND
}
