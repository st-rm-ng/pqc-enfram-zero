package org.pqc.enframzero.framework;

/**
 * Thrown when ML-DSA signature verification fails, indicating that stored data
 * may have been tampered with.
 */
public class IntegrityException extends RuntimeException {

    public IntegrityException(String message) {
        super(message);
    }
}
