package ee.cyber.cdoc2.auth.exception;

/**
 * Signals that a DID or a "ruhnu/did/" recipient identifier could not be used.
 */
public class InvalidDidRecipientException extends IllegalArgumentException {

    /** Why the DID or identifier was rejected */
    public enum Reason {
        /** identifier does not start with "ruhnu/did/" */
        MISSING_PREFIX,
        /** a DID, but not a did:web DID */
        UNSUPPORTED_METHOD,
        /** not a valid did:web DID, for example an IP address as host */
        INVALID_DID,
        /** identifier fingerprint is not 43 characters of canonical unpadded base64url (32 bytes) */
        INVALID_FINGERPRINT,
        /** DID is too long for a recipient identifier of at most 255 characters */
        TOO_LONG
    }

    private final Reason reason;

    public InvalidDidRecipientException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public InvalidDidRecipientException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
