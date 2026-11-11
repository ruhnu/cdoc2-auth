package ee.cyber.cdoc2.auth.exception;

/**
 * Signals that an SSH public key or a "ruhnu/pk/" recipient identifier could not be used.
 */
public class InvalidSshPublicKeyException extends IllegalArgumentException {

    /** Why the key was rejected */
    public enum Reason {
        /** identifier does not start with "ruhnu/pk/" */
        MISSING_PREFIX,
        /** key blob is not valid base64 */
        MALFORMED_BASE64,
        /** key blob or OpenSSH line does not parse */
        MALFORMED_KEY,
        /** key type is valid OpenSSH, but not supported (only ecdsa-sha2-nistp256 is) */
        UNSUPPORTED_KEY_TYPE,
        /** ecdsa-sha2-nistp256 key whose curve name is not nistp256 */
        CURVE_MISMATCH
    }

    private final Reason reason;

    public InvalidSshPublicKeyException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public InvalidSshPublicKeyException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
