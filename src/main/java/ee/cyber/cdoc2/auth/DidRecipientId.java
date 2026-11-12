package ee.cyber.cdoc2.auth;

import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;

import ee.cyber.cdoc2.auth.exception.InvalidDidRecipientException;
import ee.cyber.cdoc2.auth.exception.InvalidDidRecipientException.Reason;

/**
 * "ruhnu/did/&lt;did&gt;/hash/&lt;fingerprint&gt;" recipient identifier: an SSH public key that the did:web DID
 * document must list. &lt;fingerprint&gt; is the unpadded base64url of SHA-256 of the OpenSSH public key wire blob
 * ({@link SshPublicKeyParser#fingerprintBase64Url(byte[])}), so the identifier pins the key without containing it.
 *
 * @param didWeb      the DID
 * @param fingerprint key fingerprint, 43 characters of canonical unpadded base64url
 */
public record DidRecipientId(DidWeb didWeb, String fingerprint) {

    /** Recipient identifier prefix for DID recipients */
    public static final String PREFIX = "ruhnu/did/";

    /** Separator between the DID and the fingerprint */
    public static final String HASH_SEPARATOR = "/hash/";

    /** Length of the fingerprint: unpadded base64url of 32 bytes */
    public static final int FINGERPRINT_LENGTH = 43;

    /** Longest recipient identifier the shares server stores */
    public static final int MAX_LENGTH = 255;

    private static final int SHA256_LENGTH = 32;
    private static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]+");

    public DidRecipientId {
        Objects.requireNonNull(didWeb);
        checkFingerprint(fingerprint);
    }

    /**
     * Check whether a recipient identifier is of the DID kind. Says nothing about whether it is valid.
     * @param recipientId recipient identifier, may be null
     * @return true if it starts with "ruhnu/did/"
     */
    public static boolean isDidRecipientId(String recipientId) {
        return recipientId != null && recipientId.startsWith(PREFIX);
    }

    /**
     * Parse and validate a "ruhnu/did/&lt;did&gt;/hash/&lt;fingerprint&gt;" recipient identifier.
     * @param recipientId recipient identifier
     * @return parsed identifier, whose {@link #toString()} equals {@code recipientId}
     * @throws InvalidDidRecipientException if the identifier is malformed
     */
    public static DidRecipientId parse(String recipientId) {
        Objects.requireNonNull(recipientId);
        if (!isDidRecipientId(recipientId)) {
            throw new InvalidDidRecipientException(Reason.MISSING_PREFIX,
                "Recipient identifier does not start with \"" + PREFIX + "\"");
        }
        // neither a DID nor base64url contains '/', so splitting is unambiguous
        String[] parts = recipientId.substring(PREFIX.length()).split("/", -1);
        if (parts.length != 3 || !"hash".equals(parts[1])) {
            throw new InvalidDidRecipientException(Reason.INVALID_DID,
                "Recipient identifier is not of the form \"" + PREFIX + "<did>" + HASH_SEPARATOR + "<fingerprint>\"");
        }
        return new DidRecipientId(DidWeb.parse(parts[0]), parts[2]);
    }

    /**
     * Create the identifier for a key listed by a DID.
     * @param did     did:web DID
     * @param keyBlob OpenSSH public key wire blob of a supported (P-256) key
     * @return recipient identifier
     * @throws InvalidDidRecipientException if the DID is not a valid did:web DID
     * @throws ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException if the key is not supported
     */
    public static DidRecipientId of(String did, byte[] keyBlob) {
        return of(DidWeb.parse(did), keyBlob);
    }

    /**
     * Create the identifier for a key listed by a DID.
     * @param didWeb  did:web DID
     * @param keyBlob OpenSSH public key wire blob of a supported (P-256) key
     * @return recipient identifier
     * @throws ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException if the key is not supported
     */
    public static DidRecipientId of(DidWeb didWeb, byte[] keyBlob) {
        SshPublicKeyParser.fromBlob(keyBlob); // validate
        return new DidRecipientId(didWeb, SshPublicKeyParser.fingerprintBase64Url(keyBlob));
    }

    /**
     * @return the DID string
     */
    public String did() {
        return didWeb.did();
    }

    /**
     * @return the fingerprint as OpenSSH shows it (`ssh-keygen -l`), "SHA256:" + unpadded standard base64
     */
    public String openSshFingerprint() {
        return "SHA256:" + fingerprint.replace('-', '+').replace('_', '/');
    }

    /**
     * @param keyBlob OpenSSH public key wire blob
     * @return true if the key's fingerprint is the one this identifier pins
     */
    public boolean matches(byte[] keyBlob) {
        return fingerprint.equals(SshPublicKeyParser.fingerprintBase64Url(keyBlob));
    }

    /**
     * @return "ruhnu/did/&lt;did&gt;/hash/&lt;fingerprint&gt;"
     */
    @Override
    public String toString() {
        return PREFIX + didWeb.did() + HASH_SEPARATOR + fingerprint;
    }

    private static void checkFingerprint(String fingerprint) {
        Objects.requireNonNull(fingerprint);
        if (fingerprint.length() != FINGERPRINT_LENGTH || !BASE64URL.matcher(fingerprint).matches()) {
            throw new InvalidDidRecipientException(Reason.INVALID_FINGERPRINT,
                "Key fingerprint must be " + FINGERPRINT_LENGTH + " characters of unpadded base64url");
        }
        byte[] digest;
        try {
            digest = Base64.getUrlDecoder().decode(fingerprint);
        } catch (IllegalArgumentException e) {
            throw new InvalidDidRecipientException(Reason.INVALID_FINGERPRINT,
                "Key fingerprint is not valid base64url", e);
        }
        if (digest.length != SHA256_LENGTH
            || !Base64.getUrlEncoder().withoutPadding().encodeToString(digest).equals(fingerprint)) {
            throw new InvalidDidRecipientException(Reason.INVALID_FINGERPRINT,
                "Key fingerprint is not in canonical form (unpadded base64url of 32 bytes)");
        }
    }
}
