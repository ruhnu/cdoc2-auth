package ee.cyber.cdoc2.auth;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;

import ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException;
import ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException.Reason;

/**
 * Parses SSH public keys given as "ruhnu/pk/&lt;blob&gt;" recipient identifiers or as OpenSSH public key lines
 * ("ecdsa-sha2-nistp256 AAAA... comment"). &lt;blob&gt; is the standard base64 (with padding) of the OpenSSH
 * public key wire blob. Only ECDSA P-256 (ecdsa-sha2-nistp256) keys are supported.
 */
public final class SshPublicKeyParser {

    /** Recipient identifier prefix for SSH public key recipients */
    public static final String RECIPIENT_ID_PREFIX = "ruhnu/pk/";

    /** The only supported OpenSSH key type */
    public static final String KEY_TYPE_ECDSA_P256 = "ecdsa-sha2-nistp256";

    private static final String CURVE_NISTP256 = "nistp256";
    private static final int P256_COORDINATE_LEN = 32;
    private static final int P256_UNCOMPRESSED_POINT_LEN = 1 + 2 * P256_COORDINATE_LEN;
    private static final byte UNCOMPRESSED_POINT_TAG = 0x04;
    // longest key type name accepted when reading a blob; real names are < 64 chars
    private static final int MAX_NAME_LEN = 256;

    private SshPublicKeyParser() {
        // utility class
    }

    /**
     * Parse "ruhnu/pk/&lt;blob&gt;" recipient identifier into P-256 public key.
     * @param recipientId recipient identifier
     * @return EC public key
     * @throws InvalidSshPublicKeyException if identifier is malformed or key is not supported
     */
    public static ECPublicKey fromRecipientId(String recipientId) {
        Objects.requireNonNull(recipientId);
        if (!recipientId.startsWith(RECIPIENT_ID_PREFIX)) {
            throw new InvalidSshPublicKeyException(Reason.MISSING_PREFIX,
                "Recipient identifier does not start with \"" + RECIPIENT_ID_PREFIX + "\"");
        }
        // strip prefix, don't split on '/': standard base64 contains '/'
        return fromBlob(decodeBase64(recipientId.substring(RECIPIENT_ID_PREFIX.length())));
    }

    /**
     * Parse OpenSSH public key line ("ecdsa-sha2-nistp256 AAAA... optional comment") into P-256 public key.
     * @param openSshLine OpenSSH public key line, as in .pub file or `ssh-add -L` output
     * @return EC public key
     * @throws InvalidSshPublicKeyException if line is malformed or key is not supported
     */
    public static ECPublicKey fromOpenSshLine(String openSshLine) {
        return fromBlob(blobFromOpenSshLine(openSshLine));
    }

    /**
     * Create "ruhnu/pk/&lt;blob&gt;" recipient identifier from OpenSSH public key line. The comment is ignored,
     * so the same key always gives the same identifier.
     * @param openSshLine OpenSSH public key line
     * @return recipient identifier
     * @throws InvalidSshPublicKeyException if line is malformed or key is not supported
     */
    public static String recipientIdFromOpenSshLine(String openSshLine) {
        byte[] blob = blobFromOpenSshLine(openSshLine);
        fromBlob(blob); // validate
        return toRecipientId(blob);
    }

    /**
     * Create "ruhnu/pk/&lt;blob&gt;" recipient identifier from OpenSSH public key wire blob.
     * @param blob OpenSSH public key wire blob
     * @return recipient identifier
     * @throws InvalidSshPublicKeyException if key is not supported
     */
    public static String recipientIdFromBlob(byte[] blob) {
        fromBlob(blob); // validate
        return toRecipientId(blob);
    }

    /**
     * Get OpenSSH public key wire blob from "ruhnu/pk/&lt;blob&gt;" recipient identifier.
     * @param recipientId recipient identifier
     * @return key blob
     * @throws InvalidSshPublicKeyException if identifier is malformed or key is not supported
     */
    public static byte[] blobFromRecipientId(String recipientId) {
        fromRecipientId(recipientId); // validate
        return decodeBase64(recipientId.substring(RECIPIENT_ID_PREFIX.length()));
    }

    /**
     * Parse OpenSSH public key wire blob ("string keytype, string curve, string Q") into P-256 public key.
     * @param blob key blob
     * @return EC public key
     * @throws InvalidSshPublicKeyException if blob is malformed or key is not supported
     */
    public static ECPublicKey fromBlob(byte[] blob) {
        Objects.requireNonNull(blob);
        ByteBuffer buf = ByteBuffer.wrap(blob);

        String keyType = readName(buf);
        if (!KEY_TYPE_ECDSA_P256.equals(keyType)) {
            throw new InvalidSshPublicKeyException(Reason.UNSUPPORTED_KEY_TYPE,
                "SSH key type " + keyType + " is not supported, only " + KEY_TYPE_ECDSA_P256 + " is supported");
        }

        String curve = readName(buf);
        if (!CURVE_NISTP256.equals(curve)) {
            throw new InvalidSshPublicKeyException(Reason.CURVE_MISMATCH,
                "Curve " + curve + " does not match key type " + KEY_TYPE_ECDSA_P256);
        }

        byte[] q = readString(buf);
        if (buf.hasRemaining()) {
            throw new InvalidSshPublicKeyException(Reason.MALFORMED_KEY, "Trailing data after SSH public key");
        }
        if (q.length != P256_UNCOMPRESSED_POINT_LEN || q[0] != UNCOMPRESSED_POINT_TAG) {
            throw new InvalidSshPublicKeyException(Reason.MALFORMED_KEY,
                "SSH public key point is not an uncompressed P-256 point");
        }

        byte[] x = Arrays.copyOfRange(q, 1, 1 + P256_COORDINATE_LEN);
        byte[] y = Arrays.copyOfRange(q, 1 + P256_COORDINATE_LEN, P256_UNCOMPRESSED_POINT_LEN);
        try {
            // ECKey checks that the point is on the curve
            return new ECKey.Builder(Curve.P_256, Base64URL.encode(x), Base64URL.encode(y))
                .build()
                .toECPublicKey();
        } catch (IllegalArgumentException | IllegalStateException | JOSEException e) {
            throw new InvalidSshPublicKeyException(Reason.MALFORMED_KEY,
                "SSH public key point is not on P-256 curve", e);
        }
    }

    private static byte[] blobFromOpenSshLine(String openSshLine) {
        Objects.requireNonNull(openSshLine);
        String[] fields = openSshLine.strip().split("\\s+", 3);
        if (fields.length < 2) {
            throw new InvalidSshPublicKeyException(Reason.MALFORMED_KEY,
                "Not an OpenSSH public key line, expected \"<key type> <base64 key> [comment]\"");
        }
        byte[] blob = decodeBase64(fields[1]);
        String blobKeyType = readName(ByteBuffer.wrap(blob));
        if (!fields[0].equals(blobKeyType)) {
            throw new InvalidSshPublicKeyException(Reason.MALFORMED_KEY,
                "Key type " + fields[0] + " does not match key data type " + blobKeyType);
        }
        return blob;
    }

    private static String toRecipientId(byte[] blob) {
        return RECIPIENT_ID_PREFIX + Base64.getEncoder().encodeToString(blob);
    }

    private static byte[] decodeBase64(String base64) {
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new InvalidSshPublicKeyException(Reason.MALFORMED_BASE64,
                "SSH public key is not valid base64", e);
        }
    }

    private static String readName(ByteBuffer buf) {
        byte[] name = readString(buf, MAX_NAME_LEN);
        return new String(name, StandardCharsets.US_ASCII);
    }

    private static byte[] readString(ByteBuffer buf) {
        return readString(buf, buf.remaining());
    }

    /** Read SSH wire format "string": uint32 length followed by bytes */
    private static byte[] readString(ByteBuffer buf, int maxLen) {
        try {
            long len = Integer.toUnsignedLong(buf.getInt());
            if (len > maxLen || len > buf.remaining()) {
                throw new InvalidSshPublicKeyException(Reason.MALFORMED_KEY,
                    "Could not parse SSH public key: invalid field length " + len);
            }
            byte[] value = new byte[(int) len];
            buf.get(value);
            return value;
        } catch (BufferUnderflowException e) {
            throw new InvalidSshPublicKeyException(Reason.MALFORMED_KEY,
                "Could not parse SSH public key: truncated data", e);
        }
    }
}
