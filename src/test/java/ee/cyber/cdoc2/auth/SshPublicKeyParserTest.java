package ee.cyber.cdoc2.auth;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException;
import ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException.Reason;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SshPublicKeyParserTest {

    // generated with ssh-keygen -t ecdsa -b 256
    static final String P256_BLOB = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPqYlhCPIqQV+rcspT8Cqb"
        + "IEEJoEbC7MN1U+Vy+F8kNUf8hgZLMsYKnQDae+4Mt8jAxxfrxiSqEyMr2ZqMh4cqo=";
    static final String P256_LINE = "ecdsa-sha2-nistp256 " + P256_BLOB + " p256@test";
    static final String P256_RECIPIENT_ID = "ruhnu/pk/" + P256_BLOB;

    // ssh-keygen -t ecdsa -b 384
    static final String P384_LINE = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJs2a8"
        + "UwszK40a9xku5WVg8OIM9ES/B6wn8KeeAE0qfLlWKXzqnB0KtL+2fZe7e68QLQaXZ9SPI95mI3sQkYKZ4otVmHinH2ioay4zie5k/Kz81M"
        + "ASGbsbHFaCBQkT1a1w== p384@test";

    // ssh-keygen -t ed25519
    static final String ED25519_LINE =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWcEUGN1uqqDHo5611gZw30t3rU05Q9Y6zqOt8CMfDy ed@test";

    // ssh-keygen -t rsa -b 2048
    static final String RSA_LINE = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjzAgXacYXzEtXmjjd9jisg3Ew98kmqHF2cbQzV"
        + "JzK2Pv1hsoVXRObO/ep1OLZo9Z0s6d7ejnVSbYhFjIk5IhU8p/NCVr1GKLdaJQWfSztfWovQK67O0/ZeEa2rhq1f9B57Cw39lrgjtgjU+vI"
        + "4FF6JFbK7+nPojGKgX90/7pPAOcfL7a/nJhciB8e4MdhPNFSPocKYt3AoZdCLboGWvM9XZg8zksjEOGDOGAvl5i2J53St21GJxcqVlSOtP"
        + "qs5Q/tTzIk4eJMvjY7VO4Un3Mfgb4vqkplxjbWH+6v5pLNkDB+ZW+W2qaI9wTVkLsTwKZhCzlhVEnjhZp9cub0ieqx rsa@test";

    @Test
    void shouldParseP256RecipientId() {
        ECPublicKey key = SshPublicKeyParser.fromRecipientId(P256_RECIPIENT_ID);

        byte[] q = Arrays.copyOfRange(Base64.getDecoder().decode(P256_BLOB), 39, 104);
        assertEquals(new BigInteger(1, Arrays.copyOfRange(q, 1, 33)), key.getW().getAffineX());
        assertEquals(new BigInteger(1, Arrays.copyOfRange(q, 33, 65)), key.getW().getAffineY());
        assertEquals(256, key.getParams().getCurve().getField().getFieldSize());
    }

    @Test
    void shouldParseOpenSshLineToSameKey() {
        assertEquals(SshPublicKeyParser.fromRecipientId(P256_RECIPIENT_ID),
            SshPublicKeyParser.fromOpenSshLine(P256_LINE));
    }

    @Test
    void recipientIdShouldNotDependOnComment() {
        String withoutComment = "ecdsa-sha2-nistp256 " + P256_BLOB;
        String otherComment = "ecdsa-sha2-nistp256  " + P256_BLOB + "  someone else@host  \n";

        assertEquals(P256_RECIPIENT_ID, SshPublicKeyParser.recipientIdFromOpenSshLine(P256_LINE));
        assertEquals(P256_RECIPIENT_ID, SshPublicKeyParser.recipientIdFromOpenSshLine(withoutComment));
        assertEquals(P256_RECIPIENT_ID, SshPublicKeyParser.recipientIdFromOpenSshLine(otherComment));
    }

    @Test
    void recipientIdShouldBeCanonicalBase64() {
        String unpadded = P256_BLOB.substring(0, P256_BLOB.length() - 1);
        assertEquals(P256_RECIPIENT_ID,
            SshPublicKeyParser.recipientIdFromOpenSshLine("ecdsa-sha2-nistp256 " + unpadded));
    }

    @Test
    void blobShouldRoundTrip() {
        byte[] blob = SshPublicKeyParser.blobFromRecipientId(P256_RECIPIENT_ID);
        assertArrayEquals(Base64.getDecoder().decode(P256_BLOB), blob);
        assertEquals(P256_RECIPIENT_ID, SshPublicKeyParser.recipientIdFromBlob(blob));
    }

    @Test
    void shouldRejectEd25519() {
        var ex = assertThrows(InvalidSshPublicKeyException.class,
            () -> SshPublicKeyParser.fromOpenSshLine(ED25519_LINE));
        assertEquals(Reason.UNSUPPORTED_KEY_TYPE, ex.getReason());
        assertTrue(ex.getMessage().contains("ssh-ed25519"), ex.getMessage());
    }

    @Test
    void shouldRejectRsa() {
        var ex = assertThrows(InvalidSshPublicKeyException.class,
            () -> SshPublicKeyParser.recipientIdFromOpenSshLine(RSA_LINE));
        assertEquals(Reason.UNSUPPORTED_KEY_TYPE, ex.getReason());
        assertTrue(ex.getMessage().contains("ssh-rsa"), ex.getMessage());
    }

    @Test
    void shouldRejectP384() {
        var ex = assertThrows(InvalidSshPublicKeyException.class,
            () -> SshPublicKeyParser.fromOpenSshLine(P384_LINE));
        assertEquals(Reason.UNSUPPORTED_KEY_TYPE, ex.getReason());
        assertTrue(ex.getMessage().contains("ecdsa-sha2-nistp384"), ex.getMessage());
    }

    @Test
    void shouldRejectWrongCurveName() {
        byte[] q = Arrays.copyOfRange(Base64.getDecoder().decode(P256_BLOB), 39, 104);
        byte[] blob = sshBlob("ecdsa-sha2-nistp256".getBytes(StandardCharsets.US_ASCII),
            "nistp384".getBytes(StandardCharsets.US_ASCII), q);

        var ex = assertThrows(InvalidSshPublicKeyException.class,
            () -> SshPublicKeyParser.fromBlob(blob));
        assertEquals(Reason.CURVE_MISMATCH, ex.getReason());
    }

    @Test
    void shouldRejectMissingPrefix() {
        var ex = assertThrows(InvalidSshPublicKeyException.class,
            () -> SshPublicKeyParser.fromRecipientId("private/pk/" + P256_BLOB));
        assertEquals(Reason.MISSING_PREFIX, ex.getReason());

        ex = assertThrows(InvalidSshPublicKeyException.class,
            () -> SshPublicKeyParser.fromRecipientId("etsi/PNOEE-48010010101"));
        assertEquals(Reason.MISSING_PREFIX, ex.getReason());
    }

    @Test
    void shouldRejectMalformedBase64() {
        var ex = assertThrows(InvalidSshPublicKeyException.class,
            () -> SshPublicKeyParser.fromRecipientId("ruhnu/pk/not*base64!"));
        assertEquals(Reason.MALFORMED_BASE64, ex.getReason());

        ex = assertThrows(InvalidSshPublicKeyException.class,
            () -> SshPublicKeyParser.fromOpenSshLine("ecdsa-sha2-nistp256 %%%%"));
        assertEquals(Reason.MALFORMED_BASE64, ex.getReason());
    }

    @Test
    void shouldRejectTruncatedBlob() {
        byte[] blob = Base64.getDecoder().decode(P256_BLOB);
        for (int len : new int[] {0, 3, 10, 30, 40, 103}) {
            String id = "ruhnu/pk/" + Base64.getEncoder().encodeToString(Arrays.copyOf(blob, len));
            var ex = assertThrows(InvalidSshPublicKeyException.class,
                () -> SshPublicKeyParser.fromRecipientId(id), "length " + len);
            assertEquals(Reason.MALFORMED_KEY, ex.getReason(), "length " + len);
        }
    }

    @Test
    void shouldRejectTrailingData() {
        byte[] blob = Arrays.copyOf(Base64.getDecoder().decode(P256_BLOB), 105);
        var ex = assertThrows(InvalidSshPublicKeyException.class, () -> SshPublicKeyParser.fromBlob(blob));
        assertEquals(Reason.MALFORMED_KEY, ex.getReason());
    }

    @Test
    void shouldRejectGarbageBlob() {
        byte[] garbage = new byte[64];
        Arrays.fill(garbage, (byte) 0xff);
        var ex = assertThrows(InvalidSshPublicKeyException.class, () -> SshPublicKeyParser.fromBlob(garbage));
        assertEquals(Reason.MALFORMED_KEY, ex.getReason());
    }

    @Test
    void shouldRejectPointNotOnCurve() {
        byte[] blob = Base64.getDecoder().decode(P256_BLOB);
        blob[blob.length - 1] ^= 0x01;
        var ex = assertThrows(InvalidSshPublicKeyException.class, () -> SshPublicKeyParser.fromBlob(blob));
        assertEquals(Reason.MALFORMED_KEY, ex.getReason());
    }

    @Test
    void shouldRejectCompressedPoint() {
        byte[] q = Arrays.copyOfRange(Base64.getDecoder().decode(P256_BLOB), 39, 72);
        q[0] = 0x02;
        byte[] blob = sshBlob("ecdsa-sha2-nistp256".getBytes(StandardCharsets.US_ASCII),
            "nistp256".getBytes(StandardCharsets.US_ASCII), q);
        var ex = assertThrows(InvalidSshPublicKeyException.class, () -> SshPublicKeyParser.fromBlob(blob));
        assertEquals(Reason.MALFORMED_KEY, ex.getReason());
    }

    @Test
    void shouldRejectLineWithMismatchingKeyType() {
        var ex = assertThrows(InvalidSshPublicKeyException.class,
            () -> SshPublicKeyParser.fromOpenSshLine("ssh-ed25519 " + P256_BLOB));
        assertEquals(Reason.MALFORMED_KEY, ex.getReason());

        ex = assertThrows(InvalidSshPublicKeyException.class,
            () -> SshPublicKeyParser.fromOpenSshLine(P256_BLOB));
        assertEquals(Reason.MALFORMED_KEY, ex.getReason());
    }

    static byte[] sshBlob(byte[]... fields) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] f : fields) {
            out.writeBytes(ByteBuffer.allocate(4).putInt(f.length).array());
            out.writeBytes(f);
        }
        return out.toByteArray();
    }
}
