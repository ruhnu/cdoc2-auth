package ee.cyber.cdoc2.auth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import ee.cyber.cdoc2.auth.exception.InvalidDidRecipientException;
import ee.cyber.cdoc2.auth.exception.InvalidDidRecipientException.Reason;
import ee.cyber.cdoc2.auth.exception.InvalidSshPublicKeyException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DidRecipientIdTest {

    static final String DID = "did:web:example.org:p:alice";

    // ssh-keygen -lf src/test/resources/ssh-agent-token-key.pub:
    // 256 SHA256:oZju0C+SXt4iEJ/9//i8XZ0zerYE0Ra+N3S+FgcPssM cdoc2-auth-fixture (ECDSA)
    static final String FIXTURE_OPENSSH_FINGERPRINT = "SHA256:oZju0C+SXt4iEJ/9//i8XZ0zerYE0Ra+N3S+FgcPssM";
    static final String FIXTURE_FINGERPRINT = "oZju0C-SXt4iEJ_9__i8XZ0zerYE0Ra-N3S-FgcPssM";
    static final String FIXTURE_RECIPIENT_ID = "ruhnu/did/" + DID + "/hash/" + FIXTURE_FINGERPRINT;

    @Test
    void shouldBuildIdentifierFromDidAndKey() throws Exception {
        byte[] blob = fixtureBlob();

        DidRecipientId id = DidRecipientId.of(DID, blob);

        assertEquals(FIXTURE_RECIPIENT_ID, id.toString());
        assertEquals(DID, id.did());
        assertEquals(FIXTURE_FINGERPRINT, id.fingerprint());
        assertEquals(FIXTURE_OPENSSH_FINGERPRINT, id.openSshFingerprint());
        assertTrue(id.matches(blob));
        assertFalse(id.matches(Base64.getDecoder().decode(SshPublicKeyParserTest.P256_BLOB)));
    }

    @Test
    void shouldParseIdentifier() {
        DidRecipientId id = DidRecipientId.parse(FIXTURE_RECIPIENT_ID);

        assertEquals(DID, id.did());
        assertEquals(FIXTURE_FINGERPRINT, id.fingerprint());
        assertEquals(FIXTURE_RECIPIENT_ID, id.toString());
        assertEquals(id, DidRecipientId.of(DID, fixtureBlobUnchecked()));

        String withPort = "ruhnu/did/did:web:example.org%3A8443:p:alice/hash/" + FIXTURE_FINGERPRINT;
        assertEquals(8443, DidRecipientId.parse(withPort).didWeb().port());
        assertEquals(withPort, DidRecipientId.parse(withPort).toString());
    }

    @Test
    void shouldRecogniseKind() {
        assertTrue(DidRecipientId.isDidRecipientId(FIXTURE_RECIPIENT_ID));
        assertTrue(DidRecipientId.isDidRecipientId("ruhnu/did/garbage"));
        assertFalse(DidRecipientId.isDidRecipientId(SshPublicKeyParserTest.P256_RECIPIENT_ID));
        assertFalse(DidRecipientId.isDidRecipientId("etsi/PNOEE-48010010101"));
        assertFalse(DidRecipientId.isDidRecipientId(null));
    }

    @Test
    void shouldRejectOtherKinds() {
        assertReason(Reason.MISSING_PREFIX, SshPublicKeyParserTest.P256_RECIPIENT_ID);
        assertReason(Reason.MISSING_PREFIX, "did:web:example.org/hash/" + FIXTURE_FINGERPRINT);
    }

    @Test
    void shouldRejectInvalidDids() {
        assertReason(Reason.UNSUPPORTED_METHOD, "ruhnu/did/did:key:zDnaeXyz/hash/" + FIXTURE_FINGERPRINT);
        assertReason(Reason.INVALID_DID, "ruhnu/did/did:web:192.0.2.1/hash/" + FIXTURE_FINGERPRINT);
        assertReason(Reason.TOO_LONG,
            "ruhnu/did/did:web:example.org:p:" + "a".repeat(200) + "/hash/" + FIXTURE_FINGERPRINT);
    }

    @Test
    void shouldRejectMalformedStructure() {
        // extra path segment
        assertReason(Reason.INVALID_DID, "ruhnu/did/did:web:example.org/extra/hash/" + FIXTURE_FINGERPRINT);
        // other label than "hash"
        assertReason(Reason.INVALID_DID, "ruhnu/did/" + DID + "/sha256/" + FIXTURE_FINGERPRINT);
        // missing fingerprint part
        assertReason(Reason.INVALID_DID, "ruhnu/did/" + DID);
        assertReason(Reason.INVALID_DID, "ruhnu/did/" + DID + "/hash");
    }

    @Test
    void shouldRejectMalformedFingerprints() {
        String prefix = "ruhnu/did/" + DID + "/hash/";
        // padded
        assertReason(Reason.INVALID_FINGERPRINT, prefix + FIXTURE_FINGERPRINT + "=");
        // short
        assertReason(Reason.INVALID_FINGERPRINT, prefix + FIXTURE_FINGERPRINT.substring(1));
        // empty
        assertReason(Reason.INVALID_FINGERPRINT, prefix);
        // standard base64 instead of base64url: contains '+' (and '/', which changes the structure)
        assertReason(Reason.INVALID_FINGERPRINT, prefix + FIXTURE_FINGERPRINT.replace('-', '+'));
        // non-canonical: last character with non-zero trailing bits ('M' is 001100, 'N' is 001101)
        assertTrue(FIXTURE_FINGERPRINT.endsWith("M"));
        String nonCanonical = FIXTURE_FINGERPRINT.substring(0, 42) + "N";
        assertReason(Reason.INVALID_FINGERPRINT, prefix + nonCanonical);
    }

    @Test
    void shouldRejectUnsupportedKeys() {
        byte[] ed25519 = Base64.getDecoder().decode(SshPublicKeyParserTest.ED25519_LINE.split(" ")[1]);

        assertThrows(InvalidSshPublicKeyException.class, () -> DidRecipientId.of(DID, ed25519));
    }

    static byte[] fixtureBlob() throws Exception {
        try (var in = DidRecipientIdTest.class.getClassLoader().getResourceAsStream("ssh-agent-token-key.pub")) {
            String line = new String(in.readAllBytes(), StandardCharsets.US_ASCII).strip();
            return Base64.getDecoder().decode(line.split(" ")[1]);
        }
    }

    private static byte[] fixtureBlobUnchecked() {
        try {
            return fixtureBlob();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void assertReason(Reason expected, String recipientId) {
        var ex = assertThrows(InvalidDidRecipientException.class, () -> DidRecipientId.parse(recipientId),
            recipientId);
        assertEquals(expected, ex.getReason(), recipientId + ": " + ex.getMessage());
    }
}
