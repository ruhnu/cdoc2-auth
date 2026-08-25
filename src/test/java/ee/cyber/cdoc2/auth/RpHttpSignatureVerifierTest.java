package ee.cyber.cdoc2.auth;

import java.text.ParseException;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.JWK;

import ee.cyber.cdoc2.auth.exception.VerificationException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RpHttpSignatureVerifierTest {

    private static final String CS_RP_SIGNED_HASH = "sj2RtSo7c1tx+J00KWWkzyv4iQ2L2cuX0InnFFi+GAQ=";
    private static final String CS_RP_NAME = "DEMO";
    private static final String CS_SIGNATURE_INPUT =
        "rp-sig=(\"x-rp-signed-hash\" \"x-rp-name\");created=1779011296;keyid=\"rp-server-ec-key-2026\"";
    private static final String CS_SIGNATURE =
        "rp-sig=:nt5aITnpc8JjVrOYw8q46bNieq9L7y8gBjw+rJJ7BoY4X3h8BL5PwwcUBzl70iTOvikGCBOmpjbDY1661EqMMA==:";

    private static final String RP_SERVER_WELL_KNOWN_JWK_JSON = """
        {
          "kty": "EC",
          "crv": "P-256",
          "x": "SIsDcu6c2CjOEIxZyh4ctZZA-zz4pFYv0duHPlNWinU",
          "y": "50dC54PpOVtBHBGyzW1S6DgaBts-ywY3KgOclSIV97M",
          "use": "enc",
          "kid": "rp-server-ec-key-2026"
        }
        """;

    private static final String JWK_DIFFERENT_KID = """
        {
          "kty": "EC",
          "crv": "P-256",
          "x": "SIsDcu6c2CjOEIxZyh4ctZZA-zz4pFYv0duHPlNWinU",
          "y": "50dC54PpOVtBHBGyzW1S6DgaBts-ywY3KgOclSIV97M",
          "use": "enc",
          "kid": "some-other-key-id"
        }
        """;

    @Test
    void verifiesValidSignature() throws ParseException {
        RpHttpSignatureVerifier.RpHttpSignatureParams params = defaultParams();

        assertDoesNotThrow(() -> RpHttpSignatureVerifier.verify(params));
    }

    @Test
    void throwsOnMalformedSignatureInputHeader() throws ParseException {
        RpHttpSignatureVerifier.RpHttpSignatureParams params =
            new RpHttpSignatureVerifier.RpHttpSignatureParams(
                CS_RP_SIGNED_HASH,
                CS_RP_NAME,
                "this is not a valid RFC9421 Signature-Input header",
                CS_SIGNATURE,
                List.of(JWK.parse(RP_SERVER_WELL_KNOWN_JWK_JSON))
            );

        assertThrows(VerificationException.class,
            () -> RpHttpSignatureVerifier.verify(params));
    }

    @Test
    void throwsOnMalformedSignatureHeader() throws ParseException {
        RpHttpSignatureVerifier.RpHttpSignatureParams params =
            new RpHttpSignatureVerifier.RpHttpSignatureParams(
                CS_RP_SIGNED_HASH,
                CS_RP_NAME,
                CS_SIGNATURE_INPUT,
                "this is not a valid RFC9421 Signature header",
                List.of(JWK.parse(RP_SERVER_WELL_KNOWN_JWK_JSON))
            );

        assertThrows(VerificationException.class,
            () -> RpHttpSignatureVerifier.verify(params));
    }

    @Test
    void throwsWhenKeyIdNotFoundInJwks() throws ParseException {
        RpHttpSignatureVerifier.RpHttpSignatureParams params =
            new RpHttpSignatureVerifier.RpHttpSignatureParams(
                CS_RP_SIGNED_HASH,
                CS_RP_NAME,
                CS_SIGNATURE_INPUT,
                CS_SIGNATURE,
                List.of(JWK.parse(JWK_DIFFERENT_KID))
            );

        VerificationException exception = assertThrows(VerificationException.class,
            () -> RpHttpSignatureVerifier.verify(params));

        assertTrue(exception.getMessage()
                .contains("Could not find matching well-know key for keyId"),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void throwsWhenSignatureInputLabelMissing() throws ParseException {
        // Signature-Input uses label "other-label" but the verifier expects "rp-sig".
        String mismatchedInput =
            "other-label=(\"x-rp-signed-hash\" \"x-rp-name\");created=1779011296;keyid=\"rp-server-ec-key-2026\"";

        RpHttpSignatureVerifier.RpHttpSignatureParams params =
            new RpHttpSignatureVerifier.RpHttpSignatureParams(
                CS_RP_SIGNED_HASH,
                CS_RP_NAME,
                mismatchedInput,
                CS_SIGNATURE,
                List.of(JWK.parse(RP_SERVER_WELL_KNOWN_JWK_JSON))
            );

        VerificationException exception = assertThrows(VerificationException.class,
            () -> RpHttpSignatureVerifier.verify(params));

        assertTrue(exception.getMessage()
                .contains("No HTTP signature metadata found for expected label: rp-sig"),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void throwsWhenSignatureLabelMissing() throws ParseException {
        // Signature header uses label "other-sig" but Signature-Input declared "rp-sig", so the
        // metadata resolves fine but the actual signature bytes for "rp-sig" cannot be found.
        String differentLabelSignature =
            "other-sig=:nt5aITnpc8JjVrOYw8q46bNieq9L7y8gBjw+rJJ7BoY4X3h8BL5PwwcUBzl70iTOvikGCBOmpjbDY1661EqMMA==:";

        RpHttpSignatureVerifier.RpHttpSignatureParams params =
            new RpHttpSignatureVerifier.RpHttpSignatureParams(
                CS_RP_SIGNED_HASH,
                CS_RP_NAME,
                CS_SIGNATURE_INPUT,
                differentLabelSignature,
                List.of(JWK.parse(RP_SERVER_WELL_KNOWN_JWK_JSON))
            );

        VerificationException exception = assertThrows(VerificationException.class,
            () -> RpHttpSignatureVerifier.verify(params));

        assertTrue(exception.getMessage()
                .contains("No HTTP signature found for expected label: rp-sig"),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void throwsOnTamperedSignatureBytes() throws ParseException {
        // Flip one byte inside the base64 signature value, keeping the structure valid.
        String modified = flipFirstSignatureByte(CS_SIGNATURE);

        RpHttpSignatureVerifier.RpHttpSignatureParams params =
            new RpHttpSignatureVerifier.RpHttpSignatureParams(
                CS_RP_SIGNED_HASH,
                CS_RP_NAME,
                CS_SIGNATURE_INPUT,
                modified,
                List.of(JWK.parse(RP_SERVER_WELL_KNOWN_JWK_JSON))
            );

        VerificationException exception = assertThrows(VerificationException.class,
            () -> RpHttpSignatureVerifier.verify(params));

        assertTrue(exception.getMessage()
                .contains("HTTP signature verification failed"),
            "Actual message: " + exception.getMessage());
    }

    private RpHttpSignatureVerifier.RpHttpSignatureParams defaultParams() throws ParseException {
        return new RpHttpSignatureVerifier.RpHttpSignatureParams(
            CS_RP_SIGNED_HASH,
            CS_RP_NAME,
            CS_SIGNATURE_INPUT,
            CS_SIGNATURE,
            List.of(JWK.parse(RP_SERVER_WELL_KNOWN_JWK_JSON))
        );
    }

    private static String flipFirstSignatureByte(String signatureHeader) {
        int colonStart = signatureHeader.indexOf("=:");
        int colonEnd = signatureHeader.lastIndexOf(':');
        if (colonStart < 0 || colonEnd <= colonStart) {
            throw new IllegalArgumentException("Unexpected signature header format");
        }
        String base64 = signatureHeader.substring(colonStart + 2, colonEnd);
        byte[] decoded = java.util.Base64.getDecoder().decode(base64);
        decoded[0] = (byte) (decoded[0] ^ 0xFF);
        String mutated = java.util.Base64.getEncoder().encodeToString(decoded);
        return signatureHeader.substring(0, colonStart + 2)
            + mutated
            + signatureHeader.substring(colonEnd);
    }
}
