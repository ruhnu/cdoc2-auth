package ee.cyber.cdoc2.auth;

import java.security.SignatureException;
import java.util.List;
import java.util.Map;

import com.authlete.hms.ComponentValueProvider;
import com.authlete.hms.SignatureBase;
import com.authlete.hms.SignatureBaseBuilder;
import com.authlete.hms.SignatureField;
import com.authlete.hms.SignatureInputField;
import com.authlete.hms.SignatureMetadata;
import com.authlete.hms.SignatureMetadataParameters;
import com.authlete.hms.impl.JoseHttpVerifier;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;


import ee.cyber.cdoc2.auth.exception.VerificationException;

public final class RpHttpSignatureVerifier {
    private static final String RP_SIGNATURE_LABEL = "rp-sig";

    private RpHttpSignatureVerifier() {
        // utility class
    }

    static void verify(RpHttpSignatureParams httpSignatureParams) throws VerificationException {
        SignatureInputField signatureInputField;
        SignatureField signatureField;

        try {
            signatureInputField = SignatureInputField.parse(httpSignatureParams.singingInput());
            signatureField = SignatureField.parse(httpSignatureParams.signature);
        } catch (SignatureException e) {
            throw new VerificationException(e.getMessage());
        }

        SignatureMetadata signatureMetadata = signatureInputField.get(RP_SIGNATURE_LABEL);

        if (signatureMetadata == null) {
            throw new VerificationException("No HTTP signature metadata found for "
                + "expected label: " + RP_SIGNATURE_LABEL);
        }

        SignatureMetadataParameters params = signatureMetadata.getParameters();
        String keyId = params.getKeyid();
        JWK jwk = httpSignatureParams.jwtPublicKeys.stream()
            .filter(k -> k.getKeyID().equals(keyId))
            .findFirst()
            .orElseThrow(
                () -> new VerificationException("Could not find matching well-know key for keyId "
                    + keyId)
            );

        ECKey ecKey = jwk.getAlgorithm() != null
            ? jwk.toECKey()
            : new ECKey.Builder(jwk.toECKey())
              .algorithm(JWSAlgorithm.ES256)
              .build();

        byte[] signature = signatureField.get(RP_SIGNATURE_LABEL);

        if (signature == null) {
            throw new VerificationException("No HTTP signature found for "
                + "expected label: " + RP_SIGNATURE_LABEL);
        }

        ComponentValueProvider context = new ComponentValueProvider()
            .setHeaders(Map.of(
                    "x-rp-signed-hash", List.of(httpSignatureParams.rpSignedHash),
                    "x-rp-name", List.of(httpSignatureParams.rpName)
                )
            );

        try {
            SignatureBase signatureBase =
                new SignatureBaseBuilder(context).build(signatureMetadata);
            boolean isValid = signatureBase.verify(new JoseHttpVerifier(ecKey), signature);

            if (!isValid) {
                throw new VerificationException("HTTP signature verification failed");
            }
        } catch (SignatureException e) {
            throw new VerificationException(e.getMessage());
        }
    }

    public record RpHttpSignatureParams(
        String rpSignedHash,
        String rpName,
        String singingInput,
        String signature,
        List<JWK> jwtPublicKeys
    ) {
    }
}
