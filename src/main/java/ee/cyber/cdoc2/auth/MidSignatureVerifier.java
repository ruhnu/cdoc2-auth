package ee.cyber.cdoc2.auth;

import java.security.cert.X509Certificate;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

import ee.cyber.cdoc2.auth.exception.VerificationException;

final class MidSignatureVerifier {

    private MidSignatureVerifier() {
        // utility class
    }

    static void verify(
        SignedJWT signedJWT,
        X509Certificate cert
    ) throws VerificationException {

        try {
            JWSVerifier jwsVerifier = createJWSVerifier(cert);
            if (signedJWT.verify(jwsVerifier)) {
                return;
            }
        } catch (JOSEException e) {
            throw new VerificationException(e.getMessage());
        }

        throw new VerificationException("MID signature verification failure");
    }

    private static JWSVerifier createJWSVerifier(X509Certificate cert)
        throws VerificationException, JOSEException {

        String subjectSerial = SIDCertificateUtil.getSemanticsIdentifier(cert);
        String publicKeyAlgorithm = cert.getPublicKey().getAlgorithm();

        if (SupportedAlgorithm.EC.name().equals(publicKeyAlgorithm)) {
            return createECVerifier(cert, subjectSerial);
        } else if (SupportedAlgorithm.RSA.name().equals(publicKeyAlgorithm)) {
            return createRSAVerifier(cert, subjectSerial);
        }

        throw new VerificationException("Unsupported public key algorithm: " + publicKeyAlgorithm);
    }

    private static JWSVerifier createECVerifier(X509Certificate cert, String keyId)
        throws JOSEException, VerificationException {

        if (keyId == null) {
            throw new VerificationException("Expected kid for public EC key");
        }

        ECKey pubECKey = new ECKey.Builder(ECKey.parse(cert))
            .keyID(keyId)
            .build();

        return new ECDSAVerifier(pubECKey);
    }

    private static JWSVerifier createRSAVerifier(X509Certificate cert, String keyId)
        throws JOSEException, VerificationException {

        if (keyId == null) {
            throw new VerificationException("Expected kid for public RSA key");
        }

        RSAKey pubRSAKey = new RSAKey.Builder(RSAKey.parse(cert))
            .keyID(keyId)
            .build();

        return new RSASSAVerifier(pubRSAKey);
    }

    private enum SupportedAlgorithm {
        EC,
        RSA
    }
}
