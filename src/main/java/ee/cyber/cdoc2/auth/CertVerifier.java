package ee.cyber.cdoc2.auth;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import ee.cyber.cdoc2.auth.exception.VerificationException;

public class CertVerifier {
    private static final Logger log = LoggerFactory.getLogger(CertVerifier.class);

    private KeyStore trustStore;
    private boolean revocationCheckEnabled;

    public CertVerifier(KeyStore trustStore, boolean enableRevocationChecks) {
        // enable certpath validation debug logging by setting security property
        // -Djava.security.debug=certpath.ocsp,ocsp,verbose

        // ocsp.enable=true must be set to enable revocation checks over OCSP
        // revocation checks are enabled/disabled with PKIXParameters.setRevocationEnabled(revocationCheckEnabled)
        // https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/ocsp.html#ocsp-pki
        Security.setProperty("ocsp.enable", "true");
        // disable fallback for revocation checks using CRL
        Security.setProperty("com.sun.security.enableCRLDP", "false");

        this.trustStore = trustStore;
        this.revocationCheckEnabled = enableRevocationChecks;
    }

    /**
     * <ul>
     * <li> Validates certificate issuer using trustStore
     * <li> Check that certificate is not expired
     * </ul>
     *
     * @param cert certificate to validate
     * @throws VerificationException
     */
    public void checkCertificate(X509Certificate cert) throws VerificationException {

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath certPath = cf.generateCertPath(Collections.singletonList(cert));

            // Initialize PKIXParameters
            PKIXParameters pkixParams = new PKIXParameters(this.trustStore);

            // SK ocsp demo env is a minefield 💣
            // https://github.com/SK-EID/ocsp/wiki/SK-OCSP-Demo-environment
            // experimental, doesn't work for SK demo env, as SK demo env doesn't support OCSP requests using HTTP GET
            // , which Java uses
            pkixParams.setRevocationEnabled(revocationCheckEnabled);

            CertPathValidator validator = CertPathValidator.getInstance("PKIX");

            validator.validate(certPath, pkixParams); // if the CertPath does not validate,
            // an CertPathValidatorException will be thrown
            Date now = new Date();
            if (now.after(cert.getNotAfter())) {
                throw new VerificationException("Certificate expired on " + cert.getNotAfter());
            }

        } catch (NoSuchAlgorithmException | CertificateException | CertPathValidatorException
                 | KeyStoreException
                 | InvalidAlgorithmParameterException e) {
            throw new VerificationException("Certificate validation error", e);
        }
    }
}
