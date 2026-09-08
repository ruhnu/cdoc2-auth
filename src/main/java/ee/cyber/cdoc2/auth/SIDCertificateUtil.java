package ee.cyber.cdoc2.auth;

import ee.cyber.cdoc2.auth.exception.IllegalCertificateException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * Methods for parsing Smart-ID certificate
 * @see <a href="https://www.skidsolutions.eu/wp-content/uploads/2024/10/SK-CPR-SMART-ID-EN-v4_7-20241127.pdf">
 *     Certificate and OCSP Profile for Smart-ID v4.7</a>
 */
public final class SIDCertificateUtil {
    private static final Logger log = LoggerFactory.getLogger(SIDCertificateUtil.class);

    private SIDCertificateUtil() {
        // utility class
    }

    /**
     * Parse serialNumber from certificate subjectDN serialNumber
     * (example subjectDN='SERIALNUMBER=PNOEE-30303039914, GIVENNAME=OK, SURNAME=TESTNUMBER, CN="TESTNUMBER,OK", C=EE')
     * @param sidCert smart-id certificate
     * @return semanticsIdentifier as String (for example PNOEE-30303039914)
     * @throws IllegalCertificateException when certificate subjectDN doesn't contain SERIALNUMBER field
     *     or subjectDN is erroneous
     */
    public static String getSemanticsIdentifier(X509Certificate sidCert)  throws IllegalCertificateException {
        X500Principal subjectX500Principal = sidCert.getSubjectX500Principal();
        var knownOids = Map.of(
            "2.5.4.5", "serialNumber",
            "2.5.4.42", "givenName",
            "2.5.4.4", "surname");

        // X500Principal in Java 17 doesn't know about knowOids, although deprecated getSubjectDN is able to parse those
        // subjectDN='SERIALNUMBER=PNOEE-30303039914, GIVENNAME=OK, SURNAME=TESTNUMBER, CN="TESTNUMBER,OK", C=EE'
        String subjectDN = subjectX500Principal.getName(X500Principal.RFC2253, knownOids);

        try {
            LdapName ln = new LdapName(subjectDN); // throws InvalidNameException

            for (Rdn rdn : ln.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("serialNumber")) {
                    return rdn.getValue().toString();
                }
            }
            log.warn("serialNumber not found from subjectDN {}", subjectDN);
        } catch (InvalidNameException ine) {
            throw new IllegalCertificateException("Invalid subjectDN", ine);
        }
        throw new IllegalCertificateException("Error getting serialNumber from certificate subjectDN");
    }
}
