package ee.cyber.cdoc2.auth;

import ee.cyber.cdoc2.auth.exception.InvalidEtsiSemanticsIdentifierException;

import java.util.Objects;

/**
 * Natural person semantics identifier from ETSI319412-1, example "etsi/PNOEE-48010010101"
 * @see <a href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941201/01.04.02_20/en_31941201v010402a.pdf">
 *     ETSI319412-1</a>
 */
public final class EtsiIdentifier {

    public static final String PREFIX = "etsi/";

    private static final int MIN_LEN = (PREFIX + "PNOEE-0").length();
    private static final int HYPHEN_POS = (PREFIX + "PNOEE-0").indexOf("-");

    private static final int IDENTITY_TYPE_START = PREFIX.length();
    private static final int IDENTITY_TYPE_END = IDENTITY_TYPE_START + "PNO".length();

    private static final int COUNTRY_CODE_START = (PREFIX + "PNO").length();
    private static final int COUNTRY_CODE_END = COUNTRY_CODE_START + "EE".length();

    private static final int IDENTIFIER_START = (PREFIX + "PNOEE-").length();

    private final String etsiSemanticsIdentifier;

    // fields parsed from etsiSemanticsIdentifier
    private final IdentityType identityType;
    private final String countryCode;
    private final String identifier;
    /**
     * Etsi Semantics Identifier. Format "etsi/:semantics-identifier" as in ETSI319412 - 1
     * @param etsi etsi semantic identifier, for example "etsi/PNOEE-48010010101"
     * @throws InvalidEtsiSemanticsIdentifierException when etsi is not in expected format
     * @see <a href="https://github.com/SK-EID/smart-id-documentation?tab=readme-ov-file#2322-etsisemantics-identifier">
     *     Etsi Semantics Identifier
     *     </a>
     */
    public EtsiIdentifier(String etsi) throws InvalidEtsiSemanticsIdentifierException {
        validateEtsiSemanticsIdentifier(etsi);
        this.etsiSemanticsIdentifier = etsi; // Full identifier with prefix "etsi/PNOEE-48010010101"

        this.identityType = parseIdentityType(etsi); // "PNO"
        this.countryCode = parseCountryCode(etsi); // "EE"
        this.identifier = parseIdentifier(etsi);    // "48010010101"
    }

    /**
     * Get prefix that specifies identifier type.
     * @return "etsi/"
     */
    public String getPrefix() {
        return PREFIX;
    }

    /**
     * For "etsi/PNOEE-48010010101" returns "48010010101"
     * @return identifier part of semantics identifier (part after '-')
     */
    public String getIdentifier() {
        return this.identifier;
    }

    /**
     * For "etsi/PNOEE-48010010101" returns "EE"
     */
    public String getCountryCode() {
        return this.countryCode;
    }

    /**
     * For "etsi/PNOEE-48010010101" returns "PNO"
     */
    public IdentityType getIdentityType() {
        return this.identityType;
    }

    /**
     * @return identifier without prefix "etsi/", example "PNOEE-48010010101"
     */
    public String getSemanticsIdentifier() {
        return this.etsiSemanticsIdentifier.substring(IDENTITY_TYPE_START);
    }

    private void validateEtsiSemanticsIdentifier(String etsi) throws InvalidEtsiSemanticsIdentifierException {
        Objects.requireNonNull(etsi);

        if (!etsi.startsWith(PREFIX)) {
            throw new InvalidEtsiSemanticsIdentifierException(etsi + "doesn't start with " + PREFIX);
        }

        if (etsi.length() < MIN_LEN) {
            throw new InvalidEtsiSemanticsIdentifierException(etsi + " is too short");
        }

        if (etsi.charAt(HYPHEN_POS) != '-') {
            throw new InvalidEtsiSemanticsIdentifierException("- not found in expected position for " + etsi);
        }
    }

    private IdentityType parseIdentityType(String etsi) throws InvalidEtsiSemanticsIdentifierException {
        String type = etsi.substring(IDENTITY_TYPE_START, IDENTITY_TYPE_END);

        try {
            return IdentityType.valueOf(type);
        } catch (IllegalArgumentException e) {
            throw new InvalidEtsiSemanticsIdentifierException("Unknown identity type \"" + type + "\"");
        }
    }

    /**
     * Parse ISO 3166-1 alpha-2 two-letter country code from etsi
     * @param etsi etsi semantic identifier, for example "etsi/PNOEE-48010010101"
     * @return two-letter country code
     */
    private String parseCountryCode(String etsi) {
        String cc =  etsi.substring(COUNTRY_CODE_START, COUNTRY_CODE_END);
        if (!cc.matches("[A-Z]+")) {
            throw new InvalidEtsiSemanticsIdentifierException("Country code \""
                + cc + "\" should contain only uppercase characters ");
        }
        return cc;
    }

    /**
     * Parse identifier from etsi semantic identifier. Return "48010010101" from "etsi/PNOEE-48010010101"
     * @param etsi etsi semantic identifier, for example "etsi/PNOEE-48010010101"
     * @return identifier
     */
    private String parseIdentifier(String etsi) {
        return etsi.substring(IDENTIFIER_START);
    }

    /**
     * Return full etsi semantics identifier "etsi/:semantics-identifier", for example "etsi/PNOEE-48010010101"
     * @return full etsi semantics identifier
     */
    public String toString() {
        return this.etsiSemanticsIdentifier;
    }

    public enum IdentityType {
        /** for identification based on passport number */
        PAS,
        /** for identification based on national identity card number */
        IDC,
        /** for identification based on (national) personal number (national civic registration number) */
        PNO
    }
}
