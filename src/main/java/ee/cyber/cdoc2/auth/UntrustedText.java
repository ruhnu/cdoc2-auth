package ee.cyber.cdoc2.auth;

/**
 * Makes text taken from a DID document safe to put into a log line, an exception message or a terminal: control and
 * format characters (line breaks, ANSI escape sequences, bidi overrides, ...) are shown as "\\uXXXX", and long values
 * are shortened. Whoever controls a DID document controls this text.
 */
final class UntrustedText {

    /** Longest value shown, in characters, before escaping */
    static final int MAX_SHOWN = 100;

    private UntrustedText() {
        // utility class
    }

    /**
     * @param value value from an untrusted document, may be null
     * @return printable form of {@code String.valueOf(value)}
     */
    static String printable(Object value) {
        String text = String.valueOf(value);
        boolean shortened = text.length() > MAX_SHOWN;
        if (shortened) {
            text = text.substring(0, MAX_SHOWN);
        }
        StringBuilder out = new StringBuilder(text.length());
        text.codePoints().forEach(codePoint -> {
            if (isUnsafe(codePoint)) {
                out.append(String.format("\\u%04x", codePoint));
            } else {
                out.appendCodePoint(codePoint);
            }
        });
        return shortened ? out.append("...").toString() : out.toString();
    }

    private static boolean isUnsafe(int codePoint) {
        int type = Character.getType(codePoint);
        // SURROGATE: a lone surrogate, also the one left when shortening splits a pair
        return Character.isISOControl(codePoint) || type == Character.FORMAT || type == Character.LINE_SEPARATOR
            || type == Character.PARAGRAPH_SEPARATOR || type == Character.SURROGATE;
    }
}
