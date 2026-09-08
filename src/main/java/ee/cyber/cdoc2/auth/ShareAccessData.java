package ee.cyber.cdoc2.auth;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static ee.cyber.cdoc2.auth.Constants.KEY_SHARES_EP;
import static ee.cyber.cdoc2.auth.Constants.NONCE;

/**
 * Represents /key-shares/${shareId} access data used in auth token.
 * Auth token encodes share access data as URL that has the following format:
 * "https://host:443/key-shares/${shareId}?nonce=${nonce}"
 * For example
 * "https://cdoc-ccs.ria.ee:443/key-shares/9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3
 * ?nonce=649a44d6cd9827cae3f3df04fd5eda98246d2dde":
 * <ul>
 * <li> serverBaseUrl is "https://cdoc-ccs.ria.ee:443" (Note: /key-shares is OAS endpoint and not part of baseUrl)
 * <li> shareId is "9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3"
 * <li> nonce is "649a44d6cd9827cae3f3df04fd5eda98246d2dde"
 * </ul>
 */
public final class ShareAccessData {


    private final String serverBaseUrl;
    private final String shareId;
    private final String nonce;
    /**
     * /key-shares OAS endpoint data
     * @param serverBaseUrl key-shares api endpoint as "https://cdoc-css.ria.ee:443"
     * @param shareId shareId
     * @param nonce nonce returned by server /key-shares/${shareId}/nonce endpoint
     */

    public ShareAccessData(String serverBaseUrl, String shareId, String nonce) {
        Objects.requireNonNull(serverBaseUrl);
        Objects.requireNonNull(shareId);
        Objects.requireNonNull(nonce);

        this.serverBaseUrl = serverBaseUrl;
        this.shareId = shareId;
        this.nonce = nonce;
    }

    public String getShareId() {
        return this.shareId;
    }

    public String getNonce() {
        return this.nonce;
    }

    public String getServerBaseUrl() {
        return this.serverBaseUrl;
    }

    public URL toURL() throws MalformedURLException {
        return new URL(this.serverBaseUrl + KEY_SHARES_EP + "/" + this.shareId + "?" + NONCE + "=" + this.nonce);
    }

    public static ShareAccessData fromURL(URL url) throws MalformedURLException {
        Map<String, String> queryParams = decodeUrlQueryParameters(url.getQuery());
        String shareId = parseKeyShare(url.getPath());
        URL serverBaseUrl = parseServerBaseUrl(url);
        if (queryParams.containsKey(NONCE)) {
            return new ShareAccessData(
                serverBaseUrl.toString(),
                shareId,
                queryParams.get(NONCE)
            );
        }

        throw new MalformedURLException("Invalid share access url: " + url);
    }

    /**
     * Decodes urlencoded parameters into Map.
     * @param params urlencoded parameters. Example: "share=dGVzdAo%3D&recipient=etsi%2FPNOEE-48010010101"
     * @return map of decoded parameters. Example: {share=dGVzdAo=, recipient=etsi/PNOEE-48010010101}
     */
    private static Map<String, String> decodeUrlQueryParameters(String params) {
        if (params == null || params.isEmpty()) {
            return Map.of();
        }
        return Stream.of(params.split("&"))
            .map(param -> param.split("="))
            .collect(Collectors.toMap(
                pair -> URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
                pair -> pair.length > 1 ? URLDecoder.decode(pair[1], StandardCharsets.UTF_8) : ""));
    }

    /**
     * Parse key-share value from url path "/key-shares/${key-share-id}"
     * @param path url path to parse (without query parameters). Path may contain additional elements before key-share,
     *             example: /path-to/key-shares/1234
     * @return key-share-id that is sequence of characters after "/key-shares/"
     * @throws MalformedURLException if url path does not contain valid key-share
     */
    private static String parseKeyShare(String path) throws MalformedURLException {
        if (path == null || path.isEmpty()) {
            throw new MalformedURLException("Path is empty.");
        }

        Pattern pattern =
            Pattern.compile(".*" + KEY_SHARES_EP + "/([^/]+)(/.*)?"); // ([^/]+) sequence of characters not including /
                                                                 // (/.*)? any characters starting with / or nothing
        Matcher matcher = pattern.matcher(path);

        if (matcher.matches()) {
            return matcher.group(1);
        } else {
            throw new MalformedURLException("Path does not contain a valid key-share ID.");
        }
    }

    /**
     * Parse server base url from full /key-shares url
     * @param url full /key-shares url, examples:
     *            https://cdoc-ccs.ria.ee:8443/base/key-shares/123?nonce=649de"
     *            https://cdoc-ccs.ria.ee/base/key-shares/123?nonce=649de
     * @return part url that is before /key-shares
     * @throws MalformedURLException
     */
    private static URL parseServerBaseUrl(URL url) throws MalformedURLException {
        String path = url.getPath();
        int port = url.getPort();
        String portString = port == -1
            ? ""
            : ":" + port;

        String serverBaseUrl = url.getProtocol() + "://" + url.getHost() + portString
            + path.substring(0, path.indexOf(KEY_SHARES_EP));
        return new URL(serverBaseUrl);
    }
}
