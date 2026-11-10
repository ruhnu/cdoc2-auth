package ee.cyber.cdoc2.auth;

/**
 * Decides which DID hosts {@link DidWebResolver} may send a request to. The shares server allows only the hosts
 * an operator configured; clients that encrypt to a DID allow every host.
 */
@FunctionalInterface
public interface DidHostPolicy {

    /** Policy that allows every host */
    DidHostPolicy ALLOW_ALL = (host, port) -> true;

    /**
     * @param host host name from the DID, as written in the DID
     * @param port port from the DID, 443 when the DID has none
     * @return true if a request to this host and port may be sent
     */
    boolean allows(String host, int port);
}
