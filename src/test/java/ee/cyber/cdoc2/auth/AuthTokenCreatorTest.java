package ee.cyber.cdoc2.auth;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import com.authlete.sd.SDJWT;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthTokenCreatorTest {

    private static final ShareAccessData SHARE =
        new ShareAccessData("https://localhost:8443", "9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3", "59b314d4815f21f7");

    @Test
    void shouldPutPublicKeyIntoJwkHeader() throws Exception {
        KeyPair keyPair = SshPkAuthTokenVerifierTest.generateP256KeyPair();
        ECKey privateJwk = new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
            .privateKey((ECPrivateKey) keyPair.getPrivate())
            .build();

        AuthTokenCreator creator = AuthTokenCreator.builder()
            .withIssuer("ruhnu/did/did:web:example.org/hash/x")
            .withShareAccessData(SHARE)
            .withHeaderJwk(privateJwk)
            .build();
        creator.sign(new com.nimbusds.jose.crypto.ECDSASigner(privateJwk));

        SignedJWT jwt = SignedJWT.parse(SDJWT.parse(creator.createToken(0)).getCredentialJwt());
        JWK headerJwk = jwt.getHeader().getJWK();
        assertFalse(headerJwk.isPrivate());
        assertEquals(privateJwk.toPublicJWK(), headerJwk);
        assertEquals(Constants.TYPE_AUTH_TOKEN, jwt.getHeader().getType().toString());
        assertTrue(jwt.verify(new ECDSAVerifier(headerJwk.toECKey())));
    }

    @Test
    void shouldHaveNoJwkHeaderByDefault() throws Exception {
        KeyPair keyPair = SshPkAuthTokenVerifierTest.generateP256KeyPair();
        AuthTokenCreator creator = SshPkAuthTokenVerifierTest.signedCreator(
            SshPkAuthTokenVerifierTest.recipientId((ECPublicKey) keyPair.getPublic()), keyPair, SHARE);

        SignedJWT jwt = SignedJWT.parse(SDJWT.parse(creator.createToken(0)).getCredentialJwt());

        assertNull(jwt.getHeader().getJWK());
    }
}
