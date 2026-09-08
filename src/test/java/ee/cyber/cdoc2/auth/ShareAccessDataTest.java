package ee.cyber.cdoc2.auth;

import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.*;

class ShareAccessDataTest {

    @Test
    void fromURL() throws MalformedURLException {
        URL url = new URL("https://cdoc-ccs.ria.ee:443/key-shares/9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3"
             + "?nonce=649a44d6cd9827cae3f3df04fd5eda98246d2dde");
        ShareAccessData data = ShareAccessData.fromURL(url);
        assertEquals("https://cdoc-ccs.ria.ee:443", data.getServerBaseUrl());
        assertEquals("9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3", data.getShareId());
        assertEquals("649a44d6cd9827cae3f3df04fd5eda98246d2dde", data.getNonce());

        assertEquals(url, data.toURL());
    }

    @Test
    void fromURLWithAdditionalBasePath() throws MalformedURLException {
        URL url = new URL(
            "https://cdoc-ccs.ria.ee:443/other/path/key-shares/9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3"
                + "?nonce=649a44d6cd9827cae3f3df04fd5eda98246d2dde");
        ShareAccessData data = ShareAccessData.fromURL(url);
        assertEquals("https://cdoc-ccs.ria.ee:443/other/path", data.getServerBaseUrl());
        assertEquals("9EE90F2D-D946-4D54-9C3D-F4C68F7FFAE3", data.getShareId());
        assertEquals("649a44d6cd9827cae3f3df04fd5eda98246d2dde", data.getNonce());
        assertEquals(url, data.toURL());
    }
}
