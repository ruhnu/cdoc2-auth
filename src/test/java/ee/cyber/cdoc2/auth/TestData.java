package ee.cyber.cdoc2.auth;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.X509CertUtils;

/**
 * Input test data utility class.
 */
public final class TestData {

    //generated create-rsa-key-csr-crt-keystore.sh
    private static final String TEST_RSAKEY = """
        -----BEGIN RSA PRIVATE KEY-----
        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
        -----END RSA PRIVATE KEY-----
        """;

    // generated create-rsa-key-csr-crt-keystore.sh
    // signing cert sk-ca.localhost.crt must be in server sid trust store
    // mock service certificate
    public static final String TEST_RSA_CERT_PEM = "-----BEGIN CERTIFICATE-----"
        + """
        MIIFJzCCAw8CFDGOZ48HuNSuJYXsdEe/jh0jl6/6MA0GCSqGSIb3DQEBCwUAMEUx
        CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl
        cm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjYwNDA2MDkxMjA0WhcNMzYwNDAzMDkx
        MjA0WjBbMQswCQYDVQQGEwJFRTEOMAwGA1UEAwwFVEVTVE4xEzARBgNVBAQMClRF
        U1ROVU1CRVIxCzAJBgNVBCoMAk9LMRowGAYDVQQFExFQTk9FRS0zMDMwMzAzOTkx
        NDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANU8hLXf7VELA7TX8Mu5
        d+EqFLwQJwF1PAhZ17RdXtPtkW9YRxJv5kYsB745nVR+hrndN0VVou13PqSS3XTP
        xFMSnReUaXvXsczTe8k4jjiD91nC0o8DHRDjlARNWsrFHj3KkAQdUnv3NsokLjgT
        nuTjMwmW767/CUVtU/hRpg1QLR00tOGL+oJ7nQHfwaQnWw3Qs3WldgYCOVjBPiF5
        4ezcINxkLqjU8LGVjW3xvtYAEy63wWj1hOWpUNbNinPnW1ESTAPCa2iqVWMdT9oe
        I8ggEDnti82vHfvxz3s9gYmBTyVTtqIC8S6L3HX5oc7U5tsQ2QU82NP3Nl24zKTB
        EYCBSLLB9fPBUtE15FpsARvnFYYZeUj2OmFBGkQ2upUXuPeNDRoGaL5VXHNLi2/i
        1THAPUuhBOHoL+dG/oRV0Gno37oZ8OXJ6An7829XZ2PHWO81RzCA1MrdGgKFOjh0
        ZUrAWE3Wh2ELltFMas12Qc6BhusGelpMnMrYOAyCScqCNAnrPDGB1+ynpPJHF9Br
        FxojuR55hxhZEYD8Ezjoaz4XC2pSzrxS/ibVKLWqLfMJWsticm2h22LXm44qOj5A
        Bh4gzsTGlPvEduUuz4Vj6/APWvq37TVw0A2Tko2cRU7S43F7F3rGexlOt2q8NO9y
        uyqdzaENq/aHpqtGWsJg3/bzAgMBAAEwDQYJKoZIhvcNAQELBQADggIBAMG3UMdF
        w4gOC8L0FyWXpVy1E85W8KktnnRtl4zBo4XVYBxgL8/FAKo4Le1timHrjYmQeGRU
        nMWKnqPpkXHLvFL+yw0q80en/FKLsziC/07MS+/xsMmn1D1d22UZZaV4QCFkmmgd
        hcZniHV8YCwPjinto3QlzTcgVGTeYeYxY4rSlPfUeHHJQkzPL7QK/25gSVfv7IBT
        tbofxZZPSns+kV9+W7sZqpKBx60Sz0ElEnkJuJuuNEHkTx589zld/QRaNiejIsrn
        k2eK+B569rcdGM70mHWta96LyEy+botSe5J1j0fgPe1VUjBJZKrBt0rc3zCDOt9B
        9BW07twITasGh1im5uS1zadrZgoEdG2TZDpGIfMNE8dIlnfeTiPzxEbDoqidU6lv
        9b/oNqWWCER8Qa7V/7sDpPssFuOYmzI+0HEwaCJLUBn6POLIaJavYYdesGlF2lVY
        HYkFYFulRbnXb/Hf4hPQYEz/jb/Eg+BQNYbM/Ualj2ZjKSPYQhesMhkNOUcSvyru
        CqNcUqsnkcFai2ScDkFSPpoTB2PKNfZTHFfKT0ef6xVs4jIzrJa0pRa85gQS9l+L
        divlZKijCQpkAXaasAn+vT7L0+81f221wVPhHml0WsYQXK09Nj/5jMAvLBHPyCgy
        6HTOS2kp2p8Jv6vyLPj4q5/FbtlrWasK+i80
        """.replaceAll("\\s", "")
        + "-----END CERTIFICATE-----"; //remove all whitespace

    // SK-CA.localhost.crt
    public static final String TEST_RSA_CERT_ISSUER_PEM = """
        -----BEGIN CERTIFICATE-----
        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
        -----END CERTIFICATE-----""";

    // 30303039914 ECDSA certificate
    private static final String TEST_ECDSA_CERT_PEM = """
        -----BEGIN CERTIFICATE-----
        MIIBmzCCAUECFF9hc9Ki0ViUcYYUma+tY94JJLa0MAoGCCqGSM49BAMCMEUxCzAJ
        BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l
        dCBXaWRnaXRzIFB0eSBMdGQwHhcNMjYwNDA2MDk0NTEzWhcNMzYwNDAzMDk0NTEz
        WjBbMQswCQYDVQQGEwJFRTEOMAwGA1UEAwwFVEVTVE4xEzARBgNVBAQMClRFU1RO
        VU1CRVIxCzAJBgNVBCoMAk9LMRowGAYDVQQFExFQTk9FRS0zMDMwMzAzOTkxNDBZ
        MBMGByqGSM49AgEGCCqGSM49AwEHA0IABAWeVJrrXvoxM0smdRMl6pfmRLeHFVl9
        cBu9V2tLyTPVbWGM9KTWMtTK+Z8cuJP/9QwfVYbyildK3Ljh0e3DoDwwCgYIKoZI
        zj0EAwIDSAAwRQIgCdbyIvUaVrcsd0770S24Ws4MkyQXzf8o0KwC+IAWpB8CIQCs
        az188UqqiflisAEyqfmmMxl+6BybgktIreJ0sv5odg==
        -----END CERTIFICATE-----""";

    // 30303039914 ECDSA certificate private key
    private static final String TEST_ECDSA_KEY = """
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIBcKDOTuvQgeXk/Ba+B63t1oz0bTJ8hzY7y1s9HSsavmoAoGCCqGSM49
        AwEHoUQDQgAEBZ5Umute+jEzSyZ1EyXql+ZEt4cVWX1wG71Xa0vJM9VtYYz0pNYy
        1Mr5nxy4k//1DB9VhvKKV0rcuOHR7cOgPA==
        -----END EC PRIVATE KEY-----""";

    // ECDSA cyber-ca.localhost.crt
    public static final String TEST_ECDSA_CERT_ISSUER_PEM = """
        -----BEGIN CERTIFICATE-----
        MIIB3zCCAYWgAwIBAgIUM+gmA5cIzIoTe3s+xnbcFhBpq0kwCgYIKoZIzj0EAwIw
        RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
        dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNjA0MDYwOTQyMDRaFw0zNjA0MDMw
        OTQyMDRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
        VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjO
        PQMBBwNCAAQFnlSa6176MTNLJnUTJeqX5kS3hxVZfXAbvVdrS8kz1W1hjPSk1jLU
        yvmfHLiT//UMH1WG8opXSty44dHtw6A8o1MwUTAdBgNVHQ4EFgQUS1WBUOSTRHRh
        Nx4zzh1hljXm15kwHwYDVR0jBBgwFoAUS1WBUOSTRHRhNx4zzh1hljXm15kwDwYD
        VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA5E7D18NyUF9elYJ1y5Dm
        nwo50RH1tRkYwd108d9R1FECIHdJEq2SZieyGtKVgPYR0HO8qv6BXRkSFBdxcuOT
        v1P+
        -----END CERTIFICATE-----""";

    // CA certificate for Smart-id test account PNOEE-30303039914
    // https://github.com/SK-EID/smart-id-java-client/blob/master/README.md
    public static final String TEST_PEM_30303039914 = """
        -----BEGIN CERTIFICATE-----
        MIIIIjCCBgqgAwIBAgIQUJQ/xtShZhZmgogesEbsGzANBgkqhkiG9w0BAQsFADBoM
        QswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1cz
        EXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHDAaBgNVBAMME1RFU1Qgb2YgRUlELVN
        LIDIwMTYwIBcNMjQwNzAxMTA0MjM4WhgPMjAzMDEyMTcyMzU5NTlaMGMxCzAJBgNV
        BAYTAkVFMRYwFAYDVQQDDA1URVNUTlVNQkVSLE9LMRMwEQYDVQQEDApURVNUTlVNQ
        kVSMQswCQYDVQQqDAJPSzEaMBgGA1UEBRMRUE5PRUUtMzAzMDMwMzk5MTQwggMiMA
        0GCSqGSIb3DQEBAQUAA4IDDwAwggMKAoIDAQCo+o1jtKxkNWHvVBRA8Bmh08dSJxh
        L/Kzmn7WS2u6vyozbF6M3f1lpXZXqXqittSmiz72UVj02jtGeu9Hajt8tzR6B4D+D
        wWuLCvTawqc+FSjFQiEB+wHIb4DrKF4t42Aazy5mlrEy+yMGBe0ygMLd6GJmkFw1p
        zINq8vu6sEY25u6YCPnBLhRRT3LhGgJCqWQvdsN3XCV8aBwDK6IVox4MhIWgKgDF/
        dh9XW60MMiW8VYwWC7ONa3LTqXJRuUhjFxmD29Qqj81k8ZGWn79QJzTWzlh4NoDQT
        8w+8ZIOnyNBAxQ+Ay7iFR4SngQYUyHBWQspHKpG0dhKtzh3zELIko8sxnBZ9HNkwn
        IYe/CvJIlqARpSUHY/Cxo8X5upwrfkhBUmPuDDgS14ci4sFBiW2YbzzWWtxbEwiRk
        dqmA1NxoTJybA9Frj6NIjC4Zkk+tL/N8Xdblfn8kBKs+cAjk4ssQPQruSesyvzs4E
        GNgAk9PX2oeelGTt02AZiVkIpUha8VgDrRUNYyFZc3E3Z3Ph1aOCEQMMPDATaRps3
        iHw/waHIpziHzFAncnUXQDUMLr6tiq+mOlxYCi8+NEzrwT2GOixSIuvZK5HzcJTBY
        z35+ESLGjxnUjbssfra9RAvyaeE1EDfAOrJNtBHPWP4GxcayCcCuVBK2zuzydhY6K
        t8ukXh5MIM08GRGHqj8gbBMOW6zEb3OVNSfyi1xF8MYATKnM1XjSYN49My0BPkJ01
        xCwFzC2HGXUTyb8ksmHtrC8+MrGLus3M3mKFvKA9VatSeQZ8ILR6WeA54A+GMQeJu
        V54ZHZtD2085Vj7R+IjR+3jakXBvZhVoSTLT7TIIa0U6L46jUIHee/mbf5RJxesZz
        kP5zA81csYyLlzzNzFah1ff7MxDBi0v/UyJ9ngFCeLt7HewtlC8+HRbgSdk+57Kga
        FIgVFKhv34Hz1Wfh3ze1Rld3r1Dx6so4h4CZOHnUN+hprosI4t1y8jorCBF2GUDbI
        qmBCx7DgqT6aE5UcMcXd8CAwEAAaOCAckwggHFMAkGA1UdEwQCMAAwDgYDVR0PAQH
        /BAQDAgSwMHkGA1UdIARyMHAwZAYKKwYBBAHOHwMRAjBWMFQGCCsGAQUFBwIBFkho
        dHRwczovL3d3dy5za2lkc29sdXRpb25zLmV1L3Jlc291cmNlcy9jZXJ0aWZpY2F0a
        W9uLXByYWN0aWNlLXN0YXRlbWVudC8wCAYGBACPegECMB0GA1UdDgQWBBQUFyCLUa
        wSl3KCp22kZI88UhtHvTAfBgNVHSMEGDAWgBSusOrhNvgmq6XMC2ZV/jodAr8StDA
        TBgNVHSUEDDAKBggrBgEFBQcDAjB8BggrBgEFBQcBAQRwMG4wKQYIKwYBBQUHMAGG
        HWh0dHA6Ly9haWEuZGVtby5zay5lZS9laWQyMDE2MEEGCCsGAQUFBzAChjVodHRwO
        i8vc2suZWUvdXBsb2FkL2ZpbGVzL1RFU1Rfb2ZfRUlELVNLXzIwMTYuZGVyLmNydD
        AwBgNVHREEKTAnpCUwIzEhMB8GA1UEAwwYUE5PRUUtMzAzMDMwMzk5MTQtTU9DSy1
        RMCgGA1UdCQQhMB8wHQYIKwYBBQUHCQExERgPMTkwMzAzMDMxMjAwMDBaMA0GCSqG
        SIb3DQEBCwUAA4ICAQCqlSMpTx+/nwfI5eEislq9rce9eOY/9uA0b3Pi7cn6h7jdF
        es1HIlFDSUjA4DxiSWSMD0XX1MXe7J7xx/AlhwFI1WKKq3eLx4wE8sjOaacHnwV/J
        STf6iSYjAB4MRT2iJmvopgpWHS6cAQfbG7qHE19qsTvG7Ndw7pW2uhsqzeV5/hcCf
        10xxnGOMYYBtU7TheKRQtkeBiPJsv4HuIFVV0pGBnrvpqj56Q+TBD9/8bAwtmEMSc
        QUVDduXPc+uIJJoZfLlUdUwIIfhhMEjSRGnaK4H0laaFHa05+KkFtHzc/iYEGwJQb
        iKvUn35/liWbcJ7nr8uCQSuV4PHMjZ2BEVtZ6Qj58L/wSSidb4qNkSb9BtlK+wwND
        jbqysJtQCAKP7SSNuYcEAWlmvtHmpHlS3tVb7xjko/a7zqiakjCXE5gIFUmtZJFbG
        5dO/0VkT5zdrBZJoq+4DkvYSVGVDE/AtKC86YZ6d1DY2jIT0c9BlbFp40A4Xkjjjf
        5/BsRlWFAs8Ip0Y/evG68gQBATJ2g3vAbPwxvNX2x3tKGNg+aDBYMGM76rRrtLhRq
        PIE4Ygv8x/s7JoBxy1qCzuwu/KmB7puXf/y/BBdcwRHIiBq2XQTfEW3ZJJ0J5+Kq4
        8keAT4uOWoJiPLVTHwUP/UBhwOSa4nSOTAfdBXG4NqMknYwvAE9g==
        -----END CERTIFICATE-----""";

    // Issuer cert TEST of EID-SK 2016.pem for PNOEE-30303039914
    public static final String TEST_30303039914_ISSUER_PEM = """
        -----BEGIN CERTIFICATE-----
        MIIHCTCCBfGgAwIBAgIQVrOxHLphb7pfUJLPiYJRMzANBgkqhkiG9w0BAQwFADB9
        MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1
        czEwMC4GA1UEAwwnVEVTVCBvZiBFRSBDZXJ0aWZpY2F0aW9uIENlbnRyZSBSb290
        IENBMRgwFgYJKoZIhvcNAQkBFglwa2lAc2suZWUwHhcNMjAwOTAzMDY1MzAzWhcN
        MzAxMjE3MjE1OTU5WjBoMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlm
        aXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHDAaBgNV
        BAMME1RFU1Qgb2YgRUlELVNLIDIwMTYwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
        ggIKAoICAQDqyjgcqyaktULCg+LV4apGWnzzHebH8XpuolWzAAByqbzrOCGtqF3U
        rydhY6zJebM3k+JaR8s3xAszt58e6b0Syh7n4upTMDBo7UiOgyvAYh/c+y5vpDS7
        pzRXSIq9IT4o42yJI4PYsH2nkk/RYuedNi7Cu3boSrgpx+ztLjK0vzMpyeErQDRm
        Nd19hbz1uKpK7W8LJoXTdAba6O9juv9zvtL256v8glrXEKwRr9/vFxAXQqh+Uv0b
        dBLoCl+FJVcuZdEFHPCK4xrXTLK/Sg7b5lcJXn12CqC6pAu4LjBjlDX+mOAGBrD6
        n2OHRtzeWDaeRRwy+yDvd4e06UVd4Mkd/C4ibDx5OZxEuZnT5DbhJAsoNMxCiO7i
        eC1LgW482T6doD+zzfCKovRj+1djQs/L1FTd1qR73LbH9AzL2XVeacai2OaI8n4T
        LFOGjHBkkAPRCvBEtztcwStQ1vm7Y20I1BVtUiMApAdsqHxcYHvr782Rm77dlBjh
        PKAC/PyczcYvRW40wG8nKxloBDENLDNXynPjrL6GksvZt2UBqYdPnW7KLkKZd5KS
        b4wzM8cZKzKsXYZVTK3iyhgjDMSTABkBMFUuT/dzZ5s/FG5JnqJlCa9zawaOPlfS
        +UuCsdb07w9Ke9sUWBcn4nyzo7PKrO5Ud8oZHAT0CO/BEasb99RVgwIDAQABo4IC
        mDCCApQwHwYDVR0jBBgwFoAUtTQKnaUvEMXnIQ6+xLFlRxsDdv4wHQYDVR0OBBYE
        FK6w6uE2+CarpcwLZlX+Oh0CvxK0MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8E
        CDAGAQH/AgEAMIHEBgNVHSAEgbwwgbkwPAYHBACL7EABAjAxMC8GCCsGAQUFBwIB
        FiNodHRwczovL3d3dy5zay5lZS9yZXBvc2l0b29yaXVtL0NQUzA8BgcEAIvsQAEA
        MDEwLwYIKwYBBQUHAgEWI2h0dHBzOi8vd3d3LnNrLmVlL3JlcG9zaXRvb3JpdW0v
        Q1BTMDsGBgQAj3oBAjAxMC8GCCsGAQUFBwIBFiNodHRwczovL3d3dy5zay5lZS9y
        ZXBvc2l0b29yaXVtL0NQUzAnBgNVHSUEIDAeBggrBgEFBQcDCQYIKwYBBQUHAwIG
        CCsGAQUFBwMEMIGOBggrBgEFBQcBAQSBgTB/MCIGCCsGAQUFBzABhhZodHRwOi8v
        ZGVtby5zay5lZS9vY3NwMFkGCCsGAQUFBzAChk1odHRwOi8vd3d3LnNrLmVlL3Vw
        bG9hZC9maWxlcy9URVNUX29mX0VFX0NlcnRpZmljYXRpb25fQ2VudHJlX1Jvb3Rf
        Q0EuZGVyLmNydDBBBgNVHR4EOjA4oTYwBIICIiIwCocIAAAAAAAAAAAwIocgAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwJQYIKwYBBQUHAQMEGTAXMBUG
        CCsGAQUFBwsCMAkGBwQAi+xJAQEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cHM6Ly93
        d3cuc2suZWUvcmVwb3NpdG9yeS9jcmxzL3Rlc3RfZWVjY3JjYS5jcmwwDQYJKoZI
        hvcNAQEMBQADggEBACawLCQnjAOtDCaNejt1AqMVc8IwWy03TAAvceJd7rRSG9w2
        Q69OxVMVhUpQ4+K+M+Fqtpkq5IWO9GFXYeYL5JwiL4rjKPk1MIunM4ZKr6f+NQBy
        4A4oHL0ArF4QoQZuYnUS/jesjQs2HXEthcLjdSkFyaoAyfPH50c0WTMDhZj8eEIK
        NWPEqGmGZPkAc4+ivFdl7zEC6ZaaJ6NdtihQKdFcisgv3Uyc4kuzmHK/6OtNAXpg
        qaiLyf4L3ThQ2KA+EuDp6B97rOfV4JWC265HkAwxKd9/3fk7pwnfyMxIonW5MGcN
        nrlYjNXNft5cr9xu2A8mPXh2ArMiZ1yif5NDvHI=
        -----END CERTIFICATE-----""";

    // Root cert TEST_of_EE_Certification_Centre_Root_CA.pem.crt for 'TEST of EID-SK 2016.pem'
    public static final String TEST_30303039914_ISSUER_ROOT_PEM = """
        -----BEGIN CERTIFICATE-----
        MIIEEzCCAvugAwIBAgIQc/jtqiMEFERMtVvsSsH7sjANBgkqhkiG9w0BAQUFADB9
        MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1
        czEwMC4GA1UEAwwnVEVTVCBvZiBFRSBDZXJ0aWZpY2F0aW9uIENlbnRyZSBSb290
        IENBMRgwFgYJKoZIhvcNAQkBFglwa2lAc2suZWUwIhgPMjAxMDEwMDcxMjM0NTZa
        GA8yMDMwMTIxNzIzNTk1OVowfTELMAkGA1UEBhMCRUUxIjAgBgNVBAoMGUFTIFNl
        cnRpZml0c2VlcmltaXNrZXNrdXMxMDAuBgNVBAMMJ1RFU1Qgb2YgRUUgQ2VydGlm
        aWNhdGlvbiBDZW50cmUgUm9vdCBDQTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVl
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1gGpqCtDmNNEHUjC8LXq
        xRdC1kpjDgkzOTxQynzDxw/xCjy5hhyG3xX4RPrW9Z6k5ZNTNS+xzrZgQ9m5U6uM
        ywYpx3F3DVgbdQLd8DsLmuVOz02k/TwoRt1uP6xtV9qG0HsGvN81q3HvPR/zKtA7
        MmNZuwuDFQwsguKgDR2Jfk44eKmLfyzvh+Xe6Cr5+zRnsVYwMA9bgBaOZMv1TwTT
        VNi9H1ltK32Z+IhUX8W5f2qVP33R1wWCKapK1qTX/baXFsBJj++F8I8R6+gSyC3D
        kV5N/pOlWPzZYx+kHRkRe/oddURA9InJwojbnsH+zJOa2VrNKakNv2HnuYCIonzu
        pwIDAQABo4GKMIGHMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0G
        A1UdDgQWBBS1NAqdpS8QxechDr7EsWVHGwN2/jBFBgNVHSUEPjA8BggrBgEFBQcD
        AgYIKwYBBQUHAwEGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgGCCsGAQUF
        BwMJMA0GCSqGSIb3DQEBBQUAA4IBAQAj72VtxIw6p5lqeNmWoQ48j8HnUBM+6mI0
        I+VkQr0EfQhfmQ5KFaZwnIqxWrEPaxRjYwV0xKa1AixVpFOb1j+XuVmgf7khxXTy
        Bmd8JRLwl7teCkD1SDnU/yHmwY7MV9FbFBd+5XK4teHVvEVRsJ1oFwgcxVhyoviR
        SnbIPaOvk+0nxKClrlS6NW5TWZ+yG55z8OCESHaL6JcimkLFjRjSsQDWIEtDvP4S
        tH3vIMUPPiKdiNkGjVLSdChwkW3z+m0EvAjyD9rnGCmjeEm5diLFu7VMNVqupsbZ
        SfDzzBLc5+6TqgQTOG7GaZk2diMkn03iLdHGFrh8ML+mXG9SjEPI
        -----END CERTIFICATE-----""";

    //TEST of SK ID Solutions EID-Q 2021E
    //Validity end: Sun Jul 20 14:57:23 EEST 2036
    //https://www.skidsolutions.eu/resources/certificates/
    static final X509Certificate ISSUING_CERT_EID_Q_2021E =
        X509CertUtils.parse(Base64.getDecoder().decode(
            "MIIDozCCAwWgAwIBAgIQU+FdGn4AyGFg9rok5E6z7DAKBggqhkjOPQQDAzBuMQsw"
                + "CQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRh"
                + "DA5OVFJFRS0xMDc0NzAxMzEpMCcGA1UEAwwgVEVTVCBvZiBTSyBJRCBTb2x1dGlv"
                + "bnMgUk9PVCBHMUUwHhcNMjEwNzIwMTE1NzIzWhcNMzYwNzIwMTE1NzIzWjBxMQsw"
                + "CQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRh"
                + "DA5OVFJFRS0xMDc0NzAxMzEsMCoGA1UEAwwjVEVTVCBvZiBTSyBJRCBTb2x1dGlv"
                + "bnMgRUlELVEgMjAyMUUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT0wf3NUdjxWoIe"
                + "dN+ZK4hTPhTuwv03xhWhp34p4qGIZIaM+XxZc4/3dScM4CtnHniCOZoUgCysvkgb"
                + "GLh56xmMrmY/xy/3ZMk8M2JeU2NliKeZfeTAMObH6BtptPz00JSjggFjMIIBXzAf"
                + "BgNVHSMEGDAWgBTiHN5j3L74hH4BOy5LgLHhf9Xx5jAdBgNVHQ4EFgQUScfc7QYU"
                + "osdtnKbP11L9aOXoBBQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8C"
                + "AQAwbAYIKwYBBQUHAQEEYDBeMCIGCCsGAQUFBzABhhZodHRwOi8vZGVtby5zay5l"
                + "ZS9vY3NwMDgGCCsGAQUFBzAChixodHRwOi8vYy5zay5lZS9URVNUX1NLX1JPT1Rf"
                + "RzFfMjAyMUUuZGVyLmNydDA5BgNVHR8EMjAwMC6gLKAqhihodHRwOi8vYy5zay5l"
                + "ZS9URVNUX1NLX1JPT1RfRzFfMjAyMUUuY3JsMFAGA1UdIARJMEcwRQYEVR0gADA9"
                + "MDsGCCsGAQUFBwIBFi9odHRwczovL3d3dy5za2lkc29sdXRpb25zLmV1L2VuL3Jl"
                + "cG9zaXRvcnkvQ1BTLzAKBggqhkjOPQQDAwOBiwAwgYcCQgD8bAhs1OuTDgWPYHQj"
                + "22k67f4m2fgBWH1EBiN5fKNCKRf6m+zDjxiEBrVfEt1Ld1stFwSMUB43VP1AvW8P"
                + "4BwIIQJBCWQhLih0OjxBjd4vYRpkJYQF6YCv4uB6Y7/No/k8jOFaBFHCLX2uytuq"
                + "cWfH8kJRPSEtpBZacnFHoqFztE4786Q="
        ));

    //TEST of SK ID Solutions EID-Q 2024E
    //Validity end: 2039.05.31 13:01:21
    //https://www.skidsolutions.eu/resources/certificates/
    static final X509Certificate ISSUING_CERT_EID_Q_2024E =
        X509CertUtils.parse(Base64.getDecoder().decode(
            "MIIDxzCCAymgAwIBAgIUIJ92Wg42THMIC1QSOpWpxv3+22AwCgYIKoZIzj0EAwMw"
                + "bjELMAkGA1UEBhMCRUUxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzEXMBUG"
                + "A1UEYQwOTlRSRUUtMTA3NDcwMTMxKTAnBgNVBAMMIFRFU1Qgb2YgU0sgSUQgU29s"
                + "dXRpb25zIFJPT1QgRzFFMB4XDTI0MDYwMzEzMDEyMloXDTM5MDUzMTEzMDEyMVow"
                + "cTEsMCoGA1UEAwwjVEVTVCBvZiBTSyBJRCBTb2x1dGlvbnMgRUlELVEgMjAyNEUx"
                + "FzAVBgNVBGEMDk5UUkVFLTEwNzQ3MDEzMRswGQYDVQQKDBJTSyBJRCBTb2x1dGlv"
                + "bnMgQVMxCzAJBgNVBAYTAkVFMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE9tnu4Hr6"
                + "oZ3virQ52FkQ8zgSnRLjSpbr7y6hjaI5ZtvFTssL3aOgvULxOvV5x+HtOmcGVfmh"
                + "vy9YtoJENq/E3pFFOkofrkX3O/RVLdtPpiVahYa89HCgqoEVDln5ILMWo4IBgzCC"
                + "AX8wEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBTiHN5j3L74hH4BOy5L"
                + "gLHhf9Xx5jBsBggrBgEFBQcBAQRgMF4wOAYIKwYBBQUHMAKGLGh0dHA6Ly9jLnNr"
                + "LmVlL1RFU1RfU0tfUk9PVF9HMV8yMDIxRS5kZXIuY3J0MCIGCCsGAQUFBzABhhZo"
                + "dHRwOi8vZGVtby5zay5lZS9vY3NwMHAGA1UdIARpMGcwBgYEVR0gADBdBgNVHSAw"
                + "VjBUBggrBgEFBQcCARZIaHR0cHM6Ly93d3cuc2tpZHNvbHV0aW9ucy5ldS9yZXNv"
                + "dXJjZXMvY2VydGlmaWNhdGlvbi1wcmFjdGljZS1zdGF0ZW1lbnQvMDkGA1UdHwQy"
                + "MDAwLqAsoCqGKGh0dHA6Ly9jLnNrLmVlL1RFU1RfU0tfUk9PVF9HMV8yMDIxRS5j"
                + "cmwwHQYDVR0OBBYEFLAkFxmI42b4zShYZXtNFNiSZk9rMA4GA1UdDwEB/wQEAwIB"
                + "BjAKBggqhkjOPQQDAwOBiwAwgYcCQXIdNKdyvEhtB+48QZEXi2dgXiAjYD7O0D4f"
                + "4Y2KPajqrRcwd9KEYr/yFjK0JWYHqRFN47tMdYhisy7aFySEWmKcAkIBUbTJeSbo"
                + "XAKBT9+j2zQduKv8Eqb/AIQybcVXyP23w+1ujNkcQZMkok41nGOH2YNRP7aGsCZa"
                + "7Wy8pf2lw6EcfyU="
        ));

    //TEST of SK ID Solutions ROOT G1E
    //Validity end: 2041.07.09 13:47:14
    //https://www.skidsolutions.eu/resources/certificates/
    static final X509Certificate ROOT_CERT_G1E =
        X509CertUtils.parse(Base64.getDecoder().decode(
            "MIICxDCCAiagAwIBAgIQGjWemJjC5ORg6CkyNQ5DzTAKBggqhkjOPQQDBDBuMQsw"
                + "CQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRh"
                + "DA5OVFJFRS0xMDc0NzAxMzEpMCcGA1UEAwwgVEVTVCBvZiBTSyBJRCBTb2x1dGlv"
                + "bnMgUk9PVCBHMUUwHhcNMjEwNzA5MTA0NzE0WhcNNDEwNzA5MTA0NzE0WjBuMQsw"
                + "CQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRh"
                + "DA5OVFJFRS0xMDc0NzAxMzEpMCcGA1UEAwwgVEVTVCBvZiBTSyBJRCBTb2x1dGlv"
                + "bnMgUk9PVCBHMUUwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABACGx6ye24WAORL1"
                + "8N0SquoI3TTJ3dd2EcZLs+wZY0XWYzPa0S4o8BKZQTCDbXz9O2x94hpdAjZ4S3Q2"
                + "N7DAvQ0FfAHmM2JotR4UnYvxYv4JxJHpoRvrQoXOXdqO/wMymiPKTXHPFQz6nxxa"
                + "ORjy8xsrQeIdrTLj3c+HDVBRA5yE/IXed6NjMGEwDwYDVR0TAQH/BAUwAwEB/zAO"
                + "BgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFOIc3mPcvviEfgE7LkuAseF/1fHmMB8G"
                + "A1UdIwQYMBaAFOIc3mPcvviEfgE7LkuAseF/1fHmMAoGCCqGSM49BAMEA4GLADCB"
                + "hwJBNDZ3R6qmJqL5bQf01oT369DEGcLhr2vA00nRZSqeaaLMfq+RQW8aYl0njfIZ"
                + "JAC6q6IJklpH5IyYrcZ29tcBrxECQgFH5aw8ZORororrLDPl1yY2RgsCO1SFoDh5"
                + "eMEaKVtRKNSG1jLzfgiZJOdtIj/h/l/4oDc5DrDDY6kbAnl4M5pDKw=="
        ));

    //identifier from above TEST_RSA_CERT and TEST_ECDSA_CERT
    public static final String TEST_IDENTIFIER = "30303039914";
    public static final EtsiIdentifier TEST_ETSI_RECIPIENT
        = new EtsiIdentifier("etsi/PNOEE-" + TEST_IDENTIFIER);

    public static final JWSAlgorithm.Family SID_PUBLIC_KEY_ALGORITHM = JWSAlgorithm.Family.RSA;
    public static final JWSAlgorithm.Family MID_PUBLIC_KEY_ALGORITHM = JWSAlgorithm.Family.EC;

    private static final Logger log = LoggerFactory.getLogger(TestData.class);

    private TestData() {
        // utility class
    }

    public static KeyStore createTestIssuerTrustStore(List<String> pemCertificates)
        throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);

        for (String certIssuerPem : pemCertificates) {
            InputStream is = new ByteArrayInputStream(certIssuerPem.getBytes(StandardCharsets.UTF_8));
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(is);

            trustStore.setCertificateEntry(cert.getSubjectX500Principal().getName(), cert);
        }
        return trustStore;
    }

    public static KeyStore createTestIssuerTrustStoreFromCerts(List<X509Certificate> certificates)
        throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);

        for (X509Certificate cert : certificates) {
            trustStore.setCertificateEntry(cert.getSubjectX500Principal().getName(), cert);
        }
        return trustStore;
    }

    public static KeyStore createEmptyTrustStore()
        throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        return trustStore;
    }

    public static X509Certificate loadDefaultTestCert(JWSAlgorithm.Family pubKeyAlgorithm)
        throws CertificateException {

        String certPem;
        if (pubKeyAlgorithm.equals(SID_PUBLIC_KEY_ALGORITHM)) {
            certPem = TEST_RSA_CERT_PEM;
        } else if (pubKeyAlgorithm.equals(MID_PUBLIC_KEY_ALGORITHM)) {
            certPem = TEST_ECDSA_CERT_PEM;
        } else {
            throw new CertificateException("Not supported public key algorithm " + pubKeyAlgorithm);
        }

        return X509CertUtils.parse(certPem);
    }

    public static X509Certificate loadTestCert(String certPem) {
        return X509CertUtils.parse(certPem);
    }
}
