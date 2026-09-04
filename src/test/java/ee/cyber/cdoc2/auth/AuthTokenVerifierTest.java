package ee.cyber.cdoc2.auth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.JWK;

import ee.cyber.cdoc2.auth.exception.VerificationException;

import static ee.cyber.cdoc2.auth.TestData.*;
import static org.junit.jupiter.api.Assertions.*;

class AuthTokenVerifierTest {
    private static final String AUTH_NONCE_URI_PATH = "/key-shares/ff0102030405060708090a0b0c0e0dff";
    private static final String SID_AUTH_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL =
        "eyJ0eXAiOiJ2bmQuY2RvYzIuYXV0aC10b2tlbi52MStzZC1qd3QiLCJhbGciOiJSU0FTU0EtUFNTK0FDU1BfVjIifQ.eyJpc3MiOiJldHNpL1BOT0VFLTQwNTA0MDQwMDAxIiwiX3NkIjpbIlhWTzlYZ1hhYmRqa3h1aUZNQTAxMmtUSEg1WURCX0gyWXlpU21ZWklJbXciXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.ZGvyeET3GFN4cFLWRAhgG4JParjJEjv3LCIZyEnV6FpKFxBL7XzDlNysqtdGF3NZaXa5iXnWP8WOMAhDtCLOo2iwIJBfovnKLl5yFgKzoxjZfOB4tFiRkL24DKWdYYCCMIjKSPwfoB_A_IKBKy1xJwH6pUtbc0Zg1LZaOXGMJ_evI4pY3Vrc2VNZV7ej57t5Rz5CY8FCTZfgCHFJ_-upc02w4mjUmwYVTiIZdJMazVusaK9cuzUfo2UjlyBIz7Lj3LvJV_e1mJsm4lX1Swk71JNnxy60WTuT_iTMlG6kp8hFpai0jSVWJG3H1K6tCXU3B0Xh9mphaGWWeE1fYcAzL9PG64pgsch8ej6_YEH8GStulC9GJ_pr1tXID3sW5msYEgu8J3FVb0mIbRiWh8-xZ3oFs8LYP31N6vzlyXLc696euz8Ea1wZjgmB6ivxa9SV5JP5hu4UtqipY-lQPC3Czvzij31sZQW1gMWfSh0cGviQyoVNKtkWOugevCWfNAEVBc6_at-K8xSKBiVQ8evvHp7iyqYaQBQZ3p6F6k_rwnaVULF7Su5_OTnkHfwmJtwXl1-ODZXzp0yi4MVwP_odA72yG1FSZ4qjI3W28PGcl6_hMGeepUC8_-_9Bj1PG9XaaQMk4_scjLWwWi1yzTT4VLUcSl-ApGJMNlJQNb2xc7vpXFaSf7NHlp9Fp8ToOkpfl1rXayM4HzuUxE-_sYjWQhYHPV9lo7oOe8sWUS2BKkbu8M2jdDiN9c3sHDb9TtnADONvapy1CoqoJTZbfFJvkxmaZtSJxPDWztTDQud0WPuziEV_LtlzweJCvfJKnKXAe_a6WtDwDA1wo6-JFK-PM6SyFI7wWytwGlEzgvJlPuqDSfautqFjC07whudkqDQpxDv4aPsoFnHeTzHxKdf-TuZwTKNXxJCoPZK1uo1Yj2nx2wZbCTm-Bfmxq5vKDB4wN-OK2tvk5WZByR1Q-sRMpIEO1ijglRf3KT3ig5jHb6e1W1P4eJcN8AZjrZz1fI3N~WyJQMWZ6M0pkaFRoWG5Eb2pkaDlqVnV3IiwiYXVkIixbeyIuLi4iOiJoYy03cGpsYlBwb0w2bjJIemx2bVVJMlU2dEZIUU1EWUJneHAxNlVFUjdJIn0seyIuLi4iOiJFTy11UG1HYUEzLTRfT1RpdjBJUlNqTy0tc1F1NVU0T2lTMWJjaEdYbGs0In1dXQ~WyJ2R2hHSTlabl9BWVk4bVBfamJuV21nIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0Mi9rZXktc2hhcmVzL2ZmMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGUwZGZmP25vbmNlPUFBRUNBd1FGQmdjSUNRb0xEQTROX3ciXQ~";
    private static final String SID_SIGNING_CERTIFICATE_BASE64URL =
        "MIIGpzCCBi6gAwIBAgIQGcJUbe6JHI6jJyV-42vjnTAKBggqhkjOPQQDAzBxMSwwKgYDVQQDDCNURVNUIG9mIFNLIElEIFNvbHV0aW9ucyBFSUQtUSAyMDI0RTEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAoMElNLIElEIFNvbHV0aW9ucyBBUzELMAkGA1UEBhMCRUUwHhcNMjYwMTA2MTQyNTAxWhcNMjkwMTA1MTQyNTAwWjBXMQswCQYDVQQGEwJFRTEQMA4GA1UEAwwHVEVTVCxPSzENMAsGA1UEBAwEVEVTVDELMAkGA1UEKgwCT0sxGjAYBgNVBAUTEVBOT0VFLTQwNTA0MDQwMDAxMIIDIjANBgkqhkiG9w0BAQEFAAOCAw8AMIIDCgKCAwEAkI98VzyaeSueyaUQYIXMMf-1VY10Gw-b8Q13Rb9N62ROZY97wMIB__f8_PuOIoqkAPM6Tn_t4lp1R_rHrbuqs0hl2dgLlOcR5wmWmp7YfKPDvRndVLl_doIHruxY8O60rFGskSnqt4coHN4xGcmCyPkJoB8Rfm8-Y9poVKAreS0Ta32p5OSME0HjSs7-ahB2erWfb2GulFw1vyeH42d3XDpCCfd6CByvSsi4oByUqs5G-kjSrGUglflgWXK3MxBYto0swgsbD1nrW5doU_cMCfRoFURun4XguX8dTt9VeyqeJitxRfub2Hj18RbsKuoFNHQNOxAxRK4oTVCtUrYbVqBHDmoOm8r3CsSuqjuZ2njQybiUhBofpTVMCZ6lB6VgoLphmEwSEOQXIumpmpb2qJZqbZaBoyyWb4f5AQjw3Q5lwPSao5215hIgSuuENRezpP9rTzIwyOMbnV2nMSMInAuaXIXskB2NdpMsROsvOqBC0h5azTj9naCS-5EW-9eI7GGK03Du5JoKD5wYajJxfcxFwBAl8Ko71OvhGFtYiu-hqzz-CyG6NswB87KvzDYUCQ-0qOfgRBNCgYnbjnuYVJb3CGLp_cP5GmKtUC3wHX1WnPGyK4bD19Rcy-FhG6mD_ZrAPcmZ3s4FLLErpRJ3ui-fiMPLQl2bpCKTWoaEZoPg6Grnhr3bE2ZiKWmqdVwf30bG3-GnvTBTuF0T1lzt6NeBlB23SJsffCmzSFSNcFJHHYI1FYdZu2p0gL6KAabEmnE8GrTrCn93DFNBtoKu9vG30QrRzyh-itPvtn9w-9t-nDkhaVHmNCjWD1xcMeXsyK8ek0rbz5aVe_RPvCifhIpgjqNsDHh9q1QT9KIFsd6RD2XPMlekL9c6YiVY9H7uRyIQWqJwtrvNvBKj4ZT9745zTfkhCJTPvnLy-4iKeINVZ2f98BblsGAEHKGol8YA-3SRkPh9BVnVhSdI3lxCDEbmHuk21GIPE9689efSvbcDEHpqeYoxo3tXjl_hqfzPAgMBAAGjggH1MIIB8TAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFLAkFxmI42b4zShYZXtNFNiSZk9rMHAGCCsGAQUFBwEBBGQwYjAzBggrBgEFBQcwAoYnaHR0cDovL2Muc2suZWUvVEVTVF9FSUQtUV8yMDI0RS5kZXIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vYWlhLmRlbW8uc2suZWUvZWlkcTIwMjRlMDAGA1UdEQQpMCekJTAjMSEwHwYDVQQDDBhQTk9FRS00MDUwNDA0MDAwMS1ERU0wLVEweAYDVR0gBHEwbzBjBgkrBgEEAc4fEQIwVjBUBggrBgEFBQcCARZIaHR0cHM6Ly93d3cuc2tpZHNvbHV0aW9ucy5ldS9yZXNvdXJjZXMvY2VydGlmaWNhdGlvbi1wcmFjdGljZS1zdGF0ZW1lbnQvMAgGBgQAj3oBAjAoBgNVHQkEITAfMB0GCCsGAQUFBwkBMREYDzE5MDUwNDA0MTIwMDAwWjAWBgNVHSUEDzANBgsrBgEEAYPmYgUHADA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjRlLmNybDAdBgNVHQ4EFgQUX9YaVGlPdUOO2J6rzNc4sljBQBAwDgYDVR0PAQH_BAQDAgeAMAoGCCqGSM49BAMDA2cAMGQCMHhYJCeKceJv_m0xcFRssS4WVFnnCryDiuSEpjDZu0irJ_XurXXIFDr-9hhl2x7GMwIwbiD5GALRtwzUaEh-SV9jigT9Oc336f6QYf8YaSA0-Un8eRQPa9wTK0cSQrM_CUIu";
    private static final SdJwtWrapper SID_AUTH_TOKEN =
        new SdJwtWrapper(SID_AUTH_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL);

    private static final String MID_AUTH_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL =
        "eyJ0eXAiOiJ2bmQuY2RvYzIuYXV0aC10b2tlbi52MStzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJldHNpL1BOT0VFLTUxMzA3MTQ5NTYwIiwiX3NkIjpbInlxQ3pheElCOWZZaHRTb001RGdEazBadV9YWkZuQWRIOW1abFNrRm42ZnciXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.Qig3n9nZ2k6-jfItUFRh_p05BT6sSbAVzFulVtodFlYLaWCUJhW9XWKLF73DmLd6YyY7P7j2MRYAZaBO-FEWoA~WyJWb21KX1lnbFBjWUpycTlMYldBZS13IiwiYXVkIixbeyIuLi4iOiJDU2R5cWxJUzdqbDNZbl9wZjZib3FEQjVFVFFwMnU2Nnp6UW96eVdMSEJVIn0seyIuLi4iOiI2RW50ODJYQWp3US1kTDNrZmxqTUp6aEdVdTJNcC1wNi1fSFlOakhSb3NZIn1dXQ~WyJETWpFbUF1d2pCNTBhNTdHTmhlaGpnIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0Mi9rZXktc2hhcmVzL2ZmMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGUwZGZmP25vbmNlPUFBRUNBd1FGQmdjSUNRb0xEQTROX3ciXQ~";
    private static final String MID_EC_SIGNING_CERTIFICATE_BASE64URL =
        "MIIDqDCCAy6gAwIBAgIQB9W11BzBABj-0d_AZx6UHzAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEsMCoGA1UEAwwjVEVTVCBvZiBTSyBJRCBTb2x1dGlvbnMgRUlELVEgMjAyMUUwHhcNMjQwNjEyMDY0NTI4WhcNMjkwNjE2MDY0NTI3WjCBlTELMAkGA1UEBhMCRUUxLzAtBgNVBAMMJk1BUlkgw4ROTixPJ0NPTk5Fxb0txaBVU0xJSyBURVNUTlVNQkVSMSUwIwYDVQQEDBxPJ0NPTk5Fxb0txaBVU0xJSyBURVNUTlVNQkVSMRIwEAYDVQQqDAlNQVJZIMOETk4xGjAYBgNVBAUTEVBOT0VFLTUxMzA3MTQ5NTYwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWlV1aVSXw6WhagWmFmXE_oe-0R1xZzrHyoiVlgKpGiJ8cwIQLogRGQnWY7NwgQvRHCBmsl99bj57h7SWnd03m6OCAYEwggF9MAkGA1UdEwQCMAAwHwYDVR0jBBgwFoAUScfc7QYUosdtnKbP11L9aOXoBBQwcAYIKwYBBQUHAQEEZDBiMDMGCCsGAQUFBzAChidodHRwOi8vYy5zay5lZS9URVNUX0VJRC1RXzIwMjFFLmRlci5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6Ly9haWEuZGVtby5zay5lZS9laWRxMjAyMWUweAYDVR0gBHEwbzAIBgYEAI96AQIwYwYJKwYBBAHOHxIBMFYwVAYIKwYBBQUHAgEWSGh0dHBzOi8vd3d3LnNraWRzb2x1dGlvbnMuZXUvcmVzb3VyY2VzL2NlcnRpZmljYXRpb24tcHJhY3RpY2Utc3RhdGVtZW50LzA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjFlLmNybDAdBgNVHQ4EFgQUj8KjnXvGQJCRYOd5LVfPku7QsZwwDgYDVR0PAQH_BAQDAgeAMAoGCCqGSM49BAMCA2gAMGUCMQCocXWDbBnkM3WEyBdv9Vm0A1MNRv08WrR192dRBcX42Kz5oiH0SdHRJv2ffeuEeSwCMEw2tSA3ClJv233Dl7rIYU_T6UG2NQhvDD5FhnP0umZRmVfAUQ6eVcmU8AhFtNJjwg==";
    private static final SdJwtWrapper MID_AUTH_TOKEN =
        new SdJwtWrapper(MID_AUTH_TOKEN_WITH_FILTERED_DISCLOSURES_BASE64URL);

    private static final String MID_AUTH_TOKEN_WITH_FILTERED_DISCLOSURES_FOR_RSA_CERT_BASE64URL =
        "eyJ0eXAiOiJ2bmQuY2RvYzIuYXV0aC10b2tlbi52MStzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJldHNpL1BOT0VFLTM5OTAxMDE5OTkyIiwiX3NkIjpbInJsR2ZHclhicDFEY0FnQUtIaGlJejFQNVdzRE9lanFTSVJKN3dmWllmMkUiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.Iyb8Mb2tjSiAAkdUhhBLxGvLknXfXPfsrSrjOvsaUbBVv9cLPB4EdPoPR7zDFV-w5htgTvwlT4M-e86-AET_yTnDD0T6NalNQM2MZx5WwLqxGijHD9F90BEjJt6KBgNKOBflmwAMdUaxxrbmMR_DRU8GI28AzAkhsFRp7CneIHsD4_MDE3uYFnDT387h3ssJxQauu6u4j7vfLfKm5G6xH9OhxfNBZqgPWaop64eqAOCFtT-cVJ0LKalqb94ISaiybnUTmUVx6eJaf2NQz8ylBUNse0alzd0Nd68Gg0cQrf04keDIZ32IG2ser9Oa0b2NwmU1PVX5AG1o_ZVqai7urQ~WyI0bzVYU2VTbi1LdVQ0eExJZU0xWWd3IiwiYXVkIixbeyIuLi4iOiJYMEJETHRfZW1HQVJMa2NYeXItdHNTa3oxRUxGdVJvdnJSTUdfeUlxRTA0In0seyIuLi4iOiJJak9KNC1wVDJEcldHSmMxWjlKQmpXbUYwdjQzM3lCLVNWb0hsckRzbVY0In1dXQ~WyJEelVOU1o2MEtHT2k3M0tzX0VfMWdRIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0Mi9rZXktc2hhcmVzL2ZmMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGUwZGZmP25vbmNlPUFBRUNBd1FGQmdjSUNRb0xEQTROX3ciXQ~";
    private static final String MID_RSA_SIGNING_CERTIFICATE_BASE64URL =
        "MIIESTCCA9CgAwIBAgIQYoxNTpjf-fpF9YJoFuzfXDAKBggqhkjOPQQDAjBxMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEsMCoGA1UEAwwjVEVTVCBvZiBTSyBJRCBTb2x1dGlvbnMgRUlELVEgMjAyMUUwHhcNMjUwNTA1MTAzMTAzWhcNMzAwNTA5MTAzMTAyWjBwMQswCQYDVQQGEwJFRTEiMCAGA1UEAwwZVEVTVE5VTUJFUixSU0EsMzk5MDEwOTk5MjETMBEGA1UEBAwKVEVTVE5VTUJFUjEMMAoGA1UEKgwDUlNBMRowGAYDVQQFExFQTk9FRS0zOTkwMTAxOTk5MjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMPtigPkrty3_gJXsvsmDkAAYFwiHpRIAKrhqnbwZ6YpF-qsQZQc-8wdZxb6pPVCGGPI4c_nC2Q223Dqt9wOkcL9drwGbLKX3Vlr1pOAaBLYDZ8ci1MW0a91_IAStgS7ieUsUT51xll_J0l79B0MMuV3Op5ZGa3O9XzsVO3OLrY9PkiFWrNjAgydcVKCp3PEoMYRpC0fMNGImRloJa9tltR2yYwIXXKFLP1_OzfJYOcMYcn09fZNjx03HeSiA_W1P3SmRxP8XmpZTPJUxiags2Hwl2KP3VZlOi9_eCBW2-3dvVa3eAmK5tR4Bb0WYzcPE9NEG8uftKcU1LSrqZ4eC_8CAwEAAaOCAX4wggF6MAkGA1UdEwQCMAAwHwYDVR0jBBgwFoAUScfc7QYUosdtnKbP11L9aOXoBBQwcAYIKwYBBQUHAQEEZDBiMDMGCCsGAQUFBzAChidodHRwOi8vYy5zay5lZS9URVNUX0VJRC1RXzIwMjFFLmRlci5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6Ly9haWEuZGVtby5zay5lZS9laWRxMjAyMWUweAYDVR0gBHEwbzAIBgYEAI96AQIwYwYJKwYBBAHOHxIBMFYwVAYIKwYBBQUHAgEWSGh0dHBzOi8vd3d3LnNraWRzb2x1dGlvbnMuZXUvcmVzb3VyY2VzL2NlcnRpZmljYXRpb24tcHJhY3RpY2Utc3RhdGVtZW50LzA0BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vYy5zay5lZS90ZXN0X2VpZC1xXzIwMjFlLmNybDAdBgNVHQ4EFgQU47SEND7ponm7GcYaTxJkydVBQKcwCwYDVR0PBAQDAgeAMAoGCCqGSM49BAMCA2cAMGQCMF8CysKa-wUz8DtLXpaMOozw2_3X2sxC7AgkKbE7iRqZ9RRL9t9K1RBHSwz7YW71YwIwVZWlg2MhdqODcbWTOF4uqS29o9ETkPflLwrqiaCW5qQj2qEffILiNpgY7Adyq366";

    private static final String SIGNATURE_VALIDATION_PARAMS_BASE64URL =
        Base64.getUrlEncoder().encodeToString("""
            {
              "interactionsDigest": "4A3QKDqjmqAtxFj6SiY5kbTpLaDY7pPFp3oDA5qAc/8=",
              "interactionTypeUsed": "confirmationMessageAndVerificationCodeChoice",
              "signature": {
                "serverRandom": "moxzIbuBiNpW0ZwtaeybYTe0",
                "userChallenge": "qynnKC8ldGrnkCdpGKILdV2zcqJb5Wk54ZrUcEuHU5Y",
                "signatureAlgorithm": "rsassa-pss",
                "flowType": "Notification",
                "signatureAlgorithmParameters": {
                  "hashAlgorithm": "SHA-256",
                  "maskGenAlgorithm": {
                    "algorithm": "id-mgf1",
                    "parameters": {
                      "hashAlgorithm": "SHA-256"
                    }
                  },
                  "saltLength": 32,
                  "trailerField": "0xbc"
                }
              }
            }
            """.getBytes(StandardCharsets.UTF_8));

    private static final String RP_SERVER_WELL_KNOWN_JWK_JSON = """
        {
          "kty": "EC",
          "crv": "P-256",
          "x": "SIsDcu6c2CjOEIxZyh4ctZZA-zz4pFYv0duHPlNWinU",
          "y": "50dC54PpOVtBHBGyzW1S6DgaBts-ywY3KgOclSIV97M",
          "use": "enc",
          "kid": "rp-server-ec-key-2026"
        }
        """;

    private static final String CS_RP_SIGNED_HASH = "sj2RtSo7c1tx+J00KWWkzyv4iQ2L2cuX0InnFFi+GAQ=";
    private static final String CS_RP_NAME = "DEMO";
    private static final String CS_SIGNATURE_INPUT =
        "rp-sig=(\"x-rp-signed-hash\" \"x-rp-name\");created=1779011296;keyid=\"rp-server-ec-key-2026\"";
    private static final String CS_SIGNATURE =
        "rp-sig=:nt5aITnpc8JjVrOYw8q46bNieq9L7y8gBjw+rJJ7BoY4X3h8BL5PwwcUBzl70iTOvikGCBOmpjbDY1661EqMMA==:";

    private AuthTokenVerifier defaultAuthTokenVerifier;

    @BeforeEach
    void setUp() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        defaultAuthTokenVerifier = new AuthTokenVerifier(
            TestData.createTestIssuerTrustStoreFromCerts(List.of(
                ROOT_CERT_G1E,
                ISSUING_CERT_EID_Q_2024E,
                ISSUING_CERT_EID_Q_2021E
            )),
            false
        );
    }

    @Test
    void verifySidTokenSuccess() throws VerificationException {
        TokenVerificationResponse response = verifySidToken(SID_AUTH_TOKEN.getSdJwt());

        assertNotNull(response);
        assertTrue(response.nonceUri().getPath().contains(AUTH_NONCE_URI_PATH));
        assertEquals("PNOEE-40504040001", response.identifier().getSemanticsIdentifier());
    }

    @Test
    void verifyMidTokenSuccess() throws Exception {
        TokenVerificationResponse response = verifyDefaultMidToken(MID_AUTH_TOKEN.getSdJwt());

        assertNotNull(response);
        assertTrue(response.nonceUri().getPath().contains(AUTH_NONCE_URI_PATH));
        assertEquals("PNOEE-51307149560", response.identifier().getSemanticsIdentifier());
    }

    @Test
    void verifyMidTokenRSACertSuccess() throws Exception {
        TokenVerificationResponse response = defaultAuthTokenVerifier.verify(
            MID_AUTH_TOKEN_WITH_FILTERED_DISCLOSURES_FOR_RSA_CERT_BASE64URL,
            MID_RSA_SIGNING_CERTIFICATE_BASE64URL,
            null,
            getDefaultHttpSignatureParams()
        );

        assertNotNull(response);
        assertTrue(response.nonceUri().getPath().contains(AUTH_NONCE_URI_PATH));
        assertEquals("PNOEE-39901019992", response.identifier().getSemanticsIdentifier());
    }

    @Test
    void verifyTokenFailWhenNoSidMidParamsProvided() {
        VerificationException exception = assertThrows(VerificationException.class,
            () -> defaultAuthTokenVerifier.verify(
                SID_AUTH_TOKEN.getSdJwt(),
                SID_SIGNING_CERTIFICATE_BASE64URL,
                null,
                null
            )
        );

        assertTrue(exception.getMessage()
                .contains("One of SID RPv3 or RP countersignature "
                    + "verification params must be provided"),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void verifySidTokenFailWhenUnsupportedTyp() {
        VerificationException exception = assertThrows(VerificationException.class,
            () -> verifySidToken(SID_AUTH_TOKEN.replaceValue("typ", "UNKNOWN_TYPE"))
        );

        assertTrue(exception.getMessage()
                .contains("Unsupported \"typ\""),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void verifySidTokenFailWhenUnsupportedAlg() {
        VerificationException exception = assertThrows(VerificationException.class,
            () -> verifySidToken(SID_AUTH_TOKEN.replaceValue("alg", "UNKNOWN_ALG"))
        );

        assertTrue(exception.getMessage()
                .contains("Unsupported \"alg\""),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void verifySidTokenFailWhenIssDoesNotMatchCertificate() {
        VerificationException exception = assertThrows(VerificationException.class,
            () -> verifySidToken(SID_AUTH_TOKEN.replaceValue("iss", "etsi/PNOEE-40504040999"))
        );

        assertTrue(exception.getMessage()
                .contains("Token identity does not match certificate"),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void verifySidTokenFailWhenIssDoesNotStartWithEtsi() {
        VerificationException exception = assertThrows(VerificationException.class,
            () -> verifySidToken(SID_AUTH_TOKEN.replaceValue("iss", "PNOEE-40504040001"))
        );

        assertTrue(exception.getMessage()
                .contains("Only identifiers starting with etsi"),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void verifyMidTokenFailWhenUnsupportedTyp() {
        VerificationException exception = assertThrows(VerificationException.class,
            () -> verifyDefaultMidToken(MID_AUTH_TOKEN.replaceValue("typ", "UNKNOWN_TYPE"))
        );

        assertTrue(exception.getMessage()
                .contains("Unsupported \"typ\""),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void verifyMidTokenFailWhenUnsupportedAlg() {
        VerificationException exception = assertThrows(VerificationException.class,
            () -> verifyDefaultMidToken(MID_AUTH_TOKEN.replaceValue("alg", "UNKNOWN_ALG"))
        );

        assertTrue(exception.getMessage()
                .contains("Unsupported \"alg\""),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void verifyMidTokenFailWhenIssDoesNotMatchCertificate() {
        VerificationException exception = assertThrows(VerificationException.class,
            () -> verifyDefaultMidToken(MID_AUTH_TOKEN.replaceValue("iss", "etsi/PNOEE-40504040999"))
        );

        assertTrue(exception.getMessage()
                .contains("Token identity does not match certificate"),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void verifyMidTokenFailWhenIssDoesNotStartWithEtsi() {
        VerificationException exception = assertThrows(VerificationException.class,
            () -> verifyDefaultMidToken(MID_AUTH_TOKEN.replaceValue("iss", "PNOEE-40504040001"))
        );

        assertTrue(exception.getMessage()
                .contains("Only identifiers starting with etsi"),
            "Actual message: " + exception.getMessage());
    }

    @Test
    void verifyMidTokenFailsWhenRpCountersignatureInvalid() throws Exception {
        RpHttpSignatureVerifier.RpHttpSignatureParams invalidCsParams =
            new RpHttpSignatureVerifier.RpHttpSignatureParams(
                CS_RP_SIGNED_HASH,
                CS_RP_NAME,
                CS_SIGNATURE_INPUT,
                // mangled signature value — structurally invalid base64 wrapper
                "rp-sig=:not-a-valid-base64-signature:",
                List.of(JWK.parse(RP_SERVER_WELL_KNOWN_JWK_JSON))
            );

        assertThrows(VerificationException.class,
            () -> defaultAuthTokenVerifier.verify(
                MID_AUTH_TOKEN.getSdJwt(),
                MID_EC_SIGNING_CERTIFICATE_BASE64URL,
                null,
                invalidCsParams
            )
        );
    }

    @Test
    void verifySidTokenWithOptionalRpCountersignaturePasses() throws Exception {
        TokenVerificationResponse response = defaultAuthTokenVerifier.verify(
            SID_AUTH_TOKEN.getSdJwt(),
            SID_SIGNING_CERTIFICATE_BASE64URL,
            new AuthTokenVerifier.SidAuthTokenVerificationParams(
                SIGNATURE_VALIDATION_PARAMS_BASE64URL,
                "DEMO",
                "smart-id-demo"
            ),
            getDefaultHttpSignatureParams()
        );

        assertNotNull(response);
        assertTrue(response.nonceUri().getPath().contains(AUTH_NONCE_URI_PATH));
        assertEquals("PNOEE-40504040001", response.identifier().getSemanticsIdentifier());
    }

    private TokenVerificationResponse verifySidToken(String token) throws VerificationException {
        return defaultAuthTokenVerifier.verify(
            token,
            SID_SIGNING_CERTIFICATE_BASE64URL,
            new AuthTokenVerifier.SidAuthTokenVerificationParams(
                SIGNATURE_VALIDATION_PARAMS_BASE64URL,
                "DEMO",
                "smart-id-demo"
            ),
            null
        );
    }

    private TokenVerificationResponse verifyDefaultMidToken(String token) throws Exception {
        return defaultAuthTokenVerifier.verify(
            token,
            MID_EC_SIGNING_CERTIFICATE_BASE64URL,
            null,
            getDefaultHttpSignatureParams()
        );
    }

    private RpHttpSignatureVerifier.RpHttpSignatureParams getDefaultHttpSignatureParams()
        throws ParseException {
        return new RpHttpSignatureVerifier.RpHttpSignatureParams(
            CS_RP_SIGNED_HASH,
            CS_RP_NAME,
            CS_SIGNATURE_INPUT,
            CS_SIGNATURE,
            List.of(JWK.parse(RP_SERVER_WELL_KNOWN_JWK_JSON))
        );
    }
}