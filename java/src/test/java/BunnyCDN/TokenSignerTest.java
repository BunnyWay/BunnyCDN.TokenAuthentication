package BunnyCDN;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TokenSignerTest {

    private static final String SECURITY_KEY = "SecurityKey";
    private static final long EXPIRES_AT = 1598024587L;

    @Test
    void testWithCountriesAllowed() {
        String result = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/300kb.jpg",
            SECURITY_KEY, 86400, "", false, "/", "CA", null, false, EXPIRES_AT
        );
        assertEquals(
            "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-JWU7jhpnBGI-O54AYDAtrlZT86Ied4RTO2-Y8mUj60A&token_countries=CA&token_path=%2F&expires=1598024587",
            result
        );
    }

    @Test
    void testWithCountriesBlocked() {
        String result = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/300kb.jpg",
            SECURITY_KEY, 86400, "", false, null, null, "CA", false, EXPIRES_AT
        );
        assertEquals(
            "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-zKGmNRBaHRmB4THCwmIQK5U21wH-S9KaJ6Ht7Kq9Zlw&token_countries_blocked=CA&expires=1598024587",
            result
        );
    }

    @Test
    void testWithIPAddress() {
        String result = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/300kb.jpg",
            SECURITY_KEY, 86400, "1.2.3.4", false, null, null, null, false, EXPIRES_AT
        );
        assertEquals(
            "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-1-L2rISTLcujMY9UFf2tbZ41d5i-Bme1g1oTK_Z2QMLJk&expires=1598024587",
            result
        );
    }

    @Test
    void testWithIPv6Address() {
        String result = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/300kb.jpg",
            SECURITY_KEY, 86400, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false, null, null, null, false, EXPIRES_AT
        );
        assertEquals(
            "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-1-1avZgnR84EtR3eNPVtiOT8RtI9UqcvijgXVU88vxZ60&expires=1598024587",
            result
        );
    }

    @Test
    void testIPv6CompressedFormMatchesExpanded() {
        String expanded = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/300kb.jpg",
            SECURITY_KEY, 86400, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false, null, null, null, false, EXPIRES_AT
        );
        String compressed = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/300kb.jpg",
            SECURITY_KEY, 86400, "2001:db8:85a3::8a2e:370:7334", false, null, null, null, false, EXPIRES_AT
        );
        assertEquals(expanded, compressed);
    }

    @Test
    void testCombinedIPv6CountryDirectory() {
        String result = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/abc/",
            SECURITY_KEY, 86400, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", true, null, "CA,US", null, false, EXPIRES_AT
        );
        assertEquals(
            "https://token-tester.b-cdn.net/bcdn_token=HS256-1-TrSbI6dVaWEq8s7tuydKyhJSo9oKHA64KBhb2SgNv0E&token_countries=CA%2CUS&expires=1598024587/abc/",
            result
        );
    }

    @Test
    void testWithPathAllowed() {
        String result = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/abc/300kb.jpg",
            SECURITY_KEY, 86400, "", false, "/abc", null, null, false, EXPIRES_AT
        );
        assertEquals(
            "https://token-tester.b-cdn.net/abc/300kb.jpg?token=HS256-uVZvT3SbEoVKYJyDJgbcsDmSFf73cv-uNUVaJiKWpbQ&token_path=%2Fabc&expires=1598024587",
            result
        );
    }

    @Test
    void testDirectoryAllowed() {
        String result = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/abc/",
            SECURITY_KEY, 86400, "", true, null, null, null, false, EXPIRES_AT
        );
        assertEquals(
            "https://token-tester.b-cdn.net/bcdn_token=HS256-bTMv4RVOkjx2UXLfVDl-JIygaxfSIQP8UCnCy7CILuY&expires=1598024587/abc/",
            result
        );
    }

    @Test
    void testDirectoryAndPathAllowed() {
        String result = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/abc/",
            SECURITY_KEY, 86400, "", true, "/abc", null, null, false, EXPIRES_AT
        );
        assertEquals(
            "https://token-tester.b-cdn.net/bcdn_token=HS256-uVZvT3SbEoVKYJyDJgbcsDmSFf73cv-uNUVaJiKWpbQ&token_path=%2Fabc&expires=1598024587/abc/",
            result
        );
    }

    @Test
    void testWithIgnoreParams() {
        String result = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/300kb.jpg?v=123",
            SECURITY_KEY, 86400, "", false, null, null, null, true, EXPIRES_AT
        );
        assertEquals(
            "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-1lwWBD_c1IAGSj1UKPoxreu8ePDQ-Z9FoWLcRn_RRH0&token_ignore_params=true&expires=1598024587",
            result
        );
    }

    @Test
    void testWithExistingQueryParams() {
        String result = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/300kb.jpg?v=123",
            SECURITY_KEY, 86400, "", false, null, null, null, false, EXPIRES_AT
        );
        assertEquals(
            "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-q6oRQr-5ccQ-piO1HSEQu1DVMy9UMppRxGlIQwoeM5Y&v=123&expires=1598024587",
            result
        );
    }

    @Test
    void testCombinedIPCountryDirectory() {
        String result = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/abc/",
            SECURITY_KEY, 86400, "1.2.3.4", true, null, "CA,US", null, false, EXPIRES_AT
        );
        assertEquals(
            "https://token-tester.b-cdn.net/bcdn_token=HS256-1-eZuSzuE7KvWxa-lfmEG6eVOp4OmuPlFyzD6acZT8j_o&token_countries=CA%2CUS&expires=1598024587/abc/",
            result
        );
    }

    @Test
    void testWithSpeedLimit() {
        String result = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/300kb.jpg",
            SECURITY_KEY, 86400, "", false, null, null, null, false, EXPIRES_AT, 1000
        );
        assertEquals(
            "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-DAVapqNNED3Z7JkjRTYX0UOIHNtbHEuuhRNEc4A7mMQ&limit=1000&expires=1598024587",
            result
        );
    }

    @Test
    void testCombinedSpeedLimitIPDirectory() {
        String result = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/abc/",
            SECURITY_KEY, 86400, "1.2.3.4", true, null, null, null, false, EXPIRES_AT, 5000
        );
        assertEquals(
            "https://token-tester.b-cdn.net/bcdn_token=HS256-1-NasywRGZDPxXIxBgQ2iyxSP3EWxxok3bzpYhWgaU8BQ&limit=5000&expires=1598024587/abc/",
            result
        );
    }

    @Test
    void testValidationEmptyKey() {
        assertThrows(IllegalArgumentException.class, () ->
            TokenSigner.signUrl("https://example.com/f.jpg", "", 86400, "", false, null, null, null)
        );
    }

    @Test
    void testValidationNegativeExpiry() {
        assertThrows(IllegalArgumentException.class, () ->
            TokenSigner.signUrl("https://example.com/f.jpg", "key", -1, "", false, null, null, null)
        );
    }

    @Test
    void testNoUserIpOmitsFlagPrefix() {
        String result = TokenSigner.signUrl(
            "https://token-tester.b-cdn.net/300kb.jpg",
            SECURITY_KEY, 86400, "", false, null, null, null, false, EXPIRES_AT
        );
        assertFalse(result.contains("HS256-1-"));
    }

    @Test
    void testInvalidIpThrows() {
        assertThrows(IllegalArgumentException.class, () ->
            TokenSigner.signUrl(
                "https://token-tester.b-cdn.net/300kb.jpg",
                SECURITY_KEY, 86400, "not-an-ip", false, null, null, null, false, EXPIRES_AT
            )
        );
    }
}
