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
            "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-0A9FRzMI9ACT-5VKMPbJf7g8f7UHavqjBH1Z8HljoEk&expires=1598024587",
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
            "https://token-tester.b-cdn.net/bcdn_token=HS256-pj8ytucbBWXT_M5cAqKGu4pshB2Q_s28G2uMfjhc3lA&token_countries=CA%2CUS&expires=1598024587/abc/",
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
}
