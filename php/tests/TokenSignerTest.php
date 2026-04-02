<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../url_signing.php';

class TokenSignerTest extends TestCase
{
    private const SECURITY_KEY = 'SecurityKey';
    private const EXPIRES_AT = 1598024587;

    public function testWithCountriesAllowed(): void
    {
        $result = sign_bcdn_url(
            'https://token-tester.b-cdn.net/300kb.jpg',
            self::SECURITY_KEY, 86400, '', false, '/', 'CA', '', false,
            self::EXPIRES_AT
        );

        $this->assertSame(
            'https://token-tester.b-cdn.net/300kb.jpg?token=HS256-JWU7jhpnBGI-O54AYDAtrlZT86Ied4RTO2-Y8mUj60A&token_countries=CA&token_path=%2F&expires=1598024587',
            $result
        );
    }

    public function testWithCountriesBlocked(): void
    {
        $result = sign_bcdn_url(
            'https://token-tester.b-cdn.net/300kb.jpg',
            self::SECURITY_KEY, 86400, '', false, '', '', 'CA', false,
            self::EXPIRES_AT
        );

        $this->assertSame(
            'https://token-tester.b-cdn.net/300kb.jpg?token=HS256-zKGmNRBaHRmB4THCwmIQK5U21wH-S9KaJ6Ht7Kq9Zlw&token_countries_blocked=CA&expires=1598024587',
            $result
        );
    }

    public function testWithIPAddress(): void
    {
        $result = sign_bcdn_url(
            'https://token-tester.b-cdn.net/300kb.jpg',
            self::SECURITY_KEY, 86400, '1.2.3.4', false, '', '', '', false,
            self::EXPIRES_AT
        );

        $this->assertSame(
            'https://token-tester.b-cdn.net/300kb.jpg?token=HS256-0A9FRzMI9ACT-5VKMPbJf7g8f7UHavqjBH1Z8HljoEk&expires=1598024587',
            $result
        );
    }

    public function testWithIPv6Address(): void
    {
        $result = sign_bcdn_url(
            'https://token-tester.b-cdn.net/300kb.jpg',
            self::SECURITY_KEY, 86400, '2001:0db8:85a3:0000:0000:8a2e:0370:7334', false, '', '', '', false,
            self::EXPIRES_AT
        );

        $this->assertSame(
            'https://token-tester.b-cdn.net/300kb.jpg?token=HS256-7CEOZ-eY9DjC36ZnazCM3Ykj3-bR6h9V_IncIVT2s2U&expires=1598024587',
            $result
        );
    }

    public function testCombinedIPv6CountryDirectory(): void
    {
        $result = sign_bcdn_url(
            'https://token-tester.b-cdn.net/abc/',
            self::SECURITY_KEY, 86400, '2001:0db8:85a3:0000:0000:8a2e:0370:7334', true, '', 'CA,US', '', false,
            self::EXPIRES_AT
        );

        $this->assertSame(
            'https://token-tester.b-cdn.net/bcdn_token=HS256-om4aK_1Gnb3m2_5WVMtLzD-vlubUyDo1mJ0FFrKU1Kk&token_countries=CA%2CUS&expires=1598024587/abc/',
            $result
        );
    }

    public function testWithPathAllowed(): void
    {
        $result = sign_bcdn_url(
            'https://token-tester.b-cdn.net/abc/300kb.jpg',
            self::SECURITY_KEY, 86400, '', false, '/abc', '', '', false,
            self::EXPIRES_AT
        );

        $this->assertSame(
            'https://token-tester.b-cdn.net/abc/300kb.jpg?token=HS256-uVZvT3SbEoVKYJyDJgbcsDmSFf73cv-uNUVaJiKWpbQ&token_path=%2Fabc&expires=1598024587',
            $result
        );
    }

    public function testDirectoryAllowed(): void
    {
        $result = sign_bcdn_url(
            'https://token-tester.b-cdn.net/abc/',
            self::SECURITY_KEY, 86400, '', true, '', '', '', false,
            self::EXPIRES_AT
        );

        $this->assertSame(
            'https://token-tester.b-cdn.net/bcdn_token=HS256-bTMv4RVOkjx2UXLfVDl-JIygaxfSIQP8UCnCy7CILuY&expires=1598024587/abc/',
            $result
        );
    }

    public function testDirectoryAndPathAllowed(): void
    {
        $result = sign_bcdn_url(
            'https://token-tester.b-cdn.net/abc/',
            self::SECURITY_KEY, 86400, '', true, '/abc', '', '', false,
            self::EXPIRES_AT
        );

        $this->assertSame(
            'https://token-tester.b-cdn.net/bcdn_token=HS256-uVZvT3SbEoVKYJyDJgbcsDmSFf73cv-uNUVaJiKWpbQ&token_path=%2Fabc&expires=1598024587/abc/',
            $result
        );
    }

    public function testWithIgnoreParams(): void
    {
        $result = sign_bcdn_url(
            'https://token-tester.b-cdn.net/300kb.jpg?v=123',
            self::SECURITY_KEY, 86400, '', false, '', '', '', true,
            self::EXPIRES_AT
        );

        $this->assertSame(
            'https://token-tester.b-cdn.net/300kb.jpg?token=HS256-1lwWBD_c1IAGSj1UKPoxreu8ePDQ-Z9FoWLcRn_RRH0&token_ignore_params=true&expires=1598024587',
            $result
        );
    }

    public function testWithExistingQueryParams(): void
    {
        $result = sign_bcdn_url(
            'https://token-tester.b-cdn.net/300kb.jpg?v=123',
            self::SECURITY_KEY, 86400, '', false, '', '', '', false,
            self::EXPIRES_AT
        );

        $this->assertSame(
            'https://token-tester.b-cdn.net/300kb.jpg?token=HS256-q6oRQr-5ccQ-piO1HSEQu1DVMy9UMppRxGlIQwoeM5Y&v=123&expires=1598024587',
            $result
        );
    }

    public function testCombinedIPCountryDirectory(): void
    {
        $result = sign_bcdn_url(
            'https://token-tester.b-cdn.net/abc/',
            self::SECURITY_KEY, 86400, '1.2.3.4', true, '', 'CA,US', '', false,
            self::EXPIRES_AT
        );

        $this->assertSame(
            'https://token-tester.b-cdn.net/bcdn_token=HS256-pj8ytucbBWXT_M5cAqKGu4pshB2Q_s28G2uMfjhc3lA&token_countries=CA%2CUS&expires=1598024587/abc/',
            $result
        );
    }

    public function testWithSpeedLimit(): void
    {
        $result = sign_bcdn_url(
            'https://token-tester.b-cdn.net/300kb.jpg',
            self::SECURITY_KEY, 86400, '', false, '', '', '', false,
            self::EXPIRES_AT, 1000
        );

        $this->assertSame(
            'https://token-tester.b-cdn.net/300kb.jpg?token=HS256-DAVapqNNED3Z7JkjRTYX0UOIHNtbHEuuhRNEc4A7mMQ&limit=1000&expires=1598024587',
            $result
        );
    }

    public function testCombinedSpeedLimitIPDirectory(): void
    {
        $result = sign_bcdn_url(
            'https://token-tester.b-cdn.net/abc/',
            self::SECURITY_KEY, 86400, '1.2.3.4', true, '', '', '', false,
            self::EXPIRES_AT, 5000
        );

        $this->assertSame(
            'https://token-tester.b-cdn.net/bcdn_token=HS256-9M87MQhNKZqVdjqgHo1IMFVNa01tL2DwlmjBCtou08I&limit=5000&expires=1598024587/abc/',
            $result
        );
    }

    public function testValidationEmptyKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        sign_bcdn_url('https://example.com/file.jpg', '');
    }

    public function testValidationNegativeExpiry(): void
    {
        $this->expectException(InvalidArgumentException::class);
        sign_bcdn_url('https://example.com/file.jpg', 'key', -1);
    }
}
