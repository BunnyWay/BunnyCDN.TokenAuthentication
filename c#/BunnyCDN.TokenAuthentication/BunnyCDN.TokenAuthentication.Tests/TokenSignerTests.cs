using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Generic;

namespace BunnyCDN.TokenAuthentication.Tests
{
    [TestFixture]
    public class TokenSignerTests
    {
        private DateTimeOffset ExpiresAtGlobal;
        private const string SecurityKey = "SecurityKey";

        [SetUp]
        public void Setup()
        {
            ExpiresAtGlobal = new DateTimeOffset(2020, 08, 21, 15, 43, 07, TimeSpan.Zero);
        }

        [Test]
        public void WithCountriesAllowed()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
                t.SecurityKey = SecurityKey;
                t.CountriesAllowed = new List<string> { "CA" };
                t.ExpiresAt = ExpiresAtGlobal;
                t.TokenPath = "/";
            });

            url.ShouldBe("https://token-tester.b-cdn.net/300kb.jpg?token=HS256-JWU7jhpnBGI-O54AYDAtrlZT86Ied4RTO2-Y8mUj60A&token_countries=CA&token_path=%2F&expires=1598024587");
        }

        [Test]
        public void WithCountriesBlocked()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
                t.SecurityKey = SecurityKey;
                t.CountriesBlocked = new List<string> { "CA" };
                t.ExpiresAt = ExpiresAtGlobal;
            });

            url.ShouldBe("https://token-tester.b-cdn.net/300kb.jpg?token=HS256-zKGmNRBaHRmB4THCwmIQK5U21wH-S9KaJ6Ht7Kq9Zlw&token_countries_blocked=CA&expires=1598024587");
        }

        [Test]
        public void WithIPAddress()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
                t.SecurityKey = SecurityKey;
                t.ExpiresAt = ExpiresAtGlobal;
                t.UserIp = "1.2.3.4";
            });

            url.ShouldBe("https://token-tester.b-cdn.net/300kb.jpg?token=HS256-0A9FRzMI9ACT-5VKMPbJf7g8f7UHavqjBH1Z8HljoEk&expires=1598024587");
        }

        [Test]
        public void WithIPv6Address()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
                t.SecurityKey = SecurityKey;
                t.ExpiresAt = ExpiresAtGlobal;
                t.UserIp = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
            });

            url.ShouldBe("https://token-tester.b-cdn.net/300kb.jpg?token=HS256-7CEOZ-eY9DjC36ZnazCM3Ykj3-bR6h9V_IncIVT2s2U&expires=1598024587");
        }

        [Test]
        public void CombinedIPv6CountryDirectory()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/abc/";
                t.SecurityKey = SecurityKey;
                t.ExpiresAt = ExpiresAtGlobal;
                t.IsDirectory = true;
                t.UserIp = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
                t.CountriesAllowed = new List<string> { "CA", "US" };
            });

            url.ShouldBe("https://token-tester.b-cdn.net/bcdn_token=HS256-om4aK_1Gnb3m2_5WVMtLzD-vlubUyDo1mJ0FFrKU1Kk&token_countries=CA%2CUS&expires=1598024587/abc/");
        }

        [Test]
        public void ConvenienceOverloadWithIPv6()
        {
            var utcNowPlusOneHour = DateTimeOffset.UtcNow.Add(TimeSpan.FromHours(1));

            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
                t.SecurityKey = SecurityKey;
                t.ExpiresAt = utcNowPlusOneHour;
                t.UserIp = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
            });

            var urlConvenient = TokenSigner.SignUrl(SecurityKey, "https://token-tester.b-cdn.net/300kb.jpg", utcNowPlusOneHour, "2001:0db8:85a3:0000:0000:8a2e:0370:7334");

            urlConvenient.ShouldBe(url);
        }

        [Test]
        public void WithPathAllowed()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/abc/300kb.jpg";
                t.SecurityKey = SecurityKey;
                t.ExpiresAt = ExpiresAtGlobal;
                t.TokenPath = "/abc";
            });

            url.ShouldBe("https://token-tester.b-cdn.net/abc/300kb.jpg?token=HS256-uVZvT3SbEoVKYJyDJgbcsDmSFf73cv-uNUVaJiKWpbQ&token_path=%2Fabc&expires=1598024587");
        }

        [Test]
        public void DirectoryAllowed()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/abc/";
                t.SecurityKey = SecurityKey;
                t.ExpiresAt = ExpiresAtGlobal;
                t.IsDirectory = true;
            });

            url.ShouldBe("https://token-tester.b-cdn.net/bcdn_token=HS256-bTMv4RVOkjx2UXLfVDl-JIygaxfSIQP8UCnCy7CILuY&expires=1598024587/abc/");
        }

        [Test]
        public void DirectoryAndPathAllowed()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/abc/";
                t.SecurityKey = SecurityKey;
                t.ExpiresAt = ExpiresAtGlobal;
                t.IsDirectory = true;
                t.TokenPath = "/abc";
            });

            url.ShouldBe("https://token-tester.b-cdn.net/bcdn_token=HS256-uVZvT3SbEoVKYJyDJgbcsDmSFf73cv-uNUVaJiKWpbQ&token_path=%2Fabc&expires=1598024587/abc/");
        }

        [Test]
        public void WithIgnoreParams()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/300kb.jpg?v=123";
                t.SecurityKey = SecurityKey;
                t.ExpiresAt = ExpiresAtGlobal;
                t.IgnoreParams = true;
            });

            url.ShouldBe("https://token-tester.b-cdn.net/300kb.jpg?token=HS256-1lwWBD_c1IAGSj1UKPoxreu8ePDQ-Z9FoWLcRn_RRH0&token_ignore_params=true&expires=1598024587");
        }

        [Test]
        public void WithExistingQueryParams()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/300kb.jpg?v=123";
                t.SecurityKey = SecurityKey;
                t.ExpiresAt = ExpiresAtGlobal;
            });

            url.ShouldBe("https://token-tester.b-cdn.net/300kb.jpg?token=HS256-q6oRQr-5ccQ-piO1HSEQu1DVMy9UMppRxGlIQwoeM5Y&v=123&expires=1598024587");
        }

        [Test]
        public void CombinedIPCountryDirectory()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/abc/";
                t.SecurityKey = SecurityKey;
                t.ExpiresAt = ExpiresAtGlobal;
                t.IsDirectory = true;
                t.UserIp = "1.2.3.4";
                t.CountriesAllowed = new List<string> { "CA", "US" };
            });

            url.ShouldBe("https://token-tester.b-cdn.net/bcdn_token=HS256-pj8ytucbBWXT_M5cAqKGu4pshB2Q_s28G2uMfjhc3lA&token_countries=CA%2CUS&expires=1598024587/abc/");
        }

        [Test]
        public void ConvenienceOverload()
        {
            var utcNowPlusOneHour = DateTimeOffset.UtcNow.Add(TimeSpan.FromHours(1));

            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
                t.SecurityKey = SecurityKey;
                t.ExpiresAt = utcNowPlusOneHour;
                t.UserIp = "1.2.3.4";
            });

            var urlConvenient = TokenSigner.SignUrl(SecurityKey, "https://token-tester.b-cdn.net/300kb.jpg", utcNowPlusOneHour, "1.2.3.4");

            urlConvenient.ShouldBe(url);
        }

        [Test]
        public void WithSpeedLimit()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
                t.SecurityKey = SecurityKey;
                t.ExpiresAt = ExpiresAtGlobal;
                t.SpeedLimit = 1000;
            });

            url.ShouldBe("https://token-tester.b-cdn.net/300kb.jpg?token=HS256-DAVapqNNED3Z7JkjRTYX0UOIHNtbHEuuhRNEc4A7mMQ&limit=1000&expires=1598024587");
        }

        [Test]
        public void CombinedSpeedLimitIPDirectory()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/abc/";
                t.SecurityKey = SecurityKey;
                t.ExpiresAt = ExpiresAtGlobal;
                t.IsDirectory = true;
                t.UserIp = "1.2.3.4";
                t.SpeedLimit = 5000;
            });

            url.ShouldBe("https://token-tester.b-cdn.net/bcdn_token=HS256-9M87MQhNKZqVdjqgHo1IMFVNa01tL2DwlmjBCtou08I&limit=5000&expires=1598024587/abc/");
        }

        [Test]
        public void ValidationEmptySecurityKey()
        {
            Should.Throw<ArgumentNullException>(() =>
                TokenSigner.SignUrl(t =>
                {
                    t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
                    t.SecurityKey = "";
                    t.ExpiresAt = ExpiresAtGlobal;
                }));
        }

        [Test]
        public void ValidationMissingExpiry()
        {
            Should.Throw<ArgumentNullException>(() =>
                TokenSigner.SignUrl(t =>
                {
                    t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
                    t.SecurityKey = SecurityKey;
                }));
        }
    }
}
