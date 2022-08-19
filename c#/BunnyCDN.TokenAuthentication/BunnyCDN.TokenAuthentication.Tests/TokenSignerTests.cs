using NUnit.Framework;
using NUnit;
using Shouldly;
using System;
using System.Collections.Generic;

namespace BunnyCDN.TokenAuthentication.Tests
{
    [TestFixture]
    public class TokenSignerTests
    {

        public DateTimeOffset ExpiresAtGlobal { get; set; }
        public string SecurityKey { get; set; }

        [SetUp]
        public void Setup()
        {
            // Run all tests with a fixed date.
            ExpiresAtGlobal = new DateTimeOffset(2020, 08, 21, 15, 43, 07, TimeSpan.Zero);
            SecurityKey = "SecurityKey";
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

            Assert.That(url, Is.EqualTo("https://token-tester.b-cdn.net/300kb.jpg?token=3ZdIIg1-PB_UOF62lQIqfT4MWr2ENIdd0KWnQVuej3w&token_countries=CA&token_path=%2F&expires=1598024587"));
        }

        [Test]
        public void WithCountriesDisallowed()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
                t.SecurityKey = SecurityKey;
                t.CountriesBlocked = new List<string> { "CA" };
                t.ExpiresAt = ExpiresAtGlobal;
            });

            url.ShouldBe<string>("https://token-tester.b-cdn.net/300kb.jpg?token=bq6dlNKcoVbTrzCJepE5gHoC436eTtz97Ruk89V8tmU&token_countries_blocked=CA&expires=1598024587");
        }

        [Test]
        public void WithIPAddressAllowed()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
                t.SecurityKey = SecurityKey;
                t.ExpiresAt = ExpiresAtGlobal;
                t.UserIp = "1.2.3.4";
            });

            url.ShouldBe<string>("https://token-tester.b-cdn.net/300kb.jpg?token=jjTwdhWdTUAQSKbPyKGH9FSLqBe-FisgVWwGXnYEPIQ&expires=1598024587");
        }

        [Test]
        public void WithIPAddressAllowed_ConvienenceMethod()
        {
            var utcNowPlusOneHour = DateTimeOffset.UtcNow.Add(TimeSpan.FromHours(1));

            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
                t.SecurityKey = SecurityKey;
                t.ExpiresAt = utcNowPlusOneHour;
                t.UserIp = "1.2.3.4";
            });

            var urlConvienent = TokenSigner.SignUrl(SecurityKey, "https://token-tester.b-cdn.net/300kb.jpg", utcNowPlusOneHour, "1.2.3.4");

            urlConvienent.ShouldBe<string>(url);
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

            url.ShouldBe<string>("https://token-tester.b-cdn.net/abc/300kb.jpg?token=xwPaUzEMSgOZ7yl86K55G7len9n1UMiuP36IAyw8Mjs&token_path=%2Fabc&expires=1598024587");
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

            url.ShouldBe<string>("https://token-tester.b-cdn.net/bcdn_token=e0fYj-NC_YeROS_0gTGvscP7HR_Du78I7WBVSDV8P4E&expires=1598024587/abc/");
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

            url.ShouldBe<string>("https://token-tester.b-cdn.net/bcdn_token=xwPaUzEMSgOZ7yl86K55G7len9n1UMiuP36IAyw8Mjs&token_path=%2Fabc&expires=1598024587/abc/");
        }



    }

 

}
