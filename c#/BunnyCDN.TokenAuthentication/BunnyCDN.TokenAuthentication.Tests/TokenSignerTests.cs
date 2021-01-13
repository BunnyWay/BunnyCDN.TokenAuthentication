using NUnit.Framework;
using Shouldly;
using System;
using System.Collections.Generic;

namespace BunnyCDN.TokenAuthentication.Tests
{
    [TestFixture]
    public class TokenSignerTests
    {
        [Test]
        public void WithCountriesAllowed()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
                t.SecurityKey = "SecurityKey";
                t.CountriesAllowed = new List<string> { "CA" };
                t.ExpiresAt = new DateTimeOffset(2020, 08, 21, 15, 43, 07, TimeSpan.Zero);
                t.TokenPath = "/";
            });

            url.ShouldBe<string>("https://token-tester.b-cdn.net/300kb.jpg?token=3ZdIIg1-PB_UOF62lQIqfT4MWr2ENIdd0KWnQVuej3w&token_countries=CA&token_path=%2F&expires=1598024587");
        }

        [Test]
        public void WithIPAddressAllowed()
        {
            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
                t.SecurityKey = "SecurityKey";
                t.ExpiresAt = new DateTimeOffset(2020, 08, 21, 15, 43, 07, TimeSpan.Zero);
                t.UserIp = "1.2.3.4";
            });

            url.ShouldBe<string>("https://token-tester.b-cdn.net/300kb.jpg?token=xUWMwsZcXfzxMvTTFiKAN6if1WBhDZV1Shjt_GOrjG0&expires=1598024587");
        }

        [Test]
        public void WithIPAddressAllowed_ConvienenceMethod()
        {
            var utcNowPlusOneHour = DateTimeOffset.UtcNow.Add(TimeSpan.FromHours(1));

            var url = TokenSigner.SignUrl(t =>
            {
                t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
                t.SecurityKey = "SecurityKey";
                t.ExpiresAt = utcNowPlusOneHour;
                t.UserIp = "1.2.3.4";
            });

            var urlConvienent = TokenSigner.SignUrl("SecurityKey", "https://token-tester.b-cdn.net/300kb.jpg", utcNowPlusOneHour, "1.2.3.4");

            urlConvienent.ShouldBe<string>(url);
        }

    }




}
