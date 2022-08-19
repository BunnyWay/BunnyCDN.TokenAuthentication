using Flurl;
using System;
using System.Linq;
using System.Text;

namespace BunnyCDN.TokenAuthentication
{
    /// <summary>
    /// https://support.bunnycdn.com/hc/en-us/articles/360016055099-How-to-sign-URLs-for-BunnyCDN-Token-Authentication <br />
    /// URL Token Authentication allows you to generate secure URLs that expire after the set timestamp and are only accessible<br />
    /// using a token generated using a secret key and an expiry timestamp.
    /// </summary>
    public static class TokenSigner
    {
        public static string SignUrl(Action<TokenConfig> configFunc)
        {
            var config = new TokenConfig();
            configFunc(config);
            TokenConfigValidator.EnsureValid(config);

            var url = AddCountrySettings(config, new Url(config.Url));
            var signaturePath = GetSignaturePath(config, url);

            var expires = config.ExpiresAt.ToUnixTimestamp();

            // Sort query parameters before generating base hash
            var hashableBase = $"{config.SecurityKey}{signaturePath}{config.UserIp}{expires}";
            var sortedParams = url.QueryParams.OrderBy(x => x.Name).ToList(); // sort & remove old items
            url.QueryParams.Clear();

            // Set sorted parameters and generate hash
            for (int i = 0; i < sortedParams.Count; i++)
            {
                url.SetQueryParam(sortedParams[i].Name, sortedParams[i].Value);
                hashableBase += (i == 0 ? "" : "&") + $"{sortedParams[i].Name}={sortedParams[i].Value}";
            }

            var token = ReplaceChars(GetBase64EncodedHash(hashableBase));

            // Overwrite the token_path to urlencode it for the final url
            url.SetQueryParam("token_path", config.TokenPath);

            // Add expires
            url.SetQueryParam("expires", expires);

            if (config.IsDirectory)
                return url.Root + "/bcdn_token=" + token + "&" + url.Query + url.Path;
            else
                return url.Root + url.Path + "?token=" + token + "&" + url.Query;
        }

        public static string SignUrl(string securityKey, string url, DateTimeOffset expireAt)
            => SignUrl(t =>
            {
                t.Url = url;
                t.SecurityKey = securityKey;
                t.ExpiresAt = expireAt;
            });

        public static string SignUrl(string securityKey, string url, DateTimeOffset expireAt, string ipAddress)
            => SignUrl(t =>
            {
                t.Url = url;
                t.SecurityKey = securityKey;
                t.ExpiresAt = expireAt;
                t.UserIp = ipAddress;
            });

        public static string SignUrl(string securityKey, string url, TimeSpan fromUTCNow, string ipAddress)
            => SignUrl(securityKey, url, DateTimeOffset.UtcNow.Add(fromUTCNow), ipAddress);

        public static string SignUrl(string securityKey, Uri url, DateTimeOffset expireAt, string ipAddress)
            => SignUrl(securityKey, url.ToString(), expireAt, ipAddress);


        private static Url AddCountrySettings(TokenConfig config, Url url)
        {
            if (config.CountriesAllowed.Any())
                url.SetQueryParam("token_countries", string.Join(",", config.CountriesAllowed).ToUpperInvariant(), true);

            if (config.CountriesBlocked.Any())
                url.SetQueryParam("token_countries_blocked", string.Join(",", config.CountriesBlocked).ToUpperInvariant(), true);

            return url;
        }

        private static string GetSignaturePath(TokenConfig config, Url url)
        {
            if (config.HasTokenPath)
            {
                url.SetQueryParam("token_path", config.TokenPath, true);
                return config.TokenPath;
            }
            else
                return url.Path;
        }

        private static string GetBase64EncodedHash(string hashableBase)
        {
            var sha256 = System.Security.Cryptography.SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(hashableBase));
            return Convert.ToBase64String(hash);
        }

        // To properly format the token you have to then replace the following characters in the
        // resulting Base64 string: '\n' with '', '+' with '-', '/' with '_' and '=' with ''.
        private static string ReplaceChars(string base64String)
            => base64String.Replace("\n", "").Replace("+", "-").Replace("/", "_").Replace("=", "");

    }
}
