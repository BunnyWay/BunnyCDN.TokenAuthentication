using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
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

            var uri = new Uri(config.Url);

            var queryParams = ParseQueryString(uri.Query);

            if (config.CountriesAllowed.Any())
                queryParams["token_countries"] = string.Join(",", config.CountriesAllowed).ToUpperInvariant();
            if (config.CountriesBlocked.Any())
                queryParams["token_countries_blocked"] = string.Join(",", config.CountriesBlocked).ToUpperInvariant();

            var expires = config.ExpiresAt.ToUnixTimestamp();

            var parameters = BuildParameters(queryParams, config.IgnoreParams, config.TokenPath);
            var signaturePath = config.HasTokenPath ? config.TokenPath : uri.AbsolutePath;

            var signingData = JoinParams(parameters, encode: false);
            var urlData = JoinParams(parameters, encode: true);

            var message = string.Concat(signaturePath, expires, signingData, config.UserIp);
            var token = "HS256-" + HmacSha256Base64Url(config.SecurityKey, message);

            var baseUrl = string.Concat(uri.Scheme, "://", uri.Authority);
            var tail = urlData.Length > 0 ? string.Concat("&", urlData) : "";

            if (config.IsDirectory)
                return string.Concat(baseUrl, "/bcdn_token=", token, tail, "&expires=", expires, uri.AbsolutePath);
            else
                return string.Concat(baseUrl, uri.AbsolutePath, "?token=", token, tail, "&expires=", expires);
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

        public static string SignUrl(string securityKey, string url, TimeSpan fromUtcNow, string ipAddress)
            => SignUrl(securityKey, url, DateTimeOffset.UtcNow.Add(fromUtcNow), ipAddress);

        public static string SignUrl(string securityKey, Uri url, DateTimeOffset expireAt, string ipAddress)
            => SignUrl(securityKey, url.ToString(), expireAt, ipAddress);

        private static SortedDictionary<string, string> BuildParameters(
            Dictionary<string, string> queryParams,
            bool ignoreParams,
            string tokenPath)
        {
            var result = new SortedDictionary<string, string>(StringComparer.Ordinal);

            if (ignoreParams)
            {
                result["token_ignore_params"] = "true";
            }
            else
            {
                foreach (var kv in queryParams)
                    result[kv.Key] = kv.Value;
            }

            if (!string.IsNullOrEmpty(tokenPath))
                result["token_path"] = tokenPath;

            return result;
        }

        private static string JoinParams(SortedDictionary<string, string> parameters, bool encode)
        {
            if (parameters.Count == 0)
                return "";

            var sb = new StringBuilder();
            var first = true;
            foreach (var kv in parameters)
            {
                if (!first) sb.Append('&');
                sb.Append(kv.Key);
                sb.Append('=');
                sb.Append(encode ? Uri.EscapeDataString(kv.Value) : kv.Value);
                first = false;
            }
            return sb.ToString();
        }

        private static Dictionary<string, string> ParseQueryString(string query)
        {
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            if (string.IsNullOrEmpty(query))
                return result;

            // Skip leading '?'
            var start = query[0] == '?' ? 1 : 0;
            if (start >= query.Length)
                return result;

            var pairs = query.Substring(start).Split('&');
            for (var i = 0; i < pairs.Length; i++)
            {
                var part = pairs[i];
                if (part.Length == 0) continue;

                var eqIdx = part.IndexOf('=');
                string key, value;
                if (eqIdx < 0)
                {
                    key = Uri.UnescapeDataString(part);
                    value = "";
                }
                else
                {
                    key = Uri.UnescapeDataString(part.Substring(0, eqIdx));
                    value = Uri.UnescapeDataString(part.Substring(eqIdx + 1));
                }

#if NET9_0_OR_GREATER
                if (!result.TryAdd(key, value))
                    throw new ArgumentException($"Multi-valued query parameter '{key}' is not supported");
#else
                if (result.ContainsKey(key))
                    throw new ArgumentException($"Multi-valued query parameter '{key}' is not supported");
                result[key] = value;
#endif
            }
            return result;
        }

#if NET6_0_OR_GREATER
        private static string HmacSha256Base64Url(string key, string message)
        {
            Span<byte> hash = stackalloc byte[32];

            var keyLen = Encoding.UTF8.GetByteCount(key);
            var msgLen = Encoding.UTF8.GetByteCount(message);

            byte[] rentedKey = null, rentedMsg = null;
            var keyBytes = keyLen <= 256
                ? stackalloc byte[keyLen]
                : (rentedKey = System.Buffers.ArrayPool<byte>.Shared.Rent(keyLen)).AsSpan(0, keyLen);
            var msgBytes = msgLen <= 1024
                ? stackalloc byte[msgLen]
                : (rentedMsg = System.Buffers.ArrayPool<byte>.Shared.Rent(msgLen)).AsSpan(0, msgLen);

            try
            {
                Encoding.UTF8.GetBytes(key, keyBytes);
                Encoding.UTF8.GetBytes(message, msgBytes);
                HMACSHA256.HashData(keyBytes, msgBytes, hash);
            }
            finally
            {
                if (rentedKey != null) System.Buffers.ArrayPool<byte>.Shared.Return(rentedKey);
                if (rentedMsg != null) System.Buffers.ArrayPool<byte>.Shared.Return(rentedMsg);
            }

            return Base64UrlNopad(hash);
        }

        private static string Base64UrlNopad(ReadOnlySpan<byte> bytes)
        {
            Span<char> buf = stackalloc char[44]; // ceil(32/3)*4
            Convert.TryToBase64Chars(bytes, buf, out var written);

            while (written > 0 && buf[written - 1] == '=') written--;

            for (var i = 0; i < written; i++)
            {
                ref var c = ref buf[i];
                if (c == '+') c = '-';
                else if (c == '/') c = '_';
            }

            return new string(buf.Slice(0, written));
        }
#else
        private static string HmacSha256Base64Url(string key, string message)
        {
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
            {
                var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
                return Convert.ToBase64String(hash)
                    .Replace('+', '-')
                    .Replace('/', '_')
                    .TrimEnd('=');
            }
        }
#endif
    }
}
