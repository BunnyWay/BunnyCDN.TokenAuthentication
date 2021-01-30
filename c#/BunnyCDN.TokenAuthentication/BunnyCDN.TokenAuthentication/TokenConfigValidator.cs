using System;
using System.Linq;

namespace BunnyCDN.TokenAuthentication
{
    internal static class TokenConfigValidator
    {
        internal static void EnsureValid(TokenConfig config)
        {
            if (string.IsNullOrEmpty(config.SecurityKey))
                throw new ArgumentNullException(nameof(config.SecurityKey), "Please set SecurityKey");

            if (!config.HasExpiresAt)
                throw new ArgumentNullException(nameof(config), "Please set ExpiresAt");

            if (config.CountriesBlocked.Intersect(config.CountriesAllowed).Any())
                throw new ArgumentException("There are country(s) in BOTH the allowed and blocked country lists.");
        }
    }
}
