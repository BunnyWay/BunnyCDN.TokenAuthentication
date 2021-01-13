using System;
using System.Collections.Generic;

namespace BunnyCDN.TokenAuthentication
{
    /// <summary>
    /// https://support.bunnycdn.com/hc/en-us/articles/360016055099
    /// </summary>
    public class TokenConfig
    {
        /// <summary>
        /// CDN URL without the trailing '/' - eg:. http://test.b-cdn.net/file.png
        /// </summary>
        public string Url { get; set; }

        public string TokenPath { get; set; }
        internal bool HasTokenPath => !string.IsNullOrEmpty(TokenPath);

        public bool IsDirectory { get; set; }

        /// <summary>
        /// (required) Token security key from the URL Token Authentication box
        /// </summary>
        public string SecurityKey { get; set; }

        /// <summary>
        /// Optional parameter if you have the User IP feature enabled
        /// </summary>
        public string UserIp { get; set; }

        /// <summary>
        /// Any request after this timestamp will be rejected
        /// </summary>
        public DateTimeOffset ExpiresAt { get; set; } = DateTimeOffset.MinValue;
        internal bool HasExpiresAt => ExpiresAt != DateTimeOffset.MinValue;

        /// <summary>
        /// The token_countries allows you to specify a list of countries that will have access to the URL.
        /// Any request outside of these countries will be rejected.
        ///  List of countries allowed (exp. CA, US, TH)
        /// </summary>
        public IEnumerable<string> CountriesAllowed { get; set; } = new List<string>();

        /// <summary>
        /// The token_countries_blocked is similar to token_countries.
        /// It allows you to specify a list of countries that will not have access to the URL.
        /// Any request from one of the listed countries will be rejected
        /// List of countries blocked (exp. CA, US, TH)
        /// </summary>
        public IEnumerable<string> CountriesBlocked { get; set; } = new List<string>();


    }




}
