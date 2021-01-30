using System;

namespace BunnyCDN.TokenAuthentication
{
    internal static class TimeExtensions
    {
        internal static string ToUnixTimestamp(this DateTimeOffset time)
            => time.ToUnixTimeSeconds().ToString();
    }


}
