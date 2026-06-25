using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using BunnyCDN.TokenAuthentication;

internal static class Program
{
    private static int Main()
    {
        var inputsPath = FindInputsJson();
        if (inputsPath == null)
        {
            Console.Error.WriteLine("Could not locate e2e/inputs.json");
            return 1;
        }

        using var doc = JsonDocument.Parse(File.ReadAllText(inputsPath));
        var root = doc.RootElement;

        var key = root.GetProperty("key").GetString() ?? "";
        var expires = root.GetProperty("expires").GetInt64();
        var host = root.GetProperty("host").GetString() ?? "";

        var tokens = new Dictionary<string, string>();

        foreach (var c in root.GetProperty("cases").EnumerateArray())
        {
            var name = c.GetProperty("name").GetString() ?? "";
            var path = c.GetProperty("path").GetString() ?? "";
            var userIp = c.GetProperty("userIp").GetString() ?? "";
            var isDirectory = c.GetProperty("isDirectory").GetBoolean();
            var pathAllowed = c.GetProperty("pathAllowed").GetString() ?? "";
            var countriesAllowed = c.GetProperty("countriesAllowed").GetString() ?? "";
            var countriesBlocked = c.GetProperty("countriesBlocked").GetString() ?? "";
            var ignoreParams = c.GetProperty("ignoreParams").GetBoolean();
            var speedLimit = c.GetProperty("speedLimit").GetInt32();
            // countryCode is intentionally ignored for signing.

            var signedUrl = TokenSigner.SignUrl(t =>
            {
                t.Url = host + path;
                t.SecurityKey = key;
                t.ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(expires);
                t.UserIp = userIp;
                t.IsDirectory = isDirectory;
                t.TokenPath = pathAllowed;
                t.CountriesAllowed = countriesAllowed == ""
                    ? new List<string>()
                    : new List<string>(countriesAllowed.Split(','));
                t.CountriesBlocked = countriesBlocked == ""
                    ? new List<string>()
                    : new List<string>(countriesBlocked.Split(','));
                t.IgnoreParams = ignoreParams;
                t.SpeedLimit = speedLimit;
            });

            tokens[name] = ExtractToken(signedUrl);
        }

        var json = JsonSerializer.Serialize(tokens, new JsonSerializerOptions { WriteIndented = false });
        Console.WriteLine(json);
        return 0;
    }

    private static string ExtractToken(string url)
    {
        var marker = "bcdn_token=";
        var idx = url.IndexOf(marker, StringComparison.Ordinal);
        if (idx < 0)
        {
            marker = "token=";
            idx = url.IndexOf(marker, StringComparison.Ordinal);
        }

        if (idx < 0)
            return "";

        var start = idx + marker.Length;
        var amp = url.IndexOf('&', start);
        return amp < 0 ? url.Substring(start) : url.Substring(start, amp - start);
    }

    private static string? FindInputsJson()
    {
        var dir = AppContext.BaseDirectory;
        while (dir != null)
        {
            var candidate = Path.Combine(dir, "e2e", "inputs.json");
            if (File.Exists(candidate))
                return candidate;
            dir = Path.GetDirectoryName(dir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        }
        return null;
    }
}
