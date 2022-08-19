# BunnyCDN.TokenAuthentication
# C# Version

## Introduction
Currently built on .NET Core 3.1 (LTS). Will be moved (eventually) to .NET 6.0, when 3.1 reaches EOL.

## Usage
An example:

To use all the configuration options, pass a lambda to configure:
``` csharp
var signedUrl = TokenSigner.SignUrl(t =>
{
    t.Url = "https://token-tester.b-cdn.net/300kb.jpg";
    t.SecurityKey = "SecurityKey";
    t.CountriesAllowed = new List<string> { "CA" };
    t.ExpiresAt = new DateTimeOffset(2020, 08, 21, 15, 43, 07, TimeSpan.Zero);
    t.TokenPath = "/";
});
```

There are also some convenience methods, eg:

``` csharp
var utcNowPlusOneHour = DateTimeOffset.UtcNow.Add(TimeSpan.FromHours(1));
var signedUrl = TokenSigner.SignUrl("SecurityKey", "https://token-tester.b-cdn.net/300kb.jpg", utcNowPlusOneHour, "1.2.3.4");
```

``` csharp
public static string SignUrl(string securityKey, string url, DateTimeOffset expireAt)
```
``` csharp
public static string SignUrl(string securityKey, string url, DateTimeOffset expireAt, string ipAddress)
```
``` csharp
public static string SignUrl(string securityKey, string url, TimeSpan fromUTCNow, string ipAddress)
```
``` csharp
public static string SignUrl(string securityKey, Uri url, DateTimeOffset expireAt, string ipAddress)
```
