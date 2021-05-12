# BunnyCDN.TokenAuthentication
## NodeJS Version
### Introduction

This has been tested on NodeJS versions 15 and onwards.

Please note that the key provided below _is valid_. Feel free to use it to test; the zone currently only has one file: `/300kb.jpg`.

### Usage

An example:

```
var securityKey = "229248f0-f007-4bf9-ba1f-bbf1b4ad9d40";
var signedUrl = signUrl("https://token-tester.b-cdn.net/300kb.jpg", securityKey, 7200, "", false, "/", "CA,US", "JP");
```

The call above will authenticate `https://token-tester.b-cdn.net/300kb.jpg` for a period of two hours (from the current time) + allows for Canadian and American users while blocking users from Japan. This will also default to a traditional query separated URL, exp. "https://token-tester.b-cdn.net/300kb.jpg?token=...&token_countries=...&token_countries_blocked=...&token_path=...&expires=..." will be returned.

If you'd like to use directory based URLs, use the following call instead.

```
var securityKey = "229248f0-f007-4bf9-ba1f-bbf1b4ad9d40";
var signedUrl = signUrl("https://token-tester.b-cdn.net/300kb.jpg", securityKey, 7200, "", true, "/", "CA,US", "JP");
```

The call above will yield a URL in the format of: "https://token-tester.b-cdn.net/bcdn_token=...&token_countries=...&token_countries_blocked=...&token_path=...&expires=.../300kb.jpgg."

### Parameters

(String) signUrl(url, securityKey, expirationTime = 3600, userIp, isDirectory = false, pathAllowed, countriesAllowed, countriesBlocked)

- **url:** CDN URL w/o the trailing '/' - exp. http://test.b-cdn.net/file.png
- **securityKey:** Security token found in your pull zone
- **expirationTime:** Authentication validity (default. 86400 sec/24 hrs)
- **userIp:** Optional parameter if you have the User IP feature enabled
- **isDirectory:** Optional parameter - "true" returns a URL separated by forward slashes (exp. (domain)/bcdn_token=.../path) while "false" returns a URL separated by traditional query - separators (?token=...)
- **pathAllowed:** Directory to authenticate (exp. /path/to/images)
- **countriesAllowed:** List of countries allowed (exp. CA, US, TH)
- **countriesBlocked:** List of countries blocked (exp. CA, US, TH)

