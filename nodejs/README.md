# BunnyCDN.TokenAuthentication
## NodeJS Version
### Introduction

This has been tested on NodeJS versions 15 and onwards.

### Usage

An example:

```
var securityKey = "229248f0-f007-4bf9-ba1f-bbf1b4ad9d40";
var signedUrl = signUrl("https://token-tester.b-cdn.net/300kb.jpg", securityKey, 3600, "/", "", "");
```

### Parameters

```
url: CDN URL w/o the trailing '/' - exp. http://test.b-cdn.net/file.png
securityKey: Security token found in your pull zone
expirationTime: Authentication validity (default. 86400 sec/24 hrs)
userIp: Optional parameter if you have the User IP feature enabled
isDirectory: Optional parameter - "true" returns a URL separated by forward slashes (exp. (domain)/bcdn_token=...)
pathAllowed: Directory to authenticate (exp. /path/to/images)
countriesAllowed: List of countries allowed (exp. CA, US, TH)
countriesBlocked: List of countries blocked (exp. CA, US, TH)
```
