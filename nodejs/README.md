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
