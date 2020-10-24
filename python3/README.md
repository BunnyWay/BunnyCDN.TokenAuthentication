# BunnyCDN.TokenAuthentication
## Python 3 Version
### Introduction

This has been tested on Python 3.6, 3.7 and 3.8. This should work on all Python 3 environments -- Python 2 is **NOT** supported.

### Usage

An example:

```
sec_key = "229248f0-f007-4bf9-ba1f-bbf1b4ad9d40"
signed_url = sign_url("https://token-tester.b-cdn.net/300kb.jpg", sec_key, expiration_time = 3600, user_ip = "", isDirectory = True, path_allowed = "/", countries_allowed = "", countries_blocked = "")
```
