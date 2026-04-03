# BunnyCDN.TokenAuthentication
## Ruby
### Introduction

This has been tested on Ruby 3.1.1, 3.2.0 and 3.3.0, 3.3.4 & 3.3.5

### Usage

An example:

```ruby
sec_key = "229248f0-f007-4bf9-ba1f-bbf1b4ad9d40"

signed_url = sign_url("https://token-tester.b-cdn.net/300kb.jpg", sec_key: sec_key, expiration_time: 3600, path_allowed: "/300kb", countries_allowed: 'AU,NZ')

signed_url = sign_url("https://token-tester.b-cdn.net/300kb.jpg", sec_key: sec_key, expiration_time: 3600, path_allowed: "/300kb", countries_allowed: 'AU,NZ', path_url: true)
```
