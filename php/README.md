# BunnyCDN.TokenAuthentication
## PHP Version
### Introduction
The PHP snipped allows you to easily sign a full URL with a single function call and serves as an example implementation of the BunnyCDN token authentication.



### Example
```
  // Single URL signing example
  echo sign_bcdn_url(
      "https://testvideo.b-cdn.net/300kb.jpg", // Url to sign
      "50955b6d-5678-4b24-8b69-bdba5bea3102", // Token Key
      360000, // Expiration time in seconds
      "110.168.31.2", // Place user IP here
      true, // Directory token 
      "/");
```
