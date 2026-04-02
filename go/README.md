# BunnyCDN.TokenAuthentication
## Go Version
### Introduction

Requires Go 1.21+. No external dependencies.

### Usage

```go
import bunnycdn "bunnycdn-token-authentication"

url, err := bunnycdn.SignUrl(
    "https://example.b-cdn.net/video.mp4",
    "your-security-key",
    3600,   // expirationTime
    "",     // userIp
    false,  // isDirectory
    "",     // pathAllowed
    "GB",   // countriesAllowed
    "",     // countriesBlocked
    false,  // ignoreParams
    nil,    // expiresAt
)
```

### Testing

```
go test -v
```
