# bunny.net Token Authentication

URL token authentication for [bunny.net](https://bunny.net). Generates signed URLs that expire after a set timestamp, validated using HMAC-SHA256.

## Implementations

| Language | Source | Min version | Dependencies |
|----------|--------|-------------|--------------|
| [C#](c%23/) | `TokenSigner.cs` | .NET Standard 2.0 / .NET 10 | None |
| [Python](python3/) | `token.py` | Python 3.9+ | None |
| [Node.js](nodejs/) | `token.js` | Node 18+ | None |
| [PHP](php/) | `url_signing.php` | PHP 7.4+ | None |
| [Java](java/) | `TokenSigner.java` | Java 11+ | None |
| [Go](go/) | `token.go` | Go 1.21+ | None |
| [Rust](rust/) | `src/lib.rs` | Rust 2021 edition | hmac, sha2, base64, url, percent-encoding |

## Token format

Tokens are HMAC-SHA256 signatures encoded as base64url (no padding) with an `HS256-` prefix:

```
HS256-<base64url(HMAC-SHA256(key, message))>
```

The signing message is constructed as:

```
{signaturePath}{expires}{signingData}{userIp}
```

Where `signingData` is the alphabetically-sorted query parameters joined as `key=value` pairs separated by `&`.

## Parameters

| Parameter | Description |
|-----------|-------------|
| `url` | CDN URL to sign (e.g. `https://example.b-cdn.net/file.png`) |
| `securityKey` | Token Authentication Key from your Pull Zone settings |
| `expirationTime` | Token validity in seconds (default: 86400 / 24h) |
| `userIp` | Lock the token to a specific IP address |
| `isDirectory` | `true`: token embedded in path (`/bcdn_token=...`), `false`: token in query string (`?token=...`) |
| `pathAllowed` | Restrict the token scope to a specific path |
| `countriesAllowed` | Comma-separated allow-list of country codes (e.g. `CA,US`) |
| `countriesBlocked` | Comma-separated block-list of country codes |
| `ignoreParams` | Exclude query parameters from token validation |
| `expiresAt` | Absolute Unix timestamp for expiration. Overrides `expirationTime` when set. In C# this is a `DateTimeOffset` property on `TokenConfig`. |
| `speedLimit` | Download speed limit in kB/s (0 = no limit). Maps to the `limit` query parameter. |

## Quick start

### C\#

```csharp
var url = TokenSigner.SignUrl(t =>
{
    t.Url = "https://example.b-cdn.net/video.mp4";
    t.SecurityKey = "your-security-key";
    t.ExpiresAt = DateTimeOffset.UtcNow.AddHours(1);
    t.CountriesAllowed = new List<string> { "GB" };
});
```

### Python

```python
from token import sign_url

url = sign_url(
    "https://example.b-cdn.net/video.mp4",
    "your-security-key",
    expiration_time=3600,
    is_directory=False,
    countries_allowed="GB",
)
```

### Node.js

```javascript
const { signUrl } = require('./token');

const url = signUrl(
    'https://example.b-cdn.net/video.mp4',
    'your-security-key',
    3600,
);
```

### PHP

```php
require_once 'url_signing.php';

$url = sign_bcdn_url(
    'https://example.b-cdn.net/video.mp4',
    'your-security-key',
    3600,
);
```

### Java

```java
import BunnyCDN.TokenSigner;

String url = TokenSigner.signUrl(
    "https://example.b-cdn.net/video.mp4",
    "your-security-key",
    3600,
    "",             // userIp
    false,          // isDirectory
    null,           // pathAllowed
    "GB",           // countriesAllowed
    null            // countriesBlocked
);
```

### Go

```go
import bunnycdn "bunnycdn-token-authentication"

url, err := bunnycdn.SignUrl(
    "https://example.b-cdn.net/video.mp4",
    "your-security-key",
    3600,           // expirationTime
    "",             // userIp
    false,          // isDirectory
    "",             // pathAllowed
    "GB",           // countriesAllowed
    "",             // countriesBlocked
    false,          // ignoreParams
    nil,            // expiresAt
    0,              // speedLimit
)
```

### Rust

```rust
use bunnycdn_token_authentication::sign_url;

let url = sign_url(
    "https://example.b-cdn.net/video.mp4",
    "your-security-key",
    3600,           // expiration_time
    "",             // user_ip
    false,          // is_directory
    "",             // path_allowed
    "GB",           // countries_allowed
    "",             // countries_blocked
    false,          // ignore_params
    None,           // expires_at
    0,              // speed_limit
).unwrap();
```

## URL formats

**Query string** (`isDirectory = false`):
```
https://example.b-cdn.net/video.mp4?token=HS256-...&expires=1234567890
```

**Directory** (`isDirectory = true`):
```
https://example.b-cdn.net/bcdn_token=HS256-...&expires=1234567890/video.mp4
```

**With speed limit** (`speedLimit = 500`):
```
https://example.b-cdn.net/video.mp4?token=HS256-...&limit=500&expires=1234567890
```
