# BunnyCDN.TokenAuthentication
## Rust Version
### Introduction

Requires Rust 2021 edition.

### Usage

```rust
use bunnycdn_token_authentication::sign_url;

let url = sign_url(
    "https://example.b-cdn.net/video.mp4",
    "your-security-key",
    3600,   // expiration_time
    "",     // user_ip
    false,  // is_directory
    "",     // path_allowed
    "GB",   // countries_allowed
    "",     // countries_blocked
    false,  // ignore_params
    None,   // expires_at
).unwrap();
```

### Testing

```
cargo test --verbose
```
