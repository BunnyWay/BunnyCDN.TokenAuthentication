use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use sha2::Sha256;
use url::Url;

type HmacSha256 = Hmac<Sha256>;

/// Percent-encode everything except unreserved characters (RFC 3986).
const ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Generate a signed BunnyCDN URL using HMAC-SHA256 token authentication.
///
/// # Arguments
///
/// * `url` - CDN URL (e.g. `https://example.b-cdn.net/file.png`)
/// * `security_key` - Token Authentication Key from your Pull Zone settings
/// * `expiration_time` - Token validity in seconds (e.g. 86400 for 24h)
/// * `user_ip` - Lock the token to a specific IP address (empty string for none)
/// * `is_directory` - `true`: token in path (`/bcdn_token=...`), `false`: in query string
/// * `path_allowed` - Restrict the token scope to a specific path (empty string for none)
/// * `countries_allowed` - Comma-separated allow-list of country codes (empty string for none)
/// * `countries_blocked` - Comma-separated block-list of country codes (empty string for none)
/// * `ignore_params` - Exclude query parameters from token validation
/// * `expires_at` - Absolute Unix timestamp for expiration (`None` to use `expiration_time`)
pub fn sign_url(
    raw_url: &str,
    security_key: &str,
    expiration_time: i64,
    user_ip: &str,
    is_directory: bool,
    path_allowed: &str,
    countries_allowed: &str,
    countries_blocked: &str,
    ignore_params: bool,
    expires_at: Option<i64>,
    speed_limit: i64,
) -> Result<String, String> {
    if security_key.is_empty() {
        return Err("security_key must not be empty".into());
    }
    if expiration_time < 0 {
        return Err("expiration_time must be non-negative".into());
    }

    let parsed = Url::parse(raw_url).map_err(|e| format!("invalid URL: {e}"))?;

    // Parse query params, rejecting duplicates.
    let mut query_params = BTreeMap::new();
    if let Some(query) = parsed.query() {
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = if let Some(idx) = pair.find('=') {
                let k = percent_decode(&pair[..idx])?;
                let v = percent_decode(&pair[idx + 1..])?;
                (k, v)
            } else {
                (percent_decode(pair)?, String::new())
            };
            if query_params.contains_key(&key) {
                return Err(format!("duplicate query parameter \"{key}\" is not supported"));
            }
            query_params.insert(key, value);
        }
    }

    if !countries_allowed.is_empty() {
        query_params.insert("token_countries".into(), countries_allowed.into());
    }
    if !countries_blocked.is_empty() {
        query_params.insert("token_countries_blocked".into(), countries_blocked.into());
    }
    if speed_limit > 0 {
        query_params.insert("limit".into(), speed_limit.to_string());
    }

    // Compute expires.
    let expires = match expires_at {
        Some(ts) => ts.to_string(),
        None => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| format!("system time error: {e}"))?
                .as_secs() as i64;
            (now + expiration_time).to_string()
        }
    };

    // Build parameters.
    let mut parameters = BTreeMap::new();
    if ignore_params {
        parameters.insert("token_ignore_params".into(), "true".into());
    } else {
        for (k, v) in &query_params {
            parameters.insert(k.clone(), v.clone());
        }
    }
    if !path_allowed.is_empty() {
        parameters.insert("token_path".into(), path_allowed.into());
    }

    let signature_path = if path_allowed.is_empty() {
        parsed.path().to_string()
    } else {
        path_allowed.to_string()
    };

    // Build signingData (raw) and urlData (percent-encoded values).
    let signing_data = parameters
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let url_data = parameters
        .iter()
        .map(|(k, v)| {
            let encoded = utf8_percent_encode(v, ENCODE_SET).to_string();
            format!("{k}={encoded}")
        })
        .collect::<Vec<_>>()
        .join("&");

    // HMAC-SHA256.
    let message = format!("{signature_path}{expires}{signing_data}{user_ip}");
    let mut mac =
        HmacSha256::new_from_slice(security_key.as_bytes()).map_err(|e| e.to_string())?;
    mac.update(message.as_bytes());
    let digest = mac.finalize().into_bytes();
    let token = format!("HS256-{}", URL_SAFE_NO_PAD.encode(digest));

    // Build final URL.
    let base = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
    let tail = if url_data.is_empty() {
        String::new()
    } else {
        format!("&{url_data}")
    };

    if is_directory {
        Ok(format!(
            "{base}/bcdn_token={token}{tail}&expires={expires}{}",
            parsed.path()
        ))
    } else {
        Ok(format!(
            "{base}{}?token={token}{tail}&expires={expires}",
            parsed.path()
        ))
    }
}

fn percent_decode(input: &str) -> Result<String, String> {
    percent_encoding::percent_decode_str(input)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|e| format!("invalid UTF-8 in query parameter: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECURITY_KEY: &str = "SecurityKey";
    const EXPIRES_AT: i64 = 1598024587;

    #[test]
    fn with_countries_allowed() {
        let result = sign_url(
            "https://token-tester.b-cdn.net/300kb.jpg",
            SECURITY_KEY, 86400, "", false, "/", "CA", "", false, Some(EXPIRES_AT), 0,
        ).unwrap();
        assert_eq!(result,
            "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-JWU7jhpnBGI-O54AYDAtrlZT86Ied4RTO2-Y8mUj60A&token_countries=CA&token_path=%2F&expires=1598024587");
    }

    #[test]
    fn with_countries_blocked() {
        let result = sign_url(
            "https://token-tester.b-cdn.net/300kb.jpg",
            SECURITY_KEY, 86400, "", false, "", "", "CA", false, Some(EXPIRES_AT), 0,
        ).unwrap();
        assert_eq!(result,
            "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-zKGmNRBaHRmB4THCwmIQK5U21wH-S9KaJ6Ht7Kq9Zlw&token_countries_blocked=CA&expires=1598024587");
    }

    #[test]
    fn with_ip_address() {
        let result = sign_url(
            "https://token-tester.b-cdn.net/300kb.jpg",
            SECURITY_KEY, 86400, "1.2.3.4", false, "", "", "", false, Some(EXPIRES_AT), 0,
        ).unwrap();
        assert_eq!(result,
            "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-0A9FRzMI9ACT-5VKMPbJf7g8f7UHavqjBH1Z8HljoEk&expires=1598024587");
    }

    #[test]
    fn with_ipv6_address() {
        let result = sign_url(
            "https://token-tester.b-cdn.net/300kb.jpg",
            SECURITY_KEY, 86400, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false, "", "", "", false, Some(EXPIRES_AT), 0,
        ).unwrap();
        assert_eq!(result,
            "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-7CEOZ-eY9DjC36ZnazCM3Ykj3-bR6h9V_IncIVT2s2U&expires=1598024587");
    }

    #[test]
    fn combined_ipv6_country_directory() {
        let result = sign_url(
            "https://token-tester.b-cdn.net/abc/",
            SECURITY_KEY, 86400, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", true, "", "CA,US", "", false, Some(EXPIRES_AT), 0,
        ).unwrap();
        assert_eq!(result,
            "https://token-tester.b-cdn.net/bcdn_token=HS256-om4aK_1Gnb3m2_5WVMtLzD-vlubUyDo1mJ0FFrKU1Kk&token_countries=CA%2CUS&expires=1598024587/abc/");
    }

    #[test]
    fn with_path_allowed() {
        let result = sign_url(
            "https://token-tester.b-cdn.net/abc/300kb.jpg",
            SECURITY_KEY, 86400, "", false, "/abc", "", "", false, Some(EXPIRES_AT), 0,
        ).unwrap();
        assert_eq!(result,
            "https://token-tester.b-cdn.net/abc/300kb.jpg?token=HS256-uVZvT3SbEoVKYJyDJgbcsDmSFf73cv-uNUVaJiKWpbQ&token_path=%2Fabc&expires=1598024587");
    }

    #[test]
    fn directory_allowed() {
        let result = sign_url(
            "https://token-tester.b-cdn.net/abc/",
            SECURITY_KEY, 86400, "", true, "", "", "", false, Some(EXPIRES_AT), 0,
        ).unwrap();
        assert_eq!(result,
            "https://token-tester.b-cdn.net/bcdn_token=HS256-bTMv4RVOkjx2UXLfVDl-JIygaxfSIQP8UCnCy7CILuY&expires=1598024587/abc/");
    }

    #[test]
    fn directory_and_path_allowed() {
        let result = sign_url(
            "https://token-tester.b-cdn.net/abc/",
            SECURITY_KEY, 86400, "", true, "/abc", "", "", false, Some(EXPIRES_AT), 0,
        ).unwrap();
        assert_eq!(result,
            "https://token-tester.b-cdn.net/bcdn_token=HS256-uVZvT3SbEoVKYJyDJgbcsDmSFf73cv-uNUVaJiKWpbQ&token_path=%2Fabc&expires=1598024587/abc/");
    }

    #[test]
    fn with_ignore_params() {
        let result = sign_url(
            "https://token-tester.b-cdn.net/300kb.jpg?v=123",
            SECURITY_KEY, 86400, "", false, "", "", "", true, Some(EXPIRES_AT), 0,
        ).unwrap();
        assert_eq!(result,
            "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-1lwWBD_c1IAGSj1UKPoxreu8ePDQ-Z9FoWLcRn_RRH0&token_ignore_params=true&expires=1598024587");
    }

    #[test]
    fn with_existing_query_params() {
        let result = sign_url(
            "https://token-tester.b-cdn.net/300kb.jpg?v=123",
            SECURITY_KEY, 86400, "", false, "", "", "", false, Some(EXPIRES_AT), 0,
        ).unwrap();
        assert_eq!(result,
            "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-q6oRQr-5ccQ-piO1HSEQu1DVMy9UMppRxGlIQwoeM5Y&v=123&expires=1598024587");
    }

    #[test]
    fn combined_ip_country_directory() {
        let result = sign_url(
            "https://token-tester.b-cdn.net/abc/",
            SECURITY_KEY, 86400, "1.2.3.4", true, "", "CA,US", "", false, Some(EXPIRES_AT), 0,
        ).unwrap();
        assert_eq!(result,
            "https://token-tester.b-cdn.net/bcdn_token=HS256-pj8ytucbBWXT_M5cAqKGu4pshB2Q_s28G2uMfjhc3lA&token_countries=CA%2CUS&expires=1598024587/abc/");
    }

    #[test]
    fn with_speed_limit() {
        let result = sign_url(
            "https://token-tester.b-cdn.net/300kb.jpg",
            SECURITY_KEY, 86400, "", false, "", "", "", false, Some(EXPIRES_AT), 1000,
        ).unwrap();
        assert_eq!(result,
            "https://token-tester.b-cdn.net/300kb.jpg?token=HS256-DAVapqNNED3Z7JkjRTYX0UOIHNtbHEuuhRNEc4A7mMQ&limit=1000&expires=1598024587");
    }

    #[test]
    fn combined_speed_limit_ip_directory() {
        let result = sign_url(
            "https://token-tester.b-cdn.net/abc/",
            SECURITY_KEY, 86400, "1.2.3.4", true, "", "", "", false, Some(EXPIRES_AT), 5000,
        ).unwrap();
        assert_eq!(result,
            "https://token-tester.b-cdn.net/bcdn_token=HS256-9M87MQhNKZqVdjqgHo1IMFVNa01tL2DwlmjBCtou08I&limit=5000&expires=1598024587/abc/");
    }

    #[test]
    fn validation_empty_key() {
        let result = sign_url("https://example.com/f.jpg", "", 86400, "", false, "", "", "", false, None, 0);
        assert!(result.is_err());
    }

    #[test]
    fn validation_negative_expiry() {
        let result = sign_url("https://example.com/f.jpg", "key", -1, "", false, "", "", "", false, None, 0);
        assert!(result.is_err());
    }
}
