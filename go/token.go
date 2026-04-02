package bunnycdn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// SignUrl generates a signed BunnyCDN URL using HMAC-SHA256 token authentication.
//
// Parameters:
//   - rawUrl:            CDN URL (e.g. https://example.b-cdn.net/file.png)
//   - securityKey:       Token Authentication Key from your Pull Zone settings
//   - expirationTime:    Token validity in seconds (e.g. 86400 for 24h)
//   - userIp:            Lock the token to a specific IP address (empty string for none)
//   - isDirectory:       true: token in path (/bcdn_token=...), false: token in query string (?token=...)
//   - pathAllowed:       Restrict the token scope to a specific path (empty string for none)
//   - countriesAllowed:  Comma-separated allow-list of country codes (empty string for none)
//   - countriesBlocked:  Comma-separated block-list of country codes (empty string for none)
//   - ignoreParams:      Exclude query parameters from token validation
//   - expiresAt:         Absolute Unix timestamp for expiration (nil to use expirationTime)
func SignUrl(
	rawUrl string,
	securityKey string,
	expirationTime int64,
	userIp string,
	isDirectory bool,
	pathAllowed string,
	countriesAllowed string,
	countriesBlocked string,
	ignoreParams bool,
	expiresAt *int64,
	speedLimit int64,
) (string, error) {
	if securityKey == "" {
		return "", errors.New("securityKey must not be empty")
	}
	if expirationTime < 0 {
		return "", errors.New("expirationTime must be non-negative")
	}

	parsed, err := url.Parse(rawUrl)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Parse query params manually, rejecting duplicates.
	queryParams := make(map[string]string)
	if parsed.RawQuery != "" {
		for _, pair := range strings.Split(parsed.RawQuery, "&") {
			if pair == "" {
				continue
			}
			var key, value string
			if idx := strings.IndexByte(pair, '='); idx >= 0 {
				k, err := url.QueryUnescape(pair[:idx])
				if err != nil {
					return "", err
				}
				v, err := url.QueryUnescape(pair[idx+1:])
				if err != nil {
					return "", err
				}
				key, value = k, v
			} else {
				k, err := url.QueryUnescape(pair)
				if err != nil {
					return "", err
				}
				key, value = k, ""
			}
			if _, exists := queryParams[key]; exists {
				return "", fmt.Errorf("duplicate query parameter %q is not supported", key)
			}
			queryParams[key] = value
		}
	}

	if countriesAllowed != "" {
		queryParams["token_countries"] = countriesAllowed
	}
	if countriesBlocked != "" {
		queryParams["token_countries_blocked"] = countriesBlocked
	}
	if speedLimit > 0 {
		queryParams["limit"] = fmt.Sprintf("%d", speedLimit)
	}

	// Compute expires.
	var expires string
	if expiresAt != nil {
		expires = fmt.Sprintf("%d", *expiresAt)
	} else {
		expires = fmt.Sprintf("%d", time.Now().Unix()+expirationTime)
	}

	// Build parameters.
	parameters := make(map[string]string)
	if ignoreParams {
		parameters["token_ignore_params"] = "true"
	} else {
		for k, v := range queryParams {
			parameters[k] = v
		}
	}
	if pathAllowed != "" {
		parameters["token_path"] = pathAllowed
	}

	// Sort keys.
	keys := make([]string, 0, len(parameters))
	for k := range parameters {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	signaturePath := pathAllowed
	if signaturePath == "" {
		signaturePath = parsed.Path
	}

	// Build signingData (raw) and urlData (percent-encoded values).
	signingParts := make([]string, len(keys))
	urlParts := make([]string, len(keys))
	for i, k := range keys {
		v := parameters[k]
		signingParts[i] = k + "=" + v
		urlParts[i] = k + "=" + percentEncode(v)
	}
	signingData := strings.Join(signingParts, "&")
	urlData := strings.Join(urlParts, "&")

	// HMAC-SHA256.
	message := signaturePath + expires + signingData + userIp
	mac := hmac.New(sha256.New, []byte(securityKey))
	mac.Write([]byte(message))
	token := "HS256-" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Build final URL.
	base := parsed.Scheme + "://" + parsed.Host
	tail := ""
	if urlData != "" {
		tail = "&" + urlData
	}

	if isDirectory {
		return base + "/bcdn_token=" + token + tail + "&expires=" + expires + parsed.Path, nil
	}
	return base + parsed.Path + "?token=" + token + tail + "&expires=" + expires, nil
}

func percentEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
