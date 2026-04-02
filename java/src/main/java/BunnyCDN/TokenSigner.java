package BunnyCDN;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;

public class TokenSigner {

    /**
     * Convenience overload without ignoreParams and expiresAt.
     */
    public static String signUrl(
            String url,
            String securityKey,
            long expirationTime,
            String userIp,
            boolean isDirectory,
            String pathAllowed,
            String countriesAllowed,
            String countriesBlocked
    ) {
        return signUrl(url, securityKey, expirationTime, userIp,
                isDirectory, pathAllowed, countriesAllowed, countriesBlocked,
                false, null, 0);
    }

    /**
     * Signs a BunnyCDN URL with HMAC-SHA256 token authentication.
     *
     * @param url               The URL to sign
     * @param securityKey       The security key for HMAC signing
     * @param expirationTime    Seconds from now until expiration (ignored if expiresAt is non-null)
     * @param userIp            IP address to restrict access to (empty string for no restriction)
     * @param isDirectory       Whether this is a directory token
     * @param pathAllowed       Path restriction (null for none)
     * @param countriesAllowed  Comma-separated allowed country codes (null for none)
     * @param countriesBlocked  Comma-separated blocked country codes (null for none)
     * @param ignoreParams      If true, ignore query parameters and set token_ignore_params=true
     * @param expiresAt         Absolute Unix timestamp for expiration (null to use expirationTime)
     * @return The signed URL
     */
    public static String signUrl(
            String url,
            String securityKey,
            long expirationTime,
            String userIp,
            boolean isDirectory,
            String pathAllowed,
            String countriesAllowed,
            String countriesBlocked,
            boolean ignoreParams,
            Long expiresAt,
            int speedLimit
    ) {
        if (securityKey == null || securityKey.isEmpty()) {
            throw new IllegalArgumentException("securityKey must not be null or empty");
        }
        if (expirationTime < 0) {
            throw new IllegalArgumentException("expirationTime must not be negative");
        }

        try {
            // Step 1: Parse URL
            URI uri = new URI(url);

            // Step 2: Parse query string manually
            TreeMap<String, String> queryParams = new TreeMap<>();
            String query = uri.getRawQuery();
            if (query != null && !query.isEmpty()) {
                String[] pairs = query.split("&");
                for (String pair : pairs) {
                    int idx = pair.indexOf('=');
                    String key;
                    String value;
                    if (idx >= 0) {
                        key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.name());
                        value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.name());
                    } else {
                        key = URLDecoder.decode(pair, StandardCharsets.UTF_8.name());
                        value = "";
                    }
                    if (queryParams.containsKey(key)) {
                        throw new IllegalArgumentException("Duplicate query parameter: " + key);
                    }
                    queryParams.put(key, value);
                }
            }

            // Step 3: Add countries to query params
            if (countriesAllowed != null && !countriesAllowed.isEmpty()) {
                queryParams.put("token_countries", countriesAllowed);
            }
            if (countriesBlocked != null && !countriesBlocked.isEmpty()) {
                queryParams.put("token_countries_blocked", countriesBlocked);
            }
            if (speedLimit > 0) {
                queryParams.put("limit", String.valueOf(speedLimit));
            }

            // Step 4: Compute expires
            String expires;
            if (expiresAt != null) {
                expires = String.valueOf(expiresAt);
            } else {
                expires = String.valueOf(System.currentTimeMillis() / 1000L + expirationTime);
            }

            // Step 5: Build parameters
            TreeMap<String, String> parameters = new TreeMap<>();
            if (ignoreParams) {
                parameters.put("token_ignore_params", "true");
            } else {
                parameters.putAll(queryParams);
            }
            if (pathAllowed != null && !pathAllowed.isEmpty()) {
                parameters.put("token_path", pathAllowed);
            }

            // Step 6: signaturePath
            String signaturePath;
            if (pathAllowed != null && !pathAllowed.isEmpty()) {
                signaturePath = pathAllowed;
            } else {
                signaturePath = uri.getPath();
            }

            // Step 7: signingData (raw values)
            StringBuilder signingData = new StringBuilder();
            for (Map.Entry<String, String> entry : parameters.entrySet()) {
                if (signingData.length() > 0) {
                    signingData.append('&');
                }
                signingData.append(entry.getKey()).append('=').append(entry.getValue());
            }

            // Step 8: urlData (URL-encoded values, space as %20)
            StringBuilder urlData = new StringBuilder();
            for (Map.Entry<String, String> entry : parameters.entrySet()) {
                if (urlData.length() > 0) {
                    urlData.append('&');
                }
                String encodedValue = URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8.name())
                        .replace("+", "%20");
                urlData.append(entry.getKey()).append('=').append(encodedValue);
            }

            // Step 9: message
            String message = signaturePath + expires + signingData + userIp;

            // Step 10: HMAC-SHA256
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(
                    securityKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(keySpec);
            byte[] digest = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));

            // Step 11: token
            String token = "HS256-" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);

            // Step 12: Build final URL
            String base = uri.getScheme() + "://" + uri.getHost();
            String path = uri.getRawPath();
            String tail = urlData.length() == 0 ? "" : "&" + urlData;

            if (isDirectory) {
                return base + "/bcdn_token=" + token + tail + "&expires=" + expires + path;
            } else {
                return base + path + "?token=" + token + tail + "&expires=" + expires;
            }

        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign URL", e);
        }
    }
}
