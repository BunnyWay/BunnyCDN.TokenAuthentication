package BunnyCDN;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

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
     * Convenience overload without speedLimit.
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
            Long expiresAt
    ) {
        return signUrl(url, securityKey, expirationTime, userIp,
                isDirectory, pathAllowed, countriesAllowed, countriesBlocked,
                ignoreParams, expiresAt, 0);
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
            URI uri = new URI(url);

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

            if (countriesAllowed != null && !countriesAllowed.isEmpty()) {
                queryParams.put("token_countries", countriesAllowed);
            }
            if (countriesBlocked != null && !countriesBlocked.isEmpty()) {
                queryParams.put("token_countries_blocked", countriesBlocked);
            }
            if (speedLimit > 0) {
                queryParams.put("limit", String.valueOf(speedLimit));
            }

            String expires;
            if (expiresAt != null) {
                expires = String.valueOf(expiresAt);
            } else {
                expires = String.valueOf(System.currentTimeMillis() / 1000L + expirationTime);
            }

            // Signed parameters are folded in sorted (lexicographic) key order; TreeMap enforces this.
            TreeMap<String, String> parameters = new TreeMap<>();
            if (ignoreParams) {
                parameters.put("token_ignore_params", "true");
            } else {
                parameters.putAll(queryParams);
            }
            if (pathAllowed != null && !pathAllowed.isEmpty()) {
                parameters.put("token_path", pathAllowed);
            }

            String signaturePath;
            if (pathAllowed != null && !pathAllowed.isEmpty()) {
                signaturePath = pathAllowed;
            } else {
                signaturePath = uri.getPath();
            }

            // signingData folds parameters as key=value (raw, undecoded values) joined by '&'.
            StringBuilder signingData = new StringBuilder();
            for (Map.Entry<String, String> entry : parameters.entrySet()) {
                if (signingData.length() > 0) {
                    signingData.append('&');
                }
                signingData.append(entry.getKey()).append('=').append(entry.getValue());
            }

            // urlData mirrors signingData but URL-encodes values (space as %20) for the output URL.
            StringBuilder urlData = new StringBuilder();
            for (Map.Entry<String, String> entry : parameters.entrySet()) {
                if (urlData.length() > 0) {
                    urlData.append('&');
                }
                String encodedValue = URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8.name())
                        .replace("+", "%20");
                urlData.append(entry.getKey()).append('=').append(encodedValue);
            }

            // When an IP restriction is present, the token carries a "1-" flag prefix and the
            // IP bytes are folded into the HMAC; otherwise the prefix is empty and no IP bytes.
            boolean hasIp = userIp != null && !userIp.isEmpty();
            byte[] ipBytes = hasIp ? userIpToBytes(userIp) : new byte[0];
            String flagsPrefix = hasIp ? "1-" : "";

            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(
                    securityKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(keySpec);
            // HMAC payload fold order: signaturePath, expires, ipBytes, signingData.
            mac.update(signaturePath.getBytes(StandardCharsets.UTF_8));
            mac.update(expires.getBytes(StandardCharsets.UTF_8));
            mac.update(ipBytes);
            mac.update(signingData.toString().getBytes(StandardCharsets.UTF_8));
            byte[] digest = mac.doFinal();

            // Token format: "HS256-" + flag prefix ("1-" when IP-restricted) + base64url(digest), unpadded.
            String token = "HS256-" + flagsPrefix
                    + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);

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

    private static final Pattern IPV4_LITERAL = Pattern.compile("^[0-9.]+$");
    private static final Pattern IPV6_LITERAL = Pattern.compile("^[0-9A-Fa-f:.]+$");

    private static byte[] userIpToBytes(String userIp) {
        if (userIp == null || userIp.isEmpty()) {
            throw new IllegalArgumentException("userIp must not be empty");
        }
        boolean looksLikeIp = IPV4_LITERAL.matcher(userIp).matches()
                || (userIp.indexOf(':') >= 0 && IPV6_LITERAL.matcher(userIp).matches());
        if (!looksLikeIp) {
            throw new IllegalArgumentException("userIp '" + userIp + "' is not a valid IP address");
        }
        try {
            byte[] bytes = InetAddress.getByName(userIp).getAddress();
            if (bytes.length == 16) {
                // Mask IPv6 to the /64 prefix: keep the first 8 bytes (network
                // portion), zero the last 8 (interface identifier). IPv4 is left unchanged.
                for (int i = 8; i < 16; i++) {
                    bytes[i] = 0;
                }
            }
            return bytes;
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("userIp '" + userIp + "' is not a valid IP address", e);
        }
    }
}
