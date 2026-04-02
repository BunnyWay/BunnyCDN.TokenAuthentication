const crypto = require('crypto');

/**
 * Generate a signed BunnyCDN URL.
 *
 * @param {string} url               CDN URL (e.g. http://test.b-cdn.net/file.png)
 * @param {string} securityKey       Token Authentication Key from your PullZone settings
 * @param {number} expirationTime    Token validity in seconds (default 86400 / 24h)
 * @param {string} userIp            Optional - lock the token to this IP
 * @param {boolean} isDirectory      true -> token embedded in path (/bcdn_token=...)
 * @param {string} pathAllowed       Optional path override for the signature scope
 * @param {string} countriesAllowed  Comma-separated allow-list (e.g. "CA,US,TH")
 * @param {string} countriesBlocked  Comma-separated block-list
 * @param {boolean} ignoreParams     If true, query params are excluded from validation
 * @param {number|null} expiresAt    Optional fixed expiry timestamp (unix seconds)
 * @returns {string} The signed URL
 */
function signUrl(
    url,
    securityKey,
    expirationTime = 86400,
    userIp = '',
    isDirectory = false,
    pathAllowed = '',
    countriesAllowed = '',
    countriesBlocked = '',
    ignoreParams = false,
    expiresAt = null,
    speedLimit = 0,
) {
    if (!securityKey) {
        throw new Error('securityKey must not be empty');
    }
    if (expirationTime < 0) {
        throw new Error('expirationTime must be non-negative');
    }

    // 1. Parse URL
    const parsed = new URL(url);

    // 2. Collect query params, reject duplicates
    const queryParams = {};
    for (const [key, value] of parsed.searchParams) {
        if (Object.prototype.hasOwnProperty.call(queryParams, key)) {
            throw new Error(`Duplicate query parameter "${key}" is not supported`);
        }
        queryParams[key] = value;
    }

    // 3. Add country restrictions to params
    if (countriesAllowed) {
        queryParams['token_countries'] = countriesAllowed;
    }
    if (countriesBlocked) {
        queryParams['token_countries_blocked'] = countriesBlocked;
    }
    if (speedLimit > 0) {
        queryParams['limit'] = String(speedLimit);
    }

    // 4. Compute expires
    const expires = expiresAt != null
        ? String(expiresAt)
        : String(Math.floor(Date.now() / 1000) + expirationTime);

    // 5. Build parameters object
    let parameters;
    if (ignoreParams) {
        parameters = { token_ignore_params: 'true' };
    } else {
        parameters = Object.assign({}, queryParams);
    }
    if (pathAllowed) {
        parameters['token_path'] = pathAllowed;
    }
    // Sort entries by key
    const sortedEntries = Object.entries(parameters).sort(([a], [b]) => a.localeCompare(b));

    // 6. signaturePath
    const signaturePath = pathAllowed || parsed.pathname;

    // 7. signingData (raw values)
    const signingData = sortedEntries.map(([k, v]) => `${k}=${v}`).join('&');

    // 8. urlData (encoded values)
    const urlData = sortedEntries.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');

    // 9. message
    const message = `${signaturePath}${expires}${signingData}${userIp}`;

    // 10. HMAC-SHA256
    const digest = crypto.createHmac('sha256', securityKey).update(message).digest();

    // 11. token
    const token = 'HS256-' + digest.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');

    // 12. Build final URL
    const base = `${parsed.protocol}//${parsed.host}`;
    const tail = urlData ? `&${urlData}` : '';

    if (isDirectory) {
        return `${base}/bcdn_token=${token}${tail}&expires=${expires}${parsed.pathname}`;
    } else {
        return `${base}${parsed.pathname}?token=${token}${tail}&expires=${expires}`;
    }
}

module.exports = { signUrl };
