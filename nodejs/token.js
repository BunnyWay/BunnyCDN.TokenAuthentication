const crypto = require('crypto');
const net = require('net');

function userIpToBytes(userIp) {
    const family = net.isIP(userIp);
    if (family === 4) {
        const parts = userIp.split('.');
        if (parts.length !== 4) {
            throw new Error(`userIp '${userIp}' is not a valid IP address`);
        }
        const buf = Buffer.alloc(4);
        for (let i = 0; i < 4; i++) {
            const n = Number(parts[i]);
            if (!Number.isInteger(n) || n < 0 || n > 255) {
                throw new Error(`userIp '${userIp}' is not a valid IP address`);
            }
            buf[i] = n;
        }
        return buf;
    }
    if (family === 6) {
        const buf = parseIpv6(userIp);
        // Mask IPv6 to the /64 prefix: keep the first 8 bytes (network
        // portion), zero the last 8 (interface identifier). IPv4 is left unchanged.
        buf.fill(0, 8);
        return buf;
    }
    throw new Error(`userIp '${userIp}' is not a valid IP address`);
}

function parseIpv6(str) {
    let trailingV4 = null;
    const lastColon = str.lastIndexOf(':');
    if (lastColon !== -1 && str.indexOf('.') > lastColon) {
        const tail = str.slice(lastColon + 1);
        if (net.isIP(tail) !== 4) {
            throw new Error(`userIp '${str}' is not a valid IP address`);
        }
        trailingV4 = tail.split('.').map(Number);
        str = str.slice(0, lastColon) + ':0:0';
    }

    const halves = str.split('::');
    if (halves.length > 2) {
        throw new Error(`userIp '${str}' is not a valid IP address`);
    }

    const left = halves[0] === '' ? [] : halves[0].split(':');
    const right = halves.length === 2 && halves[1] !== '' ? halves[1].split(':') : [];
    const totalGiven = left.length + right.length;

    if (halves.length === 1 && totalGiven !== 8) {
        throw new Error(`userIp '${str}' is not a valid IP address`);
    }
    if (halves.length === 2 && totalGiven > 7) {
        throw new Error(`userIp '${str}' is not a valid IP address`);
    }

    const fillCount = halves.length === 2 ? 8 - totalGiven : 0;
    const hextets = [...left, ...Array(fillCount).fill('0'), ...right];
    if (hextets.length !== 8) {
        throw new Error(`userIp '${str}' is not a valid IP address`);
    }

    const buf = Buffer.alloc(16);
    for (let i = 0; i < 8; i++) {
        const h = hextets[i];
        if (!/^[0-9A-Fa-f]{1,4}$/.test(h)) {
            throw new Error(`userIp '${str}' is not a valid IP address`);
        }
        const n = parseInt(h, 16);
        buf[i * 2] = (n >>> 8) & 0xff;
        buf[i * 2 + 1] = n & 0xff;
    }

    if (trailingV4) {
        for (let i = 0; i < 4; i++) buf[12 + i] = trailingV4[i];
    }
    return buf;
}

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

    const parsed = new URL(url);

    const queryParams = {};
    for (const [key, value] of parsed.searchParams) {
        if (Object.prototype.hasOwnProperty.call(queryParams, key)) {
            throw new Error(`Duplicate query parameter "${key}" is not supported`);
        }
        queryParams[key] = value;
    }

    if (countriesAllowed) {
        queryParams['token_countries'] = countriesAllowed;
    }
    if (countriesBlocked) {
        queryParams['token_countries_blocked'] = countriesBlocked;
    }
    if (speedLimit > 0) {
        queryParams['limit'] = String(speedLimit);
    }

    const expires = expiresAt != null
        ? String(expiresAt)
        : String(Math.floor(Date.now() / 1000) + expirationTime);

    let parameters;
    if (ignoreParams) {
        parameters = { token_ignore_params: 'true' };
    } else {
        parameters = Object.assign({}, queryParams);
    }
    if (pathAllowed) {
        parameters['token_path'] = pathAllowed;
    }
    // Parameters are folded into the signature sorted by key; signingData uses raw
    // values, urlData uses URL-encoded values.
    const sortedEntries = Object.entries(parameters).sort(([a], [b]) => a.localeCompare(b));

    const signaturePath = pathAllowed || parsed.pathname;

    const signingData = sortedEntries.map(([k, v]) => `${k}=${v}`).join('&');

    const urlData = sortedEntries.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');

    const hasIp = !!userIp;
    const ipBytes = hasIp ? userIpToBytes(userIp) : Buffer.alloc(0);
    const flagsPrefix = hasIp ? '1-' : '';

    // HMAC payload is folded in this exact order: signaturePath, expires, ipBytes
    // (IPv6 masked to /64, empty when no IP), then signingData.
    const hmac = crypto.createHmac('sha256', securityKey);
    hmac.update(signaturePath);
    hmac.update(expires);
    hmac.update(ipBytes);
    hmac.update(signingData);
    const digest = hmac.digest();

    // Token is "HS256-" + flags prefix ("1-" when IP-locked, else empty) + base64url
    // digest (+/ -> -_, trailing '=' stripped).
    const token = 'HS256-' + flagsPrefix + digest.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');

    const base = `${parsed.protocol}//${parsed.host}`;
    const tail = urlData ? `&${urlData}` : '';

    if (isDirectory) {
        return `${base}/bcdn_token=${token}${tail}&expires=${expires}${parsed.pathname}`;
    } else {
        return `${base}${parsed.pathname}?token=${token}${tail}&expires=${expires}`;
    }
}

module.exports = { signUrl };
