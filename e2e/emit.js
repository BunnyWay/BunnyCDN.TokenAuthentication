const fs = require('fs');
const path = require('path');
const { signUrl } = require('../nodejs/token.js');

function extractToken(url) {
    const marker = url.includes('bcdn_token=') ? 'bcdn_token=' : 'token=';
    const start = url.indexOf(marker) + marker.length;
    let end = url.indexOf('&', start);
    if (end === -1) {
        end = url.length;
    }
    return url.slice(start, end);
}

const inputs = JSON.parse(fs.readFileSync(path.join(__dirname, 'inputs.json'), 'utf8'));
const { key, expires, host, cases } = inputs;

const result = {};
for (const c of cases) {
    const signedUrl = signUrl(
        host + c.path,
        key,
        86400,
        c.userIp,
        c.isDirectory,
        c.pathAllowed,
        c.countriesAllowed,
        c.countriesBlocked,
        c.ignoreParams,
        expires,
        c.speedLimit,
    );
    result[c.name] = extractToken(signedUrl);
}

process.stdout.write(JSON.stringify(result));
process.stdout.write('\n');
