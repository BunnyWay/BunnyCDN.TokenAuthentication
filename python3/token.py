"""BunnyCDN URL token authentication."""

import urllib.parse
import time
import hmac
import hashlib
import base64


def _b64url_no_pad(raw: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _build_parameters(
    parsed_query: str,
    *,
    ignore_params: bool,
    path_allowed: str,
) -> dict[str, str]:
    if ignore_params:
        params: dict[str, str] = {"token_ignore_params": "true"}
    else:
        raw = urllib.parse.parse_qs(parsed_query, keep_blank_values=True)
        params = {}
        for key, values in raw.items():
            if len(values) > 1:
                raise ValueError(
                    f"Multi-valued query parameter {key!r} is not supported"
                )
            params[key] = values[0]

    if path_allowed:
        params["token_path"] = path_allowed

    return dict(sorted(params.items()))


def sign_url(
    url: str,
    security_key: str,
    expiration_time: int = 86400,
    user_ip: str = "",
    is_directory: bool = True,
    path_allowed: str = "",
    countries_allowed: str = "",
    countries_blocked: str = "",
    ignore_params: bool = False,
) -> str:
    """
    Generate a signed BunnyCDN URL.

    Args:
        url:               CDN URL without trailing '/'.
                           e.g. http://test.b-cdn.net/file.png
        security_key:      Token Authentication Key from your PullZone settings.
        expiration_time:   Token validity in seconds (default 86400 / 24 h).
        user_ip:           Optional - lock the token to this IP.
        is_directory:      True  → token embedded in path  (/bcdn_token=...)
                           False → token in query string   (?token=...)
        path_allowed:      Optional path override for the signature scope.
        countries_allowed: Comma-separated allow-list (e.g. "CA,US,TH").
        countries_blocked: Comma-separated block-list.
        ignore_params:     If True, query params are excluded from validation.

    Raises:
        ValueError: On empty/missing security_key, negative expiration, or
                    multi-valued query parameters.
    """

    if not security_key:
        raise ValueError("security_key must not be empty")
    if expiration_time < 0:
        raise ValueError("expiration_time must be non-negative")

    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if countries_allowed:
        query_params["token_countries"] = [countries_allowed]
    if countries_blocked:
        query_params["token_countries_blocked"] = [countries_blocked]

    new_query = urllib.parse.urlencode(query_params, doseq=True)
    parsed = parsed._replace(query=new_query)

    expires = str(int(time.time()) + expiration_time)

    params = _build_parameters(
        parsed.query,
        ignore_params=ignore_params,
        path_allowed=path_allowed,
    )

    signature_path = path_allowed if path_allowed else parsed.path

    signing_data = "&".join(f"{k}={v}" for k, v in params.items())
    url_data = "&".join(
        f"{k}={urllib.parse.quote(v, safe='')}" for k, v in params.items()
    )

    message = f"{signature_path}{expires}{signing_data}{user_ip}"
    digest = hmac.new(
        security_key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    token = "HS256-" + _b64url_no_pad(digest)

    base = f"{parsed.scheme}://{parsed.netloc}"
    tail = f"&{url_data}" if url_data else ""

    if is_directory:
        return f"{base}/bcdn_token={token}{tail}&expires={expires}{parsed.path}"
    else:
        return f"{base}{parsed.path}?token={token}{tail}&expires={expires}"