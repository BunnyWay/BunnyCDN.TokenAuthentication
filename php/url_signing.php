<?php

/**
 * Generate a signed BunnyCDN URL using HMAC-SHA256.
 *
 * @throws InvalidArgumentException On empty security_key, negative expiration, or duplicate query keys.
 */
function sign_bcdn_url(
    string $url,
    string $security_key,
    int $expiration_time = 86400,
    string $user_ip = '',
    bool $is_directory = false,
    string $path_allowed = '',
    string $countries_allowed = '',
    string $countries_blocked = '',
    bool $ignore_params = false,
    ?int $expires_at = null,
    int $speed_limit = 0
): string {
    if ($security_key === '') {
        throw new InvalidArgumentException('security_key must not be empty');
    }
    if ($expiration_time < 0) {
        throw new InvalidArgumentException('expiration_time must be non-negative');
    }

    // Parse URL
    $parsed = parse_url($url);
    $url_scheme = $parsed['scheme'] ?? '';
    $url_host = $parsed['host'] ?? '';
    $url_path = $parsed['path'] ?? '/';
    $url_query = $parsed['query'] ?? '';

    // Parse existing query params manually (no parse_str)
    $query_params = [];
    if ($url_query !== '') {
        foreach (explode('&', $url_query) as $pair) {
            $parts = explode('=', $pair, 2);
            $key = rawurldecode($parts[0]);
            $value = isset($parts[1]) ? rawurldecode($parts[1]) : '';
            if (array_key_exists($key, $query_params)) {
                throw new InvalidArgumentException("Duplicate query parameter '{$key}' is not supported");
            }
            $query_params[$key] = $value;
        }
    }

    // Add countries params
    if ($countries_allowed !== '') {
        if (array_key_exists('token_countries', $query_params)) {
            throw new InvalidArgumentException("Duplicate query parameter 'token_countries' is not supported");
        }
        $query_params['token_countries'] = $countries_allowed;
    }
    if ($countries_blocked !== '') {
        if (array_key_exists('token_countries_blocked', $query_params)) {
            throw new InvalidArgumentException("Duplicate query parameter 'token_countries_blocked' is not supported");
        }
        $query_params['token_countries_blocked'] = $countries_blocked;
    }
    if ($speed_limit > 0) {
        $query_params['limit'] = (string) $speed_limit;
    }

    // Compute expires
    $expires = $expires_at !== null ? $expires_at : time() + $expiration_time;

    // Build parameters dict
    if ($ignore_params) {
        $parameters = ['token_ignore_params' => 'true'];
    } else {
        $parameters = $query_params;
    }

    if ($path_allowed !== '') {
        $parameters['token_path'] = $path_allowed;
    }

    ksort($parameters);

    // Signature path
    $signature_path = $path_allowed !== '' ? $path_allowed : $url_path;

    // Build signing data (raw values) and url data (rawurlencode values)
    $signing_parts = [];
    $url_parts = [];
    foreach ($parameters as $key => $value) {
        $signing_parts[] = "{$key}={$value}";
        $url_parts[] = "{$key}=" . rawurlencode($value);
    }
    $signing_data = implode('&', $signing_parts);
    $url_data = implode('&', $url_parts);

    // Build message and compute HMAC-SHA256
    $message = $signature_path . $expires . $signing_data . $user_ip;
    $digest = hash_hmac('sha256', $message, $security_key, true);

    // Build token
    $token = 'HS256-' . rtrim(strtr(base64_encode($digest), '+/', '-_'), '=');

    // Build final URL
    $base = "{$url_scheme}://{$url_host}";
    $tail = $url_data !== '' ? "&{$url_data}" : '';

    if ($is_directory) {
        return "{$base}/bcdn_token={$token}{$tail}&expires={$expires}{$url_path}";
    } else {
        return "{$base}{$url_path}?token={$token}{$tail}&expires={$expires}";
    }
}
