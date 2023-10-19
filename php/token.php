<?php

/**
 * @return string
 */
function signURL(
    $url,
    $securityKey,
    $expirationTime = 3600,
    $userIp = null,
    $isDirectoryToken = false,
    $allowedPath = null,
    $allowedCountries = null,
    $blockedCountries = null,
    $allowedReferrers = null
) {
    $parsedUrl = parse_url($url);

    $parameters = [];
    $parametersForReturn = [];
    if (array_key_exists('query', $parsedUrl)) {
        parse_str($parsedUrl['query'], $parameters);
        $parametersForReturn = $parameters;
    }

    $possibleQueries = [
        'token_countries' => $allowedCountries,
        'token_countries_blocked' => $blockedCountries,
        'token_referer' => $allowedReferrers,
        'token_path' => ! is_null($allowedPath) ? $allowedPath : null,
    ];

    foreach ($possibleQueries as $key => $value) {
        if (! is_null($value)) {
            $parameters[$key] = $value;
        }
    }

    // Expiration time
    $expires = time() + $expirationTime;

    // Construct the parameter data
    ksort($parameters);

    $hashableBase = $securityKey.(array_key_exists(
        'token_path',
        $parameters
    ) ? $parameters['token_path'] : $parsedUrl['path']).
        $expires.
        $userIp.urldecode(http_build_query($parameters));

    // Generate the token
    $token = base64_encode(hash('sha256', $hashableBase, true));
    $token = str_replace(['+', '/', '='], ['-', '_', ''], $token);

    $baseUrl = sprintf(
        '%s://%s',
        $parsedUrl['scheme'],
        $parsedUrl['host']
    );

    if ($isDirectoryToken) {
        return $baseUrl.sprintf(
            '/%s%s',
            http_build_query(
                $parametersForReturn +
                [
                    'bcdn_token' => $token,
                    'expires' => $expires,
                ] +
                $parameters,
                '',
                '&'
            ),
            $parsedUrl['path']
        );
    }

    return $baseUrl.sprintf(
        '%s?%s',
        $parsedUrl['path'],
        http_build_query(
            $parametersForReturn +
            ['token' => $token] +
            $parameters +
            ['expires' => $expires],
            '',
            '&'
        )
    );
}
