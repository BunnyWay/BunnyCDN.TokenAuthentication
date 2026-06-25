<?php

require_once __DIR__ . '/../php/url_signing.php';

function extract_token(string $url): string
{
    $marker = strpos($url, 'bcdn_token=') !== false ? 'bcdn_token=' : 'token=';
    $start = strpos($url, $marker) + strlen($marker);
    $end = strpos($url, '&', $start);
    if ($end === false) {
        $end = strlen($url);
    }
    return substr($url, $start, $end - $start);
}

$inputs = json_decode(file_get_contents(__DIR__ . '/inputs.json'), true);
$key = $inputs['key'];
$expires = $inputs['expires'];
$host = $inputs['host'];
$cases = $inputs['cases'];

$result = [];
foreach ($cases as $c) {
    $signedUrl = sign_bcdn_url(
        $host . $c['path'],
        $key,
        86400,
        $c['userIp'],
        $c['isDirectory'],
        $c['pathAllowed'],
        $c['countriesAllowed'],
        $c['countriesBlocked'],
        $c['ignoreParams'],
        $expires,
        $c['speedLimit']
    );
    $result[$c['name']] = extract_token($signedUrl);
}

echo json_encode($result) . "\n";
