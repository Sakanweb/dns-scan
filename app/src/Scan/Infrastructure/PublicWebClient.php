<?php

declare(strict_types=1);

namespace App\Scan\Infrastructure;

use App\Scan\Domain\Parsers;
use App\Scan\Domain\WebClientInterface;

final class PublicWebClient implements WebClientInterface
{
    private const USER_AGENT = 'dns-scan/1.0 (local inventory)';

    public function certificateNames(string $domain): array
    {
        $names = [];
        foreach (['%25.' . $domain, $domain] as $query) {
            $payload = $this->json("https://crt.sh/?q={$query}&output=json", 25);
            if (is_array($payload)) {
                $names = array_merge($names, Parsers::extractCrtshNames($payload, $domain));
            }
        }

        return Parsers::uniqueSorted($names);
    }

    public function certspotterNames(string $domain): array
    {
        $url = 'https://api.certspotter.com/v1/issuances'
            . '?domain=' . rawurlencode($domain)
            . '&include_subdomains=true&expand=dns_names';
        $payload = $this->json($url, 25);
        if (is_array($payload)) {
            return Parsers::extractCertspotterNames($payload, $domain);
        }

        return [];
    }

    public function waybackNames(string $domain): array
    {
        $url = 'http://web.archive.org/cdx/search/cdx'
            . '?url=*.' . rawurlencode($domain)
            . '&output=json&fl=original&collapse=urlkey&limit=400';
        $payload = $this->json($url, 25);

        return Parsers::extractWaybackHosts($payload, $domain);
    }

    public function hostsearchNames(string $domain): array
    {
        $url = 'https://api.hackertarget.com/hostsearch/?q=' . rawurlencode($domain);
        $body = $this->httpGet($url, 15);

        return Parsers::parseHostsearchBody($body, $domain);
    }

    public function reverseIpNames(string $ip): array
    {
        $url = 'https://api.hackertarget.com/reverseiplookup/?q=' . rawurlencode($ip);
        $body = $this->httpGet($url, 12);

        return Parsers::parseReverseIpBody($body);
    }

    private function json(string $url, int $timeout): mixed
    {
        $body = $this->httpGet($url, $timeout);
        if ($body === '') {
            return null;
        }
        try {
            return json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
    }

    private function httpGet(string $url, int $timeout): string
    {
        $lastError = '';
        for ($attempt = 0; $attempt < 3; $attempt++) {
            try {
                $context = stream_context_create([
                    'http' => [
                        'method' => 'GET',
                        'header' => "User-Agent: " . self::USER_AGENT . "\r\n",
                        'timeout' => $timeout,
                        'ignore_errors' => true,
                    ],
                    'ssl' => [
                        'verify_peer' => true,
                        'verify_peer_name' => true,
                    ],
                ]);
                $body = @file_get_contents($url, false, $context);
                if ($body === false) {
                    $lastError = 'request failed';
                    usleep((int) (0.4 * ($attempt + 1) * 1_000_000));
                    continue;
                }

                return $body;
            } catch (\Throwable $e) {
                $lastError = $e->getMessage();
                usleep((int) (0.4 * ($attempt + 1) * 1_000_000));
            }
        }

        return $lastError === '' ? '' : '';
    }
}
