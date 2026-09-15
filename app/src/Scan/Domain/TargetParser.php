<?php

declare(strict_types=1);

namespace App\Scan\Domain;

final class TargetParser
{
    private const CLOUD_PTR_MARKERS = [
        'amazonaws.com',
        'googleusercontent.com',
        'cloudapp.azure.com',
        'cloudapp.net',
        'linode.com',
        'digitaloceanspaces.com',
        'compute.internal',
        'in-addr.arpa',
        'ip6.arpa',
        'host.secureserver.net',
        'reverse.softlayer.com',
    ];

    public static function parse(string $raw): Target
    {
        $text = trim($raw);
        if ($text === '') {
            throw new \InvalidArgumentException('empty target');
        }

        $host = self::extractHost($text);
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return new Target($raw, 'ip', $host);
        }

        $domain = self::normalizeDomain($host);
        if (!str_contains($domain, '.') || str_contains($domain, ' ')) {
            throw new \InvalidArgumentException("not an IP or domain: {$raw}");
        }

        return new Target($raw, 'domain', $domain);
    }

    public static function isReverseDnsName(string $name): bool
    {
        $lowered = strtolower(rtrim(trim($name), '.'));
        $firstLabel = explode('.', $lowered, 2)[0] ?? '';
        if (preg_match('/^ip-\d+-\d+-\d+-\d+/', $firstLabel) === 1) {
            return true;
        }

        foreach (self::CLOUD_PTR_MARKERS as $marker) {
            if (str_ends_with($lowered, $marker)) {
                return true;
            }
        }

        return false;
    }

    private static function extractHost(string $text): string
    {
        if (str_contains($text, '://')) {
            $host = parse_url($text, PHP_URL_HOST);
            if (is_string($host) && $host !== '') {
                return $host;
            }
        }

        $withoutPath = explode('/', $text, 2)[0];
        $withoutQuery = explode('?', $withoutPath, 2)[0];

        return explode('#', $withoutQuery, 2)[0];
    }

    private static function normalizeDomain(string $host): string
    {
        return strtolower(rtrim(trim($host), '.'));
    }
}
