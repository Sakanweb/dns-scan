<?php

declare(strict_types=1);

namespace App\Scan\Domain;

final class Parsers
{
    /**
     * @return list<string>
     */
    public static function parseDigShort(string $raw): array
    {
        $values = [];
        foreach (preg_split("/\r\n|\n|\r/", $raw) ?: [] as $line) {
            $text = trim($line);
            if ($text === '' || str_starts_with($text, ';')) {
                continue;
            }
            $parts = [];
            foreach (preg_split('/\s+/', $text) ?: [] as $part) {
                if ($part !== '.' && str_ends_with($part, '.')) {
                    $part = substr($part, 0, -1);
                }
                $parts[] = $part;
            }
            $values[] = implode(' ', $parts);
        }

        return $values;
    }

    /**
     * @param iterable<array<string, mixed>> $payload
     * @return list<string>
     */
    public static function extractCrtshNames(iterable $payload, string $baseDomain): array
    {
        $base = strtolower(rtrim($baseDomain, '.'));
        $found = [];
        foreach ($payload as $row) {
            $raw = (string) ($row['name_value'] ?? '');
            foreach (preg_split("/\r\n|\n|\r/", $raw) ?: [] as $part) {
                $name = strtolower(rtrim(trim($part), '.'));
                if (str_starts_with($name, '*.')) {
                    $name = substr($name, 2);
                }
                if (self::belongsTo($name, $base)) {
                    $found[$name] = true;
                }
            }
        }

        $names = array_keys($found);
        sort($names);

        return $names;
    }

    /**
     * @return list<string>
     */
    public static function parseReverseIpBody(string $body): array
    {
        $text = trim($body);
        if ($text === '') {
            return [];
        }
        $lowered = strtolower($text);
        if (str_starts_with($lowered, 'error') || str_contains($lowered, 'api count exceeded')) {
            return [];
        }

        $names = [];
        foreach (preg_split("/\r\n|\n|\r/", $text) ?: [] as $line) {
            $item = strtolower(rtrim(trim($line), '.'));
            if ($item !== '' && !str_contains($item, ' ') && str_contains($item, '.')) {
                $names[] = $item;
            }
        }

        return self::uniqueSorted($names);
    }

    /**
     * @param iterable<string> $names
     * @return list<string>
     */
    public static function uniqueSorted(iterable $names): array
    {
        $cleaned = [];
        foreach ($names as $name) {
            if ($name === null || $name === '') {
                continue;
            }
            $item = strtolower(rtrim(trim((string) $name), '.'));
            if ($item !== '') {
                $cleaned[$item] = true;
            }
        }
        $result = array_keys($cleaned);
        sort($result);

        return $result;
    }

    public static function belongsTo(string $name, string $baseDomain): bool
    {
        return $name === $baseDomain || str_ends_with($name, '.' . $baseDomain);
    }

    public static function isIpAddress(string $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * dig +short for A/AAAA can include intermediate CNAME hosts. Keep addresses only.
     *
     * @param list<string> $values
     * @return list<string>
     */
    public static function onlyIpAddresses(array $values): array
    {
        $ips = [];
        foreach ($values as $value) {
            if (self::isIpAddress($value)) {
                $ips[] = $value;
            }
        }

        return $ips;
    }

    /**
     * @param list<string> $values
     * @return list<string>
     */
    public static function onlyHostnames(array $values): array
    {
        $names = [];
        foreach ($values as $value) {
            $item = strtolower(rtrim(trim($value), '.'));
            if ($item !== '' && !self::isIpAddress($item) && str_contains($item, '.')) {
                $names[] = $item;
            }
        }

        return $names;
    }

    /**
     * @param iterable<array<string, mixed>> $payload
     * @return list<string>
     */
    public static function extractCertspotterNames(iterable $payload, string $baseDomain): array
    {
        $found = [];
        foreach ($payload as $row) {
            $dnsNames = $row['dns_names'] ?? [];
            if (!is_iterable($dnsNames)) {
                continue;
            }
            foreach ($dnsNames as $raw) {
                $name = strtolower(rtrim(trim((string) $raw), '.'));
                if (str_starts_with($name, '*.')) {
                    $name = substr($name, 2);
                }
                if (self::belongsTo($name, $baseDomain)) {
                    $found[$name] = true;
                }
            }
        }
        $names = array_keys($found);
        sort($names);

        return $names;
    }

    /**
     * @return list<string>
     */
    public static function extractWaybackHosts(mixed $payload, string $baseDomain): array
    {
        if (!is_array($payload)) {
            return [];
        }

        $rows = $payload;
        if (
            $payload !== []
            && is_array($payload[0] ?? null)
            && ($payload[0][0] ?? null) === 'original'
        ) {
            $rows = array_slice($payload, 1);
        }

        $found = [];
        foreach ($rows as $row) {
            $url = (is_array($row) && $row !== []) ? (string) $row[0] : (string) $row;
            $host = strtolower(rtrim((string) (parse_url($url, PHP_URL_HOST) ?? ''), '.'));
            if (self::belongsTo($host, $baseDomain)) {
                $found[$host] = true;
            }
        }
        $names = array_keys($found);
        sort($names);

        return $names;
    }

    /**
     * @return list<string>
     */
    public static function parseHostsearchBody(string $body, string $baseDomain): array
    {
        $text = trim($body);
        if ($text === '') {
            return [];
        }
        $lowered = strtolower($text);
        if (str_starts_with($lowered, 'error') || str_contains($lowered, 'api count exceeded')) {
            return [];
        }

        $found = [];
        foreach (preg_split("/\r\n|\n|\r/", $text) ?: [] as $line) {
            $host = strtolower(rtrim(trim(explode(',', $line, 2)[0]), '.'));
            if (self::belongsTo($host, $baseDomain)) {
                $found[$host] = true;
            }
        }
        $names = array_keys($found);
        sort($names);

        return $names;
    }

    public static function htmlTitle(string $body): string
    {
        $lower = strtolower($body);
        $start = strpos($lower, '<title');
        if ($start === false) {
            return '';
        }
        $gt = strpos($lower, '>', $start);
        $end = $gt === false ? false : strpos($lower, '</title>', $gt);
        if ($gt === false || $end === false) {
            return '';
        }

        return preg_replace('/\s+/', ' ', trim(substr($body, $gt + 1, $end - $gt - 1))) ?? '';
    }

    public static function isDefaultPage(string $title, string $body): bool
    {
        $blob = strtolower($title . "\n" . $body);
        $markers = [
            "web server's default page",
            'plesk international',
            'welcome to nginx',
            'apache2 ubuntu default page',
            'iis windows server',
            'default website page',
            'this site is under construction',
        ];
        foreach ($markers as $marker) {
            if (str_contains($blob, $marker)) {
                return true;
            }
        }

        return false;
    }
}
