<?php

declare(strict_types=1);

namespace App\Scan\Domain;

use Yiisoft\NetworkUtilities\IpHelper;

final class Cloudflare
{
    private const NETS = [
        '103.21.244.0/22',
        '103.22.200.0/22',
        '103.31.4.0/22',
        '104.16.0.0/13',
        '104.24.0.0/14',
        '108.162.192.0/18',
        '131.0.72.0/22',
        '141.101.64.0/18',
        '162.158.0.0/15',
        '172.64.0.0/13',
        '173.245.48.0/20',
        '188.114.96.0/20',
        '190.93.240.0/20',
        '197.234.240.0/22',
        '198.41.128.0/17',
        '2400:cb00::/32',
        '2606:4700::/32',
        '2803:f800::/32',
        '2405:b500::/32',
        '2405:8100::/32',
        '2a06:98c0::/29',
        '2c0f:f248::/32',
    ];

    public static function isCloudflareIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        foreach (self::NETS as $net) {
            try {
                if (IpHelper::inRange($ip, $net)) {
                    return true;
                }
            } catch (\Throwable) {
                continue;
            }
        }

        return false;
    }

    /**
     * @param list<string> $records
     */
    public static function isCloudflareNs(array $records): bool
    {
        foreach ($records as $item) {
            if (str_contains(strtolower($item), 'cloudflare.com')) {
                return true;
            }
        }

        return false;
    }
}
