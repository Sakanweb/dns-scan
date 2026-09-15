<?php

declare(strict_types=1);

namespace App\Scan\Infrastructure;

use App\Scan\Domain\WebClientInterface;

final class DisabledWebClient implements WebClientInterface
{
    public function certificateNames(string $domain): array
    {
        return [];
    }

    public function certspotterNames(string $domain): array
    {
        return [];
    }

    public function waybackNames(string $domain): array
    {
        return [];
    }

    public function hostsearchNames(string $domain): array
    {
        return [];
    }

    public function reverseIpNames(string $ip): array
    {
        return [];
    }
}
