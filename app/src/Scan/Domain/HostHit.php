<?php

declare(strict_types=1);

namespace App\Scan\Domain;

final class HostHit
{
    /**
     * @param list<string> $ips
     * @param list<string> $cname
     * @param list<string> $sources
     */
    public function __construct(
        public readonly string $name,
        public readonly array $ips,
        public readonly array $cname,
        public readonly array $sources,
        public readonly string $kind,
        public ?HttpCheck $http = null,
    ) {
    }
}
