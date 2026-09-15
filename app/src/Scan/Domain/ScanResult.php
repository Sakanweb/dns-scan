<?php

declare(strict_types=1);

namespace App\Scan\Domain;

final class ScanResult
{
    /**
     * @param list<string> $ips
     * @param list<string> $names
     * @param list<DnsRecord> $records
     * @param list<string> $notes
     * @param list<HostHit> $hosts
     * @param list<string> $wildcardIps
     */
    public function __construct(
        public readonly Target $target,
        public array $ips = [],
        public array $names = [],
        public array $records = [],
        public array $notes = [],
        public array $hosts = [],
        public array $wildcardIps = [],
    ) {
    }
}
