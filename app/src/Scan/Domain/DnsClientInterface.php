<?php

declare(strict_types=1);

namespace App\Scan\Domain;

interface DnsClientInterface
{
    /**
     * @return list<string>
     */
    public function query(string $name, string $rtype): array;

    /**
     * @return list<string>
     */
    public function reverse(string $ip): array;

    /**
     * @return list<string>
     */
    public function zoneTransfer(string $nameserver, string $zone): array;
}
