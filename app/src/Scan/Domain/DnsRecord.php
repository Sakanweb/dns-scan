<?php

declare(strict_types=1);

namespace App\Scan\Domain;

final readonly class DnsRecord
{
    public function __construct(
        public string $name,
        public string $rtype,
        public string $value,
    ) {
    }
}
