<?php

declare(strict_types=1);

namespace App\Scan\Domain;

final readonly class Target
{
    /**
     * @param 'ip'|'domain' $kind
     */
    public function __construct(
        public string $raw,
        public string $kind,
        public string $value,
    ) {
    }
}
