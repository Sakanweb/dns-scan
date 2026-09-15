<?php

declare(strict_types=1);

namespace App\Scan\Domain;

final readonly class HttpCheck
{
    public function __construct(
        public bool $works,
        public ?int $status,
        public string $title,
        public string $finalUrl,
        public bool $tlsOk,
        public bool $defaultPage,
        public string $error,
        public int $bodyLen,
    ) {
    }
}
