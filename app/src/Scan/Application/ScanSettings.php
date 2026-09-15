<?php

declare(strict_types=1);

namespace App\Scan\Application;

final readonly class ScanSettings
{
    public function __construct(
        public int $dnsThreads = 40,
        public int $httpTimeout = 10,
        public int $dnsTimeout = 3,
        public bool $probeHttp = true,
        public bool $usePassive = true,
        public bool $useReverseIp = true,
        public bool $tryAxfr = true,
        public string $wordlistPath = '',
    ) {
    }

    public static function defaultWordlistPath(): string
    {
        return dirname(__DIR__, 3) . '/resources/wordlist.txt';
    }

    public static function fromEnv(): self
    {
        return new self(
            dnsThreads: max(1, (int) (getenv('DNS_THREADS') ?: 40)),
            httpTimeout: max(1, (int) (getenv('HTTP_TIMEOUT') ?: 10)),
            dnsTimeout: max(1, (int) (getenv('DNS_TIMEOUT') ?: 3)),
            probeHttp: true,
            usePassive: true,
            useReverseIp: true,
            tryAxfr: true,
            wordlistPath: self::defaultWordlistPath(),
        );
    }

    public function withOverrides(
        ?bool $probeHttp = null,
        ?bool $usePassive = null,
        ?bool $useReverseIp = null,
        ?bool $tryAxfr = null,
        ?int $dnsThreads = null,
        ?string $wordlistPath = null,
    ): self {
        return new self(
            dnsThreads: $dnsThreads ?? $this->dnsThreads,
            httpTimeout: $this->httpTimeout,
            dnsTimeout: $this->dnsTimeout,
            probeHttp: $probeHttp ?? $this->probeHttp,
            usePassive: $usePassive ?? $this->usePassive,
            useReverseIp: $useReverseIp ?? $this->useReverseIp,
            tryAxfr: $tryAxfr ?? $this->tryAxfr,
            wordlistPath: $wordlistPath ?? $this->wordlistPath,
        );
    }
}
