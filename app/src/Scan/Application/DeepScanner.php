<?php

declare(strict_types=1);

namespace App\Scan\Application;

use App\Scan\Domain\DnsClientInterface;
use App\Scan\Domain\HttpProberInterface;
use App\Scan\Domain\ScanResult;
use App\Scan\Domain\Target;
use App\Scan\Domain\WebClientInterface;
use App\Scan\Infrastructure\ConcurrentMapper;
use App\Scan\Job\ScanPipeline;

/** @deprecated Use ScanPipeline. Kept as thin alias for existing unit tests. */
final class DeepScanner
{
    private readonly ScanPipeline $pipeline;

    public function __construct(
        DnsClientInterface $dns,
        WebClientInterface $web,
        HttpProberInterface $http,
        ConcurrentMapper $mapper,
        ScanSettings $settings,
    ) {
        $this->pipeline = new ScanPipeline($dns, $web, $http, $mapper, $settings);
    }

    public function scan(Target $target): ScanResult
    {
        return $this->pipeline->scan($target);
    }
}
