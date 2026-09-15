<?php

declare(strict_types=1);

namespace App\Scan\Application;

use App\Scan\Domain\TargetParser;
use App\Scan\Job\ScanJobProcessor;
use App\Scan\Persistence\ScanRepository;

/**
 * Application API: enqueue jobs; processing is always via ScanJobProcessor stages.
 */
final class ScanService
{
    public function __construct(
        private readonly ScanRepository $repository,
        private readonly ScanJobProcessor $processor,
        private readonly ScanSettings $defaults,
        private readonly WorkerSwitchInterface $workerSwitch,
    ) {
    }

    public function enqueue(string $targetInput, ?ScanSettings $override = null): int
    {
        $settings = $override ?? $this->defaults;
        $target = TargetParser::parse($targetInput);

        return $this->repository->enqueue($target, $settings);
    }

    /**
     * CLI: enqueue + drain stages with DB checkpoints after each stage.
     *
     * @return array{runId: int, result: \App\Scan\Domain\ScanResult}
     */
    public function run(string $targetInput, ?ScanSettings $override = null): array
    {
        return $this->processor->runToCompletion($targetInput, $override ?? $this->defaults);
    }

    /** Worker: one pipeline stage. */
    public function processNext(): ?array
    {
        if (!$this->workerSwitch->isOn()) {
            return null;
        }

        return $this->processor->processNextStep();
    }

    public function isWorkerOn(): bool
    {
        return $this->workerSwitch->isOn();
    }

    public function toggleWorker(): bool
    {
        $next = !$this->workerSwitch->isOn();
        $this->workerSwitch->setOn($next);

        return $next;
    }
}
