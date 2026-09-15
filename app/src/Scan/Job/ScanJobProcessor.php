<?php

declare(strict_types=1);

namespace App\Scan\Job;

use App\Scan\Application\ScanSettings;
use App\Scan\Domain\DnsClientInterface;
use App\Scan\Domain\HttpProberInterface;
use App\Scan\Domain\ScanResult;
use App\Scan\Domain\TargetParser;
use App\Scan\Domain\WebClientInterface;
use App\Scan\Infrastructure\ConcurrentMapper;
use App\Scan\Infrastructure\CurlHttpProber;
use App\Scan\Infrastructure\DisabledHttpProber;
use App\Scan\Infrastructure\DisabledWebClient;
use App\Scan\Infrastructure\DigDnsClient;
use App\Scan\Infrastructure\PublicWebClient;
use App\Scan\Persistence\ScanRepository;

/**
 * Only the worker advances stages. CLI/UI enqueue and observe.
 * One tick = one stage, always persisted.
 */
final class ScanJobProcessor
{
    public function __construct(
        private readonly ScanRepository $repository,
        private readonly ConcurrentMapper $mapper,
        private readonly ScanSettings $defaults,
        private readonly DnsClientInterface $dns,
        private readonly WebClientInterface $web,
        private readonly HttpProberInterface $http,
    ) {
    }

    /**
     * @return array{runId: int, stage: string, status: string}|null
     */
    public function processNextStep(): ?array
    {
        $job = $this->repository->claimNext();
        if ($job === null) {
            return null;
        }

        return $this->advanceJob($job);
    }

    /**
     * Enqueue and wait until the worker finishes all stages.
     *
     * @return array{runId: int, result: ScanResult}
     */
    public function runToCompletion(string $targetInput, ?ScanSettings $override = null, int $timeoutSec = 600): array
    {
        $settings = $override ?? $this->defaults;
        $runId = $this->repository->enqueue(TargetParser::parse($targetInput), $settings);
        $deadline = time() + max(30, $timeoutSec);

        while (time() < $deadline) {
            $run = $this->repository->findRun($runId);
            if ($run === null) {
                throw new \RuntimeException("Run #{$runId} not found");
            }

            $status = (string) $run['status'];
            if ($status === 'done') {
                $ctx = JobContext::fromArray(is_array($run['context'] ?? null) ? $run['context'] : []);

                return ['runId' => $runId, 'result' => $ctx->toScanResult()];
            }
            if ($status === 'failed') {
                throw new \RuntimeException((string) ($run['error_text'] ?? "Run #{$runId} failed"));
            }

            usleep(500_000);
        }

        throw new \RuntimeException("Timed out waiting for worker to finish run #{$runId}");
    }

    /**
     * @param array<string, mixed> $job
     * @return array{runId: int, stage: string, status: string}
     */
    private function advanceJob(array $job): array
    {
        $runId = (int) $job['id'];
        $settings = $this->settingsFromJob($job);
        $stage = ScanStage::from((string) $job['stage']);

        try {
            if ($stage === ScanStage::Queued) {
                $stage = ScanStage::pipeline($settings->probeHttp, $settings->usePassive)[0];
                $target = TargetParser::parse((string) $job['target_input']);
                $ctx = JobContext::fromTarget($target, $this->loadWordlist($settings->wordlistPath));
            } else {
                $ctx = JobContext::fromArray(is_array($job['context'] ?? null) ? $job['context'] : []);
            }

            $pipeline = $this->makePipeline($settings);
            $ctx = $pipeline->runStage($stage, $ctx);
            $next = $this->nextStage($stage, $settings);

            if ($next === null) {
                $this->repository->completeRun($runId, $ctx->toScanResult(), $ctx);

                return ['runId' => $runId, 'stage' => ScanStage::Done->value, 'status' => 'done'];
            }

            $this->repository->saveProgress(
                $runId,
                $next,
                $stage->label() . ' → ' . $next->label(),
                $ctx,
                'running',
            );

            return ['runId' => $runId, 'stage' => $next->value, 'status' => 'running'];
        } catch (\Throwable $e) {
            $this->repository->failRun($runId, $e->getMessage());
            throw $e;
        }
    }

    private function nextStage(ScanStage $current, ScanSettings $settings): ?ScanStage
    {
        $pipeline = ScanStage::pipeline($settings->probeHttp, $settings->usePassive);
        $idx = array_search($current, $pipeline, true);
        if ($idx === false) {
            return null;
        }

        return $pipeline[$idx + 1] ?? null;
    }

    private function makePipeline(ScanSettings $settings): ScanPipeline
    {
        $dns = $this->dns instanceof DigDnsClient
            ? new DigDnsClient($settings->dnsTimeout, 1, $this->dns->resolver)
            : $this->dns;
        $web = $settings->usePassive || $settings->useReverseIp
            ? ($this->web instanceof PublicWebClient ? $this->web : new PublicWebClient())
            : new DisabledWebClient();
        $http = $settings->probeHttp
            ? new CurlHttpProber($settings->httpTimeout)
            : new DisabledHttpProber();

        return new ScanPipeline($dns, $web, $http, $this->mapper, $settings);
    }

    /** @param array<string, mixed> $job */
    private function settingsFromJob(array $job): ScanSettings
    {
        return new ScanSettings(
            dnsThreads: max(1, (int) $job['dns_threads']),
            httpTimeout: max(1, (int) $job['http_timeout']),
            dnsTimeout: $this->defaults->dnsTimeout,
            probeHttp: (bool) $job['probe_http'],
            usePassive: (bool) ($job['use_passive'] ?? $this->defaults->usePassive),
            useReverseIp: (bool) ($job['use_reverse_ip'] ?? $this->defaults->useReverseIp),
            tryAxfr: (bool) ($job['try_axfr'] ?? $this->defaults->tryAxfr),
            wordlistPath: $this->defaults->wordlistPath,
        );
    }

    /** @return list<string> */
    private function loadWordlist(string $path): array
    {
        if ($path === '' || !is_file($path)) {
            return [];
        }
        $labels = [];
        foreach (file($path, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            $item = strtolower(trim($line));
            if ($item !== '' && !str_starts_with($item, '#')) {
                $labels[] = $item;
            }
        }

        return $labels;
    }
}
