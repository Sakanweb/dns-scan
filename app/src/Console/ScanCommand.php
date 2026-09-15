<?php

declare(strict_types=1);

namespace App\Console;

use App\Scan\Application\ScanService;
use App\Scan\Application\ScanSettings;
use App\Scan\Domain\HostHit;
use App\Scan\Domain\ScanResult;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Yiisoft\Yii\Console\ExitCode;

#[AsCommand(
    name: 'scan:run',
    description: 'Deep inventory of domains/subdomains: DNS, certificates, archives, HTTP',
)]
final class ScanCommand extends Command
{
    public function __construct(
        private readonly ScanService $scanService,
        private readonly ScanSettings $defaults,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('target', InputArgument::REQUIRED, 'IPv4/IPv6 or domain')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'Output format: text|json|list', 'text')
            ->addOption('dns-only', null, InputOption::VALUE_NONE, 'DNS + wordlist only')
            ->addOption('no-http', null, InputOption::VALUE_NONE, 'Skip HTTP/HTTPS probes')
            ->addOption('no-reverse-ip', null, InputOption::VALUE_NONE, 'Skip reverse-IP lookups')
            ->addOption('no-axfr', null, InputOption::VALUE_NONE, 'Skip AXFR attempts');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $target = (string) $input->getArgument('target');
        $format = (string) $input->getOption('format');
        if (!in_array($format, ['text', 'json', 'list'], true)) {
            $output->writeln('<error>Invalid --format. Use text, json, or list.</error>');

            return ExitCode::DATAERR;
        }

        $dnsOnly = (bool) $input->getOption('dns-only');
        $settings = $this->defaults->withOverrides(
            probeHttp: !$dnsOnly && !(bool) $input->getOption('no-http'),
            usePassive: !$dnsOnly,
            useReverseIp: !$dnsOnly && !(bool) $input->getOption('no-reverse-ip'),
            tryAxfr: !(bool) $input->getOption('no-axfr'),
        );

        try {
            $payload = $this->scanService->run($target, $settings);
        } catch (\InvalidArgumentException $e) {
            $output->writeln('<error>error: ' . $e->getMessage() . '</error>');

            return ExitCode::DATAERR;
        } catch (\Throwable $e) {
            $output->writeln('<error>error: ' . $e->getMessage() . '</error>');

            return ExitCode::UNSPECIFIED_ERROR;
        }

        $output->writeln($this->render($payload['result'], $format));
        $output->writeln('run id: ' . $payload['runId'], OutputInterface::VERBOSITY_NORMAL);

        return ExitCode::OK;
    }

    private function render(ScanResult $result, string $fmt): string
    {
        $confirmed = array_values(array_filter(
            $result->hosts,
            static fn (HostHit $h): bool => $h->kind === 'confirmed',
        ));
        $working = array_values(array_filter(
            $confirmed,
            static fn (HostHit $h): bool => $h->http !== null && $h->http->works,
        ));
        $defaulted = array_values(array_filter(
            $confirmed,
            static fn (HostHit $h): bool => $h->http !== null && $h->http->defaultPage,
        ));
        $unresolved = array_values(array_filter(
            $result->hosts,
            static fn (HostHit $h): bool => $h->kind === 'unresolved',
        ));

        if ($fmt === 'list') {
            return implode("\n", array_map(static fn (HostHit $h): string => $h->name, $confirmed));
        }
        if ($fmt === 'json') {
            return json_encode($this->toJson($result), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        }

        $lines = [
            "target: {$result->target->value} ({$result->target->kind})",
            'wildcard: ' . (implode(', ', $result->wildcardIps) ?: 'none'),
            'ips: ' . (implode(', ', $result->ips) ?: '-'),
            'confirmed: ' . count($confirmed)
                . '  working: ' . count($working)
                . '  default-page: ' . count($defaulted)
                . '  unresolved: ' . count($unresolved),
        ];
        $lines = array_merge($lines, $this->section('WORKING', $working));

        $workingKeys = [];
        foreach ($working as $host) {
            $workingKeys[$host->name] = true;
        }
        $confirmedRest = array_values(array_filter(
            $confirmed,
            static fn (HostHit $h): bool => !isset($workingKeys[$h->name]),
        ));
        $lines = array_merge($lines, $this->section('CONFIRMED (dns/certs/archives)', $confirmedRest));
        if ($unresolved !== []) {
            $lines = array_merge($lines, $this->section('IN CERTS/ARCHIVES, NO DNS', $unresolved));
        }
        if ($result->notes !== []) {
            $lines[] = '';
            $lines[] = 'notes:';
            foreach ($result->notes as $note) {
                $lines[] = '  ' . $note;
            }
        }

        return implode("\n", $lines);
    }

    /**
     * @param list<HostHit> $hosts
     * @return list<string>
     */
    private function section(string $title, array $hosts): array
    {
        if ($hosts === []) {
            return [];
        }
        $lines = ['', $title . ':'];
        foreach ($hosts as $host) {
            $http = '';
            if ($host->http !== null) {
                $status = $host->http->status ?? ($host->http->error !== '' ? $host->http->error : '-');
                $titleText = $host->http->title !== '' ? $host->http->title : '-';
                $tls = $host->http->tlsOk ? 'tls-ok' : 'tls-bad';
                $flag = $host->http->defaultPage ? 'DEFAULT' : ($host->http->works ? 'UP' : 'DOWN');
                $http = "  http={$flag} {$status} {$tls} {$titleText}";
            }
            $ips = implode(',', $host->ips) ?: '-';
            $src = implode(',', $host->sources);
            $lines[] = "  {$host->name}  ip={$ips}  src={$src}{$http}";
        }

        return $lines;
    }

    /**
     * @return array<string, mixed>
     */
    private function toJson(ScanResult $result): array
    {
        return [
            'target' => $result->target->value,
            'kind' => $result->target->kind,
            'ips' => $result->ips,
            'wildcard_ips' => $result->wildcardIps,
            'names' => $result->names,
            'notes' => $result->notes,
            'hosts' => array_map(static function (HostHit $host): array {
                return [
                    'name' => $host->name,
                    'ips' => $host->ips,
                    'cname' => $host->cname,
                    'sources' => $host->sources,
                    'kind' => $host->kind,
                    'http' => $host->http === null ? null : [
                        'works' => $host->http->works,
                        'status' => $host->http->status,
                        'title' => $host->http->title,
                        'tls_ok' => $host->http->tlsOk,
                        'default_page' => $host->http->defaultPage,
                        'error' => $host->http->error,
                        'final_url' => $host->http->finalUrl,
                    ],
                ];
            }, $result->hosts),
            'records' => array_map(static fn ($rec): array => [
                'name' => $rec->name,
                'type' => $rec->rtype,
                'value' => $rec->value,
            ], $result->records),
        ];
    }
}
