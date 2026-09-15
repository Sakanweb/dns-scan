<?php

declare(strict_types=1);

namespace App\Scan\Infrastructure;

use App\Scan\Domain\DnsClientInterface;
use App\Scan\Domain\Parsers;
use Symfony\Component\Process\Process;

/**
 * Parallel dig via OS processes (real concurrency, unlike Amp fibers + blocking dig).
 */
final readonly class DigDnsClient implements DnsClientInterface
{
    public function __construct(
        private int $timeoutSec = 3,
        private int $tries = 1,
        public string $resolver = '1.1.1.1',
    ) {
    }

    /**
     * @param list<string> $extra
     * @return list<string>
     */
    public static function argv(
        array $extra,
        int $timeoutSec = 3,
        int $tries = 1,
        string $resolver = '1.1.1.1',
    ): array {
        $cmd = [
            'dig',
            "+time={$timeoutSec}",
            "+tries={$tries}",
            '+short',
        ];
        $hasExplicitNs = false;
        foreach ($extra as $arg) {
            if (str_starts_with((string) $arg, '@')) {
                $hasExplicitNs = true;
                break;
            }
        }
        if ($resolver !== '' && !$hasExplicitNs) {
            $cmd[] = '@' . ltrim($resolver, '@');
        }

        return array_merge($cmd, $extra);
    }

    public function query(string $name, string $rtype): array
    {
        return $this->run($this->digCommand([$name, $rtype]));
    }

    public function reverse(string $ip): array
    {
        return $this->run($this->digCommand(['-x', $ip]));
    }

    public function zoneTransfer(string $nameserver, string $zone): array
    {
        return $this->run($this->digCommand(["@{$nameserver}", $zone, 'AXFR']));
    }

    /**
     * @param list<string> $labels
     * @param list<string> $wildcardIps
     * @return list<string> live FQDNs
     */
    public function probeWordlist(string $domain, array $labels, array $wildcardIps, int $workers): array
    {
        $fqdns = [];
        foreach ($labels as $label) {
            $fqdns[] = "{$label}.{$domain}";
        }

        return $this->probeNames($fqdns, $wildcardIps, $workers);
    }

    /**
     * @param list<string> $fqdns
     * @param list<string> $wildcardIps
     * @return list<string> live FQDNs
     */
    public function probeNames(array $fqdns, array $wildcardIps, int $workers): array
    {
        if ($fqdns === []) {
            return [];
        }

        $jobs = [];
        foreach ($fqdns as $fqdn) {
            $jobs["{$fqdn}|A"] = $this->digCommand([$fqdn, 'A']);
            $jobs["{$fqdn}|AAAA"] = $this->digCommand([$fqdn, 'AAAA']);
            $jobs["{$fqdn}|CNAME"] = $this->digCommand([$fqdn, 'CNAME']);
        }

        $raw = $this->runParallel($jobs, max(1, $workers));
        $wildcardSet = array_fill_keys($wildcardIps, true);
        $found = [];

        foreach ($fqdns as $fqdn) {
            $a = $raw["{$fqdn}|A"] ?? [];
            $aaaa = $raw["{$fqdn}|AAAA"] ?? [];
            $cname = array_merge(
                $raw["{$fqdn}|CNAME"] ?? [],
                Parsers::onlyHostnames(array_merge($a, $aaaa)),
            );
            $answers = Parsers::onlyIpAddresses(array_merge($a, $aaaa));
            if ($answers === [] && $cname === []) {
                continue;
            }
            if ($wildcardSet !== [] && $cname === [] && $this->isSubset($answers, $wildcardSet)) {
                continue;
            }
            $found[] = $fqdn;
        }

        return $found;
    }

    /**
     * @param list<string> $names
     * @return array<string, array{ips: list<string>, cname: list<string>}>
     */
    public function resolveMany(array $names, int $workers): array
    {
        $jobs = [];
        foreach ($names as $name) {
            $jobs["{$name}|A"] = $this->digCommand([$name, 'A']);
            $jobs["{$name}|AAAA"] = $this->digCommand([$name, 'AAAA']);
            $jobs["{$name}|CNAME"] = $this->digCommand([$name, 'CNAME']);
        }
        $raw = $this->runParallel($jobs, max(1, $workers));
        $out = [];
        foreach ($names as $name) {
            $a = $raw["{$name}|A"] ?? [];
            $aaaa = $raw["{$name}|AAAA"] ?? [];
            $out[$name] = [
                'ips' => Parsers::uniqueSorted(Parsers::onlyIpAddresses(array_merge($a, $aaaa))),
                'cname' => Parsers::uniqueSorted(array_merge(
                    $raw["{$name}|CNAME"] ?? [],
                    Parsers::onlyHostnames(array_merge($a, $aaaa)),
                )),
            ];
        }

        return $out;
    }

    /**
     * @param array<string, list<string>> $commands keyed argv lists
     * @return array<string, list<string>>
     */
    public function runParallel(array $commands, int $workers): array
    {
        if ($commands === []) {
            return [];
        }

        $workers = max(1, $workers);
        $results = [];
        $pending = $commands;
        /** @var array<string, Process> $running */
        $running = [];

        while ($pending !== [] || $running !== []) {
            while (count($running) < $workers && $pending !== []) {
                $key = array_key_first($pending);
                $argv = $pending[$key];
                unset($pending[$key]);
                $process = new Process($argv);
                $process->setTimeout($this->timeoutSec * 3);
                $process->start();
                $running[$key] = $process;
            }

            foreach ($running as $key => $process) {
                if ($process->isRunning()) {
                    continue;
                }
                $results[$key] = Parsers::parseDigShort($process->getOutput());
                unset($running[$key]);
            }

            if ($running !== []) {
                usleep(5_000);
            }
        }

        return $results;
    }

    /**
     * @param list<string> $extra
     * @return list<string>
     */
    private function digCommand(array $extra): array
    {
        return self::argv($extra, $this->timeoutSec, $this->tries, $this->resolver);
    }

    /**
     * @param list<string> $command
     * @return list<string>
     */
    private function run(array $command): array
    {
        try {
            $process = new Process($command);
            $process->setTimeout($this->timeoutSec * 3);
            $process->run();

            return Parsers::parseDigShort($process->getOutput());
        } catch (\Throwable) {
            return [];
        }
    }

    /**
     * @param list<string> $answers
     * @param array<string, true> $set
     */
    private function isSubset(array $answers, array $set): bool
    {
        if ($answers === []) {
            return false;
        }
        foreach ($answers as $item) {
            if (!isset($set[$item])) {
                return false;
            }
        }

        return true;
    }
}
