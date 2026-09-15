<?php

declare(strict_types=1);

namespace App\Scan\Job;

use App\Scan\Application\ScanSettings;
use App\Scan\Domain\DnsClientInterface;
use App\Scan\Domain\HostHit;
use App\Scan\Domain\HttpProberInterface;
use App\Scan\Domain\Parsers;
use App\Scan\Domain\ScanResult;
use App\Scan\Domain\Target;
use App\Scan\Domain\TargetParser;
use App\Scan\Domain\WebClientInterface;
use App\Scan\Domain\Cloudflare;
use App\Scan\Infrastructure\ConcurrentMapper;
use App\Scan\Infrastructure\DigDnsClient;

/**
 * Runs exactly one pipeline stage per call. Worker persists JobContext between calls.
 */
final class ScanPipeline
{
    private const RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];

    private const MUTATION_PREFIXES = ['www', 'old', 'api', 'admin', 'staging', 'demo', 'dev', 'mail'];

    private const PASSIVE_SOURCES = ['crt.sh', 'certspotter', 'wayback', 'hostsearch', 'axfr'];

    public function __construct(
        private readonly DnsClientInterface $dns,
        private readonly WebClientInterface $web,
        private readonly HttpProberInterface $http,
        private readonly ConcurrentMapper $mapper,
        private readonly ScanSettings $settings,
    ) {
    }

    public function runStage(ScanStage $stage, JobContext $ctx): JobContext
    {
        return match ($stage) {
            ScanStage::DnsBase => $this->stageDnsBase($ctx),
            ScanStage::Passive => $this->stagePassive($ctx),
            ScanStage::Wordlist => $this->stageWordlist($ctx),
            ScanStage::Resolve => $this->stageResolve($ctx),
            ScanStage::HttpProbe => $this->stageHttpProbe($ctx),
            ScanStage::Finalize => $this->stageFinalize($ctx),
            default => throw new \InvalidArgumentException("Stage {$stage->value} is not executable"),
        };
    }

    /** Full in-memory run (unit tests / CLI wait helper). */
    public function scan(Target $target): ScanResult
    {
        $ctx = JobContext::fromTarget($target, $this->loadWordlist($this->settings->wordlistPath));
        foreach (ScanStage::pipeline($this->settings->probeHttp, $this->settings->usePassive) as $stage) {
            $ctx = $this->runStage($stage, $ctx);
        }

        return $ctx->toScanResult();
    }

    private function stageDnsBase(JobContext $ctx): JobContext
    {
        if ($ctx->targetKind === 'ip') {
            $ptrs = $this->dns->reverse($ctx->targetValue);
            foreach ($ptrs as $item) {
                $ctx->addRecord($ctx->targetValue, 'PTR', $item);
            }
            foreach ($this->cleanNames($ptrs) as $name) {
                $ctx->addSource($name, 'ptr');
            }
            if ($this->settings->useReverseIp && !Cloudflare::isCloudflareIp($ctx->targetValue)) {
                foreach ($this->web->reverseIpNames($ctx->targetValue) as $name) {
                    $ctx->addSource($name, 'reverse-ip');
                }
            }
            $domains = [];
            foreach (array_keys($ctx->sources) as $name) {
                if (str_contains($name, '.') && !TargetParser::isReverseDnsName($name) && !$this->isIp($name)) {
                    $domains[] = $name;
                }
            }
            $ctx->domains = $this->baseDomains($domains);
        } else {
            $ctx->addSource($ctx->targetValue, 'apex');
            $ctx->domains = [$ctx->targetValue];
        }

        $wildcard = [];
        foreach ($ctx->domains as $domain) {
            $wildcard = array_merge($wildcard, $this->collectDnsBase($ctx, $domain));
        }
        $ctx->wildcardIps = Parsers::uniqueSorted($wildcard);

        return $ctx;
    }

    private function stagePassive(JobContext $ctx): JobContext
    {
        foreach ($ctx->domains as $domain) {
            $this->addPassive($ctx, $domain);
            if ($this->settings->tryAxfr) {
                $this->tryAxfr($ctx, $domain);
            }
            if ($this->settings->useReverseIp) {
                $this->reverseForDomainIps($ctx, $domain);
            }
        }

        return $ctx;
    }

    private function stageWordlist(JobContext $ctx): JobContext
    {
        foreach ($ctx->domains as $domain) {
            $live = $this->liveSubdomains($domain, $ctx->wordlist, $this->settings->dnsThreads, $ctx->wildcardIps);
            foreach ($live as $fqdn) {
                $ctx->addSource($fqdn, 'wordlist');
            }
            $this->mutateNames($ctx, $domain, $ctx->wildcardIps);
        }

        return $ctx;
    }

    private function stageResolve(JobContext $ctx): JobContext
    {
        $hosts = $this->buildHosts($ctx->sources, $ctx->wildcardIps, $this->settings->dnsThreads);
        $ctx->hosts = array_map(static fn (HostHit $h): array => JobContext::hostToArray($h), $hosts);
        $ctx->names = Parsers::uniqueSorted(
            array_map(
                static fn (HostHit $host): string => $host->name,
                array_values(array_filter($hosts, static fn (HostHit $h): bool => $h->kind !== 'wildcard')),
            ),
        );
        $ipLists = array_map(static fn (HostHit $host): array => $host->ips, $hosts);
        $ctx->ips = Parsers::uniqueSorted($ipLists === [] ? [] : array_merge(...$ipLists));
        if ($ctx->targetKind === 'ip') {
            $ctx->ips = Parsers::uniqueSorted([$ctx->targetValue, ...$ctx->ips]);
        }

        return $ctx;
    }

    private function stageHttpProbe(JobContext $ctx): JobContext
    {
        $hosts = [];
        foreach ($ctx->hosts as $row) {
            $hosts[] = new HostHit(
                (string) $row['name'],
                array_values($row['ips'] ?? []),
                array_values($row['cname'] ?? []),
                array_values($row['sources'] ?? []),
                (string) ($row['kind'] ?? 'unresolved'),
            );
        }

        $targets = array_values(array_filter(
            $hosts,
            static fn (HostHit $host): bool => $host->kind === 'confirmed',
        ));
        if ($targets !== []) {
            $http = $this->http;
            $this->mapper->map(
                $targets,
                max(1, min($this->settings->dnsThreads, 20)),
                static function (HostHit $host) use ($http): HostHit {
                    $host->http = $http->probe($host->name);

                    return $host;
                },
            );
        }

        $byName = [];
        foreach ($hosts as $host) {
            $byName[$host->name] = JobContext::hostToArray($host);
        }
        // Keep order from previous stage, overlay probed confirmed hosts
        $ctx->hosts = array_map(
            static function (array $row) use ($byName): array {
                $name = (string) $row['name'];

                return $byName[$name] ?? $row;
            },
            $ctx->hosts,
        );

        return $ctx;
    }

    private function stageFinalize(JobContext $ctx): JobContext
    {
        // Persistence is done by ScanJobProcessor; context is already complete.
        return $ctx;
    }

    /**
     * @return list<string> wildcard ips for domain
     */
    private function collectDnsBase(JobContext $ctx, string $domain): array
    {
        $ctx->addSource($domain, 'apex');
        $domainIps = [];
        $nsRecords = [];

        foreach (self::RECORD_TYPES as $rtype) {
            $answers = $this->dns->query($domain, $rtype);
            foreach ($answers as $answer) {
                $ctx->addRecord($domain, $rtype, $answer);
                if (($rtype === 'A' || $rtype === 'AAAA') && Parsers::isIpAddress($answer)) {
                    $domainIps[$answer] = true;
                }
                $host = $this->recordHostname($rtype, $answer);
                if ($host !== null && Parsers::belongsTo($host, $domain)) {
                    $ctx->addSource($host, strtolower($rtype));
                }
                if ($rtype === 'NS') {
                    $nsRecords[] = $answer;
                }
            }
        }

        // stash NS for later AXFR/reverse stages via notes key? keep in sources domain meta
        // Store ns in context notes temporarily - better: encode in sources as __ns__
        foreach ($nsRecords as $ns) {
            $ctx->addSource($domain . '|ns|' . $ns, 'ns-meta');
        }
        foreach (array_keys($domainIps) as $ip) {
            $ctx->addSource($domain . '|ip|' . $ip, 'ip-meta');
        }

        $wildcardIps = $this->dns->query(bin2hex(random_bytes(16)) . '.' . $domain, 'A');
        $wildcardIps = array_merge(
            $wildcardIps,
            $this->dns->query(bin2hex(random_bytes(16)) . '.' . $domain, 'AAAA'),
        );
        $wildcardIps = array_values(array_unique($wildcardIps));
        if ($wildcardIps !== []) {
            $sorted = $wildcardIps;
            sort($sorted);
            $ctx->addNote('wildcard DNS on ' . $domain . ': ' . implode(', ', $sorted));
        }

        return $wildcardIps;
    }

    private function addPassive(JobContext $ctx, string $domain): void
    {
        $fetchers = [
            'crt.sh' => fn (): array => $this->web->certificateNames($domain),
            'certspotter' => fn (): array => $this->web->certspotterNames($domain),
            'wayback' => fn (): array => $this->web->waybackNames($domain),
            'hostsearch' => fn (): array => $this->web->hostsearchNames($domain),
        ];

        foreach ($fetchers as $source => $fetch) {
            try {
                $names = $fetch();
            } catch (\Throwable $e) {
                $ctx->addNote("{$source} failed: {$e->getMessage()}");
                continue;
            }
            if ($names === []) {
                $ctx->addNote("{$source}: no names");
                continue;
            }
            foreach ($names as $name) {
                $ctx->addSource($name, $source);
            }
        }
    }

    private function tryAxfr(JobContext $ctx, string $domain): void
    {
        foreach ($this->metaValues($ctx, $domain, 'ns') as $item) {
            $nameserver = $this->recordHostname('NS', $item);
            if ($nameserver === null) {
                continue;
            }
            $transferred = $this->dns->zoneTransfer($nameserver, $domain);
            if ($transferred !== []) {
                $ctx->addNote("AXFR allowed on {$nameserver}");
                foreach ($this->cleanNames($transferred) as $host) {
                    if (Parsers::belongsTo($host, $domain)) {
                        $ctx->addSource($host, 'axfr');
                    }
                }
            } else {
                $ctx->addNote("AXFR denied on {$nameserver}");
            }
        }
    }

    private function reverseForDomainIps(JobContext $ctx, string $domain): void
    {
        $nsRecords = $this->metaValues($ctx, $domain, 'ns');
        if (Cloudflare::isCloudflareNs($nsRecords)) {
            $ctx->addNote('Cloudflare NS: reverse-IP skipped for anycast addresses');
        }
        foreach ($this->metaValues($ctx, $domain, 'ip') as $ip) {
            if (Cloudflare::isCloudflareIp($ip)) {
                continue;
            }
            foreach ($this->web->reverseIpNames($ip) as $name) {
                $ctx->addSource($name, 'reverse-ip');
            }
            $ptrs = $this->dns->reverse($ip);
            foreach ($ptrs as $item) {
                $ctx->addRecord($ip, 'PTR', $item);
            }
            foreach ($this->cleanNames($ptrs) as $name) {
                $ctx->addSource($name, 'ptr');
            }
        }
    }

    /** @return list<string> */
    private function metaValues(JobContext $ctx, string $domain, string $kind): array
    {
        $prefix = $domain . '|' . $kind . '|';
        $out = [];
        foreach (array_keys($ctx->sources) as $key) {
            if (str_starts_with($key, $prefix)) {
                $out[] = substr($key, strlen($prefix));
            }
        }

        return $out;
    }

    /**
     * @param list<string> $wildcardIps
     */
    private function mutateNames(JobContext $ctx, string $domain, array $wildcardIps): void
    {
        $seeds = [];
        foreach (array_keys($ctx->sources) as $name) {
            if (str_contains($name, '|')) {
                continue;
            }
            if (Parsers::belongsTo($name, $domain) && !$this->isIp($name)) {
                $seeds[] = $name;
            }
        }

        $extras = [];
        foreach ($seeds as $name) {
            $extras[] = 'www.' . $name;
            if ($name === $domain) {
                continue;
            }
            $label = substr($name, 0, -strlen($domain) - 1);
            if (str_contains($label, '.')) {
                continue;
            }
            foreach (self::MUTATION_PREFIXES as $prefix) {
                $extras[] = "{$prefix}.{$name}";
            }
        }

        $candidates = [];
        foreach (Parsers::uniqueSorted($extras) as $fqdn) {
            if (!isset($ctx->sources[$fqdn])) {
                $candidates[] = $fqdn;
            }
        }
        foreach ($this->probeLive($candidates, $wildcardIps, $this->settings->dnsThreads) as $fqdn) {
            $ctx->addSource($fqdn, 'mutation');
        }
    }

    /**
     * @param list<string> $wordlist
     * @param list<string> $wildcardIps
     * @return list<string>
     */
    private function liveSubdomains(string $domain, array $wordlist, int $workers, array $wildcardIps): array
    {
        $labels = Parsers::uniqueSorted($wordlist);
        if ($labels === []) {
            return [];
        }

        $fqdns = [];
        foreach ($labels as $label) {
            $fqdns[] = "{$label}.{$domain}";
        }

        return $this->probeLive($fqdns, $wildcardIps, $workers);
    }

    /**
     * @param list<string> $fqdns
     * @param list<string> $wildcardIps
     * @return list<string>
     */
    private function probeLive(array $fqdns, array $wildcardIps, int $workers): array
    {
        $fqdns = Parsers::uniqueSorted($fqdns);
        if ($fqdns === []) {
            return [];
        }

        if ($this->dns instanceof DigDnsClient) {
            return $this->dns->probeNames($fqdns, $wildcardIps, $workers);
        }

        $wildcardSet = array_fill_keys($wildcardIps, true);
        $dns = $this->dns;

        /** @var list<?string> $checked */
        $checked = array_values($this->mapper->map(
            $fqdns,
            $workers,
            static function (string $fqdn) use ($dns, $wildcardSet): ?string {
                $a = $dns->query($fqdn, 'A');
                $aaaa = $dns->query($fqdn, 'AAAA');
                $cname = array_merge(
                    $dns->query($fqdn, 'CNAME'),
                    Parsers::onlyHostnames(array_merge($a, $aaaa)),
                );
                $answers = Parsers::onlyIpAddresses(array_merge($a, $aaaa));
                if ($answers === [] && $cname === []) {
                    return null;
                }
                if ($wildcardSet !== [] && $cname === [] && self::isSubsetStatic($answers, $wildcardSet)) {
                    return null;
                }

                return $fqdn;
            },
        ));

        $found = [];
        foreach ($checked as $item) {
            if ($item !== null) {
                $found[] = $item;
            }
        }

        return $found;
    }

    /**
     * @param array<string, list<string>> $sources
     * @param list<string> $wildcardIps
     * @return list<HostHit>
     */
    private function buildHosts(array $sources, array $wildcardIps, int $workers): array
    {
        $names = Parsers::uniqueSorted(
            array_values(array_filter(
                array_keys($sources),
                fn (string $name): bool => !str_contains($name, '|') && !$this->isIp($name) && str_contains($name, '.'),
            )),
        );

        $wildcardSet = array_fill_keys($wildcardIps, true);

        if ($this->dns instanceof DigDnsClient) {
            $resolved = $this->dns->resolveMany($names, $workers);
            $hits = [];
            foreach ($names as $name) {
                $ips = $resolved[$name]['ips'] ?? [];
                $cname = $resolved[$name]['cname'] ?? [];
                $src = $sources[$name] ?? [];
                sort($src);
                $hits[] = new HostHit($name, $ips, $cname, $src, self::classify($src, $ips, $cname, $wildcardSet));
            }
        } else {
            $dns = $this->dns;
            /** @var list<HostHit> $hits */
            $hits = array_values($this->mapper->map(
                $names,
                $workers,
                static function (string $name) use ($dns, $sources, $wildcardSet): HostHit {
                    $a = $dns->query($name, 'A');
                    $aaaa = $dns->query($name, 'AAAA');
                    $ips = Parsers::uniqueSorted(Parsers::onlyIpAddresses(array_merge($a, $aaaa)));
                    $cname = Parsers::uniqueSorted(array_merge(
                        $dns->query($name, 'CNAME'),
                        Parsers::onlyHostnames(array_merge($a, $aaaa)),
                    ));
                    $src = $sources[$name] ?? [];
                    sort($src);
                    $kind = self::classify($src, $ips, $cname, $wildcardSet);

                    return new HostHit($name, $ips, $cname, $src, $kind);
                },
            ));
        }

        usort(
            $hits,
            static fn (HostHit $a, HostHit $b): int => [$a->kind, $a->name] <=> [$b->kind, $b->name],
        );

        return $hits;
    }

    /**
     * @param list<string> $sources
     * @param list<string> $ips
     * @param list<string> $cname
     * @param array<string, true> $wildcardIps
     */
    private static function classify(array $sources, array $ips, array $cname, array $wildcardIps): string
    {
        if ($ips === [] && $cname === []) {
            return 'unresolved';
        }
        $keep = [...self::PASSIVE_SOURCES, 'apex', 'ptr', 'reverse-ip', 'mx', 'ns', 'soa'];
        foreach ($sources as $item) {
            if (in_array($item, $keep, true)) {
                return 'confirmed';
            }
        }
        $wildcardHit = $wildcardIps !== [] && $cname === [] && self::isSubsetStatic($ips, $wildcardIps);
        if ($wildcardHit) {
            return 'wildcard';
        }

        return 'confirmed';
    }

    private function recordHostname(string $rtype, string $answer): ?string
    {
        if (!in_array($rtype, ['MX', 'SOA', 'NS', 'CNAME', 'PTR'], true)) {
            return null;
        }
        $parts = preg_split('/\s+/', trim($answer)) ?: [];
        $token = strtolower(rtrim($parts !== [] ? (string) end($parts) : '', '.'));
        if ($token !== '' && !ctype_digit(str_replace('.', '', $token))) {
            return $token;
        }

        return null;
    }

    /**
     * @param list<string> $values
     * @return list<string>
     */
    private function cleanNames(array $values): array
    {
        $names = [];
        foreach ($values as $value) {
            $parts = preg_split('/\s+/', trim($value)) ?: [];
            $host = strtolower(rtrim($parts !== [] ? (string) end($parts) : '', '.'));
            if ($host !== '' && str_contains($host, '.') && !ctype_digit(str_replace('.', '', $host))) {
                $names[] = $host;
            }
        }

        return $names;
    }

    /**
     * @param list<string> $names
     * @return list<string>
     */
    private function baseDomains(array $names): array
    {
        $bases = [];
        foreach ($names as $name) {
            $parts = explode('.', $name);
            if (count($parts) >= 2) {
                $bases[implode('.', array_slice($parts, -2))] = true;
            }
        }
        $result = array_keys($bases);
        sort($result);

        return $result;
    }

    private function isIp(string $value): bool
    {
        return Parsers::isIpAddress($value);
    }

    /**
     * @param list<string> $answers
     * @param array<string, true> $wildcardSet
     */
    private static function isSubsetStatic(array $answers, array $wildcardSet): bool
    {
        foreach ($answers as $answer) {
            if (!isset($wildcardSet[$answer])) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return list<string>
     */
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
