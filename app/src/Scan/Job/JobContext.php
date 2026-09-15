<?php

declare(strict_types=1);

namespace App\Scan\Job;

use App\Scan\Domain\DnsRecord;
use App\Scan\Domain\HostHit;
use App\Scan\Domain\HttpCheck;
use App\Scan\Domain\ScanResult;
use App\Scan\Domain\Target;
use App\Scan\Domain\TargetParser;

/**
 * Mutable working state for one scan job. Persisted as JSON between worker ticks.
 */
final class JobContext
{
    /**
     * @param array<string, list<string>> $sources
     * @param list<array{name: string, rtype: string, value: string}> $records
     * @param list<string> $notes
     * @param list<string> $wildcardIps
     * @param list<string> $domains
     * @param list<string> $wordlist
     * @param list<array<string, mixed>> $hosts
     * @param list<string> $ips
     * @param list<string> $names
     */
    public function __construct(
        public string $targetRaw,
        public string $targetKind,
        public string $targetValue,
        public array $sources = [],
        public array $records = [],
        public array $notes = [],
        public array $wildcardIps = [],
        public array $domains = [],
        public array $wordlist = [],
        public array $hosts = [],
        public array $ips = [],
        public array $names = [],
    ) {
    }

    public static function fromTarget(Target $target, array $wordlist): self
    {
        return new self(
            targetRaw: $target->raw,
            targetKind: $target->kind,
            targetValue: $target->value,
            wordlist: $wordlist,
            domains: $target->kind === 'domain' ? [$target->value] : [],
        );
    }

    public function target(): Target
    {
        return TargetParser::parse($this->targetRaw !== '' ? $this->targetRaw : $this->targetValue);
    }

    public function addSource(string $name, string $source): void
    {
        $name = strtolower(rtrim(trim($name), '.'));
        if ($name === '') {
            return;
        }
        if (!isset($this->sources[$name])) {
            $this->sources[$name] = [];
        }
        if (!in_array($source, $this->sources[$name], true)) {
            $this->sources[$name][] = $source;
        }
    }

    public function addRecord(string $name, string $rtype, string $value): void
    {
        $this->records[] = [
            'name' => $name,
            'rtype' => $rtype,
            'value' => $value,
        ];
    }

    public function addNote(string $note): void
    {
        $this->notes[] = $note;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'target_raw' => $this->targetRaw,
            'target_kind' => $this->targetKind,
            'target_value' => $this->targetValue,
            'sources' => $this->sources,
            'records' => $this->records,
            'notes' => $this->notes,
            'wildcard_ips' => $this->wildcardIps,
            'domains' => $this->domains,
            'wordlist' => $this->wordlist,
            'hosts' => $this->hosts,
            'ips' => $this->ips,
            'names' => $this->names,
        ];
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        return new self(
            targetRaw: (string) ($data['target_raw'] ?? ''),
            targetKind: (string) ($data['target_kind'] ?? 'domain'),
            targetValue: (string) ($data['target_value'] ?? ''),
            sources: is_array($data['sources'] ?? null) ? $data['sources'] : [],
            records: is_array($data['records'] ?? null) ? $data['records'] : [],
            notes: is_array($data['notes'] ?? null) ? array_values($data['notes']) : [],
            wildcardIps: is_array($data['wildcard_ips'] ?? null) ? array_values($data['wildcard_ips']) : [],
            domains: is_array($data['domains'] ?? null) ? array_values($data['domains']) : [],
            wordlist: is_array($data['wordlist'] ?? null) ? array_values($data['wordlist']) : [],
            hosts: is_array($data['hosts'] ?? null) ? array_values($data['hosts']) : [],
            ips: is_array($data['ips'] ?? null) ? array_values($data['ips']) : [],
            names: is_array($data['names'] ?? null) ? array_values($data['names']) : [],
        );
    }

    public function toScanResult(): ScanResult
    {
        $hosts = [];
        foreach ($this->hosts as $row) {
            $http = null;
            if (isset($row['http']) && is_array($row['http'])) {
                $h = $row['http'];
                $http = new HttpCheck(
                    works: (bool) ($h['works'] ?? false),
                    status: isset($h['status']) ? (int) $h['status'] : null,
                    title: (string) ($h['title'] ?? ''),
                    finalUrl: (string) ($h['final_url'] ?? ''),
                    tlsOk: (bool) ($h['tls_ok'] ?? false),
                    defaultPage: (bool) ($h['default_page'] ?? false),
                    error: (string) ($h['error'] ?? ''),
                    bodyLen: (int) ($h['body_len'] ?? 0),
                );
            }
            $hit = new HostHit(
                name: (string) $row['name'],
                ips: array_values($row['ips'] ?? []),
                cname: array_values($row['cname'] ?? []),
                sources: array_values($row['sources'] ?? []),
                kind: (string) ($row['kind'] ?? 'unresolved'),
            );
            $hit->http = $http;
            $hosts[] = $hit;
        }

        $records = [];
        foreach ($this->records as $row) {
            $records[] = new DnsRecord(
                (string) $row['name'],
                (string) $row['rtype'],
                (string) $row['value'],
            );
        }

        return new ScanResult(
            target: $this->target(),
            ips: $this->ips,
            names: $this->names,
            records: $records,
            notes: $this->notes,
            hosts: $hosts,
            wildcardIps: $this->wildcardIps,
        );
    }

    public static function hostToArray(HostHit $host): array
    {
        $http = null;
        if ($host->http !== null) {
            $http = [
                'works' => $host->http->works,
                'status' => $host->http->status,
                'title' => $host->http->title,
                'tls_ok' => $host->http->tlsOk,
                'default_page' => $host->http->defaultPage,
                'error' => $host->http->error,
                'final_url' => $host->http->finalUrl,
                'body_len' => $host->http->bodyLen,
            ];
        }

        return [
            'name' => $host->name,
            'ips' => $host->ips,
            'cname' => $host->cname,
            'sources' => $host->sources,
            'kind' => $host->kind,
            'http' => $http,
        ];
    }
}
