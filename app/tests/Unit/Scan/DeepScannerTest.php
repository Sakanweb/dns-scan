<?php

declare(strict_types=1);

namespace App\Tests\Unit\Scan;

use App\Scan\Application\DeepScanner;
use App\Scan\Application\ScanSettings;
use App\Scan\Domain\DnsClientInterface;
use App\Scan\Domain\HttpCheck;
use App\Scan\Domain\HttpProberInterface;
use App\Scan\Domain\TargetParser;
use App\Scan\Domain\WebClientInterface;
use App\Scan\Infrastructure\ConcurrentMapper;
use Codeception\Test\Unit;

use function PHPUnit\Framework\assertContains;
use function PHPUnit\Framework\assertFalse;
use function PHPUnit\Framework\assertNotContains;
use function PHPUnit\Framework\assertSame;
use function PHPUnit\Framework\assertTrue;

final class DeepScannerTest extends Unit
{
    public function testCollectsDnsCtAndLiveSubdomains(): void
    {
        $dns = new FakeDns([
            'example.com|A' => ['1.2.3.4'],
            'example.com|AAAA' => [],
            'example.com|MX' => ['10 mail.example.com'],
            'example.com|NS' => ['ns1.example.com'],
            'example.com|TXT' => ['v=spf1 -all'],
            'example.com|CNAME' => [],
            'example.com|SOA' => ['ns1.example.com hostmaster.example.com'],
            '1.2.3.4|PTR' => ['example.com'],
            'www.example.com|A' => ['1.2.3.4'],
            'mail.example.com|A' => ['1.2.3.4'],
            'ns1.example.com|A' => ['1.2.3.5'],
        ]);
        $web = new FakeWeb(
            crt: ['example.com' => ['www.example.com', 'api.example.com']],
            reverseIp: ['1.2.3.4' => ['shop.example.com']],
        );

        $result = $this->scanner($dns, $web)->scan(TargetParser::parse('example.com'));

        assertContains('1.2.3.4', $result->ips);
        assertContains('www.example.com', $result->names);
        assertContains('mail.example.com', $result->names);
        assertContains('shop.example.com', $result->names);
        assertNotContains('ghost.example.com', $result->names);
    }

    public function testUsesPtrAndReverseIp(): void
    {
        $dns = new FakeDns([
            '9.9.9.9|PTR' => ['dns.quad9.net'],
        ]);
        $web = new FakeWeb(reverseIp: ['9.9.9.9' => ['quad9.net']]);

        $result = $this->scanner(
            $dns,
            $web,
            new ScanSettings(
                dnsThreads: 2,
                probeHttp: false,
                usePassive: false,
                useReverseIp: true,
                tryAxfr: false,
                wordlistPath: '',
            ),
            wordlist: [],
        )->scan(TargetParser::parse('9.9.9.9'));

        assertSame(['9.9.9.9'], $result->ips);
        assertContains('dns.quad9.net', $result->names);
        assertContains('quad9.net', $result->names);
    }

    public function testDropsWordlistCatchAllKeepsCertificateName(): void
    {
        $dns = new CatchAllDns([
            'example.com|A' => ['9.9.9.9'],
            'example.com|NS' => ['ns1.cloudflare.com'],
        ]);
        $web = new FakeWeb(crt: ['example.com' => ['trainings.example.com']]);

        $result = $this->scanner(
            $dns,
            $web,
            new ScanSettings(
                dnsThreads: 4,
                probeHttp: false,
                usePassive: true,
                useReverseIp: false,
                tryAxfr: false,
                wordlistPath: '',
            ),
            wordlist: ['admin', 'ghost'],
        )->scan(TargetParser::parse('example.com'));

        assertContains('trainings.example.com', $result->names);
        assertNotContains('admin.example.com', $result->names);
        assertNotContains('ghost.example.com', $result->names);
        assertSame(['9.9.9.9'], $result->wildcardIps);
    }

    public function testDoesNotAddPrefixMutationsThatOnlyHitWildcard(): void
    {
        $dns = new CatchAllDns([
            'example.com|A' => ['9.9.9.9'],
            'example.com|NS' => ['ns1.cloudflare.com'],
            'n8n.example.com|A' => ['9.9.9.9'],
        ]);
        $web = new FakeWeb(crt: ['example.com' => ['n8n.example.com']]);

        $result = $this->scanner(
            $dns,
            $web,
            new ScanSettings(
                dnsThreads: 8,
                probeHttp: false,
                usePassive: true,
                useReverseIp: false,
                tryAxfr: false,
                wordlistPath: '',
            ),
            wordlist: [],
        )->scan(TargetParser::parse('example.com'));

        assertContains('n8n.example.com', $result->names);
        assertNotContains('mail.n8n.example.com', $result->names);
        assertNotContains('admin.n8n.example.com', $result->names);
    }

    public function testKeepsPrefixMutationWhenIpDiffersFromWildcard(): void
    {
        $dns = new CatchAllDns([
            'example.com|A' => ['9.9.9.9'],
            'example.com|NS' => ['ns1.cloudflare.com'],
            'n8n.example.com|A' => ['9.9.9.9'],
            'mail.n8n.example.com|A' => ['1.2.3.4'],
        ]);
        $web = new FakeWeb(crt: ['example.com' => ['n8n.example.com']]);

        $result = $this->scanner(
            $dns,
            $web,
            new ScanSettings(
                dnsThreads: 8,
                probeHttp: false,
                usePassive: true,
                useReverseIp: false,
                tryAxfr: false,
                wordlistPath: '',
            ),
            wordlist: [],
        )->scan(TargetParser::parse('example.com'));

        assertContains('mail.n8n.example.com', $result->names);
    }

    public function testMarksWorkingAndDefaultPages(): void
    {
        $dns = new FakeDns([
            'example.com|A' => ['1.2.3.4'],
            'www.example.com|A' => ['1.2.3.4'],
        ]);
        $web = new FakeWeb(crt: ['example.com' => ['www.example.com']]);
        $http = new FakeHttp();

        $result = $this->scanner(
            $dns,
            $web,
            new ScanSettings(
                dnsThreads: 2,
                probeHttp: true,
                usePassive: true,
                useReverseIp: false,
                tryAxfr: false,
                wordlistPath: '',
            ),
            http: $http,
            wordlist: ['www'],
        )->scan(TargetParser::parse('example.com'));

        $www = null;
        $apex = null;
        foreach ($result->hosts as $host) {
            if ($host->name === 'www.example.com') {
                $www = $host;
            }
            if ($host->name === 'example.com') {
                $apex = $host;
            }
        }

        assertTrue($www?->http?->works ?? false);
        assertTrue($apex?->http?->defaultPage ?? false);
        assertFalse($apex?->http?->works ?? true);
    }

    /**
     * @param list<string> $wordlist
     */
    private function scanner(
        DnsClientInterface $dns,
        WebClientInterface $web,
        ?ScanSettings $settings = null,
        ?HttpProberInterface $http = null,
        array $wordlist = ['www', 'mail', 'ghost'],
    ): DeepScanner {
        $settings ??= new ScanSettings(
            dnsThreads: 4,
            probeHttp: false,
            usePassive: true,
            useReverseIp: true,
            tryAxfr: false,
            wordlistPath: '',
        );

        $path = sys_get_temp_dir() . '/dns-scan-wordlist-' . uniqid('', true) . '.txt';
        file_put_contents($path, implode("\n", $wordlist) . "\n");
        $settings = new ScanSettings(
            dnsThreads: $settings->dnsThreads,
            httpTimeout: $settings->httpTimeout,
            dnsTimeout: $settings->dnsTimeout,
            probeHttp: $settings->probeHttp,
            usePassive: $settings->usePassive,
            useReverseIp: $settings->useReverseIp,
            tryAxfr: $settings->tryAxfr,
            wordlistPath: $path,
        );

        return new DeepScanner(
            $dns,
            $web,
            $http ?? new class () implements HttpProberInterface {
                public function probe(string $host): HttpCheck
                {
                    return new HttpCheck(false, null, '', '', false, false, 'skipped', 0);
                }
            },
            new ConcurrentMapper(),
            $settings,
        );
    }
}

class FakeDns implements DnsClientInterface
{
    /** @var array<string, list<string>> */
    private array $table;

    /**
     * @param array<string, list<string>> $table
     */
    public function __construct(array $table)
    {
        $this->table = [];
        foreach ($table as $key => $values) {
            $this->table[strtolower((string) $key)] = $values;
        }
    }

    public function query(string $name, string $rtype): array
    {
        $key = strtolower($name) . '|' . strtoupper($rtype);

        return $this->table[strtolower($key)] ?? [];
    }

    public function reverse(string $ip): array
    {
        return $this->table[strtolower($ip . '|PTR')] ?? [];
    }

    public function zoneTransfer(string $nameserver, string $zone): array
    {
        return [];
    }
}

final class CatchAllDns extends FakeDns
{
    public function query(string $name, string $rtype): array
    {
        $known = parent::query($name, $rtype);
        if ($known !== []) {
            return $known;
        }
        if (strtoupper($rtype) === 'A' && str_ends_with(strtolower($name), '.example.com')) {
            return ['9.9.9.9'];
        }

        return [];
    }
}

final class FakeWeb implements WebClientInterface
{
    /**
     * @param array<string, list<string>> $crt
     * @param array<string, list<string>> $reverseIp
     * @param array<string, list<string>> $certspotter
     * @param array<string, list<string>> $wayback
     * @param array<string, list<string>> $hostsearch
     */
    public function __construct(
        private array $crt = [],
        private array $reverseIp = [],
        private array $certspotter = [],
        private array $wayback = [],
        private array $hostsearch = [],
    ) {
    }

    public function certificateNames(string $domain): array
    {
        return $this->crt[$domain] ?? [];
    }

    public function certspotterNames(string $domain): array
    {
        return $this->certspotter[$domain] ?? [];
    }

    public function waybackNames(string $domain): array
    {
        return $this->wayback[$domain] ?? [];
    }

    public function hostsearchNames(string $domain): array
    {
        return $this->hostsearch[$domain] ?? [];
    }

    public function reverseIpNames(string $ip): array
    {
        return $this->reverseIp[$ip] ?? [];
    }
}

final class FakeHttp implements HttpProberInterface
{
    public function probe(string $host): HttpCheck
    {
        if ($host === 'www.example.com') {
            return new HttpCheck(true, 200, 'Shop', 'https://www.example.com/', true, false, '', 1200);
        }

        return new HttpCheck(false, 200, "Web Server's Default Page", 'http://x/', false, true, '', 100);
    }
}
