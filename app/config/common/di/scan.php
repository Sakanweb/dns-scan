<?php

declare(strict_types=1);

use App\Scan\Application\ScanSettings;
use App\Scan\Application\WorkerSwitchInterface;
use App\Scan\Domain\DnsClientInterface;
use App\Scan\Domain\HttpProberInterface;
use App\Scan\Domain\WebClientInterface;
use App\Scan\Infrastructure\ConcurrentMapper;
use App\Scan\Infrastructure\CurlHttpProber;
use App\Scan\Infrastructure\DigDnsClient;
use App\Scan\Infrastructure\PublicWebClient;
use App\Scan\Job\ScanJobProcessor;
use App\Scan\Persistence\DbWorkerSwitch;
use App\Scan\Persistence\Migrator;
use App\Scan\Persistence\PdoFactory;
use App\Scan\Persistence\ScanRepository;
use Yiisoft\Definitions\Reference;

/** @var array $params */

$dnsThreads = max(1, (int) (getenv('DNS_THREADS') ?: 40));
$httpTimeout = max(1, (int) (getenv('HTTP_TIMEOUT') ?: 10));
$dnsTimeout = max(1, (int) (getenv('DNS_TIMEOUT') ?: 3));
$dnsResolver = (string) (getenv('DNS_RESOLVER') ?: '1.1.1.1');

$appRoot = dirname(__DIR__, 3);
$wordlistPath = $appRoot . '/resources/wordlist.txt';
$migrationsDir = $appRoot . '/migrations';

return [
    ScanSettings::class => [
        'class' => ScanSettings::class,
        '__construct()' => [
            'dnsThreads' => $dnsThreads,
            'httpTimeout' => $httpTimeout,
            'dnsTimeout' => $dnsTimeout,
            'probeHttp' => true,
            'usePassive' => true,
            'useReverseIp' => true,
            'tryAxfr' => true,
            'wordlistPath' => $wordlistPath,
        ],
    ],

    DnsClientInterface::class => DigDnsClient::class,
    DigDnsClient::class => [
        'class' => DigDnsClient::class,
        '__construct()' => [
            'timeoutSec' => $dnsTimeout,
            'resolver' => $dnsResolver,
        ],
    ],

    WebClientInterface::class => PublicWebClient::class,

    HttpProberInterface::class => CurlHttpProber::class,
    CurlHttpProber::class => [
        'class' => CurlHttpProber::class,
        '__construct()' => [
            'timeout' => $httpTimeout,
        ],
    ],

    ConcurrentMapper::class => ConcurrentMapper::class,

    \PDO::class => static fn (): \PDO => PdoFactory::createFromEnv(),

    Migrator::class => [
        'class' => Migrator::class,
        '__construct()' => [
            'pdo' => Reference::to(\PDO::class),
            'migrationsDir' => $migrationsDir,
        ],
    ],

    ScanRepository::class => [
        'class' => ScanRepository::class,
        '__construct()' => [
            'pdo' => Reference::to(\PDO::class),
        ],
    ],

    ScanJobProcessor::class => ScanJobProcessor::class,

    WorkerSwitchInterface::class => DbWorkerSwitch::class,
    DbWorkerSwitch::class => [
        'class' => DbWorkerSwitch::class,
        '__construct()' => [
            'pdo' => Reference::to(\PDO::class),
        ],
    ],
];
