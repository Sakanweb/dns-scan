<?php

declare(strict_types=1);

namespace App\Tests\Unit\Scan;

use App\Scan\Infrastructure\DigDnsClient;
use Codeception\Test\Unit;

use function PHPUnit\Framework\assertContains;
use function PHPUnit\Framework\assertNotContains;
use function PHPUnit\Framework\assertSame;

final class DigDnsClientTest extends Unit
{
    public function testQueryArgvPinsPublicResolver(): void
    {
        $argv = DigDnsClient::argv(['www.example.com', 'A']);

        assertSame('dig', $argv[0]);
        assertContains('@1.1.1.1', $argv);
        assertContains('www.example.com', $argv);
        assertContains('A', $argv);
        assertContains('+short', $argv);
    }

    public function testZoneTransferArgvKeepsTargetNameserverOnly(): void
    {
        $argv = DigDnsClient::argv(['@brett.ns.cloudflare.com', 'example.com', 'AXFR']);

        assertContains('@brett.ns.cloudflare.com', $argv);
        assertNotContains('@1.1.1.1', $argv);
    }
}
