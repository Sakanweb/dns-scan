<?php

declare(strict_types=1);

namespace App\Tests\Unit\Scan;

use App\Scan\Domain\TargetParser;
use Codeception\Test\Unit;
use InvalidArgumentException;

use function PHPUnit\Framework\assertFalse;
use function PHPUnit\Framework\assertSame;
use function PHPUnit\Framework\assertTrue;

final class TargetParserTest extends Unit
{
    public function testIpv4(): void
    {
        $target = TargetParser::parse('8.8.8.8');
        assertSame('ip', $target->kind);
        assertSame('8.8.8.8', $target->value);
    }

    public function testIpv6(): void
    {
        $target = TargetParser::parse('2001:4860:4860::8888');
        assertSame('ip', $target->kind);
        assertSame('2001:4860:4860::8888', $target->value);
    }

    public function testDomain(): void
    {
        $target = TargetParser::parse('Example.COM.');
        assertSame('domain', $target->kind);
        assertSame('example.com', $target->value);
    }

    public function testUrl(): void
    {
        $target = TargetParser::parse('https://www.Example.com/path?q=1');
        assertSame('domain', $target->kind);
        assertSame('www.example.com', $target->value);
    }

    public function testEmptyRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        TargetParser::parse('   ');
    }

    public function testAwsPtr(): void
    {
        assertTrue(TargetParser::isReverseDnsName('ec2-1-2-3-4.compute-1.amazonaws.com'));
    }

    public function testArpa(): void
    {
        assertTrue(TargetParser::isReverseDnsName('4.3.2.1.in-addr.arpa'));
    }

    public function testNormalDomain(): void
    {
        assertFalse(TargetParser::isReverseDnsName('mail.example.com'));
    }
}
