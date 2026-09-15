<?php

declare(strict_types=1);

namespace App\Tests\Unit\Scan;

use App\Scan\Domain\Parsers;
use Codeception\Test\Unit;

use function PHPUnit\Framework\assertFalse;
use function PHPUnit\Framework\assertSame;
use function PHPUnit\Framework\assertTrue;

final class ParsersTest extends Unit
{
    public function testParseDigShortSplitsAndStripsDots(): void
    {
        $raw = "ns1.example.com.\nns2.example.com.\n0 .\n";
        assertSame(
            ['ns1.example.com', 'ns2.example.com', '0 .'],
            Parsers::parseDigShort($raw),
        );
    }

    public function testParseDigShortIgnoresEmptyAndComments(): void
    {
        $raw = "\n; bad\n1.2.3.4\n";
        assertSame(['1.2.3.4'], Parsers::parseDigShort($raw));
    }

    public function testOnlyIpAddressesDropsCnameChainHosts(): void
    {
        assertSame(
            ['192.0.2.10', '2001:db8::1'],
            Parsers::onlyIpAddresses([
                'alias.example.com',
                '192.0.2.10',
                '2001:db8::1',
                'other.example.net',
            ]),
        );
        assertTrue(Parsers::isIpAddress('1.2.3.4'));
        assertFalse(Parsers::isIpAddress('www.example.com'));
    }

    public function testExtractCrtshNamesSplitsAndDropsWildcards(): void
    {
        $payload = [
            ['name_value' => "*.example.com\nwww.example.com"],
            ['name_value' => 'api.example.com'],
        ];
        assertSame(
            ['api.example.com', 'example.com', 'www.example.com'],
            Parsers::extractCrtshNames($payload, 'example.com'),
        );
    }

    public function testExtractCrtshNamesKeepsOnlyUnderBase(): void
    {
        $payload = [['name_value' => "evil.com\nshop.example.com"]];
        assertSame(
            ['shop.example.com'],
            Parsers::extractCrtshNames($payload, 'example.com'),
        );
    }

    public function testParseReverseIpBody(): void
    {
        assertSame(
            ['a.example.com', 'b.example.com'],
            Parsers::parseReverseIpBody("a.example.com\nb.example.com\n"),
        );
        assertSame([], Parsers::parseReverseIpBody('error invalid ip address'));
    }

    public function testUniqueSorted(): void
    {
        assertSame(
            ['mail.example.com', 'www.example.com'],
            Parsers::uniqueSorted(['WWW.Example.com.', 'www.example.com', 'mail.example.com']),
        );
    }

    public function testExtractCertspotterNames(): void
    {
        $payload = [['dns_names' => ['*.example.com', 'trainings.example.com', 'evil.com']]];
        assertSame(
            ['example.com', 'trainings.example.com'],
            Parsers::extractCertspotterNames($payload, 'example.com'),
        );
    }

    public function testExtractWaybackHosts(): void
    {
        $payload = [
            ['original'],
            ['http://companytaxi.example.com/login'],
            ['https://www.example.com/'],
        ];
        assertSame(
            ['companytaxi.example.com', 'www.example.com'],
            Parsers::extractWaybackHosts($payload, 'example.com'),
        );
    }

    public function testParseHostsearchBody(): void
    {
        $body = "portal.example.com,1.2.3.4\nother.net,9.9.9.9\n";
        assertSame(['portal.example.com'], Parsers::parseHostsearchBody($body, 'example.com'));
    }

    public function testHtmlTitleAndDefaultPage(): void
    {
        $body = "<html><title>Web Server's Default Page</title><p>Plesk International GmbH</p></html>";
        assertSame("Web Server's Default Page", Parsers::htmlTitle($body));
        assertTrue(Parsers::isDefaultPage(Parsers::htmlTitle($body), $body));
        assertFalse(Parsers::isDefaultPage('Welcome', '<h1>Welcome</h1>'));
    }
}
