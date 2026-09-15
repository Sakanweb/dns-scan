<?php

declare(strict_types=1);

namespace App\Scan\Job;

/**
 * Ordered pipeline stages. Worker advances exactly one stage per tick.
 */
enum ScanStage: string
{
    case Queued = 'queued';
    case DnsBase = 'dns_base';
    case Passive = 'passive';
    case Wordlist = 'wordlist';
    case Resolve = 'resolve';
    case HttpProbe = 'http_probe';
    case Finalize = 'finalize';
    case Done = 'done';
    case Failed = 'failed';

    /** @return list<self> */
    public static function pipeline(bool $probeHttp, bool $usePassive): array
    {
        $steps = [self::DnsBase];
        if ($usePassive) {
            $steps[] = self::Passive;
        }
        $steps[] = self::Wordlist;
        $steps[] = self::Resolve;
        if ($probeHttp) {
            $steps[] = self::HttpProbe;
        }
        $steps[] = self::Finalize;

        return $steps;
    }

    public function label(): string
    {
        return match ($this) {
            self::Queued => 'queued',
            self::DnsBase => 'DNS base + wildcard',
            self::Passive => 'passive sources (certs/archives)',
            self::Wordlist => 'wordlist + mutations',
            self::Resolve => 'resolve hosts',
            self::HttpProbe => 'HTTP probe',
            self::Finalize => 'persist results',
            self::Done => 'done',
            self::Failed => 'failed',
        };
    }
}
