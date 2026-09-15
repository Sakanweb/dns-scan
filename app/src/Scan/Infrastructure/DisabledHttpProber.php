<?php

declare(strict_types=1);

namespace App\Scan\Infrastructure;

use App\Scan\Domain\HttpCheck;
use App\Scan\Domain\HttpProberInterface;

final class DisabledHttpProber implements HttpProberInterface
{
    public function probe(string $host): HttpCheck
    {
        return new HttpCheck(false, null, '', '', false, false, 'skipped', 0);
    }
}
