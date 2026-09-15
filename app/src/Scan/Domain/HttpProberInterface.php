<?php

declare(strict_types=1);

namespace App\Scan\Domain;

interface HttpProberInterface
{
    public function probe(string $host): HttpCheck;
}
