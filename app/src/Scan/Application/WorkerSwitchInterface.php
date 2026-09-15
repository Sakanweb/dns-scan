<?php

declare(strict_types=1);

namespace App\Scan\Application;

interface WorkerSwitchInterface
{
    public function isOn(): bool;

    public function setOn(bool $on): void;
}
