<?php

declare(strict_types=1);

use App\Console;

return [
    'hello' => Console\HelloCommand::class,
    'migrate' => Console\MigrateCommand::class,
    'scan:run' => Console\ScanCommand::class,
    'scan:worker' => Console\ScanWorkerCommand::class,
];
