<?php

declare(strict_types=1);

use App\Web;
use Yiisoft\Router\Group;
use Yiisoft\Router\Route;

return [
    Group::create()
        ->routes(
            Route::get('/')
                ->action(Web\HomePage\Action::class)
                ->name('home'),
            Route::get('/scans')
                ->action(Web\Scan\History\Action::class)
                ->name('scan/history'),
            Route::get('/scans/{id:\d+}')
                ->action(Web\Scan\Show\Action::class)
                ->name('scan/show'),
            Route::post('/scans')
                ->action(Web\Scan\Create\Action::class)
                ->name('scan/create'),
            Route::post('/scans/worker')
                ->action(Web\Scan\ToggleWorker\Action::class)
                ->name('scan/worker-toggle'),
        ),
];
