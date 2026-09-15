<?php

declare(strict_types=1);

namespace App\Scan\Persistence;

use PDO;
use RuntimeException;

final class PdoFactory
{
    public static function createFromEnv(): PDO
    {
        $dsn = getenv('DB_DSN') ?: '';
        if ($dsn === '') {
            throw new RuntimeException('DB_DSN is not set');
        }

        $user = getenv('DB_USER') !== false ? (string) getenv('DB_USER') : '';
        $password = getenv('DB_PASSWORD') !== false ? (string) getenv('DB_PASSWORD') : '';

        $pdo = new PDO($dsn, $user, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);

        return $pdo;
    }
}
