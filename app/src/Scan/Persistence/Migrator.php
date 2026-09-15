<?php

declare(strict_types=1);

namespace App\Scan\Persistence;

use PDO;

/**
 * Applies one SQL file per version. Never bundles multiple CREATE TABLE in one migration.
 */
final class Migrator
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly string $migrationsDir,
    ) {
    }

    /** @return list<string> applied version filenames */
    public function migrate(): array
    {
        $this->ensureMigrationsTable();
        $applied = $this->appliedVersions();
        $done = [];

        foreach ($this->migrationFiles() as $file) {
            $version = $file->getFilename();
            if (isset($applied[$version])) {
                continue;
            }

            $sql = file_get_contents($file->getPathname());
            if ($sql === false || trim($sql) === '') {
                throw new \RuntimeException("Empty migration: {$version}");
            }

            try {
                // MariaDB DDL auto-commits; do not wrap CREATE TABLE in a transaction.
                $this->pdo->exec($sql);
                $stmt = $this->pdo->prepare(
                    'INSERT INTO schema_migrations (version) VALUES (:version)',
                );
                $stmt->execute(['version' => $version]);
                $done[] = $version;
            } catch (\Throwable $e) {
                throw new \RuntimeException("Migration failed: {$version}: {$e->getMessage()}", 0, $e);
            }
        }

        return $done;
    }

    private function ensureMigrationsTable(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS schema_migrations (
                version VARCHAR(64) NOT NULL PRIMARY KEY,
                applied_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci',
        );
    }

    /** @return array<string, true> */
    private function appliedVersions(): array
    {
        $stmt = $this->pdo->query('SELECT version FROM schema_migrations');
        if ($stmt === false) {
            return [];
        }
        $map = [];
        foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $version) {
            $map[(string) $version] = true;
        }

        return $map;
    }

    /** @return list<\SplFileInfo> */
    private function migrationFiles(): array
    {
        if (!is_dir($this->migrationsDir)) {
            throw new \RuntimeException("Migrations dir missing: {$this->migrationsDir}");
        }

        $files = [];
        foreach (scandir($this->migrationsDir) ?: [] as $name) {
            if (!str_ends_with($name, '.sql')) {
                continue;
            }
            // 001 is applied via ensureMigrationsTable + record below if needed
            $files[] = new \SplFileInfo($this->migrationsDir . '/' . $name);
        }

        usort(
            $files,
            static fn (\SplFileInfo $a, \SplFileInfo $b): int => strcmp($a->getFilename(), $b->getFilename()),
        );

        return $files;
    }
}
