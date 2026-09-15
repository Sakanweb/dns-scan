<?php

declare(strict_types=1);

namespace App\Scan\Persistence;

use App\Scan\Application\WorkerSwitchInterface;
use PDO;

final readonly class DbWorkerSwitch implements WorkerSwitchInterface
{
    public function __construct(
        private PDO $pdo,
    ) {
    }

    public function isOn(): bool
    {
        $stmt = $this->pdo->query('SELECT enabled FROM worker_control WHERE id = 1');
        if ($stmt === false) {
            return true;
        }
        $value = $stmt->fetchColumn();
        if ($value === false) {
            return true;
        }

        return (int) $value === 1;
    }

    public function setOn(bool $on): void
    {
        $stmt = $this->pdo->prepare('REPLACE INTO worker_control (id, enabled) VALUES (1, :enabled)');
        $stmt->execute(['enabled' => $on ? 1 : 0]);
    }
}
