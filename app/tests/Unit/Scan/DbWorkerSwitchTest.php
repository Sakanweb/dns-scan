<?php

declare(strict_types=1);

namespace App\Tests\Unit\Scan;

use App\Scan\Persistence\DbWorkerSwitch;
use Codeception\Test\Unit;
use PDO;

use function PHPUnit\Framework\assertFalse;
use function PHPUnit\Framework\assertTrue;

final class DbWorkerSwitchTest extends Unit
{
    public function testMissingRowDefaultsToOn(): void
    {
        assertTrue($this->switch()->isOn());
    }

    public function testSetOffThenOn(): void
    {
        $switch = $this->switch();

        $switch->setOn(false);
        assertFalse($switch->isOn());

        $switch->setOn(true);
        assertTrue($switch->isOn());
    }

    public function testSetOffTwiceStaysOff(): void
    {
        $switch = $this->switch();
        $switch->setOn(false);
        $switch->setOn(false);

        assertFalse($switch->isOn());
    }

    private function switch(): DbWorkerSwitch
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec('CREATE TABLE worker_control (id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1)');

        return new DbWorkerSwitch($pdo);
    }
}
