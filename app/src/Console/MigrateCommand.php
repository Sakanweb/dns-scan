<?php

declare(strict_types=1);

namespace App\Console;

use App\Scan\Persistence\Migrator;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Yiisoft\Yii\Console\ExitCode;

#[AsCommand(name: 'migrate', description: 'Apply pending SQL migrations (one file = one change)')]
final class MigrateCommand extends Command
{
    public function __construct(
        private readonly Migrator $migrator,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $applied = $this->migrator->migrate();
        if ($applied === []) {
            $output->writeln('<comment>No pending migrations</comment>');

            return ExitCode::OK;
        }

        foreach ($applied as $version) {
            $output->writeln("<info>Applied {$version}</info>");
        }

        return ExitCode::OK;
    }
}
