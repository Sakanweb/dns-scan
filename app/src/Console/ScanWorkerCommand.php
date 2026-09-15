<?php

declare(strict_types=1);

namespace App\Console;

use App\Scan\Application\ScanService;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Yiisoft\Yii\Console\ExitCode;

#[AsCommand(
    name: 'scan:worker',
    description: 'Process scan jobs one pipeline stage at a time',
)]
final class ScanWorkerCommand extends Command
{
    public function __construct(
        private readonly ScanService $scanService,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('loop', null, InputOption::VALUE_NONE, 'Keep polling forever')
            ->addOption('sleep', null, InputOption::VALUE_REQUIRED, 'Seconds between polls', '2')
            ->addOption('once', null, InputOption::VALUE_NONE, 'Process at most one stage and exit');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $loop = (bool) $input->getOption('loop');
        $once = (bool) $input->getOption('once') || !$loop;
        $sleep = max(1, (int) $input->getOption('sleep'));

        $output->writeln('<info>scan worker started (one stage per tick)</info>');
        $paused = false;

        do {
            if (!$this->scanService->isWorkerOn()) {
                if (!$paused) {
                    $output->writeln('<comment>worker paused</comment>');
                    $paused = true;
                }
                if (!$loop) {
                    return ExitCode::OK;
                }
                sleep($sleep);
                continue;
            }
            if ($paused) {
                $output->writeln('<info>worker resumed</info>');
                $paused = false;
            }

            try {
                $step = $this->scanService->processNext();
                if ($step !== null) {
                    $output->writeln(sprintf(
                        '<info>run #%d stage=%s status=%s</info>',
                        $step['runId'],
                        $step['stage'],
                        $step['status'],
                    ));
                    if ($once && !$loop) {
                        return ExitCode::OK;
                    }
                    continue;
                }
            } catch (\Throwable $e) {
                $output->writeln('<error>' . $e->getMessage() . '</error>');
            }

            if (!$loop) {
                $output->writeln('<comment>queue empty</comment>');

                return ExitCode::OK;
            }

            sleep($sleep);
        } while ($loop);

        return ExitCode::OK;
    }
}
