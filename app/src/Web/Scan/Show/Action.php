<?php

declare(strict_types=1);

namespace App\Web\Scan\Show;

use App\Scan\Application\ScanService;
use App\Scan\Persistence\ScanRepository;
use Psr\Http\Message\ResponseInterface;
use Yiisoft\Http\Status;
use Yiisoft\Router\HydratorAttribute\RouteArgument;
use Yiisoft\Yii\View\Renderer\WebViewRenderer;

final readonly class Action
{
    public function __construct(
        private WebViewRenderer $viewRenderer,
        private ScanRepository $repository,
        private ScanService $scanService,
    ) {
    }

    public function __invoke(#[RouteArgument('id')] int $id): ResponseInterface
    {
        $workerOn = $this->scanService->isWorkerOn();
        $run = $this->repository->findRun($id);
        if ($run === null) {
            return $this->viewRenderer
                ->render(__DIR__ . '/../History/template', [
                    'runs' => $this->repository->listRuns(100),
                    'error' => "Scan #{$id} not found",
                    'workerOn' => $workerOn,
                ])
                ->withStatus(Status::NOT_FOUND);
        }

        return $this->viewRenderer->render(__DIR__ . '/template', [
            'run' => $run,
            'workerOn' => $workerOn,
        ]);
    }
}
