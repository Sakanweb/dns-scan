<?php

declare(strict_types=1);

namespace App\Web\Scan\History;

use App\Scan\Application\ScanService;
use App\Scan\Persistence\ScanRepository;
use Psr\Http\Message\ResponseInterface;
use Yiisoft\Yii\View\Renderer\WebViewRenderer;

final readonly class Action
{
    public function __construct(
        private WebViewRenderer $viewRenderer,
        private ScanRepository $repository,
        private ScanService $scanService,
    ) {
    }

    public function __invoke(): ResponseInterface
    {
        return $this->viewRenderer->render(__DIR__ . '/template', [
            'runs' => $this->repository->listRuns(100),
            'workerOn' => $this->scanService->isWorkerOn(),
        ]);
    }
}
