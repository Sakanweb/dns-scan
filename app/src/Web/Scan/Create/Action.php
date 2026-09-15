<?php

declare(strict_types=1);

namespace App\Web\Scan\Create;

use App\Scan\Application\ScanService;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Yiisoft\Http\Header;
use Yiisoft\Http\Method;
use Yiisoft\Http\Status;
use Yiisoft\Router\UrlGeneratorInterface;

final readonly class Action
{
    public function __construct(
        private ScanService $scanService,
        private ResponseFactoryInterface $responseFactory,
        private UrlGeneratorInterface $urlGenerator,
    ) {
    }

    public function __invoke(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() !== Method::POST) {
            return $this->redirect('scan/history');
        }

        $body = $request->getParsedBody();
        $target = is_array($body) ? trim((string) ($body['target'] ?? '')) : '';
        if ($target === '') {
            return $this->redirect('scan/history');
        }

        $runId = $this->scanService->enqueue($target);

        return $this->redirect('scan/show', ['id' => $runId]);
    }

    /**
     * @param array<string, scalar> $params
     */
    private function redirect(string $name, array $params = []): ResponseInterface
    {
        return $this->responseFactory
            ->createResponse(Status::FOUND)
            ->withHeader(Header::LOCATION, $this->urlGenerator->generate($name, $params));
    }
}
