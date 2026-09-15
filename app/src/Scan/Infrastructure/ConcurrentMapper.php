<?php

declare(strict_types=1);

namespace App\Scan\Infrastructure;

use Amp\Sync\LocalSemaphore;
use function Amp\async;
use function Amp\Future\await;

final class ConcurrentMapper
{
    /**
     * @template TKey of array-key
     * @template TIn
     * @template TOut
     * @param array<TKey, TIn> $items
     * @param callable(TIn): TOut $fn
     * @return array<TKey, TOut>
     */
    public function map(array $items, int $workers, callable $fn): array
    {
        if ($items === []) {
            return [];
        }

        $workers = max(1, $workers);

        if (!function_exists('Amp\\async') || !function_exists('Amp\\Future\\await')) {
            return $this->mapSequential($items, $fn);
        }

        try {
            return $this->mapWithAmp($items, $workers, $fn);
        } catch (\Throwable) {
            return $this->mapSequential($items, $fn);
        }
    }

    /**
     * @template TKey of array-key
     * @template TIn
     * @template TOut
     * @param array<TKey, TIn> $items
     * @param callable(TIn): TOut $fn
     * @return array<TKey, TOut>
     */
    private function mapWithAmp(array $items, int $workers, callable $fn): array
    {
        $semaphore = new LocalSemaphore($workers);
        $futures = [];

        foreach ($items as $key => $item) {
            $futures[$key] = async(static function () use ($semaphore, $fn, $item) {
                $lock = $semaphore->acquire();
                try {
                    return $fn($item);
                } finally {
                    $lock->release();
                }
            });
        }

        /** @var array<TKey, TOut> $results */
        $results = await($futures);

        return $results;
    }

    /**
     * @template TKey of array-key
     * @template TIn
     * @template TOut
     * @param array<TKey, TIn> $items
     * @param callable(TIn): TOut $fn
     * @return array<TKey, TOut>
     */
    private function mapSequential(array $items, callable $fn): array
    {
        $results = [];
        foreach ($items as $key => $item) {
            $results[$key] = $fn($item);
        }

        return $results;
    }
}
