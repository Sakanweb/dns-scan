<?php

declare(strict_types=1);

/**
 * @var Yiisoft\View\WebView $this
 * @var array<string, mixed> $run
 * @var Yiisoft\Router\UrlGeneratorInterface $urlGenerator
 * @var bool $workerOn
 */

use Yiisoft\Html\Html;

$this->setTitle('Scan #' . (int) $run['id']);
$hosts = $run['hosts'] ?? [];
$notes = $run['notes'] ?? [];
$wildcard = $run['wildcard_ips'] ?? [];
$status = (string) $run['status'];
$workerOn = $workerOn ?? true;
?>
<?php if (in_array($status, ['queued', 'running'], true)): ?>
<meta http-equiv="refresh" content="10">
<?php endif; ?>
<style>
.ds { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; max-width: 1200px; margin: 0 auto; padding: 1.5rem; color: #122; }
.ds h1 { font-size: 1.4rem; }
.ds .meta { color: #678; margin-bottom: 1rem; }
.ds table { width: 100%; border-collapse: collapse; font-size: .85rem; }
.ds th, .ds td { border-bottom: 1px solid #dde3ea; padding: .45rem .35rem; text-align: left; vertical-align: top; }
.ds .ok { color: #087; font-weight: 700; }
.ds .bad { color: #a33; }
.ds .def { color: #a60; }
.ds a { color: #06c; }
.ds .wait { background: #fff8e8; border: 1px solid #f0d9a0; padding: .75rem; border-radius: 6px; margin-bottom: 1rem; }
</style>
<div class="ds">
    <p><a href="<?= Html::encode($urlGenerator->generate('scan/history')) ?>">&larr; history</a></p>
    <h1>Scan #<?= (int) $run['id'] ?> - <?= Html::encode((string) $run['target_value']) ?></h1>
    <div class="meta">
        status=<?= Html::encode($status) ?>
        · stage=<?= Html::encode((string) ($run['stage'] ?? '-')) ?>
        · <?= Html::encode((string) ($run['stage_message'] ?? '')) ?>
        · started=<?= Html::encode((string) ($run['started_at'] ?? '-')) ?>
        · finished=<?= Html::encode((string) ($run['finished_at'] ?? '-')) ?>
        · threads=<?= (int) $run['dns_threads'] ?>
        · http_timeout=<?= (int) $run['http_timeout'] ?>s
        · wildcard=<?= Html::encode($wildcard === [] ? 'none' : implode(', ', $wildcard)) ?>
    </div>

    <?php if (in_array($status, ['queued', 'running'], true)): ?>
        <div class="wait">
            Job is <strong><?= Html::encode($status) ?></strong>
            / stage <strong><?= Html::encode((string) ($run['stage'] ?? '')) ?></strong>.
            <?php if ($workerOn): ?>
                Worker advances one stage per tick. This page refreshes every 10s.
            <?php else: ?>
                Worker is paused. Resume it from the history page.
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php if ($status === 'failed'): ?>
        <div class="wait"><strong>failed:</strong> <?= Html::encode((string) ($run['error_text'] ?? 'unknown')) ?></div>
    <?php endif; ?>

    <?php if (!empty($notes)): ?>
        <h2>Notes</h2>
        <ul>
            <?php foreach ($notes as $note): ?>
                <li><?= Html::encode((string) $note) ?></li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>

    <h2>Hosts (<?= count($hosts) ?>)</h2>
    <table>
        <thead>
        <tr>
            <th>Kind</th>
            <th>Name</th>
            <th>IPs</th>
            <th>Sources</th>
            <th>HTTP</th>
        </tr>
        </thead>
        <tbody>
        <?php foreach ($hosts as $host): ?>
            <?php $http = $host['http'] ?? null; ?>
            <tr>
                <td><?= Html::encode((string) $host['kind']) ?></td>
                <td><?= Html::encode((string) $host['name']) ?></td>
                <td><?= Html::encode(implode(', ', $host['ips'] ?? []) ?: '-') ?></td>
                <td><?= Html::encode(implode(', ', $host['sources'] ?? [])) ?></td>
                <td>
                    <?php if ($http === null): ?>
                        -
                    <?php elseif (!empty($http['default_page'])): ?>
                        <span class="def">DEFAULT</span> <?= (int) ($http['status_code'] ?? 0) ?> <?= Html::encode((string) ($http['title'] ?? '')) ?>
                    <?php elseif (!empty($http['works'])): ?>
                        <span class="ok">UP</span> <?= (int) ($http['status_code'] ?? 0) ?> <?= Html::encode((string) ($http['title'] ?? '')) ?>
                    <?php else: ?>
                        <span class="bad">DOWN</span> <?= Html::encode((string) ($http['error_text'] ?? $http['title'] ?? '')) ?>
                    <?php endif; ?>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>
