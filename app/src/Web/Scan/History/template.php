<?php

declare(strict_types=1);

/**
 * @var Yiisoft\View\WebView $this
 * @var list<array<string, mixed>> $runs
 * @var Yiisoft\Router\UrlGeneratorInterface $urlGenerator
 * @var bool $workerOn
 */

use Yiisoft\Html\Html;

$this->setTitle('DNS scan history');
$workerOn = $workerOn ?? true;
$pending = false;
foreach ($runs as $run) {
    if (in_array((string) $run['status'], ['queued', 'running'], true)) {
        $pending = true;
        break;
    }
}
?>
<?php if ($pending): ?>
<meta http-equiv="refresh" content="10">
<?php endif; ?>
<style>
.ds { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; max-width: 1100px; margin: 0 auto; padding: 1.5rem; color: #122; }
.ds h1 { font-size: 1.5rem; margin: 0 0 1rem; }
.ds .toolbar { display: flex; gap: .5rem; flex-wrap: wrap; margin-bottom: 1.5rem; align-items: stretch; }
.ds form { display: flex; gap: .5rem; flex-wrap: wrap; flex: 1; align-items: stretch; }
.ds input[type=text],
.ds button,
.ds a.btn {
    box-sizing: border-box;
    height: 2.5rem;
    font: inherit;
    line-height: 1;
}
.ds input[type=text] { flex: 1; min-width: 220px; padding: 0 .7rem; border: 1px solid #9ab; border-radius: 6px; }
.ds button, .ds a.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: #0b6;
    color: #fff;
    border: 0;
    border-radius: 6px;
    padding: 0 .9rem;
    text-decoration: none;
    cursor: pointer;
    white-space: nowrap;
}
.ds button.off { background: #a33; }
.ds table { width: 100%; border-collapse: collapse; font-size: .9rem; }
.ds th, .ds td { border-bottom: 1px solid #dde3ea; padding: .55rem .4rem; text-align: left; vertical-align: top; }
.ds .muted { color: #678; }
.ds .pill { display: inline-block; padding: .1rem .45rem; border-radius: 999px; background: #e8f5ef; font-size: .75rem; }
.ds .pill.queued { background: #eef; }
.ds .pill.running { background: #ffe9c7; }
.ds .pill.failed { background: #fdd; }
</style>
<div class="ds">
    <h1>DNS scan</h1>
    <p class="muted">UI queues jobs. Worker advances one stage per tick (DNS → passive → wordlist → resolve → HTTP → finalize). Results go to MariaDB.</p>
    <?php if (!$workerOn): ?>
        <p class="muted">Worker is paused. Jobs stay queued until you turn it back on.</p>
    <?php endif; ?>

    <div class="toolbar">
    <form method="post" action="<?= Html::encode($urlGenerator->generate('scan/create')) ?>">
        <?php if (isset($csrf)): ?>
            <input type="hidden" name="<?= Html::encode(method_exists($csrf, 'getParameterName') ? $csrf->getParameterName() : '_csrf') ?>" value="<?= Html::encode((string) $csrf) ?>">
        <?php endif; ?>
        <input type="text" name="target" placeholder="example.com or 1.2.3.4" required>
        <button type="submit">Run scan</button>
        <a class="btn" href="<?= Html::encode($urlGenerator->generate('home')) ?>">Home</a>
    </form>
    <form method="post" action="<?= Html::encode($urlGenerator->generate('scan/worker-toggle')) ?>">
        <?php if (isset($csrf)): ?>
            <input type="hidden" name="<?= Html::encode(method_exists($csrf, 'getParameterName') ? $csrf->getParameterName() : '_csrf') ?>" value="<?= Html::encode((string) $csrf) ?>">
        <?php endif; ?>
        <button type="submit" class="<?= $workerOn ? '' : 'off' ?>">Worker <?= $workerOn ? 'ON' : 'OFF' ?></button>
    </form>
    </div>

    <table>
        <thead>
        <tr>
            <th>ID</th>
            <th>Target</th>
            <th>Status</th>
            <th>Stage</th>
            <th>Hosts</th>
            <th>Started</th>
            <th></th>
        </tr>
        </thead>
        <tbody>
        <?php if ($runs === []): ?>
            <tr><td colspan="7" class="muted">No scans yet.</td></tr>
        <?php endif; ?>
        <?php foreach ($runs as $run): ?>
            <tr>
                <td><?= (int) $run['id'] ?></td>
                <td>
                    <strong><?= Html::encode((string) $run['target_value']) ?></strong>
                    <div class="muted"><?= Html::encode((string) $run['target_kind']) ?> / <?= Html::encode((string) $run['target_input']) ?></div>
                </td>
                <td><span class="pill <?= Html::encode((string) $run['status']) ?>"><?= Html::encode((string) $run['status']) ?></span></td>
                <td class="muted"><?= Html::encode((string) ($run['stage'] ?? '-')) ?></td>
                <td><?= (int) ($run['host_count'] ?? 0) ?></td>
                <td class="muted"><?= Html::encode((string) ($run['started_at'] ?? '-')) ?></td>
                <td><a href="<?= Html::encode($urlGenerator->generate('scan/show', ['id' => (int) $run['id']])) ?>">open</a></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>
