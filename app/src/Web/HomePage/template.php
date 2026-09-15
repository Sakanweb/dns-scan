<?php

declare(strict_types=1);

use App\Shared\ApplicationParams;
use Yiisoft\View\WebView;

/**
 * @var WebView $this
 * @var ApplicationParams $applicationParams
 */

$this->setTitle($applicationParams->name);
?>

<div class="text-center">
    <h1>dns-scan</h1>
    <p>Yii3 + MySQL DNS inventory tool</p>
    <p>
        <a href="/scans">Open scan history</a>
    </p>
</div>
