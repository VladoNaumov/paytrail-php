<?php
declare(strict_types=1);

use App\App;

require_once __DIR__ . '/src/Config.php';
require_once __DIR__ . '/src/Logger.php';
require_once __DIR__ . '/src/Views.php';
require_once __DIR__ . '/src/PaytrailSystem.php';
require_once __DIR__ . '/src/App.php';

try {
    App::run();
} catch (Throwable $e) {
    throw $e;
}
