<?php
declare(strict_types=1);

// 🔧 ВРЕМЕННО: отладка заголовков на реальном пути.
// УДАЛИ или отключи после тестов!

/*
if (isset($_GET['__debug']) && $_GET['__debug'] === 'headers') {
    $headers = function_exists('getallheaders') ? getallheaders() : [];
    if (!$headers) {
        foreach ($_SERVER as $k => $v) {
            if (str_starts_with($k, 'HTTP_')) {
                $name = str_replace('_', '-', substr($k, 5)); // HTTP_FOO_BAR -> FOO-BAR
                $headers[$name] = $v;
            }
        }
    }
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($headers, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}
*/

use App\App;

require_once __DIR__ . '/src/Config.php';
require_once __DIR__ . '/src/Logger.php';
require_once __DIR__ . '/src/Views.php';
require_once __DIR__ . '/src/PaytrailSystem.php';
require_once __DIR__ . '/src/App.php';

App::run();
