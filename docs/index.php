<?php
declare(strict_types=1);

/**
 * ООП-версия Paytrail демо-интеграции (один файл).
 * Слои:
 *  - Config:   все настройки
 *  - Logger:   логи (json-строки)
 *  - Views:    простые HTML-страницы для success/cancel
 *  - PaytrailSystem: вся логика (создать платёж, подписи, callback)
 *  - App:      маршрутизация экшенов
 *
 * Тестовые креды Paytrail (Normal merchant):
 *   MERCHANT_ID=375917
 *   SECRET_KEY=SAIPPUAKAUPPIAS
 *
 * ВАЖНО: Для server-to-server callback сервер/прокси должен пропускать заголовки:
 * signature, checkout-*, иначе handleCallback увидит "missing_signature".
 */

/* =========================
 *         1) CONFIG
 * ========================= */
final class Config
{
    // --- Креды Paytrail (тест) ---
    public const MERCHANT_ID       = 375917;
    public const SECRET_KEY        = 'SAIPPUAKAUPPIAS';

    // --- API эндпоинт ---
    public const PAYTRAIL_ENDPOINT = 'https://services.paytrail.com/payments';

    // --- Базовый URL (папка, где лежит этот index.php) ---
    // Рекомендуется на проде жестко задавать:
    public const FORCE_BASE_URL    = 'https://www.encanta.fi/demo'; // оставь пустым '', если хочешь авто-вычисление

    // Если FORCE_BASE_URL пуст, соберём из домена/пути:
    public const YOUR_DOMAIN       = 'www.encanta.fi';
    public const APP_PATH          = '/demo'; // '' если в корне

    // --- Куда ведёт кнопка "Назад в магазин" ---
    public const BACK_URL          = 'https://encanta.fi/';

    // --- Логи ---
    public const LOG_FILE          = __DIR__ . '/paytrail.log';
    public const DEBUG_LOGS        = true;

    // Вспомогательные: base_url и self_url
    public static function baseUrl(): string
    {
        if (self::FORCE_BASE_URL !== '') {
            return rtrim(self::FORCE_BASE_URL, '/');
        }
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host   = $_SERVER['HTTP_HOST'] ?? self::YOUR_DOMAIN;
        $path   = self::APP_PATH !== '' ? self::APP_PATH : rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/\\');
        if ($path === '') $path = '/';
        return rtrim($scheme . '://' . $host . $path, '/');
    }

    public static function selfUrl(string $query): string
    {
        return self::baseUrl() . '/index.php?' . $query;
    }
}

/* =========================
 *         2) LOGGER
 * ========================= */
final class Logger
{
    /** Пишем строку JSON в лог (UTC ISO8601). Никогда не логируем секретный ключ. */
    public static function event(string $event, array $data = []): void
    {
        if (!App\Config::DEBUG_LOGS) return;
        if (isset($data['SECRET_KEY'])) unset($data['SECRET_KEY']);
        $line = '[' . gmdate('Y-m-d\TH:i:s\Z') . '] ' . $event . ' ' . json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        @file_put_contents(App\Config::LOG_FILE, $line . PHP_EOL, FILE_APPEND);
    }
}

/* =========================
 *         3) VIEWS
 * ========================= */
final class Views
{
    /** Экранировать строку для HTML */
    public static function e(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /** Страница результата (success/cancel) с деталями и кнопками */
    public static function resultPage(string $action, array $data): void
    {
        $title = $action === 'success' ? 'Оплата успешно завершена' : 'Оплата отменена';
        $note  = $data['note'] ?? '';
        $tx        = (string)($data['tx'] ?? '');
        $status    = (string)($data['status'] ?? '');
        $provider  = (string)($data['provider'] ?? '');
        $amount    = $data['amount'] ?? null;
        $reference = (string)($data['reference'] ?? '');
        $stamp     = (string)($data['stamp'] ?? '');

        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
        echo '<title>' . self::e($title) . '</title>';
        echo '<style>
            body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Helvetica,Arial,sans-serif;line-height:1.45;padding:24px;background:#f7f7f8;color:#111}
            .card{max-width:720px;margin:0 auto;background:#fff;border-radius:16px;padding:24px;box-shadow:0 8px 30px rgba(0,0,0,.06)}
            h1{margin:0 0 8px;font-size:24px}
            .ok{color:#0a7a2d}.warn{color:#a15c00}
            .grid{display:grid;grid-template-columns:160px 1fr;gap:8px 12px;margin-top:12px}
            .muted{color:#666}
            .btn{display:inline-block;margin-top:18px;padding:12px 16px;border-radius:10px;text-decoration:none;border:1px solid #ddd}
            .btn-primary{border-color:#222;color:#fff;background:#222}
            .btn + .btn{margin-left:8px}
        </style></head><body>';
        echo '<div class="card">';
        echo '<h1>' . self::e($title) . '</h1>';
        echo '<div class="' . ($action === 'success' ? 'ok' : 'warn') . '">' . self::e($note) . '</div>';

        echo '<div class="grid">';
        echo '<div class="muted">Transaction ID</div><div>' . self::e($tx) . '</div>';
        echo '<div class="muted">Status</div><div>' . self::e($status) . '</div>';
        echo '<div class="muted">Provider</div><div>' . self::e($provider) . '</div>';
        echo '<div class="muted">Amount</div><div>' . (is_numeric($amount) ? number_format(((int)$amount)/100, 2, '.', ' ') . ' €' : self::e((string)$amount)) . '</div>';
        echo '<div class="muted">Reference</div><div>' . self::e($reference) . '</div>';
        echo '<div class="muted">Stamp</div><div>' . self::e($stamp) . '</div>';
        echo '</div>';

        echo '<div>';
        if ($action === 'success') {
            echo '<a class="btn btn-primary" href="' . self::e(App\Config::BACK_URL) . '">← Назад в магазин</a>';
        } else {
            echo '<a class="btn" href="' . self::e(App\Config::baseUrl()) . '">Попробовать оплатить снова</a>';
            echo '<a class="btn" href="' . self::e(App\Config::BACK_URL) . '">← Назад в магазин</a>';
        }
        echo '</div>';

        echo '</div></body></html>';
    }
}

/* =========================
 *     4) PAYTRAIL SYSTEM
 * ========================= */
final class PaytrailSystem
{
    /* -------- Создание платежа -------- */
    public function createAndRedirect(): void
    {
        // Минимальный заказ (демо)
        $order = [
            'reference' => 'order-' . time(),
            'amount'    => 1590, // 15.90 € в центах
            'items'     => [[
                'unitPrice'     => 1590,
                'units'         => 1,
                'vatPercentage' => 24,
                'productCode'   => 'SKU-001',
                'description'   => 'Test product',
                'category'      => 'General',
            ]],
            'customer' => [
                'email'     => 'test@example.com',
                'firstName' => 'Test',
                'lastName'  => 'User',
                'phone'     => '+358501234567',
            ],
        ];

        $bodyArr = [
            'stamp'        => 'order-' . time(),
            'reference'    => $order['reference'],
            'amount'       => $order['amount'],
            'currency'     => 'EUR',
            'language'     => 'FI',
            'items'        => $order['items'],
            'customer'     => $order['customer'],
            'redirectUrls' => [
                'success' => App\Config::selfUrl('action=success'),
                'cancel'  => App\Config::selfUrl('action=cancel'),
            ],
            'callbackUrls' => [
                'success' => App\Config::selfUrl('action=callback'),
                'cancel'  => App\Config::selfUrl('action=callback'),
            ],
        ];
        $body = json_encode($bodyArr, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        // Заголовки для подписи
        $headersForSign = [
            'checkout-account'   => (string)App\Config::MERCHANT_ID,
            'checkout-algorithm' => 'sha256',
            'checkout-method'    => 'POST',
            'checkout-nonce'     => bin2hex(random_bytes(16)),
            'checkout-timestamp' => gmdate('c'),
        ];
        ksort($headersForSign, SORT_STRING);

        // Каноническая строка и HMAC подпись (сырое тело в конце)
        $lines = [];
        foreach ($headersForSign as $k => $v) { $lines[] = "$k:$v"; }
        $stringToSign = implode("\n", $lines) . "\n" . $body;
        $signature    = hash_hmac('sha256', $stringToSign, App\Config::SECRET_KEY);

        // HTTP-заголовки запроса
        $httpHeaders = array_merge(
            ['Content-Type: application/json; charset=utf-8'],
            array_map(fn($k,$v) => "$k: $v", array_keys($headersForSign), $headersForSign),
            ["signature: $signature"]
        );

        // Лог исходящего запроса
        App\Logger::event('payment_create_request', [
            'endpoint'     => App\Config::PAYTRAIL_ENDPOINT,
            'headers'      => $headersForSign,
            'has_signature'=> true,
            'body'         => $bodyArr,
            'redirectUrls' => $bodyArr['redirectUrls'],
            'callbackUrls' => $bodyArr['callbackUrls'],
        ]);

        // Отправка
        $ch = curl_init(App\Config::PAYTRAIL_ENDPOINT);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_HTTPHEADER     => $httpHeaders,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => false,
        ]);
        $respBody = curl_exec($ch);
        $code     = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr  = $respBody === false ? curl_error($ch) : null;
        curl_close($ch);

        if ($respBody === false) {
            App\Logger::event('payment_create_curl_error', ['error' => $curlErr]);
            http_response_code(500);
            die("cURL error: " . App\Views::e((string)$curlErr));
        }

        $decoded = json_decode($respBody, true);
        $isJson  = json_last_error() === JSON_ERROR_NONE;
        App\Logger::event('payment_create_response', [
            'http_code' => $code,
            'body_raw'  => $isJson ? null : $respBody,
            'body_json' => $isJson ? $decoded : null
        ]);

        if ($code !== 201) {
            http_response_code($code);
            die("Paytrail error ($code): " . App\Views::e($respBody));
        }

        // Ссылка платёжной страницы (официально: href)
        $href = $decoded['href'] ?? null;
        if (!$href && !empty($decoded['providers'][0]['url'])) {
            $href = $decoded['providers'][0]['url']; // fallback
        }

        App\Logger::event('payment_redirect', ['href' => $href]);

        if ($href) {
            header('Location: ' . $href);
            exit;
        }

        http_response_code(502);
        die('Нет ссылки на оплату (href) и нет доступных методов');
    }

    /* -------- Проверка подписи в redirect (success/cancel) -------- */
    public function verifyRedirectSignature(array $query): bool
    {
        if (empty($query['signature'])) return false;
        $chk = [];
        foreach ($query as $k => $v) {
            $lk = strtolower((string)$k);
            if (str_starts_with($lk, 'checkout-')) {
                $chk[$lk] = (string)$v;
            }
        }
        if (empty($chk)) return false;
        ksort($chk, SORT_STRING);
        $lines = [];
        foreach ($chk as $k => $v) { $lines[] = $k . ':' . $v; }
        $stringToSign = implode("\n", $lines) . "\n"; // на redirect тело пустое
        $calc = hash_hmac('sha256', $stringToSign, App\Config::SECRET_KEY);
        return hash_equals($calc, strtolower((string)$query['signature']));
    }

    /* -------- Страница результатов -------- */
    public function renderSuccessOrCancel(string $action): void
    {
        $ok        = $this->verifyRedirectSignature($_GET);
        $tx        = $_GET['checkout-transaction-id'] ?? null;
        $status    = $_GET['checkout-status'] ?? null;   // ok/fail
        $provider  = $_GET['checkout-provider'] ?? null; // напр. osuuspankki
        $amount    = $_GET['checkout-amount'] ?? null;   // в центах
        $reference = $_GET['checkout-reference'] ?? null;
        $stamp     = $_GET['checkout-stamp'] ?? null;

        App\Logger::event('redirect_' . $action, [
            'url'          => (string)($_SERVER['REQUEST_URI'] ?? ''),
            'signature_ok' => $ok,
            'status'       => $status,
            'provider'     => $provider,
            'amount'       => $amount,
            'reference'    => $reference,
            'stamp'        => $stamp,
            'tx'           => $tx,
        ]);

        $note = $action === 'success'
            ? ($ok ? 'Подпись валидна. Спасибо за оплату!' : 'Внимание: подпись не подтверждена.')
            : ($ok ? 'Подпись валидна, статус fail/отмена.' : 'Внимание: подпись не подтверждена.');

        App\Views::resultPage($action, [
            'note'      => $note,
            'tx'        => (string)$tx,
            'status'    => (string)$status,
            'provider'  => (string)$provider,
            'amount'    => $amount,
            'reference' => (string)$reference,
            'stamp'     => (string)$stamp,
        ]);
    }

    /* -------- Обработка server-to-server callback -------- */
    public function handleCallback(): void
    {
        $rawBody = file_get_contents('php://input') ?: '';
        $headers = $this->getAllHeadersLowercase();

        App\Logger::event('callback_received', [
            'headers' => $headers,
            'rawBody' => $rawBody,
        ]);

        if (!isset($headers['signature'])) {
            http_response_code(400);
            echo 'Missing signature';
            App\Logger::event('callback_error', ['reason' => 'missing_signature']);
            return;
        }
        $algo = strtolower($headers['checkout-algorithm'] ?? 'sha256');

        // Собираем checkout-* заголовки
        $checkoutHeaders = [];
        foreach ($headers as $k => $v) {
            if (str_starts_with($k, 'checkout-')) {
                $checkoutHeaders[$k] = $v;
            }
        }
        if (!$checkoutHeaders) {
            http_response_code(400);
            echo 'Missing checkout-* headers';
            App\Logger::event('callback_error', ['reason' => 'missing_checkout_headers']);
            return;
        }

        ksort($checkoutHeaders, SORT_STRING);
        $lines = [];
        foreach ($checkoutHeaders as $k => $v) { $lines[] = $k . ':' . $v; }
        $stringToSign = implode("\n", $lines) . "\n" . $rawBody;

        $calc = hash_hmac($algo, $stringToSign, App\Config::SECRET_KEY);
        $sig  = strtolower($headers['signature']);
        $valid = hash_equals($calc, $sig);

        App\Logger::event('callback_signature_check', [
            'algorithm' => $algo,
            'valid'     => $valid,
            'checkout-transaction-id' => $headers['checkout-transaction-id'] ?? null,
            'checkout-status'         => $headers['checkout-status'] ?? null,
        ]);

        if (!$valid) {
            http_response_code(400);
            echo 'Invalid signature';
            return;
        }

        // Если тело — JSON, логируем его поля
        $json = json_decode($rawBody, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            App\Logger::event('callback_parsed', ['json' => $json]);
            // здесь можно обновить заказ в БД по статусу/сумме/провайдеру и т.п.
        }

        http_response_code(200);
        echo 'OK';
    }

    /* -------- Заголовки в нижнем регистре (кроссплатформенно) -------- */
    private function getAllHeadersLowercase(): array
    {
        if (function_exists('getallheaders')) {
            $raw = getallheaders();
            $out = [];
            foreach ($raw as $k => $v) { $out[strtolower($k)] = $v; }
            return $out;
        }
        $out = [];
        foreach ($_SERVER as $name => $value) {
            if (str_starts_with($name, 'HTTP_')) {
                $k = strtolower(str_replace('_', '-', substr($name, 5)));
                $out[$k] = $value;
            }
        }
        if (isset($_SERVER['CONTENT_TYPE']))   $out['content-type']   = $_SERVER['CONTENT_TYPE'];
        if (isset($_SERVER['CONTENT_LENGTH'])) $out['content-length'] = $_SERVER['CONTENT_LENGTH'];
        return $out;
    }
}

/* =========================
 *          5) APP
 * ========================= */
final class App
{
    public static function run(): void
    {
        $action = $_GET['action'] ?? 'create';
        $sys = new App\PaytrailSystem();

        switch ($action) {
            case 'success':
                $sys->renderSuccessOrCancel('success');
                break;

            case 'cancel':
                $sys->renderSuccessOrCancel('cancel');
                break;

            case 'callback':
                $sys->handleCallback();
                break;

            case 'create':
            default:
                $sys->createAndRedirect();
                break;
        }
    }
}

/* ======= Точка входа ======= */
App\App::run();
