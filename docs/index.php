<?php
declare(strict_types=1);

namespace App;

/**
 * ООП-версия Paytrail демо-интеграции (один файл).
 * Слои:
 *  - Config:   настройки
 *  - Logger:   логи (json-строки)
 *  - Views:    HTML-страницы для success/cancel
 *  - PaytrailSystem: логика (создать платёж, подписи, callback)
 *  - App:      маршрутизация экшенов
 *
 * Тестовые креды Paytrail (Normal merchant):
 *   MERCHANT_ID=375917
 *   SECRET_KEY=SAIPPUAKAUPPIAS
 */

final class Config
{
    public const MERCHANT_ID       = 375917;
    public const SECRET_KEY        = 'SAIPPUAKAUPPIAS';

    public const PAYTRAIL_ENDPOINT = 'https://services.paytrail.com/payments';

    // Жёстко задать базовый URL (или оставить '' и собрать автоматически)
    public const FORCE_BASE_URL    = 'https://www.encanta.fi/payment'; // [Ваш выбор домена]

    public const YOUR_DOMAIN       = 'www.encanta.fi';
    public const APP_PATH          = '/payment';

    public const BACK_URL          = 'https://encanta.fi/';

    public const LOG_FILE          = __DIR__ . '/paytrail.log';
    public const DEBUG_LOGS        = true;

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

final class Logger
{
    public static function event(string $event, array $data = []): void
    {
        if (!Config::DEBUG_LOGS) return;
        unset($data['SECRET_KEY']);
        $line = '[' . gmdate('Y-m-d\TH:i:s\Z') . '] ' . $event . ' ' .
            json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        @file_put_contents(Config::LOG_FILE, $line . PHP_EOL, FILE_APPEND);
    }
}

final class Views
{
    public static function e(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

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
            echo '<a class="btn btn-primary" href="' . self::e(Config::BACK_URL) . '">← Назад в магазин</a>';
        } else {
            echo '<a class="btn" href="' . self::e(Config::baseUrl()) . '">Попробовать оплатить снова</a>';
            echo '<a class="btn" href="' . self::e(Config::BACK_URL) . '">← Назад в магазин</a>';
        }
        echo '</div>';

        echo '</div></body></html>';
    }
}

final class PaytrailSystem
{
    public function createAndRedirect(): void
    {
        $stamp = 'order-' . time();

        $order = [
            'reference' => $stamp,
            'amount' => 1590,
            'items' => [[
                'unitPrice' => 1590,
                'units' => 1,
                'vatPercentage' => 24,
                'productCode' => 'SKU-001',
                'description' => 'Test product',
                'category' => 'General',
            ]],
            'customer' => [
                'email' => 'test@example.com',
                'firstName' => 'Test',
                'lastName' => 'User',
                'phone' => '+358501234567',
            ],
        ];

        $bodyArr = [
            'stamp' => $stamp,
            'reference' => $order['reference'],
            'amount' => $order['amount'],
            'currency' => 'EUR',
            'language' => 'FI',
            'items' => $order['items'],
            'customer' => $order['customer'],
            'redirectUrls' => [
                'success' => Config::selfUrl('action=success'),
                'cancel'  => Config::selfUrl('action=cancel'),
            ],
            'callbackUrls' => [
                'success' => Config::selfUrl('action=callback'),
                'cancel'  => Config::selfUrl('action=callback'),
            ],
        ];
        $body = json_encode($bodyArr, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        $headersForSign = [
            'checkout-account'   => (string)Config::MERCHANT_ID,
            'checkout-algorithm' => 'sha256',
            'checkout-method'    => 'POST',
            'checkout-nonce'     => bin2hex(random_bytes(16)),
            'checkout-timestamp' => gmdate('c'),
        ];
        ksort($headersForSign, SORT_STRING);

        // "k:v\n..." + "\n" + raw body (официальный формат)
        $lines = [];
        foreach ($headersForSign as $k => $v) $lines[] = "$k:$v";
        $stringToSign = implode("\n", $lines) . "\n" . $body;

        $signature = hash_hmac('sha256', $stringToSign, Config::SECRET_KEY);

        $httpHeaders = array_merge(
            ['Content-Type: application/json; charset=utf-8'],
            array_map(fn($k, $v) => "$k: $v", array_keys($headersForSign), $headersForSign),
            ["signature: $signature"]
        );

        Logger::event('payment_create_request', [
            'endpoint' => Config::PAYTRAIL_ENDPOINT,
            'headers' => $headersForSign,
            'has_signature' => true,
            'body' => $bodyArr,
            'redirectUrls' => $bodyArr['redirectUrls'],
            'callbackUrls' => $bodyArr['callbackUrls'],
        ]);

        $ch = curl_init(Config::PAYTRAIL_ENDPOINT);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => $httpHeaders,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => false,
        ]);
        $respBody = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr = $respBody === false ? curl_error($ch) : null;
        curl_close($ch);

        if ($respBody === false) {
            Logger::event('payment_create_curl_error', ['error' => $curlErr]);
            http_response_code(500);
            die("cURL error: " . Views::e((string)$curlErr));
        }

        $decoded = json_decode($respBody, true);
        $isJson = json_last_error() === JSON_ERROR_NONE;
        $transactionId = $isJson ? ($decoded['transactionId'] ?? null) : null;

        Logger::event('payment_create_response', [
            'http_code' => $code,
            'transactionId' => $transactionId,
            'stamp' => $stamp,
            'body_raw'  => $isJson ? null : $respBody,
            'body_json' => $isJson ? $decoded : null
        ]);

        if ($code !== 201) {
            http_response_code($code);
            die("Paytrail error ($code): " . Views::e($respBody));
        }

        $href = $decoded['href'] ?? ($decoded['providers'][0]['url'] ?? null);
        Logger::event('payment_redirect', ['href' => $href]);

        if ($href) {
            header('Location: ' . $href);
            exit;
        }

        http_response_code(502);
        die('Нет ссылки на оплату (href) и нет доступных методов');
    }

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
        foreach ($chk as $k => $v) $lines[] = $k . ':' . $v;
        $stringToSign = implode("\n", $lines) . "\n"; // redirect без body

        $calc = hash_hmac('sha256', $stringToSign, Config::SECRET_KEY);
        return hash_equals($calc, strtolower((string)$query['signature']));
    }

    public function renderSuccessOrCancel(string $action): void
    {
        $ok = $this->verifyRedirectSignature($_GET);
        $tx = $_GET['checkout-transaction-id'] ?? null;
        $status = $_GET['checkout-status'] ?? null;
        $provider = $_GET['checkout-provider'] ?? null;
        $amount = $_GET['checkout-amount'] ?? null;
        $stamp = $_GET['checkout-stamp'] ?? null;         // 🔑 основной ID у продавца
        $reference = $_GET['checkout-reference'] ?? null; // справочный

        Logger::event('redirect_' . $action, [
            'url' => (string)($_SERVER['REQUEST_URI'] ?? ''),
            'signature_ok' => $ok,
            'status' => $status,
            'provider' => $provider,
            'amount' => $amount,
            'stamp' => $stamp,
            'reference' => $reference,
            'tx' => $tx,
        ]);

        $note = $action === 'success'
            ? ($ok ? 'Подпись валидна. Спасибо за оплату!' : 'Внимание: подпись не подтверждена.')
            : ($ok ? 'Подпись валидна, статус fail/отмена.' : 'Внимание: подпись не подтверждена.');

        Views::resultPage($action, [
            'note' => $note,
            'tx' => (string)$tx,
            'status' => (string)$status,
            'provider' => (string)$provider,
            'amount' => $amount,
            'reference' => (string)$reference,
            'stamp' => (string)$stamp,
        ]);
    }

    public function handleCallback(): void
    {
        $SECRET = Config::SECRET_KEY;

        // ---- Сбор заголовков (нижний регистр) ----
        $headers = [];
        if (function_exists('getallheaders')) {
            foreach (getallheaders() as $k => $v) { $headers[strtolower($k)] = $v; }
        }
        foreach ($_SERVER as $k => $v) {
            if (strpos($k, 'HTTP_') === 0) {
                $name = strtolower(str_replace('_', '-', substr($k, 5)));
                $headers[$name] = $v;
            }
        }

        // ---- Контекст ----
        $method     = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $uri        = $_SERVER['REQUEST_URI'] ?? '';
        $remoteIp   = $_SERVER['REMOTE_ADDR'] ?? '';
        $userAgent  = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $requestId  = $headers['request-id'] ?? ($headers['x-request-id'] ?? '');
        $rawBody    = file_get_contents('php://input') ?: '';
        $query      = $_GET ?? [];

        // [NEW] Стартовый лог входа
        Logger::event('callback_received', [
            'method'     => $method,
            'uri'        => $uri,
            'remote_ip'  => $remoteIp,
            'user_agent' => $userAgent,
            'request_id' => $requestId,
        ]);

        // ---- Ветка 1: нормальный POST с подписью в заголовке ----
        $sigHead = $headers['signature'] ?? null;
        if ($method === 'POST' && $sigHead) {
            // Canonical: значения ВСЕХ checkout-* заголовков (по алфавиту) + rawBody
            $canonHeaders = [];
            foreach ($headers as $k => $v) {
                if (strpos($k, 'checkout-') === 0) { $canonHeaders[$k] = $v; }
            }
            ksort($canonHeaders, SORT_STRING);

            // Официальная формула для callback с заголовками — как в старых гайдах: только значения + rawBody
            $canonical = implode("\n", array_values($canonHeaders)) . $rawBody;

            $calc  = hash_hmac('sha256', $canonical, $SECRET);
            $valid = hash_equals(strtolower($calc), strtolower((string)$sigHead));

            if (!$valid) {
                Logger::event('callback_error: invalid_signature', [
                    'method'     => 'POST',
                    'uri'        => $uri,
                    'remote_ip'  => $remoteIp,
                    'request_id' => $requestId,
                ]);
                http_response_code(400);
                echo 'ERR';
                return;
            }

            // Валидно — парсим JSON best-effort
            $json = json_decode($rawBody, true) ?: [];
            $tx        = $json['transactionId'] ?? ($json['checkout-transaction-id'] ?? '');
            $reference = $json['reference']     ?? ($json['checkout-reference'] ?? '');
            $status    = $json['status']        ?? ($json['checkout-status'] ?? '');
            $amount    = $json['amount']        ?? ($json['checkout-amount'] ?? null);
            $stamp     = $json['stamp']         ?? ($json['checkout-stamp'] ?? '');

            Logger::event('callback_ok: post_valid_signature', [
                'tx'        => $tx,
                'reference' => $reference,
                'status'    => $status,
                'amount'    => $amount,
                'stamp'     => $stamp,
            ]);

            http_response_code(200);
            echo 'OK';
            return;
        }

        // ---- Ветка 2: GET-callback (как подтвердил саппорт) ----
        $sigQuery = $query['signature'] ?? null;
        if ($method === 'GET' && $sigQuery) {
            // [EDT] Канонизация КЛЮЧ:ЗНАЧЕНИЕ + '\n' (как в redirect)
            $chk = [];
            foreach ($query as $k => $v) {
                $lk = strtolower((string)$k);
                if ($lk === 'signature') continue;
                if (str_starts_with($lk, 'checkout-')) {
                    $chk[$lk] = (string)$v;
                }
            }
            ksort($chk, SORT_STRING);
            $lines = [];
            foreach ($chk as $k => $v) { $lines[] = $k . ':' . $v; } // [EDT]
            $canonical = implode("\n", $lines) . "\n";                // [EDT]

            $calc  = hash_hmac('sha256', $canonical, $SECRET);
            $valid = hash_equals(strtolower($calc), strtolower((string)$sigQuery));

            if (!$valid) {
                Logger::event('callback_error: get_query_invalid_signature', [
                    'method'     => 'GET',
                    'uri'        => $uri,
                    'remote_ip'  => $remoteIp,
                    'request_id' => $requestId,
                    'reason'     => 'invalid signature',
                ]);
                http_response_code(400);
                echo 'ERR';
                return;
            }

            $tx        = $query['checkout-transaction-id'] ?? '';
            $reference = $query['checkout-reference']      ?? '';
            $status    = $query['checkout-status']         ?? '';
            $amount    = $query['checkout-amount']         ?? null;
            $stamp     = $query['checkout-stamp']          ?? '';

            Logger::event('callback_ok: get_query_valid_signature', [
                'tx'        => $tx,
                'reference' => $reference,
                'status'    => $status,
                'amount'    => $amount,
                'stamp'     => $stamp,
            ]);

            http_response_code(200);
            echo 'OK';
            return;
        }

        // ---- Иное: нет подписи / неподдерживаемый формат ----
        Logger::event('callback_error: missing_signature', [
            'method'     => $method,
            'uri'        => $uri,
            'remote_ip'  => $remoteIp,
            'request_id' => $requestId,
        ]);
        http_response_code(400);
        echo 'ERR';
    }
}

final class App
{
    public static function run(): void
    {
        $action = $_GET['action'] ?? 'create';
        $sys = new PaytrailSystem();

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

\App\App::run();
