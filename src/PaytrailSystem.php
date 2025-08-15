<?php
declare(strict_types=1);

namespace App;

final class PaytrailSystem
{
    /* -------- Создание платежа -------- */
    public function createAndRedirect(): void
    {
        // Минимальный заказ (демо)
        $order = [
            'reference' => 'order-' . time(),
            'amount' => 1590, // 15.90 € в центах
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
            'stamp' => 'order-' . time(),
            'reference' => $order['reference'],
            'amount' => $order['amount'],
            'currency' => 'EUR',
            'language' => 'FI',
            'items' => $order['items'],
            'customer' => $order['customer'],
            'redirectUrls' => [
                'success' => Config::selfUrl('action=success'),
                'cancel' => Config::selfUrl('action=cancel'),
            ],
            'callbackUrls' => [
                'success' => Config::selfUrl('action=callback'),
                'cancel' => Config::selfUrl('action=callback'),
            ],
        ];
        $body = json_encode($bodyArr, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        // Заголовки для подписи
        $headersForSign = [
            'checkout-account' => (string)Config::MERCHANT_ID,
            'checkout-algorithm' => 'sha256',
            'checkout-method' => 'POST',
            'checkout-nonce' => bin2hex(random_bytes(16)),
            'checkout-timestamp' => gmdate('c'),
        ];
        ksort($headersForSign, SORT_STRING);

        // Каноническая строка и HMAC подпись (сырое тело в конце)
        $lines = [];
        foreach ($headersForSign as $k => $v) {
            $lines[] = "$k:$v";
        }
        $stringToSign = implode("\n", $lines) . "\n" . $body;
        $signature = hash_hmac('sha256', $stringToSign, Config::SECRET_KEY);

        // HTTP-заголовки запроса
        $httpHeaders = array_merge(
            ['Content-Type: application/json; charset=utf-8'],
            array_map(fn($k, $v) => "$k: $v", array_keys($headersForSign), $headersForSign),
            ["signature: $signature"]
        );

        // Лог исходящего запроса
        Logger::event('payment_create_request', [
            'endpoint' => Config::PAYTRAIL_ENDPOINT,
            'headers' => $headersForSign,
            'has_signature' => true,
            'body' => $bodyArr,
            'redirectUrls' => $bodyArr['redirectUrls'],
            'callbackUrls' => $bodyArr['callbackUrls'],
        ]);

        // Отправка
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
        Logger::event('payment_create_response', [
            'http_code' => $code,
            'body_raw' => $isJson ? null : $respBody,
            'body_json' => $isJson ? $decoded : null
        ]);

        if ($code !== 201) {
            http_response_code($code);
            die("Paytrail error ($code): " . Views::e($respBody));
        }

        // Ссылка платёжной страницы (официально: href)
        $href = $decoded['href'] ?? null;
        if (!$href && !empty($decoded['providers'][0]['url'])) {
            $href = $decoded['providers'][0]['url']; // fallback
        }

        Logger::event('payment_redirect', ['href' => $href]);

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
        foreach ($chk as $k => $v) {
            $lines[] = $k . ':' . $v;
        }
        $stringToSign = implode("\n", $lines) . "\n"; // на redirect тело пустое
        $calc = hash_hmac('sha256', $stringToSign, Config::SECRET_KEY);
        return hash_equals($calc, strtolower((string)$query['signature']));
    }

    /* -------- Страница результатов -------- */
    public function renderSuccessOrCancel(string $action): void
    {
        $ok = $this->verifyRedirectSignature($_GET);
        $tx = $_GET['checkout-transaction-id'] ?? null;
        $status = $_GET['checkout-status'] ?? null;   // ok/fail
        $provider = $_GET['checkout-provider'] ?? null; // напр. osuuspankki
        $amount = $_GET['checkout-amount'] ?? null;   // в центах
        $reference = $_GET['checkout-reference'] ?? null;
        $stamp = $_GET['checkout-stamp'] ?? null;

        Logger::event('redirect_' . $action, [
            'url' => (string)($_SERVER['REQUEST_URI'] ?? ''),
            'signature_ok' => $ok,
            'status' => $status,
            'provider' => $provider,
            'amount' => $amount,
            'reference' => $reference,
            'stamp' => $stamp,
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

    /* -------- Обработка server-to-server callback -------- */
    public function handleCallback(): void
    {
        $rawBody = file_get_contents('php://input') ?: '';
        $headers = $this->getAllHeadersLowercase();

        Logger::event('callback_received', [
            'headers' => $headers,
            'rawBody' => $rawBody,
        ]);

        if (!isset($headers['signature'])) {
            http_response_code(400);
            echo 'Missing signature';
            Logger::event('callback_error', ['reason' => 'missing_signature']);
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
            Logger::event('callback_error', ['reason' => 'missing_checkout_headers']);
            return;
        }

        ksort($checkoutHeaders, SORT_STRING);
        $lines = [];
        foreach ($checkoutHeaders as $k => $v) {
            $lines[] = $k . ':' . $v;
        }
        $stringToSign = implode("\n", $lines) . "\n" . $rawBody;

        $calc = hash_hmac($algo, $stringToSign, Config::SECRET_KEY);
        $sig = strtolower($headers['signature']);
        $valid = hash_equals($calc, $sig);

        Logger::event('callback_signature_check', [
            'algorithm' => $algo,
            'valid' => $valid,
            'checkout-transaction-id' => $headers['checkout-transaction-id'] ?? null,
            'checkout-status' => $headers['checkout-status'] ?? null,
        ]);

        if (!$valid) {
            http_response_code(400);
            echo 'Invalid signature';
            return;
        }

        // Если тело — JSON, логируем его поля
        $json = json_decode($rawBody, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            Logger::event('callback_parsed', ['json' => $json]);
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
            foreach ($raw as $k => $v) {
                $out[strtolower($k)] = $v;
            }
            return $out;
        }
        $out = [];
        foreach ($_SERVER as $name => $value) {
            if (str_starts_with($name, 'HTTP_')) {
                $k = strtolower(str_replace('_', '-', substr($name, 5)));
                $out[$k] = $value;
            }
        }
        if (isset($_SERVER['CONTENT_TYPE'])) $out['content-type'] = $_SERVER['CONTENT_TYPE'];
        if (isset($_SERVER['CONTENT_LENGTH'])) $out['content-length'] = $_SERVER['CONTENT_LENGTH'];
        return $out;
    }
}
