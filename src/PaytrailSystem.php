<?php
declare(strict_types=1);

namespace App;

/**
 * Минимальная интеграция с Paytrail:
 * - создаёт платёж и редиректит на платёжную страницу;
 * - проверяет подпись параметров после возврата (redirect);
 * - принимает и валидирует серверный callback (server-to-server).
 */
final class PaytrailSystem
{
    public function createAndRedirect(): void
    {
        $order = [
            'reference' => 'order-' . time(),
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
            'stamp' => 'order-' . time(),
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

        $lines = [];
        foreach ($headersForSign as $k => $v) {
            $lines[] = "$k:$v";
        }
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

        Logger::event('payment_create_response', [
            'http_code' => $code,
            'body_raw'  => $isJson ? null : $respBody,
            'body_json' => $isJson ? $decoded : null
        ]);

        if ($code !== 201) {
            http_response_code($code);
            die("Paytrail error ($code): " . Views::e($respBody));
        }

        $href = $decoded['href'] ?? null;
        if (!$href && !empty($decoded['providers'][0]['url'])) {
            $href = $decoded['providers'][0]['url'];
        }

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
        foreach ($chk as $k => $v) {
            $lines[] = $k . ':' . $v;
        }
        $stringToSign = implode("\n", $lines) . "\n";
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

    public function handleCallback(): void
    {
        // язык логов — англ., чтобы техподдержке было понятно
        $LANG = 'en';

        $MSG = [
            'en' => [
                'recv'     => 'callback_received',
                'ok_post'  => 'callback_ok: post_valid_signature',
                'ok_get'   => 'callback_ok: get_query_valid_signature (Using Plan B - GET-like callback)',
                'err_miss' => 'callback_error: missing_signature (POST expected with Paytrail signature header)',
                'err_inv'  => 'callback_error: invalid_signature',
                'err_get'  => 'callback_error: get_query_invalid_signature',
                'hint_miss'=> 'Hosting action required: ensure Paytrail POST callback with headers & raw JSON reaches PHP without being converted to GET or stripped by proxy/WAF. Preserve raw body for HMAC.',
            ],
        ][$LANG];

        $now = gmdate('Y-m-d\TH:i:s\Z');

        $log = function(string $event, array $payload = []) use ($now) {
            $line = sprintf("[%s] %s %s\n", $now, $event, json_encode($payload, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
            error_log($line, 3, Config::LOG_FILE);
        };

        $getAllHeadersLower = function(): array {
            $h = function_exists('getallheaders') ? getallheaders() : [];
            if (!$h) {
                foreach ($_SERVER as $k => $v) {
                    if (strpos($k, 'HTTP_') === 0) {
                        $name = strtolower(str_replace('_', '-', substr($k, 5)));
                        $h[$name] = $v;
                    }
                }
            }
            $norm = [];
            foreach ($h as $k => $v) { $norm[strtolower($k)] = $v; }
            return $norm;
        };

        $headers   = $getAllHeadersLower();
        $method    = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $uri       = $_SERVER['REQUEST_URI'] ?? '';
        $remoteIp  = $_SERVER['REMOTE_ADDR'] ?? '';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $requestId = $headers['request-id'] ?? ($headers['x-request-id'] ?? '');
        $rawBody   = file_get_contents('php://input') ?: '';
        $query     = $_GET ?? [];

        $log($MSG['recv'], [
            'method'     => $method,
            'uri'        => $uri,
            'remote_ip'  => $remoteIp,
            'user_agent' => $userAgent,
            'request_id' => $requestId,
        ]);

        if (strtoupper($method) === 'POST') {
            $sig = $headers['signature'] ?? null;

            if (!$sig) {
                http_response_code(400);
                $log($MSG['err_miss'], [
                    'method'     => 'POST',
                    'uri'        => $uri,
                    'remote_ip'  => $remoteIp,
                    'request_id' => $requestId,
                    'hint'       => $MSG['hint_miss'],
                ]);
                echo 'ERR: missing signature';
                return;
            }

            // Канонизация для POST: значения checkout-* по порядку + raw body
            $chk = [];
            foreach ($headers as $k => $v) {
                if (strpos($k, 'checkout-') === 0) $chk[$k] = $v;
            }
            ksort($chk, SORT_STRING);
            $pieces = [];
            foreach ($chk as $v) { $pieces[] = (string)$v; }
            $canonical = implode("\n", $pieces) . $rawBody;

            $calc = hash_hmac('sha256', $canonical, Config::SECRET_KEY);
            if (!hash_equals(strtolower($calc), strtolower($sig))) {
                http_response_code(400);
                $log($MSG['err_inv'], [
                    'method'     => 'POST',
                    'uri'        => $uri,
                    'remote_ip'  => $remoteIp,
                    'request_id' => $requestId,
                ]);
                echo 'ERR: invalid signature';
                return;
            }

            $json = json_decode($rawBody, true) ?: [];
            $tx        = $json['transactionId'] ?? ($json['checkout-transaction-id'] ?? '');
            $reference = $json['reference']     ?? ($json['checkout-reference'] ?? '');
            $status    = $json['status']        ?? ($json['checkout-status'] ?? '');
            $amount    = $json['amount']        ?? ($json['checkout-amount'] ?? null);

            $log($MSG['ok_post'], [
                'tx'        => $tx,
                'reference' => $reference,
                'status'    => $status,
                'amount'    => $amount,
            ]);

            http_response_code(200);
            echo 'OK';
            return;
        }

        if (strtoupper($method) === 'GET') {
            $sig = $query['signature'] ?? null;
            if (!$sig) {
                http_response_code(400);
                $log($MSG['err_get'], [
                    'method'     => 'GET',
                    'uri'        => $uri,
                    'remote_ip'  => $remoteIp,
                    'request_id' => $requestId,
                    'reason'     => 'no signature in query',
                ]);
                echo 'ERR: missing signature';
                return;
            }

            // EDT: канонизация для GET идентична redirect:
            // key:value на строку, сортировка по ключу, в конце добавляем "\n".
            $chk = [];
            foreach ($query as $k => $v) {
                $lk = strtolower((string)$k);
                if ($lk === 'signature') continue;
                if (strpos($lk, 'checkout-') === 0) {
                    $chk[$lk] = (string)$v;
                }
            }
            ksort($chk, SORT_STRING);
            $lines = [];
            foreach ($chk as $k => $v) {
                $lines[] = $k . ':' . $v;
            }
            $canonical = implode("\n", $lines) . "\n";
            $calc = hash_hmac('sha256', $canonical, Config::SECRET_KEY);

            if (!hash_equals(strtolower($calc), strtolower($sig))) {
                http_response_code(400);
                $log($MSG['err_get'], [
                    'method'     => 'GET',
                    'uri'        => $uri,
                    'remote_ip'  => $remoteIp,
                    'request_id' => $requestId,
                    'reason'     => 'invalid signature',
                ]);
                echo 'ERR: invalid signature';
                return;
            }

            $tx        = $query['checkout-transaction-id'] ?? '';
            $reference = $query['checkout-reference'] ?? '';
            $status    = $query['checkout-status'] ?? '';
            $amount    = $query['checkout-amount'] ?? null;

            $log($MSG['ok_get'], [
                'tx'        => $tx,
                'reference' => $reference,
                'status'    => $status,
                'amount'    => $amount,
            ]);

            http_response_code(200);
            echo 'OK';
            return;
        }

        http_response_code(405);
        echo 'Method Not Allowed';
    }

}
