<?php
declare(strict_types=1);

namespace App;

/**
 * PaytrailSystem — минимальная интеграция с Paytrail:
 * - создаёт платёж и делает редирект на платёжную страницу;
 * - проверяет подпись параметров после возврата с оплаты (redirect);
 * - принимает и валидирует серверный callback от Paytrail (server-to-server);
 * - содержит утилиту для получения заголовков запроса в нижнем регистре.
 */
final class PaytrailSystem
{
    /**
     * Создаёт платёж в Paytrail и перенаправляет пользователя на страницу оплаты.
     *
     * Шаги:
     * 1) Собираем тело запроса (JSON) с заказом.
     * 2) Формируем набор служебных заголовков Paytrail и подписываем запрос (HMAC).
     * 3) Отправляем POST на Paytrail.
     * 4) Из ответа берём ссылку на оплату и делаем на неё redirect.
     *
     * На каждом этапе пишем логи для отладки.
     */
    public function createAndRedirect(): void
    {
        // Минимальный заказ для примера/теста
        $order = [
            'reference' => 'order-' . time(),  // внутренний номер/ссылка на заказ
            'amount' => 1590,                  // сумма в центах (15.90 €)
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

        // Тело запроса в формате Paytrail (добавляем stamp/язык/валюту/URL-ы)
        $bodyArr = [
            'stamp' => 'order-' . time(),           // уникальный идентификатор операции у продавца
            'reference' => $order['reference'],     // номер заказа (то, что будет возвращаться в redirect/callback)
            'amount' => $order['amount'],           // сумма в центах
            'currency' => 'EUR',
            'language' => 'FI',                     // язык платёжной страницы
            'items' => $order['items'],
            'customer' => $order['customer'],
            // Куда вернуть пользователя из Paytrail после оплаты/отмены (браузерный redirect)
            'redirectUrls' => [
                'success' => Config::selfUrl('action=success'),
                'cancel'  => Config::selfUrl('action=cancel'),
            ],
            // Куда Paytrail отправит серверное уведомление о результате (без участия пользователя)
            'callbackUrls' => [
                'success' => Config::selfUrl('action=callback'),
                'cancel'  => Config::selfUrl('action=callback'),
            ],
        ];
        // Кодируем тело в JSON без экранирования юникода и слешей
        $body = json_encode($bodyArr, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        /**
         * Блок подписи исходящего запроса
         *
         * Paytrail требует подписывать запрос заголовками checkout-* + "сырое" тело.
         * Алгоритм: собрать нужные заголовки -> отсортировать -> склеить "k:v" через \n -> добавить "\n" + body -> HMAC.
         */
        $headersForSign = [
            'checkout-account'   => (string)Config::MERCHANT_ID, // id продавца
            'checkout-algorithm' => 'sha256',                    // алгоритм подписи
            'checkout-method'    => 'POST',                      // HTTP-метод
            'checkout-nonce'     => bin2hex(random_bytes(16)),   // случайная строка
            'checkout-timestamp' => gmdate('c'),                 // время в ISO8601 (UTC)
        ];
        ksort($headersForSign, SORT_STRING); // важен стабильный порядок ключей

        // Каноническая строка для подписи
        $lines = [];
        foreach ($headersForSign as $k => $v) {
            $lines[] = "$k:$v";
        }
        $stringToSign = implode("\n", $lines) . "\n" . $body;

        // Считаем HMAC подпись по секретному ключу продавца
        $signature = hash_hmac('sha256', $stringToSign, Config::SECRET_KEY);

        // Готовим реальные HTTP-заголовки запроса (для curl)
        $httpHeaders = array_merge(
            ['Content-Type: application/json; charset=utf-8'],
            array_map(fn($k, $v) => "$k: $v", array_keys($headersForSign), $headersForSign),
            ["signature: $signature"] // подпись кладём в заголовок "signature"
        );

        // Логируем исходящий запрос (для отладки и аудита)
        Logger::event('payment_create_request', [
            'endpoint' => Config::PAYTRAIL_ENDPOINT,
            'headers' => $headersForSign,
            'has_signature' => true,
            'body' => $bodyArr,
            'redirectUrls' => $bodyArr['redirectUrls'],
            'callbackUrls' => $bodyArr['callbackUrls'],
        ]);

        // Отправляем запрос в Paytrail
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

        // Обработка сетевой ошибки cURL
        if ($respBody === false) {
            Logger::event('payment_create_curl_error', ['error' => $curlErr]);
            http_response_code(500);
            die("cURL error: " . Views::e((string)$curlErr));
        }

        // Пробуем разобрать JSON-ответ
        $decoded = json_decode($respBody, true);
        $isJson = json_last_error() === JSON_ERROR_NONE;

        // Логируем ответ Paytrail
        Logger::event('payment_create_response', [
            'http_code' => $code,
            'body_raw'  => $isJson ? null : $respBody, // если не JSON — положим сырое тело
            'body_json' => $isJson ? $decoded : null
        ]);

        // Paytrail при успешном создании платежа возвращает HTTP 201
        if ($code !== 201) {
            http_response_code($code);
            die("Paytrail error ($code): " . Views::e($respBody));
        }

        // В ответе ожидаем ссылку платёжной страницы. Основное поле — 'href'
        $href = $decoded['href'] ?? null;

        // На всякий случай берём первую ссылку из списка методов оплаты, если основной 'href' отсутствует
        if (!$href && !empty($decoded['providers'][0]['url'])) {
            $href = $decoded['providers'][0]['url']; // fallback
        }

        Logger::event('payment_redirect', ['href' => $href]);

        // Перенаправляем пользователя на страницу оплаты
        if ($href) {
            header('Location: ' . $href);
            exit;
        }

        // Если ссылки нет — считаем, что что-то пошло не так на стороне Paytrail/конфигурации
        http_response_code(502);
        die('Нет ссылки на оплату (href) и нет доступных методов');
    }

    /**
     * Проверяет подпись параметров, пришедших в redirect (после возврата пользователя из Paytrail).
     *
     * В redirect Paytrail добавляет параметры checkout-* и signature.
     * Здесь мы:
     * - отбираем все checkout-* параметры;
     * - сортируем и склеиваем "k:v" через \n (без тела, т.к. redirect без body);
     * - считаем HMAC и сравниваем с 'signature'.
     *
     * Возвращает true, если подпись корректна.
     */
    public function verifyRedirectSignature(array $query): bool
    {
        if (empty($query['signature'])) return false;

        // Собираем только checkout-* параметры (в нижнем регистре имён)
        $chk = [];
        foreach ($query as $k => $v) {
            $lk = strtolower((string)$k);
            if (str_starts_with($lk, 'checkout-')) {
                $chk[$lk] = (string)$v;
            }
        }
        if (empty($chk)) return false;

        // Сортируем по ключу и формируем каноническую строку без тела
        ksort($chk, SORT_STRING);
        $lines = [];
        foreach ($chk as $k => $v) {
            $lines[] = $k . ':' . $v;
        }
        $stringToSign = implode("\n", $lines) . "\n"; // в redirect тела нет

        // Считаем HMAC и сравниваем с подписью из запроса
        $calc = hash_hmac('sha256', $stringToSign, Config::SECRET_KEY);
        return hash_equals($calc, strtolower((string)$query['signature']));
    }

    /**
     * Рендерит страницу "успех" или "отмена" после возврата с Paytrail.
     *
     * Действия:
     * - проверяем подпись redirect-параметров;
     * - логируем ключевые параметры (статус, сумма, провайдер, reference и т.п.);
     * - выводим пользователю простую страницу с результатом (через Views::resultPage).
     *
     * @param string $action 'success' или 'cancel' — что именно мы показываем.
     */
    public function renderSuccessOrCancel(string $action): void
    {
        $ok = $this->verifyRedirectSignature($_GET);                // валидна ли подпись
        $tx = $_GET['checkout-transaction-id'] ?? null;            // id транзакции
        $status = $_GET['checkout-status'] ?? null;                 // ok | fail
        $provider = $_GET['checkout-provider'] ?? null;             // провайдер (например, банк)
        $amount = $_GET['checkout-amount'] ?? null;                 // сумма в центах
        $reference = $_GET['checkout-reference'] ?? null;           // наш ref
        $stamp = $_GET['checkout-stamp'] ?? null;                   // наш stamp

        // Логируем факт возврата
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

        // Короткая заметка для пользователя
        $note = $action === 'success'
            ? ($ok ? 'Подпись валидна. Спасибо за оплату!' : 'Внимание: подпись не подтверждена.')
            : ($ok ? 'Подпись валидна, статус fail/отмена.' : 'Внимание: подпись не подтверждена.');

        // Рендер страницы результата
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

    /**
     * Обрабатывает server-to-server callback от Paytrail.
     * Server-to-server callback — это когда Paytrail сам отправляет твоему серверу сообщение о платеже,
     * без участия пользователя и без браузера.
     *
     * Что делаем:
     * - читаем "сырое" тело запроса и заголовки;
     * - валидируем подпись по тем же правилам (checkout-* заголовки + \n + сырое тело);
     * - если тело — корректный JSON, разбираем его и можем обновить статус заказа в БД;
     * - отвечаем 200 OK, если всё хорошо, иначе 400.
     */
    public function handleCallback(): void
    {
        // 1️ Считываем "сырое" тело запроса и все заголовки
        $rawBody = file_get_contents('php://input') ?: '';
        $headers = $this->getAllHeadersLowercase();

        Logger::event('callback_received', [
            'method'  => $_SERVER['REQUEST_METHOD'] ?? null,
            'uri'     => $_SERVER['REQUEST_URI'] ?? null,
            'ip'      => $_SERVER['REMOTE_ADDR'] ?? null,
            'headers' => $headers,
            'rawBody' => $rawBody,
        ]);

        // 2️ ПРОВЕРКА №1: Есть ли заголовок Signature
        // Если нет — сразу 400 (Bad Request) и причина "missing_signature"
        if (!isset($headers['signature'])) {
            http_response_code(400);
            echo 'Missing signature';
            Logger::event('callback_error', ['reason' => 'missing_signature']);
            return;
        }

        // 3️ Определяем алгоритм подписи (обычно sha256)
        $algo = strtolower($headers['checkout-algorithm'] ?? 'sha256');

        // 4️ ПРОВЕРКА №2: Есть ли вообще заголовки checkout-* (служебные поля Paytrail)
        // Если их нет — 400 и причина "missing_checkout_headers"
        $checkoutHeaders = [];
        foreach ($headers as $k => $v) {
            if (str_starts_with($k, 'checkout-')) {
                $checkoutHeaders[$k] = $v;
            }
        }
        if (!$checkoutHeaders) {
            http_response_code(400);
            echo 'Missing checkout-* headers';
            Logger::event('callback_error', [
                'reason' => 'missing_signature',
                'hint'   => 'Paytrail не прислал заголовок "Signature". Проверьте, что callback-запрос приходит напрямую от Paytrail и что сервер не удаляет этот заголовок (например, прокси или Nginx).',
                'received_headers' => array_keys($headers) // чтобы видеть, какие заголовки вообще пришли
            ]);
            return;
        }

        // 5️ Готовим строку для подписи: сортируем checkout-* + тело запроса
        ksort($checkoutHeaders, SORT_STRING);
        $lines = [];
        foreach ($checkoutHeaders as $k => $v) {
            $lines[] = $k . ':' . $v;
        }
        $stringToSign = implode("\n", $lines) . "\n" . $rawBody;

        // 6️ Считаем свою подпись и сравниваем с переданной
        $calc = hash_hmac($algo, $stringToSign, Config::SECRET_KEY);
        $sig  = strtolower($headers['signature']);
        $valid = hash_equals($calc, $sig);

        // 7️ ПРОВЕРКА №3: Совпадает ли подпись
        // Если нет — 400 и причина "Invalid signature"
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

        // 8. Если тело — JSON, логируем его
        $json = json_decode($rawBody, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            Logger::event('callback_parsed', ['json' => $json]);
            // Здесь можно обновить заказ в БД
        }

        // 9️ Всё ок — отвечаем Paytrail'у "OK"
        http_response_code(200);
        echo 'OK';
    }


    /**
     * Возвращает все HTTP-заголовки текущего запроса в виде массива с ключами в нижнем регистре.
     *
     * Зачем:
     * - удобно для дальнейшей обработки (не зависит от регистра);
     * - одинаково работает на разных серверах (Apache/Nginx/FPM/Cli-server).
     *
     * Реализация:
     * - если доступна функция getallheaders(), используем её;
     * - иначе собираем заголовки из массива $_SERVER.
     */
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

        // Ветка на случай отсутствия getallheaders()
        $out = [];
        foreach ($_SERVER as $name => $value) {
            if (str_starts_with($name, 'HTTP_')) {
                // Превращаем HTTP_HEADER_NAME -> header-name
                $k = strtolower(str_replace('_', '-', substr($name, 5)));
                $out[$k] = $value;
            }
        }
        if (isset($_SERVER['CONTENT_TYPE']))   $out['content-type'] = $_SERVER['CONTENT_TYPE'];
        if (isset($_SERVER['CONTENT_LENGTH'])) $out['content-length'] = $_SERVER['CONTENT_LENGTH'];
        return $out;
    }
}
