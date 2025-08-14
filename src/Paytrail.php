<?php
namespace App;

use Dotenv\Dotenv;

class Paytrail
{
    public int $merchantId;
    public string $secret;
    public string $api = 'https://services.paytrail.com';
    public string $base;
    public string $algo = 'sha256';
    private string $logFile;

    public function __construct(string $rootDir)
    {
        // Загружаем .env
        Dotenv::createImmutable($rootDir)->load();

        $this->merchantId = (int)($_ENV['PAYTRAIL_MERCHANT_ID'] ?? 0);
        $this->secret     = (string)($_ENV['PAYTRAIL_SECRET_KEY'] ?? '');
        $this->base       = rtrim((string)($_ENV['BASE_URL'] ?? ''), '/');

        // Готовим путь для логов и создаём директорию при необходимости
        $logDir = $rootDir . '/storage/logs';
        if (!is_dir($logDir)) {
            @mkdir($logDir, 0777, true);
        }
        $this->logFile = $logDir . '/paytrail.log';
    }

    /* ========================= ЛОГИ ========================= */

    private function log(string $level, string $message, array $ctx = []): void
    {
        $ts = gmdate('Y-m-d H:i:s');
        $line = sprintf("[%s] %s: %s %s\n", $ts, strtoupper($level), $message,
            $ctx ? json_encode($ctx, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) : ''
        );
        @file_put_contents($this->logFile, $line, FILE_APPEND);
    }

    /* ========================= HMAC / УТИЛИТЫ ========================= */

    public static function uuid4(): string {
        $d = random_bytes(16);
        $d[6] = chr((ord($d[6]) & 0x0f) | 0x40);
        $d[8] = chr((ord($d[8]) & 0x3f) | 0x80);
        $h = bin2hex($d);
        return substr($h,0,8).'-'.substr($h,8,4).'-'.substr($h,12,4).'-'.substr($h,16,4).'-'.substr($h,20);
    }

    public static function canonical(array $kv, string $body = ''): string {
        $norm = [];
        foreach ($kv as $k => $v) {
            if ($v === null) continue;
            $norm[strtolower(trim((string)$k))] = trim((string)$v);
        }
        ksort($norm, SORT_STRING);
        $lines = [];
        foreach ($norm as $k => $v) $lines[] = $k . ':' . $v;
        return implode("\n", $lines) . "\n" . $body;
    }

    public static function hmac(string $algo, string $data, string $secret): string {
        $a = in_array(strtolower($algo), ['sha256','sha512'], true) ? strtolower($algo) : 'sha256';
        return hash_hmac($a, $data, $secret);
    }

    public static function eq(string $a, string $b): bool {
        return hash_equals(strtolower($a), strtolower($b));
    }

    public function headers(string $method, array $extra = []): array {
        return array_merge([
            'checkout-account'   => (string)$this->merchantId,
            'checkout-algorithm' => $this->algo,
            'checkout-method'    => strtoupper($method),
            'checkout-timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            'checkout-nonce'     => self::uuid4(),
        ], $extra);
    }

    public function signedHeaders(array $kv, string $body, bool $withJson = true): array {
        $algo = $kv['checkout-algorithm'] ?? $this->algo;
        $sig  = self::hmac($algo, self::canonical($kv, $body), $this->secret);
        $out = [];
        if ($withJson) $out['Content-Type'] = 'application/json; charset=utf-8';
        foreach ($kv as $k => $v) $out[$k] = $v;
        $out['signature'] = $sig;
        return $out;
    }

    private static function parseHeadersRaw(string $raw): array {
        $h = [];
        foreach (preg_split('/\r\n|\n|\r/', trim($raw)) as $line) {
            if (strpos($line, ':') === false) continue;
            [$n, $v] = explode(':', $line, 2);
            $h[strtolower(trim($n))] = trim($v);
        }
        return $h;
    }

    /** Выполняет запрос и возвращает [code, body, err, headersAssoc, requestId] */
    public function http(string $method, string $url, array $headersKv, ?array $json = null): array
    {
        $body   = $json ? json_encode($json, JSON_UNESCAPED_SLASHES) : '';
        $headersAssoc = $this->signedHeaders($headersKv, $body, $method !== 'GET');
        $headersList  = [];
        foreach ($headersAssoc as $k => $v) $headersList[] = $k . ': ' . $v;

        $this->log('info', 'HTTP request', ['method'=>$method,'url'=>$url,'headers'=>$headersAssoc,'body'=>$body]);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $headersList,
            CURLOPT_HEADER         => true,
        ]);
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $respAll   = curl_exec($ch);
        $code      = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSz  = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $err       = curl_error($ch);
        curl_close($ch);

        if ($respAll === false) {
            $this->log('error','HTTP error', ['code'=>0,'err'=>$err]);
            return [0,'',$err,[],null];
        }

        $rawHeaders = substr($respAll, 0, $headerSz);
        $respBody   = substr($respAll, $headerSz);
        $respHeaders= self::parseHeadersRaw($rawHeaders);
        $requestId  = $respHeaders['request-id'] ?? null;

        $this->log('info','HTTP response', ['code'=>$code,'headers'=>$respHeaders,'body'=>$respBody]);

        return [$code, $respBody, $err, $respHeaders, $requestId];
    }

    public function verifyResponse(array $respHeaders, string $body): bool
    {
        $algo     = $respHeaders['checkout-algorithm'] ?? $this->algo;
        $provided = $respHeaders['signature'] ?? '';
        $toSign   = [];
        foreach ($respHeaders as $k => $v) {
            if ($k === 'signature') continue;
            if (str_starts_with($k, 'checkout-')) $toSign[$k] = $v;
        }
        $calc = self::hmac($algo, self::canonical($toSign, $body), $this->secret);
        $ok   = $provided && self::eq($calc, $provided);

        $this->log($ok?'info':'error', 'Verify response signature', [
            'ok'=>$ok,'provided'=>$provided,'calc'=>$calc
        ]);

        return $ok;
    }

    public function verifyRedirect(array $query): bool
    {
        $algo     = $query['checkout-algorithm'] ?? $this->algo;
        $provided = $query['signature'] ?? '';
        $toSign   = [];
        foreach ($query as $k => $v) {
            if ($k === 'signature') continue;
            $toSign[strtolower($k)] = is_array($v) ? (string)reset($v) : (string)$v;
        }
        $calc = self::hmac($algo, self::canonical($toSign, ''), $this->secret);
        $ok   = $provided && self::eq($calc, $provided);

        $this->log($ok?'info':'error', 'Verify redirect signature', [
            'ok'=>$ok,'provided'=>$provided,'calc'=>$calc,'query'=>$query
        ]);

        return $ok;
    }

    public function verifyWebhook(array $headers, string $rawBody): bool
    {
        $h = [];
        foreach ($headers as $k => $v) {
            $h[strtolower($k)] = is_array($v) ? implode(',', $v) : (string)$v;
        }
        $algo     = $h['checkout-algorithm'] ?? $this->algo;
        $provided = $h['signature'] ?? '';
        $toSign   = [];
        foreach ($h as $k => $v) {
            if ($k === 'signature') continue;
            if (str_starts_with($k, 'checkout-')) $toSign[$k] = $v;
        }
        $calc = self::hmac($algo, self::canonical($toSign, $rawBody), $this->secret);
        $ok   = $provided && self::eq($calc, $provided);

        $this->log($ok?'info':'error','Verify webhook signature',[
            'ok'=>$ok,'provided'=>$provided,'calc'=>$calc,'headers'=>$h,'body_len'=>strlen($rawBody)
        ]);

        return $ok;
    }

    /* ========================= API ========================= */

    public function createPayment(int $amount, string $reference, string $successUrl, string $cancelUrl, string $callbackUrl): array
    {
        $payload = [
            'stamp'     => bin2hex(random_bytes(8)),
            'reference' => $reference,
            'amount'    => $amount,
            'currency'  => 'EUR',
            'language'  => 'FI',
            'items'     => [[
                'unitPrice'     => $amount,
                'units'         => 1,
                'vatPercentage' => 24,
                'productCode'   => 'SKU-TEST',
                'description'   => 'Test product',
            ]],
            'customer' => ['email' => 'customer@example.com'],
            'redirectUrls' => ['success' => $successUrl, 'cancel' => $cancelUrl],
            'callbackUrls' => ['success' => $callbackUrl, 'cancel' => $callbackUrl],
        ];

        $this->log('info','CreatePayment payload', $payload);

        $hkv = $this->headers('POST');
        return $this->http('POST', $this->api . '/payments', $hkv, $payload);
    }

    public function getStatus(string $transactionId): array
    {
        $this->log('info','GetStatus request', ['transactionId'=>$transactionId]);

        $hkv = $this->headers('GET', ['checkout-transaction-id' => $transactionId]);
        return $this->http('GET', $this->api . '/payments/' . rawurlencode($transactionId), $hkv, null);
    }
}
