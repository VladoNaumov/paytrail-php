<?php

// один вход + простой роутинг

require __DIR__ . '/../vendor/autoload.php';

use App\Paytrail;

$pt = new Paytrail(dirname(__DIR__));

$r = $_GET['r'] ?? ''; // '', create, success, cancel, webhook, status

// Главная — кнопка
if ($r === '') {
    $amount = 190;
    echo '<!doctype html><meta charset="utf-8"><title>Paytrail compact</title>';
    echo '<h1>Paytrail compact test</h1>';
    echo '<p>Сумма: €' . number_format($amount/100, 2) . '</p>';
    echo '<form action="?r=create" method="post"><input type="hidden" name="amount" value="'.$amount.'"><button>Оплатить</button></form>';
    echo '<p><a href="?r=status">Проверить статус</a></p>';
    exit;
}

// Создание платежа
if ($r === 'create' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!str_starts_with($pt->base, 'https://')) {
        http_response_code(400); exit('BASE_URL в .env должен быть HTTPS-доменом.');
    }
    $host = parse_url($pt->base, PHP_URL_HOST);
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        http_response_code(400); exit('BASE_URL не должен быть IP (используй ngrok/cloudflared).');
    }

    $amount = (int)($_POST['amount'] ?? 190);
    $ref    = 'ORDER-' . random_int(1000, 9999);
    $success= $pt->base . '/index.php?r=success&ref=' . urlencode($ref);
    $cancel = $pt->base . '/index.php?r=cancel&ref=' . urlencode($ref);
    $cb     = $pt->base . '/index.php?r=webhook';

    [$code, $body, $err, $hdrs] = $pt->createPayment($amount, $ref, $success, $cancel, $cb);

    if ($code < 200 || $code >= 300) {
        http_response_code(500); exit("Create payment failed (HTTP $code): " . htmlspecialchars($err ?: $body));
    }
    if (!$pt->verifyResponse($hdrs, $body)) {
        http_response_code(502); exit('Invalid response signature');
    }
    $data = json_decode($body, true);
    if (!is_array($data) || empty($data['href']) || empty($data['transactionId'])) {
        http_response_code(500); exit('Invalid response payload');
    }
    file_put_contents(__DIR__ . '/last.json', json_encode(['tx' => $data['transactionId'], 'ref' => $ref], JSON_UNESCAPED_SLASHES));
    header('Location: ' . $data['href'], true, 302); exit;
}

// Success / Cancel — проверка подписи редиректа
if ($r === 'success' || $r === 'cancel') {
    $ok  = $pt->verifyRedirect($_GET);
    $ref = $_GET['reference'] ?? ($_GET['checkout-reference'] ?? '');
    echo '<!doctype html><meta charset="utf-8"><title>'.($r==='success'?'Success':'Cancel').'</title>';
    echo '<h1>'.($r==='success'?'Платёж успешен':'Платёж отменён').'</h1>';
    echo '<p>Подпись возврата: <b>'.($ok?'валидна ✅':'НЕВЕРНА ❌').'</b></p>';
    if ($ref) echo '<p>Заказ: '.htmlspecialchars($ref).'</p>';
    echo '<p><a href="/index.php">На главную</a> · <a href="/index.php?r=status">Проверить статус</a></p>';
    exit;
}

// Webhook — проверка подписи
if ($r === 'webhook' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $raw = file_get_contents('php://input');
    // getallheaders может отсутствовать под CGI — fallback:
    if (!function_exists('getallheaders')) {
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (str_starts_with($name, 'HTTP_')) {
                $key = strtolower(str_replace('_', '-', substr($name, 5)));
                $headers[$key] = $value;
            }
        }
    } else {
        $headers = getallheaders();
    }
    $ok = $pt->verifyWebhook($headers ?: [], $raw);
    http_response_code($ok ? 200 : 401);
    echo $ok ? 'OK' : 'INVALID SIGNATURE';
    exit;
}

// Статус платежа
if ($r === 'status') {
    $last = is_file(__DIR__ . '/last.json') ? json_decode(file_get_contents(__DIR__ . '/last.json'), true) : null;
    if (!$last || empty($last['tx'])) {
        http_response_code(400); exit('Нет данных платежа. Сначала создайте платёж на /.');
    }
    [$code, $body, $err, $hdrs] = $pt->getStatus($last['tx']);
    header('Content-Type: application/json; charset=utf-8');
    if ($code < 200 || $code >= 300) {
        http_response_code(500); echo json_encode(['error'=>"Status failed ($code)", 'body'=>$body ?: $err], JSON_UNESCAPED_SLASHES); exit;
    }
    if (!$pt->verifyResponse($hdrs, $body)) {
        http_response_code(502); echo json_encode(['error'=>'Invalid response signature'], JSON_UNESCAPED_SLASHES); exit;
    }
    echo $body; exit;
}

// Иное
http_response_code(404);
echo 'Not Found';
