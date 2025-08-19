<?php

/* маленькая «игра» одним PHP-файлом: она имитирует обе стороны — твой сервер (продавец) и Paytrail.
Ты вводишь данные → код делает подпись → затем «Paytrail» пересобирает ту же строку и проверяет подпись тем же секретом. */


/**
 * HMAC playground — имитация подписи продавца и проверки на стороне Paytrail.
 * Запуск: php hmac_playground.php
 */

// ====== «Настройки магазина» (как в .env) ======
$MERCHANT_ID = 375917;
$SECRET_KEY = 'SAIPPUAKAUPPIAS'; // Никогда не публикуй и не клади на фронтенд!

// ====== Данные «заказа» (можешь менять) ======
$order = [
    'orderNumber' => '12345',
    'amount' => 1990,        // 19.90 € в центах
    'currency' => 'EUR',
    'merchantId' => $MERCHANT_ID,
    'timestamp' => gmdate('c'), // ISO8601, пример поля, часто используется
];

// 1) Продавец формирует «сообщение» в фиксированном порядке полей.
//    *** В реальном Paytrail порядок/набор полей строго регламентирован документацией. ***
$messageFieldsOrder = ['orderNumber', 'amount', 'currency', 'merchantId', 'timestamp'];
$message = implode('|', array_map(fn($k) => (string)$order[$k], $messageFieldsOrder));

// 2) Продавец делает подпись (HMAC-SHA256 в hex):
$signature = hash_hmac('sha256', $message, $SECRET_KEY);

// «Отправляем» в Paytrail (данные + подпись)
$sentPayload = [
    'data' => $order,
    'signature' => $signature,
];

// ====== На стороне Paytrail: проверяем ======

// Paytrail достаёт свои «известные» поля в том же порядке:
$paytrailMessage = implode('|', array_map(fn($k) => (string)$sentPayload['data'][$k], $messageFieldsOrder));

// Считает HMAC своим (тем же) ключом:
$expectedSignature = hash_hmac('sha256', $paytrailMessage, $SECRET_KEY);

// Сравнивает безопасно:
$isValid = hash_equals($expectedSignature, $sentPayload['signature']);

// Выводим всё на экран:
echo "=== Merchant side ===\n";
echo "Message:    {$message}\n";
echo "Signature:  {$signature}\n\n";

echo "=== Paytrail side ===\n";
echo "Rebuilt:    {$paytrailMessage}\n";
echo "Expected:   {$expectedSignature}\n";
echo "Provided:   {$sentPayload['signature']}\n";
echo "Match?      " . ($isValid ? "YES ✅" : "NO ❌") . "\n";

// Маленький эксперимент: «испортим» сумму и увидим, что подпись сломается
$sentPayload['data']['amount'] = 2990;
$tamperedMessage = implode('|', array_map(fn($k) => (string)$sentPayload['data'][$k], $messageFieldsOrder));
$recheck = hash_equals(hash_hmac('sha256', $tamperedMessage, $SECRET_KEY), $sentPayload['signature']);
echo "\n=== Tamper test (amount changed to 2990) ===\n";
echo "Tampered message: {$tamperedMessage}\n";
echo "Still valid?      " . ($recheck ? "YES (should NOT!)" : "NO (good) ❌") . "\n";

