<?php
/**
 * Учебный пример: симметричное шифрование (один общий ключ).
 * Алгоритм: XChaCha20-Poly1305 (sodium_crypto_secretbox).
 * Запуск: php secretbox_demo.php
 */

if (!function_exists('sodium_crypto_secretbox')) {
    fwrite(STDERR, "Расширение libsodium не найдено. Установи/включи ext-sodium.\n");
    exit(1);
}

echo "=== Симметричное шифрование: secretbox (XChaCha20-Poly1305) ===\n\n";

// 1) Генерируем СЕКРЕТНЫЙ ключ (его знают обе стороны: отправитель и получатель)
$key = sodium_crypto_secretbox_keygen(); // 32 байта
echo "Ключ (base64): " . base64_encode($key) . "\n";

// 2) Сообщение, которое шифруем
$plain = "Привет! Это секретное сообщение №42.";

// 3) Для каждого сообщения нужен новый случайный nonce (уникальный)
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES); // 24 байта

// 4) Шифруем (получаем ciphertext с встроенной аутентификацией)
$ciphertext = sodium_crypto_secretbox($plain, $nonce, $key);

// 5) Упаковываем для передачи: nonce || ciphertext (часто кодируют в base64)
$packet = base64_encode($nonce . $ciphertext);
echo "Пакет для передачи (nonce+cipher, base64):\n$packet\n\n";

// === На стороне получателя ===

// 6) Распаковываем
$decoded = base64_decode($packet, true);

// 7) Отделяем nonce и ciphertext по известной длине nonce
$nonce2      = substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$ciphertext2 = substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

// 8) Пытаемся расшифровать и проверить целостность
$decrypted = sodium_crypto_secretbox_open($ciphertext2, $nonce2, $key);

// 9) Если ключ не тот или сообщение испорчено — вернётся false
if ($decrypted === false) {
    echo "Расшифровка провалена (неверный ключ/подмена данных)\n";
    exit(1);
}

echo "Исходный текст:   $plain\n";
echo "Расшифровано как: $decrypted\n";

// 10) Покажем, что подмена ломает проверку (имитируем порчу 1 байта)
$broken = $decoded;
$broken[strlen($broken) - 1] = chr(ord($broken[strlen($broken) - 1]) ^ 0x01); // flip last bit
$nonce_b = substr($broken, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$ciph_b  = substr($broken, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$try_b   = sodium_crypto_secretbox_open($ciph_b, $nonce_b, $key);
echo "\nПроверка подмены: " . ($try_b === false ? "OK, подмена заметна ❌" : "НЕОЖИДАННО: прошло") . "\n";
