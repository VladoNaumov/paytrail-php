<?php
/**
 * Учебный пример: E2E шифрование с публичными ключами (crypto_box).
 * Алгоритмы: Curve25519 + XChaCha20-Poly1305 (через libsodium).
 * Запуск: php e2e_box_demo.php
 *
 * У нас есть Алиса и Боб.
 * - У обоих есть пара ключей: (public, secret).
 * - Алиса шифрует сообщение Бобу на его публичный ключ и СВОЙ секретный (чтобы Боб был уверен, что это Алиса).
 * - Боб расшифровывает своим секретным и публичным ключом Алисы.
 */

if (!function_exists('sodium_crypto_box_keypair')) {
    fwrite(STDERR, "Расширение libsodium не найдено. Установи/включи ext-sodium.\n");
    exit(1);
}

echo "=== E2E: crypto_box (Curve25519 + XChaCha20-Poly1305) ===\n\n";

// 1) Генерируем ключи Алисы и Боба (пары публичный+секретный)
$alice_kp = sodium_crypto_box_keypair();
$bob_kp   = sodium_crypto_box_keypair();

$alice_pub = sodium_crypto_box_publickey($alice_kp);
$alice_sec = sodium_crypto_box_secretkey($alice_kp);
$bob_pub   = sodium_crypto_box_publickey($bob_kp);
$bob_sec   = sodium_crypto_box_secretkey($bob_kp);

echo "Публичный ключ Алисы (base64): " . base64_encode($alice_pub) . "\n";
echo "Публичный ключ Боба   (base64): " . base64_encode($bob_pub)   . "\n\n";

// 2) Алиса хочет отправить сообщение Бобу
$message = "Привет, Боб! Секрет только для тебя.";

// 3) Для каждого сообщения — новый nonce
$nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);

// 4) Создаём «совместную пару» из секрета Алисы и публичного ключа Боба
$alice_to_bob_kp = sodium_crypto_box_keypair_from_secretkey_and_publickey($alice_sec, $bob_pub);

// 5) Шифруем: только Боб сможет открыть (у него есть его секретный ключ и публичный ключ Алисы)
$ciphertext = sodium_crypto_box($message, $nonce, $alice_to_bob_kp);

// 6) Алиса отправляет Бобу: nonce + ciphertext + (публичный ключ Алисы, если Боб его не знает)
$packet = base64_encode($nonce . $ciphertext);
echo "Пакет для Боба (base64):\n$packet\n\n";

// === На стороне Боба ===
// 7) Боб знает публичный ключ Алисы (как-то получил заранее или вместе с сообщением)
$decoded = base64_decode($packet, true);
$nonce2  = substr($decoded, 0, SODIUM_CRYPTO_BOX_NONCEBYTES);
$ciph2   = substr($decoded, SODIUM_CRYPTO_BOX_NONCEBYTES);

// 8) Собираем пару ключей «секрет Боба + публичный ключ Алисы»
$bob_from_alice_kp = sodium_crypto_box_keypair_from_secretkey_and_publickey($bob_sec, $alice_pub);

// 9) Расшифровываем и проверяем аутентичность (что это именно Алиса)
$decrypted = sodium_crypto_box_open($ciph2, $nonce2, $bob_from_alice_kp);

if ($decrypted === false) {
    echo "Не удалось открыть сообщение. Неверные ключи или подмена.\n";
    exit(1);
}

echo "Боб получил: $decrypted\n";

// 10) Демонстрация «sealed box» (если не нужна подпись отправителя)
// Любой может зашифровать Бобу, зная ТОЛЬКО его публичный ключ.
// Расшифровать сможет только Боб.
$sealed = sodium_crypto_box_seal("Анонимное конфиденциальное письмо Бобу", $bob_pub);
$opened = sodium_crypto_box_seal_open($sealed, $bob_kp);
echo "Sealed box → Боб открыл: $opened\n";
