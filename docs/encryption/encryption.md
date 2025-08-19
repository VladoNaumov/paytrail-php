Ниже — короткие, **практичные** примеры для PHP 8.1:

1. «Обычное» шифрование (на одном сервере/между своими сервисами).
2. **Сквозное (E2E)** шифрование — когда только отправитель и получатель могут прочитать сообщение.

Я покажу два безопасных варианта: через **libsodium** (рекомендуется) и через **OpenSSL AES-GCM** (тоже ок, если всё сделать правильно).

---

# 1) Обычное симметричное шифрование (shared secret)

## Вариант А: libsodium (рекомендуется)

Использует XChaCha20-Poly1305 с аутентификацией (AEAD).
Ключ один и тот же у шифрующей и расшифровывающей стороны.

```php
<?php
// php >= 7.2 уже с sodium. Убедись, что ext-sodium включен.
$message = "Привет, мир!";
$key = sodium_crypto_secretbox_keygen();   // 32 байта секретного ключа
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES); // 24 байта

$cipher = sodium_crypto_secretbox($message, $nonce, $key);

// передаём/храним: nonce + cipher (лучше в base64)
$packed = base64_encode($nonce . $cipher);

// ====== Расшифровка ======
$decoded = base64_decode($packed, true);
$nonce2  = substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$cipher2 = substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

$plain = sodium_crypto_secretbox_open($cipher2, $nonce2, $key);
if ($plain === false) {
    throw new RuntimeException("Не удалось расшифровать/подпись не сошлась");
}
echo $plain; // "Привет, мир!"
```

Что важно:

* **Каждый раз новый nonce** (`random_bytes(24)`).
* Храним/передаём `nonce||ciphertext`.
* Если `open()` вернул `false`, сообщение сломано/подмена.

## Вариант Б: OpenSSL AES-256-GCM

Тоже AEAD, но важно правильно упаковать IV и tag.

```php
<?php
$message = "Привет, мир!";
$key = random_bytes(32);                       // 256-битный ключ
$iv  = random_bytes(12);                       // 96-битный IV для GCM
$tag = '';                                     // сюда OpenSSL запишет тег

$cipher = openssl_encrypt(
    $message,
    'aes-256-gcm',
    $key,
    OPENSSL_RAW_DATA,
    $iv,
    $tag,      // будет 16 байт
    ""         // optional AAD, можно добавить контекст/метаданные
);

// упаковка: iv | tag | ciphertext
$packed = base64_encode($iv . $tag . $cipher);

// ====== Расшифровка ======
$decoded = base64_decode($packed, true);
$iv2   = substr($decoded, 0, 12);
$tag2  = substr($decoded, 12, 16);
$ciph2 = substr($decoded, 28);

$plain = openssl_decrypt(
    $ciph2,
    'aes-256-gcm',
    $key,
    OPENSSL_RAW_DATA,
    $iv2,
    $tag2,
    "" // AAD — должна совпасть, если использовали
);

if ($plain === false) {
    throw new RuntimeException("Не удалось расшифровать/аутентификация не прошла");
}
echo $plain;
```

---

# 2) Сквозное шифрование (End-to-End)

Идея: у каждого участника **своя пара ключей** (публичный/секретный).
Отправитель шифрует на **публичный ключ получателя** → прочитать может только получатель (у него есть секретный ключ).
Для аутентичности добавляем **подпись** (чтобы быть уверенным в отправителе).

## 2.1. E2E «конверт» с `crypto_box` (Curve25519 + XChaCha20-Poly1305)

### Генерация ключей (один раз на пользователя)

```php
<?php
// У каждого участника:
$keypair = sodium_crypto_box_keypair();
$public  = sodium_crypto_box_publickey($keypair);
$secret  = sodium_crypto_box_secretkey($keypair);

// Сохраняем public (можно публиковать), secret — строго конфиденциально
```

### Отправка сообщения (A → B)

```php
<?php
$alice_keypair = /* ключи Алисы */;
$bob_public    = /* публичный ключ Боба */;

$nonce   = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
$message = "Привет, Боб!";

$cipher = sodium_crypto_box(
    $message,
    $nonce,
    sodium_crypto_box_keypair_from_secretkey_and_publickey(
        sodium_crypto_box_secretkey($alice_keypair),
        $bob_public
    )
);

// Передаём Бобу: nonce + cipher + (опционально публичный ключ Алисы, если не известен)
$packet = base64_encode($nonce . $cipher);
```

### Получение сообщения (B расшифровывает)

```php
<?php
$bob_keypair = /* ключи Боба */;
$alice_public = /* публичный ключ Алисы */;

$decoded = base64_decode($packet, true);
$nonce2  = substr($decoded, 0, SODIUM_CRYPTO_BOX_NONCEBYTES);
$ciph2   = substr($decoded, SODIUM_CRYPTO_BOX_NONCEBYTES);

$plain = sodium_crypto_box_open(
    $ciph2,
    $nonce2,
    sodium_crypto_box_keypair_from_secretkey_and_publickey(
        sodium_crypto_box_secretkey($bob_keypair),
        $alice_public
    )
);

if ($plain === false) {
    throw new RuntimeException("Не удалось открыть коробку (не тот ключ/подмена)");
}
echo $plain;
```

> Примечание: Если не нужен «отправитель с подписью», можно использовать **sealed boxes** (`sodium_crypto_box_seal()`/`_open()`): отправителю не нужен свой ключ, только публичный ключ получателя. Получатель единственный может открыть.

```php
// Отправка без ключей отправителя:
$cipher = sodium_crypto_box_seal($message, $bob_public);

// Расшифровка у получателя:
$plain = sodium_crypto_box_seal_open($cipher, $bob_keypair);
```

## 2.2. Подпись сообщений (аутентичность отправителя)

Подписываем Ed25519 и отправляем вместе с сообщением (или подписываем уже шифротекст — оба подхода встречаются).

```php
<?php
// Генерация пары для подписи:
$sign_kp   = sodium_crypto_sign_keypair();
$sign_pub  = sodium_crypto_sign_publickey($sign_kp);
$sign_sec  = sodium_crypto_sign_secretkey($sign_kp);

// Подписать:
$signed = sodium_crypto_sign($message, $sign_kp);

// Проверить и извлечь оригинал:
$orig = sodium_crypto_sign_open($signed, $sign_pub);
if ($orig === false) {
    throw new RuntimeException("Подпись неверна");
}
```

Комбинация E2E:

1. **Подписать** сообщение (или шифртекст) ключом отправителя.
2. **Зашифровать** для получателя (его публичный ключ).
3. Получатель расшифровывает и **проверяет подпись** по публичному ключу отправителя.

---

## Рекомендации и грабли

* **Генерация ключей**: только `random_bytes()`/libsodium-keygen. Не руками.
* **Nonce/IV**: всегда новый для каждого сообщения. Не повторять!
* **Аутентификация**: используйте только AEAD (secretbox, box, AES-GCM); не используйте «голый AES-CTR/CBC» без MAC.
* **Хранение ключей**: `.env` (сервер), KMS/secret manager. Никогда на фронтенд.
* **Проверка ошибок**: проверяйте `false` у `*_open()`/`openssl_decrypt()`.
* **Формат**: упаковывайте `nonce||tag||cipher` в base64/json, храните длины явно.
* **Ротация ключей**: продумайте смену ключей и идентификаторы ключей (key id) в сообщениях.
* **Sealed box** удобно\*\* для «письма в один конец» (только получатель может открыть).

---
