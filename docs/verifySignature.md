
````md
# Paytrail подписи: практический учебник (Redirect & Callback)

Цель: надёжно проверить, что запрос пришёл именно от Paytrail, а не от злоумышленника.  
Основа: **HMAC-SHA256** по канонической строке.

---

## 0) Базовая идея (на пальцах)

- Ты и Paytrail делаете **одну и ту же** «цифровую подпись» над одними и теми же данными с **секретным ключом**.
- Если твоя подпись == подписи Paytrail (`signature`) → запрос настоящий.
- Секретный ключ знаешь только ты и Paytrail → подделать подпись нельзя.

---

## 1) Канонизация (строгость важна)

1) Берём **только** параметры/заголовки, чьи имена начинаются с `checkout-`.  
2) Делаем имена **lowercase**.  
3) Сортируем **по ключу** (лексикографически).  
4) Собираем строку формата `ключ:значение`, по одному на строку.  
5) В **конце** строки — **обязательный `\n`** (перевод строки).  
6) Для **callback**: к этой строке **добавляем тело запроса (сырой JSON)** без изменения.

Подпись:  
```php
$hmac = hash_hmac('sha256', $stringToSign, $secret);
````

Сравнение (без утечек по времени):

```php
hash_equals($hmac, strtolower($signatureFromPaytrail));
```

---

## 2) Redirect (подпись без тела)

> Проверяем `signature` в query-параметрах после редиректа пользователя.

### Минимальный рабочий пример

```php
<?php
function verifyRedirectSignature(array $query, string $secret): bool
{
    if (empty($query['signature'])) return false;

    // 1) Собираем только checkout-* (lowercase ключи)
    $canon = [];
    foreach ($query as $k => $v) {
        $lk = strtolower((string)$k);
        if (str_starts_with($lk, 'checkout-')) {
            $canon[$lk] = (string)$v;
        }
    }
    if (!$canon) return false;

    // 2) Сортируем
    ksort($canon, SORT_STRING);

    // 3) Строим строку k:v + \n в конце
    $lines = [];
    foreach ($canon as $k => $v) {
        $lines[] = "{$k}:{$v}";
    }
    $stringToSign = implode("\n", $lines) . "\n";

    // 4) HMAC и сравнение
    $calc = hash_hmac('sha256', $stringToSign, $secret);
    return hash_equals($calc, strtolower((string)$query['signature']));
}
```

### Живой пример (из твоих логов)

```
checkout-account=375917
checkout-algorithm=sha256
checkout-amount=1590
checkout-stamp=order-1755294530
checkout-reference=order-1755294530
checkout-status=ok
checkout-provider=osuuspankki
checkout-transaction-id=ac718dbc-fb00-4e86-9182-5876e83a4366
signature=2f523a24c0541e2f378ffa5f281c12de8420bb5a318eadab60e659d3cadeb78c
```

Каноническая строка:

```
checkout-account:375917
checkout-algorithm:sha256
checkout-amount:1590
checkout-provider:osuuspankki
checkout-reference:order-1755294530
checkout-stamp:order-1755294530
checkout-status:ok
checkout-transaction-id:ac718dbc-fb00-4e86-9182-5876e83a4366
```

(и **ещё один `\n` в конце!**)

Секрет: `SAIPPUAKAUPPIAS`
Результат HMAC: `2f523a24c0...de` — **совпадает** с `signature` → всё ок ✅

---

## 3) Callback (подпись с телом)

> Paytrail POST’ит на твой endpoint. Подпись лежит в **заголовке** `signature`.
> Канонизация = `checkout-*` **из заголовков** + **сырой JSON body**.

### Минимальный рабочий пример

```php
<?php
function verifyCallbackSignature(array $headers, string $rawBody, string $secret): bool
{
    if (empty($headers['signature'])) return false;

    // 1) Берём только checkout-* заголовки (lowercase имена)
    $canon = [];
    foreach ($headers as $k => $v) {
        $lk = strtolower((string)$k);
        if (str_starts_with($lk, 'checkout-')) {
            $canon[$lk] = (string)$v;
        }
    }
    if (!$canon) return false;

    // 2) Сортируем
    ksort($canon, SORT_STRING);

    // 3) Строка k:v + \n
    $lines = [];
    foreach ($canon as $k => $v) {
        $lines[] = "{$k}:{$v}";
    }
    $stringToSign = implode("\n", $lines) . "\n";

    // 4) ВАЖНО: + сырое тело БЕЗ изменений
    $stringToSign .= $rawBody;

    // 5) HMAC и сравнение
    $calc = hash_hmac('sha256', $stringToSign, $secret);
    return hash_equals($calc, strtolower((string)$headers['signature']));
}
```

### Как получить данные в «голом» PHP

```php
$rawBody = file_get_contents('php://input'); // СЫРОЙ JSON без декодирования
$headers = array_change_key_case(getallheaders() ?: [], CASE_LOWER);

$isValid = verifyCallbackSignature($headers, $rawBody, $_ENV['PAYTRAIL_SECRET']);
```

> В **Laravel**: `$rawBody = request()->getContent(); $headers = array_change_key_case(request()->headers->all(), CASE_LOWER);`
> (нормализуй до вида `['checkout-account' => '...', ...]`, т.к. в Laravel хедеры — массивы значений).

---

## 4) Универсальные вспомогательные функции

```php
<?php
function buildCanonicalString(array $pairs, ?string $rawBody = null): string {
    $canon = [];

    // Берём только checkout-* (lowercase)
    foreach ($pairs as $k => $v) {
        $lk = strtolower((string)$k);
        if (str_starts_with($lk, 'checkout-')) {
            // В заголовках иногда массивы — схлопнем
            if (is_array($v)) $v = implode(',', $v);
            $canon[$lk] = (string)$v;
        }
    }

    ksort($canon, SORT_STRING);

    $lines = [];
    foreach ($canon as $k => $v) $lines[] = "{$k}:{$v}";

    $s = implode("\n", $lines) . "\n";
    if ($rawBody !== null) $s .= $rawBody; // только для callback
    return $s;
}

function calculateSignature(string $canonical, string $secret): string {
    return hash_hmac('sha256', $canonical, $secret);
}

function secureEquals(string $a, string $b): bool {
    return hash_equals($a, strtolower($b));
}
```

Примеры использования:

```php
// Redirect:
$canonical = buildCanonicalString($_GET, null);
$calc = calculateSignature($canonical, $_ENV['PAYTRAIL_SECRET']);
$ok = secureEquals($calc, $_GET['signature'] ?? '');

// Callback:
$raw = file_get_contents('php://input');
$headers = array_change_key_case(getallheaders() ?: [], CASE_LOWER);
$canonical = buildCanonicalString($headers, $raw);
$calc = calculateSignature($canonical, $_ENV['PAYTRAIL_SECRET']);
$ok = secureEquals($calc, $headers['signature'] ?? '');
```

---



## 6) Тест-данные (быстрая проверка руками)

```php
// Redirect sample
$stringToSign =
    "checkout-account:375917\n" .
    "checkout-algorithm:sha256\n" .
    "checkout-amount:1590\n" .
    "checkout-provider:osuuspankki\n" .
    "checkout-reference:order-1755294530\n" .
    "checkout-stamp:order-1755294530\n" .
    "checkout-status:ok\n" .
    "checkout-transaction-id:ac718dbc-fb00-4e86-9182-5876e83a4366\n";

$secret = "SAIPPUAKAUPPIAS";
echo hash_hmac('sha256', $stringToSign, $secret);
// => 2f523a24c0541e2f378ffa5f281c12de8420bb5a318eadab60e659d3cadeb78c
```

## 7) Частые ошибки (и как не словить боль)

* ❌ **Нет `\n` в конце канонической строки** → подпись не совпадёт.
  ✅ Всегда добавляй завершающий перенос строки.

* ❌ **Ключи не в lowercase** или не отсортированы.
  ✅ Всегда `strtolower` имён и `ksort`.

* ❌ **Мутировал тело callback (переформатировал JSON)**.
  ✅ Используй **сырой** поток `php://input` / `$request->getContent()`.

* ❌ **Секрет в коде/репозитории**.
  ✅ Храни в `.env`, доступ ограничен, ротация при утечке.

* ❌ **Повторная обработка одного и того же платежа**.
  ✅ Сделай обработку **идемпотентной** по `transaction-id`.

* ❌ **HTTP вместо HTTPS**.
  ✅ Только HTTPS.

---

## 8) Мини-чеклист безопасности

* [ ] `PAYTRAIL_SECRET` в `.env`, длинный случайный (32+ байта).
* [ ] Redirect проверяется middleware’ом.
* [ ] Callback проверяется до парсинга JSON.
* [ ] Все сравнения через `hash_equals`.
* [ ] Логи без секрета, ограниченный доступ.
* [ ] Сверяю `stamp/reference/amount/currency` с заказом.
* [ ] Идемпотентность по `transaction-id`.
* [ ] HTTPS везде.

---

## 9) Готовая «универсальная» обёртка

```php
<?php
final class PaytrailVerifier
{
    public function __construct(private string $secret) {}

    public function verifyRedirect(array $query): bool
    {
        if (empty($query['signature'])) return false;
        $canonical = buildCanonicalString($query, null);
        $calc = calculateSignature($canonical, $this->secret);
        return hash_equals($calc, strtolower((string)$query['signature']));
    }

    public function verifyCallback(array $headers, string $rawBody): bool
    {
        if (empty($headers['signature'])) return false;
        $canonical = buildCanonicalString($headers, $rawBody);
        $calc = calculateSignature($canonical, $this->secret);
        return hash_equals($calc, strtolower((string)$headers['signature']));
    }
}
```

Использование:

```php
$verifier = new PaytrailVerifier($_ENV['PAYTRAIL_SECRET']);

if (!$verifier->verifyRedirect($_GET)) {
    abort(403);
}

$raw = file_get_contents('php://input');
$hdr = array_change_key_case(getallheaders() ?: [], CASE_LOWER);
if (!$verifier->verifyCallback($hdr, $raw)) {
    http_response_code(403);
    exit('Invalid signature');
}
```

---

## 10) Итог

* Математика — простая: **одинаковые данные + общий секрет → одинаковая подпись**.
* Сложность — в строгости «канонизации» и аккуратном обращении с «сырым» телом.
* Сделай один раз правильно — и подписи будут сходиться как часы.

```

```

