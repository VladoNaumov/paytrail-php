Вот адаптированная версия для `README.md` под GitHub:

```markdown
# Paytrail PHP Payment Demo

Тестовый модуль интеграции с [Paytrail Payment API](https://docs.paytrail.com/) на **чистом PHP**  
без использования Laravel SDK. Предназначен для локального тестирования и отладки логики оплаты.

## Возможности

- Отправка запроса **CreatePayment** (`POST /payments`) в Paytrail API.
- Приём callback-ответов (`success`, `cancel`) и валидация HMAC-подписи.
- Получение статуса платежа (`GET /payments/{transactionId}`).
- Логирование всех шагов в отдельный файл `storage/logs/paytrail.log`.

## Структура проекта

```

├── public/
│   ├── index.php          # Запуск тестового платежа
│   ├── success.php        # Обработка успешной оплаты
│   ├── cancel.php         # Обработка отмены
│   ├── status.php         # Запрос статуса платежа
├── src/
│   └── Paytrail.php       # Класс для работы с API
├── storage/
│   └── logs/
│       └── paytrail.log   # Лог-файл Paytrail
├── .env                   # Конфигурация (ID и ключ мерчанта)
├── composer.json
└── README.md

````

## Установка

```bash
git clone https://github.com/username/paytrail-php-demo.git
cd paytrail-php-demo
composer install
````

## Конфигурация

Создайте файл `.env` в корне проекта:

```env
PAYTRAIL_MERCHANT_ID=YOUR_MERCHANT_ID
PAYTRAIL_SECRET_KEY=YOUR_SECRET_KEY
BASE_URL=https://yourdomain.com
```

> **Важно:** `BASE_URL` должен быть HTTPS-доменом (не IP и не HTTP).

## Запуск (локально)

```bash
php -S 127.0.0.1:8000 -t public
```

Откройте в браузере [https://127.0.0.1:8000](https://127.0.0.1:8000)
и нажмите «Оплатить» для тестовой транзакции.

## Логи

Все действия записываются в `storage/logs/paytrail.log` с отметками времени, transactionId и статусами подписей.

## Жизненный цикл платежа

1. Пользователь нажимает **«Оплатить»**.
2. Происходит запрос `POST /payments` → Paytrail возвращает `href` для перехода на страницу оплаты.
3. Пользователь выбирает метод оплаты и подтверждает платёж.
4. Paytrail перенаправляет на `success.php` или `cancel.php` с параметрами и подписью.
5. Модуль проверяет подпись и при необходимости делает `GET /payments/{transactionId}` для проверки статуса.
6. Результаты пишутся в лог.

---

**Назначение проекта**
Минимальный, понятный пример работы с Paytrail API на PHP для тестирования, обучения и быстрой интеграции в существующие проекты.

```

---
```
