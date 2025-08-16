<?php
declare(strict_types=1);

namespace App;
final class Config
{

    /*
    public const MERCHANT_ID = 375917;
    public const SECRET_KEY = 'SAIPPUAKAUPPIAS';
    public const PAYTRAIL_ENDPOINT = 'https://services.paytrail.com/payments';
    public const FORCE_BASE_URL = 'https://www.encanta.fi/payment';
    public const YOUR_DOMAIN = 'www.encanta.fi';
    public const APP_PATH = '/payment';
    public const BACK_URL = 'https://encanta.fi/';
    public const LOG_FILE = __DIR__ . '/paytrail.log';
    public const DEBUG_LOGS = true;
    */

    public const MERCHANT_ID       = 375917;
    public const SECRET_KEY        = 'SAIPPUAKAUPPIAS';
    public const PAYTRAIL_ENDPOINT = 'https://services.paytrail.com/payments';
    public const FORCE_BASE_URL    = 'https://www.encanta.fi/payment';
    public const YOUR_DOMAIN       = 'encanta.fi';
    public const APP_PATH          = '/payment';
    public const BACK_URL          = 'https://encanta.fi/';
    public const LOG_FILE          = __DIR__ . '/paytrail.log';
    public const DEBUG_LOGS        = true;


    public static function baseUrl(): string
    {
        if (self::FORCE_BASE_URL !== '') {
            return rtrim(self::FORCE_BASE_URL, '/');
        }
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? self::YOUR_DOMAIN;
        $path = self::APP_PATH !== '' ? self::APP_PATH : rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/\\');
        if ($path === '') $path = '/';
        return rtrim($scheme . '://' . $host . $path, '/');
    }

    public static function selfUrl(string $query): string
    {
        return self::baseUrl() . '/index.php?' . $query;
    }
}
