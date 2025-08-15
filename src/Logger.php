<?php
declare(strict_types=1);

namespace App;

final class Logger
{
    public static function event(string $event, array $data = []): void
    {
        if (!Config::DEBUG_LOGS) return;
        if (isset($data['SECRET_KEY'])) unset($data['SECRET_KEY']);
        $line = '[' . gmdate('Y-m-d\TH:i:s\Z') . '] ' . $event . ' ' .
            json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        @file_put_contents(Config::LOG_FILE, $line . PHP_EOL, FILE_APPEND);
    }
}
