<?php
declare(strict_types=1);

namespace App;

final class Views
{
    public static function e(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function resultPage(string $action, array $data): void
    {
        $title = $action === 'success' ? 'Оплата успешно завершена' : 'Оплата отменена';
        $note = $data['note'] ?? '';
        $tx = (string)($data['tx'] ?? '');
        $status = (string)($data['status'] ?? '');
        $provider = (string)($data['provider'] ?? '');
        $amount = $data['amount'] ?? null;
        $reference = (string)($data['reference'] ?? '');
        $stamp = (string)($data['stamp'] ?? '');

        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
        echo '<title>' . self::e($title) . '</title>';
        echo '<style>
            body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Helvetica,Arial,sans-serif;line-height:1.45;padding:24px;background:#f7f7f8;color:#111}
            .card{max-width:720px;margin:0 auto;background:#fff;border-radius:16px;padding:24px;box-shadow:0 8px 30px rgba(0,0,0,.06)}
            h1{margin:0 0 8px;font-size:24px}
            .ok{color:#0a7a2d}.warn{color:#a15c00}
            .grid{display:grid;grid-template-columns:160px 1fr;gap:8px 12px;margin-top:12px}
            .muted{color:#666}
            .btn{display:inline-block;margin-top:18px;padding:12px 16px;border-radius:10px;text-decoration:none;border:1px solid #ddd}
            .btn-primary{border-color:#222;color:#fff;background:#222}
            .btn + .btn{margin-left:8px}
        </style></head><body>';
        echo '<div class="card">';
        echo '<h1>' . self::e($title) . '</h1>';
        echo '<div class="' . ($action === 'success' ? 'ok' : 'warn') . '">' . self::e($note) . '</div>';

        echo '<div class="grid">';
        echo '<div class="muted">Transaction ID</div><div>' . self::e($tx) . '</div>';
        echo '<div class="muted">Status</div><div>' . self::e($status) . '</div>';
        echo '<div class="muted">Provider</div><div>' . self::e($provider) . '</div>';
        echo '<div class="muted">Amount</div><div>' . (is_numeric($amount) ? number_format(((int)$amount) / 100, 2, '.', ' ') . ' €' : self::e((string)$amount)) . '</div>';
        echo '<div class="muted">Reference</div><div>' . self::e($reference) . '</div>';
        echo '<div class="muted">Stamp</div><div>' . self::e($stamp) . '</div>';
        echo '</div>';

        echo '<div>';
        if ($action === 'success') {
            echo '<a class="btn btn-primary" href="' . self::e(Config::BACK_URL) . '">← Назад в магазин</a>';
        } else {
            echo '<a class="btn" href="' . self::e(Config::baseUrl()) . '">Попробовать оплатить снова</a>';
            echo '<a class="btn" href="' . self::e(Config::BACK_URL) . '">← Назад в магазин</a>';
        }
        echo '</div>';

        echo '</div></body></html>';
    }
}
