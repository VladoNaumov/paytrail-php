<?php
declare(strict_types=1);

namespace App;

final class App
{
    public static function run(): void
    {
        $action = $_GET['action'] ?? 'create';
        $sys = new PaytrailSystem();

        switch ($action) {
            case 'success':
                $sys->renderSuccessOrCancel('success');
                break;
            case 'cancel':
                $sys->renderSuccessOrCancel('cancel');
                break;
            case 'callback':
                $sys->handleCallback();
                break;
            default:
                $sys->createAndRedirect();
        }
    }
}
