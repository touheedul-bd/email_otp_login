<?php
// config.php - simple .env loader
function loadEnv($path) {
    if (!file_exists($path)) return;
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        $parts = explode('=', $line, 2);
        if (count($parts) == 2) {
            $name = trim($parts[0]);
            $value = trim($parts[1]);
            if (!array_key_exists($name, $_ENV)) $_ENV[$name] = $value;
        }
    }
}
loadEnv(__DIR__ . '/.env');
// Convenience variables
$RECAPTCHA_SITE_KEY = $_ENV['RECAPTCHA_SITE_KEY'] ?? '';
$RECAPTCHA_SECRET_KEY = $_ENV['RECAPTCHA_SECRET_KEY'] ?? '';
$GMAIL_USERNAME = $_ENV['GMAIL_USERNAME'] ?? '';
$GMAIL_APP_PASSWORD = $_ENV['GMAIL_APP_PASSWORD'] ?? '';
$SMTP_HOST = $_ENV['SMTP_HOST'] ?? 'smtp.gmail.com';
$SMTP_PORT = $_ENV['SMTP_PORT'] ?? '587';
$SMTP_ENCRYPTION = $_ENV['SMTP_ENCRYPTION'] ?? 'tls';
