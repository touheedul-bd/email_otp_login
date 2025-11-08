<?php
// db_init.php - run once, then delete or move for security
$dbfile = __DIR__ . '/users.sqlite';
if (file_exists($dbfile)) {
    echo "users.sqlite already exists.\n";
    exit;
}
try {
    $pdo = new PDO("sqlite:$dbfile");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec("CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_verified INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );");
    $pdo->exec("CREATE TABLE otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        otp_hash TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );");
    echo "Database created: users.sqlite\n";
} catch (Exception $e) {
    echo 'Error: ' . $e->getMessage();
}
