<?php
session_start();
require_once __DIR__ . '/config.php';
header('Content-Type: application/json; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); echo json_encode(['success'=>false,'message'=>'Method not allowed']); exit; }
if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) { echo json_encode(['success'=>false,'message'=>'Invalid CSRF']); exit; }
$otp = trim($_POST['otp'] ?? '');
if (!preg_match('/^\d{4,8}$/', $otp)) { echo json_encode(['success'=>false,'message'=>'Invalid OTP format']); exit; }
if (empty($_SESSION['pending_user'])) { echo json_encode(['success'=>false,'message'=>'No pending verification']); exit; }
$pending = $_SESSION['pending_user'];
$email = $pending['email'];
$password = $pending['password'];
$mode = $pending['mode'];
$key = 'otp_' . hash('sha256', $email);
if (empty($_SESSION['otps'][$key])) { echo json_encode(['success'=>false,'message'=>'OTP not found or expired']); exit; }
$entry = $_SESSION['otps'][$key];
if (time() > $entry['expires_at']) { unset($_SESSION['otps'][$key]); echo json_encode(['success'=>false,'message'=>'OTP expired']); exit; }
if (!password_verify($otp, $entry['otp_hash'])) { echo json_encode(['success'=>false,'message'=>'Incorrect OTP']); exit; }
unset($_SESSION['otps'][$key]);
try {
    $pdo = new PDO('sqlite:' . __DIR__ . '/users.sqlite');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) { echo json_encode(['success'=>false,'message'=>'Server DB error']); exit; }
if ($mode === 'signup') {
    $pwHash = password_hash($password, PASSWORD_DEFAULT);
    try {
        $ins = $pdo->prepare("INSERT INTO users (email, password_hash, is_verified) VALUES (:email, :ph, 1)");
        $ins->execute([':email'=>$email, ':ph'=>$pwHash]);
        $_SESSION['user_id'] = $pdo->lastInsertId();
        session_regenerate_id(true);
        unset($_SESSION['pending_user']);
        echo json_encode(['success'=>true,'message'=>'Registered','redirect'=>'index.php']); exit;
    } catch (Exception $e) {
        echo json_encode(['success'=>false,'message'=>'Registration failed (maybe email exists)']); exit;
    }
} else {
    $stmt = $pdo->prepare("SELECT id, password_hash FROM users WHERE email = :email LIMIT 1");
    $stmt->execute([':email'=>$email]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) { echo json_encode(['success'=>false,'message'=>'User not found']); exit; }
    if (!password_verify($password, $row['password_hash'])) { echo json_encode(['success'=>false,'message'=>'Invalid password']); exit; }
    $_SESSION['user_id'] = $row['id'];
    session_regenerate_id(true);
    unset($_SESSION['pending_user']);
    echo json_encode(['success'=>true,'message'=>'Logged in','redirect'=>'index.php']); exit;
}
