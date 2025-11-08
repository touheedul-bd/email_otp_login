<?php
session_start();
require_once __DIR__ . '/config.php';
header('Content-Type: application/json; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); echo json_encode(['success'=>false,'message'=>'Method not allowed']); exit; }
if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) { echo json_encode(['success'=>false,'message'=>'Invalid CSRF token']); exit; }
$email = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';
$mode = ($_POST['mode'] ?? 'signup') === 'login' ? 'login' : 'signup';
$recaptcha_response = $_POST['g-recaptcha-response'] ?? '';
if (empty($recaptcha_response)) { echo json_encode(['success'=>false,'message'=>'Please complete the reCAPTCHA']); exit; }
// verify reCAPTCHA server-side
$verifyUrl = 'https://www.google.com/recaptcha/api/siteverify';
$data = http_build_query(['secret'=>$RECAPTCHA_SECRET_KEY, 'response'=>$recaptcha_response, 'remoteip'=>$_SERVER['REMOTE_ADDR']]);
$opts = ['http' => ['method'=>'POST','header'=>"Content-type: application/x-www-form-urlencoded\r\n",'content'=>$data]];
$context = stream_context_create($opts);
$result = @file_get_contents($verifyUrl, false, $context);
if (!$result) { echo json_encode(['success'=>false,'message'=>'reCAPTCHA verify failed']); exit; }
$json = json_decode($result, true);
if (empty($json['success']) || $json['success'] !== true) { echo json_encode(['success'=>false,'message'=>'reCAPTCHA verification failed']); exit; }
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) { echo json_encode(['success'=>false,'message'=>'Invalid email']); exit; }
if (strlen($password) < 6) { echo json_encode(['success'=>false,'message'=>'Password must be at least 6 characters']); exit; }
// open SQLite
try {
    $pdo = new PDO('sqlite:' . __DIR__ . '/users.sqlite');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    echo json_encode(['success'=>false,'message'=>'Server DB error']); exit;
}
// check user existence by mode
$stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
$stmt->execute([':email'=>$email]);
$userExists = (bool)$stmt->fetchColumn();
if ($mode === 'signup' && $userExists) { echo json_encode(['success'=>false,'message'=>'Email already registered — choose Login']); exit; }
if ($mode === 'login' && !$userExists) { echo json_encode(['success'=>false,'message'=>'Email not found — choose Sign up']); exit; }
// rate limit: session-based per email (60 seconds)
if (!isset($_SESSION['otp_meta'])) $_SESSION['otp_meta'] = [];
$key = 'otp_' . hash('sha256', $email);
$now = time();
if (isset($_SESSION['otp_meta'][$key]) && $now - $_SESSION['otp_meta'][$key]['last_request'] < 60) {
    echo json_encode(['success'=>false,'message'=>'Please wait before requesting another OTP']); exit;
}
// generate OTP
$otp = random_int(100000, 999999);
if (!isset($_SESSION['otps'])) $_SESSION['otps'] = [];
$_SESSION['otps'][$key] = ['otp_hash'=>password_hash((string)$otp, PASSWORD_DEFAULT),'expires_at'=>$now + 300];
$_SESSION['otp_meta'][$key] = ['last_request'=>$now,'counter'=>($_SESSION['otp_meta'][$key]['counter'] ?? 0)+1];
// optional: store in otps table
try {
    $ins = $pdo->prepare("INSERT INTO otps (email, otp_hash, expires_at) VALUES (:email, :oh, :ex)");
    $ins->execute([':email'=>$email, ':oh'=>password_hash((string)$otp, PASSWORD_DEFAULT), ':ex'=>date('Y-m-d H:i:s', $now + 300)]);
} catch (Exception $e) { /* non-fatal */ }
// save pending credentials in session
$_SESSION['pending_user'] = ['email'=>$email, 'password'=>$password, 'mode'=>$mode];
// send email: try PHPMailer (if present) otherwise mail() fallback and log
$sent = false;
// If PHPMailer installed in vendor, try to use it
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    try {
        require __DIR__ . '/vendor/autoload.php';
        $mail = new PHPMailer\PHPMailer\PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = $SMTP_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = $GMAIL_USERNAME;
        $mail->Password = $GMAIL_APP_PASSWORD;
        $mail->SMTPSecure = $SMTP_ENCRYPTION === 'tls' ? PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS : PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
        $mail->Port = (int)$SMTP_PORT;
        $mail->setFrom($GMAIL_USERNAME, 'SparklyApp');
        $mail->addAddress($email);
        $mail->Subject = 'Your SparklyApp verification code';
        $mail->Body = "Your verification code is: $otp\nThis code is valid for 5 minutes.";
        $mail->send();
        $sent = true;
    } catch (Exception $e) { $sent = false; }
} else {
    $subject = 'SparklyApp verification code';
    $message = "Your verification code is: $otp\nThis code is valid for 5 minutes.";
    $headers = "From: no-reply@sparklyapp.example\r\nContent-Type: text/plain; charset=utf-8\r\n";
    try { $sent = @mail($email, $subject, $message, $headers); } catch (Exception $e) { $sent = false; }
}
@file_put_contents(__DIR__ . '/email.log', date('Y-m-d H:i:s') . " | OTP for $email : $otp\n", FILE_APPEND | LOCK_EX);
$masked = preg_replace('/(^[^@]{2}|)(.*)([^@]{2}@.*$)/', '$1***$3', $email);
$note = $sent ? 'OTP sent to your email' : 'Unable to send real email on this server; check email.log for OTP (demo mode)';
echo json_encode(['success'=>true,'emailMasked'=>$masked,'note'=>$note]);
exit;
