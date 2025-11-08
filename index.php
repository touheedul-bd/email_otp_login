<?php
session_start();
require_once __DIR__ . '/config.php';
$csrf = $_SESSION['csrf_token'] ?? ($_SESSION['csrf_token'] = bin2hex(random_bytes(16)));
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SparklyApp — Sign up / Login (Email OTP)</title>
<link rel="stylesheet" href="assets/style.css">
<script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>
<body>
<main class="hero">
  <div class="card auth-card">
    <h1>Welcome to SparklyApp</h1>
    <p>Sign up or Login using your email. We'll send a one-time code to verify you.</p>
    <form id="authForm" action="send_otp.php" method="POST" autocomplete="off">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
      <label>Email address</label>
      <input id="email" name="email" type="email" placeholder="you@example.com" required>
      <label>Password</label>
      <div class="password-wrapper">
        <input id="password" name="password" type="password" minlength="6" required>
        <button type="button" class="pwd-toggle" id="pwdToggle" aria-label="toggle password"><span id="pwdIcon">🙈</span></button>
      </div>
      <div class="segmented">
        <label><input type="radio" name="mode" value="signup" checked> Sign up</label>
        <label><input type="radio" name="mode" value="login"> Login</label>
      </div>
      <div class="g-recaptcha" data-sitekey="<?= htmlspecialchars($RECAPTCHA_SITE_KEY) ?>"></div>
      <div style="margin-top:12px;">
        <button id="submitBtn" type="submit" class="primary">Send OTP to Email</button>
      </div>
    </form>
    <div id="formMessage" role="status" aria-live="polite"></div>
  </div>
</main>
<script src="assets/script.js"></script>
</body>
</html>
