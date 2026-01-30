<?php
declare(strict_types=1);

/* ============================
   SESSION HARDENING
   Prevents session hijacking,
   fixation, and reuse
============================ */

/* ---- PHP session security ---- */
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.sid_length', '48');
ini_set('session.sid_bits_per_character', '6');

/* Detect HTTPS safely (won't break localhost) */
$isSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');

/* Cookie params */
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => $isSecure,
    'httponly' => true,
    'samesite' => 'Lax'
]);

session_start();

/* ============================
   SESSION HIJACKING PROTECTION
============================ */

/* Fingerprint: User-Agent + partial IP */
$fingerprint = hash(
    'sha256',
    ($_SERVER['HTTP_USER_AGENT'] ?? 'unknown') .
    '|' .
    substr($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0', 0, strrpos($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0', '.'))
);

/* First request → store fingerprint */
if (!isset($_SESSION['fingerprint'])) {
    $_SESSION['fingerprint'] = $fingerprint;
    $_SESSION['created_at']  = time();
}

/* Fingerprint mismatch → possible hijack */
if (!hash_equals($_SESSION['fingerprint'], $fingerprint)) {
    session_unset();
    session_destroy();
    http_response_code(403);
    exit('Session hijacking detected.');
}

/* ============================
   SESSION ID ROTATION
============================ */

/* Regenerate session ID every 5 minutes */
if (!isset($_SESSION['last_regen'])) {
    $_SESSION['last_regen'] = time();
}

if (time() - $_SESSION['last_regen'] > 300) {
    session_regenerate_id(true);
    $_SESSION['last_regen'] = time();
}
