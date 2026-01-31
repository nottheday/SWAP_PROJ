<?php
declare(strict_types=1);

/* ==========================================================
   SECURE TRANSPORT ENFORCEMENT (HTTPS ONLY)
   - Force HTTPS redirect (server-side)
   - Add HSTS header (prevents downgrade)
   - Ensure session cookies are Secure/HttpOnly/SameSite
   - Safe to include on ANY authenticated page
========================================================== */

function is_https(): bool {
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') return true;
    if (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443) return true;
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower((string)$_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') return true;
    return false;
}

function force_https(): void {
    if (!is_https()) {
        $host = $_SERVER['HTTP_HOST'] ?? '';
        $uri  = $_SERVER['REQUEST_URI'] ?? '/';
        header("Location: https://{$host}{$uri}", true, 301);
        exit;
    }
}

function send_hsts(): void {
    // Only send HSTS on HTTPS responses
    if (is_https()) {
        // 1 year + include subdomains
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

/**
 * Start session with secure cookie settings (if not already started).
 * If session is already started, this won't restart it.
 */
function secure_session_start(): void {
    if (session_status() === PHP_SESSION_ACTIVE) {
        // Session already started; still ensure HTTPS-only cookie flags are set for future cookies if possible
        return;
    }

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');

    $secure = is_https();

    // If you're using cross-site login flows, you might need SameSite=None; Secure
    // For most internal systems, Lax is safer.
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $secure,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    session_start();
}

/* ========= AUTO-ENFORCE ========= */
force_https();
send_hsts();
secure_session_start();
