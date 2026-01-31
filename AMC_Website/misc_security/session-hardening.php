<?php
declare(strict_types=1);
require_once __DIR__ . '/../misc_security/secure-transport.php';

/* ==========================================================
   SESSION HARDENING (ANTI-HIJACK)
   - Include this near the top of every protected page
   - Works even if session_start() already happened, but best
     practice: include BEFORE session_start() if possible.
========================================================== */

/* ---------- Config (edit if you want) ---------- */
const SESSION_IDLE_TIMEOUT_SECONDS = 30 * 60;  // 30 min idle
const SESSION_ABSOLUTE_LIFETIME_SECONDS = 8 * 60 * 60; // 8 hours
const SESSION_REGEN_INTERVAL_SECONDS = 10 * 60; // regenerate every 10 min

/**
 * Use a "soft" IP binding to reduce false positives:
 * - If IPv4: bind to first 3 octets (e.g., 203.0.113.*)
 * - If IPv6: bind to first 4 hextets
 */
function ip_prefix(string $ip): string {
    if ($ip === '') return '';
    if (strpos($ip, ':') !== false) { // IPv6
        $parts = explode(':', $ip);
        $parts = array_slice($parts, 0, 4);
        return implode(':', $parts);
    }
    // IPv4
    $parts = explode('.', $ip);
    if (count($parts) >= 3) return $parts[0] . '.' . $parts[1] . '.' . $parts[2];
    return $ip;
}

function hard_logout_to_login(string $reason = 'session'): void {
    // Clear session data safely
    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION = [];

        // delete session cookie
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], (bool)$params['secure'], (bool)$params['httponly']);

        session_destroy();
    }

    header("Location: login.php?err=" . urlencode($reason));
    exit;
}

/* ---------- Start / Harden session ---------- */
function session_harden(): void {
    // --- Force HTTPS (redirect) ---
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
    $httpsUrl = "https://" . ($_SERVER['HTTP_HOST'] ?? '') . ($_SERVER['REQUEST_URI'] ?? '/');
    header("Location: " . $httpsUrl, true, 301);
    exit;
}

// --- HSTS (only when on HTTPS) ---
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');

    // If session NOT started yet, set ini params first (best case)
    if (session_status() !== PHP_SESSION_ACTIVE) {
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.cookie_httponly', '1');

        // PHP 7.3+ supports samesite via cookie params string
        $secure = is_https();

        // Ensure a strong session id
        ini_set('session.sid_length', '48');
        ini_set('session.sid_bits_per_character', '6');

        // Set cookie params (applies when session cookie is sent)
        $cookieParams = [
            'lifetime' => 0,
            'path'     => '/',
            'domain'   => '',
            'secure'   => $secure,
            'httponly' => true,
            'samesite' => 'Lax', // Lax is safer than None for most school projects
        ];
        session_set_cookie_params($cookieParams);

        session_start();
    } else {
    // Session already active; cannot change session ini settings now.
    }


    // Basic "created" time for absolute lifetime
    if (!isset($_SESSION['_created_at'])) {
        $_SESSION['_created_at'] = time();
    } else {
        if (time() - (int)$_SESSION['_created_at'] > SESSION_ABSOLUTE_LIFETIME_SECONDS) {
            hard_logout_to_login('expired');
        }
    }

    // Idle timeout
    if (!isset($_SESSION['_last_activity'])) {
        $_SESSION['_last_activity'] = time();
    } else {
        if (time() - (int)$_SESSION['_last_activity'] > SESSION_IDLE_TIMEOUT_SECONDS) {
            hard_logout_to_login('idle');
        }
    }
    $_SESSION['_last_activity'] = time();

    // Fingerprint binding (anti-hijack)
    $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    $fp = hash('sha256', ip_prefix($ip) . '|' . $ua);

    if (!isset($_SESSION['_fingerprint'])) {
        $_SESSION['_fingerprint'] = $fp;
    } else {
        if (!hash_equals((string)$_SESSION['_fingerprint'], $fp)) {
            // possible hijack (UA/IP changed)
            hard_logout_to_login('hijack');
        }
    }

    // Periodic session id regeneration (reduces fixation/hijack usefulness)
    if (!isset($_SESSION['_last_regen'])) {
        $_SESSION['_last_regen'] = time();
    } else {
        if (time() - (int)$_SESSION['_last_regen'] > SESSION_REGEN_INTERVAL_SECONDS) {
            session_regenerate_id(true);
            $_SESSION['_last_regen'] = time();
        }
    }
}

/* ==========================================================
   OPTIONAL: Call this right after login success
   (to rotate session id immediately on authentication)
========================================================== */
function session_on_login_success(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_harden();
    }

    // Rotate immediately after authentication to prevent fixation
    session_regenerate_id(true);
    $_SESSION['_last_regen'] = time();

    // Re-seed fingerprint at the moment of login
    $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    $_SESSION['_fingerprint'] = hash('sha256', ip_prefix($ip) . '|' . $ua);

    // Reset timers
    $_SESSION['_created_at'] = time();
    $_SESSION['_last_activity'] = time();
}

/* ---------- AUTO-RUN ---------- */
session_harden();
