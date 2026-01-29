<?php
/*********************************
 * AMC HR SECURE GATEWAY (ONE FILE)
 *********************************/

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();

/* ============================
   CONFIG
============================ */
$db_host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "swap";   // ✅ MATCH YOUR SQL

$BLOCK_AFTER_FAILS = 3;
$BLOCK_TIME = 300;

/* ============================
   DB CONNECT
============================ */
$mysqli = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($mysqli->connect_error) {
    http_response_code(500);
    exit(json_encode(["error" => "DB connection failed: " . $mysqli->connect_error]));
}

/* ============================
   ENSURE TABLES EXIST
============================ */
// Create ip_reputation table if it doesn't exist
$mysqli->query(
    "CREATE TABLE IF NOT EXISTS ip_reputation (
        ip VARCHAR(45) NOT NULL PRIMARY KEY,
        fails INT NOT NULL DEFAULT 0,
        blocked_until BIGINT NOT NULL DEFAULT 0
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
);

// Create login_audit table if it doesn't exist
$mysqli->query(
    "CREATE TABLE IF NOT EXISTS login_audit (
        id INT(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(45),
        ip VARCHAR(45),
        user_agent VARCHAR(255),
        success TINYINT(1),
        time DATETIME
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
);

/* ============================
   ROUTING
============================ */
$method = $_SERVER["REQUEST_METHOD"];
$action = $_GET["action"] ?? "";

/* ============================
   CLIENT INFO
============================ */
$ip  = $_SERVER["REMOTE_ADDR"];
$ua  = substr($_SERVER["HTTP_USER_AGENT"] ?? "unknown", 0, 255);
$now = time();

/* ============================
   IP REPUTATION
============================ */
$mysqli->query(
    "INSERT IGNORE INTO ip_reputation (ip,fails,blocked_until)
     VALUES ('$ip',0,0)"
);

$stmt = $mysqli->prepare(
    "SELECT fails, blocked_until FROM ip_reputation WHERE ip=?"
);
$stmt->bind_param("s", $ip);
$stmt->execute();
$stmt->bind_result($fails, $blocked_until);
$stmt->fetch();
$stmt->close();

if ($blocked_until > $now) {
    http_response_code(403);
    exit(json_encode(["error" => "IP temporarily blocked"]));
}

/* ============================
   CSRF TOKEN
============================ */
if (!isset($_SESSION["csrf"])) {
    $_SESSION["csrf"] = bin2hex(random_bytes(32));
}

if ($action === "csrf" && $method === "GET") {
    header("Content-Type: application/json");
    echo json_encode(["token" => $_SESSION["csrf"]]);
    exit;
}

/* ============================
   CAPTCHA
============================ */
if ($action === "captcha" && $method === "GET") {
    header("Content-Type: application/json");
    $a = rand(1, 100);
    $b = rand(1, 100);
    $_SESSION["captcha"] = $a + $b;
    echo json_encode(["question" => "$a + $b = ?"]);
    exit;
}

/* ============================
   LOGIN
============================ */
if ($action === "login" && $method === "POST") {
    header("Content-Type: application/json");

    $data = json_decode(file_get_contents("php://input"), true);

    /* CSRF CHECK */
    if (($data["csrf"] ?? "") !== $_SESSION["csrf"]) {
        http_response_code(403);
        exit(json_encode(["error" => "CSRF invalid"]));
    }

    /* CAPTCHA CHECK */
    if (!isset($_SESSION["captcha"]) ||
        (string)($data["captcha"] ?? "") !== (string)$_SESSION["captcha"]) {

        $fails++;
        $blocked_until = ($fails >= $BLOCK_AFTER_FAILS)
            ? $now + $BLOCK_TIME
            : 0;

        $stmt = $mysqli->prepare(
            "UPDATE ip_reputation
             SET fails=?, blocked_until=?
             WHERE ip=?"
        );
        $stmt->bind_param("iis", $fails, $blocked_until, $ip);
        $stmt->execute();
        $stmt->close();

        http_response_code(403);
        exit(json_encode(["error" => "CAPTCHA failed"]));
    }
    unset($_SESSION["captcha"]);

    /* ============================
       AUTH (MATCHES YOUR SQL)
    ============================ */
    $username = $data["username"] ?? "";
    $password = $data["password"] ?? "";
    $role     = $data["role"] ?? "";

    $stmt = $mysqli->prepare(
        "SELECT
            u.password,
            r.name AS role_name,
            u.status
         FROM users u
         JOIN role r ON u.role_id = r.id
         WHERE u.username = ?
         LIMIT 1"
    );

    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    $success = 0;

    if ($stmt->num_rows === 1) {
        $stmt->bind_result($hash, $db_role, $status);
        $stmt->fetch();

        if (
            password_verify($password, $hash) &&
            $role === $db_role &&
            ($status === NULL || $status === 'active')
        ) {
            $success = 1;
        }
    }
    $stmt->close();

    /* ============================
       LOGIN AUDIT
    ============================ */
    $stmt = $mysqli->prepare(
        "INSERT INTO login_audit
         (username, ip, user_agent, success, time)
         VALUES (?,?,?,?,NOW())"
    );
    $stmt->bind_param("ssii", $username, $ip, $ua, $success);
    $stmt->execute();
    $stmt->close();

    if (!$success) {
        $fails++;
        $blocked_until = ($fails >= $BLOCK_AFTER_FAILS)
            ? $now + $BLOCK_TIME
            : 0;

        $stmt = $mysqli->prepare(
            "UPDATE ip_reputation
             SET fails=?, blocked_until=?
             WHERE ip=?"
        );
        $stmt->bind_param("iis", $fails, $blocked_until, $ip);
        $stmt->execute();
        $stmt->close();

        http_response_code(401);
        exit(json_encode(["error" => "Invalid credentials"]));
    }

    /* RESET FAIL COUNTER */
    $stmt = $mysqli->prepare(
        "UPDATE ip_reputation
         SET fails=0, blocked_until=0
         WHERE ip=?"
    );
    $stmt->bind_param("s", $ip);
    $stmt->execute();
    $stmt->close();

    /* SESSION AUTH */
    $_SESSION["auth"] = true;
    $_SESSION["user"] = $username;
    $_SESSION["role"] = $db_role;

    echo json_encode([
        "success" => true,
        "redirect" => [
            "staff"      => "staff-dashboard.php",
            "supervisor" => "sup-dashboard.php",
            "admin"      => "admin-dashboard.php"
        ][$db_role] ?? "website.html"
    ]);
    exit;
}

/* ============================
   AUTH GUARD
============================ */
function auth_guard($role = null) {
    if (!isset($_SESSION["auth"])) {
        header("Location: index.php");
        exit;
    }
    if ($role && ($_SESSION["role"] ?? "") !== $role) {
        http_response_code(403);
        exit("Forbidden");
    }
}
?>



<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AMC HR Secure Gateway</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<style>
  body {
    margin: 0;
    font-family: "Segoe UI", Arial, sans-serif;
    background: linear-gradient(120deg,#020617,#0f172a);
    color: #e5e7eb;
    height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
    overflow: hidden;
  }
  .login-box {
    background: #020617;
    padding: 40px;
    border-radius: 14px;
    width: 380px;
    box-shadow: 0 0 25px rgba(0,0,0,0.6);
    border: 1px solid #1e293b;
    transition: transform 0.2s;
  }
  h2 { text-align: center; margin-bottom: 25px; color: #60a5fa; letter-spacing: 1px; }
  
  input, select, button {
    width: 100%;
    padding: 12px;
    margin-top: 12px;
    border-radius: 6px;
    border: 1px solid #334155;
    background: #0f172a;
    color: white;
    outline: none;
    box-sizing: border-box;
  }
  input:focus, select:focus { border-color: #2563eb; }
  
  button {
    background: #2563eb;
    border: none;
    font-weight: bold;
    cursor: pointer;
    margin-top: 20px;
    transition: 0.3s;
  }
  button:disabled { 
    background: #1e293b; 
    cursor: not-allowed; 
    opacity: 0.4; 
    color: #94a3b8;
  }
  button:hover:not(:disabled) { background: #1d4ed8; }
  
  .error { color: #f87171; margin-top: 15px; text-align: center; font-size: 13px; font-weight: 500; min-height: 18px; }
  
  .captcha-container {
    margin-top: 15px;
    padding: 12px;
    background: #1e293b;
    border-radius: 6px;
    text-align: center;
    border: 1px dashed #334155;
  }
  .captcha-q { font-weight: bold; color: #facc15; font-size: 1.1rem; }
  .hp-field { position: absolute; left: -9999px; }

  .shake { animation: shake 0.4s; }
  @keyframes shake {
    0%, 100% { transform: translateX(0); }
    25% { transform: translateX(-8px); }
    75% { transform: translateX(8px); }
  }
</style>
</head>

<body>

<div class="login-box" id="loginBox">
  <h2>AMC HR Gateway</h2>

  <input type="text" id="hp_field" class="hp-field" tabindex="-1" autocomplete="off">

  <input id="username" placeholder="Employee ID" maxlength="15" autocomplete="off" oninput="checkForm()">
  <input id="password" type="password" placeholder="Password" oninput="checkForm()">

  <select id="role" onchange="checkForm()">
    <option value="">Select Role</option>
    <option value="staff">Staff</option>
    <option value="supervisor">Supervisor</option>
    <option value="admin">System Administrator</option>
  </select>

  <div class="captcha-container">
    <p style="margin-bottom: 8px; font-size: 14px; color: #94a3b8;">Security Check</p>
    <span id="math-q" class="captcha-q"></span>
    <input type="number" id="math-ans" placeholder="Answer" oninput="checkForm()">
  </div>

  <button id="auth-btn" onclick="login()" disabled>Authenticate</button>
  <div id="error" class="error"></div>
</div>

<script>
const MAX_ATTEMPTS = 3;
let csrfToken = "";

// On page load
window.onload = async () => {
    await loadCSRF();
    await loadCaptcha();
    checkLockout();
};

// Fetch CSRF token from login.php
async function loadCSRF() {
    try {
        const res = await fetch("?action=csrf", { credentials: "same-origin" });
        const data = await res.json();
        csrfToken = data.token || "";
    } catch (err) {
        document.getElementById("error").innerText = "Failed to fetch CSRF token";
        console.error(err);
    }
}

// Enable/disable login button
function checkForm() {
    const u = document.getElementById("username").value.trim();
    const p = document.getElementById("password").value.trim();
    const r = document.getElementById("role").value;
    const a = document.getElementById("math-ans").value.trim();
    const btn = document.getElementById("auth-btn");
    const lockUntil = localStorage.getItem("lockUntil");
    const isLocked = lockUntil && Date.now() < lockUntil;

    btn.disabled = !(u && p && r && a && !isLocked);
}

// Clear inputs + shake animation
function clearInputs() {
    document.getElementById("username").value = "";
    document.getElementById("password").value = "";
    document.getElementById("role").value = "";
    document.getElementById("math-ans").value = "";

    const box = document.getElementById("loginBox");
    box.classList.add("shake");
    setTimeout(() => box.classList.remove("shake"), 400);

    checkForm();
    document.getElementById("username").focus();
}

// Load CAPTCHA from login.php
async function loadCaptcha() {
    try {
        const res = await fetch("?action=captcha", { credentials: "same-origin" });
        const data = await res.json();
        document.getElementById("math-q").innerText = data.question || "Error loading CAPTCHA";
    } catch (err) {
        document.getElementById("error").innerText = "Failed to load CAPTCHA";
        console.error(err);
    }
}

// Login function
async function login() {
    const err = document.getElementById("error");
    err.innerText = "Authenticating...";

    try {
        const res = await fetch("?action=login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify({
                username: document.getElementById("username").value,
                password: document.getElementById("password").value,
                role: document.getElementById("role").value,
                captcha: document.getElementById("math-ans").value,
                csrf: csrfToken
            })
        });

        const data = await res.json();

        if (data.success) {
            err.innerText = "Login successful! Redirecting...";
            window.location.href = data.redirect;
        } else {
            err.innerText = data.error || "Login failed";
            clearInputs();
            await loadCaptcha();
        }

    } catch (e) {
        err.innerText = "Server error - Check browser console (F12)";
        console.error("Login error:", e);
    }
}

// Lockout timer UI
function checkLockout() {
    const lockUntil = localStorage.getItem("lockUntil");
    const err = document.getElementById("error");

    if (lockUntil && Date.now() < lockUntil) {
        const remaining = Math.ceil((lockUntil - Date.now()) / 1000);
        err.innerText = `Too many attempts. Lockout: ${remaining}s`;
        checkForm();
        setTimeout(checkLockout, 1000);
    } else if (localStorage.getItem("lockUntil")) {
        err.innerText = "";
        localStorage.removeItem("lockUntil");
        checkForm();
    }
}
</script>

</body>
</html>