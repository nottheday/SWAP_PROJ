<?php
/*********************************
 * AMC HR SECURE GATEWAY (ONE FILE)
 *********************************/

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . '/./misc_security/secure-transport.php';
require_once __DIR__ . '/./misc_security/session-hardening.php';
require_once __DIR__ . '/./misc_security/sql-prevention.php';

/* ============================
   CONFIG
============================ */
$db_host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "swap";

$BLOCK_AFTER_FAILS = 3;
$BLOCK_TIME = 300;

/* ============================
   DB CONNECT
============================ */
$mysqli = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($mysqli->connect_error) {
    http_response_code(500);
    exit(json_encode(["error" => "DB connection failed"]));
    // 🔁 Reflected XSS prevented: JSON response, no HTML rendering
}

/* ============================
   ENSURE TABLES EXIST
============================ */
$mysqli->query(
    "CREATE TABLE IF NOT EXISTS ip_reputation (
        ip VARCHAR(45) NOT NULL PRIMARY KEY,
        fails INT NOT NULL DEFAULT 0,
        blocked_until BIGINT NOT NULL DEFAULT 0
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
);

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
// 💾 Stored XSS source: raw values stored, must be escaped on output elsewhere

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
    // 🔁 Reflected XSS prevented
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
    // 🔁 Reflected XSS prevented
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
    // 🔁 Reflected XSS prevented (numeric-only JSON)
    exit;
}

/* ============================
   LOGIN
============================ */
if ($action === "login" && $method === "POST") {
    header("Content-Type: application/json");

    $data = json_decode(file_get_contents("php://input"), true);

    if (($data["csrf"] ?? "") !== $_SESSION["csrf"]) {
        http_response_code(403);
        exit(json_encode(["error" => "CSRF invalid"]));
        // 🔁 Reflected XSS prevented
    }

    if (!isset($_SESSION["captcha"]) ||
        (string)($data["captcha"] ?? "") !== (string)$_SESSION["captcha"]) {

        http_response_code(403);
        exit(json_encode(["error" => "CAPTCHA failed"]));
        // 🔁 Reflected XSS prevented
    }
    unset($_SESSION["captcha"]);

    $username = $data["username"] ?? ""; // 💾 Stored XSS source
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

    $stmt = $mysqli->prepare(
        "INSERT INTO login_audit
         (username, ip, user_agent, success, time)
         VALUES (?,?,?,?,NOW())"
    );
    $stmt->bind_param("ssii", $username, $ip, $ua, $success);
    // 💾 Stored XSS: escape when rendered elsewhere
    $stmt->execute();
    $stmt->close();

    if (!$success) {
        http_response_code(401);
        exit(json_encode(["error" => "Invalid credentials"]));
        // 🔁 Reflected XSS prevented
    }

    $_SESSION["auth"] = true;
    $_SESSION["user"] = $username;
    $_SESSION["role"] = $db_role;
    session_on_login_success();

    $base_url = '/AMC_Website';
    $redirects = [
        "staff"      => $base_url . '/staff_page/staff-dashboard.php',
        "supervisor" => $base_url . '/supervisor_page/sup-dashboard.php',
        "admin"      => $base_url . '/admin_page/admin-dashboard.php'
    ];

    echo json_encode([
        "success" => true,
        "redirect" => $redirects[$db_role] ?? $base_url . '/website.html'
    ]);

    exit;

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

  <input id="username" placeholder="Username" maxlength="15" autocomplete="off" oninput="checkForm()">
  <!-- 💾 Stored / Reflected XSS source: user input -->

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
    <!-- 🧠 DOM XSS prevented: text inserted via innerText -->

    <input type="number" id="math-ans" placeholder="Answer" oninput="checkForm()">
  </div>

  <button id="auth-btn" onclick="login()" disabled>Authenticate</button>

  <div id="error" class="error"></div>
  <!-- 🧠 DOM XSS prevented: error messages set via innerText -->
</div>

<script>
// 🧠 DOM XSS PREVENTION
// No innerHTML used anywhere, innerText only

let csrfToken = "";

window.onload = async () => {
    await loadCSRF();
    await loadCaptcha();
};

async function loadCSRF() {
    const res = await fetch("?action=csrf", { credentials: "same-origin" });
    const data = await res.json();
    csrfToken = data.token || "";
}

async function loadCaptcha() {
    const res = await fetch("?action=captcha", { credentials: "same-origin" });
    const data = await res.json();
    document.getElementById("math-q").innerText = data.question;
    // 🧠 DOM XSS prevented
}

function checkForm() {
    const u = document.getElementById("username").value.trim();
    const p = document.getElementById("password").value.trim();
    const r = document.getElementById("role").value;
    const a = document.getElementById("math-ans").value.trim();
    document.getElementById("auth-btn").disabled = !(u && p && r && a);
}

async function login() {
    const err = document.getElementById("error");
    err.innerText = "Authenticating...";
    // 🧠 DOM XSS prevented

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
        window.location.href = data.redirect;
    } else {
        err.innerText = data.error || "Login failed";
        // 🧠 DOM XSS prevented
        loadCaptcha();
    }
}
</script>

</body>
</html>
