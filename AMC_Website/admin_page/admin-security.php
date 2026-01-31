<?php
declare(strict_types=1);

require_once __DIR__ . '/../misc_security/secure-transport.php';
require_once __DIR__ . '/../misc_security/session-hardening.php';
require_once __DIR__ . '/../misc_security/sql-prevention.php';

/* ===============================
   Session init (safe)
================================ */
if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.use_strict_mode', '1');
    ini_set('session.cookie_httponly', '1');
    session_start();
}

/* =========================
   SQLi detection (GET/POST)
========================= */
if (function_exists('detect_sql_injection')) {
    detect_sql_injection($_GET);
    detect_sql_injection($_POST);
}

/* ===============================
   ✅ URL Tampering Popup (ADMIN SECURITY & LOGS)
   - Any ?role=... => popup + clean reload
   - Any id/user_id/staff_id/employee_id/user param => popup + clean reload
   - Any unexpected query key => popup + clean reload
   - If URL path/filename is edited => popup + redirect to correct file
   Allowed GET keys here:
     logout
================================ */
$EXPECTED_FILE = 'admin-security.php';

function adminsecurity_clean_url(array $removeKeys = ['role','id','user_id','staff_id','employee_id','user']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);

    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function adminsecurity_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) $_SESSION['flash_unauth'] = 1;

    $clean = adminsecurity_clean_url();

    if ($forcePath !== null) {
        $qPos = strpos($clean, '?');
        $qs   = ($qPos !== false) ? substr($clean, $qPos) : '';
        header("Location: " . $forcePath . $qs);
        exit;
    }

    header("Location: " . $clean);
    exit;
}

/* ============================
   AUTH CHECK
============================ */
if (!isset($_SESSION['auth'], $_SESSION['user'], $_SESSION['role'])) {
    header('Location: /AMC_Website/login_page/login.php');
    exit;
}
if (strtolower((string)($_SESSION['role'] ?? '')) !== 'admin') {
    http_response_code(403);
    die("Access Denied: Admin only");
}

$username = (string)($_SESSION['user'] ?? '');
$role     = (string)($_SESSION['role'] ?? '');

/* ===============================
   Force correct filename if URL path is edited
================================ */
$currentFile = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '');
if ($currentFile !== '' && strtolower($currentFile) !== strtolower($EXPECTED_FILE)) {
    adminsecurity_redirect_clean(true, $EXPECTED_FILE);
}

/* ===============================
   Detect ANY unexpected query keys (URL edited)
================================ */
$allowedKeys = ['logout'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        adminsecurity_redirect_clean(true);
    }
}

/* ===============================
   Explicit tamper triggers
================================ */
if (isset($_GET['role'])) {
    // ANY role param triggers popup (even if it matches)
    adminsecurity_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['user_id']) || isset($_GET['staff_id']) || isset($_GET['employee_id']) || isset($_GET['user'])) {
    adminsecurity_redirect_clean(true);
}

/* ============================
   LOGOUT handling (keep original behavior)
============================ */
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header('Location: /AMC_Website/login.php');
    exit;
}

/* ============================
   DB CONNECTION
============================ */
$db_host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "swap";

$mysqli = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($mysqli->connect_error) die("DB connection failed: " . $mysqli->connect_error);
$mysqli->set_charset("utf8mb4");

/* ============================
   ADMIN INFO
============================ */
$admin_name = 'Admin';
$email = '';
$job_title = '';

$stmt = $mysqli->prepare("
    SELECT s.name, s.email, s.job_title
    FROM users u
    JOIN staff s ON u.staff_id=s.id
    WHERE u.username=?
");
if ($stmt) {
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->bind_result($admin_name, $email, $job_title);
    $stmt->fetch();
    $stmt->close();
}

/* ============================
   SECURITY LOGS
============================ */
$logs = $mysqli->query("SELECT username, ip, success, time FROM login_audit ORDER BY time DESC");

/* ============================
   STATS (kept, even if not displayed)
============================ */
$total_staff = (int)($mysqli->query("SELECT COUNT(*) as total FROM staff WHERE status='active'")->fetch_assoc()['total'] ?? 0);
$total_depts = (int)($mysqli->query("SELECT COUNT(*) as total FROM department")->fetch_assoc()['total'] ?? 0);
$expired_certs = (int)($mysqli->query("SELECT COUNT(*) as total FROM staff_certification WHERE expiry_date < CURDATE()")->fetch_assoc()['total'] ?? 0);

/* ============================
   LOGIN SUMMARY
============================ */
$total_success = (int)($mysqli->query("SELECT COUNT(*) as total FROM login_audit WHERE success=1")->fetch_assoc()['total'] ?? 0);
$total_fail    = (int)($mysqli->query("SELECT COUNT(*) as total FROM login_audit WHERE success=0")->fetch_assoc()['total'] ?? 0);

/* ============================
   LOGIN SUMMARY BY USER
============================ */
$user_summary = [];
$result = $mysqli->query("
    SELECT username,
        SUM(success=1) as success_count,
        SUM(success=0) as fail_count
    FROM login_audit
    GROUP BY username
    ORDER BY username
");
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $user_summary[] = $row;
    }
}

$mysqli->close();

/* ========= One-time popup flag ========= */
$showUnauth = !empty($_SESSION['flash_unauth']);
if ($showUnauth) unset($_SESSION['flash_unauth']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AMC HR - Security & Logs</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Inter',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;}
.container{display:flex;min-height:100vh;}
.sidebar{width:280px;background:rgba(15,23,42,0.95);border-right:1px solid rgba(71,85,105,0.3);padding-top:32px;position:fixed;top:0;left:0;bottom:0;overflow-y:auto;z-index:100;}
.sidebar::-webkit-scrollbar{width:6px;}
.sidebar::-webkit-scrollbar-thumb{background:rgba(96,165,250,0.3);border-radius:3px;}
.logo{padding:0 32px;margin-bottom:48px;}
.logo h1{font-size:32px;font-weight:700;background:linear-gradient(135deg,#60a5fa 0%,#3b82f6 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.logo .role-badge{display:inline-block;margin-top:8px;padding:4px 12px;background:rgba(168,85,247,0.2);border:1px solid rgba(168,85,247,0.3);border-radius:6px;font-size:12px;font-weight:600;color:#c084fc;text-transform:uppercase;}
.nav-menu{list-style:none;padding:0;margin:0;}
.nav-section-title{padding:8px 32px;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:24px;margin-bottom:8px;}
.nav-item{margin-bottom:4px;}
.nav-link{display:flex;align-items:center;gap:12px;padding:12px 32px;color:#94a3b8;text-decoration:none;font-size:14px;font-weight:500;border-left:3px solid transparent;border-radius:6px;transition:all 0.2s ease;white-space:nowrap;}
.nav-link:hover{background:rgba(59,130,246,0.1);color:#60a5fa;border-left-color:#3b82f6;}
.nav-link.active{background:rgba(59,130,246,0.15);color:#60a5fa;border-left-color:#3b82f6;}
.nav-icon{font-size:18px;width:20px;text-align:center;}
.main-content{flex:1;margin-left:280px;padding:32px 48px;}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:48px;gap:20px;}
.welcome-section h1{
    font-size:32px;
    font-weight:700;
    margin-bottom:8px;
    background:linear-gradient(135deg,#60a5fa,#3b82f6);
    -webkit-background-clip:text;
    -webkit-text-fill-color:transparent;
}
.welcome-section p { color: #94a3b8; font-size: 14px; }.user-info { text-align: right; }
.user-info .name { font-weight: 600;font-size: 16px;color: #e2e8f0;margin-bottom: 4px;}
.user-info .role { font-size: 13px; color: purple; margin-bottom: 12px; }
.logout-btn{display:inline-block;padding:8px 20px;background:rgba(239,68,68,.2);border:1px solid rgba(239,68,68,.4);border-radius:8px;color:#fca5a5;text-decoration:none;font-size:13px;font-weight:600;}
.logout-btn:hover{background:rgba(239,68,68,.3);}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:24px;margin-bottom:48px;}
.stat-card{padding:28px;background:rgba(30,41,59,0.6);border:1px solid rgba(71,85,105,0.3);border-radius:16px;transition:all 0.3s ease;}
.stat-card:hover{transform:translateY(-4px);box-shadow:0 12px 32px rgba(0,0,0,0.4);border-color:rgba(96,165,250,0.5);}
.stat-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;}
.stat-label{font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;}
.stat-icon{font-size:24px;opacity:0.7;}
.stat-value{font-size:36px;font-weight:700;color:#60a5fa;line-height:1;}
.table-container{overflow-x:auto;background:rgba(30,41,59,0.6);border:1px solid rgba(71,85,105,0.3);border-radius:16px;padding:24px;margin-bottom:48px;}
.logs-table{width:100%;border-collapse:collapse;}
.logs-table th, .logs-table td{padding:12px;border-bottom:1px solid rgba(71,85,105,0.3);}
.logs-table th{color:#94a3b8;text-transform:uppercase;font-size:13px;}
.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;}
.status-dot.success{background:#22c55e;}
.status-dot.failed{background:#ef4444;}

/* ===== Unauthorised popup modal ===== */
.unauth-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;z-index:10000}
.unauth-modal{width:min(520px,92vw);background:#0b1224;border:1px solid rgba(239,68,68,.5);border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.5);overflow:hidden}
.unauth-head{padding:14px 16px;background:rgba(239,68,68,.12);border-bottom:1px solid rgba(239,68,68,.25);font-weight:900;color:#fecaca}
.unauth-body{padding:16px;color:#e2e8f0;line-height:1.5}
.unauth-actions{padding:14px 16px;display:flex;justify-content:flex-end;border-top:1px solid rgba(71,85,105,.25)}
.unauth-actions button{border-color:rgba(239,68,68,.55);background:rgba(239,68,68,.2);color:#fecaca;padding:10px 16px;border-radius:10px;border:1px solid rgba(239,68,68,.55);font-weight:800;cursor:pointer;transition:.2s}
.unauth-actions button:hover{background:rgba(239,68,68,.28)}

@media(max-width:768px){
    .sidebar{width:100%;position:relative;height:auto;border-right:none;border-bottom:1px solid rgba(71,85,105,0.3);}
    .main-content{margin-left:0;padding:20px;}
    .container{flex-direction:column;}
}
</style>
</head>
<body>

<!-- ===== Unauthorised Access Detected (shows after tampering) ===== -->
<div class="unauth-backdrop" id="unauthModal" <?php echo $showUnauth ? 'style="display:flex"' : ''; ?>>
  <div class="unauth-modal" role="dialog" aria-modal="true">
    <div class="unauth-head">⚠️Unauthorised Access Detected</div>
    <div class="unauth-body">
      Your request was blocked because the URL looked modified (role/id/query/path tampering).<br>
      You have been returned to this page safely.
    </div>
    <div class="unauth-actions">
      <button type="button" onclick="document.getElementById('unauthModal').style.display='none'">OK</button>
    </div>
  </div>
</div>

<div class="container">
    <!-- Sidebar -->
    <aside class="sidebar">
        <div class="logo">
            <h1>AMC HR</h1>
            <span class="role-badge">Administrator</span>
        </div>
        <nav>
            <ul class="nav-menu">
                <li class="nav-item"><a href="admin-dashboard.php" class="nav-link"><span class="nav-icon">📊</span>Dashboard</a></li>
                <li class="nav-section-title">Management</li>
                <li class="nav-item"><a href="admin-users.php" class="nav-link"><span class="nav-icon">👥</span>Manage Users</a></li>
                <li class="nav-item"><a href="admin-departments.php" class="nav-link"><span class="nav-icon">🏢</span>Departments</a></li>
                <li class="nav-section-title">Operations</li>
                <li class="nav-item"><a href="admin-leave-management.php" class="nav-link"><span class="nav-icon">📅</span>Leave Management</a></li>
                <li class="nav-item"><a href="admin-training.php" class="nav-link"><span class="nav-icon">🎓</span>Training</a></li>
                <li class="nav-item"><a href="admin-certifications.php" class="nav-link"><span class="nav-icon">📜</span>Certifications</a></li>
                <li class="nav-section-title">System</li>
                <li class="nav-item"><a href="admin-reports.php" class="nav-link"><span class="nav-icon">📈</span>Reports</a></li>
                <li class="nav-item"><a href="admin-security.php" class="nav-link active"><span class="nav-icon">🔒</span>Security & Logs</a></li>
            </ul>
        </nav>
    </aside>

    <main class="main-content">
        <header class="header">
            <div class="welcome-section">
                <h1>Security & Logs</h1>
                <p>Overview of Security and Login Logs</p>
            </div>
            <div class="user-info">
                <div class="name"><?php echo htmlspecialchars((string)$admin_name, ENT_QUOTES, 'UTF-8') ?></div>
                <div class="role"><?php echo htmlspecialchars((string)$role, ENT_QUOTES, 'UTF-8'); ?></div>
                <a href="?logout=1" class="logout-btn">Logout</a>
            </div>
        </header>

        <!-- Login Summary -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-header"><span class="stat-label">Total Success</span><span class="stat-icon">✅</span></div>
                <div class="stat-value"><?php echo (int)$total_success; ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-header"><span class="stat-label">Total Fail</span><span class="stat-icon">❌</span></div>
                <div class="stat-value" style="color:#f87171;"><?php echo (int)$total_fail; ?></div>
            </div>
        </div>

        <!-- Summary by User -->
        <div class="table-container">
            <h3>Login Summary by User</h3>
            <table class="logs-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Success</th>
                        <th>Fail</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach($user_summary as $u): ?>
                    <tr>
                        <td><?php echo htmlspecialchars((string)$u['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                        <td><?php echo (int)$u['success_count']; ?></td>
                        <td style="color:#f87171;"><?php echo (int)$u['fail_count']; ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <!-- Full Logs Table -->
        <div class="table-container">
            <h3>Full Security Logs</h3>
            <table class="logs-table">
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Username</th>
                        <th>IP Address</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($logs): ?>
                        <?php while($log = $logs->fetch_assoc()): ?>
                        <tr>
                            <td>
                                <span class="status-dot <?php echo ((int)$log['success'] === 1) ? 'success' : 'failed'; ?>"></span>
                                <?php echo ((int)$log['success'] === 1) ? 'Success' : 'Failed'; ?>
                            </td>
                            <td><?php echo htmlspecialchars((string)$log['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars((string)$log['ip'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars(date('M d, Y H:i', strtotime((string)$log['time'])), ENT_QUOTES, 'UTF-8'); ?></td>
                        </tr>
                        <?php endwhile; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </main>
</div>
</body>
</html>
