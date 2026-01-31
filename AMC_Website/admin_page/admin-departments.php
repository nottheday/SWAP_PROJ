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
   ✅ URL Tampering Popup (ADMIN DEPARTMENTS)
   - Any ?role=... (staff/admin/supervisor etc) => popup + clean reload
   - Any id/user_id/staff_id/employee_id/user param => popup + clean reload
   - Any unexpected query key => popup + clean reload
   - If URL path/filename is edited (e.g. staff-dashboard -> admin-departments)
     => popup + redirect to correct file
   Allowed GET keys here: logout
================================ */
$EXPECTED_FILE = 'admin-departments.php';

function admindept_clean_url(array $removeKeys = ['role','id','user_id','staff_id','employee_id','user']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);

    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function admindept_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) {
        $_SESSION['flash_unauth'] = 1;
    }

    $clean = admindept_clean_url();

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
    header('Location: /AMC_Website/login.php');
    exit;
}

$username = (string)$_SESSION['user'];
$role     = strtolower((string)$_SESSION['role']);

/* ===============================
   Force correct filename if URL path is edited
================================ */
$currentFile = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '');
if ($currentFile !== '' && strtolower($currentFile) !== strtolower($EXPECTED_FILE)) {
    admindept_redirect_clean(true, $EXPECTED_FILE);
}

/* ===============================
   Detect ANY unexpected query keys (URL edited)
================================ */
$allowedKeys = ['logout'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        admindept_redirect_clean(true);
    }
}

/* ===============================
   Explicit tamper triggers
================================ */
if (isset($_GET['role'])) {
    // ANY role param triggers popup (even if it matches)
    admindept_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['user_id']) || isset($_GET['staff_id']) || isset($_GET['employee_id']) || isset($_GET['user'])) {
    admindept_redirect_clean(true);
}

/* ============================
   ROLE RESTRICTION
============================ */
if ($role !== 'admin') {
    http_response_code(403);
    die("Access Denied");
}

/* ============================
   ADMIN INFO
============================ */
$admin_data = db_one("
    SELECT s.name
    FROM users u
    JOIN staff s ON u.staff_id = s.id
    WHERE u.username = ?
", "s", [$username]);

$admin_name = htmlspecialchars($admin_data['name'] ?? 'Admin', ENT_QUOTES, 'UTF-8');

/* ============================
   DEPARTMENTS + STAFF (ACTIVE & INACTIVE)
============================ */
$rows = db_all("
    SELECT
        d.id   AS department_id,
        d.name AS department_name,
        s.name AS staff_name,
        s.status AS staff_status
    FROM department d
    LEFT JOIN staff s
        ON s.department_id = d.id
    ORDER BY d.name, s.name
");

/* ============================
   LOGOUT
============================ */
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header('Location: /AMC_Website/login.php');
    exit;
}

/* ========= One-time popup flag ========= */
$showUnauth = !empty($_SESSION['flash_unauth']);
if ($showUnauth) unset($_SESSION['flash_unauth']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AMC HR - Departments</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">

<style>
/* --- Reset & Body --- */
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Inter',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;}
.container{display:flex;min-height:100vh;}

/* --- Sidebar (MATCH DASHBOARD EXACTLY) --- */
.sidebar{
    width:280px;
    background:rgba(15,23,42,0.95);
    border-right:1px solid rgba(71,85,105,0.3);
    padding-top:32px;
    position:fixed;
    top:0; bottom:0; left:0;
    overflow-y:auto;
}
.sidebar::-webkit-scrollbar{width:6px;}
.sidebar::-webkit-scrollbar-thumb{background:rgba(96,165,250,0.3);border-radius:3px;}

.logo{padding:0 32px;margin-bottom:48px;}
.logo h1{font-size:32px;font-weight:700;background:linear-gradient(135deg,#60a5fa,#3b82f6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.role-badge{display:inline-block;margin-top:8px;padding:4px 12px;background:rgba(168,85,247,0.2);border:1px solid rgba(168,85,247,0.3);border-radius:6px;font-size:12px;font-weight:600;color:#c084fc;text-transform:uppercase;}

.nav-menu{list-style:none;}
.nav-section-title{padding:8px 32px;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:24px;margin-bottom:8px;}
.nav-item{margin-bottom:4px;}

.nav-link{
    display:flex;
    align-items:center;
    gap:12px;
    padding:12px 32px;
    color:#94a3b8;
    text-decoration:none;
    font-size:14px;
    font-weight:500;
    transition:all 0.2s ease;
    border-left:3px solid transparent;
}
.nav-link:hover{background: rgba(59,130,246,0.1);color:#60a5fa;border-left-color:#3b82f6;}
.nav-link.active{background: rgba(59,130,246,0.15);color:#60a5fa;border-left-color:#3b82f6;}
.nav-icon{font-size:18px;width:20px;text-align:center;}

/* --- Main Content --- */
.main-content{flex:1;margin-left:280px;padding:32px 48px;}

/* --- Header --- */
.header{
    display:flex;
    justify-content:space-between;
    align-items:center;
    margin-bottom:32px;
    padding-bottom:24px;
    border-bottom:1px solid rgba(71,85,105,.3);
}
.welcome-section h1{
    font-size:32px;
    font-weight:700;
    margin-bottom:8px;
    background:linear-gradient(135deg,#60a5fa,#3b82f6);
    -webkit-background-clip:text;
    -webkit-text-fill-color:transparent;
}
.welcome-section p { color: #94a3b8; font-size: 14px; }
.user-info { text-align: right; }
.user-info .name { font-weight: 600;font-size: 16px;color: #e2e8f0;margin-bottom: 4px;}
.user-info .role { font-size: 13px; color: purple; margin-bottom: 12px; }
.logout-btn{display:inline-block;padding:8px 20px;background:rgba(239,68,68,.2);border:1px solid rgba(239,68,68,.4);border-radius:8px;color:#fca5a5;text-decoration:none;font-size:13px;font-weight:600;}
.logout-btn:hover{background:rgba(239,68,68,.3);}

/* --- Panel --- */
.panel{background:rgba(15,23,42,.6);border:1px solid rgba(71,85,105,.3);border-radius:12px;overflow:hidden;}
.panel-header{padding:20px 24px;background:rgba(30,41,59,.8);border-bottom:1px solid rgba(71,85,105,.3);}
.panel-title{font-size:16px;font-weight:700;color:#60a5fa;text-transform:uppercase;}
.panel-body{padding:24px;}

/* --- Table --- */
table{width:100%;border-collapse:collapse;}
th,td{padding:12px;border-bottom:2px solid rgba(117,117,117,117);text-align:left;}
th{font-size:12px;font-weight:700;color:#93c5fd;text-transform:uppercase;}
td{font-size:14px;}
tr:hover{background:rgba(59,130,246,.05);}

.status-badge{margin-left:8px;padding:4px 10px;border-radius:6px;font-size:11px;font-weight:700;text-transform:uppercase;}
.status-success{background:rgba(34,197,94,.2);color:#4ade80;border:1px solid rgba(34,197,94,.3);}
.status-failed{background:rgba(239,68,68,.2);color:#f87171;border:1px solid rgba(239,68,68,.3);}
.staff-row{display:flex;align-items:center;gap:8px;margin-bottom:6px;}

/* --- Responsive (MATCH DASHBOARD BEHAVIOR) --- */
@media(max-width:1024px){
    .sidebar{width:240px;}
    .main-content{margin-left:240px;padding:24px 32px;}
}
@media(max-width:768px){
    .sidebar{
        width:100%;
        position:relative;
        height:auto;
        border-right:none;
        border-bottom:1px solid rgba(71,85,105,0.3);
    }
    .main-content{margin-left:0;padding:20px;}
    .container{flex-direction:column;}
    .header{flex-direction:column;align-items:flex-start;gap:14px;}
    .user-info{text-align:left;}
}

/* ===== Unauthorised popup modal ===== */
.unauth-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;z-index:10000}
.unauth-modal{width:min(520px,92vw);background:#0b1224;border:1px solid rgba(239,68,68,.5);border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.5);overflow:hidden}
.unauth-head{padding:14px 16px;background:rgba(239,68,68,.12);border-bottom:1px solid rgba(239,68,68,.25);font-weight:900;color:#fecaca}
.unauth-body{padding:16px;color:#e2e8f0;line-height:1.5}
.unauth-actions{padding:14px 16px;display:flex;justify-content:flex-end;border-top:1px solid rgba(71,85,105,.25)}
.unauth-actions button{border-color:rgba(239,68,68,.55);background:rgba(239,68,68,.2);color:#fecaca;padding:10px 16px;border-radius:10px;border:1px solid rgba(239,68,68,.55);font-weight:800;cursor:pointer;transition:.2s}
.unauth-actions button:hover{background:rgba(239,68,68,.28)}
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
            <li class="nav-item">
                <a href="admin-dashboard.php" class="nav-link">
                    <span class="nav-icon">📊</span>Dashboard
                </a>
            </li>

            <li class="nav-section-title">Management</li>
            <li class="nav-item">
                <a href="admin-users.php" class="nav-link">
                    <span class="nav-icon">👥</span>Manage Users
                </a>
            </li>
            <li class="nav-item">
                <a href="admin-departments.php" class="nav-link active">
                    <span class="nav-icon">🏢</span>Departments
                </a>
            </li>

            <li class="nav-section-title">Operations</li>
            <li class="nav-item">
                <a href="admin-leave-management.php" class="nav-link">
                    <span class="nav-icon">📅</span>Leave Management
                </a>
            </li>
            <li class="nav-item">
                <a href="admin-training.php" class="nav-link">
                    <span class="nav-icon">🎓</span>Training
                </a>
            </li>
            <li class="nav-item">
                <a href="admin-certifications.php" class="nav-link">
                    <span class="nav-icon">📜</span>Certifications
                </a>
            </li>

            <li class="nav-section-title">System</li>
            <li class="nav-item">
                <a href="admin-reports.php" class="nav-link">
                    <span class="nav-icon">📈</span>Reports
                </a>
            </li>
            <li class="nav-item">
                <a href="admin-security.php" class="nav-link">
                    <span class="nav-icon">🔒</span>Security Logs
                </a>
            </li>
        </ul>
    </nav>
</aside>

<!-- Main -->
<main class="main-content">
<header class="header">
    <div class="welcome-section">
        <h1>Departments</h1>
        <p>Organisation structure overview</p>
    </div>
    <div class="user-info">
        <div class="name"><?php echo htmlspecialchars($admin_name, ENT_QUOTES, 'UTF-8'); ?></div>
        <div class="role"><?php echo htmlspecialchars((string)($_SESSION['role'] ?? 'admin'), ENT_QUOTES, 'UTF-8'); ?></div>
        <a href="?logout=1" class="logout-btn">Logout</a>
    </div>
</header>

<div class="panel">
    <div class="panel-header">
        <div class="panel-title">All Departments</div>
    </div>
    <div class="panel-body">
        <table>
            <thead>
            <tr>
                <th>Department</th>
                <th>Staff</th>
            </tr>
            </thead>
            <tbody>

            <?php
            $currentDept = null;
            foreach ($rows as $r):
                $deptId = (int)$r['department_id'];
                if ($currentDept !== $deptId):
                    $currentDept = $deptId;
            ?>
            <tr>
                <td><strong><?= htmlspecialchars((string)$r['department_name'], ENT_QUOTES, 'UTF-8') ?></strong></td>
                <td>
                    <?php if (!empty($r['staff_name'])): ?>
                        <div class="staff-row">
                            <?= htmlspecialchars((string)$r['staff_name'], ENT_QUOTES, 'UTF-8') ?>
                            <span class="status-badge <?= ((string)$r['staff_status']==='active')?'status-success':'status-failed' ?>">
                                <?= htmlspecialchars((string)$r['staff_status'], ENT_QUOTES, 'UTF-8') ?>
                            </span>
                        </div>
                    <?php else: ?>
                        <em>No staff</em>
                    <?php endif; ?>
                </td>
            </tr>
            <?php else: ?>
            <tr>
                <td></td>
                <td>
                    <?php if (!empty($r['staff_name'])): ?>
                    <div class="staff-row">
                        <?= htmlspecialchars((string)$r['staff_name'], ENT_QUOTES, 'UTF-8') ?>
                        <span class="status-badge <?= ((string)$r['staff_status']==='active')?'status-success':'status-failed' ?>">
                            <?= htmlspecialchars((string)$r['staff_status'], ENT_QUOTES, 'UTF-8') ?>
                        </span>
                    </div>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endif; endforeach; ?>

            </tbody>
        </table>
    </div>
</div>
</main>

</div>
</body>
</html>
