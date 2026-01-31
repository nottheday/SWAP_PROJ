<?php
declare(strict_types=1);

require_once __DIR__ . '/../misc_security/secure-transport.php';
require_once __DIR__ . '/../misc_security/session-hardening.php';
require_once __DIR__ . '/../misc_security/sql-prevention.php';

/* ===============================
   Session init (safe)
   - avoids "ini_set cannot be changed when session is active"
================================ */
if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.use_strict_mode', '1');
    ini_set('session.cookie_httponly', '1');
    session_start();
}

/* =========================
   SQLi detection (GET/POST)
   ========================= */
detect_sql_injection($_GET);
detect_sql_injection($_POST);

/* ===============================
   ✅ URL Tampering Popup (ADMIN DASHBOARD)
   - If ?role=staff/admin/supervisor (ANY role param) => popup + clean reload
   - If id/employee_id/user_id/staff_id/user etc => popup + clean reload
   - If ANY unexpected query keys appear => popup + clean reload
   - If URL path/filename is edited (e.g. staff-dashboard -> admin-dashboard)
     => popup + redirect back to correct page clean URL
   Allowed GET keys here: logout
================================ */
$EXPECTED_FILE = 'admin-dashboard.php';

function admindash_clean_url(array $removeKeys = ['role','id','staff_id','employee_id','user_id','user']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);

    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function admindash_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) {
        $_SESSION['flash_unauth'] = 1;
    }

    $clean = admindash_clean_url();

    if ($forcePath !== null) {
        $qPos = strpos($clean, '?');
        $qs   = ($qPos !== false) ? substr($clean, $qPos) : '';
        header("Location: " . $forcePath . $qs);
        exit;
    }

    header("Location: " . $clean);
    exit;
}

/* ===============================
   AUTH first (so session role is reliable)
================================ */
if (!isset($_SESSION['auth'], $_SESSION['user'], $_SESSION['role'])) {
    header('Location: /AMC_Website/login_page/login.php');
    exit;
}

$username = (string)$_SESSION['user'];
$role     = strtolower((string)$_SESSION['role']);

/* ===============================
   Force correct filename if URL path is edited
================================ */
$currentFile = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '');
if ($currentFile !== '' && strtolower($currentFile) !== strtolower($EXPECTED_FILE)) {
    admindash_redirect_clean(true, $EXPECTED_FILE);
}

/* ===============================
   Detect ANY unexpected query keys (URL edited)
================================ */
$allowedKeys = ['logout'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        admindash_redirect_clean(true);
    }
}

/* ===============================
   Explicit tamper triggers
================================ */
if (isset($_GET['role'])) {
    // ANY role param triggers popup (even if it matches)
    admindash_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['employee_id']) || isset($_GET['staff_id']) || isset($_GET['user_id']) || isset($_GET['user'])) {
    admindash_redirect_clean(true);
}

/* =========================
   Database Config
   ========================= */
$db_host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "swap";

$mysqli = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($mysqli->connect_error) die("Database connection failed: " . $mysqli->connect_error);
$mysqli->set_charset('utf8mb4');

/* =========================
   Authentication & Role Check
   ========================= */
if ($role !== 'admin') {
    http_response_code(403);
    die("Access Denied: Admins only. Your role: " . htmlspecialchars((string)($_SESSION['role'] ?? ''), ENT_QUOTES, 'UTF-8'));
}

/* =========================
   Fetch Admin Info
   ========================= */
$stmt = $mysqli->prepare("
    SELECT s.name, s.email, s.job_title
    FROM users u
    JOIN staff s ON u.staff_id = s.id
    WHERE u.username = ?
");
$stmt->bind_param("s", $username);
$stmt->execute();
$stmt->bind_result($admin_name, $email, $job_title);
$stmt->fetch();
$stmt->close();

/* =========================
   System Statistics
   ========================= */
$users_stats = $mysqli->query("
    SELECT r.name AS role_name, COUNT(u.id) AS count
    FROM users u
    JOIN role r ON u.role_id = r.id
    WHERE u.status='active'
    GROUP BY r.name
");

$users_by_role = [];
if ($users_stats) {
    while ($row = $users_stats->fetch_assoc()) {
        $users_by_role[(string)$row['role_name']] = (int)$row['count'];
    }
}

$total_staff_row   = $mysqli->query("SELECT COUNT(*) AS total FROM staff WHERE status='active'")->fetch_assoc();
$total_depts_row   = $mysqli->query("SELECT COUNT(*) AS total FROM department")->fetch_assoc();
$pending_leave_row = $mysqli->query("SELECT COUNT(*) AS total FROM leave_application WHERE status='pending'")->fetch_assoc();
$expired_certs_row = $mysqli->query("SELECT COUNT(*) AS total FROM staff_certification WHERE expiry_date < CURDATE()")->fetch_assoc();

$total_staff   = (int)($total_staff_row['total'] ?? 0);
$total_depts   = (int)($total_depts_row['total'] ?? 0);
$pending_leave = (int)($pending_leave_row['total'] ?? 0);
$expired_certs = (int)($expired_certs_row['total'] ?? 0);

/* =========================
   Recent Login Activity
   ========================= */
$recent_logins = $mysqli->query("
    SELECT username, ip, success, time
    FROM login_audit
    ORDER BY time DESC
    LIMIT 10
");

/* =========================
   Alerts
   ========================= */
$alerts = [];

$critical_certs_row = $mysqli->query("SELECT COUNT(*) AS count FROM staff_certification WHERE expiry_date < DATE_SUB(CURDATE(), INTERVAL 90 DAY)")->fetch_assoc();
$critical_certs = (int)($critical_certs_row['count'] ?? 0);
if ($critical_certs > 0) {
    $alerts[] = [
        'type'    => 'critical',
        'icon'    => '⚠️',
        'message' => $critical_certs . " certifications expired over 90 days ago",
        'link'    => 'admin-certifications.php'
    ];
}

$failed_logins_row = $mysqli->query("SELECT COUNT(*) AS count FROM login_audit WHERE success=0 AND time > DATE_SUB(NOW(), INTERVAL 24 HOUR)")->fetch_assoc();
$failed_logins = (int)($failed_logins_row['count'] ?? 0);
if ($failed_logins > 10) {
    $alerts[] = [
        'type'    => 'warning',
        'icon'    => '🔒',
        'message' => $failed_logins . " failed login attempts in last 24 hours",
        'link'    => 'admin-security.php'
    ];
}

$old_pending_row = $mysqli->query("SELECT COUNT(*) AS count FROM leave_application WHERE status='pending' AND start_date < DATE_SUB(CURDATE(), INTERVAL 30 DAY)")->fetch_assoc();
$old_pending = (int)($old_pending_row['count'] ?? 0);
if ($old_pending > 0) {
    $alerts[] = [
        'type'    => 'warning',
        'icon'    => '📅',
        'message' => $old_pending . " leave requests pending over 30 days",
        'link'    => 'admin-leave-management.php'
    ];
}

/* =========================
   Handle Logout
   ========================= */
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: /AMC_Website/login.php');
    exit;
}

$mysqli->close();

/* ========= One-time modal flag ========= */
$showUnauth = !empty($_SESSION['flash_unauth']);
if ($showUnauth) unset($_SESSION['flash_unauth']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AMC HR - Admin Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
/* --- Reset & Body --- */
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Inter',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;}
.container{display:flex;min-height:100vh;}

/* --- Sidebar (STANDARDIZED) --- */
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
.logo .role-badge{display:inline-block;margin-top:8px;padding:4px 12px;background:rgba(168,85,247,0.2);border:1px solid rgba(168,85,247,0.3);border-radius:6px;font-size:12px;font-weight:600;color:#c084fc;text-transform:uppercase;}
.nav-menu{list-style:none;}
.nav-section-title{padding:8px 32px;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:24px;margin-bottom:8px;}
.nav-item{margin-bottom:4px;}
.nav-link{display:flex;align-items:center;gap:12px;padding:12px 32px;color:#94a3b8;text-decoration:none;font-size:14px;font-weight:500;transition:all 0.2s ease;border-left:3px solid transparent;}
.nav-link:hover{background: rgba(59,130,246,0.1);color:#60a5fa;border-left-color:#3b82f6;}
.nav-link.active{background: rgba(59,130,246,0.15);color:#60a5fa;border-left-color:#3b82f6;}
.nav-icon{font-size:18px;width:20px;text-align:center;}

/* --- Main Content --- */
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
.welcome-section p { color: #94a3b8; font-size: 14px; }
.user-info { text-align: right; }
.user-info .name { font-weight: 600;font-size: 16px;color: #e2e8f0;margin-bottom: 4px;}
.user-info .role { font-size: 13px; color: purple; margin-bottom: 12px; }
.logout-btn{display:inline-block;padding:8px 20px;background:rgba(239,68,68,.2);border:1px solid rgba(239,68,68,.4);border-radius:8px;color:#fca5a5;text-decoration:none;font-size:13px;font-weight:600;}
.logout-btn:hover{background: rgba(239,68,68,0.3);border-color: rgba(239,68,68,0.6);}

/* --- Alerts --- */
.alerts-section{margin-bottom:32px;}
.alert-card{padding:16px 20px;border-radius:12px;margin-bottom:12px;display:flex;align-items:center;gap:16px;text-decoration:none;transition:all 0.2s ease;}
.alert-card.critical{background: rgba(127,29,29,0.3);border:1px solid rgba(239,68,68,0.5);}
.alert-card.warning{background: rgba(113,63,18,0.3);border:1px solid rgba(251,146,60,0.5);}
.alert-card:hover{transform:translateX(4px);}
.alert-icon{font-size:24px;}
.alert-message{flex:1;font-size:14px;font-weight:500;}
.alert-card.critical .alert-message{color:#fca5a5;}
.alert-card.warning .alert-message{color:#fdba74;}

/* --- Stats Grid --- */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:24px;margin-bottom:48px;}
.stat-card{padding:28px;background:rgba(30,41,59,0.6);border:1px solid rgba(71,85,105,0.3);border-radius:16px;transition:all 0.3s ease;}
.stat-card:hover{transform:translateY(-4px);box-shadow:0 12px 32px rgba(0,0,0,0.4);border-color:rgba(96,165,250,0.5);}
.stat-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;}
.stat-label{font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;}
.stat-icon{font-size:24px;opacity:0.7;}
.stat-value{font-size:36px;font-weight:700;color:#60a5fa;line-height:1;}

/* --- Quick Actions --- */
.quick-panel{background:rgba(30,41,59,0.6);border:1px solid rgba(71,85,105,0.3);border-radius:16px;padding:32px;margin-bottom:48px;}
.quick-panel .section-title{margin-bottom:18px;}
.quick-table{width:100%;border-collapse:collapse;}
.quick-table th{text-align:left;padding:12px;font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid rgba(71,85,105,0.3);}
.quick-table td{padding:16px 12px;font-size:14px;color:#cbd5e1;border-bottom:1px solid rgba(71,85,105,0.2);}
.quick-table tbody tr:hover{background:rgba(59,130,246,0.05);}
.qa-btn{display:inline-block;padding:10px 14px;background:rgba(59,130,246,0.18);border:1px solid rgba(59,130,246,0.35);border-radius:10px;color:#93c5fd;text-decoration:none;font-size:13px;font-weight:700;transition:all 0.2s ease;}
.qa-btn:hover{background:rgba(59,130,246,0.28);border-color:rgba(59,130,246,0.55);transform:translateY(-1px);}

/* --- Recent Activity --- */
.activity-section{background:rgba(30,41,59,0.6);border:1px solid rgba(71,85,105,0.3);border-radius:16px;padding:32px;}
.section-title{font-size:20px;font-weight:600;color:#e2e8f0;margin-bottom:24px;}
.activity-table{width:100%;border-collapse:collapse;}
.activity-table th{text-align:left;padding:12px;font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid rgba(71,85,105,0.3);}
.activity-table td{padding:16px 12px;font-size:14px;color:#cbd5e1;border-bottom:1px solid rgba(71,85,105,0.2);}
.activity-table tbody tr:hover{background:rgba(59,130,246,0.05);}
.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;}
.status-dot.success{background:#22c55e;}
.status-dot.failed{background:#ef4444;}

/* --- Responsive --- */
@media(max-width:1024px){.sidebar{width:240px;}.main-content{margin-left:240px;padding:24px 32px;}.stats-grid{grid-template-columns:repeat(2,1fr);}}
@media(max-width:768px){.sidebar{width:100%;position:relative;height:auto;border-right:none;border-bottom:1px solid rgba(71,85,105,0.3);}.main-content{margin-left:0;padding:20px;}.container{flex-direction:column;}.header{flex-direction:column;align-items:flex-start;}.stats-grid{grid-template-columns:1fr;}}

/* ===== Popup modal (same as your other pages) ===== */
.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;z-index:9999}
.modal{width:min(520px,92vw);background:#0b1224;border:1px solid rgba(239,68,68,.5);border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.5);overflow:hidden}
.modal-head{padding:14px 16px;background:rgba(239,68,68,.12);border-bottom:1px solid rgba(239,68,68,.25);font-weight:900;color:#fecaca}
.modal-body{padding:16px;color:#e2e8f0;line-height:1.5}
.modal-actions{padding:14px 16px;display:flex;justify-content:flex-end;border-top:1px solid rgba(71,85,105,.25)}
.modal-actions button{border-color:rgba(239,68,68,.55);background:rgba(239,68,68,.2);color:#fecaca;padding:10px 16px;border-radius:10px;border:1px solid rgba(239,68,68,.55);font-weight:800;cursor:pointer;transition:.2s}
.modal-actions button:hover{background:rgba(239,68,68,.28)}
</style>
</head>
<body>

<!-- ===== Modal Popup (shows after tampering) ===== -->
<div class="modal-backdrop" id="unauthModal" <?php echo $showUnauth ? 'style="display:flex"' : ''; ?>>
  <div class="modal" role="dialog" aria-modal="true">
    <div class="modal-head">⚠️Unauthorised Access Detected</div>
    <div class="modal-body">
      Your request was blocked because the URL looked modified (role/ID/query/path tampering).<br>
      You have been returned to this page safely.
    </div>
    <div class="modal-actions">
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
                <li class="nav-item"><a href="admin-dashboard.php" class="nav-link active"><span class="nav-icon">📊</span>Dashboard</a></li>

                <li class="nav-section-title">Management</li>
                <li class="nav-item"><a href="admin-users.php" class="nav-link"><span class="nav-icon">👥</span>Manage Users</a></li>
                <li class="nav-item"><a href="admin-departments.php" class="nav-link"><span class="nav-icon">🏢</span>Departments</a></li>

                <li class="nav-section-title">Operations</li>
                <li class="nav-item"><a href="admin-leave-management.php" class="nav-link"><span class="nav-icon">📅</span>Leave Management</a></li>
                <li class="nav-item"><a href="admin-training.php" class="nav-link"><span class="nav-icon">🎓</span>Training</a></li>
                <li class="nav-item"><a href="admin-certifications.php" class="nav-link"><span class="nav-icon">📜</span>Certifications</a></li>

                <li class="nav-section-title">System</li>
                <li class="nav-item"><a href="admin-reports.php" class="nav-link"><span class="nav-icon">📈</span>Reports</a></li>
                <li class="nav-item"><a href="admin-security.php" class="nav-link"><span class="nav-icon">🔒</span>Security & Logs</a></li>
            </ul>
        </nav>
    </aside>

    <!-- Main Content -->
    <main class="main-content">
        <!-- Header -->
        <header class="header">
            <div class="welcome-section">
                <h1>Welcome back, <?php echo htmlspecialchars(($admin_name ?? $username), ENT_QUOTES, 'UTF-8'); ?></h1>
                <p>System Administrator Dashboard</p>
            </div>
        <div class="user-info">
                <div class="name"><?= htmlspecialchars((string)($admin_name ?? $username), ENT_QUOTES, 'UTF-8') ?></div>
                <div class="role"><?php echo htmlspecialchars((string)($_SESSION['role'] ?? 'admin'), ENT_QUOTES, 'UTF-8'); ?></div>
                <a href="?logout=1" class="logout-btn">Logout</a>
            </div>
        </header>

        <!-- Alerts -->
        <?php if(count($alerts) > 0): ?>
        <div class="alerts-section">
            <?php foreach($alerts as $alert): ?>
            <a href="<?php echo htmlspecialchars((string)$alert['link'], ENT_QUOTES, 'UTF-8'); ?>" class="alert-card <?php echo htmlspecialchars((string)$alert['type'], ENT_QUOTES, 'UTF-8'); ?>">
                <span class="alert-icon"><?php echo htmlspecialchars((string)$alert['icon'], ENT_QUOTES, 'UTF-8'); ?></span>
                <span class="alert-message"><?php echo htmlspecialchars((string)$alert['message'], ENT_QUOTES, 'UTF-8'); ?></span>
                <span style="color:#64748b;">→</span>
            </a>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>

        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-header"><span class="stat-label">Total Staff</span><span class="stat-icon">👥</span></div><div class="stat-value"><?php echo (int)$total_staff; ?></div></div>
            <div class="stat-card"><div class="stat-header"><span class="stat-label">Departments</span><span class="stat-icon">🏢</span></div><div class="stat-value"><?php echo (int)$total_depts; ?></div></div>
            <div class="stat-card"><div class="stat-header"><span class="stat-label">Admins</span><span class="stat-icon">👑</span></div><div class="stat-value"><?php echo (int)($users_by_role['admin'] ?? 0); ?></div></div>
            <div class="stat-card"><div class="stat-header"><span class="stat-label">Supervisors</span><span class="stat-icon">👔</span></div><div class="stat-value"><?php echo (int)($users_by_role['supervisor'] ?? 0); ?></div></div>
            <div class="stat-card"><div class="stat-header"><span class="stat-label">Pending Leave</span><span class="stat-icon">📅</span></div><div class="stat-value" style="color:#fbbf24;"><?php echo (int)$pending_leave; ?></div></div>
            <div class="stat-card"><div class="stat-header"><span class="stat-label">Expired Certs</span><span class="stat-icon">⚠️</span></div><div class="stat-value" style="color:#f87171;"><?php echo (int)$expired_certs; ?></div></div>
        </div>

        <!-- Quick Actions -->
        <div class="quick-panel">
            <h3 class="section-title">Quick Actions</h3>
            <table class="quick-table">
                <thead>
                    <tr>
                        <th>Module</th>
                        <th>Shortcut</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Users</td>
                        <td>Manage user accounts & roles</td>
                        <td><a class="qa-btn" href="admin-users.php">Open →</a></td>
                    </tr>
                    <tr>
                        <td>Departments</td>
                        <td>Create / edit departments</td>
                        <td><a class="qa-btn" href="admin-departments.php">Open →</a></td>
                    </tr>
                    <tr>
                        <td>Leave Management</td>
                        <td>Approve / reject leave requests</td>
                        <td><a class="qa-btn" href="admin-leave-management.php">Open →</a></td>
                    </tr>
                    <tr>
                        <td>Training Programs</td>
                        <td>Manage trainings & attendance</td>
                        <td><a class="qa-btn" href="admin-training.php">Open →</a></td>
                    </tr>
                    <tr>
                        <td>Certifications</td>
                        <td>Track certification expiry & renewals</td>
                        <td><a class="qa-btn" href="admin-certifications.php">Open →</a></td>
                    </tr>
                    <tr>
                        <td>Security & Logs</td>
                        <td>Review logins and suspicious events</td>
                        <td><a class="qa-btn" href="admin-security.php">Open →</a></td>
                    </tr>
                    <tr>
                        <td>Reports</td>
                        <td>Generate system reports</td>
                        <td><a class="qa-btn" href="admin-reports.php">Open →</a></td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Recent Login Activity -->
        <div class="activity-section">
            <h3 class="section-title">Recent Login Activity</h3>
            <table class="activity-table">
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Username</th>
                        <th>IP Address</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($recent_logins): ?>
                        <?php while($login=$recent_logins->fetch_assoc()): ?>
                        <tr>
                            <td><span class="status-dot <?php echo ((int)$login['success']===1)?'success':'failed'; ?>"></span><?php echo ((int)$login['success']===1)?'Success':'Failed'; ?></td>
                            <td><?php echo htmlspecialchars((string)$login['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo htmlspecialchars((string)$login['ip'], ENT_QUOTES, 'UTF-8'); ?></td>
                            <td><?php echo !empty($login['time']) ? date('M d, Y H:i',strtotime((string)$login['time'])) : '-'; ?></td>
                        </tr>
                        <?php endwhile; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <?php
          // keeps your existing library popups (e.g. SQLi) if your sql-prevention.php provides them
          if (function_exists('render_security_popups')) {
              render_security_popups();
          }
        ?>
    </main>
</div>
</body>
</html>
