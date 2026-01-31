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
   ✅ URL Tampering Popup (ADMIN TRAINING)
   - Any ?role=... (staff/admin/supervisor etc) => popup + clean reload
   - Any id/user_id/staff_id/employee_id/user param => popup + clean reload
   - Any unexpected query key => popup + clean reload
   - If URL path/filename is edited (e.g. staff-dashboard -> admin-training)
     => popup + redirect to correct file
   Allowed GET keys here:
     logout, employee, course, approval, date, msg, err
================================ */
$EXPECTED_FILE = 'admin-training.php';

function admintraining_clean_url(array $removeKeys = ['role','id','user_id','staff_id','employee_id','user']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);

    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function admintraining_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) $_SESSION['flash_unauth'] = 1;

    $clean = admintraining_clean_url();

    if ($forcePath !== null) {
        $qPos = strpos($clean, '?');
        $qs   = ($qPos !== false) ? substr($clean, $qPos) : '';
        header("Location: " . $forcePath . $qs);
        exit;
    }

    header("Location: " . $clean);
    exit;
}

/* =========================
   AUTH + RBAC (ADMIN ONLY)
========================= */
if (!isset($_SESSION['auth'], $_SESSION['user'], $_SESSION['role'])) {
    header('Location: /AMC_Website/login_page/login.php');
    exit;
}
if (strtolower((string)($_SESSION['role'] ?? '')) !== 'admin') {
    http_response_code(403);
    die("Access Denied: Admins only. Your role: " . htmlspecialchars((string)($_SESSION['role'] ?? ''), ENT_QUOTES, 'UTF-8'));
}

$username = (string)($_SESSION['user'] ?? 'admin');
$role     = (string)($_SESSION['role'] ?? 'admin');

/* ===============================
   Force correct filename if URL path is edited
================================ */
$currentFile = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '');
if ($currentFile !== '' && strtolower($currentFile) !== strtolower($EXPECTED_FILE)) {
    admintraining_redirect_clean(true, $EXPECTED_FILE);
}

/* ===============================
   Detect ANY unexpected query keys (URL edited)
================================ */
$allowedKeys = ['logout','employee','course','approval','date','msg','err'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        admintraining_redirect_clean(true);
    }
}

/* ===============================
   Explicit tamper triggers
================================ */
if (isset($_GET['role'])) {
    // ANY role param triggers popup (even if it matches)
    admintraining_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['user_id']) || isset($_GET['staff_id']) || isset($_GET['employee_id']) || isset($_GET['user'])) {
    admintraining_redirect_clean(true);
}

/* =========================
   ACTIVE SIDEBAR TAB (AUTO)
========================= */
$currentPage = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '');
function navActive(string $file, string $currentPage): string {
    return $file === $currentPage ? ' active' : '';
}

/* =========================
   CSRF
========================= */
function ensureCsrf(): void {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // CSRF-PROTECTED
    }
}
function requireCsrf(): void {
    $t = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals((string)($_SESSION['csrf_token'] ?? ''), $t)) {
        http_response_code(403);
        exit("CSRF blocked."); // CSRF-PROTECTED
    }
}
ensureCsrf();

/* =========================
   DB CONNECTION
========================= */
$db_host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "swap";

$mysqli = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($mysqli->connect_error) die("Database connection failed: " . $mysqli->connect_error);
$mysqli->set_charset("utf8mb4");

/* =========================
   DB SCHEMA CHECK HELPERS
========================= */
function tableHasColumn(mysqli $mysqli, string $dbName, string $table, string $column): bool {
    $sql = "
        SELECT 1
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = ?
          AND TABLE_NAME = ?
          AND COLUMN_NAME = ?
        LIMIT 1
    ";
    $st = $mysqli->prepare($sql);
    if (!$st) return false;
    $st->bind_param("sss", $dbName, $table, $column);
    $st->execute();
    $st->store_result();
    $ok = ($st->num_rows > 0);
    $st->close();
    return $ok;
}

$has_approval_status = tableHasColumn($mysqli, $db_name, 'training_attendance', 'approval_status');
$has_approval_reason = tableHasColumn($mysqli, $db_name, 'training_attendance', 'approval_reason');
$has_approval_by     = tableHasColumn($mysqli, $db_name, 'training_attendance', 'approval_by');
$has_approval_date   = tableHasColumn($mysqli, $db_name, 'training_attendance', 'approval_date');

$approval_enabled = ($has_approval_status && $has_approval_reason && $has_approval_by && $has_approval_date);

/* =========================
   ADMIN INFO
========================= */
$admin_name = $username;
$admin_stmt = $mysqli->prepare("
    SELECT s.name
    FROM users u
    JOIN staff s ON u.staff_id = s.id
    WHERE u.username = ?
    LIMIT 1
");
if ($admin_stmt) {
    $admin_stmt->bind_param("s", $username);
    $admin_stmt->execute();
    $admin_stmt->bind_result($nameTmp);
    if ($admin_stmt->fetch() && !empty($nameTmp)) $admin_name = $nameTmp;
    $admin_stmt->close();
}

/* =========================
   LOGOUT
========================= */
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: /AMC_Website/login.php');
    exit;
}

/* =========================
   HANDLE APPROVAL UPDATE
========================= */
$success_message = null;
$error_message   = null;

if (isset($_POST['update_approval'])) {
    requireCsrf(); // CSRF-PROTECTED

    if (!$approval_enabled) {
        $error_message = "Approval system is disabled because approval columns do not exist in training_attendance.";
        header("Location: " . strtok($_SERVER["REQUEST_URI"], '?') . "?msg=&err=" . urlencode($error_message));
        exit;
    }

    $staff_id   = (int)($_POST['staff_id'] ?? 0);
    $session_id = (int)($_POST['training_sessions_id'] ?? 0);
    $new_status = (string)($_POST['approval_status'] ?? '');
    $reason     = trim((string)($_POST['approval_reason'] ?? ''));

    if ($staff_id <= 0 || $session_id <= 0 || ($new_status !== 'approved' && $new_status !== 'not_approved')) {
        $error_message = "Invalid approval request.";
    } elseif ($reason === '') {
        $error_message = "Reason is required.";
    } else {
        $upd = $mysqli->prepare("
            UPDATE training_attendance
            SET approval_status = ?, approval_reason = ?, approval_by = ?, approval_date = NOW()
            WHERE staff_id = ? AND training_sessions_id = ?
        ");
        if (!$upd) {
            $error_message = "Update failed. Check if approval columns exist in training_attendance.";
        } else {
            $upd->bind_param("sssii", $new_status, $reason, $username, $staff_id, $session_id);
            if ($upd->execute()) $success_message = "Approval updated.";
            else $error_message = "Failed to update approval.";
            $upd->close();
        }
    }

    // PRG redirect
    header("Location: " . strtok($_SERVER["REQUEST_URI"], '?') . "?msg=" . urlencode((string)($success_message ?? '')) . "&err=" . urlencode((string)($error_message ?? '')));
    exit;
}

/* PRG messages (reflected input => always escape on output) */
if (!empty($_GET['msg'])) $success_message = (string)$_GET['msg'];
if (!empty($_GET['err'])) $error_message   = (string)$_GET['err'];

/* =========================
   FILTERS
========================= */
$employee_filter = (string)($_GET['employee'] ?? '');
$course_filter   = (string)($_GET['course'] ?? '');
$approval_filter = (string)($_GET['approval'] ?? 'all');
$date_filter     = (string)($_GET['date'] ?? '');

if (!$approval_enabled) {
    $approval_filter = 'all';
}

/* =========================
   LIST STAFF TRAINING (ADMIN VIEW)
========================= */
$selectApproval = "";
if ($approval_enabled) {
    $selectApproval = "
        , COALESCE(NULLIF(ta.approval_status,''), 'pending') AS approval_status
        , ta.approval_reason
        , ta.approval_by
        , ta.approval_date
    ";
} else {
    $selectApproval = "
        , 'pending' AS approval_status
        , NULL AS approval_reason
        , NULL AS approval_by
        , NULL AS approval_date
    ";
}

$query = "
    SELECT
        s.id AS staff_id,
        s.name AS employee_name,
        s.email,
        s.job_title,
        d.name AS department_name,

        ts.id AS training_sessions_id,
        ts.name AS course_title,
        ts.description AS course_description,
        ts.start_date,
        ts.end_date,

        ta.status AS attendance_status
        $selectApproval,

        CASE
            WHEN ts.start_date <= DATE_ADD(CURDATE(), INTERVAL 7 DAY) THEN 'HIGH'
            ELSE 'NORMAL'
        END AS priority
    FROM training_attendance ta
    JOIN staff s ON ta.staff_id = s.id
    JOIN training_sessions ts ON ta.training_sessions_id = ts.id
    LEFT JOIN department d ON s.department_id = d.id
    WHERE s.status = 'active'
";

$types  = "";
$values = [];

if ($employee_filter !== '') {
    $query .= " AND s.name LIKE ?";
    $types .= "s";
    $values[] = "%{$employee_filter}%";
}
if ($course_filter !== '') {
    $query .= " AND ts.name LIKE ?";
    $types .= "s";
    $values[] = "%{$course_filter}%";
}
if ($date_filter !== '') {
    $query .= " AND DATE_FORMAT(ts.start_date, '%Y-%m') = ?";
    $types .= "s";
    $values[] = $date_filter;
}

if ($approval_enabled) {
    if ($approval_filter === 'approved') {
        $query .= " AND ta.approval_status = 'approved'";
    } elseif ($approval_filter === 'not_approved') {
        $query .= " AND ta.approval_status = 'not_approved'";
    } elseif ($approval_filter === 'pending') {
        $query .= " AND (ta.approval_status IS NULL OR ta.approval_status = '' OR ta.approval_status = 'pending')";
    }
}

$query .= " ORDER BY ts.start_date ASC, s.name ASC";

$stmt = $mysqli->prepare($query);
$training_rows = [];

if (!$stmt) {
    $error_message = $error_message ?? "Query failed. Check DB schema / column names.";
} else {
    if ($types !== "" && !empty($values)) {
        $bind = [];
        $bind[] = $types;
        foreach ($values as $k => $val) $bind[] = &$values[$k];
        call_user_func_array([$stmt, 'bind_param'], $bind);
    }

    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) $training_rows[] = $row;
    $stmt->close();
}

/* Stats */
$total_rows    = count($training_rows);
$approved_cnt  = $approval_enabled ? count(array_filter($training_rows, fn($r) => ($r['approval_status'] ?? '') === 'approved')) : 0;
$rejected_cnt  = $approval_enabled ? count(array_filter($training_rows, fn($r) => ($r['approval_status'] ?? '') === 'not_approved')) : 0;
$pending_cnt   = $total_rows - $approved_cnt - $rejected_cnt;
$high_priority = count(array_filter($training_rows, fn($r) => ($r['priority'] ?? '') === 'HIGH'));

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
<title>AMC HR - Training Programs</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
/* --- Reset & Body --- */
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Inter',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;overflow-x:hidden;}
.container{display:flex;min-height:100vh;}

/* --- Sidebar (same as your Admin Dashboard) --- */
.sidebar{
    width:280px;
    background:rgba(15,23,42,0.95);
    border-right:1px solid rgba(71,85,105,0.3);
    padding-top:32px;
    position:fixed;
    top:0; bottom:0; left:0;
    overflow-y:auto;
    scrollbar-gutter: stable;
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
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;gap:20px;}
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

.success-message{background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);color:#86efac;padding:12px 16px;border-radius:8px;margin-bottom:16px;font-size:14px;text-align:center;}
.error-message{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#fca5a5;padding:12px 16px;border-radius:8px;margin-bottom:16px;font-size:14px;text-align:center;}
.info-message{background:rgba(59,130,246,0.08);border:1px solid rgba(59,130,246,0.25);color:#93c5fd;padding:12px 16px;border-radius:8px;margin-bottom:16px;font-size:14px;text-align:center;}

/* Stats */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:18px;}
.stat-card{padding:18px;background:rgba(30,41,59,0.6);border:1px solid rgba(71,85,105,0.3);border-radius:14px;}
.stat-label{font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;margin-bottom:8px;}
.stat-value{font-size:30px;font-weight:800;color:#60a5fa;line-height:1;}

/* Filters */
.filter-section{background:rgba(30,41,59,0.6);border:1px solid rgba(71,85,105,0.3);border-radius:16px;padding:18px;margin-bottom:18px;}
.filter-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;}
.filter-label{font-size:12px;font-weight:700;color:#60a5fa;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;display:block;}
.filter-input,.filter-select{
    width:100%;
    padding:12px 14px;
    background:rgba(15,23,42,0.65);
    border:1px solid rgba(71,85,105,0.35);
    border-radius:10px;
    color:#e2e8f0;
    outline:none;
    font-size:14px;
}
.filter-input:focus,.filter-select:focus{border-color:#3b82f6;}
.filter-select{cursor:pointer;}
.filter-select option{background:#1e293b;color:#e2e8f0;}

/* Table */
.training-table{width:100%;border-collapse:collapse;background:rgba(30,41,59,0.6);border:1px solid rgba(71,85,105,0.3);border-radius:16px;overflow:hidden;}
.training-table thead{background:rgba(15,23,42,0.7);border-bottom:1px solid rgba(71,85,105,0.4);}
.training-table th{padding:14px 14px;text-align:left;font-size:12px;font-weight:700;color:#60a5fa;text-transform:uppercase;letter-spacing:0.5px;}
.training-table td{padding:16px 14px;border-bottom:1px solid rgba(71,85,105,0.2);font-size:14px;color:#e2e8f0;vertical-align:top;}
.training-table tbody tr:hover{background:rgba(59,130,246,0.05);}
.training-table tbody tr:last-child td{border-bottom:none;}

.badge{display:inline-block;padding:6px 10px;border-radius:6px;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:0.5px;border:1px solid transparent;}
.badge.approved{background:rgba(34,197,94,0.12);border-color:rgba(34,197,94,0.25);color:#86efac;}
.badge.not_approved{background:rgba(239,68,68,0.12);border-color:rgba(239,68,68,0.25);color:#fca5a5;}
.badge.pending{background:rgba(251,146,60,0.14);border-color:rgba(251,146,60,0.25);color:#fdba74;}
.badge.na{background:rgba(148,163,184,0.14);border-color:rgba(148,163,184,0.25);color:#cbd5e1;}

.priority-badge{display:inline-block;padding:6px 12px;border-radius:6px;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:0.5px;border:1px solid transparent;}
.priority-badge.high{background:rgba(239,68,68,0.15);color:#f87171;border-color:rgba(239,68,68,0.3);}
.priority-badge.normal{background:rgba(59,130,246,0.15);color:#60a5fa;border-color:rgba(59,130,246,0.3);}

.action-row{display:flex;flex-direction:column;gap:10px;}
.btn{padding:10px 12px;border:none;border-radius:10px;font-size:13px;font-weight:800;cursor:pointer;transition:all 0.2s ease;}
.btn-approve{background:linear-gradient(135deg,#22c55e 0%,#16a34a 100%);color:#fff;}
.btn-reject{background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);color:#fff;}
.btn-cancel{background:rgba(148,163,184,0.18);border:1px solid rgba(148,163,184,0.25);color:#e2e8f0;}
.btn:hover{transform:translateY(-1px);}
.btn:disabled{opacity:0.45;cursor:not-allowed;transform:none;}

.reason-box{display:none;padding:14px;background:rgba(15,23,42,0.65);border:1px solid rgba(71,85,105,0.35);border-radius:14px;}
.reason-box label{display:block;margin-bottom:8px;font-size:12px;font-weight:800;color:#60a5fa;text-transform:uppercase;letter-spacing:0.5px;}
.reason-box textarea{
    width:100%;
    min-height:90px;
    resize:vertical;
    padding:12px 12px;
    background:rgba(30,41,59,0.6);
    border:1px solid rgba(71,85,105,0.35);
    border-radius:12px;
    color:#e2e8f0;
    font-family:'Inter',sans-serif;
    font-size:14px;
    outline:none;
}
.reason-box textarea:focus{border-color:#3b82f6;}
.reason-actions{margin-top:10px;display:flex;gap:10px;justify-content:flex-end;flex-wrap:wrap;}

.no-results{text-align:center;padding:40px;color:#94a3b8;font-size:15px;background:rgba(30,41,59,0.6);border:1px solid rgba(71,85,105,0.3);border-radius:16px;}

/* --- Responsive --- */
@media(max-width:1024px){
    .sidebar{width:240px;}
    .main-content{margin-left:240px;padding:24px 32px;}
}
@media(max-width:768px){
    .sidebar{width:100%;position:relative;height:auto;border-right:none;border-bottom:1px solid rgba(71,85,105,0.3);}
    .main-content{margin-left:0;padding:20px;}
    .container{flex-direction:column;}
    .header{flex-direction:column;align-items:flex-start;}
    .filter-grid{grid-template-columns:1fr;}
    .training-table th,.training-table td{padding:12px 10px;}
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
            <li class="nav-item"><a href="admin-dashboard.php" class="nav-link"><span class="nav-icon">📊</span>Dashboard</a></li>
            <li class="nav-section-title">Management</li>
            <li class="nav-item"><a href="admin-users.php" class="nav-link"><span class="nav-icon">👥</span>Manage Users</a></li>
            <li class="nav-item"><a href="admin-departments.php" class="nav-link"><span class="nav-icon">🏢</span>Departments</a></li>
            <li class="nav-section-title">Operations</li>
            <li class="nav-item"><a href="admin-leave-management.php" class="nav-link"><span class="nav-icon">📅</span>Leave Management</a></li>
            <li class="nav-item"><a href="admin-training.php" class="nav-link active"><span class="nav-icon">🎓</span>Training</a></li>
            <li class="nav-item"><a href="admin-certifications.php" class="nav-link"><span class="nav-icon">📜</span>Certifications</a></li>
            <li class="nav-section-title">System</li>
            <li class="nav-item"><a href="admin-reports.php" class="nav-link"><span class="nav-icon">📈</span>Reports</a></li>
            <li class="nav-item"><a href="admin-security.php" class="nav-link"><span class="nav-icon">🔒</span>Security Logs</a></li>
        </ul>
    </nav>
</aside>

<!-- Main Content -->
<main class="main-content">
<header class="header">
    <div class="welcome-section">
        <h1>Training Programs</h1>
        <p>Approve / Not approve staff training attendance with reasons.</p>
    </div>
    <div class="user-info">
        <div class="name"><?= htmlspecialchars((string)$admin_name, ENT_QUOTES, 'UTF-8') ?></div>
        <div class="role"><?php echo htmlspecialchars((string)($_SESSION['role'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></div>
        <a href="?logout=1" class="logout-btn">Logout</a>
    </div>
</header>

<?php if (!$approval_enabled): ?>
<div class="info-message">
Approval system is currently disabled because these columns are missing in <strong>training_attendance</strong>:
<br><code>approval_status, approval_reason, approval_by, approval_date</code>
<br>Page will still work (no crash), but approvals are disabled until you add them.
</div>
<?php endif; ?>

<?php if (!empty($success_message)): ?>
<div class="success-message"><?php echo htmlspecialchars((string)$success_message, ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>
<?php if (!empty($error_message)): ?>
<div class="error-message"><?php echo htmlspecialchars((string)$error_message, ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>

<!-- Stats -->
<div class="stats-grid">
    <div class="stat-card">
        <div class="stat-label">Total Records</div>
        <div class="stat-value"><?php echo (int)$total_rows; ?></div>
    </div>
    <div class="stat-card">
        <div class="stat-label">Approved</div>
        <div class="stat-value" style="color:#86efac;"><?php echo (int)$approved_cnt; ?></div>
    </div>
    <div class="stat-card">
        <div class="stat-label">Not Approved</div>
        <div class="stat-value" style="color:#fca5a5;"><?php echo (int)$rejected_cnt; ?></div>
    </div>
    <div class="stat-card">
        <div class="stat-label">Pending</div>
        <div class="stat-value" style="color:#fdba74;"><?php echo (int)$pending_cnt; ?></div>
    </div>
    <div class="stat-card">
        <div class="stat-label">High Priority</div>
        <div class="stat-value" style="color:#f87171;"><?php echo (int)$high_priority; ?></div>
    </div>
</div>

<!-- Filters -->
<div class="filter-section">
    <form method="GET" class="filter-grid">
        <div>
            <label class="filter-label">Employee</label>
            <input type="text" name="employee" class="filter-input" placeholder="Search employee..."
                   value="<?php echo htmlspecialchars($employee_filter, ENT_QUOTES, 'UTF-8'); ?>">
        </div>

        <div>
            <label class="filter-label">Course Title</label>
            <input type="text" name="course" class="filter-input" placeholder="Search course..."
                   value="<?php echo htmlspecialchars($course_filter, ENT_QUOTES, 'UTF-8'); ?>">
        </div>

        <div>
            <label class="filter-label">Approval Status</label>
            <select name="approval" class="filter-select" onchange="this.form.submit()" <?php echo !$approval_enabled ? 'disabled' : ''; ?>>
                <option value="all" <?php echo $approval_filter === 'all' ? 'selected' : ''; ?>>All</option>
                <option value="pending" <?php echo $approval_filter === 'pending' ? 'selected' : ''; ?>>Pending</option>
                <option value="approved" <?php echo $approval_filter === 'approved' ? 'selected' : ''; ?>>Approved</option>
                <option value="not_approved" <?php echo $approval_filter === 'not_approved' ? 'selected' : ''; ?>>Not Approved</option>
            </select>
        </div>

        <div>
            <label class="filter-label">Start Date (Month)</label>
            <input type="month" name="date" class="filter-input"
                   value="<?php echo htmlspecialchars($date_filter, ENT_QUOTES, 'UTF-8'); ?>"
                   onchange="this.form.submit()">
        </div>
    </form>
</div>

<!-- Table -->
<?php if (count($training_rows) > 0): ?>
<table class="training-table">
    <thead>
        <tr>
            <th>EMPLOYEE</th>
            <th>COURSE</th>
            <th>DATES</th>
            <th>ATTENDANCE</th>
            <th>APPROVAL</th>
            <th>PRIORITY</th>
            <th>ACTION</th>
        </tr>
    </thead>
    <tbody>
    <?php foreach ($training_rows as $i => $row): ?>
        <?php
            $approval = (string)($row['approval_status'] ?? 'pending');
            if ($approval !== 'approved' && $approval !== 'not_approved') $approval = 'pending';
            $rid = "reasonBox_" . $i;
        ?>
        <tr>
            <td>
                <strong><?php echo htmlspecialchars((string)($row['employee_name'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></strong>
                <br>
                <small style="color:#94a3b8;">
                    <?php
                        $jt = (string)($row['job_title'] ?? '');
                        $dn = (string)($row['department_name'] ?? '');
                        echo htmlspecialchars($jt . (!empty($dn) ? " • " . $dn : ""), ENT_QUOTES, 'UTF-8');
                    ?>
                </small>
            </td>
            <td>
                <strong><?php echo htmlspecialchars((string)($row['course_title'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></strong>
                <?php if (!empty($row['course_description'])): ?>
                    <br><small style="color:#94a3b8;"><?php echo htmlspecialchars((string)$row['course_description'], ENT_QUOTES, 'UTF-8'); ?></small>
                <?php endif; ?>
            </td>
            <td>
                <small style="color:#94a3b8;">Start</small><br>
                <?php echo htmlspecialchars(date('M d, Y', strtotime((string)$row['start_date'])), ENT_QUOTES, 'UTF-8'); ?>
                <br><br>
                <small style="color:#94a3b8;">End</small><br>
                <?php echo htmlspecialchars(date('M d, Y', strtotime((string)$row['end_date'])), ENT_QUOTES, 'UTF-8'); ?>
            </td>
            <td><?php echo htmlspecialchars((string)($row['attendance_status'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></td>
            <td>
                <?php if ($approval_enabled): ?>
                    <span class="badge <?php echo htmlspecialchars($approval, ENT_QUOTES, 'UTF-8'); ?>">
                        <?php echo htmlspecialchars(str_replace('_', ' ', $approval), ENT_QUOTES, 'UTF-8'); ?>
                    </span>
                    <?php if (!empty($row['approval_reason'])): ?>
                        <br><small style="color:#94a3b8;">Reason: <?php echo htmlspecialchars((string)$row['approval_reason'], ENT_QUOTES, 'UTF-8'); ?></small>
                    <?php endif; ?>
                    <?php if (!empty($row['approval_by'])): ?>
                        <br><small style="color:#94a3b8;">By: <?php echo htmlspecialchars((string)$row['approval_by'], ENT_QUOTES, 'UTF-8'); ?></small>
                    <?php endif; ?>
                <?php else: ?>
                    <span class="badge na">N/A</span>
                    <br><small style="color:#94a3b8;">Approval columns not in DB.</small>
                <?php endif; ?>
            </td>
            <td>
                <?php
                    $prio = strtoupper((string)($row['priority'] ?? 'NORMAL'));
                    $prioClass = ($prio === 'HIGH') ? 'high' : 'normal';
                ?>
                <span class="priority-badge <?php echo $prioClass; ?>">
                    <?php echo htmlspecialchars($prio, ENT_QUOTES, 'UTF-8'); ?>
                </span>
            </td>
            <td>
                <div class="action-row">
                    <button class="btn btn-approve" type="button"
                        onclick="openReason('<?php echo $rid; ?>','approved')"
                        <?php echo !$approval_enabled ? 'disabled' : ''; ?>>
                        Approve
                    </button>
                    <button class="btn btn-reject" type="button"
                        onclick="openReason('<?php echo $rid; ?>','not_approved')"
                        <?php echo !$approval_enabled ? 'disabled' : ''; ?>>
                        Not Approve
                    </button>

                    <div class="reason-box" id="<?php echo $rid; ?>">
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string)$_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                            <input type="hidden" name="staff_id" value="<?php echo (int)$row['staff_id']; ?>">
                            <input type="hidden" name="training_sessions_id" value="<?php echo (int)$row['training_sessions_id']; ?>">
                            <input type="hidden" name="approval_status" id="<?php echo $rid; ?>_status" value="">

                            <label>Reason</label>
                            <textarea name="approval_reason" placeholder="Enter reason (required)"><?php echo htmlspecialchars((string)($row['approval_reason'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></textarea>

                            <div class="reason-actions">
                                <button type="button" class="btn btn-cancel" onclick="closeReason('<?php echo $rid; ?>')">Cancel</button>
                                <button type="submit" name="update_approval" class="btn btn-approve">Save</button>
                            </div>
                        </form>
                    </div>
                </div>
            </td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php else: ?>
<div class="no-results">No training programs found matching your filters.</div>
<?php endif; ?>
</main>
</div>

<script>
function openReason(boxId, status) {
    const box = document.getElementById(boxId);
    const statusInput = document.getElementById(boxId + "_status");
    if (!box || !statusInput) return;

    document.querySelectorAll('.reason-box').forEach(b => {
        if (b.id !== boxId) b.style.display = 'none';
    });

    statusInput.value = status;
    box.style.display = 'block';
    box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function closeReason(boxId) {
    const box = document.getElementById(boxId);
    if (box) box.style.display = 'none';
}
</script>
</body>
</html>
