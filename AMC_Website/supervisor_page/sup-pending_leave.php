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
   ✅ URL Tampering Popup (PENDING LEAVE)
   - If ?role=staff/admin/supervisor (ANY role param) => popup + clean reload
   - If id/employee_id/user_id/staff_id etc => popup + clean reload
   - If ANY unexpected query keys appear => popup + clean reload
   - If URL path/filename is edited (e.g. staff-dashboard -> admin-dashboard)
     => popup + redirect back to correct page clean URL
   Allowed GET keys here: logout, name, department, leave_type, status
================================ */
$EXPECTED_FILE = 'sup-pending_leave.php';

function supleave_clean_url(array $removeKeys = ['role','id','staff_id','employee_id','user_id','user']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);

    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function supleave_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) {
        $_SESSION['flash_unauth'] = 1;
    }

    $clean = supleave_clean_url();

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
    supleave_redirect_clean(true, $EXPECTED_FILE);
}

/* ===============================
   Detect ANY unexpected query keys (URL edited)
================================ */
$allowedKeys = ['logout', 'name', 'department', 'leave_type', 'status'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        supleave_redirect_clean(true);
    }
}

/* ===============================
   Explicit tamper triggers
================================ */
if (isset($_GET['role'])) {
    // ANY role param triggers popup (even if it matches)
    supleave_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['employee_id']) || isset($_GET['staff_id']) || isset($_GET['user_id']) || isset($_GET['user'])) {
    supleave_redirect_clean(true);
}

/* =========================
   DATABASE CONFIG
   ========================= */
$db_host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "swap";

$mysqli = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($mysqli->connect_error) {
    die("Database connection failed: " . $mysqli->connect_error);
}
$mysqli->set_charset('utf8mb4');

/* =========================
   AUTH + RBAC
   ========================= */
if (!in_array($role, ['supervisor', 'admin', 'hr'], true)) {
    http_response_code(403);
    die("Access Denied: This page is for supervisors/admin/hr only.");
}

/* =========================
   Fetch logged-in staff details
   ========================= */
$stmt = $mysqli->prepare("
    SELECT s.name, s.email, s.job_title, d.name as department_name
    FROM users u
    JOIN staff s ON u.staff_id = s.id
    LEFT JOIN department d ON s.department_id = d.id
    WHERE u.username = ?
");
$stmt->bind_param("s", $username);
$stmt->execute();
$stmt->bind_result($staff_name, $email, $job_title, $department_name);
$stmt->fetch();
$stmt->close();

if (!isset($_SESSION['dept'])) {
    $_SESSION['dept'] = $department_name;
}

/* =========================
   CSRF TOKEN
   ========================= */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* =========================
   Helper: check if a column exists
   ========================= */
function columnExists(mysqli $mysqli, string $table, string $column): bool {
    $sql = "SELECT 1
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = ?
              AND COLUMN_NAME = ?
            LIMIT 1";
    $stmt = $mysqli->prepare($sql);
    if (!$stmt) return false;
    $stmt->bind_param("ss", $table, $column);
    $stmt->execute();
    $stmt->store_result();
    $ok = ($stmt->num_rows === 1);
    $stmt->close();
    return $ok;
}

/* =========================
   Get logged-in user ID
   ========================= */
$user_stmt = $mysqli->prepare("SELECT id FROM users WHERE username = ?");
$user_stmt->bind_param("s", $username);
$user_stmt->execute();
$user_stmt->bind_result($logged_in_user_id);
$user_stmt->fetch();
$user_stmt->close();

if (empty($logged_in_user_id)) {
    http_response_code(500);
    die("Unable to resolve user id.");
}

/* =========================
   OPTIONAL SCOPE CONTROL
   ========================= */
$has_staff_supervisor_id = columnExists($mysqli, 'staff', 'supervisor_id');
$has_users_department_id = columnExists($mysqli, 'users', 'department_id');
$has_staff_department_id = columnExists($mysqli, 'staff', 'department_id');

$supervisor_department_id = null;

if (!$has_staff_supervisor_id && $has_users_department_id) {
    $deptStmt = $mysqli->prepare("SELECT department_id FROM users WHERE id = ?");
    if ($deptStmt) {
        $deptStmt->bind_param("i", $logged_in_user_id);
        $deptStmt->execute();
        $deptStmt->bind_result($supervisor_department_id);
        $deptStmt->fetch();
        $deptStmt->close();
    }
}

$canApprove = ($_SESSION['dept'] === 'HR' || $_SESSION['dept'] === 'Human Resources');

/* =========================
   Handle approve/reject actions (POST only)
   ========================= */
$success_message = null;
$error_message = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$canApprove) {
        http_response_code(403);
        die("Forbidden: Only HR department can approve or reject leave requests.");
    }

    $csrf = $_POST['csrf_token'] ?? '';
    if (!is_string($csrf) || !hash_equals($_SESSION['csrf_token'], $csrf)) {
        http_response_code(403);
        die("CSRF blocked.");
    }

    $action   = (string)($_POST['action'] ?? '');
    $leave_id = filter_input(INPUT_POST, 'leave_id', FILTER_VALIDATE_INT);

    if (!in_array($action, ['approve', 'reject'], true) || !$leave_id || $leave_id <= 0) {
        http_response_code(400);
        die("Invalid request.");
    }

    $new_status = ($action === 'approve') ? 'approved' : 'rejected';

    $update_stmt = $mysqli->prepare("
        UPDATE leave_application
        SET status = ?, approved_by = ?
        WHERE id = ?
    ");
    if (!$update_stmt) {
        $error_message = "Failed to prepare update query.";
    } else {
        $update_stmt->bind_param("sii", $new_status, $logged_in_user_id, $leave_id);

        if ($update_stmt->execute()) {
            $success_message = "Leave request #{$leave_id} has been {$new_status}.";
        } else {
            $error_message = "Failed to update leave request.";
        }
        $update_stmt->close();

        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
}

/* =========================
   Handle filters (GET)
   ========================= */
$name_filter       = (string)($_GET['name'] ?? '');
$department_filter = (string)($_GET['department'] ?? 'all');
$leave_type_filter = (string)($_GET['leave_type'] ?? 'all');
$status_filter     = (string)($_GET['status'] ?? 'all');

/* =========================
   Build query to get leave requests
   ========================= */
$query = "
    SELECT 
        la.id as leave_id,
        s.id as staff_id,
        s.name as employee_name,
        d.name as department_name,
        lt.name as leave_type,
        la.start_date,
        la.end_date,
        la.status,
        DATEDIFF(la.end_date, la.start_date) + 1 as duration_days
    FROM leave_application la
    JOIN staff s ON la.staff_id = s.id
    JOIN leave_type lt ON la.leave_type_id = lt.id
    LEFT JOIN department d ON s.department_id = d.id
    WHERE s.status = 'active'
";

$types = "";
$params = [];

if (!$canApprove) {
    $query .= " AND s.department_id = (
        SELECT s2.department_id
        FROM users u2
        JOIN staff s2 ON u2.staff_id = s2.id
        WHERE u2.username = ?
    )";
    $types .= "s";
    $params[] = $username;
}

if ($name_filter !== '') {
    $query .= " AND s.name LIKE ?";
    $types .= "s";
    $params[] = "%" . $name_filter . "%";
}
if ($department_filter !== 'all') {
    $query .= " AND d.name = ?";
    $types .= "s";
    $params[] = $department_filter;
}
if ($leave_type_filter !== 'all') {
    $query .= " AND lt.name = ?";
    $types .= "s";
    $params[] = $leave_type_filter;
}
if ($status_filter !== 'all') {
    $query .= " AND la.status = ?";
    $types .= "s";
    $params[] = $status_filter;
}

$query .= " ORDER BY 
    CASE la.status 
        WHEN 'pending' THEN 1 
        WHEN 'approved' THEN 2 
        WHEN 'rejected' THEN 3 
    END, 
    la.start_date DESC";

$stmt = $mysqli->prepare($query);
if (!$stmt) {
    die("Query prepare failed: " . $mysqli->error);
}

if (!empty($params)) {
    $stmt->bind_param($types, ...$params);
}

$stmt->execute();
$result = $stmt->get_result();

$leave_requests = [];
while ($row = $result->fetch_assoc()) {
    $leave_requests[] = $row; // escape on output
}
$stmt->close();

/* =========================
   Filter dropdown data
   ========================= */
$dept_query = "SELECT DISTINCT name FROM department ORDER BY name";
$dept_result = $mysqli->query($dept_query);
$departments = [];
while ($dept = $dept_result->fetch_assoc()) {
    $departments[] = (string)$dept['name'];
}

$leave_types_query = "SELECT DISTINCT name FROM leave_type ORDER BY name";
$leave_types_result = $mysqli->query($leave_types_query);
$leave_types = [];
while ($lt = $leave_types_result->fetch_assoc()) {
    $leave_types[] = (string)$lt['name'];
}

/* =========================
   Logout
   ========================= */
if (isset($_GET['logout'])) {
    session_unset();
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
<title>AMC HR - Pending Leave</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Inter',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;}
.container{display:flex;min-height:100vh;}
.sidebar{width:280px;background:rgba(15,23,42,0.95);border-right:1px solid rgba(71,85,105,0.3);padding:32px 0;position:fixed;height:100vh;overflow-y:auto;}
.logo{padding:0 32px;margin-bottom:48px;}
.logo h1{font-size:32px;font-weight:700;background:linear-gradient(135deg,#60a5fa 0%,#3b82f6 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
.logo .role-badge{display:inline-block;margin-top:8px;padding:4px 12px;background:rgba(251,146,60,0.2);border:1px solid rgba(251,146,60,0.3);border-radius:6px;font-size:12px;font-weight:600;color:#fb923c;text-transform:uppercase;}
.nav-menu{list-style:none;}
.nav-item{margin-bottom:8px;}
.nav-link{display:flex;align-items:center;gap:12px;padding:14px 32px;color:#94a3b8;text-decoration:none;font-size:15px;font-weight:500;transition:all 0.2s ease;border-left:3px solid transparent;}
.nav-link:hover{background:rgba(59,130,246,0.1);color:#60a5fa;border-left-color:#3b82f6;}
.nav-link.active{background:rgba(59,130,246,0.15);color:#60a5fa;border-left-color:#3b82f6;}
.nav-icon{font-size:20px;}
.main-content{flex:1;margin-left:280px;padding:40px;}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:40px;padding-bottom:24px;border-bottom:1px solid rgba(71,85,105,0.3);}
.welcome-section h2{font-size:32px;font-weight:700;color:#f1f5f9;margin-bottom:8px;}
.welcome-section p{color:#94a3b8;font-size:16px;}
.header-actions{display:flex;align-items:center;gap:24px;}
.user-info{display:flex;flex-direction:column;align-items:flex-end;color:#94a3b8;font-size:14px;}
.user-info strong{color:#60a5fa;font-weight:600;}
.logout-btn{padding:10px 24px;background:rgba(239,68,68,0.2);border:1px solid rgba(239,68,68,0.4);border-radius:8px;color:#fca5a5;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none;transition:all 0.2s ease;}
.logout-btn:hover{background:rgba(239,68,68,0.3);border-color:rgba(239,68,68,0.6);}
.stats-banner{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:24px;margin-bottom:40px;}
.stat-card{background:rgba(30,41,59,0.5);border:1px solid rgba(71,85,105,0.3);border-radius:12px;padding:24px;transition:all 0.2s ease;}
.stat-card:hover{background:rgba(30,41,59,0.7);border-color:rgba(71,85,105,0.5);transform:translateY(-2px);}
.stat-value{font-size:36px;font-weight:700;color:#60a5fa;margin-bottom:8px;}
.stat-label{color:#94a3b8;font-size:14px;font-weight:500;}
.success-message{background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:8px;padding:16px 20px;color:#4ade80;margin-bottom:24px;}
.error-message{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:8px;padding:16px 20px;color:#f87171;margin-bottom:24px;}
.filter-section{background:rgba(30,41,59,0.5);border:1px solid rgba(71,85,105,0.3);border-radius:12px;padding:24px;margin-bottom:32px;}
.filter-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px;}
.filter-group{display:flex;flex-direction:column;gap:8px;}
.filter-label{font-size:14px;font-weight:500;color:#cbd5e1;}
.filter-input,.filter-select{padding:12px 16px;background:rgba(15,23,42,0.7);border:1px solid rgba(71,85,105,0.3);border-radius:8px;color:#e2e8f0;font-size:14px;transition:all 0.2s ease;}
.filter-input:focus,.filter-select:focus{outline:none;border-color:#3b82f6;background:rgba(15,23,42,0.9);}
.filter-input::placeholder{color:#64748b;}
.leave-table{width:100%;background:rgba(30,41,59,0.5);border:1px solid rgba(71,85,105,0.3);border-radius:12px;overflow:hidden;}
.leave-table thead{background:rgba(15,23,42,0.7);}
.leave-table th{padding:16px 20px;text-align:left;font-size:12px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid rgba(71,85,105,0.3);}
.leave-table td{padding:20px;border-bottom:1px solid rgba(71,85,105,0.2);color:#cbd5e1;}
.leave-table tbody tr{transition:background 0.2s ease;}
.leave-table tbody tr:hover{background:rgba(59,130,246,0.05);}
.leave-table tbody tr:last-child td{border-bottom:none;}
.status-badge{display:inline-block;padding:6px 12px;border-radius:6px;font-size:12px;font-weight:600;text-transform:uppercase;}
.status-badge.pending{background:rgba(251,191,36,0.2);color:#fbbf24;border:1px solid rgba(251,191,36,0.3);}
.status-badge.approved{background:rgba(34,197,94,0.2);color:#4ade80;border:1px solid rgba(34,197,94,0.3);}
.status-badge.rejected{background:rgba(239,68,68,0.2);color:#f87171;border:1px solid rgba(239,68,68,0.3);}
.action-buttons{display:flex;gap:8px;}
.approve-btn,.reject-btn{padding:8px 16px;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer;transition:all 0.2s ease;border:1px solid;}
.approve-btn{background:rgba(34,197,94,0.1);border-color:rgba(34,197,94,0.3);color:#4ade80;}
.approve-btn:hover{background:rgba(34,197,94,0.2);border-color:rgba(34,197,94,0.5);}
.reject-btn{background:rgba(239,68,68,0.1);border-color:rgba(239,68,68,0.3);color:#f87171;}
.reject-btn:hover{background:rgba(239,68,68,0.2);border-color:rgba(239,68,68,0.5);}
.processed-text{color:#64748b;font-size:13px;font-style:italic;}
.no-results{background:rgba(30,41,59,0.5);border:1px solid rgba(71,85,105,0.3);border-radius:12px;padding:60px 40px;text-align:center;color:#94a3b8;font-size:16px;}
@media(max-width:768px){.sidebar{position:relative;width:100%;height:auto;border-right:none;border-bottom:1px solid rgba(71,85,105,0.3);}.main-content{margin-left:0;padding:20px;}.container{flex-direction:column;}.header{flex-direction:column;align-items:flex-start;}.header-actions{width:100%;justify-content:space-between;}.filter-grid{grid-template-columns:1fr;}.leave-table{font-size:14px;}.leave-table th,.leave-table td{padding:12px 8px;}}

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
<aside class="sidebar">
<div class="logo">
<h1>AMC HR</h1>
<span class="role-badge">Supervisor</span>
</div>
<nav>
<ul class="nav-menu">
<li class="nav-item"><a href="sup-dashboard.php" class="nav-link"><span class="nav-icon">📊</span><span>Dashboard</span></a></li>
<li class="nav-item"><a href="sup-workforce_ready.php" class="nav-link"><span class="nav-icon">👥</span><span>Workforce Ready</span></a></li>
<li class="nav-item"><a href="sup-training_due.php" class="nav-link"><span class="nav-icon">🎓</span><span>Training Due</span></a></li>
<li class="nav-item"><a href="sup-expired_certs.php" class="nav-link"><span class="nav-icon">📜</span><span>Expired Certs</span></a></li>
<li class="nav-item"><a href="sup-pending_leave.php" class="nav-link active"><span class="nav-icon">📅</span><span>Pending Leave</span></a></li>
</ul>
</nav>
</aside>

<main class="main-content">
<header class="header">
<div class="welcome-section">
<h2>Leave Requests</h2>
<p>Review and approve leave applications</p>
</div>
<div class="header-actions">
<div class="user-info">
<span><strong><?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></strong></span>
<span style="text-transform: capitalize;"><?php echo htmlspecialchars($role, ENT_QUOTES, 'UTF-8'); ?></span>
</div>
<a href="?logout=1" class="logout-btn">Logout</a>
</div>
</header>

<?php if (!empty($success_message)): ?>
<div class="success-message">
<?php echo htmlspecialchars((string)$success_message, ENT_QUOTES, 'UTF-8'); ?>
</div>
<?php endif; ?>

<?php if (!empty($error_message)): ?>
<div class="error-message">
<?php echo htmlspecialchars((string)$error_message, ENT_QUOTES, 'UTF-8'); ?>
</div>
<?php endif; ?>

<div class="stats-banner">
<?php
$total_requests = count($leave_requests);
$pending  = count(array_filter($leave_requests, fn($r) => ($r['status'] ?? '') === 'pending'));
$approved = count(array_filter($leave_requests, fn($r) => ($r['status'] ?? '') === 'approved'));
$rejected = count(array_filter($leave_requests, fn($r) => ($r['status'] ?? '') === 'rejected'));
?>
<div class="stat-card"><div class="stat-value"><?php echo (int)$total_requests; ?></div><div class="stat-label">Total Requests</div></div>
<div class="stat-card"><div class="stat-value" style="color:#fbbf24;"><?php echo (int)$pending; ?></div><div class="stat-label">Pending</div></div>
<div class="stat-card"><div class="stat-value" style="color:#4ade80;"><?php echo (int)$approved; ?></div><div class="stat-label">Approved</div></div>
<div class="stat-card"><div class="stat-value" style="color:#f87171;"><?php echo (int)$rejected; ?></div><div class="stat-label">Rejected</div></div>
</div>

<div class="filter-section">
<form method="GET" class="filter-grid">
<div class="filter-group">
<label class="filter-label">Employee Name</label>
<input type="text" name="name" class="filter-input" placeholder="Search name..."
value="<?php echo htmlspecialchars($name_filter, ENT_QUOTES, 'UTF-8'); ?>">
</div>

<div class="filter-group">
<label class="filter-label">Department</label>
<select name="department" class="filter-select" onchange="this.form.submit()">
<option value="all" <?php echo $department_filter==='all'?'selected':''; ?>>All Departments</option>
<?php foreach($departments as $dept): ?>
<option value="<?php echo htmlspecialchars($dept, ENT_QUOTES, 'UTF-8'); ?>" <?php echo $department_filter===$dept?'selected':''; ?>>
<?php echo htmlspecialchars($dept, ENT_QUOTES, 'UTF-8'); ?></option>
<?php endforeach; ?>
</select>
</div>

<div class="filter-group">
<label class="filter-label">Leave Type</label>
<select name="leave_type" class="filter-select" onchange="this.form.submit()">
<option value="all" <?php echo $leave_type_filter==='all'?'selected':''; ?>>All Types</option>
<?php foreach($leave_types as $lt): ?>
<option value="<?php echo htmlspecialchars($lt, ENT_QUOTES, 'UTF-8'); ?>" <?php echo $leave_type_filter===$lt?'selected':''; ?>>
<?php echo htmlspecialchars($lt, ENT_QUOTES, 'UTF-8'); ?></option>
<?php endforeach; ?>
</select>
</div>

<div class="filter-group">
<label class="filter-label">Status</label>
<select name="status" class="filter-select" onchange="this.form.submit()">
<option value="all" <?php echo $status_filter==='all'?'selected':''; ?>>All Status</option>
<option value="pending" <?php echo $status_filter==='pending'?'selected':''; ?>>Pending</option>
<option value="approved" <?php echo $status_filter==='approved'?'selected':''; ?>>Approved</option>
<option value="rejected" <?php echo $status_filter==='rejected'?'selected':''; ?>>Rejected</option>
</select>
</div>
</form>
</div>

<?php if(count($leave_requests)>0): ?>
<table class="leave-table">
<thead>
<tr>
<th>EMPLOYEE NAME</th>
<th>DEPARTMENT</th>
<th>LEAVE TYPE</th>
<th>START DATE</th>
<th>END DATE</th>
<th>DURATION</th>
<th>STATUS</th>
<?php if($canApprove): ?><th>ACTION</th><?php endif; ?>
</tr>
</thead>
<tbody>
<?php foreach($leave_requests as $request): ?>
<tr>
<td><?php echo htmlspecialchars((string)$request['employee_name'], ENT_QUOTES, 'UTF-8'); ?></td>
<td><?php echo htmlspecialchars((string)($request['department_name']??'N/A'), ENT_QUOTES, 'UTF-8'); ?></td>
<td><?php echo htmlspecialchars((string)$request['leave_type'], ENT_QUOTES, 'UTF-8'); ?></td>
<td><?php echo !empty($request['start_date']) ? date('M d, Y', strtotime((string)$request['start_date'])) : '-'; ?></td>
<td><?php echo !empty($request['end_date']) ? date('M d, Y', strtotime((string)$request['end_date'])) : '-'; ?></td>
<td><?php echo (int)($request['duration_days'] ?? 0); ?> day<?php echo ((int)($request['duration_days'] ?? 0) > 1) ? 's' : ''; ?></td>
<td><span class="status-badge <?php echo htmlspecialchars(strtolower((string)($request['status'] ?? 'pending')), ENT_QUOTES, 'UTF-8'); ?>">
<?php echo htmlspecialchars(strtoupper((string)($request['status'] ?? 'pending')), ENT_QUOTES, 'UTF-8'); ?></span></td>
<?php if($canApprove): ?>
<td>
<?php if(($request['status'] ?? '')==='pending'): ?>
<form method="POST" class="action-buttons">
<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string)$_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
<input type="hidden" name="leave_id" value="<?php echo (int)($request['leave_id'] ?? 0); ?>">
<button type="submit" name="action" value="approve" class="approve-btn">Approve</button>
<button type="submit" name="action" value="reject" class="reject-btn">Reject</button>
</form>
<?php else: ?><span class="processed-text">Processed</span><?php endif; ?>
</td>
<?php endif; ?>
</tr>
<?php endforeach; ?>
</tbody>
</table>
<?php else: ?>
<div class="no-results">No leave requests found matching your filters.</div>
<?php endif; ?>

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
