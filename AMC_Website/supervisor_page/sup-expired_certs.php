<?php
declare(strict_types=1);

require_once __DIR__ . '/../misc_security/secure-transport.php';
require_once __DIR__ . '/../misc_security/session-hardening.php';
require_once __DIR__ . '/../misc_security/sql-prevention.php';

/* ===============================
   Session init (safe)
   - avoids double session_start / ini_set warnings
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
   ✅ URL Tampering Popup (SUP-EXPIRED CERTS)
   Requirements (same style as your reference):
   1) If ?role=staff/admin/supervisor (ANY role param) => popup + clean reload
   2) If any ID-like param present => popup + clean reload
   3) If ANY unexpected query string keys appear (URL edited) => popup + clean reload
   4) If someone tries to load this script under a different filename/path
      => popup + redirect back to the correct sup-expired_certs.php clean URL
   Notes:
   - We allow only: logout, name, cert, urgency (GET) for this page.
================================ */
$EXPECTED_FILE = 'sup-expired_certs.php';

function supexp_clean_url(array $removeKeys = ['role','id','staff_id','employee_id','user_id','user']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);

    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function supexp_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) {
        $_SESSION['flash_unauth'] = 1;
    }

    $clean = supexp_clean_url();

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
   Auth first (so role is reliable)
================================ */
if (!isset($_SESSION['auth'], $_SESSION['user'], $_SESSION['role'])) {
    header('Location: /AMC_Website/login_page/login.php');
    exit;
}

$username = (string)$_SESSION['user'];
$role     = strtolower((string)$_SESSION['role']);

/* ===============================
   Force correct filename if URL path is edited
   (e.g. sup-expired_certs.php changed to admin-dashboard.php in URL)
================================ */
$currentFile = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '');
if ($currentFile !== '' && strtolower($currentFile) !== strtolower($EXPECTED_FILE)) {
    supexp_redirect_clean(true, $EXPECTED_FILE);
}

/* ===============================
   Detect ANY unexpected query keys (URL edited)
   Allowed keys for this page: logout, name, cert, urgency
================================ */
$allowedKeys = ['logout', 'name', 'cert', 'urgency'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        supexp_redirect_clean(true);
    }
}

/* ===============================
   Explicit tamper triggers
================================ */
if (isset($_GET['role'])) {
    // ANY role param triggers popup (even if it matches)
    supexp_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['staff_id']) || isset($_GET['employee_id']) || isset($_GET['user_id']) || isset($_GET['user'])) {
    supexp_redirect_clean(true);
}

/* ============================
   CSRF PROTECTION
   Generate token if not exists
   ============================ */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* ============================
   DOM XSS PREVENTION
   Add Content Security Policy (CSP)
   ============================ */
header("Content-Security-Policy: 
    default-src 'self';
    script-src 'self';
    style-src 'self' https://fonts.googleapis.com;
    font-src https://fonts.gstatic.com;
    img-src 'self' data:;
    object-src 'none';
    base-uri 'self';
    frame-ancestors 'none';
");

/* =========================
   RBAC: supervisor only
   ========================= */
if ($role !== 'supervisor') {
    http_response_code(403);
    die("Access Denied: This page is for supervisors only.");
}

/* =========================
   DB connection
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

/* ============================
   REFLECTED XSS PREVENTION
   Sanitize GET inputs on output (NOT for SQL; SQL uses prepared stmt)
   ============================ */
$name_filter    = (string)($_GET['name'] ?? '');
$cert_filter    = (string)($_GET['cert'] ?? '');
$urgency_filter = (string)($_GET['urgency'] ?? 'all');

/* ============================
   Build query to get expired certifications
   ============================ */
$query = "
    SELECT 
        sc.id as cert_id,
        s.id as staff_id,
        s.name as employee_name,
        d.name as department_name,
        sc.name as cert_name,
        sc.issue_date,
        sc.expiry_date,
        DATEDIFF(CURDATE(), sc.expiry_date) as days_expired,
        CASE 
            WHEN DATEDIFF(CURDATE(), sc.expiry_date) > 90 THEN 'CRITICAL'
            WHEN DATEDIFF(CURDATE(), sc.expiry_date) > 30 THEN 'HIGH'
            ELSE 'MEDIUM'
        END as urgency
    FROM staff_certification sc
    JOIN staff s ON sc.staff_id = s.id
    LEFT JOIN department d ON s.department_id = d.id
    WHERE sc.expiry_date < CURDATE() AND s.status = 'active'
";

if ($name_filter !== '') {
    $query .= " AND s.name LIKE ?";
}
if ($cert_filter !== '') {
    $query .= " AND sc.name LIKE ?";
}

$query .= " ORDER BY sc.expiry_date ASC";

/* Prepare statement */
$stmt = $mysqli->prepare($query);
if (!$stmt) {
    die("Query prepare failed.");
}

$params = [];
$types  = "";

if ($name_filter !== '') {
    $name_param = "%" . $name_filter . "%";
    $params[] = $name_param;
    $types   .= "s";
}
if ($cert_filter !== '') {
    $cert_param = "%" . $cert_filter . "%";
    $params[] = $cert_param;
    $types   .= "s";
}

if (!empty($params)) {
    $stmt->bind_param($types, ...$params);
}

$stmt->execute();
$result = $stmt->get_result();

/* Fetch all expired certifications */
$expired_certs = [];
while ($row = $result->fetch_assoc()) {
    $expired_certs[] = $row; // escape on output
}
$stmt->close();

/* Apply urgency filter */
if ($urgency_filter !== 'all') {
    $expired_certs = array_values(array_filter($expired_certs, function($cert) use ($urgency_filter) {
        return ($cert['urgency'] ?? '') === $urgency_filter;
    }));
}

/* Get unique departments (not used in UI, kept for future) */
$dept_query  = "SELECT DISTINCT name FROM department ORDER BY name";
$dept_result = $mysqli->query($dept_query);
$departments = [];
if ($dept_result) {
    while ($dept = $dept_result->fetch_assoc()) {
        $departments[] = (string)$dept['name'];
    }
}

/* Handle renew action */
$success_message = null;
if (isset($_POST['renew'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], (string)$_POST['csrf_token'])) {
        die("CSRF validation failed.");
    }

    $cert_id  = (int)($_POST['cert_id'] ?? 0);
    $employee = (string)($_POST['employee_name'] ?? '');

    $success_message = "Renewal process initiated for " . htmlspecialchars($employee, ENT_QUOTES, 'UTF-8') . "'s certification.";
}

/* Handle logout */
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
<title>AMC HR - Expired Certifications</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
        }

        .container {
            display: flex;
            min-height: 100vh;
        }

        /* Sidebar Styles */
        .sidebar {
            width: 280px;
            background: rgba(15, 23, 42, 0.95);
            border-right: 1px solid rgba(71, 85, 105, 0.3);
            padding: 32px 0;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
        }

        .logo {
            padding: 0 32px;
            margin-bottom: 48px;
        }

        .logo h1 {
            font-size: 32px;
            font-weight: 700;
            background: linear-gradient(135deg, #60a5fa 0%, #3b82f6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .logo .role-badge {
            display: inline-block;
            margin-top: 8px;
            padding: 4px 12px;
            background: rgba(251, 146, 60, 0.2);
            border: 1px solid rgba(251, 146, 60, 0.3);
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            color: #fb923c;
            text-transform: uppercase;
        }

        .nav-menu {
            list-style: none;
        }

        .nav-item {
            margin-bottom: 8px;
        }

        .nav-link {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 14px 32px;
            color: #94a3b8;
            text-decoration: none;
            font-size: 15px;
            font-weight: 500;
            transition: all 0.2s ease;
            border-left: 3px solid transparent;
        }

        .nav-link:hover {
            background: rgba(59, 130, 246, 0.1);
            color: #60a5fa;
            border-left-color: #3b82f6;
        }

        .nav-link.active {
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            border-left-color: #3b82f6;
        }

        .nav-icon {
            font-size: 20px;
        }

        /* Main Content Styles */
        .main-content {
            flex: 1;
            margin-left: 280px;
            padding: 32px 48px;
        }

        /* Header Styles */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 48px;
            gap: 20px;
        }

        .welcome-section h2 {
            font-size: 28px;
            font-weight: 700;
            color: #e2e8f0;
            margin-bottom: 8px;
        }

        .welcome-section p {
            font-size: 14px;
            color: #94a3b8;
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .user-info {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            color: #94a3b8;
            font-size: 14px;
        }

        .user-info strong {
            color: #60a5fa;
            font-weight: 600;
        }

        .logout-btn {
            padding: 10px 24px;
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid rgba(239, 68, 68, 0.4);
            border-radius: 8px;
            color: #fca5a5;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s ease;
        }

        .logout-btn:hover {
            background: rgba(239, 68, 68, 0.3);
            border-color: rgba(239, 68, 68, 0.6);
        }

        .success-message {
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            color: #86efac;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            text-align: center;
        }

        /* Statistics Banner */
        .stats-banner {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }

        .stat-card {
            padding: 20px;
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.3);
            border-radius: 12px;
            text-align: center;
        }

        .stat-value {
            font-size: 32px;
            font-weight: 700;
            color: #60a5fa;
            margin-bottom: 8px;
        }

        .stat-label {
            font-size: 13px;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* Filter Section */
        .filter-section {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.3);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 32px;
        }

        .filter-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 16px;
        }

        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .filter-label {
            font-size: 13px;
            font-weight: 600;
            color: #60a5fa;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .filter-input,
        .filter-select {
            padding: 12px 16px;
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.4);
            border-radius: 8px;
            color: #e2e8f0;
            font-size: 14px;
            font-family: 'Inter', sans-serif;
            outline: none;
            transition: all 0.2s ease;
        }

        .filter-input::placeholder {
            color: #64748b;
        }

        .filter-input:focus,
        .filter-select:focus {
            background: rgba(30, 41, 59, 0.8);
            border-color: #3b82f6;
        }

        .filter-select {
            cursor: pointer;
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg width='12' height='8' viewBox='0 0 12 8' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 1L6 6L11 1' stroke='%2394a3b8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 16px center;
            padding-right: 40px;
        }

        .filter-select option {
            background: #1e293b;
            color: #e2e8f0;
        }

        /* Cert Table */
        .cert-table {
            width: 100%;
            border-collapse: collapse;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.3);
            border-radius: 12px;
            overflow: hidden;
        }

        .cert-table thead {
            background: rgba(30, 41, 59, 0.8);
            border-bottom: 1px solid rgba(71, 85, 105, 0.4);
        }

        .cert-table th {
            padding: 16px;
            text-align: left;
            font-size: 13px;
            font-weight: 600;
            color: #60a5fa;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .cert-table td {
            padding: 20px 16px;
            border-bottom: 1px solid rgba(71, 85, 105, 0.2);
            font-size: 15px;
            color: #e2e8f0;
        }

        .cert-table tbody tr {
            transition: all 0.2s ease;
        }

        .cert-table tbody tr:hover {
            background: rgba(59, 130, 246, 0.05);
        }

        .cert-table tbody tr:last-child td {
            border-bottom: none;
        }

        .urgency-badge {
            display: inline-block;
            padding: 6px 16px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .urgency-badge.critical {
            background: rgba(127, 29, 29, 0.3);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.5);
        }

        .urgency-badge.high {
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .urgency-badge.medium {
            background: rgba(251, 146, 60, 0.15);
            color: #fb923c;
            border: 1px solid rgba(251, 146, 60, 0.3);
        }

        .renew-btn {
            padding: 10px 20px;
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            border: none;
            border-radius: 8px;
            color: #ffffff;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 2px 8px rgba(59, 130, 246, 0.3);
        }

        .renew-btn:hover {
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
            transform: translateY(-1px);
        }

        .renew-btn:active {
            transform: translateY(0);
        }

        .no-results {
            text-align: center;
            padding: 48px;
            color: #94a3b8;
            font-size: 16px;
        }

        /* Responsive Design */
        @media (max-width: 1024px) {
            .sidebar { width: 240px; }
            .main-content { margin-left: 240px; padding: 24px 32px; }
        }
        @media (max-width: 768px) {
            .sidebar { width: 100%; position: relative; height: auto; border-right: none; border-bottom: 1px solid rgba(71, 85, 105, 0.3); }
            .main-content { margin-left: 0; padding: 20px; }
            .container { flex-direction: column; }
            .header { flex-direction: column; align-items: flex-start; }
            .header-actions { width: 100%; justify-content: space-between; }
            .filter-grid { grid-template-columns: 1fr; }
            .cert-table { font-size: 14px; }
            .cert-table th, .cert-table td { padding: 12px 8px; }
        }

        /* Loading Animation */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .cert-table tbody tr { animation: fadeIn 0.4s ease-out forwards; }

        /* ===== Popup modal (same as your reference) ===== */
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
<!-- Sidebar unchanged -->
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
            <li class="nav-item"><a href="sup-expired_certs.php" class="nav-link active"><span class="nav-icon">📜</span><span>Expired Certs</span></a></li>
            <li class="nav-item"><a href="sup-pending_leave.php" class="nav-link"><span class="nav-icon">📅</span><span>Pending Leave</span></a></li>
        </ul>
    </nav>
</aside>

<!-- Main Content -->
<main class="main-content">
<header class="header">
    <div class="welcome-section">
        <h2>Expired Certifications</h2>
        <p>Track and manage expired staff certifications</p>
    </div>
    <div class="header-actions">
        <div class="user-info">
            <span><strong><?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></strong></span>
            <span style="text-transform: capitalize;"><?php echo htmlspecialchars($role, ENT_QUOTES, 'UTF-8'); ?></span>
        </div>
        <a href="?logout=1" class="logout-btn">Logout</a>
    </div>
</header>

<?php if ($success_message): ?>
    <div class="success-message"><?php echo htmlspecialchars((string)$success_message, ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>

<!-- Statistics Banner -->
<div class="stats-banner">
<?php
$total_expired = count($expired_certs);
$critical = count(array_filter($expired_certs, fn($c) => ($c['urgency'] ?? '') === 'CRITICAL'));
$high     = count(array_filter($expired_certs, fn($c) => ($c['urgency'] ?? '') === 'HIGH'));
$medium   = count(array_filter($expired_certs, fn($c) => ($c['urgency'] ?? '') === 'MEDIUM'));
?>
<div class="stat-card"><div class="stat-value"><?php echo (int)$total_expired; ?></div><div class="stat-label">Total Expired</div></div>
<div class="stat-card"><div class="stat-value" style="color: #fca5a5;"><?php echo (int)$critical; ?></div><div class="stat-label">Critical (90+ days)</div></div>
<div class="stat-card"><div class="stat-value" style="color: #f87171;"><?php echo (int)$high; ?></div><div class="stat-label">High (30-90 days)</div></div>
<div class="stat-card"><div class="stat-value" style="color: #fb923c;"><?php echo (int)$medium; ?></div><div class="stat-label">Medium (&lt; 30 days)</div></div>
</div>

<!-- Filter Section -->
<div class="filter-section">
<form method="GET" class="filter-grid">
    <div class="filter-group">
        <label class="filter-label">Employee Name</label>
        <input type="text" name="name" class="filter-input" placeholder="Search employee..."
        value="<?php echo htmlspecialchars($name_filter, ENT_QUOTES, 'UTF-8'); ?>">
    </div>
    <div class="filter-group">
        <label class="filter-label">Certification</label>
        <input type="text" name="cert" class="filter-input" placeholder="Search certification..."
        value="<?php echo htmlspecialchars($cert_filter, ENT_QUOTES, 'UTF-8'); ?>">
    </div>
    <div class="filter-group">
        <label class="filter-label">Urgency</label>
        <select name="urgency" class="filter-select" onchange="this.form.submit()">
            <option value="all" <?php echo $urgency_filter === 'all' ? 'selected' : ''; ?>>All</option>
            <option value="CRITICAL" <?php echo $urgency_filter === 'CRITICAL' ? 'selected' : ''; ?>>Critical</option>
            <option value="HIGH" <?php echo $urgency_filter === 'HIGH' ? 'selected' : ''; ?>>High</option>
            <option value="MEDIUM" <?php echo $urgency_filter === 'MEDIUM' ? 'selected' : ''; ?>>Medium</option>
        </select>
    </div>
</form>
</div>

<!-- Certifications Table -->
<?php if (count($expired_certs) > 0): ?>
<table class="cert-table">
<thead>
<tr>
<th>EMPLOYEE NAME</th>
<th>DEPARTMENT</th>
<th>CERTIFICATION</th>
<th>EXPIRED DATE</th>
<th>DAYS OVERDUE</th>
<th>URGENCY</th>
<th>ACTION</th>
</tr>
</thead>
<tbody>
<?php foreach ($expired_certs as $cert): ?>
<tr>
<td><?php echo htmlspecialchars((string)$cert['employee_name'], ENT_QUOTES, 'UTF-8'); ?></td>
<td><?php echo htmlspecialchars((string)($cert['department_name'] ?? 'N/A'), ENT_QUOTES, 'UTF-8'); ?></td>
<td><?php echo htmlspecialchars((string)$cert['cert_name'], ENT_QUOTES, 'UTF-8'); ?></td>
<td><?php echo !empty($cert['expiry_date']) ? date('M d, Y', strtotime((string)$cert['expiry_date'])) : '-'; ?></td>
<td><?php echo (int)($cert['days_expired'] ?? 0); ?> days</td>
<td>
<span class="urgency-badge <?php echo htmlspecialchars(strtolower((string)($cert['urgency'] ?? 'medium')), ENT_QUOTES, 'UTF-8'); ?>">
<?php echo htmlspecialchars((string)($cert['urgency'] ?? 'MEDIUM'), ENT_QUOTES, 'UTF-8'); ?>
</span>
</td>
<td>
<form method="POST" style="display: inline;">
    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string)$_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
    <input type="hidden" name="cert_id" value="<?php echo (int)($cert['cert_id'] ?? 0); ?>">
    <input type="hidden" name="employee_name" value="<?php echo htmlspecialchars((string)$cert['employee_name'], ENT_QUOTES, 'UTF-8'); ?>">
    <button type="submit" name="renew" class="renew-btn">Initiate Renewal</button>
</form>
</td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
<?php else: ?>
<div class="no-results">
No expired certifications found matching your filters.
</div>
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
``
