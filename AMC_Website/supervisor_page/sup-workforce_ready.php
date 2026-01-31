<?php
declare(strict_types=1);

require_once __DIR__ . '/../misc_security/secure-transport.php';
require_once __DIR__ . '/../misc_security/session-hardening.php';
require_once __DIR__ . '/../misc_security/sql-prevention.php';

/* ===============================
   Session init (safe)
   - prevents ini_set warnings / double session_start
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
   ✅ URL Tampering Popup (SUP-WORKFORCE READY)
   Requirements (same style as your staff-apply_leave.php):
   1) If ?role=staff/admin/supervisor (ANY role param) => popup + clean reload
   2) If any ID-like param present => popup + clean reload
   3) If ANY unexpected query string keys appear (URL edited) => popup + clean reload
   4) If someone tries to load this script under a different filename/path
      => popup + redirect back to the correct sup-workforce_ready.php clean URL
   Notes:
   - We allow only: logout, search, department, status (GET) for this page.
================================ */
$EXPECTED_FILE = 'sup-workforce_ready.php';

function supwr_clean_url(array $removeKeys = ['role','id','staff_id','employee_id','user_id','user']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);

    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function supwr_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) {
        $_SESSION['flash_unauth'] = 1;
    }

    $clean = supwr_clean_url();

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
   (e.g. sup-workforce_ready.php changed to admin-dashboard.php in URL)
================================ */
$currentFile = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '');
if ($currentFile !== '' && strtolower($currentFile) !== strtolower($EXPECTED_FILE)) {
    supwr_redirect_clean(true, $EXPECTED_FILE);
}

/* ===============================
   Detect ANY unexpected query keys
   Allowed keys for this page: logout, search, department, status
================================ */
$allowedKeys = ['logout', 'search', 'department', 'status'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        supwr_redirect_clean(true);
    }
}

/* ===============================
   Explicit tamper triggers (kept for clarity)
================================ */
if (isset($_GET['role'])) {
    // ANY role param triggers popup (even if it matches)
    supwr_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['staff_id']) || isset($_GET['employee_id']) || isset($_GET['user_id']) || isset($_GET['user'])) {
    supwr_redirect_clean(true);
}

/* =========================
   RBAC: supervisor only
   ========================= */
if ($role !== 'supervisor') {
    http_response_code(403);
    die("Access Denied: This page is for supervisors only.");
}

/* =========================
   CSRF helpers (kept from your file)
   ========================= */
function ensureCsrf(): void {
  if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
  }
}
function requireCsrf(): void {
  $t = (string)($_POST['csrf_token'] ?? '');
  if (!hash_equals($_SESSION['csrf_token'] ?? '', $t)) {
    http_response_code(403);
    exit("CSRF blocked.");
  }
}
ensureCsrf();

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

/* =========================
   FETCH SUPERVISOR DETAILS
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

/* Store supervisor's department in session */
if (!isset($_SESSION['dept'])) {
    $_SESSION['dept'] = $department_name;
}

/* Handle search and filters safely (Reflected XSS safe) */
$search_query       = htmlspecialchars($_GET['search'] ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8');
$department_filter  = htmlspecialchars($_GET['department'] ?? 'all', ENT_QUOTES | ENT_HTML5, 'UTF-8');
$status_filter      = htmlspecialchars($_GET['status'] ?? 'all', ENT_QUOTES | ENT_HTML5, 'UTF-8');

/* =========================
   Build workforce readiness query
   ========================= */
$query = "
    SELECT 
        s.id,
        s.name,
        s.job_title,
        d.name as department_name,
        s.status as employment_status,
        wr.is_ready,
        wr.reason,
        wr.updated_at,
        CASE 
            WHEN wr.is_ready = 1 THEN 'READY'
            ELSE 'NOT READY'
        END as readiness_status,
        (SELECT COUNT(*) FROM training_attendance ta 
         WHERE ta.staff_id = s.id AND ta.status = 'pending') as pending_training,
        (SELECT COUNT(*) FROM staff_certification sc 
         WHERE sc.staff_id = s.id AND sc.expiry_date < CURDATE()) as expired_certs
    FROM staff s
    LEFT JOIN department d ON s.department_id = d.id
    LEFT JOIN workforce_ready wr ON s.id = wr.staff_id
    WHERE s.status = 'active'
";

/* Department restriction: HR sees all, others see only their dept */
if (($_SESSION['dept'] ?? '') !== 'HR') {
    $query .= " AND s.department_id = (
        SELECT s2.department_id
        FROM users u2
        JOIN staff s2 ON u2.staff_id = s2.id
        WHERE u2.username = ?
    )";
}

/* Search condition safely */
if (!empty($_GET['search'])) {
    $query .= " AND (s.name LIKE ? OR s.job_title LIKE ?)";
}

/* Department filter */
if ($department_filter !== 'all') {
    $query .= " AND d.name = ?";
}

$query .= " ORDER BY s.name ASC";

/* Prepare statement */
$stmt = $mysqli->prepare($query);

$params = [];
$types  = "";

/* Bind username for department restriction (only if not HR) */
if (($_SESSION['dept'] ?? '') !== 'HR') {
    $params[] = $username;
    $types   .= "s";
}

/* optional search */
if (!empty($_GET['search'])) {
    $search_param = "%" . (string)$_GET['search'] . "%"; // safe via prepared stmt
    $params[] = $search_param;
    $params[] = $search_param;
    $types   .= "ss";
}

/* optional department filter */
if ($department_filter !== 'all') {
    $params[] = (string)$_GET['department']; // safe via prepared stmt
    $types   .= "s";
}

/* final bind */
if (!empty($params)) {
    $stmt->bind_param($types, ...$params);
}

$stmt->execute();
$result = $stmt->get_result();

/* Fetch all employees safely (Stored XSS prevention on output) */
$employees = [];
while ($row = $result->fetch_assoc()) {
    $row['name']            = htmlspecialchars((string)$row['name'], ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $row['job_title']       = htmlspecialchars((string)$row['job_title'], ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $row['department_name'] = htmlspecialchars((string)($row['department_name'] ?? 'N/A'), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $row['reason']          = htmlspecialchars((string)($row['reason'] ?? '-'), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $employees[] = $row;
}
$stmt->close();

/* Apply status filter after fetching (computed) */
if ($status_filter !== 'all') {
    $employees = array_values(array_filter($employees, function($emp) use ($status_filter) {
        return ($emp['readiness_status'] ?? '') === $status_filter;
    }));
}

/* Get unique departments for filter dropdown */
$dept_query  = "SELECT DISTINCT name FROM department ORDER BY name";
$dept_result = $mysqli->query($dept_query);
$departments = [];
while ($dept = $dept_result->fetch_assoc()) {
    $departments[] = htmlspecialchars((string)$dept['name'], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

/* Logout */
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
<title>AMC HR - Workforce Ready</title>
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

        /* Directory Section */
        .directory-section {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(71, 85, 105, 0.3);
            border-radius: 16px;
            padding: 32px;
        }

        .directory-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 32px;
            flex-wrap: wrap;
            gap: 20px;
        }

        .directory-title {
            font-size: 28px;
            font-weight: 600;
            color: #e2e8f0;
        }

        .filters-container {
            display: flex;
            gap: 16px;
            align-items: center;
            flex-wrap: wrap;
        }

        .search-input {
            padding: 12px 20px;
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.4);
            border-radius: 8px;
            color: #e2e8f0;
            font-size: 14px;
            font-family: 'Inter', sans-serif;
            min-width: 250px;
            outline: none;
            transition: all 0.2s ease;
        }

        .search-input::placeholder {
            color: #64748b;
        }

        .search-input:focus {
            background: rgba(30, 41, 59, 0.8);
            border-color: #3b82f6;
        }

        .filter-select {
            padding: 12px 40px 12px 20px;
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.4);
            border-radius: 8px;
            color: #e2e8f0;
            font-size: 14px;
            font-family: 'Inter', sans-serif;
            cursor: pointer;
            outline: none;
            transition: all 0.2s ease;
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg width='12' height='8' viewBox='0 0 12 8' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 1L6 6L11 1' stroke='%2394a3b8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 16px center;
        }

        .filter-select:focus {
            background-color: rgba(30, 41, 59, 0.8);
            border-color: #3b82f6;
        }

        .filter-select option {
            background: #1e293b;
            color: #e2e8f0;
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

        /* Table Styles */
        .employee-table {
            width: 100%;
            border-collapse: collapse;
        }

        .employee-table thead {
            border-bottom: 1px solid rgba(71, 85, 105, 0.4);
        }

        .employee-table th {
            padding: 16px;
            text-align: left;
            font-size: 13px;
            font-weight: 600;
            color: #60a5fa;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .employee-table td {
            padding: 20px 16px;
            border-bottom: 1px solid rgba(71, 85, 105, 0.2);
            font-size: 15px;
            color: #e2e8f0;
        }

        .employee-table tbody tr {
            transition: all 0.2s ease;
            cursor: pointer;
        }

        .employee-table tbody tr:hover {
            background: rgba(59, 130, 246, 0.05);
        }

        .status-badge {
            display: inline-block;
            padding: 6px 16px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .status-badge.ready {
            background: rgba(34, 197, 94, 0.15);
            color: #4ade80;
            border: 1px solid rgba(34, 197, 94, 0.3);
        }

        .status-badge.not-ready {
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .details-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 4px 12px;
            background: rgba(100, 116, 139, 0.15);
            border: 1px solid rgba(100, 116, 139, 0.3);
            border-radius: 6px;
            font-size: 12px;
            color: #94a3b8;
            margin-right: 8px;
        }

        .details-badge.warning {
            background: rgba(251, 146, 60, 0.15);
            border-color: rgba(251, 146, 60, 0.3);
            color: #fb923c;
        }

        .no-results {
            text-align: center;
            padding: 48px;
            color: #94a3b8;
            font-size: 16px;
        }

        /* Responsive Design */
        @media (max-width: 1024px) {
            .sidebar {
                width: 240px;
            }

            .main-content {
                margin-left: 240px;
                padding: 24px 32px;
            }
        }

        @media (max-width: 768px) {
            .sidebar {
                width: 100%;
                position: relative;
                height: auto;
                border-right: none;
                border-bottom: 1px solid rgba(71, 85, 105, 0.3);
            }

            .main-content {
                margin-left: 0;
                padding: 20px;
            }

            .container {
                flex-direction: column;
            }

            .header {
                flex-direction: column;
                align-items: flex-start;
            }

            .header-actions {
                width: 100%;
                justify-content: space-between;
            }

            .directory-header {
                flex-direction: column;
                align-items: flex-start;
            }

            .filters-container {
                width: 100%;
                flex-direction: column;
            }

            .search-input,
            .filter-select {
                width: 100%;
            }

            .employee-table {
                font-size: 14px;
            }

            .employee-table th,
            .employee-table td {
                padding: 12px 8px;
            }
        }

        /* Loading Animation */
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .employee-table tbody tr {
            animation: fadeIn 0.4s ease-out forwards;
        }

        .toggle-btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.85rem;
            transition: all 0.3s ease;
        }

        .toggle-btn.ready {
            background: linear-gradient(135deg, #10b981, #059669);
            color: white;
        }

        .toggle-btn.not-ready {
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: white;
        }

        .toggle-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }

        /* ===== Popup modal (same style as your reference) ===== */
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
        <span class="role-badge"><?php echo htmlspecialchars($_SESSION['role'] ?? 'Supervisor', ENT_QUOTES, 'UTF-8'); ?></span>
    </div>
    <nav>
        <ul class="nav-menu">
            <li class="nav-item">
                <a href="sup-dashboard.php" class="nav-link">
                    <span class="nav-icon">📊</span>
                    <span>Dashboard</span>
                </a>
            </li>
            <li class="nav-item">
                <a href="sup-workforce_ready.php" class="nav-link active">
                    <span class="nav-icon">👥</span>
                    <span>Workforce Ready</span>
                </a>
            </li>
            <li class="nav-item">
                <a href="sup-training_due.php" class="nav-link">
                    <span class="nav-icon">🎓</span>
                    <span>Training Due</span>
                </a>
            </li>
            <li class="nav-item">
                <a href="sup-expired_certs.php" class="nav-link">
                    <span class="nav-icon">📜</span>
                    <span>Expired Certs</span>
                </a>
            </li>
            <li class="nav-item">
                <a href="sup-pending_leave.php" class="nav-link">
                    <span class="nav-icon">📅</span>
                    <span>Pending Leave</span>
                </a>
            </li>
        </ul>
    </nav>
</aside>

    <!-- Main Content -->
    <main class="main-content">
        <header class="header">
            <div class="welcome-section">
                <h2>Workforce Readiness</h2>
                <p>Monitor staff training completion and certification status</p>
            </div>
            <div class="header-actions">
                <div class="user-info">
                    <span><strong><?php echo htmlspecialchars($username, ENT_QUOTES | ENT_HTML5, 'UTF-8'); ?></strong></span>
                    <span style="text-transform: capitalize;"><?php echo htmlspecialchars($role, ENT_QUOTES | ENT_HTML5, 'UTF-8'); ?></span>
                </div>
                <a href="?logout=1" class="logout-btn">Logout</a>
            </div>
        </header>

        <div class="stats-banner">
            <?php
            $total_staff = count($employees);
            $ready_count = count(array_filter($employees, fn($e) => ($e['readiness_status'] ?? '') === 'READY'));
            $not_ready_count = $total_staff - $ready_count;
            $ready_percentage = $total_staff > 0 ? round(($ready_count / $total_staff) * 100) : 0;
            ?>
            <div class="stat-card">
                <div class="stat-value"><?php echo (int)$total_staff; ?></div>
                <div class="stat-label">Total Staff</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #4ade80;"><?php echo (int)$ready_count; ?></div>
                <div class="stat-label">Ready</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #f87171;"><?php echo (int)$not_ready_count; ?></div>
                <div class="stat-label">Not Ready</div>
            </div>
            <div class="stat-card">
                <div class="stat-value"><?php echo (int)$ready_percentage; ?>%</div>
                <div class="stat-label">Readiness Rate</div>
            </div>
        </div>

        <section class="directory-section">
            <div class="directory-header">
                <h2 class="directory-title">Staff Directory</h2>
                <form method="GET" class="filters-container">
                    <input 
                        type="text" 
                        name="search" 
                        class="search-input" 
                        placeholder="Search Name or Role..."
                        value="<?php echo $search_query; ?>"
                    >
                    <select name="department" class="filter-select" onchange="this.form.submit()">
                        <option value="all" <?php echo $department_filter === 'all' ? 'selected' : ''; ?>>All Departments</option>
                        <?php foreach ($departments as $dept): ?>
                        <option value="<?php echo $dept; ?>" <?php echo $department_filter === $dept ? 'selected' : ''; ?>>
                            <?php echo $dept; ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                    <select name="status" class="filter-select" onchange="this.form.submit()">
                        <option value="all" <?php echo $status_filter === 'all' ? 'selected' : ''; ?>>All Statuses</option>
                        <option value="READY" <?php echo $status_filter === 'READY' ? 'selected' : ''; ?>>Ready</option>
                        <option value="NOT READY" <?php echo $status_filter === 'NOT READY' ? 'selected' : ''; ?>>Not Ready</option>
                    </select>
                </form>
            </div>

            <?php if (count($employees) > 0): ?>
            <table class="employee-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Department</th>
                        <th>Job Title</th>
                        <th>Issues</th>
                        <th>Status</th>
                        <th>Reason</th>
                        <th>Updated</th>
                        <?php if (($_SESSION['role'] ?? '') === 'supervisor'): ?>
                        <th>Action</th>
                        <?php endif; ?>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($employees as $employee): ?>
                    <tr>
                        <td><?php echo $employee['name']; ?></td>
                        <td><?php echo $employee['department_name']; ?></td>
                        <td><?php echo $employee['job_title']; ?></td>
                        <td>
                            <?php if ((int)$employee['pending_training'] > 0): ?>
                            <span class="details-badge warning">🎓 <?php echo (int)$employee['pending_training']; ?> Training Pending</span>
                            <?php endif; ?>
                            <?php if ((int)$employee['expired_certs'] > 0): ?>
                            <span class="details-badge warning">📜 <?php echo (int)$employee['expired_certs']; ?> Cert Expired</span>
                            <?php endif; ?>
                            <?php if ((int)$employee['pending_training'] === 0 && (int)$employee['expired_certs'] === 0): ?>
                            <span class="details-badge">✓ All Clear</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <span class="status-badge <?php echo strtolower(str_replace(' ', '-', (string)$employee['readiness_status'])); ?>">
                                <?php echo htmlspecialchars((string)$employee['readiness_status'], ENT_QUOTES, 'UTF-8'); ?>
                            </span>
                        </td>
                        <td><?php echo $employee['reason']; ?></td>
                        <td><?php echo !empty($employee['updated_at']) ? htmlspecialchars(date('Y-m-d H:i', strtotime((string)$employee['updated_at'])), ENT_QUOTES, 'UTF-8') : '-'; ?></td>
                        <?php if (($_SESSION['role'] ?? '') === 'supervisor'): ?>
                        <td>
                            <button 
                                class="toggle-btn <?php echo !empty($employee['is_ready']) ? 'ready' : 'not-ready'; ?>" 
                                data-id="<?php echo (int)$employee['id']; ?>"
                                data-current="<?php echo !empty($employee['is_ready']) ? '1' : '0'; ?>">
                                <?php echo !empty($employee['is_ready']) ? '✓ Ready' : '✗ Not Ready'; ?>
                            </button>
                        </td>
                        <?php endif; ?>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php else: ?>
            <div class="no-results">
                No employees found matching your search criteria.
            </div>
            <?php endif; ?>
        </section>
    </main>
</div>

<script>
// DOM-based XSS prevention: send plain text to server; never inject into DOM as HTML
document.querySelectorAll('.toggle-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        const staffId = this.dataset.id;

        const reason = prompt('Enter reason (required):');
        if (reason === null || reason.trim() === '') {
            alert('Reason is required');
            return;
        }

        fetch('toggle_ready.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                staff_id: staffId,
                reason: reason
            })
        })
        .then(r => r.text())
        .then(data => {
            if (data.trim() === 'OK') {
                location.reload();
            } else {
                alert('Error: ' + data);
            }
        })
        .catch(() => alert('Network error'));
    });
});
</script>

<?php
  // keeps your existing library popups (e.g. SQLi) if your sql-prevention.php provides them
  if (function_exists('render_security_popups')) {
      render_security_popups();
  }
?>

</body>
</html>
