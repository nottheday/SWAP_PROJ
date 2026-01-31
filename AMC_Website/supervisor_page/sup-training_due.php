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
   ✅ URL Tampering Popup (SUP-TRAINING DUE)
   Requirements (same style as your staff-apply_leave.php):
   1) If ?role=staff/admin/supervisor (ANY role param) => popup + clean reload
   2) If any ID-like param present => popup + clean reload
   3) If ANY unexpected query string keys appear (URL edited) => popup + clean reload
   4) If someone tries to load this script under a different filename/path
      => popup + redirect back to the correct sup-training_due.php clean URL
   Notes:
   - We allow only: logout, employee, course, priority, date (GET) for this page.
================================ */
$EXPECTED_FILE = 'sup-training_due.php';

function suptr_clean_url(array $removeKeys = ['role','id','staff_id','employee_id','user_id','user']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);

    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function suptr_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) {
        $_SESSION['flash_unauth'] = 1;
    }

    $clean = suptr_clean_url();

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
   (e.g. sup-training_due.php changed to admin-dashboard.php in URL)
================================ */
$currentFile = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '');
if ($currentFile !== '' && strtolower($currentFile) !== strtolower($EXPECTED_FILE)) {
    suptr_redirect_clean(true, $EXPECTED_FILE);
}

/* ===============================
   Detect ANY unexpected query keys
   Allowed keys for this page: logout, employee, course, priority, date
================================ */
$allowedKeys = ['logout', 'employee', 'course', 'priority', 'date'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        suptr_redirect_clean(true);
    }
}

/* ===============================
   Explicit tamper triggers (kept for clarity)
================================ */
if (isset($_GET['role'])) {
    // ANY role param triggers popup (even if it matches)
    suptr_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['staff_id']) || isset($_GET['employee_id']) || isset($_GET['user_id']) || isset($_GET['user'])) {
    suptr_redirect_clean(true);
}

/* =========================
   RBAC: supervisor only
   ========================= */
if ($role !== 'supervisor') {
    http_response_code(403);
    die("Access Denied: Supervisors only.");
}

/* =========================
   CSRF helpers
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
   Fetch supervisor profile
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

/* =========================
   Filters (Reflected XSS safe on output)
   ========================= */
$employee_filter = (string)($_GET['employee'] ?? '');
$course_filter   = (string)($_GET['course'] ?? '');
$priority_filter = (string)($_GET['priority'] ?? 'all');
$date_filter     = (string)($_GET['date'] ?? '');

/* =========================
   Fetch pending training
   ========================= */
$query = "
    SELECT 
        s.id as staff_id,
        s.name as employee_name,
        ts.id as training_sessions_id,
        ts.name as course_title,
        ts.description as course_description,
        ts.start_date as due_date,
        ta.status,
        CASE 
            WHEN ts.start_date <= DATE_ADD(CURDATE(), INTERVAL 7 DAY) THEN 'HIGH'
            ELSE 'NORMAL'
        END as priority
    FROM training_attendance ta
    JOIN staff s ON ta.staff_id = s.id
    JOIN training_sessions ts ON ta.training_sessions_id = ts.id
    WHERE ta.status = 'pending' AND s.status = 'active'
";

/* Add filters safely using prepared statements */
$params = [];
$types  = "";

/* Employee filter */
if ($employee_filter !== '') {
    $query .= " AND s.name LIKE ?";
    $employee_param = "%" . $employee_filter . "%";
    $params[] = $employee_param;
    $types   .= "s";
}

/* Course filter */
if ($course_filter !== '') {
    $query .= " AND ts.name LIKE ?";
    $course_param = "%" . $course_filter . "%";
    $params[] = $course_param;
    $types   .= "s";
}

/* Date filter */
if ($date_filter !== '') {
    $query .= " AND DATE_FORMAT(ts.start_date, '%Y-%m') = ?";
    $params[] = $date_filter;
    $types   .= "s";
}

$query .= " ORDER BY ts.start_date ASC, s.name ASC";

$stmt = $mysqli->prepare($query);
if (!$stmt) {
    die("Query prepare failed.");
}
if (!empty($params)) {
    $stmt->bind_param($types, ...$params);
}

$stmt->execute();
$result = $stmt->get_result();

$training_requirements = [];
while ($row = $result->fetch_assoc()) {
    $training_requirements[] = $row;
}
$stmt->close();

/* Apply priority filter after fetching */
if ($priority_filter !== 'all') {
    $training_requirements = array_values(array_filter($training_requirements, fn($t) => ($t['priority'] ?? '') === $priority_filter));
}

/* =========================
   Mark training complete
   ========================= */
$success_message = null;
$error_message   = null;

if (isset($_POST['mark_complete'])) {
    requireCsrf();

    $staff_id    = (int)($_POST['staff_id'] ?? 0);
    $training_id = (int)($_POST['training_id'] ?? 0);

    if ($staff_id <= 0 || $training_id <= 0) {
        $error_message = "Invalid request.";
    } else {
        $update_stmt = $mysqli->prepare("
            UPDATE training_attendance 
            SET status = 'completed', completion_date = CURDATE() 
            WHERE staff_id = ? AND training_sessions_id = ?
        ");
        if ($update_stmt) {
            $update_stmt->bind_param("ii", $staff_id, $training_id);
            if ($update_stmt->execute()) {
                $success_message = "Training marked as completed successfully!";
            } else {
                $error_message = "Failed to update training status.";
            }
            $update_stmt->close();
        } else {
            $error_message = "Server error.";
        }
    }

    header("Location: " . $EXPECTED_FILE);
    exit;
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
<title>AMC HR - Training Due</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
/* Reset */
* {margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Inter',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;}
.container{display:flex;min-height:100vh;}
/* Sidebar */
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
/* Main content */
.main-content{flex:1;margin-left:280px;padding:32px 48px;}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:48px;gap:20px;}
.welcome-section h2{font-size:28px;font-weight:700;color:#e2e8f0;margin-bottom:8px;}
.welcome-section p{font-size:14px;color:#94a3b8;}
.header-actions{display:flex;align-items:center;gap:20px;}
.user-info{display:flex;flex-direction:column;align-items:flex-end;color:#94a3b8;font-size:14px;}
.user-info strong{color:#60a5fa;font-weight:600;}
.logout-btn{padding:10px 24px;background:rgba(239,68,68,0.2);border:1px solid rgba(239,68,68,0.4);border-radius:8px;color:#fca5a5;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none;transition:all 0.2s ease;}
.logout-btn:hover{background:rgba(239,68,68,0.3);border-color:rgba(239,68,68,0.6);}
/* Filters */
.filter-section{background:rgba(15,23,42,0.6);border:1px solid rgba(71,85,105,0.3);border-radius:12px;padding:24px;margin-bottom:32px;}
.filter-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px;}
.filter-group{display:flex;flex-direction:column;gap:8px;}
.filter-label{font-size:13px;font-weight:600;color:#60a5fa;text-transform:uppercase;letter-spacing:0.5px;}
.filter-input,.filter-select{padding:12px 16px;background:rgba(30,41,59,0.6);border:1px solid rgba(71,85,105,0.4);border-radius:8px;color:#e2e8f0;font-size:14px;font-family:'Inter',sans-serif;outline:none;transition:all 0.2s ease;}
.filter-input::placeholder{color:#64748b;}
.filter-input:focus,.filter-select:focus{background:rgba(30,41,59,0.8);border-color:#3b82f6;}
.filter-select{cursor:pointer;appearance:none;background-image:url("data:image/svg+xml,%3Csvg width='12' height='8' viewBox='0 0 12 8' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 1L6 6L11 1' stroke='%2394a3b8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 16px center;padding-right:40px;}
.filter-select option{background:#1e293b;color:#e2e8f0;}
/* Stats */
.stats-banner{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:32px;}
.stat-card{padding:20px;background:rgba(30,41,59,0.6);border:1px solid rgba(71,85,105,0.3);border-radius:12px;text-align:center;}
.stat-value{font-size:32px;font-weight:700;color:#60a5fa;margin-bottom:8px;}
.stat-label{font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;}
/* Table */
.training-table{width:100%;border-collapse:collapse;background:rgba(15,23,42,0.6);border:1px solid rgba(71,85,105,0.3);border-radius:12px;overflow:hidden;}
.training-table thead{background:rgba(30,41,59,0.8);border-bottom:1px solid rgba(71,85,105,0.4);}
.training-table th{padding:16px;text-align:left;font-size:13px;font-weight:600;color:#60a5fa;text-transform:uppercase;letter-spacing:0.5px;}
.training-table td{padding:20px 16px;border-bottom:1px solid rgba(71,85,105,0.2);font-size:15px;color:#e2e8f0;}
.training-table tbody tr{transition:all 0.2s ease;}
.training-table tbody tr:hover{background:rgba(59,130,246,0.05);}
.priority-badge{display:inline-block;padding:6px 16px;border-radius:6px;font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;}
.priority-badge.high{background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3);}
.priority-badge.normal{background:rgba(59,130,246,0.15);color:#60a5fa;border:1px solid rgba(59,130,246,0.3);}
.action-btn{padding:10px 20px;background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);border:none;border-radius:8px;color:#ffffff;font-size:14px;font-weight:600;cursor:pointer;transition:all 0.2s ease;box-shadow:0 2px 8px rgba(59,130,246,0.3);}
.action-btn:hover{background:linear-gradient(135deg,#2563eb 0%,#1d4ed8 100%);box-shadow:0 4px 12px rgba(59,130,246,0.4);transform:translateY(-1px);}
.action-btn:active{transform:translateY(0);}
.success-message{background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);color:#86efac;padding:12px 16px;border-radius:8px;margin-bottom:20px;font-size:14px;text-align:center;}
.error-message{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#fca5a5;padding:12px 16px;border-radius:8px;margin-bottom:20px;font-size:14px;text-align:center;}
.no-results{text-align:center;padding:48px;color:#94a3b8;font-size:16px;}
@media(max-width:1024px){.sidebar{width:240px}.main-content{margin-left:240px;padding:24px 32px;}}
@media(max-width:768px){.sidebar{width:100%;position:relative;height:auto;border-right:none;border-bottom:1px solid rgba(71,85,105,0.3);}.main-content{margin-left:0;padding:20px;}.container{flex-direction:column;}.header{flex-direction:column;align-items:flex-start;}.header-actions{width:100%;justify-content:space-between;}.filter-grid{grid-template-columns:1fr;}.training-table{font-size:14px;}.training-table th,.training-table td{padding:12px 8px;}}

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
        <span class="role-badge" id="role-badge"><?php echo htmlspecialchars($role, ENT_QUOTES, 'UTF-8'); ?></span>
    </div>
    <nav>
        <ul class="nav-menu">
            <li class="nav-item"><a href="sup-dashboard.php" class="nav-link"><span class="nav-icon">📊</span><span>Dashboard</span></a></li>
            <li class="nav-item"><a href="sup-workforce_ready.php" class="nav-link"><span class="nav-icon">👥</span><span>Workforce Ready</span></a></li>
            <li class="nav-item"><a href="sup-training_due.php" class="nav-link active"><span class="nav-icon">🎓</span><span>Training Due</span></a></li>
            <li class="nav-item"><a href="sup-expired_certs.php" class="nav-link"><span class="nav-icon">📜</span><span>Expired Certs</span></a></li>
            <li class="nav-item"><a href="sup-pending_leave.php" class="nav-link"><span class="nav-icon">📅</span><span>Pending Leave</span></a></li>
        </ul>
    </nav>
</aside>

<!-- Main Content -->
<main class="main-content">
<header class="header">
    <div class="welcome-section">
        <h2>Training Due</h2>
        <p>Monitor and manage pending training requirements</p>
    </div>
    <div class="header-actions">
        <div class="user-info">
            <span><strong id="user-name"><?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></strong></span>
            <span style="text-transform: capitalize;" id="user-role"><?php echo htmlspecialchars($role, ENT_QUOTES, 'UTF-8'); ?></span>
        </div>
        <a href="?logout=1" class="logout-btn">Logout</a>
    </div>
</header>

<?php if($success_message): ?>
<div class="success-message"><?php echo htmlspecialchars((string)$success_message, ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>
<?php if($error_message): ?>
<div class="error-message"><?php echo htmlspecialchars((string)$error_message, ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>

<!-- Stats Banner -->
<div class="stats-banner">
<?php
$total_training   = count($training_requirements);
$high_priority    = count(array_filter($training_requirements, fn($t)=>($t['priority'] ?? '')==='HIGH'));
$normal_priority  = $total_training - $high_priority;
?>
<div class="stat-card"><div class="stat-value"><?php echo (int)$total_training; ?></div><div class="stat-label">Total Pending</div></div>
<div class="stat-card"><div class="stat-value" style="color:#f87171;"><?php echo (int)$high_priority; ?></div><div class="stat-label">High Priority</div></div>
<div class="stat-card"><div class="stat-value" style="color:#60a5fa;"><?php echo (int)$normal_priority; ?></div><div class="stat-label">Normal Priority</div></div>
</div>

<!-- Filters -->
<div class="filter-section">
<form method="GET" class="filter-grid">
<div class="filter-group">
<label class="filter-label">Employee</label>
<input type="text" name="employee" class="filter-input" placeholder="Search employee..." value="<?php echo htmlspecialchars($employee_filter, ENT_QUOTES, 'UTF-8');?>"/>
</div>
<div class="filter-group">
<label class="filter-label">Course Title</label>
<input type="text" name="course" class="filter-input" placeholder="Search course..." value="<?php echo htmlspecialchars($course_filter, ENT_QUOTES, 'UTF-8');?>"/>
</div>
<div class="filter-group">
<label class="filter-label">Priority</label>
<select name="priority" class="filter-select" onchange="this.form.submit()">
<option value="all" <?php echo $priority_filter==='all'?'selected':'';?>>All</option>
<option value="HIGH" <?php echo $priority_filter==='HIGH'?'selected':'';?>>High</option>
<option value="NORMAL" <?php echo $priority_filter==='NORMAL'?'selected':'';?>>Normal</option>
</select>
</div>
<div class="filter-group">
<label class="filter-label">Due Date (Month)</label>
<input type="month" name="date" class="filter-input" value="<?php echo htmlspecialchars($date_filter, ENT_QUOTES, 'UTF-8');?>" onchange="this.form.submit()"/>
</div>
</form>
</div>

<!-- DOM XSS prevention: Build table safely using JS -->
<div id="training-table-container"></div>

<script>
// DOM XSS prevention: use textContent, never innerHTML
const trainings = <?php echo json_encode($training_requirements, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>;
const container = document.getElementById('training-table-container');

if (Array.isArray(trainings) && trainings.length > 0) {
    const table = document.createElement('table');
    table.className = 'training-table';

    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    ['EMPLOYEE NAME','REQUIRED COURSE','DUE DATE','PRIORITY','ACTION'].forEach(h => {
        const th = document.createElement('th');
        th.textContent = h;
        headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');

    trainings.forEach(t => {
        const tr = document.createElement('tr');

        const tdName = document.createElement('td');
        tdName.textContent = String(t.employee_name ?? '');
        tr.appendChild(tdName);

        const tdCourse = document.createElement('td');
        const strong = document.createElement('strong');
        strong.textContent = String(t.course_title ?? '');
        tdCourse.appendChild(strong);

        if (t.course_description) {
            const br = document.createElement('br');
            tdCourse.appendChild(br);
            const small = document.createElement('small');
            small.style.color = '#94a3b8';
            small.textContent = String(t.course_description);
            tdCourse.appendChild(small);
        }
        tr.appendChild(tdCourse);

        const tdDue = document.createElement('td');
        const dueDate = new Date(String(t.due_date ?? ''));
        tdDue.textContent = isNaN(dueDate.getTime())
            ? '-'
            : dueDate.toLocaleDateString('en-US', {month:'short', day:'2-digit', year:'numeric'});
        tr.appendChild(tdDue);

        const tdPriority = document.createElement('td');
        const span = document.createElement('span');
        const pr = String(t.priority ?? 'NORMAL').toLowerCase();
        span.className = 'priority-badge ' + pr;
        span.textContent = String(t.priority ?? 'NORMAL');
        tdPriority.appendChild(span);
        tr.appendChild(tdPriority);

        const tdAction = document.createElement('td');
        const form = document.createElement('form');
        form.method = 'POST';
        form.style.display = 'inline';

        const staffInput = document.createElement('input');
        staffInput.type = 'hidden';
        staffInput.name = 'staff_id';
        staffInput.value = String(t.staff_id ?? '');
        form.appendChild(staffInput);

        const trainingInput = document.createElement('input');
        trainingInput.type = 'hidden';
        trainingInput.name = 'training_id';
        trainingInput.value = String(t.training_sessions_id ?? '');
        form.appendChild(trainingInput);

        const csrfInput = document.createElement('input');
        csrfInput.type = 'hidden';
        csrfInput.name = 'csrf_token';
        csrfInput.value = <?php echo json_encode((string)($_SESSION['csrf_token'] ?? ''), JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT); ?>;
        form.appendChild(csrfInput);

        const btn = document.createElement('button');
        btn.type = 'submit';
        btn.name = 'mark_complete';
        btn.className = 'action-btn';
        btn.textContent = 'Mark Complete';
        form.appendChild(btn);

        tdAction.appendChild(form);
        tr.appendChild(tdAction);

        tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    container.appendChild(table);
} else {
    const noResults = document.createElement('div');
    noResults.className = 'no-results';
    noResults.textContent = 'No pending training requirements found matching your filters.';
    container.appendChild(noResults);
}
</script>

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
