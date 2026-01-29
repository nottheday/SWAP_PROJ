<?php
/* =========================
   0) SESSION HARDENING
   IMPORTANT: ini_set MUST be before session_start()
   ========================= */
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
// ini_set('session.cookie_secure', '1'); // enable only if HTTPS

session_start();

/* =========================
   1) BLOCK URL TAMPERING
   ========================= */
if (isset($_GET['role'])) {
    $requestedRole = strtolower($_GET['role']);
    $sessionRole   = strtolower($_SESSION['role'] ?? '');

    // If role in URL does NOT match session role → tampering
    if ($requestedRole !== $sessionRole) {
        http_response_code(403);
        exit("Forbidden: role tampering detected.");
    }

    // If it matches (e.g. bob ?role=supervisor), ignore it
    unset($_GET['role']);
}

// ID-based tampering should always be blocked
if (isset($_GET['id']) || isset($_GET['employee_id'])) {
    http_response_code(403);
    exit("Forbidden: parameter tampering detected.");
}

/* =========================
   2) DATABASE CONFIG
   ========================= */
$db_host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "swap";

$mysqli = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($mysqli->connect_error) {
    die("Database connection failed: " . $mysqli->connect_error);
}

/* =========================
   3) AUTH + RBAC
   ========================= */
if (!isset($_SESSION['auth']) || !isset($_SESSION['user']) || !isset($_SESSION['role'])) {
    header('Location: login.php');
    exit;
}

if ($_SESSION['role'] !== 'supervisor') {
    http_response_code(403);
    die("Access Denied: This page is for supervisors only.");
}

$username = $_SESSION['user'];
$role = $_SESSION['role'];

/* =========================
   4) CSRF TOKEN
   ========================= */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* =========================
   5) Helper: check if a column exists
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
   6) Get logged-in supervisor ID
   ========================= */
$user_stmt = $mysqli->prepare("SELECT id FROM users WHERE username = ?");
$user_stmt->bind_param("s", $username);
$user_stmt->execute();
$user_stmt->bind_result($logged_in_user_id);
$user_stmt->fetch();
$user_stmt->close();

if (empty($logged_in_user_id)) {
    http_response_code(500);
    die("Unable to resolve supervisor user id.");
}

/* =========================
   7) OPTIONAL SCOPE CONTROL
   - Prefer supervisor_id if it exists (your DB doesn't)
   - Else use department-based scope if users.department_id exists
   ========================= */
$has_staff_supervisor_id = columnExists($mysqli, 'staff', 'supervisor_id');
$has_users_department_id = columnExists($mysqli, 'users', 'department_id');
$has_staff_department_id = columnExists($mysqli, 'staff', 'department_id');

$supervisor_department_id = null;

if (!$has_staff_supervisor_id && $has_users_department_id) {
    // Try to get supervisor's department_id (if column exists)
    $deptStmt = $mysqli->prepare("SELECT department_id FROM users WHERE id = ?");
    if ($deptStmt) {
        $deptStmt->bind_param("i", $logged_in_user_id);
        $deptStmt->execute();
        $deptStmt->bind_result($supervisor_department_id);
        $deptStmt->fetch();
        $deptStmt->close();
    }
}

/* =========================
   8) Handle approve/reject actions (POST only)
   - CSRF protection
   - validate action + leave_id
   - Scope enforcement:
       A) if staff.supervisor_id exists -> enforce team
       B) else if users.department_id exists -> enforce department scope
       C) else -> no scope check possible (still safe vs URL tampering)
   ========================= */
$success_message = null;
$error_message = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF validate
    $csrf = $_POST['csrf_token'] ?? '';
    if (!is_string($csrf) || !hash_equals($_SESSION['csrf_token'], $csrf)) {
        http_response_code(403);
        die("CSRF blocked.");
    }

    $action = $_POST['action'] ?? '';
    $leave_id = filter_input(INPUT_POST, 'leave_id', FILTER_VALIDATE_INT);

    if (!in_array($action, ['approve', 'reject'], true) || !$leave_id || $leave_id <= 0) {
        http_response_code(400);
        die("Invalid request.");
    }

    $new_status = ($action === 'approve') ? 'approved' : 'rejected';

    // ----- Scope check (if possible) -----
    $scope_ok = true;

    if ($has_staff_supervisor_id) {
        // Team scope via staff.supervisor_id (only if your schema has it)
        $scope_check = $mysqli->prepare("
            SELECT la.id
            FROM leave_application la
            JOIN staff s ON la.staff_id = s.id
            WHERE la.id = ?
              AND s.supervisor_id = ?
            LIMIT 1
        ");
        if ($scope_check) {
            $scope_check->bind_param("ii", $leave_id, $logged_in_user_id);
            $scope_check->execute();
            $scope_check->store_result();
            $scope_ok = ($scope_check->num_rows === 1);
            $scope_check->close();
        }
    } elseif ($has_users_department_id && $has_staff_department_id && !empty($supervisor_department_id)) {
        // Department scope via users.department_id -> staff.department_id
        $scope_check = $mysqli->prepare("
            SELECT la.id
            FROM leave_application la
            JOIN staff s ON la.staff_id = s.id
            WHERE la.id = ?
              AND s.department_id = ?
            LIMIT 1
        ");
        if ($scope_check) {
            $scope_check->bind_param("ii", $leave_id, $supervisor_department_id);
            $scope_check->execute();
            $scope_check->store_result();
            $scope_ok = ($scope_check->num_rows === 1);
            $scope_check->close();
        }
    }

    if (!$scope_ok) {
        http_response_code(403);
        die("Forbidden: You can only approve/reject leave within your scope.");
    }

    // Update leave status safely
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

        // POST-Redirect-GET
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
}

/* =========================
   9) Handle filters (GET)
   ========================= */
$name_filter = $_GET['name'] ?? '';
$department_filter = $_GET['department'] ?? 'all';
$leave_type_filter = $_GET['leave_type'] ?? 'all';
$status_filter = $_GET['status'] ?? 'all';

/* =========================
   10) Build query to get leave requests
   - Also scope list by supervisor/team if possible
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

/* Scope the supervisor’s view */
$types = "";
$params = [];

if ($has_staff_supervisor_id) {
    $query .= " AND s.supervisor_id = ?";
    $types .= "i";
    $params[] = &$logged_in_user_id;
} elseif ($has_users_department_id && $has_staff_department_id && !empty($supervisor_department_id)) {
    $query .= " AND s.department_id = ?";
    $types .= "i";
    $params[] = &$supervisor_department_id;
}

/* Add filters */
if (!empty($name_filter)) {
    $query .= " AND s.name LIKE ?";
    $name_param = "%{$name_filter}%";
    $types .= "s";
    $params[] = &$name_param;
}
if ($department_filter !== 'all') {
    $query .= " AND d.name = ?";
    $types .= "s";
    $params[] = &$department_filter;
}
if ($leave_type_filter !== 'all') {
    $query .= " AND lt.name = ?";
    $types .= "s";
    $params[] = &$leave_type_filter;
}
if ($status_filter !== 'all') {
    $query .= " AND la.status = ?";
    $types .= "s";
    $params[] = &$status_filter;
}

$query .= " ORDER BY 
    CASE la.status 
        WHEN 'pending' THEN 1 
        WHEN 'approved' THEN 2 
        WHEN 'rejected' THEN 3 
    END, 
    la.start_date DESC";

/* Prepare statement */
$stmt = $mysqli->prepare($query);
if (!$stmt) {
    die("Query prepare failed: " . $mysqli->error);
}

/* Bind parameters if any */
if (!empty($params)) {
    array_unshift($params, $types);
    call_user_func_array([$stmt, 'bind_param'], $params);
}

$stmt->execute();
$result = $stmt->get_result();

/* Fetch all leave requests */
$leave_requests = [];
while ($row = $result->fetch_assoc()) {
    $leave_requests[] = $row;
}
$stmt->close();

/* =========================
   11) Filter dropdown data
   ========================= */
$dept_query = "SELECT DISTINCT name FROM department ORDER BY name";
$dept_result = $mysqli->query($dept_query);
$departments = [];
while ($dept = $dept_result->fetch_assoc()) {
    $departments[] = $dept['name'];
}

$leave_types_query = "SELECT DISTINCT name FROM leave_type ORDER BY name";
$leave_types_result = $mysqli->query($leave_types_query);
$leave_types = [];
while ($lt = $leave_types_result->fetch_assoc()) {
    $leave_types[] = $lt['name'];
}

/* =========================
   12) Logout
   ========================= */
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header('Location: login.php');
    exit;
}

$mysqli->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AMC HR - Pending Leave</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        /* ✅ YOUR ORIGINAL CSS (UNCHANGED) */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
        .container { display: flex; min-height: 100vh; }
        .sidebar { width: 280px; background: rgba(15, 23, 42, 0.95); border-right: 1px solid rgba(71, 85, 105, 0.3); padding: 32px 0; position: fixed; height: 100vh; overflow-y: auto; }
        .logo { padding: 0 32px; margin-bottom: 48px; }
        .logo h1 { font-size: 32px; font-weight: 700; background: linear-gradient(135deg, #60a5fa 0%, #3b82f6 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .logo .role-badge { display: inline-block; margin-top: 8px; padding: 4px 12px; background: rgba(251, 146, 60, 0.2); border: 1px solid rgba(251, 146, 60, 0.3); border-radius: 6px; font-size: 12px; font-weight: 600; color: #fb923c; text-transform: uppercase; }
        .nav-menu { list-style: none; }
        .nav-item { margin-bottom: 8px; }
        .nav-link { display: flex; align-items: center; gap: 12px; padding: 14px 32px; color: #94a3b8; text-decoration: none; font-size: 15px; font-weight: 500; transition: all 0.2s ease; border-left: 3px solid transparent; }
        .nav-link:hover { background: rgba(59, 130, 246, 0.1); color: #60a5fa; border-left-color: #3b82f6; }
        .nav-link.active { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border-left-color: #3b82f6; }
        .nav-icon { font-size: 20px; }
        .main-content { flex: 1; margin-left: 280px; padding: 32px 48px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 48px; gap: 20px; }
        .welcome-section h2 { font-size: 28px; font-weight: 700; color: #e2e8f0; margin-bottom: 8px; }
        .welcome-section p { font-size: 14px; color: #94a3b8; }
        .header-actions { display: flex; align-items: center; gap: 20px; }
        .user-info { display: flex; flex-direction: column; align-items: flex-end; color: #94a3b8; font-size: 14px; }
        .user-info strong { color: #60a5fa; font-weight: 600; }
        .logout-btn { padding: 10px 24px; background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 8px; color: #fca5a5; font-size: 14px; font-weight: 600; cursor: pointer; text-decoration: none; transition: all 0.2s ease; }
        .logout-btn:hover { background: rgba(239, 68, 68, 0.3); border-color: rgba(239, 68, 68, 0.6); }
        .success-message { background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); color: #86efac; padding: 12px 16px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; text-align: center; }
        .error-message { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); color: #fca5a5; padding: 12px 16px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; text-align: center; }
        .stats-banner { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }
        .stat-card { padding: 20px; background: rgba(30, 41, 59, 0.6); border: 1px solid rgba(71, 85, 105, 0.3); border-radius: 12px; text-align: center; }
        .stat-value { font-size: 32px; font-weight: 700; color: #60a5fa; margin-bottom: 8px; }
        .stat-label { font-size: 13px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }
        .filter-section { background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(71, 85, 105, 0.3); border-radius: 12px; padding: 24px; margin-bottom: 32px; }
        .filter-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; }
        .filter-group { display: flex; flex-direction: column; gap: 8px; }
        .filter-label { font-size: 13px; font-weight: 600; color: #60a5fa; text-transform: uppercase; letter-spacing: 0.5px; }
        .filter-input, .filter-select { padding: 12px 16px; background: rgba(30, 41, 59, 0.6); border: 1px solid rgba(71, 85, 105, 0.4); border-radius: 8px; color: #e2e8f0; font-size: 14px; font-family: 'Inter', sans-serif; outline: none; transition: all 0.2s ease; }
        .filter-input::placeholder { color: #64748b; }
        .filter-input:focus, .filter-select:focus { background: rgba(30, 41, 59, 0.8); border-color: #3b82f6; }
        .filter-select { cursor: pointer; appearance: none; background-image: url("data:image/svg+xml,%3Csvg width='12' height='8' viewBox='0 0 12 8' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 1L6 6L11 1' stroke='%2394a3b8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 16px center; padding-right: 40px; }
        .filter-select option { background: #1e293b; color: #e2e8f0; }
        .leave-table { width: 100%; border-collapse: collapse; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(71, 85, 105, 0.3); border-radius: 12px; overflow: hidden; }
        .leave-table thead { background: rgba(30, 41, 59, 0.8); border-bottom: 1px solid rgba(71, 85, 105, 0.4); }
        .leave-table th { padding: 16px; text-align: left; font-size: 13px; font-weight: 600; color: #60a5fa; text-transform: uppercase; letter-spacing: 0.5px; }
        .leave-table td { padding: 20px 16px; border-bottom: 1px solid rgba(71, 85, 105, 0.2); font-size: 15px; color: #e2e8f0; }
        .leave-table tbody tr { transition: all 0.2s ease; }
        .leave-table tbody tr:hover { background: rgba(59, 130, 246, 0.05); }
        .leave-table tbody tr:last-child td { border-bottom: none; }
        .status-badge { display: inline-block; padding: 6px 16px; border-radius: 6px; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        .status-badge.pending { background: rgba(234, 179, 8, 0.15); color: #fbbf24; border: 1px solid rgba(234, 179, 8, 0.3); }
        .status-badge.approved { background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3); }
        .status-badge.rejected { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
        .action-buttons { display: flex; gap: 10px; }
        .approve-btn, .reject-btn { padding: 10px 20px; border: none; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s ease; }
        .approve-btn { background: #22c55e; color: #ffffff; box-shadow: 0 2px 8px rgba(34, 197, 94, 0.3); }
        .approve-btn:hover { background: #16a34a; box-shadow: 0 4px 12px rgba(34, 197, 94, 0.4); transform: translateY(-1px); }
        .reject-btn { background: #ef4444; color: #ffffff; box-shadow: 0 2px 8px rgba(239, 68, 68, 0.3); }
        .reject-btn:hover { background: #dc2626; box-shadow: 0 4px 12px rgba(239, 68, 68, 0.4); transform: translateY(-1px); }
        .approve-btn:active, .reject-btn:active { transform: translateY(0); }
        .processed-text { color: #64748b; font-size: 14px; font-style: italic; }
        .no-results { text-align: center; padding: 48px; color: #94a3b8; font-size: 16px; }
        @media (max-width: 1024px) { .sidebar { width: 240px; } .main-content { margin-left: 240px; padding: 24px 32px; } }
        @media (max-width: 768px) { .sidebar { width: 100%; position: relative; height: auto; border-right: none; border-bottom: 1px solid rgba(71, 85, 105, 0.3); } .main-content { margin-left: 0; padding: 20px; } .container { flex-direction: column; } .header { flex-direction: column; align-items: flex-start; } .header-actions { width: 100%; justify-content: space-between; } .filter-grid { grid-template-columns: 1fr; } .leave-table { font-size: 14px; } .leave-table th, .leave-table td { padding: 12px 8px; } .action-buttons { flex-direction: column; } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .leave-table tbody tr { animation: fadeIn 0.4s ease-out forwards; }
    </style>
</head>
<body>
<div class="container">
    <!-- Sidebar -->
    <aside class="sidebar">
        <div class="logo">
            <h1>AMC HR</h1>
            <span class="role-badge">Supervisor</span>
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
                    <a href="sup-workforce_ready.php" class="nav-link">
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
                    <a href="sup-pending_leave.php" class="nav-link active">
                        <span class="nav-icon">📅</span>
                        <span>Pending Leave</span>
                    </a>
                </li>
            </ul>
        </nav>
    </aside>

    <!-- Main Content -->
    <main class="main-content">
        <!-- Header -->
        <header class="header">
            <div class="welcome-section">
                <h2>Leave Requests</h2>
                <p>Review and approve leave applications</p>
            </div>
            <div class="header-actions">
                <div class="user-info">
                    <span><strong><?php echo htmlspecialchars($username); ?></strong></span>
                    <span style="text-transform: capitalize;"><?php echo htmlspecialchars($role); ?></span>
                </div>
                <a href="?logout=1" class="logout-btn">Logout</a>
            </div>
        </header>

        <?php if (!empty($success_message)): ?>
            <div class="success-message"><?php echo htmlspecialchars($success_message); ?></div>
        <?php endif; ?>

        <?php if (!empty($error_message)): ?>
            <div class="error-message"><?php echo htmlspecialchars($error_message); ?></div>
        <?php endif; ?>

        <!-- Statistics Banner -->
        <div class="stats-banner">
            <?php
            $total_requests = count($leave_requests);
            $pending = count(array_filter($leave_requests, fn($r) => $r['status'] === 'pending'));
            $approved = count(array_filter($leave_requests, fn($r) => $r['status'] === 'approved'));
            $rejected = count(array_filter($leave_requests, fn($r) => $r['status'] === 'rejected'));
            ?>
            <div class="stat-card">
                <div class="stat-value"><?php echo $total_requests; ?></div>
                <div class="stat-label">Total Requests</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #fbbf24;"><?php echo $pending; ?></div>
                <div class="stat-label">Pending</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #4ade80;"><?php echo $approved; ?></div>
                <div class="stat-label">Approved</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #f87171;"><?php echo $rejected; ?></div>
                <div class="stat-label">Rejected</div>
            </div>
        </div>

        <!-- Filter Section -->
        <div class="filter-section">
            <form method="GET" class="filter-grid">
                <div class="filter-group">
                    <label class="filter-label">Employee Name</label>
                    <input
                        type="text"
                        name="name"
                        class="filter-input"
                        placeholder="Search name..."
                        value="<?php echo htmlspecialchars($name_filter); ?>"
                    >
                </div>

                <div class="filter-group">
                    <label class="filter-label">Department</label>
                    <select name="department" class="filter-select" onchange="this.form.submit()">
                        <option value="all" <?php echo $department_filter === 'all' ? 'selected' : ''; ?>>All Departments</option>
                        <?php foreach ($departments as $dept): ?>
                            <option value="<?php echo htmlspecialchars($dept); ?>" <?php echo $department_filter === $dept ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($dept); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="filter-group">
                    <label class="filter-label">Leave Type</label>
                    <select name="leave_type" class="filter-select" onchange="this.form.submit()">
                        <option value="all" <?php echo $leave_type_filter === 'all' ? 'selected' : ''; ?>>All Types</option>
                        <?php foreach ($leave_types as $lt): ?>
                            <option value="<?php echo htmlspecialchars($lt); ?>" <?php echo $leave_type_filter === $lt ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($lt); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="filter-group">
                    <label class="filter-label">Status</label>
                    <select name="status" class="filter-select" onchange="this.form.submit()">
                        <option value="all" <?php echo $status_filter === 'all' ? 'selected' : ''; ?>>All Status</option>
                        <option value="pending" <?php echo $status_filter === 'pending' ? 'selected' : ''; ?>>Pending</option>
                        <option value="approved" <?php echo $status_filter === 'approved' ? 'selected' : ''; ?>>Approved</option>
                        <option value="rejected" <?php echo $status_filter === 'rejected' ? 'selected' : ''; ?>>Rejected</option>
                    </select>
                </div>
            </form>
        </div>

        <!-- Leave Table -->
        <?php if (count($leave_requests) > 0): ?>
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
                    <th>ACTION</th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($leave_requests as $request): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($request['employee_name']); ?></td>
                        <td><?php echo htmlspecialchars($request['department_name'] ?? 'N/A'); ?></td>
                        <td><?php echo htmlspecialchars($request['leave_type']); ?></td>
                        <td><?php echo date('M d, Y', strtotime($request['start_date'])); ?></td>
                        <td><?php echo date('M d, Y', strtotime($request['end_date'])); ?></td>
                        <td><?php echo (int)$request['duration_days']; ?> day<?php echo ((int)$request['duration_days'] > 1) ? 's' : ''; ?></td>
                        <td>
                            <span class="status-badge <?php echo strtolower($request['status']); ?>">
                                <?php echo htmlspecialchars(strtoupper($request['status'])); ?>
                            </span>
                        </td>
                        <td>
                            <?php if ($request['status'] === 'pending'): ?>
                                <form method="POST" class="action-buttons">
                                    <!-- ✅ CSRF token (MITIGATION) -->
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                    <input type="hidden" name="leave_id" value="<?php echo (int)$request['leave_id']; ?>">
                                    <button type="submit" name="action" value="approve" class="approve-btn">Approve</button>
                                    <button type="submit" name="action" value="reject" class="reject-btn">Reject</button>
                                </form>
                            <?php else: ?>
                                <span class="processed-text">Processed</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php else: ?>
            <div class="no-results">
                No leave requests found matching your filters.
            </div>
        <?php endif; ?>
    </main>
</div>
</body>
</html>
