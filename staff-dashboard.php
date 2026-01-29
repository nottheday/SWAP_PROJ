<?php
session_start();

/*
  ASSUMPTION:
  - After login, you set:
    $_SESSION['user'] = username or employee_id
    $_SESSION['role'] = 'staff' or 'supervisor' (or 'admin')
*/

// Not logged in -> kick out
if (!isset($_SESSION['user']) || !isset($_SESSION['role'])) {
    header("Location: amc_hr_gateway.php");
    exit;
}

$currentRole = strtolower($_SESSION['role']);      // trusted
$urlRole     = isset($_GET['role']) ? strtolower(trim($_GET['role'])) : null;

// If role in URL is present and doesn't match session role -> tampering
if ($urlRole !== null && $urlRole !== $currentRole) {
    // Build same page URL WITHOUT the "role" parameter
    $query = $_GET;
    unset($query['role']);

    $base = strtok($_SERVER["REQUEST_URI"], '?');
    $cleanUrl = $base . (count($query) ? ('?' . http_build_query($query)) : '');

    // Reload same page + popup
    echo "<script>
        alert('Unauthorised Access Detected');
        window.location.replace(" . json_encode($cleanUrl) . ");
    </script>";
    exit;
}

$username = $_SESSION['user'];
$role = $_SESSION['role'];

/* -------------------------
   DB connection (swap DB)
-------------------------- */
$db_host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "swap";

$mysqli = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($mysqli->connect_error) {
    die("Database connection failed: " . $mysqli->connect_error);
}

/* -------------------------
   Resolve logged-in staff_id
   Assumption:
   - users.username maps to staff.username
   If your staff table uses a different column, tell me and I’ll adjust.
-------------------------- */
$staff_id = null;

// Option A: staff.username exists
$staffStmt = $mysqli->prepare("
    SELECT s.id, s.name, s.department_id
    FROM staff s
    JOIN users u ON u.staff_id = s.id
    WHERE u.username = ?
    LIMIT 1
");
if ($staffStmt) {
    $staffStmt->bind_param("s", $username);
    $staffStmt->execute();
    $staffStmt->bind_result($staff_id, $staff_name, $staff_department_id);
    $staffStmt->fetch();
    $staffStmt->close();
}

// Option B fallback: if no row found, try users -> staff via name (less ideal)
if (empty($staff_id)) {
    $userNameStmt = $mysqli->prepare("SELECT name FROM users WHERE username = ? LIMIT 1");
    if ($userNameStmt) {
        $userNameStmt->bind_param("s", $username);
        $userNameStmt->execute();
        $userNameStmt->bind_result($maybeName);
        $userNameStmt->fetch();
        $userNameStmt->close();

        if (!empty($maybeName)) {
            $staffStmt2 = $mysqli->prepare("SELECT id, name, department_id FROM staff WHERE name = ? LIMIT 1");
            if ($staffStmt2) {
                $staffStmt2->bind_param("s", $maybeName);
                $staffStmt2->execute();
                $staffStmt2->bind_result($staff_id, $staff_name, $staff_department_id);
                $staffStmt2->fetch();
                $staffStmt2->close();
            }
        }
    }
}

if (empty($staff_id)) {
    // Still allow dashboard UI, but stats will be 0
    $staff_id = 0;
    $staff_name = $username;
    $staff_department_id = null;
}

/* -------------------------
   Load staff dashboard stats
   Tables assumed (based on your code):
   - leave_application (id, staff_id, status, start_date, end_date)
   - training (staff_id, status, due_date)  <-- If you don't have this, it will show 0.
-------------------------- */
$total_leave = 0; $pending_leave = 0; $approved_leave = 0; $rejected_leave = 0;
$training_due = 0; $expired_certs = 0;

try {
    // Leave stats for this staff only
    $leaveCountStmt = $mysqli->prepare("
        SELECT
          SUM(1) AS total,
          SUM(status='pending') AS pending,
          SUM(status='approved') AS approved,
          SUM(status='rejected') AS rejected
        FROM leave_application
        WHERE staff_id = ?
    ");
    if ($leaveCountStmt) {
        $leaveCountStmt->bind_param("i", $staff_id);
        $leaveCountStmt->execute();
        $res = $leaveCountStmt->get_result()->fetch_assoc();
        $total_leave = (int)($res['total'] ?? 0);
        $pending_leave = (int)($res['pending'] ?? 0);
        $approved_leave = (int)($res['approved'] ?? 0);
        $rejected_leave = (int)($res['rejected'] ?? 0);
        $leaveCountStmt->close();
    }

    // Optional training stats (only if you have a training table)
    // If your table names are different (e.g. staff_training, training_records), tell me.
    $trainingTableExists = $mysqli->query("SHOW TABLES LIKE 'training'");
    if ($trainingTableExists && $trainingTableExists->num_rows > 0) {
        // Training due: due_date within next 30 days OR status='due'
        $trainDueStmt = $mysqli->prepare("
            SELECT COUNT(*) 
            FROM training
            WHERE staff_id = ?
              AND (
                    status = 'due'
                 OR (due_date IS NOT NULL AND due_date <= DATE_ADD(CURDATE(), INTERVAL 30 DAY))
              )
        ");
        if ($trainDueStmt) {
            $trainDueStmt->bind_param("i", $staff_id);
            $trainDueStmt->execute();
            $trainDueStmt->bind_result($training_due);
            $trainDueStmt->fetch();
            $trainDueStmt->close();
        }

        // Expired certs: status='expired' OR due_date < today
        $expiredStmt = $mysqli->prepare("
            SELECT COUNT(*)
            FROM training
            WHERE staff_id = ?
              AND (
                    status = 'expired'
                 OR (due_date IS NOT NULL AND due_date < CURDATE())
              )
        ");
        if ($expiredStmt) {
            $expiredStmt->bind_param("i", $staff_id);
            $expiredStmt->execute();
            $expiredStmt->bind_result($expired_certs);
            $expiredStmt->fetch();
            $expiredStmt->close();
        }
    }
} catch (Throwable $e) {
    // Keep dashboard functional even if stats fail
}

/* -------------------------
   Recent leave list (last 8)
-------------------------- */
$recent_leaves = [];
$recentStmt = $mysqli->prepare("
    SELECT la.id, lt.name AS leave_type, la.start_date, la.end_date, la.status,
           DATEDIFF(la.end_date, la.start_date) + 1 AS duration_days
    FROM leave_application la
    JOIN leave_type lt ON la.leave_type_id = lt.id
    WHERE la.staff_id = ?
    ORDER BY la.id DESC
    LIMIT 8
");
if ($recentStmt) {
    $recentStmt->bind_param("i", $staff_id);
    $recentStmt->execute();
    $r = $recentStmt->get_result();
    while ($row = $r->fetch_assoc()) $recent_leaves[] = $row;
    $recentStmt->close();
}

/* -------------------------
   Logout
-------------------------- */
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
    <title>AMC HR - Staff Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        /* ===== Same look & feel as Bob's supervisor pages ===== */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
        }
        .container { display: flex; min-height: 100vh; }

        /* Sidebar */
        .sidebar {
            width: 280px;
            background: rgba(15, 23, 42, 0.95);
            border-right: 1px solid rgba(71, 85, 105, 0.3);
            padding: 32px 0;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
        }
        .logo { padding: 0 32px; margin-bottom: 48px; }
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
            background: rgba(34, 197, 94, 0.16);
            border: 1px solid rgba(34, 197, 94, 0.28);
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            color: #4ade80;
            text-transform: uppercase;
        }

        .nav-menu { list-style: none; }
        .nav-item { margin-bottom: 8px; }
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
        .nav-icon { font-size: 20px; }

        /* Main */
        .main-content {
            flex: 1;
            margin-left: 280px;
            padding: 32px 48px;
        }

        /* Header */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 28px;
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
        .user-info strong { color: #60a5fa; font-weight: 600; }

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

        /* Stats banner */
        .stats-banner {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
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

        /* Cards */
        .grid-2 {
            display: grid;
            grid-template-columns: 1.4fr 1fr;
            gap: 16px;
            margin-top: 16px;
        }
        .panel {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.3);
            border-radius: 12px;
            overflow: hidden;
        }
        .panel-head {
            padding: 16px 18px;
            background: rgba(30, 41, 59, 0.8);
            border-bottom: 1px solid rgba(71, 85, 105, 0.35);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .panel-title {
            font-size: 14px;
            font-weight: 700;
            color: #60a5fa;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .panel-body { padding: 16px 18px; }

        /* Table */
        table { width: 100%; border-collapse: collapse; }
        th, td {
            padding: 14px 10px;
            border-bottom: 1px solid rgba(71, 85, 105, 0.22);
            font-size: 14px;
        }
        th {
            text-align: left;
            color: #93c5fd;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        tr:hover { background: rgba(59, 130, 246, 0.05); }
        .muted { color: #94a3b8; font-size: 13px; }

        .status-badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .status-badge.pending {
            background: rgba(234, 179, 8, 0.15);
            color: #fbbf24;
            border: 1px solid rgba(234, 179, 8, 0.3);
        }
        .status-badge.approved {
            background: rgba(34, 197, 94, 0.15);
            color: #4ade80;
            border: 1px solid rgba(34, 197, 94, 0.3);
        }
        .status-badge.rejected {
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .btn {
            display: inline-block;
            padding: 10px 14px;
            border-radius: 10px;
            text-decoration: none;
            font-weight: 700;
            font-size: 14px;
            transition: all 0.2s ease;
        }
        .btn-primary {
            background: rgba(59, 130, 246, 0.2);
            border: 1px solid rgba(59, 130, 246, 0.45);
            color: #93c5fd;
        }
        .btn-primary:hover { background: rgba(59, 130, 246, 0.28); }
        .btn-green {
            background: rgba(34, 197, 94, 0.18);
            border: 1px solid rgba(34, 197, 94, 0.40);
            color: #86efac;
        }
        .btn-green:hover { background: rgba(34, 197, 94, 0.26); }

        @media (max-width: 1024px) {
            .sidebar { width: 240px; }
            .main-content { margin-left: 240px; padding: 24px 32px; }
            .grid-2 { grid-template-columns: 1fr; }
        }
        @media (max-width: 768px) {
            .sidebar { width: 100%; position: relative; height: auto; border-right: none; border-bottom: 1px solid rgba(71,85,105,0.3); }
            .main-content { margin-left: 0; padding: 20px; }
            .container { flex-direction: column; }
            .header { flex-direction: column; align-items: flex-start; }
            .header-actions { width: 100%; justify-content: space-between; }
        }
    </style>
</head>
<body>
<div class="container">
    <!-- Sidebar -->
    <aside class="sidebar">
        <div class="logo">
            <h1>AMC HR</h1>
            <span class="role-badge">Staff</span>
        </div>
        <nav>
            <ul class="nav-menu">
                <li class="nav-item">
                    <a href="staff-dashboard.php" class="nav-link active">
                        <span class="nav-icon">🏠</span>
                        <span>Dashboard</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="staff-apply_leave.php" class="nav-link">
                        <span class="nav-icon">📝</span>
                        <span>Apply Leave</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="staff-my_leave.php" class="nav-link">
                        <span class="nav-icon">📅</span>
                        <span>My Leave</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="staff-training.php" class="nav-link">
                        <span class="nav-icon">🎓</span>
                        <span>My Training</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="staff-profile.php" class="nav-link">
                        <span class="nav-icon">👤</span>
                        <span>My Profile</span>
                    </a>
                </li>
            </ul>
        </nav>
    </aside>

    <!-- Main Content -->
    <main class="main-content">
        <header class="header">
            <div class="welcome-section">
                <h2>Welcome, <?php echo htmlspecialchars($staff_name); ?> 👋</h2>
                <p>Here’s your personal overview (leave + training)</p>
            </div>

            <div class="header-actions">
                <div class="user-info">
                    <span><strong><?php echo htmlspecialchars($username); ?></strong></span>
                    <span style="text-transform: capitalize;"><?php echo htmlspecialchars($role); ?></span>
                </div>
                <a href="?logout=1" class="logout-btn">Logout</a>
            </div>
        </header>

        <!-- Stats Banner -->
        <div class="stats-banner">
            <div class="stat-card">
                <div class="stat-value"><?php echo (int)$total_leave; ?></div>
                <div class="stat-label">Total Leave Requests</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#fbbf24;"><?php echo (int)$pending_leave; ?></div>
                <div class="stat-label">Pending Leave</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#4ade80;"><?php echo (int)$approved_leave; ?></div>
                <div class="stat-label">Approved Leave</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#f87171;"><?php echo (int)$rejected_leave; ?></div>
                <div class="stat-label">Rejected Leave</div>
            </div>
        </div>

        <!-- Secondary stats -->
        <div class="stats-banner">
            <div class="stat-card">
                <div class="stat-value" style="color:#93c5fd;"><?php echo (int)$training_due; ?></div>
                <div class="stat-label">Training Due (≤30 days)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#f87171;"><?php echo (int)$expired_certs; ?></div>
                <div class="stat-label">Expired / Overdue</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#e2e8f0;"><?php echo (int)$staff_id; ?></div>
                <div class="stat-label">Staff ID</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#e2e8f0;"><?php echo htmlspecialchars((string)($staff_department_id ?? 'N/A')); ?></div>
                <div class="stat-label">Department ID</div>
            </div>
        </div>

        <div class="grid-2">
            <!-- Recent Leave -->
            <section class="panel">
                <div class="panel-head">
                    <div class="panel-title">Recent Leave Requests</div>
                    <a class="btn btn-primary" href="staff-my_leave.php">View All</a>
                </div>
                <div class="panel-body">
                    <?php if (empty($recent_leaves)): ?>
                        <p class="muted">No leave requests found yet.</p>
                        <br>
                        <a class="btn btn-green" href="staff-apply_leave.php">Apply Leave</a>
                    <?php else: ?>
                        <table>
                            <thead>
                                <tr>
                                    <th>Type</th>
                                    <th>Start</th>
                                    <th>End</th>
                                    <th>Days</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                            <?php foreach ($recent_leaves as $lv): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($lv['leave_type']); ?></td>
                                    <td><?php echo date('M d, Y', strtotime($lv['start_date'])); ?></td>
                                    <td><?php echo date('M d, Y', strtotime($lv['end_date'])); ?></td>
                                    <td><?php echo (int)$lv['duration_days']; ?></td>
                                    <td>
                                        <span class="status-badge <?php echo strtolower($lv['status']); ?>">
                                            <?php echo htmlspecialchars(strtoupper($lv['status'])); ?>
                                        </span>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </section>

            <!-- Quick Actions -->
            <section class="panel">
                <div class="panel-head">
                    <div class="panel-title">Quick Actions</div>
                </div>
                <div class="panel-body">
                    <p class="muted" style="margin-bottom: 14px;">
                        Staff can only manage their own leave and training records.
                    </p>
                    <div style="display:flex; flex-direction:column; gap:10px;">
                        <a class="btn btn-green" href="staff-apply_leave.php">📝 Apply Leave</a>
                        <a class="btn btn-primary" href="staff-my_leave.php">📅 View My Leave</a>
                        <a class="btn btn-primary" href="staff-training.php">🎓 View My Training</a>
                        <a class="btn btn-primary" href="staff-profile.php">👤 Update My Profile</a>
                    </div>
                </div>
            </section>
        </div>
    </main>
</div>
</body>
</html>
