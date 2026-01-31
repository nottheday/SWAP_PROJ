<?php
declare(strict_types=1);

require_once __DIR__ . '/../misc_security/secure-transport.php';
require_once __DIR__ . '/../misc_security/session-hardening.php';
require_once __DIR__ . '/../misc_security/sql-prevention.php';

/* ===============================
   Session init (safe: avoid ini_set warnings / double start)
================================ */
if (session_status() !== PHP_SESSION_ACTIVE) {
    // Only set INI BEFORE session_start
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
   ✅ URL Tampering Popup (STAFF DASHBOARD)
   Requirements:
   1) If ?role=staff/admin/supervisor (ANY role param) => popup + clean reload
   2) If any ID-like param present => popup + clean reload
   3) If ANY unexpected query string keys appear (URL edited) => popup + clean reload
   4) If someone tries to load this page under a different filename/path (URL edited)
      => popup + redirect back to the correct staff-dashboard.php clean URL
================================ */

/* --- helpers --- */
function staffdash_clean_url(array $removeKeys = ['role','id','staff_id','employee_id','user_id']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);

    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function staffdash_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) {
        $_SESSION['flash_unauth'] = 1; // show modal once after reload
    }

    // Clean query string
    $clean = staffdash_clean_url();

    // If we want to force the correct file path, ignore current base
    if ($forcePath !== null) {
        $qPos = strpos($clean, '?');
        $qs   = ($qPos !== false) ? substr($clean, $qPos) : '';
        header("Location: " . $forcePath . $qs);
        exit;
    }

    header("Location: " . $clean);
    exit;
}

/* --- Auth first (so we can reliably compare roles) --- */
if (!isset($_SESSION['auth'], $_SESSION['user'], $_SESSION['role'])) {
    header('Location: /AMC_Website/login.php');
    exit;
}

/* --- Force correct filename if URL is edited to something else but still reaches this script --- */
$expectedFile = 'staff-dashboard.php';
$currentFile  = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '');
if ($currentFile !== '' && strtolower($currentFile) !== strtolower($expectedFile)) {
    // Redirect to the correct page (same folder) + popup
    staffdash_redirect_clean(true, $expectedFile);
}

/* --- Detect ANY unexpected query keys (URL edited) ---
   Allowed keys for this page: logout only
*/
$allowedKeys = ['logout'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        // Any extra param (including role/id/etc) => popup + clean reload
        staffdash_redirect_clean(true);
    }
}

/* --- Explicit tamper triggers (kept for clarity) --- */
if (isset($_GET['role'])) {
    // Requirement: ANY role param => popup (even if it matches)
    staffdash_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['staff_id']) || isset($_GET['employee_id']) || isset($_GET['user_id'])) {
    staffdash_redirect_clean(true);
}

/* ===============================
   RBAC: this dashboard is STAFF only
================================ */
if (strtolower((string)$_SESSION['role']) !== 'staff') {
    http_response_code(403);
    exit("Access Denied: staff only.");
}

$username = (string)$_SESSION['user'];
$role     = (string)$_SESSION['role'];

/* ===== Auto-highlight current sidebar tab ===== */
$currentPage = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
function navActive(string $file, string $currentPage): string {
    return $file === $currentPage ? ' active' : '';
}

/* -------------------------
   Resolve logged-in staff_id
   (Use security library db_one)
-------------------------- */
$staff_id = 0;
$staff_name = $username;
$staff_department_id = null;

$me = db_one("
    SELECT s.id, s.name, s.department_id
    FROM staff s
    JOIN users u ON u.staff_id = s.id
    WHERE u.username = ?
    LIMIT 1
", "s", [$username]);

if ($me) {
    $staff_id = (int)$me['id'];
    $staff_name = (string)($me['name'] ?? $username);
    $staff_department_id = $me['department_id'] ?? null;
} else {
    // fallback (less ideal): if you have users.name and it matches staff.name
    $u = db_one("SELECT name FROM users WHERE username = ? LIMIT 1", "s", [$username]);
    $maybeName = $u['name'] ?? null;

    if (!empty($maybeName)) {
        $s2 = db_one("SELECT id, name, department_id FROM staff WHERE name = ? LIMIT 1", "s", [$maybeName]);
        if ($s2) {
            $staff_id = (int)$s2['id'];
            $staff_name = (string)($s2['name'] ?? $username);
            $staff_department_id = $s2['department_id'] ?? null;
        }
    }
}

/* -------------------------
   Load staff dashboard stats
-------------------------- */
$total_leave = 0; $pending_leave = 0; $approved_leave = 0; $rejected_leave = 0;
$training_due = 0; $expired_certs = 0;

try {
    // Leave stats for this staff only
    $leaveStats = db_one("
        SELECT
          COUNT(*) AS total,
          SUM(status='pending')  AS pending,
          SUM(status='approved') AS approved,
          SUM(status='rejected') AS rejected
        FROM leave_application
        WHERE staff_id = ?
    ", "i", [$staff_id]);

    if ($leaveStats) {
        $total_leave    = (int)($leaveStats['total'] ?? 0);
        $pending_leave  = (int)($leaveStats['pending'] ?? 0);
        $approved_leave = (int)($leaveStats['approved'] ?? 0);
        $rejected_leave = (int)($leaveStats['rejected'] ?? 0);
    }

    // Optional training stats (only if you have a training table)
    $trainingTableExists = db_one("SHOW TABLES LIKE 'training'");
    if ($trainingTableExists) {
        $due = db_one("
            SELECT COUNT(*) AS c
            FROM training
            WHERE staff_id = ?
              AND (
                    status = 'due'
                 OR (due_date IS NOT NULL AND due_date <= DATE_ADD(CURDATE(), INTERVAL 30 DAY))
              )
        ", "i", [$staff_id]);
        $training_due = (int)($due['c'] ?? 0);

        $exp = db_one("
            SELECT COUNT(*) AS c
            FROM training
            WHERE staff_id = ?
              AND (
                    status = 'expired'
                 OR (due_date IS NOT NULL AND due_date < CURDATE())
              )
        ", "i", [$staff_id]);
        $expired_certs = (int)($exp['c'] ?? 0);
    }
} catch (Throwable $e) {
    // Keep dashboard functional even if stats fail
}

/* -------------------------
   Recent leave list (last 8)
-------------------------- */
$recent_leaves = db_all("
    SELECT la.id, lt.name AS leave_type, la.start_date, la.end_date, la.status,
           DATEDIFF(la.end_date, la.start_date) + 1 AS duration_days
    FROM leave_application la
    JOIN leave_type lt ON la.leave_type_id = lt.id
    WHERE la.staff_id = ?
    ORDER BY la.id DESC
    LIMIT 8
", "i", [$staff_id]);

/* -------------------------
   Logout
-------------------------- */
if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: /AMC_Website/login.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AMC HR - Staff Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
        }
        .container { display: flex; min-height: 100vh; }

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

        .main-content {
            flex: 1;
            margin-left: 280px;
            padding: 32px 48px;
        }

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
        .btn-primary:hover { background: rgba(59, 130, 246, 0.28) ;}
        .btn-green {
            background: rgba(34, 197, 94, 0.18);
            border: 1px solid rgba(34, 197, 94, 0.40);
            color: #86efac;
        }
        .btn-green:hover { background: rgba(34, 197, 94, 0.26); }

        /* ===== Modal popup ===== */
        .modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;z-index:9999}
        .modal{width:min(520px,92vw);background:#0b1224;border:1px solid rgba(239,68,68,.5);border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.5);overflow:hidden}
        .modal-head{padding:14px 16px;background:rgba(239,68,68,.12);border-bottom:1px solid rgba(239,68,68,.25);font-weight:900;color:#fecaca}
        .modal-body{padding:16px;color:#e2e8f0;line-height:1.5}
        .modal-actions{padding:14px 16px;display:flex;justify-content:flex-end;border-top:1px solid rgba(71,85,105,.25)}
        .modal-actions button{border-radius:10px;border:1px solid rgba(239,68,68,.55);background:rgba(239,68,68,.2);color:#fecaca;padding:10px 16px;font-weight:900;cursor:pointer}
        .modal-actions button:hover{background:rgba(239,68,68,.28)}

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

<?php
$showUnauth = !empty($_SESSION['flash_unauth']);
if ($showUnauth) unset($_SESSION['flash_unauth']);

$showSqli = !empty($_SESSION['flash_sqli']);
if ($showSqli) unset($_SESSION['flash_sqli']);

$showAny = $showUnauth || $showSqli;
$modalMsg = $showSqli
    ? "⚠ SQL Injection Attempt Detected.<br>Your request was blocked and you were returned to this page safely."
    : "Your request was blocked because the URL looked modified (role/ID/query/path tampering).<br>You have been returned to this page safely.";
?>
<div class="modal-backdrop" id="unauthModal" <?php echo $showAny ? 'style="display:flex"' : ''; ?>>
  <div class="modal" role="dialog" aria-modal="true">
    <div class="modal-head"><?php echo $showSqli ? '⚠️ SQL Injection Attempt Detected' : '⚠️Unauthorised Access Detected'; ?></div>
    <div class="modal-body"><?php echo $modalMsg; ?></div>
    <div class="modal-actions">
      <button type="button" onclick="document.getElementById('unauthModal').style.display='none'">OK</button>
    </div>
  </div>
</div>

<div class="container">
    <aside class="sidebar">
        <div class="logo">
            <h1>AMC HR</h1>
            <span class="role-badge">Staff</span>
        </div>
        <nav>
            <ul class="nav-menu">
                <li class="nav-item">
                    <a href="staff-dashboard.php" class="nav-link<?php echo navActive('staff-dashboard.php', $currentPage); ?>">
                        <span class="nav-icon">🏠</span><span>Dashboard</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="staff-apply_leave.php" class="nav-link<?php echo navActive('staff-apply_leave.php', $currentPage); ?>">
                        <span class="nav-icon">📝</span><span>Apply Leave</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="staff-my_leave.php" class="nav-link<?php echo navActive('staff-my_leave.php', $currentPage); ?>">
                        <span class="nav-icon">📅</span><span>My Leave</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="staff-training.php" class="nav-link<?php echo navActive('staff-training.php', $currentPage); ?>">
                        <span class="nav-icon">🎓</span><span>My Training</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="staff-certification.php" class="nav-link<?php echo navActive('staff-certification.php', $currentPage); ?>">
                        <span class="nav-icon">📄</span><span>My Certifications</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="staff-profile.php" class="nav-link<?php echo navActive('staff-profile.php', $currentPage); ?>">
                        <span class="nav-icon">👤</span><span>My Profile</span>
                    </a>
                </li>
            </ul>
        </nav>
    </aside>

    <main class="main-content">
        <header class="header">
            <div class="welcome-section">
                <h2>Welcome, <?php echo htmlspecialchars($staff_name); ?> 👋</h2>
                <p>Here’s your personal overview (Leave + Training)</p>
            </div>

            <div class="header-actions">
                <div class="user-info">
                    <span><strong><?php echo htmlspecialchars($username); ?></strong></span>
                    <span style="text-transform: capitalize;"><?php echo htmlspecialchars($role); ?></span>
                </div>
                <a href="?logout=1" class="logout-btn">Logout</a>
            </div>
        </header>

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
                                    <td><?php echo htmlspecialchars((string)$lv['leave_type']); ?></td>
                                    <td><?php echo date('M d, Y', strtotime((string)$lv['start_date'])); ?></td>
                                    <td><?php echo date('M d, Y', strtotime((string)$lv['end_date'])); ?></td>
                                    <td><?php echo (int)$lv['duration_days']; ?></td>
                                    <td>
                                        <span class="status-badge <?php echo strtolower((string)$lv['status']); ?>">
                                            <?php echo htmlspecialchars(strtoupper((string)$lv['status'])); ?>
                                        </span>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </section>

            <section class="panel">
                <div class="panel-head">
                    <div class="panel-title">Quick Actions</div>
                </div>
                <div class="panel-body">
                    <div style="display:flex; flex-direction:column; gap:10px;">
                        <a class="btn btn-green" href="staff-apply_leave.php">📝 Apply Leave</a>
                        <a class="btn btn-primary" href="staff-my_leave.php">📅 View My Leave</a>
                        <a class="btn btn-primary" href="staff-training.php">🎓 View My Training</a>
                        <a class="btn btn-primary" href="staff-certification.php">📄 Upload My Certs</a>
                        <a class="btn btn-primary" href="staff-profile.php">👤 Update My Profile</a>
                    </div>
                </div>
            </section>
        </div>
    </main>
</div>
</body>
</html>
