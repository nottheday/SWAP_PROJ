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
   ✅ URL Tampering Popup (ADMIN USERS)
   - Any ?role=... (staff/admin/supervisor etc) => popup + clean reload
   - Any id/user_id/staff_id/employee_id/user param => popup + clean reload
   - Any unexpected query key => popup + clean reload
   - If URL path/filename is edited (e.g. staff-dashboard -> admin-users)
     => popup + redirect to correct file
   Allowed GET keys here: logout
================================ */
$EXPECTED_FILE = 'admin-users.php';

function adminusers_clean_url(array $removeKeys = ['role','id','user_id','staff_id','employee_id','user']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);

    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function adminusers_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) {
        $_SESSION['flash_unauth'] = 1;
    }

    $clean = adminusers_clean_url();

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
    adminusers_redirect_clean(true, $EXPECTED_FILE);
}

/* ===============================
   Detect ANY unexpected query keys (URL edited)
================================ */
$allowedKeys = ['logout'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        adminusers_redirect_clean(true);
    }
}

/* ===============================
   Explicit tamper triggers
================================ */
if (isset($_GET['role'])) {
    // ANY role param triggers popup (even if it matches)
    adminusers_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['user_id']) || isset($_GET['staff_id']) || isset($_GET['employee_id']) || isset($_GET['user'])) {
    adminusers_redirect_clean(true);
}

/* ============================
   ROLE RESTRICTION
============================ */
if ($role !== 'admin') {
    http_response_code(403);
    die("Access Denied");
}

/* ============================
   ADMIN INFO + Stored XSS Protection
============================ */
$admin_data = db_one("
    SELECT s.name
    FROM users u
    JOIN staff s ON u.staff_id = s.id
    WHERE u.username = ?
", "s", [$username]);

$admin_name = htmlspecialchars($admin_data['name'] ?? 'Admin', ENT_QUOTES, 'UTF-8');

/* ============================
   FLASH MESSAGES
============================ */
$success_message = "";
$error_message   = "";

/* ============================
   CRUD OPERATIONS
============================ */
try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $action = (string)($_POST['action'] ?? '');

        // Users fields
        $user_id  = (int)($_POST['user_id'] ?? 0);
        $u_name   = trim((string)($_POST['username'] ?? ''));
        $u_pass   = (string)($_POST['password'] ?? '');
        $u_status = trim((string)($_POST['user_status'] ?? 'active'));
        $role_id  = (int)($_POST['role_id'] ?? 0);

        // Staff fields
        $staff_id = (int)($_POST['staff_id'] ?? 0);
        $s_name   = trim((string)($_POST['name'] ?? ''));
        $s_email  = trim((string)($_POST['email'] ?? ''));
        $s_phone  = trim((string)($_POST['phone_number'] ?? ''));
        $s_job    = trim((string)($_POST['job_title'] ?? ''));
        $s_status = trim((string)($_POST['staff_status'] ?? 'active'));
        $dept_id  = (int)($_POST['department_id'] ?? 0);

        /* ----------------------------
           ADD USER
        ---------------------------- */
        if ($action === 'add') {
            if ($u_name === '' || $u_pass === '' || $role_id <= 0 || $s_name === '' || $s_email === '') {
                throw new RuntimeException("Please fill in required fields (username, password, role, staff name, staff email).");
            }

            $exists = db_one("SELECT id FROM users WHERE username = ? LIMIT 1", "s", [$u_name]);
            if ($exists) throw new RuntimeException("Username already exists.");

            db_exec("
                INSERT INTO staff (name, email, phone_number, job_title, status, department_id)
                VALUES (?, ?, ?, ?, ?, ?)
            ", "sssssi", [$s_name, $s_email, $s_phone, $s_job, $s_status, $dept_id]);

            $newStaff = db_one("SELECT id FROM staff WHERE email = ? ORDER BY id DESC LIMIT 1", "s", [$s_email]);
            if (!$newStaff) throw new RuntimeException("Failed to create staff record.");
            $newStaffId = (int)$newStaff['id'];

            $hashed = password_hash($u_pass, PASSWORD_BCRYPT);

            db_exec("
                INSERT INTO users (username, password, status, role_id, staff_id)
                VALUES (?, ?, ?, ?, ?)
            ", "sssii", [$u_name, $hashed, $u_status, $role_id, $newStaffId]);

            $success_message = "User added successfully.";
        }

        /* ----------------------------
           UPDATE USER
        ---------------------------- */
        if ($action === 'update') {
            if ($user_id <= 0) throw new RuntimeException("Invalid user id.");

            if ($staff_id <= 0) {
                $row = db_one("SELECT staff_id FROM users WHERE id = ? LIMIT 1", "i", [$user_id]);
                if (!$row) throw new RuntimeException("User not found.");
                $staff_id = (int)$row['staff_id'];
            }

            if ($u_name === '' || $role_id <= 0 || $s_name === '' || $s_email === '') {
                throw new RuntimeException("Please fill in required fields.");
            }

            $exists = db_one("SELECT id FROM users WHERE username = ? AND id <> ? LIMIT 1", "si", [$u_name, $user_id]);
            if ($exists) throw new RuntimeException("Username already exists.");

            db_exec("
                UPDATE staff
                SET name = ?, email = ?, phone_number = ?, job_title = ?, status = ?, department_id = ?
                WHERE id = ?
            ", "sssssii", [$s_name, $s_email, $s_phone, $s_job, $s_status, $dept_id, $staff_id]);

            if ($u_pass !== '') {
                $hashed = password_hash($u_pass, PASSWORD_BCRYPT);
                db_exec("
                    UPDATE users
                    SET username = ?, password = ?, status = ?, role_id = ?
                    WHERE id = ?
                ", "sssii", [$u_name, $hashed, $u_status, $role_id, $user_id]);
            } else {
                db_exec("
                    UPDATE users
                    SET username = ?, status = ?, role_id = ?
                    WHERE id = ?
                ", "ssii", [$u_name, $u_status, $role_id, $user_id]);
            }

            $success_message = "User updated successfully.";
        }

        /* ----------------------------
           DELETE USER
        ---------------------------- */
        if ($action === 'delete') {
            if ($user_id <= 0) throw new RuntimeException("Invalid user id.");

            $row = db_one("SELECT staff_id FROM users WHERE id = ? LIMIT 1", "i", [$user_id]);
            if (!$row) throw new RuntimeException("User not found.");
            $delStaffId = (int)$row['staff_id'];

            db_exec("DELETE FROM users WHERE id = ?", "i", [$user_id]);

            $cnt = db_one("SELECT COUNT(*) AS c FROM users WHERE staff_id = ?", "i", [$delStaffId]);
            if (($cnt['c'] ?? 0) == 0) {
                db_exec("DELETE FROM staff WHERE id = ?", "i", [$delStaffId]);
            }

            $success_message = "User deleted successfully.";
        }
    }
} catch (Throwable $e) {
    $error_message = htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
}

/* ============================
   DROPDOWNS
============================ */
$roles      = db_all("SELECT id, name FROM role ORDER BY name");
$department = db_all("SELECT id, name FROM department ORDER BY name");

/* ============================
   USERS LIST
============================ */
$users = db_all("
    SELECT 
        u.id AS user_id,
        u.staff_id,
        u.username,
        u.status,
        u.role_id,
        r.name AS role,
        s.name AS staff_name,
        s.email,
        s.phone_number,
        s.job_title,
        s.status AS staff_status,
        s.department_id,
        MAX(la.time) AS last_login
    FROM users u
    JOIN role r ON u.role_id = r.id
    JOIN staff s ON u.staff_id = s.id
    LEFT JOIN login_audit la 
        ON la.username = u.username
        AND la.success = 1
    GROUP BY 
        u.id, u.staff_id, u.username, u.status, u.role_id, r.name,
        s.name, s.email, s.phone_number, s.job_title, s.status, s.department_id
    ORDER BY u.username
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
<title>AMC HR - Admin Users</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Inter',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;}
.container{display:flex;min-height:100vh;}
.sidebar{width:280px;background:rgba(15,23,42,0.95);border-right:1px solid rgba(71,85,105,0.3);padding-top:32px;position:fixed;top:0;bottom:0;left:0;overflow-y:auto;}
.sidebar::-webkit-scrollbar{width:6px;}
.sidebar::-webkit-scrollbar-thumb{background:rgba(96,165,250,0.3);border-radius:3px;}
.logo{padding:0 32px;margin-bottom:48px;}
.logo h1{font-size:32px;font-weight:700;background:linear-gradient(135deg,#60a5fa,#3b82f6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.role-badge{display:inline-block;margin-top:8px;padding:4px 12px;background:rgba(168,85,247,0.2);border:1px solid rgba(168,85,247,0.3);border-radius:6px;font-size:12px;font-weight:600;color:#c084fc;text-transform:uppercase;}
.nav-menu{list-style:none;}
.nav-section-title{padding:8px 32px;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:24px;margin-bottom:8px;}
.nav-item{margin-bottom:4px;}
.nav-link{display:flex;align-items:center;gap:12px;padding:12px 32px;color:#94a3b8;text-decoration:none;font-size:14px;font-weight:500;transition:all .2s ease;border-left:3px solid transparent;}
.nav-link:hover{background:rgba(59,130,246,0.1);color:#60a5fa;border-left-color:#3b82f6;}
.nav-link.active{background:rgba(59,130,246,0.15);color:#60a5fa;border-left-color:#3b82f6;}
.nav-icon{font-size:18px;width:20px;text-align:center;}
.main-content{flex:1;margin-left:280px;padding:32px 48px;}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;padding-bottom:24px;border-bottom:1px solid rgba(71,85,105,.3);}
.welcome-section h1{font-size:32px;font-weight:700;margin-bottom:8px;background:linear-gradient(135deg,#60a5fa,#3b82f6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.welcome-section p{color:#94a3b8;font-size:14px;}
.user-info{text-align:right;}
.user-info .name{font-weight:600;font-size:16px;color:#e2e8f0;margin-bottom:4px;}
.user-info .role{font-size:13px;color:purple;margin-bottom:12px;}
.logout-btn{display:inline-block;padding:8px 20px;background:rgba(239,68,68,.2);border:1px solid rgba(239,68,68,.4);border-radius:8px;color:#fca5a5;text-decoration:none;font-size:13px;font-weight:600;}
.logout-btn:hover{background:rgba(239,68,68,.3);border-color:rgba(239,68,68,.6);}
.panel{background:rgba(15,23,42,.6);border:1px solid rgba(71,85,105,.3);border-radius:12px;overflow:hidden;}
.panel-header{display:flex;align-items:center;justify-content:space-between;padding:20px 24px;background:rgba(30,41,59,.8);border-bottom:1px solid rgba(71,85,105,0.3);}
.panel-title{font-size:16px;font-weight:700;color:#60a5fa;text-transform:uppercase;}
.panel-body{padding:24px;}
table{width:100%;border-collapse:collapse;}
th,td{padding:12px;text-align:left;border-bottom:1px solid rgba(71,85,105,.2);}
th{font-size:12px;font-weight:700;color:#93c5fd;text-transform:uppercase;letter-spacing:.5px;}
td{font-size:14px;color:#e2e8f0;}
tr:hover{background:rgba(59,130,246,0.05);}
.status-badge{padding:4px 10px;border-radius:6px;font-size:11px;font-weight:700;text-transform:uppercase;}
.status-success{background:rgba(34,197,94,.2);color:#4ade80;border:1px solid rgba(34,197,94,.3);}
.status-failed{background:rgba(239,68,68,.2);color:#f87171;border:1px solid rgba(239,68,68,.3);}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:8px 14px;border-radius:10px;border:1px solid transparent;text-decoration:none;font-size:13px;font-weight:700;cursor:pointer;}
.btn-primary{background:rgba(59,130,246,.20);border-color:rgba(59,130,246,.45);color:#93c5fd;}
.btn-primary:hover{background:rgba(59,130,246,.28);border-color:rgba(59,130,246,.65);}
.btn-secondary{background:rgba(148,163,184,.12);border-color:rgba(148,163,184,.28);color:#e2e8f0;}
.btn-secondary:hover{background:rgba(148,163,184,.18);border-color:rgba(148,163,184,.40);}
.btn-danger{background:rgba(239,68,68,.20);border-color:rgba(239,68,68,.45);color:#fecaca;}
.btn-danger:hover{background:rgba(239,68,68,.28);border-color:rgba(239,68,68,.65);}
.btn-xs{padding:6px 10px;border-radius:8px;font-size:12px;}
.btn-row{display:flex;gap:10px;align-items:center;flex-wrap:nowrap;}
.alert{margin:0 0 16px 0;padding:12px 14px;border-radius:10px;border:1px solid rgba(71,85,105,.3);background:rgba(15,23,42,.55);}
.alert-success{border-color:rgba(34,197,94,.35);background:rgba(34,197,94,.12);color:#bbf7d0;}
.alert-error{border-color:rgba(239,68,68,.35);background:rgba(239,68,68,.12);color:#fecaca;}
.modal-backdrop{position:fixed;inset:0;background:rgba(2,6,23,.65);display:none;align-items:center;justify-content:center;padding:18px;z-index:9999;}
.modal{width:min(860px, 100%);background:rgba(15,23,42,.98);border:1px solid rgba(71,85,105,.35);border-radius:14px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.45);}
.modal-header{display:flex;align-items:center;justify-content:space-between;padding:16px 18px;background:rgba(30,41,59,.85);border-bottom:1px solid rgba(71,85,105,.3);}
.modal-title{font-weight:800;color:#93c5fd;text-transform:uppercase;font-size:13px;letter-spacing:.8px;}
.modal-body{padding:18px;}
.modal-footer{display:flex;gap:10px;justify-content:flex-end;padding:14px 18px;border-top:1px solid rgba(71,85,105,.3);background:rgba(15,23,42,.85);}
.close-x{background:transparent;border:1px solid rgba(148,163,184,.25);color:#e2e8f0;border-radius:10px;padding:6px 10px;cursor:pointer;}
.close-x:hover{border-color:rgba(148,163,184,.45);}
.form-grid{display:grid;grid-template-columns:repeat(2, minmax(0,1fr));gap:14px;}
.form-group label{display:block;font-size:12px;color:#94a3b8;font-weight:700;margin-bottom:6px;text-transform:uppercase;letter-spacing:.4px;}
.form-group input,.form-group select{width:100%;padding:10px 12px;border-radius:10px;border:1px solid rgba(71,85,105,.35);background:rgba(2,6,23,.35);color:#e2e8f0;outline:none;}
.form-group input:focus,.form-group select:focus{border-color:rgba(59,130,246,.65);}
.form-note{font-size:12px;color:#94a3b8;margin-top:6px;}
@media(max-width:1024px){.sidebar{width:240px;}.main-content{margin-left:240px;padding:24px 32px;}}
@media(max-width:768px){.sidebar{width:100%;position:relative;height:auto;border-right:none;border-bottom:1px solid rgba(71,85,105,.3);}.main-content{margin-left:0;padding:20px;}.container{flex-direction:column;}.header{flex-direction:column;align-items:flex-start;gap:14px;}.user-info{text-align:left;}.form-grid{grid-template-columns:1fr;}}

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
                <li class="nav-item"><a href="admin-users.php" class="nav-link active"><span class="nav-icon">👥</span>Manage Users</a></li>
                <li class="nav-item"><a href="admin-departments.php" class="nav-link"><span class="nav-icon">🏢</span>Departments</a></li>
                <li class="nav-section-title">Operations</li>
                <li class="nav-item"><a href="admin-leave-management.php" class="nav-link"><span class="nav-icon">📅</span>Leave Management</a></li>
                <li class="nav-item"><a href="admin-training.php" class="nav-link"><span class="nav-icon">🎓</span>Training</a></li>
                <li class="nav-item"><a href="admin-certifications.php" class="nav-link"><span class="nav-icon">📜</span>Certifications</a></li>
                <li class="nav-section-title">System</li>
                <li class="nav-item"><a href="admin-reports.php" class="nav-link"><span class="nav-icon">📈</span>Reports</a></li>
                <li class="nav-item"><a href="admin-security.php" class="nav-link"><span class="nav-icon">🔒</span>Security Logs</a></li>
            </ul>
        </nav>
    </aside>

<main class="main-content">
    <!-- Header -->
    <header class="header">
        <div class="welcome-section">
            <h1>User Management</h1>
            <p>Manage system users</p>
        </div>
        <div class="user-info">
            <div class="name"><?= $admin_name ?></div>
            <div class="role"><?= htmlspecialchars((string)($_SESSION['role'] ?? 'admin'), ENT_QUOTES, 'UTF-8') ?></div>
            <a href="?logout=1" class="logout-btn">Logout</a>
        </div>
    </header>

    <!-- Flash messages -->
    <?php if (!empty($success_message)): ?>
        <div class="alert alert-success"><?= htmlspecialchars($success_message, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif; ?>
    <?php if (!empty($error_message)): ?>
        <div class="alert alert-error"><?= $error_message ?></div>
    <?php endif; ?>

    <!-- Users Panel -->
    <div class="panel">
        <div class="panel-header">
            <div class="panel-title">All Users</div>
            <button class="btn btn-primary" type="button" id="btnOpenAdd">➕ Add User</button>
        </div>
        <div class="panel-body">
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Last Login</th>
                        <th style="width:170px;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($users as $u): ?>
                    <tr
                        data-user_id="<?= (int)$u['user_id'] ?>"
                        data-staff_id="<?= (int)$u['staff_id'] ?>"
                        data-username="<?= htmlspecialchars((string)$u['username'], ENT_QUOTES, 'UTF-8') ?>"
                        data-role_id="<?= (int)$u['role_id'] ?>"
                        data-status="<?= htmlspecialchars((string)$u['status'], ENT_QUOTES, 'UTF-8') ?>"
                        data-staff_name="<?= htmlspecialchars((string)$u['staff_name'], ENT_QUOTES, 'UTF-8') ?>"
                        data-email="<?= htmlspecialchars((string)$u['email'], ENT_QUOTES, 'UTF-8') ?>"
                        data-phone_number="<?= htmlspecialchars((string)$u['phone_number'], ENT_QUOTES, 'UTF-8') ?>"
                        data-job_title="<?= htmlspecialchars((string)$u['job_title'], ENT_QUOTES, 'UTF-8') ?>"
                        data-staff_status="<?= htmlspecialchars((string)$u['staff_status'], ENT_QUOTES, 'UTF-8') ?>"
                        data-department_id="<?= (int)$u['department_id'] ?>"
                    >
                        <td><?= htmlspecialchars((string)$u['username'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td><?= htmlspecialchars((string)$u['email'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td><?= htmlspecialchars((string)$u['role'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td>
                            <span class="status-badge <?= ((string)$u['status']==='active')?'status-success':'status-failed' ?>">
                                <?= htmlspecialchars((string)$u['status'], ENT_QUOTES, 'UTF-8') ?>
                            </span>
                        </td>
                        <td><?= $u['last_login'] ? date('M d, Y H:i', strtotime((string)$u['last_login'])) : 'Never' ?></td>
                        <td>
                            <div class="btn-row">
                              <button class="btn btn-secondary btn-xs btnEdit" type="button">✏️ Update</button>
                              <button class="btn btn-danger btn-xs btnDelete" type="button">🗑️ Delete</button>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</main>
</div>

<!-- Modal Backdrop -->
<div class="modal-backdrop" id="modalBackdrop">
    <!-- Add / Update Modal -->
    <div class="modal" id="modalForm">
        <div class="modal-header">
            <span class="modal-title" id="modalTitle">Add User</span>
            <button type="button" class="close-x" id="modalClose">✖</button>
        </div>
        <form method="POST" class="modal-body" id="userForm">
            <input type="hidden" name="action" id="formAction" value="add">
            <input type="hidden" name="user_id" id="formUserId" value="">
            <input type="hidden" name="staff_id" id="formStaffId" value="">

            <div class="form-grid">
                <div class="form-group">
                    <label for="username">Username *</label>
                    <input type="text" name="username" id="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password <span class="form-note">(Leave empty on update to keep current)</span></label>
                    <input type="password" name="password" id="password">
                </div>
                <div class="form-group">
                    <label for="role_id">Role *</label>
                    <select name="role_id" id="role_id" required>
                        <?php foreach($roles as $r): ?>
                            <option value="<?= (int)$r['id'] ?>"><?= htmlspecialchars((string)$r['name'], ENT_QUOTES, 'UTF-8') ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group">
                    <label for="user_status">User Status</label>
                    <select name="user_status" id="user_status">
                        <option value="active">Active</option>
                        <option value="inactive">Inactive</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="name">Staff Name *</label>
                    <input type="text" name="name" id="name" required>
                </div>
                <div class="form-group">
                    <label for="email">Email *</label>
                    <input type="email" name="email" id="email" required>
                </div>
                <div class="form-group">
                    <label for="phone_number">Phone Number</label>
                    <input type="text" name="phone_number" id="phone_number">
                </div>
                <div class="form-group">
                    <label for="job_title">Job Title</label>
                    <input type="text" name="job_title" id="job_title">
                </div>

                <div class="form-group">
                    <label for="staff_status">Staff Status</label>
                    <select name="staff_status" id="staff_status">
                        <option value="active">Active</option>
                        <option value="inactive">Inactive</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="department_id">Department</label>
                    <select name="department_id" id="department_id">
                        <?php foreach($department as $d): ?>
                            <option value="<?= (int)$d['id'] ?>"><?= htmlspecialchars((string)$d['name'], ENT_QUOTES, 'UTF-8') ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
            </div>

            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" id="btnCancel">Cancel</button>
                <button type="submit" class="btn btn-primary">Save</button>
            </div>
        </form>
    </div>
</div>

<script>
// DOM XSS safe: we only read dataset values (already escaped), and set input.value (not innerHTML)
const modalBackdrop = document.getElementById('modalBackdrop');
const modalTitle = document.getElementById('modalTitle');
const formAction = document.getElementById('formAction');
const formUserId = document.getElementById('formUserId');
const formStaffId = document.getElementById('formStaffId');
const userForm = document.getElementById('userForm');
const btnOpenAdd = document.getElementById('btnOpenAdd');
const modalClose = document.getElementById('modalClose');
const btnCancel = document.getElementById('btnCancel');

function openModal() { modalBackdrop.style.display = 'flex'; }
function closeModal() { modalBackdrop.style.display = 'none'; userForm.reset(); }

btnOpenAdd.addEventListener('click', () => {
    modalTitle.textContent = 'Add User';
    formAction.value = 'add';
    formUserId.value = '';
    formStaffId.value = '';
    openModal();
});

modalClose.addEventListener('click', (e) => { e.preventDefault(); closeModal(); });
btnCancel.addEventListener('click', (e) => { e.preventDefault(); closeModal(); });

document.querySelectorAll('.btnEdit').forEach(btn => {
    btn.addEventListener('click', e => {
        const tr = e.target.closest('tr');
        modalTitle.textContent = 'Update User';
        formAction.value = 'update';
        formUserId.value = tr.dataset.user_id;
        formStaffId.value = tr.dataset.staff_id;

        userForm.username.value = tr.dataset.username || '';
        userForm.password.value = '';
        userForm.role_id.value = tr.dataset.role_id || '';
        userForm.user_status.value = tr.dataset.status || 'active';

        userForm.name.value = tr.dataset.staff_name || '';
        userForm.email.value = tr.dataset.email || '';
        userForm.phone_number.value = tr.dataset.phone_number || '';
        userForm.job_title.value = tr.dataset.job_title || '';
        userForm.staff_status.value = tr.dataset.staff_status || 'active';
        userForm.department_id.value = tr.dataset.department_id || '';

        openModal();
    });
});

document.querySelectorAll('.btnDelete').forEach(btn => {
    btn.addEventListener('click', e => {
        const tr = e.target.closest('tr');
        if (confirm('Are you sure you want to delete this user?')) {
            const f = document.createElement('form');
            f.method = 'POST';
            f.style.display = 'none';

            const a = document.createElement('input');
            a.name = 'action';
            a.value = 'delete';
            f.appendChild(a);

            const u = document.createElement('input');
            u.name = 'user_id';
            u.value = tr.dataset.user_id;
            f.appendChild(u);

            document.body.appendChild(f);
            f.submit();
        }
    });
});
</script>

<?php
if (function_exists('render_security_popups')) {
    render_security_popups();
}
?>
</body>
</html>
