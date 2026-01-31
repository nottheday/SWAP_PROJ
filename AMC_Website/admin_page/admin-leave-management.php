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
   ✅ URL Tampering Popup (ADMIN LEAVE MANAGEMENT)
   - Any ?role=... (staff/admin/supervisor etc) => popup + clean reload
   - Any id/user_id/staff_id/employee_id/user param => popup + clean reload
   - Any unexpected query key => popup + clean reload
   - If URL path/filename is edited (e.g. staff-dashboard -> admin-leave-management)
     => popup + redirect to correct file
   Allowed GET keys here: logout
================================ */
$EXPECTED_FILE = 'admin-leave-management.php';

function adminleave_clean_url(array $removeKeys = ['role','id','user_id','staff_id','employee_id','user']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);
    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function adminleave_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) $_SESSION['flash_unauth'] = 1;

    $clean = adminleave_clean_url();

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
    adminleave_redirect_clean(true, $EXPECTED_FILE);
}

/* ===============================
   Detect ANY unexpected query keys (URL edited)
================================ */
$allowedKeys = ['logout'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        adminleave_redirect_clean(true);
    }
}

/* ===============================
   Explicit tamper triggers
================================ */
if (isset($_GET['role'])) {
    // ANY role param triggers popup (even if it matches)
    adminleave_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['user_id']) || isset($_GET['staff_id']) || isset($_GET['employee_id']) || isset($_GET['user'])) {
    adminleave_redirect_clean(true);
}

/* ============================
   ROLE RESTRICTION
============================ */
if ($role !== 'admin') {
    http_response_code(403);
    die("Access Denied: Admin only");
}

/* ============================
   Logout handling (allowed GET)
============================ */
if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: /AMC_Website/login.php');
    exit;
}

/* =========================
   DB CONFIG
========================= */
$db_host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "swap";

$mysqli = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($mysqli->connect_error) {
    die("DB connection failed: " . $mysqli->connect_error);
}

/* =========================
   User id (approved_by)
========================= */
$user_id = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : 0;

/* =========================
   CSRF token
========================= */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* =========================
   Handle approve/reject
========================= */
$success_message = '';
$error_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['leave_id'], $_POST['action'], $_POST['csrf_token'])) {
    $csrf = (string)$_POST['csrf_token'];
    if (!hash_equals((string)$_SESSION['csrf_token'], $csrf)) {
        die("CSRF validation failed");
    }

    $leave_id = (int)$_POST['leave_id'];
    $new_status = ((string)$_POST['action'] === 'approve') ? 'approved' : 'rejected';

    $stmt = $mysqli->prepare("UPDATE leave_application SET status=?, approved_by=? WHERE id=?");
    if ($stmt) {
        $stmt->bind_param("sii", $new_status, $user_id, $leave_id);
        if ($stmt->execute()) {
            $success_message = "Leave #{$leave_id} has been {$new_status}.";
        } else {
            $error_message = "Failed to update leave.";
        }
        $stmt->close();
    } else {
        $error_message = "Failed to prepare query.";
    }
}

/* =========================
   Fetch pending leaves
========================= */
$pending_leaves = [];
$stmt = $mysqli->prepare("
    SELECT la.id AS leave_id, s.name AS employee_name, d.name AS department_name, 
           lt.name AS leave_type, la.start_date, la.end_date, la.reason, la.supporting_doc
    FROM leave_application la
    JOIN staff s ON la.staff_id = s.id
    JOIN leave_type lt ON la.leave_type_id = lt.id
    LEFT JOIN department d ON s.department_id = d.id
    WHERE la.status='pending'
    ORDER BY la.start_date DESC
");
if ($stmt) {
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) $pending_leaves[] = $row;
    $stmt->close();
}

/* =========================
   Fetch admin info for header
========================= */
$admin_name = $username;
$email = '';
$job_title = '';
$stmt = $mysqli->prepare("
    SELECT s.name, s.email, s.job_title
    FROM users u
    JOIN staff s ON u.staff_id=s.id
    WHERE u.username=?
");
if ($stmt) {
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->bind_result($admin_name, $email, $job_title);
    $stmt->fetch();
    $stmt->close();
}

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
<title>AMC HR - Leave Management</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
/* --- Full Dashboard Layout + Sidebar --- */
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Inter',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;}
.container{display:flex;min-height:100vh;}

/* Sidebar with scroll like security.php */
.sidebar{
    width:280px;
    background:rgba(15,23,42,0.95);
    border-right:1px solid rgba(71,85,105,0.3);
    padding-top:32px;
    position:fixed;
    top:0;
    left:0;
    bottom:0;
    overflow-y:auto;
    z-index:100;
}
.sidebar::-webkit-scrollbar{width:6px;}
.sidebar::-webkit-scrollbar-thumb{background:rgba(96,165,250,0.3);border-radius:3px;}

.logo{padding:0 32px;margin-bottom:48px;}
.logo h1{font-size:32px;font-weight:700;background:linear-gradient(135deg,#60a5fa 0%,#3b82f6 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.logo .role-badge{display:inline-block;margin-top:8px;padding:4px 12px;background:rgba(168,85,247,0.2);border:1px solid rgba(168,85,247,0.3);border-radius:6px;font-size:12px;font-weight:600;color:#c084fc;text-transform:uppercase;}

.nav-menu{list-style:none;padding:0;}
.nav-section-title{padding:8px 32px;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:24px;margin-bottom:8px;}
.nav-item{margin-bottom:4px;}
.nav-link{display:flex;align-items:center;gap:12px;padding:12px 32px;color:#94a3b8;text-decoration:none;font-size:14px;font-weight:500;transition:all 0.2s ease;border-left:3px solid transparent;border-radius:6px;}
.nav-link:hover{background: rgba(59,130,246,0.1);color:#60a5fa;border-left-color:#3b82f6;}
.nav-link.active{background: rgba(59,130,246,0.15);color:#60a5fa;border-left-color:#3b82f6;}
.nav-icon{font-size:18px;width:20px;text-align:center;}

/* Main content next to sidebar */
.main-content{flex:1;margin-left:280px;padding:32px 48px;}

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
.logout-btn:hover{background:rgba(239,68,68,.3);}

/* Table styling */
table{width:100%;border-collapse:collapse;margin-top:24px;}
th,td{padding:12px;border-bottom:1px solid rgba(71,85,105,0.3);text-align:left;}
th{color:#94a3b8;text-transform:uppercase;font-size:13px;}
button.approve{background:#22c55e;color:#fff;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;}
button.reject{background:#ef4444;color:#fff;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;}
button:hover{opacity:0.9;}
.processed-text{color:#64748b;font-size:14px;font-style:italic;}
.show-btn{background: rgba(59,130,246,0.2);border:1px solid rgba(59,130,246,0.4);color:#60a5fa;padding:6px 12px;border-radius:6px;font-size:12px;cursor:pointer;}
.show-btn:hover{background: rgba(59,130,246,0.3);}

/* Modal */
.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);justify-content:center;align-items:center;z-index:999;}
.modal-content{background:#0f172a;padding:30px;border-radius:12px;max-width:800px;width:90%;max-height:80vh;overflow:auto;color:#e2e8f0;position:relative;}
#modal-body{font-size:15px;line-height:1.6;word-wrap:break-word;}
.modal-close{position:absolute;top:10px;right:15px;cursor:pointer;font-size:20px;}

/* Responsive */
@media(max-width:768px){
    .sidebar{width:100%;position:relative;height:auto;border-right:none;border-bottom:1px solid rgba(71,85,105,0.3);}
    .main-content{margin-left:0;padding:20px;}
    .container{flex-direction:column;}
    .modal-content{width:95%;max-height:90vh;}
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
                <li class="nav-item"><a href="admin-leave-management.php" class="nav-link active"><span class="nav-icon">📅</span>Leave Management</a></li>
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
                <h1>Pending Leave Requests</h1>
                <p>Review and approve leave applications</p>
            </div>
            <div class="user-info">
                <div class="name"><?= htmlspecialchars((string)$admin_name, ENT_QUOTES, 'UTF-8') ?></div>
                <div class="role"><?php echo htmlspecialchars((string)($_SESSION['role'] ?? 'admin'), ENT_QUOTES, 'UTF-8'); ?></div>
                <a href="?logout=1" class="logout-btn">Logout</a>
            </div>
        </header>

        <!-- Success/Error messages -->
        <?php if (!empty($success_message)): ?>
            <div style="background: rgba(34,197,94,0.1); color:#86efac; padding:12px; border-radius:8px; margin-bottom:20px;">
                <?php echo htmlspecialchars($success_message, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>
        <?php if (!empty($error_message)): ?>
            <div style="background: rgba(239,68,68,0.1); color:#fca5a5; padding:12px; border-radius:8px; margin-bottom:20px;">
                <?php echo htmlspecialchars($error_message, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <!-- Pending Leaves Table -->
        <?php if (count($pending_leaves) > 0): ?>
        <table>
            <thead>
                <tr>
                    <th>Employee</th>
                    <th>Department</th>
                    <th>Leave Type</th>
                    <th>Start</th>
                    <th>End</th>
                    <th>Reason</th>
                    <th>Document</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($pending_leaves as $leave): ?>
                <tr>
                    <td><?php echo htmlspecialchars((string)$leave['employee_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                    <td><?php echo htmlspecialchars((string)($leave['department_name'] ?? 'N/A'), ENT_QUOTES, 'UTF-8'); ?></td>
                    <td><?php echo htmlspecialchars((string)$leave['leave_type'], ENT_QUOTES, 'UTF-8'); ?></td>
                    <td><?php echo date('M d, Y', strtotime((string)$leave['start_date'])); ?></td>
                    <td><?php echo date('M d, Y', strtotime((string)$leave['end_date'])); ?></td>
                    <td>
                        <?php
                        if (!empty($leave['reason'])) {
                            $reasonEsc = htmlspecialchars((string)$leave['reason'], ENT_QUOTES, 'UTF-8');
                            echo "<button class='show-btn' data-content='{$reasonEsc}'>View</button>";
                        } else {
                            echo 'N/A';
                        }
                        ?>
                    </td>
                    <td>
                        <?php
                        if (!empty($leave['supporting_doc'])) {
                            $file = basename((string)$leave['supporting_doc']); // prevent path traversal
                            $fileEsc = htmlspecialchars($file, ENT_QUOTES, 'UTF-8');
                            $html = "<img src='../uploads/certs/{$fileEsc}' style='max-width:100%;max-height:70vh;' alt='Supporting document'>";
                            $htmlAttr = htmlspecialchars($html, ENT_QUOTES, 'UTF-8');
                            echo "<button class='show-btn' data-content=\"{$htmlAttr}\">View</button>";
                        } else {
                            echo 'N/A';
                        }
                        ?>
                    </td>
                    <td>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string)$_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                            <input type="hidden" name="leave_id" value="<?php echo (int)$leave['leave_id']; ?>">
                            <button type="submit" name="action" value="approve" class="approve">Approve</button>
                            <button type="submit" name="action" value="reject" class="reject">Reject</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php else: ?>
            <p>No pending leave requests.</p>
        <?php endif; ?>

        <!-- Modal -->
        <div class="modal" id="modal">
            <div class="modal-content">
                <span class="modal-close" id="modal-close">&times;</span>
                <div id="modal-body"></div>
            </div>
        </div>

        <script>
        const modal = document.getElementById('modal');
        const modalBody = document.getElementById('modal-body');
        const modalClose = document.getElementById('modal-close');

        modalClose.onclick = () => modal.style.display = 'none';
        window.onclick = e => { if (e.target === modal) modal.style.display = 'none'; };

        document.querySelectorAll('.show-btn').forEach(btn => {
            btn.onclick = () => {
                // data-content is already escaped. We decode minimal formatting here:
                const content = btn.dataset.content || '';
                modalBody.innerHTML = content.replace(/\n/g,'<br>');
                modal.style.display='flex';
            };
        });
        </script>
    </main>
</div>
</body>
</html>
