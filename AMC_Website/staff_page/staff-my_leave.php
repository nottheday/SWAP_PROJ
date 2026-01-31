<?php
declare(strict_types=1);

require_once __DIR__ . '/../misc_security/secure-transport.php';
require_once __DIR__ . '/../misc_security/session-hardening.php';
require_once __DIR__ . '/../misc_security/sql-prevention.php';

/* ===============================
   Session init (safe: avoid ini_set warnings / double start)
================================ */
if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.use_strict_mode', '1');
    ini_set('session.cookie_httponly', '1');
    session_start();
}

/* ===============================
   ✅ URL Tampering Popup (MY LEAVE)
   Requirements you asked:
   1) If ?role=staff/admin/supervisor (ANY role param) => popup + clean reload
   2) If any URL is edited (ANY unexpected query key) => popup + clean reload
   3) If someone tries to access this page but URL path/filename is edited
      (e.g. staff-my_leave.php changed to admin-dashboard.php) => popup + redirect to correct page
   Allowed query keys for this page: logout only
================================ */
$EXPECTED_FILE = 'staff-my_leave.php';

function myleave_clean_url(array $removeKeys = ['role','id','staff_id','employee_id','user_id']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);

    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function myleave_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) {
        $_SESSION['flash_unauth'] = 1;
    }

    $clean = myleave_clean_url();

    // If someone edited the filename/path, force back to expected file
    if ($forcePath !== null) {
        $qPos = strpos($clean, '?');
        $qs   = ($qPos !== false) ? substr($clean, $qPos) : '';
        header('Location: ' . $forcePath . $qs);
        exit;
    }

    header('Location: ' . $clean);
    exit;
}

/* ===============================
   Auth first (must come before tamper checks that need session)
================================ */
if (!isset($_SESSION['auth'], $_SESSION['user'], $_SESSION['role'])) {
    header('Location: AMC_Website/login_page/login.php');
    exit;
}

/* ===============================
   Force correct filename if URL is edited to another file name
   Example: staff-my_leave.php changed to admin-dashboard.php
================================ */
$currentFile = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '');
if ($currentFile !== '' && strtolower($currentFile) !== strtolower($EXPECTED_FILE)) {
    myleave_redirect_clean(true, $EXPECTED_FILE);
}

/* ===============================
   Detect ANY unexpected query keys (URL edited)
   Allowed keys for this page: logout only
================================ */
$allowedKeys = ['logout'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        myleave_redirect_clean(true);
    }
}

/* ===============================
   Explicit tamper triggers (kept for clarity)
================================ */
if (isset($_GET['role'])) {
    // ANY role param triggers popup (even if it matches)
    myleave_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['staff_id']) || isset($_GET['employee_id']) || isset($_GET['user_id'])) {
    myleave_redirect_clean(true);
}

/* ===============================
   RBAC: staff only
================================ */
if (strtolower((string)$_SESSION['role']) !== 'staff') {
    http_response_code(403);
    exit("Access Denied: staff only.");
}

$username = (string)$_SESSION['user'];
$role     = (string)$_SESSION['role'];

/* ===============================
   Auto-highlight current sidebar tab
================================ */
$currentPage = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
function navActive(string $file, string $currentPage): string {
    return $file === $currentPage ? ' active' : '';
}

/* ===============================
   DB
================================ */
$mysqli = new mysqli("localhost", "root", "", "swap");
if ($mysqli->connect_error) die("DB connection failed: " . $mysqli->connect_error);
$mysqli->set_charset('utf8mb4');

function columnExists(mysqli $mysqli, string $table, string $column): bool {
    $sql = "SELECT 1 FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=? LIMIT 1";
    $st = $mysqli->prepare($sql);
    if (!$st) return false;
    $st->bind_param("ss", $table, $column);
    $st->execute(); $st->store_result();
    $ok = ($st->num_rows === 1);
    $st->close();
    return $ok;
}

function resolveStaff(mysqli $mysqli, string $username): array {
    $staff_id = 0; $staff_name = $username; $dept_id = null;

    // Preferred: users.staff_id -> staff.id
    if (columnExists($mysqli, 'users', 'staff_id')) {
        $st = $mysqli->prepare("
            SELECT s.id, s.name, s.department_id
            FROM users u
            JOIN staff s ON s.id = u.staff_id
            WHERE u.username = ?
            LIMIT 1
        ");
        if ($st) {
            $st->bind_param("s", $username);
            $st->execute();
            $st->bind_result($staff_id, $staff_name, $dept_id);
            $st->fetch();
            $st->close();
        }
    }

    // Fallback: users.name -> staff.name
    if (empty($staff_id) && columnExists($mysqli, 'users', 'name')) {
        $u = $mysqli->prepare("SELECT name FROM users WHERE username=? LIMIT 1");
        if ($u) {
            $u->bind_param("s", $username);
            $u->execute();
            $u->bind_result($nm);
            $u->fetch();
            $u->close();

            if (!empty($nm)) {
                $s = $mysqli->prepare("SELECT id, name, department_id FROM staff WHERE name=? LIMIT 1");
                if ($s) {
                    $s->bind_param("s", $nm);
                    $s->execute();
                    $s->bind_result($staff_id, $staff_name, $dept_id);
                    $s->fetch();
                    $s->close();
                }
            }
        }
    }

    return ['staff_id' => (int)($staff_id ?: 0), 'staff_name' => (string)$staff_name, 'department_id' => $dept_id];
}

if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

$staff = resolveStaff($mysqli, $username);
$staff_id = (int)$staff['staff_id'];

$success = '';
$error   = '';

/* ===============================
   Cancel (only your own pending leave)
================================ */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') === 'cancel') {
    $csrf = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token'], $csrf)) { http_response_code(403); exit("CSRF blocked."); }

    $leave_id = filter_input(INPUT_POST, 'leave_id', FILTER_VALIDATE_INT);

    if (!$leave_id || $leave_id <= 0) $error = "Invalid leave id.";
    elseif ($staff_id <= 0) $error = "Staff record not found.";
    else {
        $st = $mysqli->prepare("SELECT id FROM leave_application WHERE id=? AND staff_id=? AND status='pending' LIMIT 1");
        $st->bind_param("ii", $leave_id, $staff_id);
        $st->execute();
        $st->store_result();
        $ok = ($st->num_rows === 1);
        $st->close();

        if (!$ok) {
            $error = "You can only cancel your own PENDING requests.";
        } else {
            // prefer updating status
            $upd = $mysqli->prepare("UPDATE leave_application SET status='cancelled' WHERE id=? AND staff_id=?");
            if ($upd) {
                $upd->bind_param("ii", $leave_id, $staff_id);
                if ($upd->execute()) $success = "Leave request #{$leave_id} cancelled.";
                else $error = "Cancel failed (status update rejected).";
                $upd->close();
            }

            // fallback delete if you want (kept from your code)
            if (!$success && !$error) {
                $del = $mysqli->prepare("DELETE FROM leave_application WHERE id=? AND staff_id=?");
                if ($del) {
                    $del->bind_param("ii", $leave_id, $staff_id);
                    if ($del->execute()) $success = "Leave request #{$leave_id} cancelled (deleted).";
                    else $error = "Cancel failed.";
                    $del->close();
                }
            }

            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        }
    }
}

/* ===============================
   Load my leave
================================ */
$my_leave = [];
$st = $mysqli->prepare("
    SELECT la.id AS leave_id, lt.name AS leave_type, la.start_date, la.end_date, la.status,
           DATEDIFF(la.end_date, la.start_date) + 1 AS duration_days
    FROM leave_application la
    JOIN leave_type lt ON la.leave_type_id = lt.id
    WHERE la.staff_id = ?
    ORDER BY la.id DESC
    LIMIT 100
");
if ($st) {
    $st->bind_param("i", $staff_id);
    $st->execute();
    $r = $st->get_result();
    while ($row = $r->fetch_assoc()) $my_leave[] = $row;
    $st->close();
}

/* ===============================
   Logout
================================ */
if (isset($_GET['logout'])) {
    session_unset(); session_destroy();
    header("Location: /AMC_Website/login.php");
    exit;
}

$mysqli->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AMC HR - My Leave</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Inter',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
    .container{display:flex;min-height:100vh}
    .sidebar{width:280px;background:rgba(15,23,42,.95);border-right:1px solid rgba(71,85,105,.3);padding:32px 0;position:fixed;height:100vh;overflow-y:auto}
    .logo{padding:0 32px;margin-bottom:48px}
    .logo h1{font-size:32px;font-weight:700;background:linear-gradient(135deg,#60a5fa 0%,#3b82f6 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
    .role-badge{display:inline-block;margin-top:8px;padding:4px 12px;background:rgba(34,197,94,.16);border:1px solid rgba(34,197,94,.28);border-radius:6px;font-size:12px;font-weight:700;color:#4ade80;text-transform:uppercase}
    .nav-menu{list-style:none}
    .nav-item{margin-bottom:8px}
    .nav-link{display:flex;align-items:center;gap:12px;padding:14px 32px;color:#94a3b8;text-decoration:none;font-size:15px;font-weight:500;transition:.2s;border-left:3px solid transparent}
    .nav-link:hover{background:rgba(59,130,246,.1);color:#60a5fa;border-left-color:#3b82f6}
    .nav-link.active{background:rgba(59,130,246,.15);color:#60a5fa;border-left-color:#3b82f6}
    .nav-icon{font-size:20px}
    .main-content{flex:1;margin-left:280px;padding:32px 48px}
    .header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;gap:20px}
    .welcome-section h2{font-size:28px;font-weight:700;margin-bottom:8px}
    .welcome-section p{font-size:14px;color:#94a3b8}
    .header-actions{display:flex;align-items:center;gap:20px}
    .user-info{display:flex;flex-direction:column;align-items:flex-end;color:#94a3b8;font-size:14px}
    .user-info strong{color:#60a5fa;font-weight:600}
    .logout-btn{padding:10px 24px;background:rgba(239,68,68,.2);border:1px solid rgba(239,68,68,.4);border-radius:8px;color:#fca5a5;font-size:14px;font-weight:600;text-decoration:none;transition:.2s}
    .logout-btn:hover{background:rgba(239,68,68,.3);border-color:rgba(239,68,68,.6)}
    .panel{background:rgba(15,23,42,.6);border:1px solid rgba(71,85,105,.3);border-radius:12px;overflow:hidden}
    .panel-head{padding:16px 18px;background:rgba(30,41,59,.8);border-bottom:1px solid rgba(71,85,105,.35)}
    .panel-title{font-size:14px;font-weight:700;color:#60a5fa;text-transform:uppercase;letter-spacing:.5px}
    .panel-body{padding:18px}
    table{width:100%;border-collapse:collapse}
    th,td{padding:14px 10px;border-bottom:1px solid rgba(71,85,105,.22);font-size:14px}
    th{text-align:left;color:#93c5fd;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
    tr:hover{background:rgba(59,130,246,.05)}
    .status-badge{display:inline-block;padding:6px 12px;border-radius:6px;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.5px}
    .pending{background:rgba(234,179,8,.15);color:#fbbf24;border:1px solid rgba(234,179,8,.3)}
    .approved{background:rgba(34,197,94,.15);color:#4ade80;border:1px solid rgba(34,197,94,.3)}
    .rejected{background:rgba(239,68,68,.15);color:#f87171;border:1px solid rgba(239,68,68,.3)}
    .cancelled{background:rgba(148,163,184,.12);color:#cbd5e1;border:1px solid rgba(148,163,184,.25)}
    .btn-cancel{
      padding:10px 14px;border-radius:10px;border:1px solid rgba(239,68,68,.55);
      background:rgba(239,68,68,.2);color:#fca5a5;font-weight:900;cursor:pointer;transition:.2s
    }
    .btn-cancel:hover{background:rgba(239,68,68,.28)}
    .muted{color:#94a3b8;font-size:13px}

    /* Popup modal */
    .modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;z-index:9999}
    .modal{width:min(520px,92vw);background:#0b1224;border:1px solid rgba(239,68,68,.5);border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.5);overflow:hidden}
    .modal-head{padding:14px 16px;background:rgba(239,68,68,.12);border-bottom:1px solid rgba(239,68,68,.25);font-weight:900;color:#fecaca}
    .modal-body{padding:16px;color:#e2e8f0;line-height:1.5}
    .modal-actions{padding:14px 16px;display:flex;justify-content:flex-end;border-top:1px solid rgba(71,85,105,.25)}
    .modal-actions button{border-color:rgba(239,68,68,.55);background:rgba(239,68,68,.2);color:#fecaca}
    .modal-actions button:hover{background:rgba(239,68,68,.28)}

    @media(max-width:1024px){.sidebar{width:240px}.main-content{margin-left:240px;padding:24px 32px}}
    @media(max-width:768px){.sidebar{width:100%;position:relative;height:auto;border-right:none;border-bottom:1px solid rgba(71,85,105,.3)}.main-content{margin-left:0;padding:20px}.container{flex-direction:column}.header{flex-direction:column;align-items:flex-start}.header-actions{width:100%;justify-content:space-between}}
  </style>
</head>
<body>

<?php
$showUnauth = !empty($_SESSION['flash_unauth']);
if ($showUnauth) unset($_SESSION['flash_unauth']);
?>
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
    <div class="logo"><h1>AMC HR</h1><span class="role-badge">Staff</span></div>
    <nav>
      <ul class="nav-menu">
        <li class="nav-item"><a href="staff-dashboard.php" class="nav-link<?php echo navActive('staff-dashboard.php', $currentPage); ?>"><span class="nav-icon">🏠</span><span>Dashboard</span></a></li>
        <li class="nav-item"><a href="staff-apply_leave.php" class="nav-link<?php echo navActive('staff-apply_leave.php', $currentPage); ?>"><span class="nav-icon">📝</span><span>Apply Leave</span></a></li>
        <li class="nav-item"><a href="staff-my_leave.php" class="nav-link<?php echo navActive('staff-my_leave.php', $currentPage); ?>"><span class="nav-icon">📅</span><span>My Leave</span></a></li>
        <li class="nav-item"><a href="staff-training.php" class="nav-link<?php echo navActive('staff-training.php', $currentPage); ?>"><span class="nav-icon">🎓</span><span>My Training</span></a></li>
        <li class="nav-item"><a href="staff-certification.php" class="nav-link<?php echo navActive('staff-certification.php', $currentPage); ?>"><span class="nav-icon">📄</span><span>My Certifications</span></a></li>
        <li class="nav-item"><a href="staff-profile.php" class="nav-link<?php echo navActive('staff-profile.php', $currentPage); ?>"><span class="nav-icon">👤</span><span>My Profile</span></a></li>
      </ul>
    </nav>
  </aside>

  <main class="main-content">
    <header class="header">
      <div class="welcome-section">
        <h2>My Leave</h2>
        <p>View your leave history and status</p>
      </div>
      <div class="header-actions">
        <div class="user-info">
          <span><strong><?php echo htmlspecialchars($username); ?></strong></span>
          <span style="text-transform: capitalize;"><?php echo htmlspecialchars($role); ?></span>
        </div>
        <a class="logout-btn" href="?logout=1">Logout</a>
      </div>
    </header>

    <section class="panel">
      <div class="panel-head"><div class="panel-title">Leave Requests</div></div>
      <div class="panel-body">
        <?php if (empty($my_leave)): ?>
          <p class="muted">No leave requests found.</p>
        <?php else: ?>
          <table>
            <thead>
              <tr>
                <th>ID</th><th>Type</th><th>Start</th><th>End</th><th>Days</th><th>Status</th><th>Action</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($my_leave as $lv): ?>
                <tr>
                  <td><?php echo (int)$lv['leave_id']; ?></td>
                  <td><?php echo htmlspecialchars((string)$lv['leave_type']); ?></td>
                  <td><?php echo date('M d, Y', strtotime((string)$lv['start_date'])); ?></td>
                  <td><?php echo date('M d, Y', strtotime((string)$lv['end_date'])); ?></td>
                  <td><?php echo (int)$lv['duration_days']; ?></td>
                  <td>
                    <span class="status-badge <?php echo htmlspecialchars(strtolower((string)$lv['status'])); ?>">
                      <?php echo htmlspecialchars(strtoupper((string)$lv['status'])); ?>
                    </span>
                  </td>
                  <td>
                    <?php if ((string)$lv['status'] === 'pending'): ?>
                      <form method="POST" style="margin:0;">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string)$_SESSION['csrf_token']); ?>">
                        <input type="hidden" name="leave_id" value="<?php echo (int)$lv['leave_id']; ?>">
                        <button class="btn-cancel" type="submit" name="action" value="cancel">Cancel</button>
                      </form>
                    <?php else: ?>
                      <span class="muted">—</span>
                    <?php endif; ?>
                  </td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        <?php endif; ?>
      </div>
    </section>
  </main>
</div>
</body>
</html>
