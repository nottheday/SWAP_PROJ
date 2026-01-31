<?php
declare(strict_types=1);

require_once __DIR__ . '/../misc_security/secure-transport.php';
require_once __DIR__ . '/../misc_security/session-hardening.php';
require_once __DIR__ . '/../misc_security/sql-prevention.php';

/* ===============================
   Session init (avoid ini_set warnings / double start)
================================ */
if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.use_strict_mode', '1');
    ini_set('session.cookie_httponly', '1');
    session_start();
}

/* ===============================
   ✅ URL Tampering Popup (STAFF TRAINING)
   Your requirements:
   1) If ?role=staff/admin/supervisor (ANY role param) => popup + clean reload
   2) If URL is edited (ANY unexpected query key)      => popup + clean reload
   3) If filename/path is edited (e.g. staff-training.php -> admin-dashboard.php)
      => popup + redirect back to correct page (staff-training.php)
   Allowed query keys on this page: logout only
================================ */
$EXPECTED_FILE = 'staff-training.php';

function training_clean_url(array $removeKeys = ['role','id','staff_id','employee_id','user_id']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);

    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function training_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) {
        $_SESSION['flash_unauth'] = 1;
    }

    $clean = training_clean_url();

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
   Auth first (must come before any tamper checks using session role)
================================ */
if (!isset($_SESSION['auth'], $_SESSION['user'], $_SESSION['role'])) {
    header("Location: /AMC_Website/login_page/login.php");
    exit;
}

/* ===============================
   Force correct filename if URL path is edited
================================ */
$currentFile = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '');
if ($currentFile !== '' && strtolower($currentFile) !== strtolower($EXPECTED_FILE)) {
    training_redirect_clean(true, $EXPECTED_FILE);
}

/* ===============================
   Detect ANY unexpected query keys (URL edited)
   Allowed keys: logout only
================================ */
$allowedKeys = ['logout'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        training_redirect_clean(true);
    }
}

/* ===============================
   Explicit tamper triggers (kept for clarity)
================================ */
if (isset($_GET['role'])) {
    // ANY role param triggers popup (even if it matches)
    training_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['staff_id']) || isset($_GET['employee_id']) || isset($_GET['user_id'])) {
    training_redirect_clean(true);
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
$mysqli->set_charset("utf8mb4");

function columnExists(mysqli $mysqli, string $table, string $column): bool {
    $sql = "SELECT 1 FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=? LIMIT 1";
    $st = $mysqli->prepare($sql);
    if (!$st) return false;
    $st->bind_param("ss", $table, $column);
    $st->execute();
    $st->store_result();
    $ok = ($st->num_rows === 1);
    $st->close();
    return $ok;
}

function tableExists(mysqli $mysqli, string $table): bool {
    $sql = "SELECT 1
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = ?
            LIMIT 1";
    $st = $mysqli->prepare($sql);
    if (!$st) return false;
    $st->bind_param("s", $table);
    $st->execute();
    $st->store_result();
    $ok = ($st->num_rows === 1);
    $st->close();
    return $ok;
}

function resolveStaffId(mysqli $mysqli, string $username): int {
    $staff_id = 0;

    if (columnExists($mysqli, 'users', 'staff_id')) {
        $st = $mysqli->prepare("SELECT staff_id FROM users WHERE username=? LIMIT 1");
        if ($st) {
            $st->bind_param("s", $username);
            $st->execute();
            $st->bind_result($staff_id);
            $st->fetch();
            $st->close();
        }
    }

    if (empty($staff_id) && columnExists($mysqli, 'users', 'name')) {
        $u = $mysqli->prepare("SELECT name FROM users WHERE username=? LIMIT 1");
        if ($u) {
            $u->bind_param("s", $username);
            $u->execute();
            $u->bind_result($nm);
            $u->fetch();
            $u->close();

            if (!empty($nm)) {
                $s = $mysqli->prepare("SELECT id FROM staff WHERE name=? LIMIT 1");
                if ($s) {
                    $s->bind_param("s", $nm);
                    $s->execute();
                    $s->bind_result($staff_id);
                    $s->fetch();
                    $s->close();
                }
            }
        }
    }

    return (int)$staff_id;
}

$staff_id = resolveStaffId($mysqli, $username);

/* ============================================================
   Staff training reads from:
   training_attendance + training_sessions
============================================================ */
$rows = [];
$note = "";

if ($staff_id <= 0) {
    $note = "Unable to find your staff ID (users.staff_id not set / mismatch).";
} elseif (!tableExists($mysqli, 'training_attendance') || !tableExists($mysqli, 'training_sessions')) {
    $note = "Missing required tables: training_attendance / training_sessions.";
} elseif (
    !columnExists($mysqli, 'training_attendance', 'staff_id') ||
    !columnExists($mysqli, 'training_attendance', 'training_sessions_id') ||
    !columnExists($mysqli, 'training_sessions', 'id')
) {
    $note = "Training tables exist but required columns are missing.";
} else {
    $select = [];
    $select[] = "ts.id AS training_sessions_id";
    $select[] = (columnExists($mysqli, 'training_sessions', 'name') ? "ts.name AS course_title" : "'' AS course_title");
    $select[] = (columnExists($mysqli, 'training_sessions', 'start_date') ? "ts.start_date" : "NULL AS start_date");
    $select[] = (columnExists($mysqli, 'training_sessions', 'end_date') ? "ts.end_date" : "NULL AS end_date");
    $select[] = (columnExists($mysqli, 'training_attendance', 'status') ? "ta.status AS attendance_status" : "'' AS attendance_status");

    if (columnExists($mysqli, 'training_attendance', 'approval_status')) {
        $select[] = "COALESCE(NULLIF(ta.approval_status,''), 'pending') AS approval_status";
    } else {
        $select[] = "'pending' AS approval_status";
    }
    $select[] = (columnExists($mysqli, 'training_attendance', 'approval_reason') ? "ta.approval_reason" : "'' AS approval_reason");
    $select[] = (columnExists($mysqli, 'training_attendance', 'approval_by') ? "ta.approval_by" : "'' AS approval_by");
    $select[] = (columnExists($mysqli, 'training_attendance', 'approval_date') ? "ta.approval_date" : "NULL AS approval_date");

    $orderBy = columnExists($mysqli, 'training_sessions', 'start_date') ? "ts.start_date DESC" : "ts.id DESC";

    $sql = "
        SELECT " . implode(", ", $select) . "
        FROM training_attendance ta
        JOIN training_sessions ts ON ta.training_sessions_id = ts.id
        WHERE ta.staff_id = ?
        ORDER BY $orderBy
        LIMIT 200
    ";

    $st = $mysqli->prepare($sql);
    if (!$st) {
        $note = "Failed to prepare training query.";
    } else {
        $st->bind_param("i", $staff_id);
        $st->execute();
        $res = $st->get_result();
        while ($row = $res->fetch_assoc()) {
            $a = strtolower((string)($row['approval_status'] ?? 'pending'));
            if ($a !== 'approved' && $a !== 'not_approved') $a = 'pending';
            $row['approval_status'] = $a;
            $rows[] = $row;
        }
        $st->close();
    }
}

/* ===============================
   Logout (allowed query key)
================================ */
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header("Location: /AMC_Website/login.php");
    exit;
}

$mysqli->close();

/* ===============================
   Popup flag (one-time)
================================ */
$showUnauth = !empty($_SESSION['flash_unauth']);
if ($showUnauth) unset($_SESSION['flash_unauth']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AMC HR - My Training</title>
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
    th,td{padding:14px 10px;border-bottom:1px solid rgba(71,85,105,.22);font-size:14px;vertical-align:top}
    th{text-align:left;color:#93c5fd;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
    tr:hover{background:rgba(59,130,246,.05)}
    .muted{color:#94a3b8;font-size:13px}

    .badge{display:inline-block;padding:6px 10px;border-radius:6px;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.5px;border:1px solid transparent}
    .badge.approved{background:rgba(34,197,94,.12);border-color:rgba(34,197,94,.25);color:#86efac}
    .badge.not_approved{background:rgba(239,68,68,.12);border-color:rgba(239,68,68,.25);color:#fca5a5}
    .badge.pending{background:rgba(251,146,60,.14);border-color:rgba(251,146,60,.25);color:#fdba74}

    /* Modal popup */
    .modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;z-index:9999}
    .modal{width:min(520px,92vw);background:#0b1224;border:1px solid rgba(239,68,68,.5);border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.5);overflow:hidden}
    .modal-head{padding:14px 16px;background:rgba(239,68,68,.12);border-bottom:1px solid rgba(239,68,68,.25);font-weight:900;color:#fecaca}
    .modal-body{padding:16px;color:#e2e8f0;line-height:1.5}
    .modal-actions{padding:14px 16px;display:flex;justify-content:flex-end;border-top:1px solid rgba(71,85,105,.25)}
    .modal-actions button{
      padding:10px 16px;border-radius:10px;border:1px solid rgba(239,68,68,.55);
      background:rgba(239,68,68,.2);color:#fecaca;font-weight:900;cursor:pointer;transition:.2s
    }
    .modal-actions button:hover{background:rgba(239,68,68,.28)}

    @media(max-width:1024px){.sidebar{width:240px}.main-content{margin-left:240px;padding:24px 32px}}
    @media(max-width:768px){.sidebar{width:100%;position:relative;height:auto;border-right:none;border-bottom:1px solid rgba(71,85,105,.3)}.main-content{margin-left:0;padding:20px}.container{flex-direction:column}.header{flex-direction:column;align-items:flex-start}.header-actions{width:100%;justify-content:space-between}}
  </style>
</head>
<body>

<!-- ===== Modal Popup ===== -->
<div class="modal-backdrop" id="unauthModal" <?php echo $showUnauth ? 'style="display:flex"' : ''; ?>>
  <div class="modal" role="dialog" aria-modal="true">
    <div class="modal-head">⚠️Unauthorised Access Detected</div>
    <div class="modal-body">
      Your request was blocked because the URL looked modified (role/query/path tampering).<br>
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
        <h2>My Training</h2>
        <p>View your training records</p>
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
      <div class="panel-head"><div class="panel-title">Training Records</div></div>
      <div class="panel-body">
        <?php if ($note): ?>
          <p class="muted"><?php echo htmlspecialchars($note); ?></p>
        <?php elseif (empty($rows)): ?>
          <p class="muted">No training records found.</p>
        <?php else: ?>
          <table>
            <thead>
              <tr>
                <th>COURSE</th>
                <th>DATES</th>
                <th>ATTENDANCE</th>
                <th>APPROVAL</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($rows as $r): ?>
                <?php
                  $approval = (string)($r['approval_status'] ?? 'pending');
                  if ($approval !== 'approved' && $approval !== 'not_approved') $approval = 'pending';

                  $start = !empty($r['start_date']) ? date('M d, Y', strtotime((string)$r['start_date'])) : '';
                  $end   = !empty($r['end_date'])   ? date('M d, Y', strtotime((string)$r['end_date']))   : '';
                  $apprDate = !empty($r['approval_date']) ? date('M d, Y H:i', strtotime((string)$r['approval_date'])) : '';
                ?>
                <tr>
                  <td><strong><?php echo htmlspecialchars((string)($r['course_title'] ?? '')); ?></strong></td>
                  <td>
                    <?php if ($start || $end): ?>
                      <span class="muted">Start</span><br><?php echo htmlspecialchars($start); ?><br><br>
                      <span class="muted">End</span><br><?php echo htmlspecialchars($end); ?>
                    <?php else: ?>
                      <span class="muted">—</span>
                    <?php endif; ?>
                  </td>
                  <td><?php echo htmlspecialchars((string)($r['attendance_status'] ?? '')); ?></td>
                  <td>
                    <span class="badge <?php echo htmlspecialchars($approval); ?>">
                      <?php echo htmlspecialchars(str_replace('_', ' ', $approval)); ?>
                    </span>

                    <?php if (!empty($r['approval_reason'])): ?>
                      <br><span class="muted">Reason: <?php echo htmlspecialchars((string)$r['approval_reason']); ?></span>
                    <?php endif; ?>

                    <?php if (!empty($r['approval_by'])): ?>
                      <br><span class="muted">By: <?php echo htmlspecialchars((string)$r['approval_by']); ?></span>
                    <?php endif; ?>

                    <?php if (!empty($apprDate)): ?>
                      <br><span class="muted">On: <?php echo htmlspecialchars($apprDate); ?></span>
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
