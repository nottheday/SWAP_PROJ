<?php
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
session_start();

if (isset($_GET['role'])) {
    $requestedRole = strtolower((string)$_GET['role']);
    $sessionRole   = strtolower((string)($_SESSION['role'] ?? ''));
    if ($requestedRole !== $sessionRole) { http_response_code(403); exit("Forbidden: role tampering detected."); }
    unset($_GET['role']);
}
if (isset($_GET['id']) || isset($_GET['staff_id']) || isset($_GET['employee_id'])) {
    http_response_code(403); exit("Forbidden: parameter tampering detected.");
}

if (!isset($_SESSION['auth'], $_SESSION['user'], $_SESSION['role'])) { header("Location: login.php"); exit; }
if ($_SESSION['role'] !== 'staff') { http_response_code(403); exit("Access Denied: staff only."); }

$username = $_SESSION['user'];
$role = $_SESSION['role'];

$mysqli = new mysqli("localhost", "root", "", "swap");
if ($mysqli->connect_error) die("DB connection failed: " . $mysqli->connect_error);

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
function resolveStaff(mysqli $mysqli, string $username): int {
    $staff_id = 0;
    if (columnExists($mysqli, 'users', 'staff_id')) {
        $st = $mysqli->prepare("SELECT staff_id FROM users WHERE username=? LIMIT 1");
        if ($st) { $st->bind_param("s",$username); $st->execute(); $st->bind_result($staff_id); $st->fetch(); $st->close(); }
    }
    if (empty($staff_id) && columnExists($mysqli, 'users', 'name')) {
        $u = $mysqli->prepare("SELECT name FROM users WHERE username=? LIMIT 1");
        if ($u) {
            $u->bind_param("s",$username); $u->execute(); $u->bind_result($nm); $u->fetch(); $u->close();
            if (!empty($nm)) {
                $s = $mysqli->prepare("SELECT id FROM staff WHERE name=? LIMIT 1");
                if ($s) { $s->bind_param("s",$nm); $s->execute(); $s->bind_result($staff_id); $s->fetch(); $s->close(); }
            }
        }
    }
    return (int)$staff_id;
}

$staff_id = resolveStaff($mysqli, $username);

/* Find a training table */
$training_table = null;
$candidates = ['training', 'training_records', 'staff_training'];
foreach ($candidates as $t) {
    $r = $mysqli->query("SHOW TABLES LIKE '{$t}'");
    if ($r && $r->num_rows > 0) { $training_table = $t; break; }
}

$rows = [];
$note = '';

if ($training_table) {
    // Build a safe select list based on common columns that exist
    $cols = [];
    $colmap = [
        'course_name' => 'Course',
        'name'        => 'Course',
        'status'      => 'Status',
        'due_date'    => 'Due Date',
        'completed_date' => 'Completed',
        'completion_date' => 'Completed',
    ];

    foreach ($colmap as $c => $label) {
        if (columnExists($mysqli, $training_table, $c)) $cols[] = $c;
    }

    if (!in_array('staff_id', $cols, true)) {
        // staff_id is required for filtering even if not displayed
        if (!columnExists($mysqli, $training_table, 'staff_id')) {
            $note = "Training table found ({$training_table}) but missing staff_id column.";
        } else {
            // keep cols display-only, still filter by staff_id
        }
    }

    if (!$note) {
        $selectCols = $cols ? implode(", ", array_map(fn($x)=>"`$x`", $cols)) : "*";
        $st = $mysqli->prepare("SELECT {$selectCols} FROM `{$training_table}` WHERE staff_id=? ORDER BY 1 DESC LIMIT 100");
        if ($st) {
            $st->bind_param("i", $staff_id);
            $st->execute();
            $r = $st->get_result();
            while ($row = $r->fetch_assoc()) $rows[] = $row;
            $st->close();
        }
    }
} else {
    $note = "No training table found. (Expected: training / training_records / staff_training)";
}

if (isset($_GET['logout'])) { session_unset(); session_destroy(); header("Location: login.php"); exit; }
$mysqli->close();
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
    th,td{padding:14px 10px;border-bottom:1px solid rgba(71,85,105,.22);font-size:14px}
    th{text-align:left;color:#93c5fd;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
    tr:hover{background:rgba(59,130,246,.05)}
    .muted{color:#94a3b8;font-size:13px}
    @media(max-width:1024px){.sidebar{width:240px}.main-content{margin-left:240px;padding:24px 32px}}
    @media(max-width:768px){.sidebar{width:100%;position:relative;height:auto;border-right:none;border-bottom:1px solid rgba(71,85,105,.3)}.main-content{margin-left:0;padding:20px}.container{flex-direction:column}.header{flex-direction:column;align-items:flex-start}.header-actions{width:100%;justify-content:space-between}}
  </style>
</head>
<body>
<div class="container">
  <aside class="sidebar">
    <div class="logo"><h1>AMC HR</h1><span class="role-badge">Staff</span></div>
    <nav>
      <ul class="nav-menu">
        <li class="nav-item"><a href="staff-dashboard.php" class="nav-link"><span class="nav-icon">🏠</span><span>Dashboard</span></a></li>
        <li class="nav-item"><a href="staff-apply_leave.php" class="nav-link"><span class="nav-icon">📝</span><span>Apply Leave</span></a></li>
        <li class="nav-item"><a href="staff-my_leave.php" class="nav-link"><span class="nav-icon">📅</span><span>My Leave</span></a></li>
        <li class="nav-item"><a href="staff-training.php" class="nav-link active"><span class="nav-icon">🎓</span><span>My Training</span></a></li>
        <li class="nav-item"><a href="staff-profile.php" class="nav-link"><span class="nav-icon">👤</span><span>My Profile</span></a></li>
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
                <?php foreach (array_keys($rows[0]) as $k): ?>
                  <th><?php echo htmlspecialchars(strtoupper(str_replace('_',' ',$k))); ?></th>
                <?php endforeach; ?>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($rows as $r): ?>
                <tr>
                  <?php foreach ($r as $v): ?>
                    <td><?php echo htmlspecialchars((string)$v); ?></td>
                  <?php endforeach; ?>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        <?php endif; ?>
        <p class="muted" style="margin-top:10px;">Security: staff can only view their own records (filtered by staff_id server-side).</p>
      </div>
    </section>
  </main>
</div>
</body>
</html>
