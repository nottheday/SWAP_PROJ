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
function resolveStaffRow(mysqli $mysqli, string $username): array {
    $staff = ['id'=>0,'name'=>$username,'department_id'=>null,'status'=>null];

    if (columnExists($mysqli,'users','staff_id')) {
        $st = $mysqli->prepare("
            SELECT s.*
            FROM users u JOIN staff s ON s.id = u.staff_id
            WHERE u.username=? LIMIT 1
        ");
        if ($st) {
            $st->bind_param("s",$username);
            $st->execute();
            $res = $st->get_result();
            if ($res && $res->num_rows === 1) $staff = $res->fetch_assoc();
            $st->close();
        }
        return $staff;
    }

    if (columnExists($mysqli,'users','name')) {
        $u = $mysqli->prepare("SELECT name FROM users WHERE username=? LIMIT 1");
        if ($u) {
            $u->bind_param("s",$username); $u->execute(); $u->bind_result($nm); $u->fetch(); $u->close();
            if (!empty($nm)) {
                $s = $mysqli->prepare("SELECT * FROM staff WHERE name=? LIMIT 1");
                if ($s) {
                    $s->bind_param("s",$nm);
                    $s->execute();
                    $res = $s->get_result();
                    if ($res && $res->num_rows === 1) $staff = $res->fetch_assoc();
                    $s->close();
                }
            }
        }
    }
    return $staff;
}

if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

$staffRow = resolveStaffRow($mysqli, $username);
$staff_id = (int)($staffRow['id'] ?? 0);

$success = '';
$error = '';

/* Determine which editable fields exist */
$editable = [];
foreach (['phone','email','address'] as $c) {
    if (columnExists($mysqli, 'staff', $c)) $editable[] = $c;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token'], $csrf)) { http_response_code(403); exit("CSRF blocked."); }

    if ($staff_id <= 0) $error = "Staff record not linked to this account.";
    elseif (empty($editable)) $error = "No editable profile fields exist in staff table (phone/email/address not found).";
    else {
        $sets = [];
        $types = "";
        $vals = [];

        foreach ($editable as $c) {
            $val = trim((string)($_POST[$c] ?? ''));
            $sets[] = "`$c` = ?";
            $types .= "s";
            $vals[] = $val;
        }

        $types .= "i";
        $vals[] = $staff_id;

        $sql = "UPDATE staff SET " . implode(", ", $sets) . " WHERE id = ? LIMIT 1";
        $st = $mysqli->prepare($sql);
        if (!$st) $error = "Failed to prepare update.";
        else {
            $bind = [];
            $bind[] = $types;
            foreach ($vals as $k => $v) $bind[] = &$vals[$k];
            call_user_func_array([$st,'bind_param'], $bind);

            if ($st->execute()) $success = "Profile updated successfully.";
            else $error = "Update failed.";
            $st->close();

            // reload updated data
            $staffRow = resolveStaffRow($mysqli, $username);
        }
    }
}

if (isset($_GET['logout'])) { session_unset(); session_destroy(); header("Location: login.php"); exit; }
$mysqli->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AMC HR - My Profile</title>
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
    .msg-ok{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);color:#86efac;padding:12px 16px;border-radius:8px;margin-bottom:16px;text-align:center}
    .msg-err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5;padding:12px 16px;border-radius:8px;margin-bottom:16px;text-align:center}
    .panel{background:rgba(15,23,42,.6);border:1px solid rgba(71,85,105,.3);border-radius:12px;overflow:hidden}
    .panel-head{padding:16px 18px;background:rgba(30,41,59,.8);border-bottom:1px solid rgba(71,85,105,.35)}
    .panel-title{font-size:14px;font-weight:700;color:#60a5fa;text-transform:uppercase;letter-spacing:.5px}
    .panel-body{padding:18px}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
    label{font-size:13px;font-weight:800;color:#93c5fd;text-transform:uppercase;letter-spacing:.5px}
    input{
      width:100%;margin-top:8px;padding:12px 14px;background:rgba(30,41,59,.6);
      border:1px solid rgba(71,85,105,.4);border-radius:10px;color:#e2e8f0;outline:none
    }
    .actions{margin-top:14px;display:flex;gap:10px;flex-wrap:wrap}
    button{
      padding:10px 16px;border-radius:10px;border:1px solid rgba(59,130,246,.45);
      background:rgba(59,130,246,.2);color:#93c5fd;font-weight:900;cursor:pointer;transition:.2s
    }
    button:hover{background:rgba(59,130,246,.28)}
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
        <li class="nav-item"><a href="staff-training.php" class="nav-link"><span class="nav-icon">🎓</span><span>My Training</span></a></li>
        <li class="nav-item"><a href="staff-profile.php" class="nav-link active"><span class="nav-icon">👤</span><span>My Profile</span></a></li>
      </ul>
    </nav>
  </aside>

  <main class="main-content">
    <header class="header">
      <div class="welcome-section">
        <h2>My Profile</h2>
        <p>Update your personal information</p>
      </div>
      <div class="header-actions">
        <div class="user-info">
          <span><strong><?php echo htmlspecialchars($username); ?></strong></span>
          <span style="text-transform: capitalize;"><?php echo htmlspecialchars($role); ?></span>
        </div>
        <a class="logout-btn" href="?logout=1">Logout</a>
      </div>
    </header>

    <?php if ($success): ?><div class="msg-ok"><?php echo htmlspecialchars($success); ?></div><?php endif; ?>
    <?php if ($error): ?><div class="msg-err"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>

    <section class="panel">
      <div class="panel-head"><div class="panel-title">Profile Details</div></div>
      <div class="panel-body">
        <form method="POST">
          <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

          <div class="grid">
            <div>
              <label>Name</label>
              <input value="<?php echo htmlspecialchars((string)($staffRow['name'] ?? $username)); ?>" disabled>
              <p class="muted" style="margin-top:8px;">(Name is read-only in this demo. Editable fields depend on your staff table columns.)</p>
            </div>

            <?php if (in_array('email', $editable, true)): ?>
              <div>
                <label>Email</label>
                <input type="email" name="email" value="<?php echo htmlspecialchars((string)($staffRow['email'] ?? '')); ?>">
              </div>
            <?php endif; ?>

            <?php if (in_array('phone', $editable, true)): ?>
              <div>
                <label>Phone</label>
                <input type="text" name="phone" value="<?php echo htmlspecialchars((string)($staffRow['phone'] ?? '')); ?>">
              </div>
            <?php endif; ?>

            <?php if (in_array('address', $editable, true)): ?>
              <div>
                <label>Address</label>
                <input type="text" name="address" value="<?php echo htmlspecialchars((string)($staffRow['address'] ?? '')); ?>">
              </div>
            <?php endif; ?>
          </div>

          <div class="actions">
            <button type="submit">Save Changes</button>
          </div>

          <p class="muted" style="margin-top:10px;">Security: updates are scoped to your staff_id server-side (no URL/ID tampering).</p>
        </form>
      </div>
    </section>
  </main>
</div>
</body>
</html>
