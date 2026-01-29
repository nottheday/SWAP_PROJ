<?php
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
session_start();

/* --- URL tampering handling (safe UX) --- */
if (isset($_GET['role'])) {
    $requestedRole = strtolower((string)$_GET['role']);
    $sessionRole   = strtolower((string)($_SESSION['role'] ?? ''));
    if ($requestedRole !== $sessionRole) { http_response_code(403); exit("Forbidden: role tampering detected."); }
    unset($_GET['role']);
}
if (isset($_GET['id']) || isset($_GET['staff_id']) || isset($_GET['employee_id'])) {
    http_response_code(403); exit("Forbidden: parameter tampering detected.");
}

/* --- Auth + RBAC --- */
if (!isset($_SESSION['auth'], $_SESSION['user'], $_SESSION['role'])) { header("Location: login.php"); exit; }
if ($_SESSION['role'] !== 'staff') { http_response_code(403); exit("Access Denied: staff only."); }

$username = $_SESSION['user'];
$role = $_SESSION['role'];

/* --- DB --- */
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

function resolveStaff(mysqli $mysqli, string $username): array {
    $staff_id = 0; $staff_name = $username; $dept_id = null;

    $has_users_staff_id = columnExists($mysqli, 'users', 'staff_id');
    if ($has_users_staff_id) {
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

    return ['staff_id'=>$staff_id ?: 0, 'staff_name'=>$staff_name, 'department_id'=>$dept_id];
}

function getStaffGender(mysqli $mysqli, int $staff_id): string {
    $genderCol = null;
    if (columnExists($mysqli, 'staff', 'gender')) $genderCol = 'gender';
    else if (columnExists($mysqli, 'staff', 'staff_gender')) $genderCol = 'staff_gender';

    if (!$genderCol) return 'male';

    $sql = "SELECT {$genderCol} FROM staff WHERE id=? LIMIT 1";
    $st = $mysqli->prepare($sql);
    if (!$st) return 'male';
    $st->bind_param("i", $staff_id);
    $st->execute();
    $st->bind_result($g);
    $st->fetch();
    $st->close();

    $g = strtolower(trim((string)$g));
    if ($g === 'f' || $g === 'female') return 'female';
    return 'male';
}

function daysInclusive(string $start, string $end): int {
    $s = DateTime::createFromFormat('Y-m-d', $start);
    $e = DateTime::createFromFormat('Y-m-d', $end);
    if (!$s || !$e) return 0;
    $diff = $s->diff($e);
    return (int)$diff->days + 1;
}

function quotaFor(string $gender, string $leaveNameLower): int {
    $isAnnual = str_contains($leaveNameLower, 'annual');
    $isMedical = str_contains($leaveNameLower, 'medical') || $leaveNameLower === 'mc' || str_contains($leaveNameLower, 'mc');
    $isMaternity = str_contains($leaveNameLower, 'maternity');

    if ($isAnnual) return 14;
    if ($isMedical) return 10;
    if ($isMaternity) return ($gender === 'female') ? 60 : 0;
    return 0;
}

function requireUploadFor(string $leaveNameLower): bool {
    return (str_contains($leaveNameLower, 'medical') || str_contains($leaveNameLower, 'maternity') || $leaveNameLower === 'mc' || str_contains($leaveNameLower, 'mc'));
}

function blockUploadFor(string $leaveNameLower): bool {
    return str_contains($leaveNameLower, 'annual');
}

/**
 * SECURE upload: ONLY JPEG/PNG allowed. Deny everything else.
 * - checks PHP upload error
 * - checks file size
 * - blocks dangerous name patterns
 * - verifies REAL MIME with finfo
 * - only allows image/jpeg or image/png
 * - generates random filename
 */
function saveUploadImagesOnly(string $fieldName, string $dirRelative = 'uploads/certs', int $maxBytes = 2097152): array {
    // returns [ok(bool), filename|null, error|null]
    if (empty($_FILES[$fieldName]) || empty($_FILES[$fieldName]['name'])) {
        return [true, null, null];
    }

    $f = $_FILES[$fieldName];

    if (!is_uploaded_file($f['tmp_name'])) {
        return [false, null, "Invalid upload attempt."];
    }

    if ($f['error'] !== UPLOAD_ERR_OK) {
        return [false, null, "File upload failed. Please try again."];
    }

    if ((int)$f['size'] > $maxBytes) {
        return [false, null, "File too large. Max 2MB allowed."];
    }

    $original = (string)$f['name'];
    $lower = strtolower($original);

    // Hard block common webshell/double-extension tricks
    $blocked = ['.php', '.phtml', '.php3', '.php4', '.phar', '.cgi', '.pl', '.asp', '.aspx', '.jsp', '.js', '.html', '.htm', '.svg'];
    foreach ($blocked as $bad) {
        if (str_contains($lower, $bad)) {
            return [false, null, "Invalid file type."];
        }
    }

    // Extension allowlist (only for naming; REAL check is MIME below)
    $ext = strtolower(pathinfo($original, PATHINFO_EXTENSION));
    $allowedExt = ['jpg','jpeg','png'];
    if (!in_array($ext, $allowedExt, true)) {
        return [false, null, "Only JPEG/PNG files are allowed."];
    }

    // Verify real MIME type
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->file($f['tmp_name']);

    $mimeToExt = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
    ];

    if (!isset($mimeToExt[$mime])) {
        return [false, null, "Only JPEG/PNG files are allowed."];
    }

    $uploadDir = __DIR__ . "/" . $dirRelative . "/";
    if (!is_dir($uploadDir)) {
        if (!mkdir($uploadDir, 0755, true)) {
            return [false, null, "Server storage error."];
        }
    }

    // Safe base name (display only; stored name is random)
    $base = preg_replace('/[^a-zA-Z0-9_-]/', '_', pathinfo($original, PATHINFO_FILENAME));

    // Use MIME-derived extension to prevent spoofing (.png but actually jpeg)
    $safeExt = $mimeToExt[$mime];
    $filename = $base . "_" . time() . "_" . bin2hex(random_bytes(8)) . "." . $safeExt;

    $dest = $uploadDir . $filename;

    if (!move_uploaded_file($f['tmp_name'], $dest)) {
        return [false, null, "Could not save uploaded file."];
    }

    @chmod($dest, 0640);
    return [true, $filename, null];
}

$staff = resolveStaff($mysqli, $username);
$staff_id = (int)$staff['staff_id'];
$staff_name = (string)$staff['staff_name'];

if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

/* --- Load leave types --- */
$leave_types = [];
$res = $mysqli->query("SELECT id, name FROM leave_type ORDER BY name");
if ($res) while ($row = $res->fetch_assoc()) $leave_types[] = $row;

$success = '';
$error = '';
$today = date('Y-m-d');

/* --- Submit leave (POST) --- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token'], $csrf)) { http_response_code(403); exit("CSRF blocked."); }

    if ($staff_id <= 0) { $error = "Staff record not found. Link users -> staff first."; }
    else {
        $leave_type_id = filter_input(INPUT_POST, 'leave_type_id', FILTER_VALIDATE_INT);
        $start_date = (string)($_POST['start_date'] ?? '');
        $end_date   = (string)($_POST['end_date'] ?? '');
        $reason     = trim((string)($_POST['reason'] ?? ''));

        if (!$leave_type_id || $leave_type_id <= 0) $error = "Please choose a leave type.";
        elseif (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $start_date) || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $end_date)) $error = "Invalid date format.";
        elseif ($start_date < $today) $error = "Start date cannot be before today.";
        elseif ($end_date < $start_date) $error = "End date cannot be before start date.";
        else {
            // get leave type name
            $ltName = '';
            $stLT = $mysqli->prepare("SELECT name FROM leave_type WHERE id=? LIMIT 1");
            if ($stLT) {
                $stLT->bind_param("i", $leave_type_id);
                $stLT->execute();
                $stLT->bind_result($ltName);
                $stLT->fetch();
                $stLT->close();
            }
            $ltLower = strtolower(trim((string)$ltName));

            $daysReq = daysInclusive($start_date, $end_date);
            if ($daysReq <= 0) $error = "Invalid duration selected.";
            else {
                $gender = getStaffGender($mysqli, $staff_id);

                $needsUpload  = requireUploadFor($ltLower);
                $blocksUpload = blockUploadFor($ltLower);

                // Annual: deny upload
                if ($blocksUpload && !empty($_FILES['supporting_doc']['name'])) {
                    $error = "Annual Leave does not allow uploading supporting documents.";
                }

                // Medical/Maternity: require upload
                if (!$error && $needsUpload && empty($_FILES['supporting_doc']['name'])) {
                    $error = "Supporting document is required for Medical/Maternity leave (JPEG/PNG only).";
                }

                // Save upload if needed/allowed
                $uploadedFile = null;
                if (
                    !$error &&
                    ($needsUpload || (!empty($_FILES['supporting_doc']['name']) && !$blocksUpload))
                ) {
                    [$okUp, $fn, $upErr] = saveUploadImagesOnly('supporting_doc');
                    if (!$okUp) $error = $upErr;
                    else $uploadedFile = $fn;
                }

                if (!$error) {
                    $defaultQuota = quotaFor($gender, $ltLower);
                    if ($defaultQuota === 0 && str_contains($ltLower, 'maternity')) {
                        $error = "Maternity leave is not available for this staff profile.";
                    }
                }

                if (!$error) {
                    $mysqli->begin_transaction();

                    try {
                        $bal = null;
                        $stB = $mysqli->prepare("SELECT balance FROM leave_balance WHERE staff_id=? AND leave_type_id=? LIMIT 1");
                        $stB->bind_param("ii", $staff_id, $leave_type_id);
                        $stB->execute();
                        $stB->bind_result($balVal);
                        if ($stB->fetch()) $bal = (int)$balVal;
                        $stB->close();

                        if ($bal === null) {
                            $gender = getStaffGender($mysqli, $staff_id);
                            $ltLower = strtolower(trim((string)$ltName));
                            $init = quotaFor($gender, $ltLower);

                            $stI = $mysqli->prepare("INSERT INTO leave_balance (staff_id, leave_type_id, balance) VALUES (?, ?, ?)");
                            $stI->bind_param("iii", $staff_id, $leave_type_id, $init);
                            $stI->execute();
                            $stI->close();

                            $bal = $init;
                        }

                        if ($daysReq > $bal) {
                            throw new Exception("Insufficient leave balance. You requested {$daysReq} day(s) but have {$bal} day(s) left.");
                        }

                        $has_reason = columnExists($mysqli, 'leave_application', 'reason');
                        $has_doccol = columnExists($mysqli, 'leave_application', 'supporting_doc');

                        if ($has_reason && $has_doccol) {
                            $st = $mysqli->prepare("INSERT INTO leave_application (staff_id, leave_type_id, start_date, end_date, status, reason, supporting_doc)
                                                    VALUES (?, ?, ?, ?, 'pending', ?, ?)");
                            $st->bind_param("iissss", $staff_id, $leave_type_id, $start_date, $end_date, $reason, $uploadedFile);
                        } elseif ($has_reason) {
                            $st = $mysqli->prepare("INSERT INTO leave_application (staff_id, leave_type_id, start_date, end_date, status, reason)
                                                    VALUES (?, ?, ?, ?, 'pending', ?)");
                            $st->bind_param("iisss", $staff_id, $leave_type_id, $start_date, $end_date, $reason);
                        } else {
                            $st = $mysqli->prepare("INSERT INTO leave_application (staff_id, leave_type_id, start_date, end_date, status)
                                                    VALUES (?, ?, ?, ?, 'pending')");
                            $st->bind_param("iiss", $staff_id, $leave_type_id, $start_date, $end_date);
                        }

                        if (!$st || !$st->execute()) {
                            throw new Exception("Failed to submit leave request.");
                        }
                        $st->close();

                        $newBal = $bal - $daysReq;
                        $stU = $mysqli->prepare("UPDATE leave_balance SET balance=? WHERE staff_id=? AND leave_type_id=?");
                        $stU->bind_param("iii", $newBal, $staff_id, $leave_type_id);
                        $stU->execute();
                        $stU->close();

                        $mysqli->commit();
                        $success = "Leave request submitted. Duration: {$daysReq} day(s). Remaining balance: {$newBal} day(s).";
                    } catch (Throwable $e) {
                        $mysqli->rollback();
                        $error = $e->getMessage();
                    }
                }
            }
        }
    }
}

/* --- Logout --- */
if (isset($_GET['logout'])) {
    session_unset(); session_destroy();
    header("Location: login.php"); exit;
}
$mysqli->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AMC HR - Apply Leave</title>
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
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
    label{font-size:13px;font-weight:700;color:#93c5fd;text-transform:uppercase;letter-spacing:.5px}
    input,select,textarea{
      width:100%;margin-top:8px;padding:12px 14px;background:rgba(30,41,59,.6);
      border:1px solid rgba(71,85,105,.4);border-radius:10px;color:#e2e8f0;outline:none
    }
    textarea{min-height:110px;resize:vertical}
    .actions{margin-top:14px;display:flex;gap:10px;flex-wrap:wrap}
    button{
      padding:10px 16px;border-radius:10px;border:1px solid rgba(59,130,246,.45);
      background:rgba(59,130,246,.2);color:#93c5fd;font-weight:800;cursor:pointer;transition:.2s
    }
    button:hover{background:rgba(59,130,246,.28)}
    .muted{color:#94a3b8;font-size:13px;margin-top:10px}
    .hint{display:block;margin-top:6px;font-size:12px;color:#94a3b8}
    @media(max-width:1024px){.sidebar{width:240px}.main-content{margin-left:240px;padding:24px 32px}}
    @media(max-width:768px){.sidebar{width:100%;position:relative;height:auto;border-right:none;border-bottom:1px solid rgba(71,85,105,.3)}.main-content{margin-left:0;padding:20px}.container{flex-direction:column}.header{flex-direction:column;align-items:flex-start}.header-actions{width:100%;justify-content:space-between}}
  </style>
</head>
<body>
<div class="container">
  <aside class="sidebar">
    <div class="logo">
      <h1>AMC HR</h1>
      <span class="role-badge">Staff</span>
    </div>
    <nav>
      <ul class="nav-menu">
        <li class="nav-item"><a href="staff-dashboard.php" class="nav-link"><span class="nav-icon">🏠</span><span>Dashboard</span></a></li>
        <li class="nav-item"><a href="staff-apply_leave.php" class="nav-link active"><span class="nav-icon">📝</span><span>Apply Leave</span></a></li>
        <li class="nav-item"><a href="staff-my_leave.php" class="nav-link"><span class="nav-icon">📅</span><span>My Leave</span></a></li>
        <li class="nav-item"><a href="staff-training.php" class="nav-link"><span class="nav-icon">🎓</span><span>My Training</span></a></li>
        <li class="nav-item"><a href="staff-profile.php" class="nav-link"><span class="nav-icon">👤</span><span>My Profile</span></a></li>
      </ul>
    </nav>
  </aside>

  <main class="main-content">
    <header class="header">
      <div class="welcome-section">
        <h2>Apply Leave</h2>
        <p>Submit a new leave request (your own only)</p>
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
      <div class="panel-head"><div class="panel-title">Leave Request Form</div></div>
      <div class="panel-body">
        <form method="POST" enctype="multipart/form-data">
          <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

          <div class="grid">
            <div>
              <label>Leave Type</label>
              <select name="leave_type_id" id="leave_type_id" required>
                <option value="">Select leave type</option>
                <?php foreach ($leave_types as $lt): ?>
                  <option value="<?php echo (int)$lt['id']; ?>"><?php echo htmlspecialchars($lt['name']); ?></option>
                <?php endforeach; ?>
              </select>
              <span class="hint">Annual: no upload. Medical/Maternity: upload required (JPEG/PNG only).</span>
            </div>

            <div>
              <label>Start Date</label>
              <input type="date" name="start_date" id="start_date" min="<?php echo htmlspecialchars($today); ?>" required>
              <span class="hint">Cannot select dates before today.</span>
            </div>

            <div>
              <label>End Date</label>
              <input type="date" name="end_date" id="end_date" min="<?php echo htmlspecialchars($today); ?>" required>
            </div>

            <div>
              <label>Upload Cert (Medical/Maternity)</label>
              <input type="file" name="supporting_doc" id="supporting_doc" accept=".jpg,.jpeg,.png">
              <span class="hint" id="upload_hint">Upload required only for Medical/Maternity (JPEG/PNG only).</span>
            </div>
          </div>

          <div style="margin-top:14px;">
            <label>Reason (optional)</label>
            <textarea name="reason" placeholder="E.g., medical appointment, family matters..."></textarea>
            <div class="muted">
              Security: request is tied to your session + staff_id server-side (no URL/id tampering).
            </div>
          </div>

          <div class="actions">
            <button type="submit">Submit Request</button>
          </div>
        </form>
      </div>
    </section>
  </main>
</div>

<script>
(function(){
  const leaveSelect = document.getElementById('leave_type_id');
  const upload = document.getElementById('supporting_doc');
  const hint = document.getElementById('upload_hint');

  const start = document.getElementById('start_date');
  const end = document.getElementById('end_date');

  function normalize(s){ return (s || '').toLowerCase(); }

  function isAnnual(name){
    return normalize(name).includes('annual');
  }
  function isMedicalOrMaternity(name){
    const n = normalize(name);
    return n.includes('medical') || n.includes('maternity') || n === 'mc' || n.includes('mc');
  }

  function onLeaveChange(){
    const selectedText = leaveSelect.options[leaveSelect.selectedIndex]?.text || '';
    if (isAnnual(selectedText)) {
      upload.disabled = true;
      upload.value = "";
      upload.required = false;
      hint.textContent = "Annual Leave: upload is blocked.";
    } else if (isMedicalOrMaternity(selectedText)) {
      upload.disabled = false;
      upload.required = true;
      hint.textContent = "Medical/Maternity: upload is required (JPEG/PNG only).";
    } else {
      upload.disabled = false;
      upload.required = false;
      hint.textContent = "Upload optional (if applicable). JPEG/PNG only.";
    }
  }

  function onStartChange(){
    if (start.value) {
      end.min = start.value;
      if (end.value && end.value < start.value) end.value = start.value;
    }
  }

  leaveSelect.addEventListener('change', onLeaveChange);
  start.addEventListener('change', onStartChange);

  onLeaveChange();
  onStartChange();
})();
</script>
</body>
</html>
