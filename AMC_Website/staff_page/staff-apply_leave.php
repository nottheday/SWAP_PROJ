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

/* =========================
   SQLi detection (GET/POST)
   ========================= */
detect_sql_injection($_GET);
detect_sql_injection($_POST);

/* ===============================
   ✅ URL Tampering Popup (APPLY LEAVE)
   Requirements:
   1) If ?role=staff/admin/supervisor (ANY role param) => popup + clean reload
   2) If any ID-like param present => popup + clean reload
   3) If ANY unexpected query string keys appear (URL edited) => popup + clean reload
   4) If someone tries to load this script under a different filename/path
      => popup + redirect back to the correct staff-apply_leave.php clean URL
   Notes:
   - We allow only: logout (GET) for this page.
================================ */
$EXPECTED_FILE = 'staff-apply_leave.php';

function staffapply_clean_url(array $removeKeys = ['role','id','staff_id','employee_id','user_id']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);

    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function staffapply_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) {
        $_SESSION['flash_unauth'] = 1;
    }

    $clean = staffapply_clean_url();

    if ($forcePath !== null) {
        $qPos = strpos($clean, '?');
        $qs   = ($qPos !== false) ? substr($clean, $qPos) : '';
        header("Location: " . $forcePath . $qs);
        exit;
    }

    header("Location: " . $clean);
    exit;
}

/* ===============================
   Auth first (so role is reliable)
================================ */
if (!isset($_SESSION['auth'], $_SESSION['user'], $_SESSION['role'])) {
    header('Location: /AMC_Website/login_page/login.php');
    exit;
}

/* ===============================
   Force correct filename if URL is edited to another file name
   (e.g. staff-apply_leave.php changed to admin-dashboard.php in URL)
================================ */
$currentFile = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '');
if ($currentFile !== '' && strtolower($currentFile) !== strtolower($EXPECTED_FILE)) {
    staffapply_redirect_clean(true, $EXPECTED_FILE);
}

/* ===============================
   Detect ANY unexpected query keys (URL edited)
   Allowed keys for this page: logout only
================================ */
$allowedKeys = ['logout'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        staffapply_redirect_clean(true);
    }
}

/* ===============================
   Explicit tamper triggers (kept for clarity)
================================ */
if (isset($_GET['role'])) {
    // ANY role param triggers popup (even if it matches)
    staffapply_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['staff_id']) || isset($_GET['employee_id']) || isset($_GET['user_id'])) {
    staffapply_redirect_clean(true);
}

/* ========= RBAC: staff only ========= */
$currentRole = strtolower((string)$_SESSION['role']);
if ($currentRole !== 'staff') {
    http_response_code(403);
    exit('Access Denied.');
}

$username = (string)$_SESSION['user'];
$role     = (string)$_SESSION['role'];

/* ========= DB ========= */
$mysqli = new mysqli('localhost', 'root', '', 'swap');
if ($mysqli->connect_error) die('DB connection failed: ' . $mysqli->connect_error);
$mysqli->set_charset('utf8mb4');

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

function resolveStaff(mysqli $mysqli, string $username): array {
    $staff_id = 0; $staff_name = $username; $dept_id = null;

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

    return ['staff_id' => $staff_id ?: 0, 'staff_name' => $staff_name, 'department_id' => $dept_id];
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
    $isAnnual    = str_contains($leaveNameLower, 'annual');
    $isMedical   = str_contains($leaveNameLower, 'medical') || $leaveNameLower === 'mc' || str_contains($leaveNameLower, 'mc');
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

function saveUploadImagesOnly(string $fieldName, string $dirRelative = '../uploads/certs', int $maxBytes = 2097152): array {
    if (empty($_FILES[$fieldName]) || empty($_FILES[$fieldName]['name'])) {
        return [true, null, null];
    }

    $f = $_FILES[$fieldName];

    if (!is_uploaded_file($f['tmp_name'])) return [false, null, "Invalid upload attempt."];
    if ($f['error'] !== UPLOAD_ERR_OK) return [false, null, "File upload failed. Please try again."];
    if ((int)$f['size'] > $maxBytes) return [false, null, "File too large. Max 2MB allowed."];

    $original = (string)$f['name'];
    $lower = strtolower($original);

    $blocked = ['.php', '.phtml', '.php3', '.php4', '.phar', '.cgi', '.pl', '.asp', '.aspx', '.jsp', '.js', '.html', '.htm', '.svg'];
    foreach ($blocked as $bad) {
        if (str_contains($lower, $bad)) return [false, null, "Invalid file type."];
    }

    $ext = strtolower(pathinfo($original, PATHINFO_EXTENSION));
    $allowedExt = ['jpg','jpeg','png'];
    if (!in_array($ext, $allowedExt, true)) return [false, null, "Only JPEG/PNG files are allowed."];

    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->file($f['tmp_name']);

    $mimeToExt = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
    ];
    if (!isset($mimeToExt[$mime])) return [false, null, "Only JPEG/PNG files are allowed."];

    $uploadDir = __DIR__ . "/" . $dirRelative . "/";
    if (!is_dir($uploadDir) && !mkdir($uploadDir, 0755, true)) return [false, null, "Server storage error."];

    $base = preg_replace('/[^a-zA-Z0-9_-]/', '_', pathinfo($original, PATHINFO_FILENAME));
    $safeExt = $mimeToExt[$mime];
    $filename = $base . "_" . time() . "_" . bin2hex(random_bytes(8)) . "." . $safeExt;

    $dest = $uploadDir . $filename;
    if (!move_uploaded_file($f['tmp_name'], $dest)) return [false, null, "Could not save uploaded file."];

    @chmod($dest, 0640);
    return [true, $filename, null];
}

function saveUploadImagesOnlyHardened(string $fieldName, string $dirRelative = '../uploads/certs'): array {

    [$ok, $filename, $error] = saveUploadImagesOnly($fieldName, $dirRelative);

    if (!$ok || !$filename) {
        return [$ok, $filename, $error];
    }

    $fullPath = __DIR__ . "/" . $dirRelative . "/" . $filename;

    $fh = fopen($fullPath, 'rb');
    $magic = fread($fh, 8);
    fclose($fh);

    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

    $signatures = [
        'jpg' => ["\xFF\xD8\xFF"],
        'jpeg'=> ["\xFF\xD8\xFF"],
        'png' => ["\x89PNG\x0D\x0A\x1A\x0A"]
    ];

    $valid = false;
    foreach ($signatures[$ext] ?? [] as $sig) {
        if (str_starts_with($magic, $sig)) {
            $valid = true;
            break;
        }
    }

    if (!$valid) {
        @unlink($fullPath);
        return [false, null, "Invalid image signature."];
    }

    $info = @getimagesize($fullPath);
    if ($info === false) {
        @unlink($fullPath);
        return [false, null, "Invalid or corrupted image."];
    }

    [$width, $height, $type] = $info;

    if (!in_array($type, [IMAGETYPE_JPEG, IMAGETYPE_PNG], true)) {
        @unlink($fullPath);
        return [false, null, "Unsupported image type."];
    }

    if ($width > 6000 || $height > 6000) {
        @unlink($fullPath);
        return [false, null, "Image dimensions too large."];
    }

    @chmod($fullPath, 0640);

    return [true, $filename, null];
}

/* ========= Load staff + CSRF ========= */
$staff = resolveStaff($mysqli, $username);
$staff_id   = (int)$staff['staff_id'];

// Stored XSS prevention (HTML encode on output)
$staff_name = htmlspecialchars((string)$staff['staff_name'], ENT_QUOTES, 'UTF-8');

$gender = getStaffGender($mysqli, $staff_id);

if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

/* ========= Load leave types ========= */
$leave_types = [];
$res = $mysqli->query("SELECT id, name FROM leave_type ORDER BY name");
if ($res) {
    while ($row = $res->fetch_assoc()) {
        $nameLower = strtolower(trim((string)$row['name']));
        if ($gender === 'male' && str_contains($nameLower, 'maternity')) continue;
        $row['name'] = htmlspecialchars((string)$row['name'], ENT_QUOTES, 'UTF-8'); // Stored XSS
        $leave_types[] = $row;
    }
}

$success = '';
$error   = '';
$today   = date('Y-m-d');

/* ========= Submit leave ========= */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token'], $csrf)) { http_response_code(403); exit("CSRF blocked."); }

    if ($staff_id <= 0) {
        $error = "Staff record not found. Link users -> staff first.";
    } else {
        $leave_type_id = filter_input(INPUT_POST, 'leave_type_id', FILTER_VALIDATE_INT);
        $start_date    = (string)($_POST['start_date'] ?? '');
        $end_date      = (string)($_POST['end_date'] ?? '');
        $reason        = trim((string)($_POST['reason'] ?? ''));

        $reason = htmlspecialchars($reason, ENT_QUOTES, 'UTF-8'); // Stored XSS

        if (!$leave_type_id || $leave_type_id <= 0) $error = "Please choose a leave type.";
        elseif (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $start_date) || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $end_date)) $error = "Invalid date format.";
        elseif ($start_date < $today) $error = "Start date cannot be before today.";
        elseif ($end_date < $start_date) $error = "End date cannot be before start date.";
        else {
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
                $needsUpload  = requireUploadFor($ltLower);
                $blocksUpload = blockUploadFor($ltLower);

                if ($blocksUpload && !empty($_FILES['supporting_doc']['name'])) {
                    $error = "Annual Leave does not allow uploading supporting documents.";
                }
                if (!$error && $needsUpload && empty($_FILES['supporting_doc']['name'])) {
                    $error = "Supporting document is required for Medical/Maternity/MC leave (JPEG/PNG only).";
                }

                $uploadedFile = null;
                if (!$error && ($needsUpload || (!empty($_FILES['supporting_doc']['name']) && !$blocksUpload))) {
                    [$okUp, $fn, $upErr] = saveUploadImagesOnlyHardened('supporting_doc', '../uploads/certs');
                    if (!$okUp) $error = (string)$upErr;
                    else $uploadedFile = htmlspecialchars((string)$fn, ENT_QUOTES, 'UTF-8'); // Stored XSS
                }

                if (!$error) {
                    $mysqli->begin_transaction();
                    try {
                        $bal = null;

                        $stB = $mysqli->prepare("SELECT balance FROM leave_balance WHERE staff_id=? AND leave_type_id=? LIMIT 1");
                        if (!$stB) throw new Exception("Balance query failed.");
                        $stB->bind_param("ii", $staff_id, $leave_type_id);
                        $stB->execute();
                        $stB->bind_result($balVal);
                        if ($stB->fetch()) $bal = (int)$balVal;
                        $stB->close();

                        if ($bal === null) {
                            $init = quotaFor($gender, $ltLower);
                            $stI = $mysqli->prepare("INSERT INTO leave_balance (staff_id, leave_type_id, balance) VALUES (?, ?, ?)");
                            if (!$stI) throw new Exception("Balance init failed.");
                            $stI->bind_param("iii", $staff_id, $leave_type_id, $init);
                            $stI->execute();
                            $stI->close();
                            $bal = $init;
                        }

                        if ($daysReq > $bal) throw new Exception("Insufficient leave balance. You requested {$daysReq} day(s) but have {$bal} day(s) left.");

                        $has_reason = columnExists($mysqli, 'leave_application', 'reason');
                        $has_doccol = columnExists($mysqli, 'leave_application', 'supporting_doc');

                        if ($has_reason && $has_doccol) {
                            $st = $mysqli->prepare("INSERT INTO leave_application (staff_id, leave_type_id, start_date, end_date, status, reason, supporting_doc)
                                                    VALUES (?, ?, ?, ?, 'pending', ?, ?)");
                            if (!$st) throw new Exception("Insert failed.");
                            $st->bind_param("iissss", $staff_id, $leave_type_id, $start_date, $end_date, $reason, $uploadedFile);
                        } elseif ($has_reason) {
                            $st = $mysqli->prepare("INSERT INTO leave_application (staff_id, leave_type_id, start_date, end_date, status, reason)
                                                    VALUES (?, ?, ?, ?, 'pending', ?)");
                            if (!$st) throw new Exception("Insert failed.");
                            $st->bind_param("iisss", $staff_id, $leave_type_id, $start_date, $end_date, $reason);
                        } else {
                            $st = $mysqli->prepare("INSERT INTO leave_application (staff_id, leave_type_id, start_date, end_date, status)
                                                    VALUES (?, ?, ?, ?, 'pending')");
                            if (!$st) throw new Exception("Insert failed.");
                            $st->bind_param("iiss", $staff_id, $leave_type_id, $start_date, $end_date);
                        }

                        if (!$st->execute()) throw new Exception("Failed to submit leave request.");
                        $st->close();

                        $newBal = $bal - $daysReq;
                        $stU = $mysqli->prepare("UPDATE leave_balance SET balance=? WHERE staff_id=? AND leave_type_id=?");
                        if (!$stU) throw new Exception("Balance update failed.");
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

/* ========= Logout ========= */
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header('Location: /AMC_Website/login.php');
    exit;
}

$mysqli->close();

/* ========= One-time modal flag ========= */
$showUnauth = !empty($_SESSION['flash_unauth']);
if ($showUnauth) unset($_SESSION['flash_unauth']);
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
      width:100%;margin-top:8px;padding:12px 14px;background:white;
      border:1px solid rgba(71,85,105,.4);border-radius:10px;color:black;outline:none
    }
    textarea{min-height:110px;resize:vertical}
    .actions{margin-top:14px;display:flex;gap:10px;flex-wrap:wrap}
    button{
      padding:10px 16px;border-radius:10px;border:1px solid rgba(59,130,246,.45);
      background:rgba(59,130,246,.2);color:#93c5fd;font-weight:800;cursor:pointer;transition:.2s
    }
    button:hover{background:rgba(59,130,246,.28)}
    .hint{display:block;margin-top:6px;font-size:12px;color:#94a3b8}

    /* ===== Popup modal ===== */
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

<!-- ===== Modal Popup (shows after tampering) ===== -->
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
        <li class="nav-item"><a href="staff-certification.php" class="nav-link"><span class="nav-icon">📄</span><span>My Certifications</span></a></li>
        <li class="nav-item"><a href="staff-profile.php" class="nav-link"><span class="nav-icon">👤</span><span>My Profile</span></a></li>
      </ul>
    </nav>
  </aside>

  <main class="main-content">
    <header class="header">
      <div class="welcome-section">
        <h2>Apply Leave</h2>
        <p>Submit a new leave request</p>
      </div>
      <div class="header-actions">
        <div class="user-info">
          <span><strong><?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></strong></span>
          <span style="text-transform: capitalize;"><?php echo htmlspecialchars($role, ENT_QUOTES, 'UTF-8'); ?></span>
        </div>
        <a class="logout-btn" href="?logout=1">Logout</a>
      </div>
    </header>

    <?php if ($success): ?><div class="msg-ok"><?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></div><?php endif; ?>
    <?php if ($error): ?><div class="msg-err"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div><?php endif; ?>

    <section class="panel">
      <div class="panel-head"><div class="panel-title">Leave Request Form</div></div>
      <div class="panel-body">
        <form method="POST" enctype="multipart/form-data">
          <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars((string)$_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">

          <div class="grid">
            <div>
              <label>Leave Type</label>
              <select name="leave_type_id" id="leave_type_id" required>
                <option value="">Select leave type</option>
                <?php foreach ($leave_types as $lt): ?>
                  <option value="<?php echo (int)$lt['id']; ?>"><?php echo $lt['name']; ?></option>
                <?php endforeach; ?>
              </select>
              <span class="hint">Annual: upload blocked.</span>
              <span class="hint">Medical/Maternity/MC: upload required. Others: optional.</span>
            </div>

            <div>
              <label>Start Date</label>
              <input type="date" name="start_date" id="start_date" min="<?php echo htmlspecialchars($today, ENT_QUOTES, 'UTF-8'); ?>" required>
              <span class="hint">Cannot select dates before today.</span>
            </div>

            <div>
              <label>End Date</label>
              <input type="date" name="end_date" id="end_date" min="<?php echo htmlspecialchars($today, ENT_QUOTES, 'UTF-8'); ?>" required>
            </div>

            <div>
              <label>Upload Document</label>
              <input type="file" name="supporting_doc" id="supporting_doc" accept=".jpg,.jpeg,.png">
              <span class="hint" id="upload_hint">Select a leave type to see upload requirement.</span>
            </div>
          </div>

          <div style="margin-top:14px;">
            <label>Reason (optional)</label>
            <textarea name="reason" placeholder="E.g., medical appointment, family matters..."></textarea>
          </div>

          <div class="actions">
            <button type="submit">Submit Request</button>
          </div>

          <p class="hint" style="margin-top:10px;">
            Security: requests are scoped to your staff_id server-side (no URL/ID tampering).
          </p>
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
  function isAnnual(name){ return normalize(name).includes('annual'); }
  function isMedicalOrMaternityOrMC(name){
    const n = normalize(name);
    return n.includes('medical') || n.includes('maternity') || n === 'mc' || n.includes('mc');
  }

  function onLeaveChange(){
    const selectedText = leaveSelect.options[leaveSelect.selectedIndex]?.text || '';

    if (!selectedText) {
      upload.disabled = false;
      upload.required = false;
      hint.textContent = "Select a leave type to see upload requirement.";
      return;
    }

    if (isAnnual(selectedText)) {
      upload.disabled = true;
      upload.value = "";
      upload.required = false;
      hint.textContent = "Annual Leave: Upload is blocked.";
    } else if (isMedicalOrMaternityOrMC(selectedText)) {
      upload.disabled = false;
      upload.required = true;
      hint.textContent = "Upload is REQUIRED (JPEG/PNG only). Max: 2MB";
    } else {
      upload.disabled = false;
      upload.required = true;
      hint.textContent = "Upload is REQUIRED (JPEG/PNG only). Max: 2MB";
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

  // DOM XSS prevention: use textContent only (no innerHTML)
})();
</script>

</body>
</html>
