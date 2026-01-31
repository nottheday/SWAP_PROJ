<?php
require_once __DIR__ . '/../misc_security/secure-transport.php';
require_once __DIR__ . '/../misc_security/session-hardening.php';
require_once __DIR__ . '/../misc_security/sql-prevention.php';
/* =========================
   DB + helper
========================= */
$mysqli = new mysqli("localhost", "root", "", "swap");
if ($mysqli->connect_error) die("DB connection failed: " . $mysqli->connect_error);

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

/* =========================
   Auth + RBAC
========================= */
if (!isset($_SESSION['auth'], $_SESSION['user'], $_SESSION['role'])) {
    header("Location: /AMC_Website/login_page/login.php");
    exit;
}
if ($_SESSION['role'] !== 'staff') {
    http_response_code(403);
    exit("Access Denied: staff only.");
}

$username = (string)$_SESSION['user'];
$role     = (string)$_SESSION['role'];

/* =========================
   URL/Role tampering handler
   - Reload same page + flash modal
========================= */
function reloadWithUnauthPopup(): void {
    $_SESSION['flash_unauth'] = 1;
    $clean = strtok($_SERVER['REQUEST_URI'], '?');
    header("Location: " . $clean);
    exit;
}

// Role tampering
if (isset($_GET['role'])) {
    $requestedRole = strtolower((string)$_GET['role']);
    $sessionRole   = strtolower((string)($_SESSION['role'] ?? ''));
    if ($requestedRole !== $sessionRole) reloadWithUnauthPopup();
    reloadWithUnauthPopup(); // even if same, strip query
}

// ID tampering
if (isset($_GET['id']) || isset($_GET['staff_id']) || isset($_GET['employee_id'])) {
    reloadWithUnauthPopup();
}

/* =========================
   CSRF token (for POST forms)
========================= */
if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

/* =========================
   Sidebar active page helper
========================= */
$currentPage = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
function navActive(string $file, string $currentPage): string {
    return $file === $currentPage ? ' active' : '';
}

/* =========================
   Resolve staff_id
========================= */
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
            $nm = '';
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

/* =========================
   Ensure cert_file exists
========================= */
$has_cert_file = columnExists($mysqli, 'staff_certification', 'cert_file');
if (!$has_cert_file) {
    try { $mysqli->query("ALTER TABLE staff_certification ADD COLUMN cert_file VARCHAR(255) NULL"); } catch (Throwable $e) {}
    $has_cert_file = columnExists($mysqli, 'staff_certification', 'cert_file');
}

/* =========================
   File upload helper
   - JPEG/PNG only
========================= */
function saveUploadImagesOnly(string $fieldName, string $dirRelative = '../uploads/certifications', int $maxBytes = 2097152): array {
    if (empty($_FILES[$fieldName]) || empty($_FILES[$fieldName]['name'])) return [false, null, "Please choose a JPEG/PNG file to upload."];

    $f = $_FILES[$fieldName];
    if (!is_uploaded_file($f['tmp_name'])) return [false, null, "Invalid upload attempt."];
    if ($f['error'] !== UPLOAD_ERR_OK) return [false, null, "File upload failed."];
    if ((int)$f['size'] > $maxBytes) return [false, null, "File too large. Max 2MB."];

    $original = (string)$f['name'];
    $ext = strtolower(pathinfo($original, PATHINFO_EXTENSION));
    if (!in_array($ext, ['jpg','jpeg','png'], true)) return [false, null, "Only JPEG/PNG files are allowed."];

    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->file($f['tmp_name']);
    $mimeToExt = ['image/jpeg'=>'jpg','image/png'=>'png'];
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

/* =========================
   Handle POST (Upload) with PRG
   - Reflected XSS prevention: htmlspecialchars on flash messages
========================= */
$today = date('Y-m-d');
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token'], $csrf)) {
        $_SESSION['flash_error'] = "CSRF blocked.";
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }

    $error = '';
    $success = '';
    if ($staff_id <= 0) {
        $error = "Staff record not linked to this account.";
    } else {
        $cert_name   = trim((string)($_POST['cert_name'] ?? ''));
        $issue_date  = (string)($_POST['issue_date'] ?? '');
        $expiry_date = (string)($_POST['expiry_date'] ?? '');

        if ($cert_name === '') $error = "Certification name is required.";
        elseif (preg_match('/<\s*script\b/i', $cert_name)) $error = "Invalid characters in certification name."; // XSS input block
        elseif ($issue_date && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $issue_date)) $error = "Invalid issue date format.";
        elseif ($expiry_date && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $expiry_date)) $error = "Invalid expiry date format.";
        elseif ($issue_date && $expiry_date && $expiry_date < $issue_date) $error = "Expiry date cannot be before issue date.";
        else {
            [$okUp, $fn, $upErr] = saveUploadImagesOnly('cert_upload');
            if (!$okUp) $error = $upErr;

            if (!$error) {
                if ($has_cert_file) {
                    $st = $mysqli->prepare("INSERT INTO staff_certification (name, issue_date, expiry_date, staff_id, cert_file) VALUES (?, ?, ?, ?, ?)");
                    $st->bind_param("sssis", $cert_name, $issue_date, $expiry_date, $staff_id, $fn);
                } else {
                    $st = $mysqli->prepare("INSERT INTO staff_certification (name, issue_date, expiry_date, staff_id) VALUES (?, ?, ?, ?)");
                    $st->bind_param("sssi", $cert_name, $issue_date, $expiry_date, $staff_id);
                }
                if ($st && $st->execute()) {
                    $success = $has_cert_file ? "Certification uploaded successfully." : "Uploaded (DB missing cert_file column).";
                } else $error = "Failed to save certification record.";
                if ($st) $st->close();
            }
        }
    }

    $_SESSION['flash_success'] = $success; // Reflected XSS safe
    $_SESSION['flash_error']   = $error;   // Reflected XSS safe
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* =========================
   Flash messages (for PRG)
   - Reflected XSS safe: htmlspecialchars applied on output
========================= */
$success = $_SESSION['flash_success'] ?? '';
$error   = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash_success'], $_SESSION['flash_error']);

/* =========================
   Load certifications
   - Stored XSS prevention: htmlspecialchars applied when rendering table
========================= */
$myCerts = [];
if ($staff_id > 0) {
    $selectCols = "id, name, issue_date, expiry_date";
    if ($has_cert_file) $selectCols .= ", cert_file";

    $st = $mysqli->prepare("SELECT {$selectCols} FROM staff_certification WHERE staff_id=? ORDER BY id DESC LIMIT 200");
    if ($st) {
        $st->bind_param("i", $staff_id);
        $st->execute();
        $r = $st->get_result();
        while ($row = $r->fetch_assoc()) $myCerts[] = $row;
        $st->close();
    }
}

/* =========================
   Logout
========================= */
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
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AMC HR - My Certifications</title>
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
.panel{background:rgba(15,23,42,.6);border:1px solid rgba(71,85,105,.3);border-radius:12px;overflow:hidden;margin-bottom:16px}
.panel-head{padding:16px 18px;background:rgba(30,41,59,.8);border-bottom:1px solid rgba(71,85,105,.35)}
.panel-title{font-size:14px;font-weight:800;color:#60a5fa;text-transform:uppercase;letter-spacing:.5px}
.panel-body{padding:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
label{font-size:13px;font-weight:800;color:#93c5fd;text-transform:uppercase;letter-spacing:.5px}
input{width:100%;margin-top:8px;padding:12px 14px;background:white;border:1px solid rgba(71,85,105,.4);border-radius:10px;color:black;outline:none}
.actions{margin-top:14px;display:flex;gap:10px;flex-wrap:wrap}
button{padding:10px 16px;border-radius:10px;border:1px solid rgba(59,130,246,.45);background:rgba(59,130,246,.2);color:#93c5fd;font-weight:900;cursor:pointer;transition:.2s}
button:hover{background:rgba(59,130,246,.28)}
.muted{color:#94a3b8;font-size:13px}
table{width:100%;border-collapse:collapse}
th,td{padding:14px 10px;border-bottom:1px solid rgba(71,85,105,.22);font-size:14px}
th{text-align:left;color:#93c5fd;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
tr:hover{background:rgba(59,130,246,.05)}
.link{color:#93c5fd;text-decoration:none;font-weight:800}
.link:hover{text-decoration:underline}
.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;z-index:9999}
.modal{width:min(520px,92vw);background:#0b1224;border:1px solid rgba(239,68,68,.5);border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.5);overflow:hidden}
.modal-head{padding:14px 16px;background:rgba(239,68,68,.12);border-bottom:1px solid rgba(239,68,68,.25);font-weight:900;color:#fecaca}
.modal-body{padding:16px;color:#e2e8f0;line-height:1.5}
.modal-actions{padding:14px 16px;display:flex;justify-content:flex-end;border-top:1px solid rgba(71,85,105,.25)}
.modal-actions button{border-color:rgba(239,68,68,.55);background:rgba(239,68,68,.2);color:#fecaca}
.modal-actions button:hover{background:rgba(239,68,68,.28)}
@media(max-width:1024px){.sidebar{width:240px}.main-content{margin-left:240px;padding:24px 32px}}
@media(max-width:768px){.sidebar{width:100%;position:relative;height:auto;border-right:none;border-bottom:1px solid rgba(71,85,105,.3)}.main-content{margin-left:0;padding:16px 20px}}
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
      Your request was blocked because it looked like URL/role tampering.<br>
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
        <li class="nav-item"><a href="staff-dashboard.php" class="nav-link<?php echo navActive('staff-dashboard.php',$currentPage); ?>"><span class="nav-icon">🏠</span><span>Dashboard</span></a></li>
        <li class="nav-item"><a href="staff-apply_leave.php" class="nav-link<?php echo navActive('staff-apply_leave.php',$currentPage); ?>"><span class="nav-icon">📝</span><span>Apply Leave</span></a></li>
        <li class="nav-item"><a href="staff-my_leave.php" class="nav-link<?php echo navActive('staff-my_leave.php',$currentPage); ?>"><span class="nav-icon">📅</span><span>My Leave</span></a></li>
        <li class="nav-item"><a href="staff-training.php" class="nav-link<?php echo navActive('staff-training.php',$currentPage); ?>"><span class="nav-icon">🎓</span><span>My Training</span></a></li>
        <li class="nav-item"><a href="staff-certification.php" class="nav-link<?php echo navActive('staff-certification.php',$currentPage); ?>"><span class="nav-icon">📄</span><span>My Certifications</span></a></li>
        <li class="nav-item"><a href="staff-profile.php" class="nav-link<?php echo navActive('staff-profile.php',$currentPage); ?>"><span class="nav-icon">👤</span><span>My Profile</span></a></li>
      </ul>
    </nav>
  </aside>

  <main class="main-content">
    <header class="header">
      <div class="welcome-section">
        <h2>My Certifications</h2>
        <p>Upload and view your certifications (JPEG/PNG only)</p>
      </div>
      <div class="header-actions">
        <div class="user-info">
          <span><strong><?php echo htmlspecialchars($username); ?></strong></span> <!-- Reflected XSS safe -->
          <span style="text-transform: capitalize;"><?php echo htmlspecialchars($role); ?></span> <!-- Reflected XSS safe -->
        </div>
        <a class="logout-btn" href="?logout=1">Logout</a>
      </div>
    </header>

    <?php if ($success): ?><div class="msg-ok"><?php echo htmlspecialchars($success); ?></div><?php endif; ?> <!-- Reflected XSS safe -->
    <?php if ($error): ?><div class="msg-err"><?php echo htmlspecialchars($error); ?></div><?php endif; ?> <!-- Reflected XSS safe -->

    <?php if (!$has_cert_file): ?>
      <div class="msg-err">
        Your DB table <strong>staff_certification</strong> has no <strong>cert_file</strong> column yet.
        This page will still work, but filenames won’t be stored until you add it.
      </div>
    <?php endif; ?>

    <section class="panel">
      <div class="panel-head"><div class="panel-title">Upload Certification</div></div>
      <div class="panel-body">
        <form method="POST" enctype="multipart/form-data">
          <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>"> <!-- Reflected XSS safe -->

          <div class="grid">
            <div>
              <label>Certification Name</label>
              <input type="text" name="cert_name" placeholder="e.g. First Aid, ISO 27001" required>
            </div>
            <div>
              <label>Issue Date</label>
              <input type="date" name="issue_date" id="issue_date" required>
            </div>
            <div>
              <label>Expiry Date</label>
              <input type="date" name="expiry_date" id="expiry_date">
            </div>
            <div>
              <label>Upload File (JPEG/PNG)</label>
              <input type="file" name="cert_upload" accept=".jpg,.jpeg,.png" required>
              <p class="muted" style="margin-top:8px;">Max 2MB. Only JPEG/PNG allowed.</p>
            </div>
          </div>

          <div class="actions">
            <button type="submit">Upload</button>
          </div>
        </form>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head"><div class="panel-title">My Uploaded Certifications</div></div>
      <div class="panel-body">
        <?php if (empty($myCerts)): ?>
          <p class="muted">No certifications uploaded yet.</p>
        <?php else: ?>
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Issue</th>
                <th>Expiry</th>
                <th>File</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($myCerts as $c): ?>
                <tr>
                  <td><?php echo (int)$c['id']; ?></td>
                  <td><?php echo htmlspecialchars($c['name']); ?></td> <!-- Stored XSS safe -->
                  <td><?php echo htmlspecialchars($c['issue_date']); ?></td>
                  <td><?php echo htmlspecialchars($c['expiry_date']); ?></td>
                  <td>
                    <?php if (!empty($c['cert_file'])): ?>
                      <a class="link" href="../uploads/certifications/<?php echo rawurlencode($c['cert_file']); ?>" target="_blank">View</a> <!-- DOM XSS safe -->
                    <?php else: ?>
                      <span class="muted">N/A</span>
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
