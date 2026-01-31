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
   ✅ URL Tampering Popup (ADMIN CERTIFICATIONS)
   - Any ?role=... (staff/admin/supervisor etc) => popup + clean reload
   - Any id/user_id/staff_id/employee_id/user param => popup + clean reload
   - Any unexpected query key => popup + clean reload
   - If URL path/filename is edited (e.g. staff-dashboard -> admin-certifications)
     => popup + redirect to correct file
   Allowed GET keys here:
     logout, delete, view
================================ */
$EXPECTED_FILE = 'admin-certifications.php';

function admincert_clean_url(array $removeKeys = ['role','id','user_id','staff_id','employee_id','user']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);

    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function admincert_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) $_SESSION['flash_unauth'] = 1;

    $clean = admincert_clean_url();

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
    header('Location: login.php');
    exit;
}
if (strtolower((string)($_SESSION['role'] ?? '')) !== 'admin') {
    http_response_code(403);
    exit("Access Denied");
}

$username = (string)($_SESSION['user'] ?? '');

/* ===============================
   Force correct filename if URL path is edited
================================ */
$currentFile = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '');
if ($currentFile !== '' && strtolower($currentFile) !== strtolower($EXPECTED_FILE)) {
    admincert_redirect_clean(true, $EXPECTED_FILE);
}

/* ===============================
   Detect ANY unexpected query keys (URL edited)
================================ */
$allowedKeys = ['logout','delete','view'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        admincert_redirect_clean(true);
    }
}

/* ===============================
   Explicit tamper triggers
================================ */
if (isset($_GET['role'])) {
    // ANY role param triggers popup (even if it matches)
    admincert_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['user_id']) || isset($_GET['staff_id']) || isset($_GET['employee_id']) || isset($_GET['user'])) {
    admincert_redirect_clean(true);
}

/* --- Handle Logout --- */
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: /AMC_Website/login.php');
    exit;
}

/* ============================
   DB CONNECTION
============================ */
$mysqli = new mysqli("localhost", "root", "", "swap");
if ($mysqli->connect_error) {
    die("Database connection failed");
}
$mysqli->set_charset("utf8mb4");

/* ============================
   DELETE
============================ */
if (isset($_GET['delete'])) {
    $id = (int)$_GET['delete'];

    $stmt = $mysqli->prepare("SELECT cert_file FROM staff_certification WHERE id=?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $stmt->bind_result($file);
    $stmt->fetch();
    $stmt->close();

    if ($file) {
        $safeFile = basename((string)$file);
        $path = "../uploads/certifications/$safeFile";
        if (is_file($path)) unlink($path);
    }

    $stmt = $mysqli->prepare("DELETE FROM staff_certification WHERE id=?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $stmt->close();

    header("Location: admin-certifications.php");
    exit;
}

/* ============================
   UPDATE
============================ */
if (isset($_POST['update_id'])) {
    $update_id = (int)($_POST['update_id'] ?? 0);
    $name      = trim((string)($_POST['name'] ?? ''));
    $issue     = (string)($_POST['issue_date'] ?? '');
    $expiry    = (string)($_POST['expiry_date'] ?? '');

    $stmt = $mysqli->prepare("
        UPDATE staff_certification
        SET name=?, issue_date=?, expiry_date=?
        WHERE id=?
    ");
    $stmt->bind_param("sssi", $name, $issue, $expiry, $update_id);
    $stmt->execute();
    $stmt->close();

    header("Location: admin-certifications.php");
    exit;
}

/* ============================
   VIEW FILE
============================ */
if (isset($_GET['view'])) {
    $id = (int)$_GET['view'];

    $stmt = $mysqli->prepare("SELECT cert_file FROM staff_certification WHERE id=?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $stmt->bind_result($file);
    $stmt->fetch();
    $stmt->close();

    $safeFile = $file ? basename((string)$file) : '';
    $path = "../uploads/certifications/$safeFile";
    if ($safeFile === '' || !is_file($path)) {
        http_response_code(404);
        exit("File not found");
    }

    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime  = $finfo->file($path) ?: 'application/octet-stream';

    header("Content-Type: " . $mime);
    header("Content-Disposition: inline; filename=\"" . basename($safeFile) . "\"");
    header("Content-Length: " . (string)filesize($path));
    readfile($path);
    exit;
}

/* ============================
   FETCH DATA
============================ */
$data = [];
$stmt = $mysqli->prepare("
    SELECT sc.id, sc.name, sc.issue_date, sc.expiry_date, sc.cert_file,
           s.name AS staff_name
    FROM staff_certification sc
    JOIN staff s ON s.id = sc.staff_id
    ORDER BY sc.id DESC
");
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) $data[] = $row;
$stmt->close();

/* ============================
   ADMIN NAME
============================ */
$stmt = $mysqli->prepare("
    SELECT s.name
    FROM users u
    JOIN staff s ON u.staff_id = s.id
    WHERE u.username = ?
");
$stmt->bind_param("s", $username);
$stmt->execute();
$admin = $stmt->get_result()->fetch_assoc();
$stmt->close();
$admin_name = $admin['name'] ?? 'Admin';

/* ========= One-time popup flag ========= */
$showUnauth = !empty($_SESSION['flash_unauth']);
if ($showUnauth) unset($_SESSION['flash_unauth']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AMC HR - Certifications</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
/* ======= Reset & Body ======= */
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Inter',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;}
.container{display:flex;min-height:100vh;}

/* -- Sidebar --*/
.sidebar{
    width:280px;
    background:rgba(15,23,42,0.95);
    border-right:1px solid rgba(71,85,105,0.3);
    padding-top:32px;
    position:fixed;
    top:0; bottom:0; left:0;
    overflow-y:auto;
}
.sidebar::-webkit-scrollbar{width:6px;}
.sidebar::-webkit-scrollbar-thumb{background:rgba(96,165,250,0.3);border-radius:3px;}
.logo{padding:0 32px;margin-bottom:48px;}
.logo h1{font-size:32px;font-weight:700;background:linear-gradient(135deg,#60a5fa,#3b82f6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.logo .role-badge{display:inline-block;margin-top:8px;padding:4px 12px;background:rgba(168,85,247,0.2);border:1px solid rgba(168,85,247,0.3);border-radius:6px;font-size:12px;font-weight:600;color:#c084fc;text-transform:uppercase;}
.nav-menu{list-style:none;}
.nav-section-title{padding:8px 32px;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:24px;margin-bottom:8px;}
.nav-item{margin-bottom:4px;}
.nav-link{display:flex;align-items:center;gap:12px;padding:12px 32px;color:#94a3b8;text-decoration:none;font-size:14px;font-weight:500;transition:all 0.2s ease;border-left:3px solid transparent;}
.nav-link:hover{background: rgba(59,130,246,0.1);color:#60a5fa;border-left-color:#3b82f6;}
.nav-link.active{background: rgba(59,130,246,0.15);color:#60a5fa;border-left-color:#3b82f6;}
.nav-icon{font-size:18px;width:20px;text-align:center;}

/* -- Main Content --*/
.main-content{flex:1;margin-left:280px;padding:32px 48px;}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:48px;gap:20px;}
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

/* --- Panel --- */
.panel{background:rgba(15,23,42,.6);border:1px solid rgba(71,85,105,.3);border-radius:12px;overflow:hidden;}
.panel-header{padding:20px 24px;background:rgba(30,41,59,.8);border-bottom:1px solid rgba(71,85,105,.3);}
.panel-title{font-size:16px;font-weight:700;color:#60a5fa;text-transform:uppercase;}
.panel-body{padding:24px;}

/* --- Table --- */
table{width:100%;border-collapse:collapse;}
th,td{padding:12px;border-bottom: solid rgba(117,117,117,117);text-align:center;}
th{font-size:12px;font-weight:700;color:#93c5fd;text-transform:uppercase;}
td{font-size:14px;}
tr:hover{background:rgba(59,130,246,.05);}
.view{color:#60a5fa;text-decoration:none;}

/* ======= BUTTONS ======= */
.btn{padding:6px 12px;border:none;border-radius:6px;color:#fff;cursor:pointer;font-size:14px;}
.btn-edit{background:#3b82f6;}
.btn-edit:hover{background:#60a5fa;}
.btn-delete{background:#ef4444;}
.btn-delete:hover{background:#f87171;}

/* ======= MODAL ======= */
.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);justify-content:center;align-items:center;z-index:1000;}
.modal-content{background:#1e293b;padding:24px;border-radius:12px;width:100%;max-width:400px;position:relative;}
.modal-content h2{margin-bottom:16px;color:#60a5fa;text-align:center;}
.modal-content label{display:block;margin-bottom:6px;font-size:14px;color:#93c5fd;}
.modal-content input{width:100%;padding:10px;margin-bottom:16px;border:1px solid rgba(71,85,105,0.5);border-radius:8px;color:black;font-size:14px;}
.modal-content input:focus{border-color:#3b82f6;outline:none;}
.modal-content button{width:100%;padding:12px;background:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer;}
.modal-content button:hover{background:#60a5fa;}
.modal-close{position:absolute;top:12px;right:12px;font-size:18px;color:#fff;cursor:pointer;}

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
                <li class="nav-item"><a href="admin-leave-management.php" class="nav-link"><span class="nav-icon">📅</span>Leave Management</a></li>
                <li class="nav-item"><a href="admin-training.php" class="nav-link"><span class="nav-icon">🎓</span>Training</a></li>
                <li class="nav-item"><a href="admin-certifications.php" class="nav-link active"><span class="nav-icon">📜</span>Certifications</a></li>

                <li class="nav-section-title">System</li>
                <li class="nav-item"><a href="admin-reports.php" class="nav-link"><span class="nav-icon">📈</span>Reports</a></li>
                <li class="nav-item"><a href="admin-security.php" class="nav-link"><span class="nav-icon">🔒</span>Security & Logs</a></li>
            </ul>
        </nav>
    </aside>

<!-- MAIN -->
<main class="main-content">
<header class="header">
  <div class="welcome-section">
    <h1>Certifications</h1>
    <p>Overview of Staff Certifications</p>
  </div>
  <div class="user-info">
    <div class="name"><?= htmlspecialchars((string)$admin_name, ENT_QUOTES, 'UTF-8') ?></div>
    <div class="role"><?php echo htmlspecialchars((string)($_SESSION['role'] ?? ''), ENT_QUOTES, 'UTF-8') ?></div>
    <a href="?logout=1" class="logout-btn">Logout</a>
  </div>
</header>

<div class="panel">
  <div class="panel-header">
    <div class="panel-title">Staff Certifications</div>
  </div>
  <div class="panel-body">
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Staff</th>
          <th>Certificate Name</th>
          <th>Issue</th>
          <th>Expiry</th>
          <th>File</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        <?php foreach ($data as $r): ?>
          <tr>
            <td><?= (int)$r['id'] ?></td>
            <td><?= htmlspecialchars((string)$r['staff_name'], ENT_QUOTES, 'UTF-8') ?></td>
            <td><?= htmlspecialchars((string)$r['name'], ENT_QUOTES, 'UTF-8') ?></td>
            <td><?= htmlspecialchars((string)$r['issue_date'], ENT_QUOTES, 'UTF-8') ?></td>
            <td><?= htmlspecialchars((string)$r['expiry_date'], ENT_QUOTES, 'UTF-8') ?></td>
            <td>
              <?php if (!empty($r['cert_file'])): ?>
                <a class="view" href="?view=<?= (int)$r['id'] ?>">View</a>
              <?php else: ?>
                <span class="missing">Missing</span>
              <?php endif; ?>
            </td>
            <td>
              <button class="btn btn-edit"
                onclick="openModal(
                  <?= (int)$r['id'] ?>,
                  '<?= htmlspecialchars((string)$r['name'], ENT_QUOTES, 'UTF-8') ?>',
                  '<?= htmlspecialchars((string)$r['issue_date'], ENT_QUOTES, 'UTF-8') ?>',
                  '<?= htmlspecialchars((string)$r['expiry_date'], ENT_QUOTES, 'UTF-8') ?>'
                )">Edit</button>
              <button class="btn btn-delete" onclick="openDeleteModal(<?= (int)$r['id'] ?>)">Delete</button>
            </td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>

  </div>
</div>
</main>
</div>

<!-- UPDATE MODAL -->
<div class="modal" id="updateModal">
    <div class="modal-content">
        <span class="modal-close" onclick="closeModal()">&times;</span>
        <h2>Update Certification</h2>
        <form method="post">
            <input type="hidden" name="update_id" id="update_id">
            <label for="cert_name">Certification Name</label>
            <input type="text" name="name" id="cert_name" required>
            <label for="issue_date">Issue Date</label>
            <input type="date" name="issue_date" id="issue_date" required>
            <label for="expiry_date">Expiry Date</label>
            <input type="date" name="expiry_date" id="expiry_date" required>
            <button type="submit">Update Certification</button>
        </form>
    </div>
</div>

<!-- DELETE MODAL -->
<div class="modal" id="deleteModal">
    <div class="modal-content">
        <span class="modal-close" onclick="closeDeleteModal()">&times;</span>
        <h2>Confirm Delete</h2>
        <p>Are you sure you want to delete this certification?</p>
        <div style="display:flex;gap:12px;justify-content:center;margin-top:16px;">
            <button id="confirmDelete" class="btn btn-delete">OK</button>
            <button onclick="closeDeleteModal()" class="btn btn-edit" type="button">Cancel</button>
        </div>
    </div>
</div>

<script>
// UPDATE MODAL
function openModal(id, name, issue, expiry){
    document.getElementById('update_id').value = id;
    document.getElementById('cert_name').value = name;
    document.getElementById('issue_date').value = issue;
    document.getElementById('expiry_date').value = expiry;
    document.getElementById('updateModal').style.display = 'flex';
}

function closeModal(){
    document.getElementById('updateModal').style.display = 'none';
}

window.onclick = function(event){
    let modal = document.getElementById('updateModal');
    if(event.target === modal) modal.style.display = 'none';
}

// DELETE MODAL
let deleteId = null;

function openDeleteModal(id){
    deleteId = id;
    document.getElementById('deleteModal').style.display = 'flex';
}

function closeDeleteModal(){
    deleteId = null;
    document.getElementById('deleteModal').style.display = 'none';
}

document.getElementById('confirmDelete').addEventListener('click', function(){
    if(deleteId){
        window.location = '?delete=' + deleteId;
    }
});
</script>
</body>
</html>
