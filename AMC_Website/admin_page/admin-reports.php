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
   ✅ URL Tampering Popup (ADMIN REPORTS)
   - Any ?role=... => popup + clean reload
   - Any id/user_id/staff_id/employee_id/user param => popup + clean reload
   - Any unexpected query key => popup + clean reload
   - If URL path/filename is edited (e.g. staff-dashboard -> admin-reports)
     => popup + redirect to correct file
   Allowed GET keys here:
     logout
================================ */
$EXPECTED_FILE = 'admin-reports.php';

function adminreports_clean_url(array $removeKeys = ['role','id','user_id','staff_id','employee_id','user']): string {
    $query = $_GET;
    foreach ($removeKeys as $k) unset($query[$k]);

    $base = strtok($_SERVER['REQUEST_URI'], '?');
    return $base . (count($query) ? ('?' . http_build_query($query)) : '');
}

function adminreports_redirect_clean(bool $withPopup = true, ?string $forcePath = null): void {
    if ($withPopup) $_SESSION['flash_unauth'] = 1;

    $clean = adminreports_clean_url();

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
   AUTH CHECK (must be before tamper checks that depend on role)
============================ */
if (!isset($_SESSION['auth'], $_SESSION['user'], $_SESSION['role'])) {
    header('Location: /AMC_Website/login_page/login.php');
    exit;
}
if (strtolower((string)($_SESSION['role'] ?? '')) !== 'admin') {
    http_response_code(403);
    die("Access Denied");
}

$username = (string)($_SESSION['user'] ?? '');

/* ===============================
   Force correct filename if URL path is edited
================================ */
$currentFile = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '');
if ($currentFile !== '' && strtolower($currentFile) !== strtolower($EXPECTED_FILE)) {
    adminreports_redirect_clean(true, $EXPECTED_FILE);
}

/* ===============================
   Detect ANY unexpected query keys (URL edited)
================================ */
$allowedKeys = ['logout'];
foreach (array_keys($_GET) as $k) {
    if (!in_array($k, $allowedKeys, true)) {
        adminreports_redirect_clean(true);
    }
}

/* ===============================
   Explicit tamper triggers
================================ */
if (isset($_GET['role'])) {
    // ANY role param triggers popup (even if it matches)
    adminreports_redirect_clean(true);
}
if (isset($_GET['id']) || isset($_GET['user_id']) || isset($_GET['staff_id']) || isset($_GET['employee_id']) || isset($_GET['user'])) {
    adminreports_redirect_clean(true);
}

/* ============================
   LOGOUT handling (keep your original behavior)
============================ */
if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: /AMC_Website/login.php');
    exit;
}

/* ============================
   DB config
============================ */
$db_host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "swap";

$mysqli = new mysqli($db_host,$db_user,$db_pass,$db_name);
if ($mysqli->connect_error) die("DB connection failed: ".$mysqli->connect_error);
$mysqli->set_charset("utf8mb4");

/* ============================
   Fetch Admin Info
============================ */
$stmt = $mysqli->prepare("
    SELECT s.name, s.email, s.job_title
    FROM users u
    JOIN staff s ON u.staff_id = s.id
    WHERE u.username = ?
");
$stmt->bind_param("s", $username);
$stmt->execute();
$stmt->bind_result($admin_name, $email, $job_title);
$stmt->fetch();
$stmt->close();

/* ============================
   Leave Statistics
============================ */
$months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
$leave_data = array_fill(0,12,0);
$approved_data = array_fill(0,12,0);
$rejected_data = array_fill(0,12,0);

$result = $mysqli->query("SELECT COUNT(*) AS total_staff FROM staff");
$total_staff = $result ? ($result->fetch_assoc()['total_staff'] ?? 0) : 0;

$result = $mysqli->query("SELECT COUNT(*) AS total_leaves FROM leave_application");
$total_leaves = $result ? ($result->fetch_assoc()['total_leaves'] ?? 0) : 0;

$result = $mysqli->query("SELECT COUNT(*) AS approved_leaves FROM leave_application WHERE status='approved'");
$approved_leaves = $result ? ($result->fetch_assoc()['approved_leaves'] ?? 0) : 0;

$result = $mysqli->query("SELECT COUNT(*) AS rejected_leaves FROM leave_application WHERE status='rejected'");
$rejected_leaves = $result ? ($result->fetch_assoc()['rejected_leaves'] ?? 0) : 0;

$result = $mysqli->query("SELECT COUNT(*) AS pending_leaves FROM leave_application WHERE status='pending'");
$pending_leaves = $result ? ($result->fetch_assoc()['pending_leaves'] ?? 0) : 0;

// Monthly leave requests
$result = $mysqli->query("SELECT MONTH(start_date) AS month, COUNT(*) AS total FROM leave_application GROUP BY MONTH(start_date)");
if ($result) while($row = $result->fetch_assoc()) $leave_data[(int)$row['month']-1] = (int)$row['total'];

$result = $mysqli->query("SELECT MONTH(start_date) AS month, COUNT(*) AS total FROM leave_application WHERE status='approved' GROUP BY MONTH(start_date)");
if ($result) while($row = $result->fetch_assoc()) $approved_data[(int)$row['month']-1] = (int)$row['total'];

$result = $mysqli->query("SELECT MONTH(start_date) AS month, COUNT(*) AS total FROM leave_application WHERE status='rejected' GROUP BY MONTH(start_date)");
if ($result) while($row = $result->fetch_assoc()) $rejected_data[(int)$row['month']-1] = (int)$row['total'];

/* ============================
   Security Statistics
============================ */
$result = $mysqli->query("SELECT SUM(success=1) AS total_success, SUM(success=0) AS total_fail FROM login_audit");
$totals = $result ? $result->fetch_assoc() : [];
$total_success = $totals['total_success'] ?? 0;
$total_fail = $totals['total_fail'] ?? 0;

// Per-user login stats
$user_labels = [];
$user_success = [];
$user_fail = [];

$result = $mysqli->query("SELECT username, SUM(success=1) AS success, SUM(success=0) AS fail FROM login_audit GROUP BY username");
if ($result) {
    while($row = $result->fetch_assoc()){
        $user_labels[] = (string)$row['username'];
        $user_success[] = (int)$row['success'];
        $user_fail[] = (int)$row['fail'];
    }
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
<title>AMC HR - Reports</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Inter',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;}
.container{display:flex;min-height:100vh;}

/* ===== Sidebar (MATCH DASHBOARD BIGGEST) ===== */
.sidebar{
    width:280px;
    background:rgba(15,23,42,0.95);
    border-right:1px solid rgba(71,85,105,0.3);
    padding-top:32px;
    position:fixed;
    top:0;bottom:0;left:0;
    overflow-y:auto;
}
.sidebar::-webkit-scrollbar{width:6px;}
.sidebar::-webkit-scrollbar-thumb{background:rgba(96,165,250,0.3);border-radius:3px;}
.logo{padding:0 32px;margin-bottom:48px;}
.logo h1{
    font-size:32px;
    font-weight:700;
    background:linear-gradient(135deg,#60a5fa,#3b82f6);
    -webkit-background-clip:text;
    -webkit-text-fill-color:transparent;
}
.role-badge{display:inline-block;margin-top:8px;padding:4px 12px;background:rgba(168,85,247,0.2);border:1px solid rgba(168,85,247,0.3);border-radius:6px;font-size:12px;font-weight:600;color:#c084fc;text-transform:uppercase;}
.nav-menu{list-style:none;}
.nav-section-title{
    padding:8px 32px;
    font-size:11px;
    font-weight:700;
    color:#64748b;
    text-transform:uppercase;
    letter-spacing:1px;
    margin-top:24px;
    margin-bottom:8px;
}
.nav-item{margin-bottom:4px;}
.nav-link{
    display:flex;
    align-items:center;
    gap:12px;
    padding:12px 32px;
    color:#94a3b8;
    text-decoration:none;
    font-size:14px;
    font-weight:500;
    transition:all .2s ease;
    border-left:3px solid transparent;
}
.nav-link:hover{background: rgba(59,130,246,0.1);color:#60a5fa;border-left-color:#3b82f6;}
.nav-link.active{background: rgba(59,130,246,0.15);color:#60a5fa;border-left-color:#3b82f6;}
.nav-icon{font-size:18px;width:20px;text-align:center;}

/* ===== Main content ===== */
.main-content{flex:1;margin-left:280px;padding:32px 48px;}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;}
.welcome-section h1{
    font-size:32px;
    font-weight:700;
    margin-bottom:8px;
    background:linear-gradient(135deg,#60a5fa,#3b82f6);
    -webkit-background-clip:text;
    -webkit-text-fill-color:transparent;
}
.welcome-section p { color: #94a3b8; font-size: 14px; }.user-info { text-align: right; }
.user-info .name { font-weight: 600;font-size: 16px;color: #e2e8f0;margin-bottom: 4px;}
.user-info .role { font-size: 13px; color: purple; margin-bottom: 12px; }
.logout-btn{display:inline-block;padding:8px 20px;background:rgba(239,68,68,.2);border:1px solid rgba(239,68,68,.4);border-radius:8px;color:#fca5a5;text-decoration:none;font-size:13px;font-weight:600;}
.logout-btn:hover{background:rgba(239,68,68,.3);}

.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:40px;}
.card{background:rgba(30,41,59,0.8);padding:24px;border-radius:16px;border:1px solid rgba(71,85,105,0.3);}
.card h3{font-size:14px;color:#94a3b8;margin-bottom:8px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;}
.card p{font-size:28px;font-weight:700;color:#60a5fa;}
.chart-container{background:rgba(30,41,59,0.8);padding:24px;border-radius:16px;margin-bottom:20px;text-align:center;border:1px solid rgba(71,85,105,0.3);}
.chart-container canvas{max-width:900px;height:400px;margin:0 auto;}
canvas.small-chart{max-width:500px;height:300px;margin:0 auto;}

.tabs{display:flex;gap:16px;margin-bottom:24px;}
.tab-btn{padding:10px 20px;background:rgba(59,130,246,0.1);border-radius:8px;cursor:pointer;color:#60a5fa;font-weight:700;border:1px solid rgba(59,130,246,0.25);}
.tab-btn.active{background:rgba(59,130,246,0.2);border-color:rgba(59,130,246,0.45);}

/* ===== Unauthorised popup modal ===== */
.unauth-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;z-index:10000}
.unauth-modal{width:min(520px,92vw);background:#0b1224;border:1px solid rgba(239,68,68,.5);border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.5);overflow:hidden}
.unauth-head{padding:14px 16px;background:rgba(239,68,68,.12);border-bottom:1px solid rgba(239,68,68,.25);font-weight:900;color:#fecaca}
.unauth-body{padding:16px;color:#e2e8f0;line-height:1.5}
.unauth-actions{padding:14px 16px;display:flex;justify-content:flex-end;border-top:1px solid rgba(71,85,105,.25)}
.unauth-actions button{border-color:rgba(239,68,68,.55);background:rgba(239,68,68,.2);color:#fecaca;padding:10px 16px;border-radius:10px;border:1px solid rgba(239,68,68,.55);font-weight:800;cursor:pointer;transition:.2s}
.unauth-actions button:hover{background:rgba(239,68,68,.28)}

/* ===== Responsive (MATCH DASHBOARD) ===== */
@media(max-width:1024px){
  .sidebar{width:240px;}
  .main-content{margin-left:240px;padding:24px 32px;}
}
@media(max-width:768px){
  .sidebar{width:100%;position:relative;height:auto;border-right:none;border-bottom:1px solid rgba(71,85,105,0.3);}
  .main-content{margin-left:0;padding:20px;}
  .container{flex-direction:column;}
}
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
    <aside class="sidebar">
        <div class="logo">
            <h1>AMC HR</h1>
            <span class="role-badge">Administrator</span>
        </div>
        <nav>
            <ul class="nav-menu">
                <li class="nav-item">
                    <a href="admin-dashboard.php" class="nav-link">
                        <span class="nav-icon">📊</span><span>Dashboard</span>
                    </a>
                </li>

                <li class="nav-section-title">Management</li>
                <li class="nav-item">
                    <a href="admin-users.php" class="nav-link">
                        <span class="nav-icon">👥</span><span>Manage Users</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="admin-departments.php" class="nav-link">
                        <span class="nav-icon">🏢</span><span>Departments</span>
                    </a>
                </li>

                <li class="nav-section-title">Operations</li>
                <li class="nav-item">
                    <a href="admin-leave-management.php" class="nav-link">
                        <span class="nav-icon">📅</span><span>Leave Management</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="admin-training.php" class="nav-link">
                        <span class="nav-icon">🎓</span><span>Training</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="admin-certifications.php" class="nav-link">
                        <span class="nav-icon">📜</span><span>Certifications</span>
                    </a>
                </li>

                <li class="nav-section-title">System</li>
                <li class="nav-item">
                    <a href="admin-reports.php" class="nav-link active">
                        <span class="nav-icon">📈</span><span>Reports</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="admin-security.php" class="nav-link">
                        <span class="nav-icon">🔒</span><span>Security & Logs</span>
                    </a>
                </li>
            </ul>
        </nav>
    </aside>

    <main class="main-content">
        <header class="header">
            <div class="welcome-section">
                <h1>System Reports</h1>
                <p>Overview of HR statistics</p>
            </div>
            <div class="user-info">
                <div class="name"><?= htmlspecialchars((string)$admin_name, ENT_QUOTES, 'UTF-8') ?></div>
                <div class="role"><?php echo htmlspecialchars((string)($_SESSION['role'] ?? ''), ENT_QUOTES, 'UTF-8') ?></div>
                <a href="?logout=1" class="logout-btn">Logout</a>
            </div>
        </header>

        <!-- Tabs -->
        <div class="tabs">
            <div class="tab-btn active" data-tab="leave-tab">Leave Reports</div>
            <div class="tab-btn" data-tab="security-tab">Security & Logs</div>
        </div>

        <!-- Leave Tab -->
        <div id="leave-tab">
            <section class="stats">
                <div class="card"><h3>Total Staff</h3><p><?php echo (int)$total_staff; ?></p></div>
                <div class="card"><h3>Total Leave Requests</h3><p><?php echo (int)$total_leaves; ?></p></div>
                <div class="card"><h3>Approved</h3><p><?php echo (int)$approved_leaves; ?></p></div>
                <div class="card"><h3>Pending</h3><p><?php echo (int)$pending_leaves; ?></p></div>
                <div class="card"><h3>Rejected</h3><p><?php echo (int)$rejected_leaves; ?></p></div>
            </section>

            <div class="chart-container">
                <h3>Monthly Leave Requests (All)</h3>
                <canvas id="leaveChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Approved Leaves Per Month</h3>
                <canvas id="approvedChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Rejected Leaves Per Month</h3>
                <canvas id="rejectedChart"></canvas>
            </div>
        </div>

        <!-- Security Tab -->
        <div id="security-tab" style="display:none;">
            <section class="stats">
                <div class="card"><h3>Total Success</h3><p><?php echo (int)$total_success; ?></p></div>
                <div class="card"><h3>Total Fail</h3><p><?php echo (int)$total_fail; ?></p></div>
            </section>

            <section class="stats">
                <?php foreach($user_labels as $i => $user): ?>
                <div class="card">
                    <h3><?php echo htmlspecialchars((string)$user, ENT_QUOTES, 'UTF-8'); ?></h3>
                    <p>✅ <?php echo (int)$user_success[$i]; ?> &nbsp;&nbsp; ❌ <?php echo (int)$user_fail[$i]; ?></p>
                </div>
                <?php endforeach; ?>
            </section>

            <div class="chart-container">
                <h3>Overall Login Success vs Failure</h3>
                <canvas id="totalLoginChart" class="small-chart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Login Success/Failure by User</h3>
                <canvas id="securityChart"></canvas>
            </div>
        </div>

    </main>
</div>

<script>
// Tabs
document.querySelectorAll('.tab-btn').forEach(btn=>{
    btn.addEventListener('click',()=>{
        document.querySelectorAll('#leave-tab,#security-tab').forEach(tab=>tab.style.display='none');
        document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
        btn.classList.add('active');
        const tab = document.getElementById(btn.dataset.tab);
        tab.style.display='block';
        if(btn.dataset.tab === 'security-tab' && !window.securityChartsInitialized){
            initSecurityCharts();
            window.securityChartsInitialized = true;
        }
    });
});

// Leave charts
const months = <?php echo json_encode($months); ?>;
const leaveData = <?php echo json_encode($leave_data); ?>;
const approvedData = <?php echo json_encode($approved_data); ?>;
const rejectedData = <?php echo json_encode($rejected_data); ?>;

new Chart(document.getElementById('leaveChart'), {
    type:'line',
    data:{labels:months,datasets:[{label:'All Leaves',data:leaveData,borderColor:'#60a5fa',backgroundColor:'rgba(96,165,250,0.2)',tension:0.4,fill:true}]},
    options:{responsive:true,plugins:{legend:{labels:{color:'#e2e8f0'}}},scales:{x:{ticks:{color:'#94a3b8'}},y:{ticks:{color:'#94a3b8'}}}}
});
new Chart(document.getElementById('approvedChart'), {
    type:'bar',
    data:{labels:months,datasets:[{label:'Approved',data:approvedData,backgroundColor:'#22c55e'}]},
    options:{responsive:true,plugins:{legend:{labels:{color:'#e2e8f0'}}},scales:{x:{ticks:{color:'#94a3b8'}},y:{ticks:{color:'#94a3b8'}}}}
});
new Chart(document.getElementById('rejectedChart'), {
    type:'bar',
    data:{labels:months,datasets:[{label:'Rejected',data:rejectedData,backgroundColor:'#ef4444'}]},
    options:{responsive:true,plugins:{legend:{labels:{color:'#e2e8f0'}}},scales:{x:{ticks:{color:'#94a3b8'}},y:{ticks:{color:'#94a3b8'}}}}
});

// Security charts
const userLabels = <?php echo json_encode($user_labels); ?>;
const userSuccess = <?php echo json_encode($user_success); ?>;
const userFail = <?php echo json_encode($user_fail); ?>;
const totalSuccess = <?php echo (int)$total_success; ?>;
const totalFail = <?php echo (int)$total_fail; ?>;

function initSecurityCharts(){
    new Chart(document.getElementById('totalLoginChart'),{
        type:'doughnut',
        data:{labels:['Success','Fail'],datasets:[{data:[totalSuccess,totalFail],backgroundColor:['#22c55e','#ef4444'],borderColor:['#16a34a','#b91c1c'],borderWidth:1}]},
        options:{responsive:true,plugins:{legend:{labels:{color:'#e2e8f0'}}}}
    });

    new Chart(document.getElementById('securityChart'),{
        type:'bar',
        data:{labels:userLabels,datasets:[{label:'Success',data:userSuccess,backgroundColor:'#22c55e'},{label:'Fail',data:userFail,backgroundColor:'#ef4444'}]},
        options:{responsive:true,plugins:{legend:{labels:{color:'#e2e8f0'}}},scales:{x:{ticks:{color:'#94a3b8'}},y:{ticks:{color:'#94a3b8'}}}}
    });
}
</script>
</body>
</html>
