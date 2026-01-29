<?php
declare(strict_types=1);

ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
session_start();

/* Block obvious URL tampering attempts (role/id in URL) */
if (isset($_GET['role']) || isset($_GET['id']) || isset($_GET['user']) || isset($_GET['employee_id'])) {
  http_response_code(400);
  exit("Invalid request.");
}

function requireLogin(): void {
  if (empty($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
  }
}

function requireAnyRole(array $allowedRoles): void {
  requireLogin();
  $role = $_SESSION['role'] ?? 'staff';
  if (!in_array($role, $allowedRoles, true)) {
    http_response_code(403);
    exit("Forbidden.");
  }
}

function ensureCsrf(): void {
  if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
  }
}

function requireCsrf(): void {
  $t = (string)($_POST['csrf_token'] ?? '');
  if (!hash_equals($_SESSION['csrf_token'] ?? '', $t)) {
    http_response_code(403);
    exit("CSRF blocked.");
  }
};

// Database configuration
$db_host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "swap";

// Connect to database
$mysqli = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($mysqli->connect_error) {
    die("Database connection failed: " . $mysqli->connect_error);
}

// Check if user is logged in and is a supervisor
if (!isset($_SESSION['auth']) || !isset($_SESSION['user']) || !isset($_SESSION['role'])) {
    header('Location: login.php');
    exit;
}

// Verify user is a supervisor
if ($_SESSION['role'] !== 'supervisor') {
    http_response_code(403);
    die("Access Denied: This page is for supervisors only.");
}

// Get user information from session
$username = $_SESSION['user'];
$role = $_SESSION['role'];

// Get staff details for the logged-in user
$stmt = $mysqli->prepare("
    SELECT s.name, s.email, s.job_title, d.name as department_name
    FROM users u
    JOIN staff s ON u.staff_id = s.id
    LEFT JOIN department d ON s.department_id = d.id
    WHERE u.username = ?
");
$stmt->bind_param("s", $username);
$stmt->execute();
$stmt->bind_result($staff_name, $email, $job_title, $department_name);
$stmt->fetch();
$stmt->close();

// Handle search and filters
$search_query = $_GET['search'] ?? '';
$department_filter = $_GET['department'] ?? 'all';
$status_filter = $_GET['status'] ?? 'all';

// Build the query to get workforce readiness data
$query = "
    SELECT 
        s.id,
        s.name,
        s.job_title,
        d.name as department_name,
        s.status as employment_status,
        CASE 
            WHEN NOT EXISTS (
                SELECT 1 FROM training_attendance ta
                WHERE ta.staff_id = s.id AND ta.status = 'pending'
            )
            AND NOT EXISTS (
                SELECT 1 FROM staff_certification sc
                WHERE sc.staff_id = s.id AND sc.expiry_date < CURDATE()
            )
            THEN 'READY'
            ELSE 'NOT READY'
        END as readiness_status,
        (SELECT COUNT(*) FROM training_attendance ta 
         WHERE ta.staff_id = s.id AND ta.status = 'pending') as pending_training,
        (SELECT COUNT(*) FROM staff_certification sc 
         WHERE sc.staff_id = s.id AND sc.expiry_date < CURDATE()) as expired_certs
    FROM staff s
    LEFT JOIN department d ON s.department_id = d.id
    WHERE s.status = 'active'
";

// Add search condition
if (!empty($search_query)) {
    $query .= " AND (s.name LIKE ? OR s.job_title LIKE ?)";
}

// Add department filter
if ($department_filter !== 'all') {
    $query .= " AND d.name = ?";
}

$query .= " ORDER BY s.name ASC";

// Prepare statement
$stmt = $mysqli->prepare($query);

// Bind parameters based on filters
if (!empty($search_query) && $department_filter !== 'all') {
    $search_param = "%{$search_query}%";
    $stmt->bind_param("sss", $search_param, $search_param, $department_filter);
} elseif (!empty($search_query)) {
    $search_param = "%{$search_query}%";
    $stmt->bind_param("ss", $search_param, $search_param);
} elseif ($department_filter !== 'all') {
    $stmt->bind_param("s", $department_filter);
}

$stmt->execute();
$result = $stmt->get_result();

// Fetch all employees
$employees = [];
while ($row = $result->fetch_assoc()) {
    $employees[] = $row;
}
$stmt->close();

// Apply status filter after fetching (since it's computed)
if ($status_filter !== 'all') {
    $employees = array_filter($employees, function($emp) use ($status_filter) {
        return $emp['readiness_status'] === $status_filter;
    });
}

// Get unique departments for filter dropdown
$dept_query = "SELECT DISTINCT name FROM department ORDER BY name";
$dept_result = $mysqli->query($dept_query);
$departments = [];
while ($dept = $dept_result->fetch_assoc()) {
    $departments[] = $dept['name'];
}

// Handle logout
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header('Location: login.php');
    exit;
}

$mysqli->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AMC HR - Workforce Ready</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
        }

        .container {
            display: flex;
            min-height: 100vh;
        }

        /* Sidebar Styles */
        .sidebar {
            width: 280px;
            background: rgba(15, 23, 42, 0.95);
            border-right: 1px solid rgba(71, 85, 105, 0.3);
            padding: 32px 0;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
        }

        .logo {
            padding: 0 32px;
            margin-bottom: 48px;
        }

        .logo h1 {
            font-size: 32px;
            font-weight: 700;
            background: linear-gradient(135deg, #60a5fa 0%, #3b82f6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .logo .role-badge {
            display: inline-block;
            margin-top: 8px;
            padding: 4px 12px;
            background: rgba(251, 146, 60, 0.2);
            border: 1px solid rgba(251, 146, 60, 0.3);
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            color: #fb923c;
            text-transform: uppercase;
        }

        .nav-menu {
            list-style: none;
        }

        .nav-item {
            margin-bottom: 8px;
        }

        .nav-link {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 14px 32px;
            color: #94a3b8;
            text-decoration: none;
            font-size: 15px;
            font-weight: 500;
            transition: all 0.2s ease;
            border-left: 3px solid transparent;
        }

        .nav-link:hover {
            background: rgba(59, 130, 246, 0.1);
            color: #60a5fa;
            border-left-color: #3b82f6;
        }

        .nav-link.active {
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            border-left-color: #3b82f6;
        }

        .nav-icon {
            font-size: 20px;
        }

        /* Main Content Styles */
        .main-content {
            flex: 1;
            margin-left: 280px;
            padding: 32px 48px;
        }

        /* Header Styles */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 48px;
            gap: 20px;
        }

        .welcome-section h2 {
            font-size: 28px;
            font-weight: 700;
            color: #e2e8f0;
            margin-bottom: 8px;
        }

        .welcome-section p {
            font-size: 14px;
            color: #94a3b8;
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .user-info {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            color: #94a3b8;
            font-size: 14px;
        }

        .user-info strong {
            color: #60a5fa;
            font-weight: 600;
        }

        .logout-btn {
            padding: 10px 24px;
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid rgba(239, 68, 68, 0.4);
            border-radius: 8px;
            color: #fca5a5;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s ease;
        }

        .logout-btn:hover {
            background: rgba(239, 68, 68, 0.3);
            border-color: rgba(239, 68, 68, 0.6);
        }

        /* Directory Section */
        .directory-section {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(71, 85, 105, 0.3);
            border-radius: 16px;
            padding: 32px;
        }

        .directory-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 32px;
            flex-wrap: wrap;
            gap: 20px;
        }

        .directory-title {
            font-size: 28px;
            font-weight: 600;
            color: #e2e8f0;
        }

        .filters-container {
            display: flex;
            gap: 16px;
            align-items: center;
            flex-wrap: wrap;
        }

        .search-input {
            padding: 12px 20px;
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.4);
            border-radius: 8px;
            color: #e2e8f0;
            font-size: 14px;
            font-family: 'Inter', sans-serif;
            min-width: 250px;
            outline: none;
            transition: all 0.2s ease;
        }

        .search-input::placeholder {
            color: #64748b;
        }

        .search-input:focus {
            background: rgba(30, 41, 59, 0.8);
            border-color: #3b82f6;
        }

        .filter-select {
            padding: 12px 40px 12px 20px;
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.4);
            border-radius: 8px;
            color: #e2e8f0;
            font-size: 14px;
            font-family: 'Inter', sans-serif;
            cursor: pointer;
            outline: none;
            transition: all 0.2s ease;
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg width='12' height='8' viewBox='0 0 12 8' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 1L6 6L11 1' stroke='%2394a3b8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 16px center;
        }

        .filter-select:focus {
            background-color: rgba(30, 41, 59, 0.8);
            border-color: #3b82f6;
        }

        .filter-select option {
            background: #1e293b;
            color: #e2e8f0;
        }

        /* Statistics Banner */
        .stats-banner {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }

        .stat-card {
            padding: 20px;
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.3);
            border-radius: 12px;
            text-align: center;
        }

        .stat-value {
            font-size: 32px;
            font-weight: 700;
            color: #60a5fa;
            margin-bottom: 8px;
        }

        .stat-label {
            font-size: 13px;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* Table Styles */
        .employee-table {
            width: 100%;
            border-collapse: collapse;
        }

        .employee-table thead {
            border-bottom: 1px solid rgba(71, 85, 105, 0.4);
        }

        .employee-table th {
            padding: 16px;
            text-align: left;
            font-size: 13px;
            font-weight: 600;
            color: #60a5fa;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .employee-table td {
            padding: 20px 16px;
            border-bottom: 1px solid rgba(71, 85, 105, 0.2);
            font-size: 15px;
            color: #e2e8f0;
        }

        .employee-table tbody tr {
            transition: all 0.2s ease;
            cursor: pointer;
        }

        .employee-table tbody tr:hover {
            background: rgba(59, 130, 246, 0.05);
        }

        .status-badge {
            display: inline-block;
            padding: 6px 16px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .status-badge.ready {
            background: rgba(34, 197, 94, 0.15);
            color: #4ade80;
            border: 1px solid rgba(34, 197, 94, 0.3);
        }

        .status-badge.not-ready {
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .details-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 4px 12px;
            background: rgba(100, 116, 139, 0.15);
            border: 1px solid rgba(100, 116, 139, 0.3);
            border-radius: 6px;
            font-size: 12px;
            color: #94a3b8;
            margin-right: 8px;
        }

        .details-badge.warning {
            background: rgba(251, 146, 60, 0.15);
            border-color: rgba(251, 146, 60, 0.3);
            color: #fb923c;
        }

        .no-results {
            text-align: center;
            padding: 48px;
            color: #94a3b8;
            font-size: 16px;
        }

        /* Responsive Design */
        @media (max-width: 1024px) {
            .sidebar {
                width: 240px;
            }

            .main-content {
                margin-left: 240px;
                padding: 24px 32px;
            }
        }

        @media (max-width: 768px) {
            .sidebar {
                width: 100%;
                position: relative;
                height: auto;
                border-right: none;
                border-bottom: 1px solid rgba(71, 85, 105, 0.3);
            }

            .main-content {
                margin-left: 0;
                padding: 20px;
            }

            .container {
                flex-direction: column;
            }

            .header {
                flex-direction: column;
                align-items: flex-start;
            }

            .header-actions {
                width: 100%;
                justify-content: space-between;
            }

            .directory-header {
                flex-direction: column;
                align-items: flex-start;
            }

            .filters-container {
                width: 100%;
                flex-direction: column;
            }

            .search-input,
            .filter-select {
                width: 100%;
            }

            .employee-table {
                font-size: 14px;
            }

            .employee-table th,
            .employee-table td {
                padding: 12px 8px;
            }
        }

        /* Loading Animation */
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .employee-table tbody tr {
            animation: fadeIn 0.4s ease-out forwards;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Sidebar -->
        <aside class="sidebar">
            <div class="logo">
                <h1>AMC HR</h1>
                <span class="role-badge">Supervisor</span>
            </div>
            <nav>
                <ul class="nav-menu">
                    <li class="nav-item">
                        <a href="sup-dashboard.php" class="nav-link">
                            <span class="nav-icon">📊</span>
                            <span>Dashboard</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="sup-workforce_ready.php" class="nav-link active">
                            <span class="nav-icon">👥</span>
                            <span>Workforce Ready</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="sup-training_due.php" class="nav-link">
                            <span class="nav-icon">🎓</span>
                            <span>Training Due</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="sup-expired_certs.php" class="nav-link">
                            <span class="nav-icon">📜</span>
                            <span>Expired Certs</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="sup-pending_leave.php" class="nav-link">
                            <span class="nav-icon">📅</span>
                            <span>Pending Leave</span>
                        </a>
                    </li>
                </ul>
            </nav>
        </aside>

        <!-- Main Content -->
        <main class="main-content">
            <!-- Header -->
            <header class="header">
                <div class="welcome-section">
                    <h2>Workforce Readiness</h2>
                    <p>Monitor staff training completion and certification status</p>
                </div>
                <div class="header-actions">
                    <div class="user-info">
                        <span><strong><?php echo htmlspecialchars($username); ?></strong></span>
                        <span style="text-transform: capitalize;"><?php echo htmlspecialchars($role); ?></span>
                    </div>
                    <a href="?logout=1" class="logout-btn">Logout</a>
                </div>
            </header>

            <!-- Statistics Banner -->
            <div class="stats-banner">
                <?php
                $total_staff = count($employees);
                $ready_count = count(array_filter($employees, fn($e) => $e['readiness_status'] === 'READY'));
                $not_ready_count = $total_staff - $ready_count;
                $ready_percentage = $total_staff > 0 ? round(($ready_count / $total_staff) * 100) : 0;
                ?>
                <div class="stat-card">
                    <div class="stat-value"><?php echo $total_staff; ?></div>
                    <div class="stat-label">Total Staff</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #4ade80;"><?php echo $ready_count; ?></div>
                    <div class="stat-label">Ready</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #f87171;"><?php echo $not_ready_count; ?></div>
                    <div class="stat-label">Not Ready</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value"><?php echo $ready_percentage; ?>%</div>
                    <div class="stat-label">Readiness Rate</div>
                </div>
            </div>

            <!-- Directory Section -->
            <section class="directory-section">
                <div class="directory-header">
                    <h2 class="directory-title">Staff Directory</h2>
                    
                    <form method="GET" class="filters-container">
                        <input 
                            type="text" 
                            name="search" 
                            class="search-input" 
                            placeholder="Search Name or Role..."
                            value="<?php echo htmlspecialchars($search_query); ?>"
                        >
                        
                        <select name="department" class="filter-select" onchange="this.form.submit()">
                            <option value="all" <?php echo $department_filter === 'all' ? 'selected' : ''; ?>>All Departments</option>
                            <?php foreach ($departments as $dept): ?>
                            <option value="<?php echo htmlspecialchars($dept); ?>" <?php echo $department_filter === $dept ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($dept); ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                        
                        <select name="status" class="filter-select" onchange="this.form.submit()">
                            <option value="all" <?php echo $status_filter === 'all' ? 'selected' : ''; ?>>All Statuses</option>
                            <option value="READY" <?php echo $status_filter === 'READY' ? 'selected' : ''; ?>>Ready</option>
                            <option value="NOT READY" <?php echo $status_filter === 'NOT READY' ? 'selected' : ''; ?>>Not Ready</option>
                        </select>
                    </form>
                </div>

                <?php if (count($employees) > 0): ?>
                <table class="employee-table">
                    <thead>
                        <tr>
                            <th>EMPLOYEE NAME</th>
                            <th>DEPARTMENT</th>
                            <th>ROLE</th>
                            <th>DETAILS</th>
                            <th>READINESS STATUS</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($employees as $employee): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($employee['name']); ?></td>
                            <td><?php echo htmlspecialchars($employee['department_name'] ?? 'N/A'); ?></td>
                            <td><?php echo htmlspecialchars($employee['job_title']); ?></td>
                            <td>
                                <?php if ($employee['pending_training'] > 0): ?>
                                <span class="details-badge warning">
                                    🎓 <?php echo $employee['pending_training']; ?> Training Pending
                                </span>
                                <?php endif; ?>
                                <?php if ($employee['expired_certs'] > 0): ?>
                                <span class="details-badge warning">
                                    📜 <?php echo $employee['expired_certs']; ?> Cert Expired
                                </span>
                                <?php endif; ?>
                                <?php if ($employee['pending_training'] == 0 && $employee['expired_certs'] == 0): ?>
                                <span class="details-badge">✓ All Clear</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <span class="status-badge <?php echo strtolower(str_replace(' ', '-', $employee['readiness_status'])); ?>">
                                    <?php echo htmlspecialchars($employee['readiness_status']); ?>
                                </span>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                <?php else: ?>
                <div class="no-results">
                    No employees found matching your search criteria.
                </div>
                <?php endif; ?>
            </section>
        </main>
    </div>
</body>
</html>