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

// Handle filters
$employee_filter = $_GET['employee'] ?? '';
$course_filter = $_GET['course'] ?? '';
$priority_filter = $_GET['priority'] ?? 'all';
$date_filter = $_GET['date'] ?? '';

// Build query to get training due (pending training attendance)
$query = "
    SELECT 
        s.id as staff_id,
        s.name as employee_name,
        ts.name as course_title,
        ts.description as course_description,
        ts.start_date as due_date,
        ts.end_date,
        ta.status,
        CASE 
            WHEN ts.start_date <= DATE_ADD(CURDATE(), INTERVAL 7 DAY) THEN 'HIGH'
            ELSE 'NORMAL'
        END as priority
    FROM training_attendance ta
    JOIN staff s ON ta.staff_id = s.id
    JOIN training_sessions ts ON ta.training_sessions_id = ts.id
    WHERE ta.status = 'pending' AND s.status = 'active'
";

// Add filters
if (!empty($employee_filter)) {
    $query .= " AND s.name LIKE ?";
}
if (!empty($course_filter)) {
    $query .= " AND ts.name LIKE ?";
}
if (!empty($date_filter)) {
    $query .= " AND DATE_FORMAT(ts.start_date, '%Y-%m') = ?";
}

$query .= " ORDER BY ts.start_date ASC, s.name ASC";

// Prepare statement
$stmt = $mysqli->prepare($query);

// Bind parameters dynamically
$params = [];
$types = "";

if (!empty($employee_filter)) {
    $employee_param = "%{$employee_filter}%";
    $params[] = &$employee_param;
    $types .= "s";
}
if (!empty($course_filter)) {
    $course_param = "%{$course_filter}%";
    $params[] = &$course_param;
    $types .= "s";
}
if (!empty($date_filter)) {
    $params[] = &$date_filter;
    $types .= "s";
}

if (!empty($params)) {
    array_unshift($params, $types);
    call_user_func_array(array($stmt, 'bind_param'), $params);
}

$stmt->execute();
$result = $stmt->get_result();

// Fetch all training requirements
$training_requirements = [];
while ($row = $result->fetch_assoc()) {
    $training_requirements[] = $row;
}
$stmt->close();

// Apply priority filter after fetching
if ($priority_filter !== 'all') {
    $training_requirements = array_filter($training_requirements, function($training) use ($priority_filter) {
        return $training['priority'] === $priority_filter;
    });
}

// Handle enrollment/completion action
if (isset($_POST['mark_complete'])) {
    $staff_id = $_POST['staff_id'];
    $training_id = $_POST['training_id'];
    
    $update_stmt = $mysqli->prepare("
        UPDATE training_attendance 
        SET status = 'completed', completion_date = CURDATE() 
        WHERE staff_id = ? AND training_sessions_id = ?
    ");
    $update_stmt->bind_param("ii", $staff_id, $training_id);
    
    if ($update_stmt->execute()) {
        $success_message = "Training marked as completed successfully!";
    } else {
        $error_message = "Failed to update training status.";
    }
    $update_stmt->close();
    
    // Refresh the page to show updated data
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
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
    <title>AMC HR - Training Due</title>
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

        /* Filter Section */
        .filter-section {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.3);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 32px;
        }

        .filter-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 16px;
        }

        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .filter-label {
            font-size: 13px;
            font-weight: 600;
            color: #60a5fa;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .filter-input,
        .filter-select {
            padding: 12px 16px;
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.4);
            border-radius: 8px;
            color: #e2e8f0;
            font-size: 14px;
            font-family: 'Inter', sans-serif;
            outline: none;
            transition: all 0.2s ease;
        }

        .filter-input::placeholder {
            color: #64748b;
        }

        .filter-input:focus,
        .filter-select:focus {
            background: rgba(30, 41, 59, 0.8);
            border-color: #3b82f6;
        }

        .filter-select {
            cursor: pointer;
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg width='12' height='8' viewBox='0 0 12 8' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 1L6 6L11 1' stroke='%2394a3b8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 16px center;
            padding-right: 40px;
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

        /* Training Table */
        .training-table {
            width: 100%;
            border-collapse: collapse;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.3);
            border-radius: 12px;
            overflow: hidden;
        }

        .training-table thead {
            background: rgba(30, 41, 59, 0.8);
            border-bottom: 1px solid rgba(71, 85, 105, 0.4);
        }

        .training-table th {
            padding: 16px;
            text-align: left;
            font-size: 13px;
            font-weight: 600;
            color: #60a5fa;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .training-table td {
            padding: 20px 16px;
            border-bottom: 1px solid rgba(71, 85, 105, 0.2);
            font-size: 15px;
            color: #e2e8f0;
        }

        .training-table tbody tr {
            transition: all 0.2s ease;
        }

        .training-table tbody tr:hover {
            background: rgba(59, 130, 246, 0.05);
        }

        .training-table tbody tr:last-child td {
            border-bottom: none;
        }

        .priority-badge {
            display: inline-block;
            padding: 6px 16px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .priority-badge.high {
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .priority-badge.normal {
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }

        .action-btn {
            padding: 10px 20px;
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            border: none;
            border-radius: 8px;
            color: #ffffff;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 2px 8px rgba(59, 130, 246, 0.3);
        }

        .action-btn:hover {
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
            transform: translateY(-1px);
        }

        .action-btn:active {
            transform: translateY(0);
        }

        .success-message {
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            color: #86efac;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            text-align: center;
        }

        .error-message {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fca5a5;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            text-align: center;
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

            .filter-grid {
                grid-template-columns: 1fr;
            }

            .training-table {
                font-size: 14px;
            }

            .training-table th,
            .training-table td {
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

        .training-table tbody tr {
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
                        <a href="sup-workforce_ready.php" class="nav-link">
                            <span class="nav-icon">👥</span>
                            <span>Workforce Ready</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="sup-training.php" class="nav-link active">
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
                    <h2>Training Due</h2>
                    <p>Monitor and manage pending training requirements</p>
                </div>
                <div class="header-actions">
                    <div class="user-info">
                        <span><strong><?php echo htmlspecialchars($username); ?></strong></span>
                        <span style="text-transform: capitalize;"><?php echo htmlspecialchars($role); ?></span>
                    </div>
                    <a href="?logout=1" class="logout-btn">Logout</a>
                </div>
            </header>

            <?php if (isset($success_message)): ?>
                <div class="success-message"><?php echo htmlspecialchars($success_message); ?></div>
            <?php endif; ?>

            <?php if (isset($error_message)): ?>
                <div class="error-message"><?php echo htmlspecialchars($error_message); ?></div>
            <?php endif; ?>

            <!-- Statistics Banner -->
            <div class="stats-banner">
                <?php
                $total_training = count($training_requirements);
                $high_priority = count(array_filter($training_requirements, fn($t) => $t['priority'] === 'HIGH'));
                $normal_priority = $total_training - $high_priority;
                ?>
                <div class="stat-card">
                    <div class="stat-value"><?php echo $total_training; ?></div>
                    <div class="stat-label">Total Pending</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #f87171;"><?php echo $high_priority; ?></div>
                    <div class="stat-label">High Priority</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #60a5fa;"><?php echo $normal_priority; ?></div>
                    <div class="stat-label">Normal Priority</div>
                </div>
            </div>

            <!-- Filter Section -->
            <div class="filter-section">
                <form method="GET" class="filter-grid">
                    <div class="filter-group">
                        <label class="filter-label">Employee</label>
                        <input 
                            type="text" 
                            name="employee" 
                            class="filter-input" 
                            placeholder="Search employee..."
                            value="<?php echo htmlspecialchars($employee_filter); ?>"
                        >
                    </div>

                    <div class="filter-group">
                        <label class="filter-label">Course Title</label>
                        <input 
                            type="text" 
                            name="course" 
                            class="filter-input" 
                            placeholder="Search course..."
                            value="<?php echo htmlspecialchars($course_filter); ?>"
                        >
                    </div>

                    <div class="filter-group">
                        <label class="filter-label">Priority</label>
                        <select name="priority" class="filter-select" onchange="this.form.submit()">
                            <option value="all" <?php echo $priority_filter === 'all' ? 'selected' : ''; ?>>All</option>
                            <option value="HIGH" <?php echo $priority_filter === 'HIGH' ? 'selected' : ''; ?>>High</option>
                            <option value="NORMAL" <?php echo $priority_filter === 'NORMAL' ? 'selected' : ''; ?>>Normal</option>
                        </select>
                    </div>

                    <div class="filter-group">
                        <label class="filter-label">Due Date (Month)</label>
                        <input 
                            type="month" 
                            name="date" 
                            class="filter-input" 
                            value="<?php echo htmlspecialchars($date_filter); ?>"
                            onchange="this.form.submit()"
                        >
                    </div>
                </form>
            </div>

            <!-- Training Table -->
            <?php if (count($training_requirements) > 0): ?>
            <table class="training-table">
                <thead>
                    <tr>
                        <th>EMPLOYEE NAME</th>
                        <th>REQUIRED COURSE</th>
                        <th>DUE DATE</th>
                        <th>PRIORITY</th>
                        <th>ACTION</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($training_requirements as $training): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($training['employee_name']); ?></td>
                        <td>
                            <strong><?php echo htmlspecialchars($training['course_title']); ?></strong>
                            <?php if (!empty($training['course_description'])): ?>
                            <br><small style="color: #94a3b8;"><?php echo htmlspecialchars($training['course_description']); ?></small>
                            <?php endif; ?>
                        </td>
                        <td><?php echo date('M d, Y', strtotime($training['due_date'])); ?></td>
                        <td>
                            <span class="priority-badge <?php echo strtolower($training['priority']); ?>">
                                <?php echo htmlspecialchars($training['priority']); ?>
                            </span>
                        </td>
                        <td>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="staff_id" value="<?php echo $training['staff_id']; ?>">
                                <input type="hidden" name="training_id" value="<?php echo $training['training_sessions_id'] ?? 0; ?>">
                                <button type="submit" name="mark_complete" class="action-btn">Mark Complete</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php else: ?>
            <div class="no-results">
                No pending training requirements found matching your filters.
            </div>
            <?php endif; ?>
        </main>
    </div>
</body>
</html>