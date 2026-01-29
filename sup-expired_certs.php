<?php
session_start();

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

// Handle filters
$name_filter = $_GET['name'] ?? '';
$cert_filter = $_GET['cert'] ?? '';
$urgency_filter = $_GET['urgency'] ?? 'all';

// Build query to get expired certifications
$query = "
    SELECT 
        sc.id as cert_id,
        s.id as staff_id,
        s.name as employee_name,
        d.name as department_name,
        sc.name as cert_name,
        sc.issue_date,
        sc.expiry_date,
        DATEDIFF(CURDATE(), sc.expiry_date) as days_expired,
        CASE 
            WHEN DATEDIFF(CURDATE(), sc.expiry_date) > 90 THEN 'CRITICAL'
            WHEN DATEDIFF(CURDATE(), sc.expiry_date) > 30 THEN 'HIGH'
            ELSE 'MEDIUM'
        END as urgency
    FROM staff_certification sc
    JOIN staff s ON sc.staff_id = s.id
    LEFT JOIN department d ON s.department_id = d.id
    WHERE sc.expiry_date < CURDATE() AND s.status = 'active'
";

// Add filters
if (!empty($name_filter)) {
    $query .= " AND s.name LIKE ?";
}
if (!empty($cert_filter)) {
    $query .= " AND sc.name LIKE ?";
}

$query .= " ORDER BY sc.expiry_date ASC";

// Prepare statement
$stmt = $mysqli->prepare($query);

// Bind parameters
$params = [];
$types = "";

if (!empty($name_filter)) {
    $name_param = "%{$name_filter}%";
    $params[] = &$name_param;
    $types .= "s";
}
if (!empty($cert_filter)) {
    $cert_param = "%{$cert_filter}%";
    $params[] = &$cert_param;
    $types .= "s";
}

if (!empty($params)) {
    array_unshift($params, $types);
    call_user_func_array(array($stmt, 'bind_param'), $params);
}

$stmt->execute();
$result = $stmt->get_result();

// Fetch all expired certifications
$expired_certs = [];
while ($row = $result->fetch_assoc()) {
    $expired_certs[] = $row;
}
$stmt->close();

// Apply urgency filter
if ($urgency_filter !== 'all') {
    $expired_certs = array_filter($expired_certs, function($cert) use ($urgency_filter) {
        return $cert['urgency'] === $urgency_filter;
    });
}

// Get unique departments
$dept_query = "SELECT DISTINCT name FROM department ORDER BY name";
$dept_result = $mysqli->query($dept_query);
$departments = [];
while ($dept = $dept_result->fetch_assoc()) {
    $departments[] = $dept['name'];
}

// Handle renew action
if (isset($_POST['renew'])) {
    $cert_id = $_POST['cert_id'];
    $employee = $_POST['employee_name'];
    
    // In a real system, this would create a renewal task or update the certification
    $success_message = "Renewal process initiated for $employee's certification.";
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
    <title>AMC HR - Expired Certifications</title>
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

        /* Cert Table */
        .cert-table {
            width: 100%;
            border-collapse: collapse;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.3);
            border-radius: 12px;
            overflow: hidden;
        }

        .cert-table thead {
            background: rgba(30, 41, 59, 0.8);
            border-bottom: 1px solid rgba(71, 85, 105, 0.4);
        }

        .cert-table th {
            padding: 16px;
            text-align: left;
            font-size: 13px;
            font-weight: 600;
            color: #60a5fa;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .cert-table td {
            padding: 20px 16px;
            border-bottom: 1px solid rgba(71, 85, 105, 0.2);
            font-size: 15px;
            color: #e2e8f0;
        }

        .cert-table tbody tr {
            transition: all 0.2s ease;
        }

        .cert-table tbody tr:hover {
            background: rgba(59, 130, 246, 0.05);
        }

        .cert-table tbody tr:last-child td {
            border-bottom: none;
        }

        .urgency-badge {
            display: inline-block;
            padding: 6px 16px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .urgency-badge.critical {
            background: rgba(127, 29, 29, 0.3);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.5);
        }

        .urgency-badge.high {
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .urgency-badge.medium {
            background: rgba(251, 146, 60, 0.15);
            color: #fb923c;
            border: 1px solid rgba(251, 146, 60, 0.3);
        }

        .renew-btn {
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

        .renew-btn:hover {
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
            transform: translateY(-1px);
        }

        .renew-btn:active {
            transform: translateY(0);
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

            .cert-table {
                font-size: 14px;
            }

            .cert-table th,
            .cert-table td {
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

        .cert-table tbody tr {
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
                        <a href="sup-training_due.php" class="nav-link">
                            <span class="nav-icon">🎓</span>
                            <span>Training Due</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="sup-expired_certs.php" class="nav-link active">
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
                    <h2>Expired Certifications</h2>
                    <p>Track and manage expired staff certifications</p>
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

            <!-- Statistics Banner -->
            <div class="stats-banner">
                <?php
                $total_expired = count($expired_certs);
                $critical = count(array_filter($expired_certs, fn($c) => $c['urgency'] === 'CRITICAL'));
                $high = count(array_filter($expired_certs, fn($c) => $c['urgency'] === 'HIGH'));
                $medium = count(array_filter($expired_certs, fn($c) => $c['urgency'] === 'MEDIUM'));
                ?>
                <div class="stat-card">
                    <div class="stat-value"><?php echo $total_expired; ?></div>
                    <div class="stat-label">Total Expired</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #fca5a5;"><?php echo $critical; ?></div>
                    <div class="stat-label">Critical (90+ days)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #f87171;"><?php echo $high; ?></div>
                    <div class="stat-label">High (30-90 days)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #fb923c;"><?php echo $medium; ?></div>
                    <div class="stat-label">Medium (< 30 days)</div>
                </div>
            </div>

            <!-- Filter Section -->
            <div class="filter-section">
                <form method="GET" class="filter-grid">
                    <div class="filter-group">
                        <label class="filter-label">Employee Name</label>
                        <input 
                            type="text" 
                            name="name" 
                            class="filter-input" 
                            placeholder="Search employee..."
                            value="<?php echo htmlspecialchars($name_filter); ?>"
                        >
                    </div>

                    <div class="filter-group">
                        <label class="filter-label">Certification</label>
                        <input 
                            type="text" 
                            name="cert" 
                            class="filter-input" 
                            placeholder="Search certification..."
                            value="<?php echo htmlspecialchars($cert_filter); ?>"
                        >
                    </div>

                    <div class="filter-group">
                        <label class="filter-label">Urgency</label>
                        <select name="urgency" class="filter-select" onchange="this.form.submit()">
                            <option value="all" <?php echo $urgency_filter === 'all' ? 'selected' : ''; ?>>All</option>
                            <option value="CRITICAL" <?php echo $urgency_filter === 'CRITICAL' ? 'selected' : ''; ?>>Critical</option>
                            <option value="HIGH" <?php echo $urgency_filter === 'HIGH' ? 'selected' : ''; ?>>High</option>
                            <option value="MEDIUM" <?php echo $urgency_filter === 'MEDIUM' ? 'selected' : ''; ?>>Medium</option>
                        </select>
                    </div>
                </form>
            </div>

            <!-- Certifications Table -->
            <?php if (count($expired_certs) > 0): ?>
            <table class="cert-table">
                <thead>
                    <tr>
                        <th>EMPLOYEE NAME</th>
                        <th>DEPARTMENT</th>
                        <th>CERTIFICATION</th>
                        <th>EXPIRED DATE</th>
                        <th>DAYS OVERDUE</th>
                        <th>URGENCY</th>
                        <th>ACTION</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($expired_certs as $cert): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($cert['employee_name']); ?></td>
                        <td><?php echo htmlspecialchars($cert['department_name'] ?? 'N/A'); ?></td>
                        <td><?php echo htmlspecialchars($cert['cert_name']); ?></td>
                        <td><?php echo date('M d, Y', strtotime($cert['expiry_date'])); ?></td>
                        <td><?php echo $cert['days_expired']; ?> days</td>
                        <td>
                            <span class="urgency-badge <?php echo strtolower($cert['urgency']); ?>">
                                <?php echo htmlspecialchars($cert['urgency']); ?>
                            </span>
                        </td>
                        <td>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="cert_id" value="<?php echo $cert['cert_id']; ?>">
                                <input type="hidden" name="employee_name" value="<?php echo htmlspecialchars($cert['employee_name']); ?>">
                                <button type="submit" name="renew" class="renew-btn">Initiate Renewal</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php else: ?>
            <div class="no-results">
                No expired certifications found matching your filters.
            </div>
            <?php endif; ?>
        </main>
    </div>
</body>
</html>