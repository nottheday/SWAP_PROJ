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

// Check if user is logged in and is an admin
if (!isset($_SESSION['auth']) || !isset($_SESSION['user']) || !isset($_SESSION['role'])) {
    header('Location: login.php');
    exit;
}

// Verify user is an admin
if ($_SESSION['role'] !== 'admin') {
    http_response_code(403);
    die("Access Denied: This page is for administrators only. Your role: " . $_SESSION['role']);
}

// Get user information from session
$username = $_SESSION['user'];
$role = $_SESSION['role'];

// Get admin details
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

// Get system statistics
// Total users by role
$users_stats = $mysqli->query("
    SELECT 
        r.name as role_name,
        COUNT(u.id) as count
    FROM users u
    JOIN role r ON u.role_id = r.id
    WHERE u.status = 'active'
    GROUP BY r.name
");
$users_by_role = [];
while ($row = $users_stats->fetch_assoc()) {
    $users_by_role[$row['role_name']] = $row['count'];
}

// Total staff
$total_staff_query = $mysqli->query("SELECT COUNT(*) as total FROM staff WHERE status = 'active'");
$total_staff = $total_staff_query->fetch_assoc()['total'];

// Total departments
$total_depts_query = $mysqli->query("SELECT COUNT(*) as total FROM department");
$total_depts = $total_depts_query->fetch_assoc()['total'];

// Pending leave applications
$pending_leave_query = $mysqli->query("SELECT COUNT(*) as total FROM leave_application WHERE status = 'pending'");
$pending_leave = $pending_leave_query->fetch_assoc()['total'];

// Pending training
$pending_training_query = $mysqli->query("SELECT COUNT(*) as total FROM training_attendance WHERE status = 'pending'");
$pending_training = $pending_training_query->fetch_assoc()['total'];

// Expired certifications
$expired_certs_query = $mysqli->query("SELECT COUNT(*) as total FROM staff_certification WHERE expiry_date < CURDATE()");
$expired_certs = $expired_certs_query->fetch_assoc()['total'];

// Recent login activity (last 10)
$recent_logins = $mysqli->query("
    SELECT 
        username,
        ip,
        success,
        time
    FROM login_audit
    ORDER BY time DESC
    LIMIT 10
");

// System alerts (critical items requiring attention)
$alerts = [];

// Check for critical expired certs (90+ days)
$critical_certs = $mysqli->query("
    SELECT COUNT(*) as count 
    FROM staff_certification 
    WHERE expiry_date < DATE_SUB(CURDATE(), INTERVAL 90 DAY)
")->fetch_assoc()['count'];
if ($critical_certs > 0) {
    $alerts[] = [
        'type' => 'critical',
        'icon' => '⚠️',
        'message' => "$critical_certs certifications expired over 90 days ago",
        'link' => 'admin-certifications.php'
    ];
}

// Check for failed login attempts
$failed_logins = $mysqli->query("
    SELECT COUNT(*) as count 
    FROM login_audit 
    WHERE success = 0 AND time > DATE_SUB(NOW(), INTERVAL 24 HOUR)
")->fetch_assoc()['count'];
if ($failed_logins > 10) {
    $alerts[] = [
        'type' => 'warning',
        'icon' => '🔒',
        'message' => "$failed_logins failed login attempts in last 24 hours",
        'link' => 'admin-security.php'
    ];
}

// Check for old pending leave requests (30+ days)
$old_pending = $mysqli->query("
    SELECT COUNT(*) as count 
    FROM leave_application 
    WHERE status = 'pending' AND start_date < DATE_SUB(CURDATE(), INTERVAL 30 DAY)
")->fetch_assoc()['count'];
if ($old_pending > 0) {
    $alerts[] = [
        'type' => 'warning',
        'icon' => '📅',
        'message' => "$old_pending leave requests pending over 30 days",
        'link' => 'admin-leave.php'
    ];
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
    <title>AMC HR - Admin Dashboard</title>
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
            background: rgba(168, 85, 247, 0.2);
            border: 1px solid rgba(168, 85, 247, 0.3);
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            color: #c084fc;
            text-transform: uppercase;
        }

        .nav-menu {
            list-style: none;
        }

        .nav-section-title {
            padding: 8px 32px;
            font-size: 11px;
            font-weight: 700;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 24px;
            margin-bottom: 8px;
        }

        .nav-item {
            margin-bottom: 4px;
        }

        .nav-link {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 32px;
            color: #94a3b8;
            text-decoration: none;
            font-size: 14px;
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
            font-size: 18px;
            width: 20px;
            text-align: center;
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
            font-size: 32px;
            font-weight: 700;
            color: #e2e8f0;
            margin-bottom: 8px;
        }

        .welcome-section p {
            font-size: 15px;
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
            color: #c084fc;
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

        /* Alert Section */
        .alerts-section {
            margin-bottom: 32px;
        }

        .alert-card {
            padding: 16px 20px;
            border-radius: 12px;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 16px;
            text-decoration: none;
            transition: all 0.2s ease;
        }

        .alert-card.critical {
            background: rgba(127, 29, 29, 0.3);
            border: 1px solid rgba(239, 68, 68, 0.5);
        }

        .alert-card.warning {
            background: rgba(113, 63, 18, 0.3);
            border: 1px solid rgba(251, 146, 60, 0.5);
        }

        .alert-card:hover {
            transform: translateX(4px);
        }

        .alert-icon {
            font-size: 24px;
        }

        .alert-message {
            flex: 1;
            font-size: 14px;
            font-weight: 500;
        }

        .alert-card.critical .alert-message {
            color: #fca5a5;
        }

        .alert-card.warning .alert-message {
            color: #fdba74;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 24px;
            margin-bottom: 48px;
        }

        .stat-card {
            padding: 28px;
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.3);
            border-radius: 16px;
            transition: all 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 12px 32px rgba(0, 0, 0, 0.4);
            border-color: rgba(96, 165, 250, 0.5);
        }

        .stat-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }

        .stat-label {
            font-size: 13px;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }

        .stat-icon {
            font-size: 24px;
            opacity: 0.7;
        }

        .stat-value {
            font-size: 36px;
            font-weight: 700;
            color: #60a5fa;
            line-height: 1;
        }

        /* Quick Actions */
        .quick-actions {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 48px;
        }

        .action-btn {
            padding: 20px;
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.3);
            border-radius: 12px;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 12px;
            transition: all 0.2s ease;
        }

        .action-btn:hover {
            background: rgba(59, 130, 246, 0.2);
            border-color: rgba(59, 130, 246, 0.5);
            transform: translateY(-2px);
        }

        .action-icon {
            font-size: 24px;
        }

        .action-text {
            font-size: 14px;
            font-weight: 600;
            color: #e2e8f0;
        }

        /* Recent Activity */
        .activity-section {
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.3);
            border-radius: 16px;
            padding: 32px;
        }

        .section-title {
            font-size: 20px;
            font-weight: 600;
            color: #e2e8f0;
            margin-bottom: 24px;
        }

        .activity-table {
            width: 100%;
            border-collapse: collapse;
        }

        .activity-table th {
            text-align: left;
            padding: 12px;
            font-size: 12px;
            font-weight: 600;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid rgba(71, 85, 105, 0.3);
        }

        .activity-table td {
            padding: 16px 12px;
            font-size: 14px;
            color: #cbd5e1;
            border-bottom: 1px solid rgba(71, 85, 105, 0.2);
        }

        .activity-table tbody tr:hover {
            background: rgba(59, 130, 246, 0.05);
        }

        .status-dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 8px;
        }

        .status-dot.success {
            background: #22c55e;
        }

        .status-dot.failed {
            background: #ef4444;
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

            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
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

            .stats-grid,
            .quick-actions {
                grid-template-columns: 1fr;
            }
        }

        /* Loading Animation */
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .stat-card {
            animation: fadeIn 0.6s ease-out forwards;
        }

        .stat-card:nth-child(1) { animation-delay: 0.1s; }
        .stat-card:nth-child(2) { animation-delay: 0.2s; }
        .stat-card:nth-child(3) { animation-delay: 0.3s; }
        .stat-card:nth-child(4) { animation-delay: 0.4s; }
        .stat-card:nth-child(5) { animation-delay: 0.5s; }
        .stat-card:nth-child(6) { animation-delay: 0.6s; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Sidebar -->
        <aside class="sidebar">
            <div class="logo">
                <h1>AMC HR</h1>
                <span class="role-badge">Administrator</span>
            </div>
            <nav>
                <ul class="nav-menu">
                    <li class="nav-item">
                        <a href="admin-dashboard.php" class="nav-link active">
                            <span class="nav-icon">📊</span>
                            <span>Dashboard</span>
                        </a>
                    </li>
                    
                    <li class="nav-section-title">User Management</li>
                    <li class="nav-item">
                        <a href="admin-users.php" class="nav-link">
                            <span class="nav-icon">👥</span>
                            <span>Manage Users</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="admin-staff.php" class="nav-link">
                            <span class="nav-icon">👤</span>
                            <span>Staff Directory</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="admin-departments.php" class="nav-link">
                            <span class="nav-icon">🏢</span>
                            <span>Departments</span>
                        </a>
                    </li>
                    
                    <li class="nav-section-title">Operations</li>
                    <li class="nav-item">
                        <a href="admin-leave.php" class="nav-link">
                            <span class="nav-icon">📅</span>
                            <span>Leave Management</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="admin-training.php" class="nav-link">
                            <span class="nav-icon">🎓</span>
                            <span>Training Programs</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="admin-certifications.php" class="nav-link">
                            <span class="nav-icon">📜</span>
                            <span>Certifications</span>
                        </a>
                    </li>
                    
                    <li class="nav-section-title">System</li>
                    <li class="nav-item">
                        <a href="admin-reports.php" class="nav-link">
                            <span class="nav-icon">📈</span>
                            <span>Reports</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="admin-security.php" class="nav-link">
                            <span class="nav-icon">🔒</span>
                            <span>Security & Logs</span>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="admin-settings.php" class="nav-link">
                            <span class="nav-icon">⚙️</span>
                            <span>System Settings</span>
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
                    <h2>Welcome back, <?php echo htmlspecialchars($admin_name ?? $username); ?></h2>
                    <p>System Administrator Dashboard</p>
                </div>
                <div class="header-actions">
                    <div class="user-info">
                        <span><strong><?php echo htmlspecialchars($username); ?></strong></span>
                        <span style="text-transform: capitalize;"><?php echo htmlspecialchars($role); ?></span>
                    </div>
                    <a href="?logout=1" class="logout-btn">Logout</a>
                </div>
            </header>

            <!-- System Alerts -->
            <?php if (count($alerts) > 0): ?>
            <div class="alerts-section">
                <?php foreach ($alerts as $alert): ?>
                <a href="<?php echo $alert['link']; ?>" class="alert-card <?php echo $alert['type']; ?>">
                    <span class="alert-icon"><?php echo $alert['icon']; ?></span>
                    <span class="alert-message"><?php echo $alert['message']; ?></span>
                    <span style="color: #64748b;">→</span>
                </a>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>

            <!-- Statistics Grid -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-label">Total Staff</span>
                        <span class="stat-icon">👥</span>
                    </div>
                    <div class="stat-value"><?php echo $total_staff; ?></div>
                </div>

                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-label">Departments</span>
                        <span class="stat-icon">🏢</span>
                    </div>
                    <div class="stat-value"><?php echo $total_depts; ?></div>
                </div>

                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-label">Admins</span>
                        <span class="stat-icon">👑</span>
                    </div>
                    <div class="stat-value"><?php echo $users_by_role['admin'] ?? 0; ?></div>
                </div>

                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-label">Supervisors</span>
                        <span class="stat-icon">👔</span>
                    </div>
                    <div class="stat-value"><?php echo $users_by_role['supervisor'] ?? 0; ?></div>
                </div>

                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-label">Pending Leave</span>
                        <span class="stat-icon">📅</span>
                    </div>
                    <div class="stat-value" style="color: #fbbf24;"><?php echo $pending_leave; ?></div>
                </div>

                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-label">Expired Certs</span>
                        <span class="stat-icon">⚠️</span>
                    </div>
                    <div class="stat-value" style="color: #f87171;"><?php echo $expired_certs; ?></div>
                </div>
            </div>

            <!-- Quick Actions -->
            <div class="quick-actions">
                <a href="admin-users.php?action=add" class="action-btn">
                    <span class="action-icon">➕</span>
                    <span class="action-text">Add New User</span>
                </a>
                <a href="admin-staff.php?action=add" class="action-btn">
                    <span class="action-icon">👤</span>
                    <span class="action-text">Add Staff Member</span>
                </a>
                <a href="admin-training.php?action=create" class="action-btn">
                    <span class="action-icon">🎓</span>
                    <span class="action-text">Create Training</span>
                </a>
                <a href="admin-reports.php" class="action-btn">
                    <span class="action-icon">📊</span>
                    <span class="action-text">Generate Report</span>
                </a>
            </div>

            <!-- Recent Login Activity -->
            <div class="activity-section">
                <h3 class="section-title">Recent Login Activity</h3>
                <table class="activity-table">
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>Username</th>
                            <th>IP Address</th>
                            <th>Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($login = $recent_logins->fetch_assoc()): ?>
                        <tr>
                            <td>
                                <span class="status-dot <?php echo $login['success'] ? 'success' : 'failed'; ?>"></span>
                                <?php echo $login['success'] ? 'Success' : 'Failed'; ?>
                            </td>
                            <td><?php echo htmlspecialchars($login['username']); ?></td>
                            <td><?php echo htmlspecialchars($login['ip']); ?></td>
                            <td><?php echo date('M d, Y H:i', strtotime($login['time'])); ?></td>
                        </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </main>
    </div>
</body>
</html>