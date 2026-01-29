<?php
session_start();

/*
  ASSUMPTION:
  - After login, you set:
    $_SESSION['user'] = username or employee_id
    $_SESSION['role'] = 'staff' or 'supervisor' (or 'admin')
*/

// Not logged in -> kick out
if (!isset($_SESSION['user']) || !isset($_SESSION['role'])) {
    header("Location: amc_hr_gateway.php");
    exit;
}

$currentRole = strtolower($_SESSION['role']);      // trusted
$urlRole     = isset($_GET['role']) ? strtolower(trim($_GET['role'])) : null;

// If role in URL is present and doesn't match session role -> tampering
if ($urlRole !== null && $urlRole !== $currentRole) {
    // Build same page URL WITHOUT the "role" parameter
    $query = $_GET;
    unset($query['role']);

    $base = strtok($_SERVER["REQUEST_URI"], '?');
    $cleanUrl = $base . (count($query) ? ('?' . http_build_query($query)) : '');

    // Reload same page + popup
    echo "<script>
        alert('Unauthorised Access Detected');
        window.location.replace(" . json_encode($cleanUrl) . ");
    </script>";
    exit;
}

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
    die("Access Denied: This page is for supervisors only. Your role: " . $_SESSION['role']);
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

// Calculate Workforce Ready Percentage
// Staff who have completed all required training and have no expired certifications
$workforce_query = "
    SELECT 
        COUNT(DISTINCT s.id) as total_staff,
        COUNT(DISTINCT CASE 
            WHEN NOT EXISTS (
                SELECT 1 FROM training_attendance ta
                WHERE ta.staff_id = s.id AND ta.status = 'pending'
            )
            AND NOT EXISTS (
                SELECT 1 FROM staff_certification sc
                WHERE sc.staff_id = s.id AND sc.expiry_date < CURDATE()
            )
            THEN s.id 
        END) as ready_staff
    FROM staff s
    WHERE s.status = 'active'
";
$result = $mysqli->query($workforce_query);
$workforce_data = $result->fetch_assoc();
$total_staff = $workforce_data['total_staff'] ?: 1;
$ready_staff = $workforce_data['ready_staff'] ?: 0;
$workforce_ready_percentage = round(($ready_staff / $total_staff) * 100);

// Count Training Due (pending training sessions)
$training_due_query = "
    SELECT COUNT(DISTINCT ta.id) as training_due
    FROM training_attendance ta
    WHERE ta.status = 'pending'
";
$result = $mysqli->query($training_due_query);
$training_data = $result->fetch_assoc();
$training_due = $training_data['training_due'] ?: 0;

// Count Expired Certifications
$expired_certs_query = "
    SELECT COUNT(*) as expired_certs
    FROM staff_certification
    WHERE expiry_date < CURDATE()
";
$result = $mysqli->query($expired_certs_query);
$cert_data = $result->fetch_assoc();
$expired_certs = $cert_data['expired_certs'] ?: 0;

// Count Pending Leave Applications
$pending_leave_query = "
    SELECT COUNT(*) as pending_leave
    FROM leave_application
    WHERE status = 'pending'
";
$result = $mysqli->query($pending_leave_query);
$leave_data = $result->fetch_assoc();
$pending_leave = $leave_data['pending_leave'] ?: 0;

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
    <title>AMC HR - Supervisor Dashboard</title>
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

        /* Metrics Cards */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 24px;
            margin-bottom: 48px;
        }

        .metric-card-link {
            text-decoration: none;
            display: block;
        }

        .metric-card {
            padding: 32px;
            border-radius: 16px;
            text-align: center;
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .metric-card-link:hover .metric-card {
            transform: translateY(-4px);
            box-shadow: 0 12px 32px rgba(0, 0, 0, 0.4);
        }

        .metric-card-link:active .metric-card {
            transform: translateY(-2px);
        }

        .metric-card.green {
            background: linear-gradient(135deg, #3d5a3d 0%, #2d4a2d 100%);
            border: 1px solid rgba(74, 222, 128, 0.2);
        }

        .metric-card.orange {
            background: linear-gradient(135deg, #5a4433 0%, #4a3423 100%);
            border: 1px solid rgba(251, 146, 60, 0.2);
        }

        .metric-card.red {
            background: linear-gradient(135deg, #5a3333 0%, #4a2323 100%);
            border: 1px solid rgba(248, 113, 113, 0.2);
        }

        .metric-card.blue {
            background: linear-gradient(135deg, #334155 0%, #283548 100%);
            border: 1px solid rgba(96, 165, 250, 0.2);
        }

        .metric-title {
            font-size: 18px;
            font-weight: 500;
            color: rgba(255, 255, 255, 0.8);
            margin-bottom: 16px;
        }

        .metric-value {
            font-size: 56px;
            font-weight: 700;
            color: #ffffff;
            line-height: 1;
        }

        /* System Overview Section */
        .overview-section {
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(71, 85, 105, 0.3);
            border-radius: 16px;
            padding: 32px;
        }

        .overview-title {
            font-size: 24px;
            font-weight: 600;
            color: #e2e8f0;
            margin-bottom: 16px;
        }

        .overview-text {
            font-size: 16px;
            line-height: 1.6;
            color: #94a3b8;
        }

        .overview-list {
            list-style: none;
            margin-top: 20px;
        }

        .overview-list li {
            padding: 12px 0;
            border-bottom: 1px solid rgba(71, 85, 105, 0.2);
            color: #cbd5e1;
        }

        .overview-list li:last-child {
            border-bottom: none;
        }

        .overview-list li strong {
            color: #60a5fa;
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

            .metrics-grid {
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

            .metrics-grid {
                grid-template-columns: 1fr;
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

        .metric-card {
            animation: fadeIn 0.6s ease-out forwards;
        }

        .metric-card:nth-child(1) { animation-delay: 0.1s; }
        .metric-card:nth-child(2) { animation-delay: 0.2s; }
        .metric-card:nth-child(3) { animation-delay: 0.3s; }
        .metric-card:nth-child(4) { animation-delay: 0.4s; }
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
                        <a href="sup-dashboard.php" class="nav-link active">
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
                    <h2>Welcome, <?php echo htmlspecialchars($staff_name ?? $username); ?></h2>
                    <p><?php echo htmlspecialchars($job_title ?? 'Supervisor'); ?> <?php echo $department_name ? '• ' . htmlspecialchars($department_name) : ''; ?></p>
                </div>
                <div class="header-actions">
                    <div class="user-info">
                        <span><strong><?php echo htmlspecialchars($username); ?></strong></span>
                        <span style="text-transform: capitalize;"><?php echo htmlspecialchars($role); ?></span>
                    </div>
                    <a href="?logout=1" class="logout-btn">Logout</a>
                </div>
            </header>

            <!-- Metrics Grid -->
            <div class="metrics-grid">
                <a href="sup-workforce_ready.php" class="metric-card-link">
                    <div class="metric-card green">
                        <div class="metric-title">Workforce Ready</div>
                        <div class="metric-value"><?php echo $workforce_ready_percentage; ?>%</div>
                    </div>
                </a>

                <a href="sup-training_due.php" class="metric-card-link">
                    <div class="metric-card orange">
                        <div class="metric-title">Training Due</div>
                        <div class="metric-value"><?php echo $training_due; ?></div>
                    </div>
                </a>

                <a href="sup-expired_certs.php" class="metric-card-link">
                    <div class="metric-card red">
                        <div class="metric-title">Expired Certs</div>
                        <div class="metric-value"><?php echo $expired_certs; ?></div>
                    </div>
                </a>

                <a href="sup-pending_leave.php" class="metric-card-link">
                    <div class="metric-card blue">
                        <div class="metric-title">Pending Leave</div>
                        <div class="metric-value"><?php echo $pending_leave; ?></div>
                    </div>
                </a>
            </div>

            <!-- System Overview -->
            <section class="overview-section">
                <h2 class="overview-title">Supervisor Dashboard Overview</h2>
                <p class="overview-text">
                    As a supervisor, you have access to team management tools and approval workflows. Use this dashboard to monitor your team's readiness and handle pending requests.
                </p>
                
                <ul class="overview-list">
                    <li><strong>👥 Workforce Ready:</strong> View staff training completion and certification status</li>
                    <li><strong>🎓 Training Due:</strong> Monitor pending and upcoming training requirements</li>
                    <li><strong>📜 Expired Certs:</strong> Track and manage expired certifications</li>
                    <li><strong>📅 Pending Leave:</strong> Review and approve/reject staff leave applications</li>
                </ul>
            </section>
        </main>
    </div>
</body>
</html>