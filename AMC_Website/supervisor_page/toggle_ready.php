<?php
session_start();
require_once __DIR__ . '/../misc_security/secure-transport.php';
require_once __DIR__ . '/../misc_security/session-hardening.php';
require_once __DIR__ . '/../misc_security/sql-prevention.php';

if ($_SESSION['role'] !== 'supervisor') {
    http_response_code(403);
    exit("Forbidden");
}

$data = json_decode(file_get_contents("php://input"), true);

$staff_id = (int)$data['staff_id'];
$reason = trim($data['reason']);

if (!$staff_id || $reason === '') {
    http_response_code(400);
    exit("Invalid input");
}

$mysqli = new mysqli("localhost", "root", "", "swap");

// Check if supervisor can manage this staff (same department or HR)
$check = $mysqli->prepare("
    SELECT d.name as dept_name 
    FROM staff s
    LEFT JOIN department d ON s.department_id = d.id
    WHERE s.id = ?
");
$check->bind_param("i", $staff_id);
$check->execute();
$result = $check->get_result()->fetch_assoc();
$staff_dept = $result['dept_name'];
$check->close();

if ($_SESSION['dept'] !== 'HR' && $_SESSION['dept'] !== 'Human Resources' && $_SESSION['dept'] !== $staff_dept) {
    http_response_code(403);
    exit("Cannot modify staff from other departments");
}

// Toggle logic
$stmt = $mysqli->prepare("
    INSERT INTO workforce_ready (staff_id, is_ready, reason, updated_by)
    VALUES (?, 1, ?, ?)
    ON DUPLICATE KEY UPDATE 
        is_ready = IF(is_ready = 1, 0, 1),
        reason = VALUES(reason),
        updated_by = VALUES(updated_by),
        updated_at = CURRENT_TIMESTAMP
");

$stmt->bind_param("iss", $staff_id, $reason, $_SESSION['user']);
$stmt->execute();

$stmt->close();
$mysqli->close();

echo "OK";
?>