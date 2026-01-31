<?php
declare(strict_types=1);

// Error suppression + logging
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/logs/sql_security.log');

// Auto-create logs directory
if (!is_dir(__DIR__ . '/logs')) {
    @mkdir(__DIR__ . '/logs', 0750, true);
}

/* ========================= DATABASE CONNECTION ========================= */

function db(): mysqli
{
    static $db;
    if ($db instanceof mysqli) return $db;

    $db = @new mysqli("localhost", "root", "", "swap");

    if ($db->connect_error) {
        log_security_event("DB_CONNECTION_FAILED", "Connection error");
        http_response_code(500);
        exit("Database unavailable");
    }

    $db->set_charset("utf8mb4");
    $db->options(MYSQLI_OPT_INT_AND_FLOAT_NATIVE, 1);
    $db->query("SET SESSION sql_mode='TRADITIONAL'");
    
    // Auto-create security_logs table
    $db->query("CREATE TABLE IF NOT EXISTS security_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        event_type VARCHAR(50) NOT NULL,
        param_name VARCHAR(100),
        param_value TEXT,
        ip_address VARCHAR(45),
        user_agent VARCHAR(500),
        request_url VARCHAR(500),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_event_type (event_type),
        INDEX idx_created_at (created_at),
        INDEX idx_ip (ip_address)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    return $db;
}

/* ========================= PREPARED STATEMENTS ========================= */

function db_stmt(string $sql): mysqli_stmt
{
    $stmt = @db()->prepare($sql);
    if (!$stmt) {
        log_security_event("SQL_PREPARE_FAILED", "Failed to prepare statement");
        http_response_code(500);
        exit("Query error");
    }
    return $stmt;
}

function db_run(string $sql, string $types = "", array $params = []): mysqli_stmt
{
    $stmt = db_stmt($sql);

    if ($types !== "") {
        if (strlen($types) !== count($params)) {
            log_security_event("PARAM_MISMATCH", "Parameter count mismatch");
            http_response_code(400);
            exit("Invalid parameters");
        }
        
        if (!@$stmt->bind_param($types, ...$params)) {
            log_security_event("BIND_FAILED", "Parameter binding failed");
            http_response_code(500);
            exit("Request error");
        }
    }

    if (!@$stmt->execute()) {
        log_security_event("SQL_EXECUTE_FAILED", "Query execution failed");
        http_response_code(500);
        exit("Operation failed");
    }

    return $stmt;
}

function db_one(string $sql, string $types = "", array $params = []): ?array
{
    $res = db_run($sql, $types, $params)->get_result();
    return $res ? ($res->fetch_assoc() ?: null) : null;
}

function db_all(string $sql, string $types = "", array $params = []): array
{
    $res = db_run($sql, $types, $params)->get_result();
    return $res ? $res->fetch_all(MYSQLI_ASSOC) : [];
}

function db_exec(string $sql, string $types = "", array $params = []): int
{
    $stmt = db_run($sql, $types, $params);
    return $stmt->affected_rows;
}

/* ========================= INPUT VALIDATION ========================= */

function sql_ident(string $name): string
{
    if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]{0,63}$/', $name)) {
        log_security_event("INVALID_IDENTIFIER", "Invalid SQL identifier", ['identifier' => $name]);
        http_response_code(400);
        exit("Invalid identifier");
    }
    return $name;
}

function validate_id($id, string $field_name = 'id'): int
{
    $id_int = filter_var($id, FILTER_VALIDATE_INT);
    
    if ($id_int === false || $id_int < 1) {
        log_security_event("INVALID_ID", "Invalid ID parameter", ['field' => $field_name, 'value' => $id]);
        http_response_code(400);
        exit("Invalid ID");
    }
    
    return $id_int;
}

function validate_search(string $search, int $max_length = 100): string
{
    $search = trim(substr($search, 0, $max_length));
    
    if (looks_like_sqli($search)) {
        log_security_event("SQLI_IN_SEARCH", "SQL injection detected in search", ['search_term' => $search]);
        
        if (session_status() !== PHP_SESSION_ACTIVE) {
            @session_start();
        }
        $_SESSION['flash_sqli'] = 1;
        
        http_response_code(400);
        exit("Invalid search");
    }
    
    if (!preg_match('/^[a-zA-Z0-9\s\-_.,@]+$/', $search)) {
        log_security_event("INVALID_SEARCH_CHARS", "Invalid characters in search", ['search_term' => $search]);
        http_response_code(400);
        exit("Invalid characters");
    }
    
    return $search;
}

function validate_date(string $date, string $field_name = 'date'): string
{
    $timestamp = strtotime($date);
    
    if ($timestamp === false) {
        log_security_event("INVALID_DATE", "Invalid date format", ['field' => $field_name, 'value' => $date]);
        http_response_code(400);
        exit("Invalid date");
    }
    
    return date('Y-m-d', $timestamp);
}

function validate_enum(string $value, array $allowed, string $field_name = 'status'): string
{
    if (!in_array($value, $allowed, true)) {
        log_security_event("INVALID_ENUM", "Invalid enum value", ['field' => $field_name, 'value' => $value]);
        http_response_code(400);
        exit("Invalid value");
    }
    
    return $value;
}

/* ========================= SQL INJECTION DETECTION ========================= */

function looks_like_sqli(string $value): bool
{
    $patterns = [
        '/(--|#|\/\*|\*\/)/i',
        '/\b(union|select|insert|update|delete|drop|alter|create|exec|execute|script|javascript|onerror)\b/i',
        '/(\bor\b\s*\d+\s*=\s*\d+|\band\b\s*\d+\s*=\s*\d+)/i',
        '/(\bor\b\s*[\'"]?\w+[\'"]?\s*=\s*[\'"]?\w+[\'"]?)/i',
        '/(\'|\"|`)(\s*)(or|and|union)(\s*)(\'|\"|`)/i',
        '/(0x[0-9a-f]+|char\()/i',
        '/;\s*(select|insert|update|delete|drop)/i',
        '/information_schema/i',
        '/\b(sleep|benchmark|waitfor)\s*\(/i',
    ];
    
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $value)) {
            return true;
        }
    }
    
    return false;
}

function detect_sql_injection(array $inputs, bool $log = true): bool
{
    foreach ($inputs as $k => $v) {
        if (is_array($v)) {
            if (detect_sql_injection($v, $log)) return true;
            continue;
        }
        
        if (!is_string($v)) continue;

        if (looks_like_sqli($v)) {
            if ($log) {
                log_security_event("SQLI_ATTEMPT", "SQL injection attempt detected", [
                    'param' => $k,
                    'value' => substr($v, 0, 200),
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                    'url' => $_SERVER['REQUEST_URI'] ?? 'unknown'
                ]);
                
                // Log to database
                try {
                    db_exec(
                        "INSERT INTO security_logs (event_type, param_name, param_value, ip_address, user_agent, request_url) 
                         VALUES (?, ?, ?, ?, ?, ?)",
                        "ssssss",
                        ['sqli_attempt', $k, substr($v, 0, 500), $_SERVER['REMOTE_ADDR'] ?? 'unknown', 
                         substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 500), $_SERVER['REQUEST_URI'] ?? 'unknown']
                    );
                } catch (Exception $e) {
                    // Silently fail if table doesn't exist
                }
            }
            
            if (session_status() !== PHP_SESSION_ACTIVE) {
                @session_start();
            }
            $_SESSION['flash_sqli'] = 1;
            
            return true;
        }
    }
    
    return false;
}

function auto_detect_sqli(): void
{
    $all_inputs = array_merge($_GET, $_POST, $_COOKIE);
    
    if (detect_sql_injection($all_inputs, true)) {
        log_security_event("REQUEST_BLOCKED", "Malicious request blocked");
        http_response_code(403);
        exit("Request blocked");
    }
}

/* ========================= SECURITY LOGGING ========================= */

function log_security_event(string $event_type, string $message, array $context = []): void
{
    $log_entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'event_type' => $event_type,
        'message' => $message,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user' => $_SESSION['user'] ?? 'anonymous',
        'session_id' => session_id(),
        'context' => $context
    ];
    
    $log_file = __DIR__ . '/logs/sql_security.log';
    $log_line = json_encode($log_entry) . PHP_EOL;
    
    @file_put_contents($log_file, $log_line, FILE_APPEND | LOCK_EX);
    error_log("[SQL_SECURITY] {$event_type}: {$message}");
}

/* ========================= UTILITY FUNCTIONS ========================= */

function redirect_clean_url(array $removeKeys = ['role','id','staff_id','employee_id','user_id'], bool $withPopup = true): void
{
    $query = $_GET;

    foreach ($removeKeys as $key) {
        unset($query[$key]);
    }

    $base = strtok($_SERVER["REQUEST_URI"], '?');
    $cleanUrl = $base . (count($query) ? ('?' . http_build_query($query)) : '');

    if ($withPopup) {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            @session_start();
        }
        $_SESSION['flash_unauth'] = 1;
    }
    
    header("Location: " . $cleanUrl);
    exit;
}

function render_security_popups(): void
{
    $unauth = !empty($_SESSION['flash_unauth']);
    $sqli   = !empty($_SESSION['flash_sqli']);

    unset($_SESSION['flash_unauth'], $_SESSION['flash_sqli']);

    if (!$unauth && !$sqli) return;

    $msg = $sqli ? "⚠️ SQL Injection Attempt Detected & Blocked" : "🚫 Unauthorized Access Detected";
    $details = $sqli 
        ? "Malicious SQL patterns detected. Incident logged with your IP address." 
        : "Unauthorized access attempt logged.";

    ?>
    <div id="secModal" style="position:fixed;inset:0;background:rgba(0,0,0,.75);display:flex;align-items:center;justify-content:center;z-index:99999;backdrop-filter:blur(4px);">
        <div style="width:min(480px,92vw);background:#1e293b;color:#fff;border:2px solid #ef4444;border-radius:16px;padding:28px;box-shadow:0 25px 50px rgba(0,0,0,.5);font-family:system-ui;">
            <div style="font-size:24px;font-weight:800;margin-bottom:12px;color:#ef4444;display:flex;align-items:center;gap:12px;">
                <span style="font-size:32px;">🛡️</span>
                <span>Security Alert</span>
            </div>
            <div style="font-size:16px;font-weight:600;opacity:.95;line-height:1.5;margin-bottom:8px;color:#fca5a5;">
                <?php echo htmlspecialchars($msg); ?>
            </div>
            <div style="font-size:14px;opacity:.8;line-height:1.6;margin-bottom:20px;color:#cbd5e1;">
                <?php echo htmlspecialchars($details); ?>
            </div>
            <?php if ($sqli): ?>
            <div style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);border-radius:8px;padding:12px;margin-bottom:20px;">
                <div style="font-size:12px;color:#fca5a5;font-weight:600;margin-bottom:4px;">🔍 DETECTION DETAILS:</div>
                <div style="font-size:11px;color:#cbd5e1;font-family:monospace;">
                    Timestamp: <?php echo date('Y-m-d H:i:s'); ?><br>
                    IP: <?php echo htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'unknown'); ?><br>
                    Incident ID: <?php echo substr(md5(uniqid()), 0, 8); ?>
                </div>
            </div>
            <?php endif; ?>
            <button onclick="document.getElementById('secModal').remove()"
                    style="width:100%;border:0;background:#ef4444;color:#fff;padding:14px;border-radius:10px;font-weight:700;font-size:15px;cursor:pointer;">
                I Understand
            </button>
        </div>
    </div>
    <style>
        #secModal button:hover { background:#dc2626!important; }
    </style>
    <?php
}

/* ========================= HELPER FUNCTIONS ========================= */

function get_staff_by_id(int $staff_id): ?array
{
    $staff_id = validate_id($staff_id, 'staff_id');
    return db_one("SELECT * FROM staff WHERE id = ?", "i", [$staff_id]);
}

function search_staff(string $search_term): array
{
    $search_term = validate_search($search_term);
    $like_term = "%{$search_term}%";
    return db_all("SELECT * FROM staff WHERE name LIKE ? OR email LIKE ? ORDER BY name", "ss", [$like_term, $like_term]);
}

function get_training_by_type(string $training_type): array
{
    $training_type = validate_search($training_type);
    return db_all(
        "SELECT * FROM staff_training st 
         JOIN training_type tt ON st.training_id = tt.id 
         WHERE tt.name LIKE ? 
         ORDER BY st.completion_date DESC",
        "s",
        ["%{$training_type}%"]
    );
}

function approve_leave(int $leave_id, int $approved_by): bool
{
    $leave_id = validate_id($leave_id, 'leave_id');
    $approved_by = validate_id($approved_by, 'approved_by');
    
    $affected = db_exec(
        "UPDATE leave_application SET status = 'approved', approved_by = ? WHERE id = ?",
        "ii",
        [$approved_by, $leave_id]
    );
    
    return $affected > 0;
}

function get_user_by_username(string $username): ?array
{
    if (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username)) {
        log_security_event("INVALID_USERNAME", "Invalid username format", ['username' => $username]);
        return null;
    }
    
    return db_one("SELECT * FROM users WHERE username = ?", "s", [$username]);
}

/* ========================= AUTO-INITIALIZATION ========================= */

if (php_sapi_name() !== 'cli') {
    auto_detect_sqli();
}