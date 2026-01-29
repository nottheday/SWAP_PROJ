<?php
/***************************************
 * PASSWORD RESET UTILITY
 * Run this file once to reset all passwords
 ***************************************/

// Database configuration
$db_host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "swap";

// Connect to database
$mysqli = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

// Set the new password for all users
$new_password = "password123";  // Change this to whatever you want

// Generate password hash
$password_hash = password_hash($new_password, PASSWORD_DEFAULT);

echo "<h2>Password Reset Utility</h2>";
echo "<p>New password hash generated: <code>$password_hash</code></p>";
echo "<p>Password will be set to: <strong>$new_password</strong></p>";
echo "<hr>";

// Update all users
$users = ['alice', 'bob', 'charlie', 'admin'];

foreach ($users as $username) {
    $stmt = $mysqli->prepare("UPDATE users SET password = ? WHERE username = ?");
    $stmt->bind_param("ss", $password_hash, $username);
    
    if ($stmt->execute()) {
        echo "✓ Updated password for: <strong>$username</strong><br>";
    } else {
        echo "✗ Failed to update: <strong>$username</strong><br>";
    }
    $stmt->close();
}

$mysqli->close();

echo "<hr>";
echo "<h3>Test the login now with:</h3>";
echo "<ul>";
echo "<li>Username: alice, Password: $new_password, Role: staff</li>";
echo "<li>Username: bob, Password: $new_password, Role: supervisor</li>";
echo "<li>Username: charlie, Password: $new_password, Role: staff</li>";
echo "<li>Username: admin, Password: $new_password, Role: admin</li>";
echo "</ul>";

echo "<p style='color: red;'><strong>IMPORTANT: Delete this file after use for security!</strong></p>";
?>