<?php
// Sample vulnerable PHP code for testing

// A03: SQL Injection
$userId = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $userId;
$result = mysqli_query($conn, $query);

// A03: XSS
echo $_GET['name'];
print $_POST['comment'];

// A02: Weak Password Hashing
$password = $_POST['password'];
$hash = md5($password);

// A05: Hardcoded Secrets
$password = "admin123";
$api_key = "sk_live_1234567890abcdef";

// A03: Command Injection
$filename = $_GET['file'];
exec("cat " . $filename);

// A10: SSRF
$url = $_GET['url'];
$content = file_get_contents($url);

// A07: Weak Session Management
session_start();
// Missing session security configuration

?>

