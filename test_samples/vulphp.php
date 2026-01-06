<?php
// vulnerable-login.php
// Contains multiple security flaws

$conn = mysqli_connect("localhost", "root", "", "testdb");

$username = $_POST["username"];
$password = $_POST["password"];

// ❌ SQL Injection
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $query);

// ❌ Authentication bypass possible
if (mysqli_num_rows($result) > 0) {
    echo "Login successful";
} else {
    echo "Login failed";
}

// ❌ Command Injection
if (isset($_GET["cmd"])) {
    system($_GET["cmd"]);
}
?>
