<?php

// 1. SQL Injection
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " + $id; // Concatenation in query

// 2. Cross-Site Scripting (XSS)
$name = $_POST['name'];
echo "<div>Welcome, " . $name . "</div>";

// 3. Weak Hashing
$password = "supersecret";
$hash = md5($password);

// 4. Remote Code Execution possibility
$cmd = $_GET['cmd'];
system($cmd); 

?>
