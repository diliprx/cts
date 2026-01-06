<?php
// secure-login.php
// Secure PHP coding practices

session_start();

$users = [
    "admin" => password_hash("StrongPassword@123", PASSWORD_BCRYPT)
];

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = filter_input(INPUT_POST, "username", FILTER_SANITIZE_SPECIAL_CHARS);
    $password = $_POST["password"] ?? "";

    if (!$username || !$password) {
        die("Invalid input");
    }

    if (!isset($users[$username])) {
        die("Authentication failed");
    }

    if (!password_verify($password, $users[$username])) {
        die("Authentication failed");
    }

    session_regenerate_id(true);
    $_SESSION["user"] = $username;

    echo "Login successful";
}
?>
