// Sample vulnerable JavaScript code for testing

// A03: SQL Injection
function getUser(userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  return db.query(query);
}

// A03: XSS
function displayMessage(message) {
  document.getElementById("content").innerHTML = message;
}

// A02: Weak Password Hashing
const crypto = require("crypto");
function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

// A05: Hardcoded Secrets
const config = {
  api_key: "sk_live_1234567890abcdef",
  password: "admin123",
};

// A07: Weak Session Management
function storeToken(token) {
  localStorage.setItem("auth_token", token);
}

// A10: SSRF
function fetchUserData(url) {
  return fetch(url); // User-controlled URL
}
