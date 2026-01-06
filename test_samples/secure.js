// secure-login.js
// Demonstrates secure coding best practices

const express = require("express");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json());

// Rate limiting to prevent brute force attacks
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5
});

const users = {
  admin: bcrypt.hashSync("StrongPassword@123", 10)
};

app.post("/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Invalid input" });
  }

  if (!users[username]) {
    return res.status(401).json({ message: "Authentication failed" });
  }

  const isMatch = await bcrypt.compare(password, users[username]);
  if (!isMatch) {
    return res.status(401).json({ message: "Authentication failed" });
  }

  res.json({ message: "Login successful" });
});

app.listen(3000, () => console.log("Secure server running"));
