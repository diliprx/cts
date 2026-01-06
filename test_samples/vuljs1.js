// vulnerable-login.js
// Contains multiple security vulnerabilities

const express = require("express");
const app = express();
app.use(express.json());

const users = {
  admin: "admin123" // ❌ Hardcoded credentials
};

app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // ❌ No input validation
  if (users[username] == password) {
    res.send("Login successful");
  } else {
    res.send("Login failed");
  }
});

// ❌ Dangerous use of eval (Code Injection)
app.get("/calc", (req, res) => {
  const result = eval(req.query.exp);
  res.send("Result: " + result);
});

app.listen(3000);
