// Express.js vulnerable code with taint sources

const express = require("express");
const app = express();

// A03: SQL Injection - tainted req.query flows to db.query
app.get("/user", (req, res) => {
  const userId = req.query.id; // TAINT SOURCE
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query); // SINK - SQL Injection!
});

// A03: XSS - tainted req.query flows to innerHTML
app.get("/display", (req, res) => {
  const message = req.query.msg; // TAINT SOURCE
  const html = "<div>" + message + "</div>";
  res.send(html); // Not directly detected, but innerHTML would be
});

// A03: Command Injection - tainted req.body flows to exec
app.post("/backup", (req, res) => {
  const filename = req.body.file; // TAINT SOURCE
  const cmd = "tar -czf backup.tar.gz " + filename;
  exec(cmd); // SINK - Command Injection!
});

// A10: SSRF - tainted req.params flows to fetch
app.get("/proxy/:url", (req, res) => {
  const targetUrl = req.params.url; // TAINT SOURCE
  fetch(targetUrl).then((data) => res.send(data)); // SINK - SSRF!
});

// A03: Code Injection - tainted req.body flows to eval
app.post("/calc", (req, res) => {
  const expression = req.body.expr; // TAINT SOURCE
  const result = eval(expression); // SINK - Code Injection!
  res.json({ result });
});

// Example with sanitization
app.get("/safe", (req, res) => {
  const userId = req.query.id; // TAINT SOURCE
  const safeId = parseInt(userId); // SANITIZER - removes taint
  const query = "SELECT * FROM users WHERE id = " + safeId;
  db.query(query); // Should be safe
});
