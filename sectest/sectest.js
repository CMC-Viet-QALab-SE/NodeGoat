'use strict';

// Intentionally vulnerable sample for CI/CD SAST gate (Semgrep).
// DO NOT wire this into the real app — it exists only to be scanned.

const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');

// Hardcoded credentials — p/secrets (SAST) will flag these.
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

module.exports = function (app, db) {
  // 1) Command injection: user input concatenated into a shell command.
  app.get('/sectest/ping', (req, res) => {
    exec('ping -c 1 ' + req.query.host, (err, stdout) => res.send(stdout));
  });

  // 2) Path traversal: req input joined into a filesystem path (ERROR-level rule).
  app.get('/sectest/read', (req, res) => {
    const target = path.join(__dirname, req.query.file);
    res.send(fs.readFileSync(target, 'utf8'));
  });

  // 3) SQL injection: user input concatenated into a query string.
  app.get('/sectest/user', (req, res) => {
    const query = "SELECT * FROM users WHERE id = '" + req.query.id + "'";
    db.query(query, (err, rows) => res.json(rows));
  });

  // 4) Reflected XSS + eval on user-controlled expression.
  app.get('/sectest/calc', (req, res) => {
    res.send('Result: ' + eval(req.query.expr));
  });
};
