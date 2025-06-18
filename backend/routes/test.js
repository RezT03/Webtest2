const express = require('express');
const router = express.Router();
const { exec } = require('child_process');
const path = require('path');
const db = require('../config/db');
const fs = require('fs');
const moment = require('moment')


router.post('/scan-all', async (req, res) => {
  const { url, dos_enabled, requests_num, duration, packet_size } = req.body;
  const userId = req.session.userId || 1;
  const resultLogs = [];

  const execPython = (script, args = [], label = '') => {
    return new Promise((resolve) => {
      exec(`python3 ${path.join(__dirname, '../utils', script)} ${args.join(' ')}`, (err, stdout) => {
        resultLogs.push(`--- ${label} ---\n${stdout}`);
        resolve();
      });
    });
  };

  // Run all scan processes
  await execPython("misConfig.py", [url], "Server Misconfiguration")
  await execPython('techDetector.py', [url], 'CVE/Software Detection');
  await execPython("xss-sqli-tester.py", [url], "XSS and SQL Injection Test");

 if (dos_enabled === 'true') {
  const headerString = req.body.cookie_header ? `Cookie: ${req.body.cookie_header}` : null;
  await execPython('dosTester.py', [url, requests_num || 100, duration || 10, packet_size || 1024, headerString || ''], 'DoS Test');
}

  // Log to DB
  await db.query('INSERT INTO test_results (user_id, test_type, target_url, request_payload, result, summary) VALUES (?, ?, ?, ?, ?, ?)', [
    userId, 'scan-all', url,
    JSON.stringify(req.body),
    resultLogs.join('\n\n'),
    'Hasil gabungan pengujian keamanan'
  ]);

  res.send(resultLogs.join('\n\n'));
});

module.exports = router;